"""``check`` — the hard validation gate.

Validates state consistency before ``publish``:

* schema — every record parses against its model,
* lifecycle legality — every finding's status satisfies its entry guard,
* orphan references — no dangling project/finding/session links,
* duplicate project identity — no two projects share a git_url or local_path,
* OSV conformance — every finding's OSV validates against the pinned schema,
* disclosure-draft conformance — every finding's CSAF and OpenVEX drafts
  validate (the CVE draft is intentionally non-submittable and is not checked).

A ``check`` that raises counts as a failed check (Constitution VII), so the whole
run is wrapped and any exception becomes a failure rather than a crash.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .export.csaf import finding_to_csaf, validate_csaf
from .export.openvex import finding_to_openvex, validate_openvex
from .export.osv import finding_to_osv, validate_osv
from .schema import (
    Coverage,
    Finding,
    FindingStatus,
    Methodology,
    Project,
    Session,
)
from .store import Store

_MODEL_BY_KIND = {
    "project": Project,
    "finding": Finding,
    "session": Session,
    "coverage": Coverage,
    "methodology": Methodology,
}


@dataclass
class CheckReport:
    ok: bool = True
    errors: list[str] = field(default_factory=list)

    def fail(self, message: str) -> None:
        self.ok = False
        self.errors.append(message)


def run_check(store: Store) -> CheckReport:
    report = CheckReport()
    try:
        parsed = _check_schema(store, report)
        _check_duplicate_identity(parsed["project"], report)
        _check_orphans(parsed, report)
        _check_lifecycle_at_rest(parsed["finding"], store, report)
        _check_osv(parsed["finding"], report)
        _check_csaf(parsed["finding"], report)
        _check_openvex(parsed["finding"], report)
    except Exception as exc:  # a check that raises is a failed check
        report.fail(f"check raised: {exc!r}")
    return report


def _check_schema(store: Store, report: CheckReport) -> dict[str, list]:
    parsed: dict[str, list] = {kind: [] for kind in _MODEL_BY_KIND}
    for raw in store.raw_records():
        model = _MODEL_BY_KIND.get(raw.kind)
        if model is None:
            report.fail(f"{raw.ident}: unknown record kind {raw.kind!r}")
            continue
        try:
            parsed[raw.kind].append(model.from_markdown(raw.text))
        except Exception as exc:
            report.fail(f"{raw.ident}: schema violation: {exc}")
    return parsed


def _check_duplicate_identity(projects: list[Project], report: CheckReport) -> None:
    seen: dict[str, str] = {}
    for project in projects:
        identity = project.identity
        if identity in seen:
            report.fail(
                f"duplicate project identity {identity!r}: "
                f"{seen[identity]!r} and {project.id!r}"
            )
        else:
            seen[identity] = project.id


def _check_orphans(parsed: dict[str, list], report: CheckReport) -> None:
    project_ids = {p.id for p in parsed["project"]}
    finding_ids = {f.id for f in parsed["finding"]}

    for finding in parsed["finding"]:
        if finding.project not in project_ids:
            report.fail(
                f"finding {finding.id!r} references unknown project {finding.project!r}"
            )
    for coverage in parsed["coverage"]:
        if coverage.project not in project_ids:
            report.fail(
                f"coverage {coverage.ref!r} references unknown project "
                f"{coverage.project!r}"
            )
    for session in parsed["session"]:
        if session.project is not None and session.project not in project_ids:
            report.fail(
                f"session {session.id!r} references unknown project "
                f"{session.project!r}"
            )
        for fid in session.findings_touched:
            if fid not in finding_ids:
                report.fail(
                    f"session {session.id!r} touched unknown finding {fid!r}"
                )


def _check_lifecycle_at_rest(
    findings: list[Finding], store: Store, report: CheckReport
) -> None:
    for finding in findings:
        status = finding.status
        if status is FindingStatus.verified:
            if not finding.evidence_ref or not store.detail_exists(finding.evidence_ref):
                report.fail(
                    f"finding {finding.id!r} is verified but has no resolving "
                    f"evidence_ref"
                )
        elif status is FindingStatus.disclosed:
            if not finding.cve:
                report.fail(f"finding {finding.id!r} is disclosed without a cve")
            if not finding.has_reference_type("advisory"):
                report.fail(
                    f"finding {finding.id!r} is disclosed without an advisory reference"
                )
        elif status is FindingStatus.patched:
            if not finding.cve:
                report.fail(f"finding {finding.id!r} is patched without a cve")
            if not finding.has_reference_type("fix"):
                report.fail(
                    f"finding {finding.id!r} is patched without a fix reference"
                )


def _check_osv(findings: list[Finding], report: CheckReport) -> None:
    for finding in findings:
        errors = validate_osv(finding_to_osv(finding))
        for err in errors:
            report.fail(f"finding {finding.id!r} OSV non-conformance: {err}")


def _check_csaf(findings: list[Finding], report: CheckReport) -> None:
    for finding in findings:
        errors = validate_csaf(finding_to_csaf(finding))
        for err in errors:
            report.fail(f"finding {finding.id!r} CSAF non-conformance: {err}")


def _check_openvex(findings: list[Finding], report: CheckReport) -> None:
    for finding in findings:
        errors = validate_openvex(finding_to_openvex(finding))
        for err in errors:
            report.fail(f"finding {finding.id!r} OpenVEX non-conformance: {err}")
