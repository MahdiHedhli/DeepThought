"""Feature 004 — SIBLING HUNT session (read-only variant analysis).

SIBLING HUNT takes a VERIFIED finding, derives a variant signature from its typed
fields, gates EACH target independently, and hunts read-only for sibling
instances of the same bug class — writing candidate variant findings and read
coverage, ingesting exactly one worker envelope per gated-proceed target. It
mirrors DISCOVER's shape and reuses its firewall, adding a same-class filter and
a per-project authority firewall.

Structure of this file:
* T003 — same-project path (gate, refuse rules, variants, same-class filter,
  scope containment, coverage, injection inertness).
* T004 — cross-project path (per-sibling gate, authority invariants).
* T005 — package exports.
* T006 — OSV-validity of every variant.
* T008 — the `check` gate holds over variant output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deepthought.export.osv import finding_to_osv, validate_osv
from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.schema import (
    CloseState,
    CoverageMethod,
    FindingStatus,
    GateOutcome,
    SessionType,
)
from deepthought.store import FileStore

from .conftest import make_finding, make_project

GATE = HermesUltraCodeGate()
SIBLINGS = str(Path(__file__).parent / "fixtures" / "siblings.sarif")


# --- helpers ----------------------------------------------------------------


def _verified_sql_finding(project: str = "src-proj", finding_id: str = "F-0007"):
    """A VERIFIED source finding whose typed fields derive an inject:sql class.

    The summary carries the py/sql-injection ruleId token, so the session's
    source-signature derivation (closed lookup over the typed summary) yields the
    inject:sql capability WITHOUT needing a persisted primitive.
    """
    return make_finding(
        id=finding_id,
        project=project,
        status="verified",
        summary="py/sql-injection: user input reaches a SQL query in app/db.py",
        body="## Root cause\n\nUser input reaches a query.\n\n**Location:** `app/db.py:42`",
        # A verified finding at rest needs a resolving evidence_ref for check; but
        # the source is only READ here, so we leave it candidate-shaped for the
        # in-memory tests and rely on the store seeding below to set it verified.
        evidence_ref=None,
    )


def _seed_source(store: FileStore, project_id: str = "src-proj") -> None:
    """Register the source project (scope app) and a verified source finding.

    The verified finding is written directly at status=verified with a resolving
    evidence_ref so `check` stays green; SIBLING HUNT only reads it.
    """
    store.save_project(
        make_project(
            id=project_id,
            git_url=f"https://example.test/{project_id}",
            authorization_basis="permissive_oss",
            scope_allowlist=["app"],
        )
    )
    finding = _verified_sql_finding(project=project_id)
    # Page a resolving evidence artifact so a verified finding is check-clean.
    ref = store.write_detail("S-seed", "evidence.txt", "seed evidence for the source")
    finding.evidence_ref = ref
    store.save_finding(finding)


def _run(store, **kwargs):
    from deepthought.sessions import SiblingHuntSession

    return run_session(store, GATE, SiblingHuntSession(**kwargs))


# --- gate: proceed / hold / refuse ------------------------------------------


def test_sibling_hunt_runs_through_harness_and_closes_clean(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)

    record = _run(
        store,
        project_id="src-proj",
        finding_id="F-0007",
        sarif_path=SIBLINGS,
        root=None,
    )

    assert record.type is SessionType.sibling_hunt
    assert record.gate_outcome is GateOutcome.proceed
    assert record.close_state is CloseState.clean
    assert record.project == "src-proj"
    assert record.has_next_steps()


def test_empty_scope_source_holds_at_gate(state_dir):
    store = FileStore(state_dir)
    store.save_project(
        make_project(id="src-proj", git_url="https://example.test/x", scope_allowlist=[])
    )
    finding = _verified_sql_finding()
    store.save_finding(finding)

    record = _run(store, project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)
    assert record.gate_outcome is GateOutcome.hold
    # A held gate writes no findings.
    assert store.list_findings(project="src-proj") == [finding] or all(
        f.status is FindingStatus.verified for f in store.list_findings()
    )


def test_no_basis_source_refuses_at_gate(state_dir):
    store = FileStore(state_dir)
    store.save_project(
        make_project(
            id="src-proj",
            git_url="https://example.test/x",
            authorization_basis=None,
            scope_allowlist=["app"],
        )
    )
    store.save_finding(_verified_sql_finding())

    record = _run(store, project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)
    assert record.gate_outcome is GateOutcome.refuse


# --- refuse (in run): missing / wrong-project / not-verified source ----------


def test_refuses_when_source_finding_missing(state_dir):
    store = FileStore(state_dir)
    store.save_project(
        make_project(id="src-proj", git_url="https://example.test/x", scope_allowlist=["app"])
    )
    record = _run(store, project_id="src-proj", finding_id="F-9999", sarif_path=SIBLINGS)
    assert record.gate_outcome is GateOutcome.proceed
    assert record.close_state is CloseState.clean
    # No worker, no variants written.
    assert store.list_findings(project="src-proj") == []


def test_refuses_when_source_belongs_to_another_project(state_dir):
    store = FileStore(state_dir)
    _seed_source(store, project_id="src-proj")
    # A second project whose gate we run, but the finding belongs to src-proj.
    store.save_project(
        make_project(id="other", git_url="https://example.test/other", scope_allowlist=["app"])
    )
    record = _run(store, project_id="other", finding_id="F-0007", sarif_path=SIBLINGS)
    assert record.close_state is CloseState.clean
    # No variants written for 'other'.
    assert store.list_findings(project="other") == []


def test_refuses_when_source_is_not_verified(state_dir):
    store = FileStore(state_dir)
    store.save_project(
        make_project(id="src-proj", git_url="https://example.test/x", scope_allowlist=["app"])
    )
    # A candidate (not verified) source — SIBLING HUNT only hunts from verified.
    store.save_finding(_verified_sql_finding())  # written as verified? no:
    cand = make_finding(id="F-0100", project="src-proj", status="candidate")
    store.save_finding(cand)

    record = _run(store, project_id="src-proj", finding_id="F-0100", sarif_path=SIBLINGS)
    assert record.close_state is CloseState.clean
    # No new variants written beyond the seeded findings.
    ids_before = {"F-0007", "F-0100"}
    ids_after = {f.id for f in store.list_findings(project="src-proj")}
    assert ids_after == ids_before


# --- the hunt: variants, same-class filter, scope containment ----------------


def test_writes_candidate_variants_for_same_class_siblings(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS
    )
    record = run_session(store, GATE, session)

    variants = [
        f
        for f in store.list_findings(project="src-proj")
        if f.status is FindingStatus.candidate
    ]
    # siblings.sarif has 2 in-scope inject:sql results (app/reports.py, app/search.py),
    # 1 different-class (app/files.py -> write:arbitrary-file, dropped by same-class
    # filter), 1 out-of-scope inject:sql (vendor/..., dropped by scope containment).
    assert len(variants) == 2
    assert all(f.project == "src-proj" for f in variants)
    # fresh ids past the store max (source is F-0007).
    assert all(int(f.id.split("-")[1]) > 7 for f in variants)
    # the different-class file is not present.
    assert not any("files.py" in (f.body or "") for f in variants)
    # the out-of-scope vendor instance is not present.
    assert not any("vendor" in (f.body or "") for f in variants)


def test_same_class_filter_drops_different_capability(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS
    )
    run_session(store, GATE, session)
    # signature capability is inject:sql; the path-injection (write:arbitrary-file)
    # instance must be dropped.
    assert session.signature is not None
    assert session.signature.capability == "inject:sql"
    variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    assert all("sql" in f.summary.lower() for f in variants)


def test_ledger_holds_sibling_primitives_and_envelope_validated(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS
    )
    run_session(store, GATE, session)

    # The conductor ingested the worker envelope; the ledger holds the sibling
    # primitives (same-class, so inject:sql), and self.envelopes holds validated
    # envelope(s).
    assert session.conductor is not None
    assert len(session.conductor.ledger) == 2
    assert session.envelopes
    for env in session.envelopes:
        assert env is not None
        assert all(p.kind == "inject:sql" for p in env.primitives)


def test_teaches_back_read_coverage(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    record = _run(store, project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)

    cov = store.list_coverage(project="src-proj")
    assert cov
    assert all(c.method is CoverageMethod.read for c in cov)
    assert record.coverage_changed


def test_injection_in_sarif_and_hint_changes_nothing_structural(state_dir, tmp_path):
    store = FileStore(state_dir)
    _seed_source(store)
    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS
    )
    run_session(store, GATE, session)
    # Poisoned SARIF message text lands only in a data field (the finding body),
    # never as an instruction; capability of every ingested primitive is inject:sql.
    for env in session.envelopes:
        assert all(p.kind == "inject:sql" for p in env.primitives)


# --- T005: exports ----------------------------------------------------------


def test_signature_exports_from_sibling_package():
    from deepthought.sibling import Signature, signature_from_finding  # noqa: F401

    assert Signature.__name__ == "Signature"


def test_session_exports_from_sessions_package():
    from deepthought.sessions import SiblingHuntSession  # noqa: F401

    assert SiblingHuntSession.type is SessionType.sibling_hunt


# --- T006: OSV validity -----------------------------------------------------


def test_every_variant_is_osv_valid(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    _run(store, project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)

    variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    assert variants
    for f in variants:
        assert validate_osv(finding_to_osv(f)) == []


# --- T004: cross-project path (authority firewall) --------------------------


def _register_sibling(store, sibling_id="sib-proj", *, basis="permissive_oss", scope=("app",)):
    store.save_project(
        make_project(
            id=sibling_id,
            name=f"Sibling {sibling_id}",
            git_url=f"https://example.test/{sibling_id}",
            authorization_basis=basis,
            scope_allowlist=list(scope),
        )
    )


def test_authorized_in_scope_sibling_is_hunted_and_variants_bound_to_it(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
    )
    run_session(store, GATE, session)

    # Variants written for BOTH the source and the sibling, each bound to its
    # OWN project, over its OWN in-scope areas.
    src_variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    sib_variants = [
        f for f in store.list_findings(project="sib-proj") if f.status is FindingStatus.candidate
    ]
    assert len(src_variants) == 2
    assert len(sib_variants) == 2
    assert all(f.project == "sib-proj" for f in sib_variants)
    # Coverage attributed to the sibling.
    assert store.list_coverage(project="sib-proj")
    # Fresh, non-colliding ids across both targets.
    all_ids = [f.id for f in src_variants + sib_variants]
    assert len(all_ids) == len(set(all_ids))


def test_sibling_with_no_basis_is_refused_no_records(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj", basis=None)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
    )
    run_session(store, GATE, session)

    # Refused at its OWN gate: no worker, no findings, no coverage.
    assert store.list_findings(project="sib-proj") == []
    assert store.list_coverage(project="sib-proj") == []
    outcome = next(t for t in session.target_outcomes if t.project_id == "sib-proj")
    assert not outcome.proceeded
    assert outcome.gate_outcome == "refuse"


def test_sibling_with_empty_scope_is_held_no_records(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj", scope=())

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
    )
    run_session(store, GATE, session)

    assert store.list_findings(project="sib-proj") == []
    assert store.list_coverage(project="sib-proj") == []
    outcome = next(t for t in session.target_outcomes if t.project_id == "sib-proj")
    assert not outcome.proceeded
    assert outcome.gate_outcome == "hold"


def test_unregistered_named_sibling_is_skipped_never_created(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    projects_before = {p.id for p in store.list_projects()}

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["ghost-proj"],
        sarif_path=SIBLINGS,
    )
    run_session(store, GATE, session)

    # The named-but-unregistered sibling was never created.
    assert {p.id for p in store.list_projects()} == projects_before
    assert store.get_project("ghost-proj") is None
    outcome = next(t for t in session.target_outcomes if t.project_id == "ghost-proj")
    assert outcome.gate_outcome == "skipped"
    assert not outcome.proceeded


def test_authority_invariant_never_widens_scope_or_creates_projects(state_dir, monkeypatch):
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")
    # A named unauthorized sibling and an unregistered one, to exercise every path.
    _register_sibling(store, "unauth-proj", basis=None)

    # Spy on save_project: it must NEVER be called during a hunt.
    calls = {"save_project": 0}
    real_save = store.save_project

    def spy_save(project):
        calls["save_project"] += 1
        return real_save(project)

    monkeypatch.setattr(store, "save_project", spy_save)

    # Snapshot each project's scope/basis to assert they are untouched.
    before = {
        p.id: (tuple(p.scope_allowlist), p.authorization_basis)
        for p in store.list_projects()
    }

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj", "unauth-proj", "ghost-proj"],
        sarif_path=SIBLINGS,
    )
    run_session(store, GATE, session)

    # Never created or mutated a project.
    assert calls["save_project"] == 0
    after = {
        p.id: (tuple(p.scope_allowlist), p.authorization_basis)
        for p in store.list_projects()
    }
    assert after == before

    # Every finding/coverage written is for a target that proceeded at its gate:
    # subset of {source} union {authorized in-scope named siblings}.
    proceeded_projects = {t.project_id for t in session.target_outcomes if t.proceeded}
    assert proceeded_projects <= {"src-proj", "sib-proj"}
    written_projects = {f.project for f in store.list_findings() if f.status is FindingStatus.candidate}
    assert written_projects <= {"src-proj", "sib-proj"}
    cov_projects = {c.project for c in store.list_coverage()}
    assert cov_projects <= {"src-proj", "sib-proj"}


def test_cross_project_variants_are_all_osv_valid(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")
    _run(
        store,
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
    )
    variants = [f for f in store.list_findings() if f.status is FindingStatus.candidate]
    assert variants
    for f in variants:
        assert validate_osv(finding_to_osv(f)) == []


# --- T008: check stays a hard gate over SIBLING HUNT output -----------------


def test_check_is_green_on_hunt_output(state_dir):
    from deepthought.check import run_check

    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")
    _run(
        store,
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
    )
    report = run_check(store)
    assert report.ok, report.errors


def test_check_fails_on_a_corrupted_variant(state_dir):
    from deepthought.check import run_check

    store = FileStore(state_dir)
    _seed_source(store)
    _run(store, project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)

    variant = next(
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    )
    # Hand-corrupt the variant into a state that cannot export to valid OSV: a
    # verified finding with no resolving evidence_ref is lifecycle-illegal at rest.
    variant.status = FindingStatus.verified
    variant.evidence_ref = None
    store.save_finding(variant)

    report = run_check(store)
    assert not report.ok
