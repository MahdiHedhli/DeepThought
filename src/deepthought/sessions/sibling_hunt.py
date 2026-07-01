"""SIBLING HUNT session — read-only variant analysis (feature 004).

SIBLING HUNT is the variant-analysis session. It starts from a VERIFIED finding
(a confirmed bug class), derives a runtime variant :class:`Signature` from that
finding's *typed* fields only, and hunts read-only for SIBLING instances of the
same bug class — across the source project's in-scope areas AND across any
pre-authorized sibling project — producing new candidate variant Findings.

It mirrors DISCOVER's shape (a single stub Marvin worker per target that reads
SARIF, writes candidate findings, pages detail, and returns exactly one
:class:`Envelope`; an orchestrator that ingests ONLY the typed envelope through a
:class:`Conductor`), and reuses DISCOVER's firewalls unchanged. Three firewalls
make it safe as a *security* feature:

1. **Input firewall (the signature).** The signature is DERIVED from typed fields
   (:mod:`deepthought.sibling.signature`), never authored from the source
   finding's untrusted free-text body. A hostile source finding can at worst fail
   to yield a signature — the hunt then reports it has no class to look for.

2. **Authority firewall (per-target gate).** Cross-project reach is only ever
   downward through the SAME gate: the source project and each NAMED sibling are
   gated INDEPENDENTLY (``GateContext.from_project`` + the unchanged three-outcome
   gate). A sibling must ALREADY exist in the Store WITH its own
   ``authorization_basis`` — no basis refuses, empty scope holds. The session only
   ever *loads* projects (``get_project``); it NEVER calls ``save_project``,
   mutates a ``scope_allowlist``, or sets an ``authorization_basis``. The huntable
   target set is fixed at dispatch and never grows. A named sibling that does not
   resolve is skipped and logged, never created.

3. **Envelope firewall (the worker seam).** The orchestrator ingests only the
   validated, length-capped envelope; hints are inert; ``detail_ref`` is never
   loaded; the coverage delta is re-validated against the orchestrator's own
   authorization so a worker cannot widen scope through the coverage channel.

Plus a **same-class filter**: a sibling instance is kept only when its derived
capability equals the signature's capability — that is what makes this variant
analysis rather than a second DISCOVER. Out-of-scope instances are dropped by the
reused ``scope``/``root`` containment BEFORE the class filter.

SIBLING HUNT is READ-ONLY (Constitution Article III sequencing, exactly as 002):
it executes nothing, opens no socket, requires no Docker, and transmits nothing.
Variants enter status ``candidate``; only a later sandboxed VERIFY (003) promotes
any of them on evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..ingest.sarif import (
    SarifError,
    load_sarif,
    sarif_to_findings,
    sarif_to_primitives,
)
from ..orchestrator import Conductor
from ..protocol.gate import DefaultGate, GateContext
from ..protocol.session import BaseSession, SessionOutcome
from ..schema import (
    Coverage,
    CoverageDepth,
    CoverageMethod,
    Envelope,
    FindingStatus,
    Project,
    SessionType,
)
from ..schema.envelope import Primitive
from ..sibling.signature import Signature, signature_from_finding
from ..store import NotFoundError, Store
from .discover import (
    _ATTESTATION_REF_MAX,
    _COVERAGE_AREA_MAX,
    _attestation_ref,
    _coverage_areas,
    _next_finding_index,
    _resolve_checkout,
)

_ENVELOPE_VERSION = "1.0"
_WORKER_ID = "marvin-sibling-hunt"

# The gate the session uses to re-gate each NAMED sibling target independently.
# It is the same three-outcome DefaultGate the harness runs the source through
# (HermesUltraCode delegates to it); re-gating siblings here keeps every target's
# authorization decision on the identical contract. It is never used to widen
# authority — only to REFUSE/HOLD a sibling that does not pass its own gate.
_SIBLING_GATE = DefaultGate()


@dataclass
class TargetOutcome:
    """The per-target result of the hunt, recorded for the session summary.

    One of these per target in the fixed target list. A non-proceed target has
    ``proceeded=False``, no envelope, and empty findings/coverage — it produced
    no records at all.
    """

    project_id: str
    gate_outcome: str
    proceeded: bool
    reason: str | None = None
    findings: list[str] = field(default_factory=list)
    coverage: list[str] = field(default_factory=list)


def _source_primitives(finding, signature: Signature | None) -> list[Primitive]:
    """Reconstruct the source finding's suspected primitive from typed fields.

    The source finding's primitive is not a persisted record; it is re-derived
    here from the finding's own SARIF-derived signal via the SAME closed lookup
    the signature uses. This is used only to describe the source class in the
    paged detail — never to widen authority. Returns at most one primitive.
    """
    if signature is None:
        return []
    return [
        Primitive(
            kind=signature.capability,
            target_locus=(signature.locus_pattern or finding.id)[:256],
            preconditions=[],
            grants=[signature.capability],
            confidence="suspected",
            finding_ref=finding.id[:128],
        )
    ]


def _same_class(
    findings: list, primitives: list[Primitive], capability: str
) -> tuple[list, list[Primitive]]:
    """Keep only the sibling instances whose capability matches the signature.

    A variant is a sibling of the source class only when its derived capability
    equals the signature's ``capability``. An instance mapping to a different
    capability (or to none) is dropped — this is the same-class filter that makes
    the hunt variant analysis rather than a second DISCOVER. Findings are kept
    only when a same-class primitive binds to them.
    """
    kept_finding_ids = {p.finding_ref for p in primitives if p.kind == capability}
    kept_findings = [f for f in findings if f.id in kept_finding_ids]
    kept_primitives = [
        p for p in primitives if p.kind == capability and p.finding_ref in kept_finding_ids
    ]
    return kept_findings, kept_primitives


def _run_marvin_worker(
    store: Store,
    session_id: str,
    target: Project,
    signature: Signature,
    sarif_path: str | None,
    root: Path | None,
    id_start: int,
) -> tuple[Envelope | dict, int]:
    """One stub Marvin per target. Reads SARIF, keeps same-class in-scope
    siblings, writes variant findings, pages detail, returns ONE envelope.

    Returns ``(envelope, next_id_start)`` so the orchestrator can allocate fresh,
    non-colliding finding ids across multiple targets in one hunt. All variant
    detail is paged to the Store; nothing is inlined into the return value beyond
    the typed envelope. The worker mutates the Store only AFTER the envelope
    validates, so an over-cap field can never strand persisted findings.
    """
    contained_scope = _coverage_areas(target, root)
    findings: list = []
    primitives: list[Primitive] = []
    detail_name = "sibling-hunt.txt"

    if sarif_path:
        try:
            sarif = load_sarif(sarif_path)
        except SarifError as exc:
            detail_ref = store.write_detail(
                session_id,
                f"{target.id}-{detail_name}",
                f"SIBLING HUNT worker for {target.id}: SARIF load failed: {exc}\n",
            )
            return (
                Envelope(
                    envelope_version=_ENVELOPE_VERSION,
                    session_ref=session_id,
                    worker_id=_WORKER_ID,
                    task_ref=f"hunt {signature.capability} siblings in {target.id}"[:512],
                    outcome="blocked",
                    primitives=[],
                    findings_written=[],
                    coverage_delta=[],
                    next_step_hints=[],
                    detail_ref=detail_ref,
                    gate_attestation={
                        "scope_ok": True,
                        "authorization_ref": _attestation_ref(target),
                    },
                ),
                id_start,
            )

        # Reuse the DISCOVER/SARIF path with the TARGET's own scope/root
        # containment: out-of-scope (or traversal/symlink) instances are dropped
        # before anything else. Then apply the SAME-CLASS filter so only siblings
        # of the signature's capability survive.
        raw_findings = sarif_to_findings(
            sarif, project=target.id, id_start=id_start, scope=contained_scope, root=root
        )
        raw_primitives = sarif_to_primitives(
            sarif,
            finding_ids=[f.id for f in raw_findings],
            scope=contained_scope,
            root=root,
        )
        findings, primitives = _same_class(
            raw_findings, raw_primitives, signature.capability
        )

    next_id_start = id_start + len(findings)
    outcome = "resolved" if findings else "empty"
    detail_ref = f"detail/{session_id}/{target.id}-{detail_name}"

    envelope = Envelope(
        envelope_version=_ENVELOPE_VERSION,
        session_ref=session_id,
        worker_id=_WORKER_ID,
        task_ref=f"hunt {signature.capability} siblings in {target.id}"[:512],
        outcome=outcome,
        primitives=primitives,
        findings_written=[f.id for f in findings],
        coverage_delta=(
            [
                {"area": area, "method": "read", "depth": "touched"}
                for area in contained_scope
                if len(area) <= _COVERAGE_AREA_MAX
            ]
            if sarif_path and findings
            else []
        ),
        next_step_hints=_hints(signature, findings),
        detail_ref=detail_ref,
        gate_attestation={
            "scope_ok": True,
            "authorization_ref": _attestation_ref(target),
        },
    )

    # The envelope validated. Only NOW mutate the Store.
    for finding in findings:
        store.save_finding(finding)
    store.write_detail(
        session_id,
        f"{target.id}-{detail_name}",
        _detail_body(target, signature, sarif_path, findings, primitives),
    )
    return envelope, next_id_start


def _hints(signature: Signature, findings: list) -> list[str]:
    if not findings:
        return []
    return [
        f"{len(findings)} {signature.capability} variant(s) found as siblings of "
        f"{signature.source_finding}; queue VERIFY for each behind the sandbox."[:280]
    ]


def _detail_body(
    target: Project,
    signature: Signature,
    sarif_path: str | None,
    findings: list,
    primitives: list[Primitive],
) -> str:
    lines = [
        f"# SIBLING HUNT worker detail for {target.id}",
        "",
        f"Signature capability: {signature.capability}",
        f"Source finding: {signature.source_finding} (project {signature.source_project})",
        f"SARIF: {sarif_path or '(none)'}",
        "",
        "## Same-class variant findings",
    ]
    for finding in findings:
        lines.append(f"- {finding.id}: {finding.summary}")
    lines.append("")
    lines.append("## Suspected sibling primitives")
    for prim in primitives:
        lines.append(f"- {prim.kind} @ {prim.target_locus} -> {prim.finding_ref}")
    lines.append("")
    return "\n".join(lines)


class SiblingHuntSession(BaseSession):
    """Hunt read-only for same-class variants of a verified finding.

    Expose ``self.signature`` (the derived variant signature, or ``None``),
    ``self.conductor`` (the single ingest channel, shared across targets),
    ``self.envelopes`` (the validated envelopes it consumed), and
    ``self.target_outcomes`` (the per-target gate/finding result) after
    :meth:`run` for inspection.
    """

    type = SessionType.sibling_hunt

    def __init__(
        self,
        project_id: str,
        finding_id: str,
        sibling_project_ids: list[str] | None = None,
        sarif_path: str | None = None,
        root: str | None = None,
    ) -> None:
        self.project_id = project_id
        self.finding_id = finding_id
        # NAMED, pre-registered sibling projects to also hunt. Deduped; the source
        # is never double-hunted. This list is the ONLY cross-project reach, and
        # every entry must already exist in the Store with its own gate.
        self.sibling_project_ids = list(dict.fromkeys(sibling_project_ids or []))
        self.sarif_path = sarif_path
        self.root = root
        # Exposed after run().
        self.signature: Signature | None = None
        self.conductor: Conductor | None = None
        self.envelopes: list[Envelope] = []
        self.target_outcomes: list[TargetOutcome] = []

    # --- gate context (the SOURCE project's gate) --------------------------

    def _project(self, store: Store) -> Project:
        project = store.get_project(self.project_id)
        if project is None:
            raise NotFoundError(f"project {self.project_id!r} not found")
        return project

    def build_gate_context(self, store: Store) -> GateContext:
        # The harness gates the SOURCE project. Each named sibling is re-gated
        # INDEPENDENTLY inside run() with its own GateContext.from_project.
        return GateContext.from_project(self._project(store), self.type)

    # --- scoped work -------------------------------------------------------

    def run(self, store: Store, session_id: str) -> SessionOutcome:
        source_project = self._project(store)

        # --- validate the source finding (refuse before any worker) ---
        finding = store.get_finding(self.finding_id)
        if finding is None:
            return self._refuse(
                f"source finding {self.finding_id!r} not found",
                "Provide the id of a VERIFIED finding in this project to hunt from.",
            )
        if finding.project != self.project_id:
            return self._refuse(
                f"finding {finding.id!r} belongs to {finding.project!r}, not "
                f"{self.project_id!r}",
                f"Run SIBLING HUNT under the finding's own project ({finding.project!r}).",
            )
        if finding.status is not FindingStatus.verified:
            return self._refuse(
                f"finding {finding.id!r} is {finding.status.value!r}, not verified",
                "SIBLING HUNT hunts only from a VERIFIED finding. VERIFY it first "
                "(behind the sandbox), then hunt its siblings.",
            )

        # --- derive the variant signature from TYPED fields only ---
        signature = signature_from_finding(finding, _source_primitives(finding, None))
        if signature is None:
            # No class could be derived from typed fields. The hunt never invents
            # a capability; it stops cleanly.
            return self._refuse(
                f"no variant class could be derived from {finding.id!r}'s typed fields",
                "The verified finding maps to no known capability via the closed "
                "lookup, so there is no bug class to hunt. Re-derive after binding "
                "a primitive to the finding, or hunt from a different finding.",
            )
        self.signature = signature

        # --- fix the target list at dispatch: source + named siblings ---
        # The set of huntable targets is fixed here and NEVER grows. Each named
        # sibling must already exist in the Store; an unknown sibling is skipped
        # and logged, never created.
        conductor = Conductor()
        self.conductor = conductor
        id_start = _next_finding_index(store)

        # 1) the source project (already gated by the harness -> proceed).
        id_start = self._hunt_target(
            store, session_id, source_project, signature, id_start, gated=True
        )

        # 2) each named sibling, gated INDEPENDENTLY at its own gate.
        for sibling_id in self.sibling_project_ids:
            if sibling_id == self.project_id:
                continue  # never double-hunt the source
            sibling = store.get_project(sibling_id)
            if sibling is None:
                # Named but not registered: SKIP and log. Never create a project.
                self.target_outcomes.append(
                    TargetOutcome(
                        project_id=sibling_id,
                        gate_outcome="skipped",
                        proceeded=False,
                        reason="sibling project not registered in the Store; skipped "
                        "(SIBLING HUNT never creates a project)",
                    )
                )
                continue
            id_start = self._hunt_sibling(
                store, session_id, sibling, signature, id_start
            )

        return self._teach_back(source_project, signature)

    # --- per-target hunt ---------------------------------------------------

    def _hunt_sibling(
        self,
        store: Store,
        session_id: str,
        sibling: Project,
        signature: Signature,
        id_start: int,
    ) -> int:
        """Gate a NAMED sibling INDEPENDENTLY, then hunt only on proceed.

        The sibling is gated with its OWN ``GateContext.from_project`` through the
        same three-outcome gate: no basis -> refuse, empty scope -> hold. A
        non-proceed sibling produces NO worker, NO findings, and NO coverage — it
        is recorded in the outcome and nothing is written for it.
        """
        decision = _SIBLING_GATE.evaluate(
            GateContext.from_project(sibling, self.type)
        )
        if not decision.proceeds:
            self.target_outcomes.append(
                TargetOutcome(
                    project_id=sibling.id,
                    gate_outcome=decision.outcome.value,
                    proceeded=False,
                    reason=decision.reason,
                )
            )
            return id_start
        return self._hunt_target(
            store, session_id, sibling, signature, id_start, gated=True
        )

    def _hunt_target(
        self,
        store: Store,
        session_id: str,
        target: Project,
        signature: Signature,
        id_start: int,
        *,
        gated: bool,
    ) -> int:
        """Dispatch one worker for a gated-proceed target and ingest its envelope.

        Binds the variant findings and read coverage to the TARGET project. The
        orchestrator ingests only the typed envelope through the shared Conductor
        and re-validates the coverage delta against the target's own contained
        scope — a worker cannot widen scope through the coverage channel.
        """
        assert gated  # only ever called for a proceed-at-gate target
        root = _resolve_checkout(self.root or target.local_path)
        envelope, next_id_start = _run_marvin_worker(
            store, session_id, target, signature, self.sarif_path, root, id_start
        )

        result = self.conductor.ingest(envelope)
        if not result.ok:
            # A rejected envelope updates no ledger and writes no coverage.
            self.target_outcomes.append(
                TargetOutcome(
                    project_id=target.id,
                    gate_outcome="proceed",
                    proceeded=True,
                    reason=f"worker envelope rejected at ingest ({result.reason})",
                )
            )
            return id_start  # no ids consumed if nothing was written

        validated = result.envelope
        self.envelopes.append(validated)
        coverage_refs = self._write_read_coverage(
            store, target, session_id, validated, root
        )
        self.target_outcomes.append(
            TargetOutcome(
                project_id=target.id,
                gate_outcome="proceed",
                proceeded=True,
                reason=validated.outcome.value,
                findings=list(validated.findings_written),
                coverage=coverage_refs,
            )
        )
        return next_id_start

    @staticmethod
    def _write_read_coverage(
        store: Store,
        target: Project,
        session_id: str,
        envelope: Envelope,
        root: Path | None,
    ) -> list[str]:
        """Persist coverage from the validated envelope, RE-VALIDATED against the
        TARGET's own authorization (the same firewall DISCOVER applies).

        Each delta is kept only if its area is in the target's contained scope AND
        its method is ``read`` AND its depth is legal — so a worker cannot record
        coverage for an out-of-scope area or a non-read method through the
        coverage channel. Coverage is bound to the target project.
        """
        allowed_areas = set(_coverage_areas(target, root))
        legal_depths = {d.value for d in CoverageDepth}
        refs: list[str] = []
        for delta in envelope.coverage_delta:
            if (
                delta.area not in allowed_areas
                or delta.method != CoverageMethod.read.value
                or delta.depth not in legal_depths
            ):
                continue
            coverage = Coverage(
                project=target.id,
                area=delta.area,
                method=CoverageMethod(delta.method),
                depth=CoverageDepth(delta.depth),
                last_session=session_id,
                body=(
                    f"Read-only SIBLING HUNT over `{delta.area}` for variants of "
                    f"the verified bug class. Nothing executed."
                ),
            )
            store.save_coverage(coverage)
            refs.append(coverage.ref)
        return refs

    # --- teach back / refuse ----------------------------------------------

    def _teach_back(self, source: Project, signature: Signature) -> SessionOutcome:
        proceeded = [t for t in self.target_outcomes if t.proceeded]
        refused = [t for t in self.target_outcomes if not t.proceeded]
        all_findings = [fid for t in proceeded for fid in t.findings]
        all_coverage = [cref for t in proceeded for cref in t.coverage]
        n_variants = len(all_findings)

        parts = [
            f"SIBLING HUNT on {source.id!r} (READ-ONLY): derived a "
            f"{signature.capability!r} variant signature from {signature.source_finding!r} "
            f"and hunted {len(proceeded)} authorized target(s). Found {n_variants} "
            f"same-class variant candidate(s); recorded read coverage for "
            f"{len(all_coverage)} in-scope area(s). "
            f"{len(self.conductor.ledger)} sibling primitive(s) now in the ledger. "
            f"No code executed; scope unchanged."
        ]
        if refused:
            gated_off = ", ".join(
                f"{t.project_id} ({t.gate_outcome})" for t in refused
            )
            parts.append(
                f"Did NOT hunt (no records written): {gated_off}. No project was "
                f"created and no scope was widened."
            )
        summary = " ".join(parts)

        if n_variants:
            next_steps = (
                f"{n_variants} same-class variant candidate(s) recorded. Queue a "
                f"VERIFY session for each behind the egress-controlled sandbox "
                f"(feature 003) to promote them on evidence; nothing executes until "
                f"then."
            )
        else:
            next_steps = (
                f"No same-class variants surfaced for the {signature.capability!r} "
                f"signature. Provide tool SARIF over the authorized targets' in-scope "
                f"areas and re-run SIBLING HUNT, or hunt from a different verified "
                f"finding."
            )
        return SessionOutcome(
            summary=summary,
            next_steps=next_steps,
            findings_touched=all_findings,
            coverage_changed=all_coverage,
        )

    def _refuse(self, reason: str, next_steps: str) -> SessionOutcome:
        """Close clean with no worker, no findings, no coverage.

        A refusal inside the (already gate-proceeded) source hunt — the source
        finding is missing, belongs to another project, is not verified, or yields
        no signature. Nothing is dispatched and no record is written.
        """
        return SessionOutcome(
            summary=(
                f"SIBLING HUNT on {self.project_id!r} (READ-ONLY): refused — {reason}. "
                f"No worker dispatched, no variant written, scope unchanged."
            ),
            next_steps=next_steps,
        )
