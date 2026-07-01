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

1. **Input firewall (the signature).** The session derives capability from the
   finding's TYPED summary via the closed lookup (:mod:`deepthought.sibling.signature`),
   never authored from the source finding's untrusted free-text body. Primitives
   are not persisted across sessions, so the bound-primitive path — still supported
   by ``signature_from_finding`` for direct callers/tests — is not exercised by the
   session. A hostile source finding can at worst fail to yield a signature — the
   hunt then reports it has no class to look for.

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
# FALLBACK gate for gating siblings only when the session is run OUTSIDE the
# harness (``harness_gate`` unset). Inside a normal ``run_session`` the sibling is
# gated with ``self.harness_gate`` — the SAME gate the harness applied to the
# source — so a stricter deployment gate governs every sibling. It is never used to
# widen authority, only to REFUSE/HOLD a sibling that does not pass its own gate.
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
    session_id: str,
    target: Project,
    signature: Signature,
    sarif_path: str | None,
    root: Path | None,
    id_start: int,
) -> tuple[Envelope | dict, list, str]:
    """One stub Marvin per target. Reads SARIF, keeps same-class in-scope
    siblings, and BUILDS (without persisting) the variant findings, one typed
    envelope, and the paged detail body.

    Returns ``(envelope, findings, detail_body)``. The worker PERSISTS NOTHING:
    the orchestrator writes the findings and the detail to the Store only AFTER
    the envelope passes ``Conductor.ingest`` (mutate-only-on-accept), so a rejected
    envelope strands nothing in the Store. Finding ids are allocated from
    ``id_start`` (the orchestrator computes it fresh from persisted Store state per
    target); because a rejected target persists no findings, the ids it would have
    used stay free for the next target with no reuse or overwrite. Nothing is
    inlined into orchestrator state beyond the typed envelope.
    """
    contained_scope = _coverage_areas(target, root)
    findings: list = []
    primitives: list[Primitive] = []
    detail_name = "sibling-hunt.txt"
    detail_ref = f"detail/{session_id}/{target.id}-{detail_name}"

    if sarif_path:
        try:
            sarif = load_sarif(sarif_path)
        except SarifError as exc:
            blocked = Envelope(
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
            )
            return (
                blocked,
                [],
                f"SIBLING HUNT worker for {target.id}: SARIF load failed: {exc}\n",
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

    outcome = "resolved" if findings else "empty"

    envelope = Envelope(
        envelope_version=_ENVELOPE_VERSION,
        session_ref=session_id,
        worker_id=_WORKER_ID,
        task_ref=f"hunt {signature.capability} siblings in {target.id}"[:512],
        outcome=outcome,
        primitives=primitives,
        findings_written=[f.id for f in findings],
        # A target SCANNED with SARIF attests read coverage for its in-scope
        # areas even when zero same-class variants survive the filter — a scanned
        # empty target is still read coverage (mirroring DISCOVER's `if sarif_path`
        # gate). The orchestrator re-validates each delta against the target's own
        # scope, so this cannot widen authority.
        coverage_delta=(
            [
                {"area": area, "method": "read", "depth": "touched"}
                for area in contained_scope
                if len(area) <= _COVERAGE_AREA_MAX
            ]
            if sarif_path
            else []
        ),
        next_step_hints=_hints(signature, findings),
        detail_ref=detail_ref,
        gate_attestation={
            "scope_ok": True,
            "authorization_ref": _attestation_ref(target),
        },
    )
    detail_body = _detail_body(target, signature, sarif_path, findings, primitives)
    return envelope, findings, detail_body


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

        # --- derive the variant signature from the finding's TYPED summary ---
        # The session derives capability from the finding's typed summary via the
        # closed lookup (the same one DISCOVER uses). Primitives are not persisted
        # across sessions, so the session passes none; the bound-primitive path in
        # signature_from_finding stays supported for direct callers/tests but is
        # not exercised here.
        signature = signature_from_finding(finding)
        if signature is None:
            # No class could be derived from the typed summary. The hunt never
            # invents a capability; it stops cleanly.
            return self._refuse(
                f"no variant class could be derived from {finding.id!r}'s typed fields",
                "The verified finding maps to no known capability via the closed "
                "lookup over its typed summary, so there is no bug class to hunt. "
                "Hunt from a different verified finding whose summary maps to a "
                "known capability.",
            )
        self.signature = signature

        # --- fix the target list at dispatch: source + named siblings ---
        # The set of huntable targets is fixed here and NEVER grows. Each named
        # sibling must already exist in the Store; an unknown sibling is skipped
        # and logged, never created.
        conductor = Conductor()
        self.conductor = conductor

        # 1) the source project (already gated by the harness -> proceed). Only the
        #    source uses the CLI --root; siblings resolve against their own path.
        self._hunt_target(
            store, session_id, source_project, signature, gated=True, is_source=True
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
            self._hunt_sibling(store, session_id, sibling, signature)

        return self._teach_back(source_project, signature)

    # --- per-target hunt ---------------------------------------------------

    def _hunt_sibling(
        self,
        store: Store,
        session_id: str,
        sibling: Project,
        signature: Signature,
    ) -> None:
        """Gate a NAMED sibling INDEPENDENTLY, then hunt only on proceed.

        The sibling is gated with its OWN ``GateContext.from_project`` through the
        SAME gate the harness applied to the source (``self.harness_gate``, injected
        by ``run_session``) — so a stricter deployment gate governs every sibling,
        never a hardcoded default. Same three outcomes: no basis -> refuse, empty
        scope -> hold. A non-proceed sibling produces NO worker, NO findings, and NO
        coverage — it is recorded in the outcome and nothing is written for it.
        """
        gate = self.harness_gate or _SIBLING_GATE
        decision = gate.evaluate(GateContext.from_project(sibling, self.type))
        if not decision.proceeds:
            self.target_outcomes.append(
                TargetOutcome(
                    project_id=sibling.id,
                    gate_outcome=decision.outcome.value,
                    proceeded=False,
                    reason=decision.reason,
                )
            )
            return
        self._hunt_target(
            store, session_id, sibling, signature, gated=True, is_source=False
        )

    def _hunt_target(
        self,
        store: Store,
        session_id: str,
        target: Project,
        signature: Signature,
        *,
        gated: bool,
        is_source: bool,
    ) -> None:
        """Dispatch one worker for a gated-proceed target and ingest its envelope.

        Binds the variant findings and read coverage to the TARGET project. The
        orchestrator ingests only the typed envelope through the shared Conductor
        and re-validates the coverage delta against the target's own contained
        scope — a worker cannot widen scope through the coverage channel.

        The CLI ``--root`` applies ONLY to the source project (``is_source``); a
        named sibling always resolves its SARIF/coverage against its OWN
        ``local_path``, never the source's checkout root.
        """
        assert gated  # only ever called for a proceed-at-gate target
        try:
            # ALL fallible per-target work is inside this guard so one target's
            # failure (a bad checkout path -> OSError, a Store read error, or an
            # over-cap field the Envelope rejects -> ValidationError) is isolated
            # to that target and never aborts the whole multi-target hunt. --root
            # applies to the source only; a named sibling uses its own local_path.
            root = _resolve_checkout(
                (self.root if is_source else None) or target.local_path
            )
            # Allocate finding ids authoritatively from persisted Store state,
            # re-read per target. A rejected target persists nothing (below), so its
            # ids stay free and are never reused or overwritten across targets.
            id_start = _next_finding_index(store)
            envelope, findings, detail_body = _run_marvin_worker(
                session_id, target, signature, self.sarif_path, root, id_start
            )
        except Exception as exc:
            # PER-TARGET ISOLATION (broad by design): ANY failure processing one
            # target — a bad checkout path, a Store read error, an over-cap field
            # the Envelope rejects, etc. — is contained to that target and never
            # aborts the multi-target hunt. It is recorded and surfaced distinctly
            # in the teach-back (never silently swallowed). BaseException
            # (KeyboardInterrupt/SystemExit) still propagates.
            self.target_outcomes.append(
                TargetOutcome(
                    project_id=target.id,
                    gate_outcome="proceed",
                    proceeded=True,
                    reason=f"worker failed for {target.id}: {type(exc).__name__}",
                )
            )
            return

        result = self.conductor.ingest(envelope)
        if not result.ok:
            # MUTATE-ONLY-ON-ACCEPT. The worker persisted nothing; a rejected
            # envelope therefore strands NO findings and writes no detail, ledger,
            # or coverage. The ids it would have used stay free for the next target.
            self.target_outcomes.append(
                TargetOutcome(
                    project_id=target.id,
                    gate_outcome="proceed",
                    proceeded=True,
                    reason=f"worker envelope rejected at ingest ({result.reason})",
                )
            )
            return

        validated = result.envelope
        self.envelopes.append(validated)  # ingested into the ledger (in-memory)
        saved_ids: list[str] = []
        try:
            # Accepted: ONLY NOW mutate the Store — persist the variant findings and
            # page the detail, from the worker's built (now validated) output. These
            # writes are ALSO inside the per-target isolation guard: a Store write
            # failure (permission/disk) for THIS target is recorded and surfaced as
            # that target's failure and the hunt continues to the next target — it
            # never aborts the whole session.
            for finding in findings:
                store.save_finding(finding)
                saved_ids.append(finding.id)
            store.write_detail(session_id, f"{target.id}-sibling-hunt.txt", detail_body)
            coverage_refs = self._write_read_coverage(
                store, target, session_id, validated, root
            )
        except Exception as exc:
            # A write failure mid-batch may have already persisted SOME variants.
            # Report EXACTLY those (findings=saved_ids) so the session log matches
            # Store state — no persisted variant is left unreported — and surface the
            # partial failure distinctly. The hunt continues to the next target.
            self.target_outcomes.append(
                TargetOutcome(
                    project_id=target.id,
                    gate_outcome="proceed",
                    proceeded=True,
                    reason=(
                        f"worker failed for {target.id}: {type(exc).__name__} "
                        f"(store write); {len(saved_ids)} variant(s) persisted before "
                        f"the failure"
                    ),
                    findings=saved_ids,
                )
            )
            return
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
        # A proceed-at-gate target that did NOT complete cleanly — its worker was
        # BLOCKED (e.g. its SARIF failed to load) or FAILED (an isolated per-target
        # error caught by _hunt_target) — is not a clean empty run. Anything whose
        # recorded reason is not the clean "resolved"/"empty" envelope outcome is
        # surfaced distinctly so the operator never reads a block/failure as "no
        # variants found".
        blocked = [t for t in proceeded if t.reason not in ("resolved", "empty")]

        parts = [
            f"SIBLING HUNT on {source.id!r} (READ-ONLY): derived a "
            f"{signature.capability!r} variant signature from {signature.source_finding!r} "
            f"and hunted {len(proceeded)} authorized target(s). Found {n_variants} "
            f"same-class variant candidate(s); recorded read coverage for "
            f"{len(all_coverage)} in-scope area(s). "
            f"{len(self.conductor.ledger)} sibling primitive(s) now in the ledger. "
            f"No code executed; scope unchanged."
        ]
        if blocked:
            blocked_ids = ", ".join(
                f"{t.project_id} ({t.reason})" for t in blocked
            )
            parts.append(
                f"BLOCKED/FAILED target(s) (no findings or coverage recorded): "
                f"{blocked_ids} — the worker could not read its input (e.g. a "
                f"malformed or unreadable SARIF) or hit an isolated per-target error. "
                f"See the paged detail / reason; other targets were unaffected."
            )
        if refused:
            gated_off = ", ".join(
                f"{t.project_id} ({t.gate_outcome})" for t in refused
            )
            parts.append(
                f"Did NOT hunt (no records written): {gated_off}. No project was "
                f"created and no scope was widened."
            )
        summary = " ".join(parts)

        if blocked and not n_variants:
            # SARIF was supplied but a target's worker was blocked/failed — point at
            # the paged detail / reason, not at "provide SARIF".
            next_steps = (
                f"A SIBLING HUNT worker was BLOCKED or FAILED for a target. Inspect "
                f"the recorded reason and the paged detail "
                f"(detail/<session>/<target>-sibling-hunt.txt in the state store) — "
                f"e.g. a malformed/unreadable SARIF or an isolated per-target error — "
                f"fix it, and re-run SIBLING HUNT on {source.id!r}."
            )
        elif n_variants:
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
