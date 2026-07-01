"""DISCOVER session — reason over code and SARIF for candidates, READ-ONLY (002).

DISCOVER is the second half of the Improbability Drive's reasoning. Where MAP
records *what surface exists*, DISCOVER reasons over that surface (and any tool
SARIF) to propose *candidate findings* and the *suspected primitives* they
grant. It is strictly read-only per the constitution's feature-002 sequencing:
it executes nothing, imports no target code, opens no socket, and widens no
scope. A SARIF file is parsed as data only (see ``ingest.sarif``).

The session is the orchestrator-plus-worker topology in miniature, and that
topology is the point of this slice:

* **The worker (a Marvin).** :func:`_run_marvin_worker` is a local function
  standing in for a Codex worker. It reads the SARIF, maps it to candidate
  Findings and suspected Primitives, WRITES the findings to the Store, pages its
  full working detail to ``state/detail/<session>/discover.txt`` via
  ``store.write_detail``, and returns exactly one :class:`Envelope`. Everything
  the worker "reasoned" lives either in a Store record or in the paged detail
  file — never in the value it hands back except as the typed envelope.

* **The orchestrator (:meth:`DiscoverSession.run`).** It dispatches the one
  worker and then ingests ONLY the returned envelope, through a
  :class:`Conductor`. It never reads the worker's free-text and never loads the
  detail file into its own state. The Ledger, fed only by the ingested envelope,
  ends up holding the discovered primitives. This is the injection firewall
  (Constitution VIII) applied to a real session: the worker seam admits an
  untyped ``dict`` (what a real out-of-process worker returns), and the Conductor
  is the one door that validates it — a malformed or prompt-injected payload is
  rejected at ingest, touches no ledger, and writes no coverage.

Then, having ingested the envelope, the orchestrator teaches back: it records
``Coverage(method='read')`` for each in-scope area it reasoned over (FR-6 —
DISCOVER writes findings *and* coverage), and returns the findings and coverage
it touched so the harness can close the session.

The findings the worker writes are candidates carrying no evidence, so they pass
the Store's lifecycle-at-rest guard and export to conformant OSV by construction
(``ingest.sarif`` guarantees this). VERIFY (feature 003), behind the sandbox, is
what later promotes any of them on evidence.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..ingest.sarif import (
    SarifError,
    load_sarif,
    sarif_to_findings,
    sarif_to_primitives,
)
from ..orchestrator import Conductor
from ..protocol.gate import GateContext
from ..protocol.session import BaseSession, SessionOutcome
from ..scope import area_in_scope
from ..schema import (
    Coverage,
    CoverageDepth,
    CoverageMethod,
    Envelope,
    Project,
    SessionType,
)
from ..store import NotFoundError, Store

# The worker's envelope version and stub id. The orchestrator reads these off the
# typed envelope; they are not load-bearing beyond identifying the worker plane.
_ENVELOPE_VERSION = "1.0"
_WORKER_ID = "marvin-discover"

# The envelope's CoverageDelta.area is a length-capped Short field. Scope
# allowlist entries are uncapped, so an over-long area is omitted from the
# envelope delta (the full Coverage record is still written to the Store).
_COVERAGE_AREA_MAX = 128

# The envelope's gate_attestation.authorization_ref is a length-capped Ref (256).
# Truncate the project's ref to that cap when attesting, so a long engagement
# reference can never fail envelope construction.
_ATTESTATION_REF_MAX = 256


def _attestation_ref(project: Project) -> str:
    ref = project.authorization_ref or (
        project.authorization_basis.value if project.authorization_basis else "none"
    )
    return ref[:_ATTESTATION_REF_MAX]


def _resolve_checkout(candidate: str | None) -> Path | None:
    """A checkout root to containment-check scope areas against, or None."""
    if not candidate:
        return None
    path = Path(candidate)
    return path if path.is_dir() else None


def _coverage_areas(project: Project, root: Path | None) -> list[str]:
    """Deduped, stripped, non-blank, in-scope areas DISCOVER may record."""
    areas: list[str] = []
    for area in dict.fromkeys(a.strip() for a in project.scope_allowlist):
        if area and area_in_scope(area, root):
            areas.append(area)
    return areas

_FINDING_ID = re.compile(r"^F-(\d+)$")


def _next_finding_index(store: Store) -> int:
    """The next free ``F-NNNN`` index across the whole store.

    A repeat DISCOVER must not collide finding ids with a prior run (which would
    overwrite or orphan earlier findings). Ids are assigned past the current max.
    """
    highest = 0
    for finding in store.list_findings():
        match = _FINDING_ID.match(finding.id)
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


def _run_marvin_worker(
    store: Store,
    session_id: str,
    project: Project,
    sarif_path: str | None,
    root: Path | None,
) -> Envelope | dict:
    """The stub Marvin worker. Reads SARIF, writes candidate findings, pages
    detail, and returns exactly one envelope.

    Standing in for a Codex worker: it does the deep, narrow work in its own
    context and hands back only the envelope. All of its detail is paged to the
    Store; none of it is inlined into the return value beyond the envelope.

    The return type is ``Envelope | dict`` on purpose: the real pooled worker
    runs out of process and hands back an *untyped* payload (a dict) that the
    orchestrator must re-validate at ingest. This in-repo stub returns a typed
    :class:`Envelope`, but the seam admits the dict so the orchestrator's
    rejection path is a real, exercised boundary — not dead code. The Conductor
    is the one door that turns either form into ingested (or rejected) state.
    """
    findings = []
    primitives = []
    sarif_note = "no SARIF provided; nothing to reason over"
    # Compute the root-aware contained scope once; reused for the SARIF filter
    # and the coverage_delta so the two agree and we resolve paths only once.
    contained_scope = _coverage_areas(project, root)

    if sarif_path:
        try:
            sarif = load_sarif(sarif_path)
        except SarifError as exc:
            # A malformed SARIF is a blocked worker, not a crashed orchestrator.
            # It writes nothing and reports the block through the envelope.
            detail_ref = store.write_detail(
                session_id,
                "discover.txt",
                f"DISCOVER worker for {project.id}: SARIF load failed: {exc}\n",
            )
            return Envelope(
                envelope_version=_ENVELOPE_VERSION,
                session_ref=session_id,
                worker_id=_WORKER_ID,
                task_ref=f"discover candidates for {project.id} from SARIF",
                outcome="blocked",
                primitives=[],
                findings_written=[],
                coverage_delta=[],
                next_step_hints=[],
                detail_ref=detail_ref,
                gate_attestation={
                    "scope_ok": True,
                    "authorization_ref": _attestation_ref(project),
                },
            )

        id_start = _next_finding_index(store)
        # Filter SARIF results to the project's CONTAINED scope (computed above) —
        # the same root-aware set coverage uses. An area that escapes the root
        # (e.g. a symlink resolving outside it) is refused for findings exactly as
        # for coverage: DISCOVER never reports a path outside the target tree.
        findings = sarif_to_findings(
            sarif, project=project.id, id_start=id_start, scope=contained_scope, root=root
        )
        primitives = sarif_to_primitives(
            sarif,
            finding_ids=[f.id for f in findings],
            scope=contained_scope,
            root=root,
        )
        sarif_note = (
            f"parsed SARIF {sarif_path!r}: {len(findings)} candidate finding(s), "
            f"{len(primitives)} suspected primitive(s)"
        )

    outcome = "resolved" if findings else "empty"
    # The detail ref is deterministic; compute it now but do NOT write yet. The
    # Store is mutated only AFTER the Envelope validates, so an unvalidated worker
    # result (e.g. an over-cap field) can never strand persisted findings.
    detail_ref = f"detail/{session_id}/discover.txt"

    envelope = Envelope(
        envelope_version=_ENVELOPE_VERSION,
        session_ref=session_id,
        worker_id=_WORKER_ID,
        task_ref=f"discover candidates for {project.id} from SARIF",
        outcome=outcome,
        primitives=primitives,
        findings_written=[f.id for f in findings],
        # DISCOVER reasoned over the in-scope areas by READING static signals and
        # SARIF — it executed nothing. So the honest method is 'read' (data-model:
        # method is CoverageMethod.read for every 002 coverage record), not
        # 'static' (a tooling pass) and never 'fuzz' (needs the sandbox). Depth is
        # 'touched': a static reasoning pass surveyed but did not exhaust the area.
        # The envelope's area field is length-capped; a scope entry longer than
        # the cap is omitted from the delta here (the orchestrator still records
        # the full, uncapped Coverage record for it in _write_read_coverage), so
        # an over-long scope path never fails the whole envelope's validation.
        # Only claim coverage when there was actually a SARIF input to reason
        # over — matching the orchestrator's inputs_read gate, so the envelope
        # delta stays consistent with the Coverage records actually written.
        coverage_delta=(
            [
                {"area": area, "method": "read", "depth": "touched"}
                for area in contained_scope
                if len(area) <= _COVERAGE_AREA_MAX
            ]
            if sarif_path
            else []
        ),
        next_step_hints=_hints(findings, primitives),
        detail_ref=detail_ref,
        gate_attestation={
            "scope_ok": True,
            "authorization_ref": _attestation_ref(project),
        },
    )

    # The envelope validated. Only NOW mutate the Store: persist the candidate
    # findings and page the worker detail. If envelope construction had raised,
    # nothing above would have been written.
    for finding in findings:
        store.save_finding(finding)
    store.write_detail(
        session_id,
        "discover.txt",
        _detail_body(project, sarif_path, findings, primitives, sarif_note),
    )
    return envelope


def _detail_body(
    project: Project,
    sarif_path: str | None,
    findings: list,
    primitives: list,
    note: str,
) -> str:
    lines = [
        f"# DISCOVER worker detail for {project.id}",
        "",
        f"SARIF: {sarif_path or '(none)'}",
        note,
        "",
        "## Candidate findings",
    ]
    for finding in findings:
        lines.append(f"- {finding.id}: {finding.summary}")
    lines.append("")
    lines.append("## Suspected primitives")
    for prim in primitives:
        lines.append(
            f"- {prim.kind} @ {prim.target_locus} ({prim.confidence.value}) "
            f"-> {prim.finding_ref}"
        )
    lines.append("")
    return "\n".join(lines)


def _hints(findings: list, primitives: list) -> list[str]:
    if not findings:
        return []
    # A hint is a suggestion the orchestrator MAY act on; it never acts on its
    # own. Kept short and capped by the envelope schema.
    return [
        f"{len(findings)} candidate finding(s) with {len(primitives)} suspected "
        f"primitive(s); queue VERIFY once the sandbox lands (feature 003)."
    ]


class DiscoverSession(BaseSession):
    type = SessionType.discover

    def __init__(
        self,
        project_id: str,
        sarif_path: str | None = None,
        root: str | None = None,
    ):
        self.project_id = project_id
        self.sarif_path = sarif_path
        # root is accepted for symmetry with MAP (a fresh checkout location for
        # code reasoning). Feature 002's DISCOVER reasons over SARIF; the code
        # walk is the MAP surface it builds on. Kept for a stable signature.
        self.root = root
        # Exposed after run() for inspection: the orchestrator's ingest channel
        # and the single envelope it consumed.
        self.conductor: Conductor | None = None
        self.envelope: Envelope | None = None

    def _project(self, store: Store) -> Project:
        project = store.get_project(self.project_id)
        if project is None:
            raise NotFoundError(f"project {self.project_id!r} not found")
        return project

    def build_gate_context(self, store: Store) -> GateContext:
        return GateContext.from_project(self._project(store), self.type)

    def run(self, store: Store, session_id: str) -> SessionOutcome:
        project = self._project(store)

        # --- orchestrator dispatches ONE worker ---
        # The worker does the reasoning, writes findings, and pages detail. It
        # returns exactly one typed envelope.
        root = _resolve_checkout(self.root or project.local_path)
        envelope = _run_marvin_worker(store, session_id, project, self.sarif_path, root)

        # --- orchestrator ingests ONLY the envelope, through the Conductor ---
        # Never the worker's free-text, never the detail file. The Ledger updates
        # from the envelope's primitives alone. The worker may hand back an
        # untyped dict (the real out-of-process seam); the Conductor is the door
        # that validates it — so the rejection path below is a real boundary.
        conductor = Conductor()
        result = conductor.ingest(envelope)
        self.conductor = conductor
        # Read the VALIDATED envelope back from the Conductor, never the raw
        # payload we handed in. If the worker returned an untyped dict, `envelope`
        # is still a dict here; `result.envelope` is the schema-validated view
        # (None on rejection). This is the firewall: the orchestrator only ever
        # touches typed, validated fields.
        self.envelope = result.envelope

        if not result.ok:
            # A rejected envelope updates no ledger and writes no coverage; the
            # session still closes clean with the block recorded and a
            # remediation next step. Nothing on the raw envelope is trusted here.
            summary = (
                f"DISCOVER on {project.id!r}: worker envelope rejected at ingest "
                f"({result.reason}). Ledger unchanged; no candidates ingested."
            )
            return SessionOutcome(
                summary=summary,
                next_steps=(
                    "Re-run DISCOVER with a well-formed worker envelope; inspect "
                    "the paged detail for the worker's block reason."
                ),
            )

        # Past ingest, ``result.envelope`` is the validated Envelope. Everything
        # the orchestrator teaches back is derived from that typed envelope — not
        # from any worker free-text and not from the raw payload.
        envelope = result.envelope
        n_findings = len(envelope.findings_written)
        n_primitives = len(envelope.primitives)

        # --- teach back coverage (FR-6: DISCOVER writes findings AND coverage) ---
        # Only record read coverage when the worker actually read an input. In
        # 002 DISCOVER reads SARIF; with no SARIF (or a SARIF that failed to
        # load, outcome 'blocked') nothing was surveyed, so recording the areas
        # as read would corrupt the coverage signal operators rely on before
        # VERIFY. Nothing outside the scope allowlist is ever covered.
        # bool(): a blank sarif_path ("" / "--sarif '' ") is no input, matching
        # the worker's `if sarif_path` check — so it records no coverage.
        inputs_read = bool(self.sarif_path) and envelope.outcome.value != "blocked"
        if inputs_read:
            coverage_refs = self._write_read_coverage(store, project, session_id, root)
        else:
            coverage_refs = []

        outcome = envelope.outcome.value
        if outcome == "blocked":
            # A blocked worker (e.g. SARIF failed to load) is NOT an empty success
            # — say so plainly so the operator does not read it as a clean run.
            summary = (
                f"DISCOVER on {project.id!r} (READ-ONLY): worker was BLOCKED — no "
                f"findings or primitives ingested, no coverage recorded. No code "
                f"executed; scope unchanged."
            )
        else:
            primitive_word = "primitive" if n_primitives == 1 else "primitives"
            finding_word = "finding" if n_findings == 1 else "findings"
            summary = (
                f"DISCOVER on {project.id!r} (READ-ONLY): worker returned "
                f"{n_findings} candidate {finding_word} and {n_primitives} suspected "
                f"{primitive_word}. Ingested the envelope only; {len(conductor.ledger)} "
                f"primitive(s) now in the ledger; recorded read coverage for "
                f"{len(coverage_refs)} in-scope area(s). No code executed; scope unchanged."
            )

        return SessionOutcome(
            summary=summary,
            next_steps=self._suggest_next(project, n_findings, outcome),
            # findings_touched is exactly what the envelope reported written.
            findings_touched=list(envelope.findings_written),
            coverage_changed=coverage_refs,
        )

    @staticmethod
    def _write_read_coverage(
        store: Store, project: Project, session_id: str, root: Path | None
    ) -> list[str]:
        """Persist Coverage(method='read', depth='touched') for each in-scope area.

        A static reasoning pass surveyed (but did not exhaust) the in-scope
        surface by reading, so ``read``/``touched`` is the honest record. Only
        deduped, non-blank, in-scope areas are covered — a blank or an escaping
        entry (``../secret``, ``/etc``) that MAP would refuse is never recorded,
        so DISCOVER cannot claim an out-of-root area was surveyed.
        """
        refs: list[str] = []
        for area in _coverage_areas(project, root):
            coverage = Coverage(
                project=project.id,
                area=area,
                method=CoverageMethod.read,
                depth=CoverageDepth.touched,
                last_session=session_id,
                body=(
                    f"Read-only DISCOVER reasoning over `{area}`: static signals "
                    f"and SARIF surveyed for candidates. Nothing executed."
                ),
            )
            store.save_coverage(coverage)
            refs.append(coverage.ref)
        return refs

    @staticmethod
    def _suggest_next(project: Project, n_findings: int, outcome: str = "resolved") -> str:
        if outcome == "blocked":
            # SARIF was supplied but failed to load — point at the paged detail
            # for the reason, not at "provide SARIF".
            return (
                f"The DISCOVER worker was blocked. Inspect the paged detail "
                f"(state/detail/<session>/discover.txt) for the block reason (e.g. a "
                f"malformed or unsupported SARIF), fix it, and re-run DISCOVER on "
                f"{project.id!r}."
            )
        if n_findings == 0:
            return (
                f"No candidates surfaced for {project.id!r}. Provide tool SARIF "
                f"over the in-scope areas ({', '.join(project.scope_allowlist) or '(none)'}) "
                f"and re-run DISCOVER."
            )
        return (
            f"{n_findings} candidate finding(s) recorded for {project.id!r}. Queue a "
            f"VERIFY session (feature 003) to promote them on evidence — VERIFY runs "
            f"only behind the egress-controlled sandbox; nothing executes until then."
        )
