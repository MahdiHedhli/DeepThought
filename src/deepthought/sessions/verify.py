"""VERIFY session — promote a candidate on sandboxed evidence (feature 003).

VERIFY is the session that turns a *candidate* finding into a *verified* one, and
it is the first session that would ever run target code — so it is the first
gated by the sandbox (Constitution Article III). In this slice it runs a repro
**only** through an injected :class:`~deepthought.sandbox.Sandbox`, and the
injected sandbox in tests is a ``NoopSandbox`` that executes nothing. No target
code runs, no Docker daemon is required, no network is opened, and no subprocess
is spawned anywhere in this session.

The shape mirrors the orchestrator/worker firewall (Constitution VIII), applied
to execution:

* **The sandbox is the only door to execution.** VERIFY hands a hardened
  :class:`~deepthought.sandbox.SandboxSpec` to ``self.sandbox.run(spec)`` and gets
  back a typed :class:`~deepthought.sandbox.SandboxResult`. There is no
  ``subprocess``, no shell, and no in-process execution of target code here. The
  backing sandbox is **dependency-injected**: a real executing backend is never
  constructed in this file, so this session cannot execute untrusted code even by
  accident — it can only ask whatever ``Sandbox`` it was handed.

* **The ``SandboxResult`` is a firewall.** The orchestrator reads only the typed
  result (``reproduced``, ``exit_code``, ``wall_seconds``, and the
  ``stdout_ref``/``stderr_ref`` *pointers*). Raw target stdout/stderr is paged to
  the Store and referenced by pointer; it is never loaded into orchestrator
  context and never inlined into the session teach-back. A repro whose output
  carries an injected instruction changes nothing beyond a data artifact.

* **Promotion is at the Store boundary, not a field write.** VERIFY pages a short
  evidence artifact via ``store.write_detail(session_id, 'verify-result.txt', …)``,
  sets ``finding.evidence_ref`` to that resolving ref, and asks
  ``store.transition_finding(finding_id, verified)``. The lifecycle guard —
  unchanged from 001 — owns the decision and requires the ``evidence_ref`` to be
  non-empty **and** resolve (Constitution Article IV). VERIFY never assigns
  ``status = verified`` by hand.

On a non-reproducing result VERIFY still pages the (negative) artifact — a failed
repro is durable state — but sets no resolving ``evidence_ref``, so the finding
stays ``candidate`` and the reason is recorded in the session summary. VERIFY
refuses outright to run against a finding that is not a ``candidate``.
"""

from __future__ import annotations

from ..protocol.gate import GateContext
from ..protocol.session import BaseSession, SessionOutcome
from ..sandbox import Sandbox, SandboxError, SandboxResult, SandboxSpec
from ..schema import (
    Finding,
    FindingStatus,
    Project,
    SessionType,
)
from ..schema.common import iso_z, utcnow
from ..schema.finding import TransitionLogEntry
from ..store import NotFoundError, Store

# The evidence artifact's stable name under the session's detail directory. The
# resolving ref is ``detail/<session>/verify-result.txt`` — exactly the shape the
# lifecycle guard's ``detail_exists`` check resolves.
_EVIDENCE_NAME = "verify-result.txt"


class VerifySession(BaseSession):
    """Run a candidate's repro in the sandbox and promote it on evidence.

    The ``sandbox`` is dependency-injected so tests pass a ``NoopSandbox`` and no
    real executing backend is ever constructed here. Expose ``self.sandbox_result``
    and ``self.outcome`` after :meth:`run` for inspection.
    """

    type = SessionType.verify

    def __init__(
        self,
        project_id: str,
        finding_id: str,
        spec: SandboxSpec,
        sandbox: Sandbox,
        *,
        dry_run: bool = False,
    ) -> None:
        self.project_id = project_id
        self.finding_id = finding_id
        # The typed repro request. Data only — an argv command and a hardened
        # policy; never a shell string, never inlined repro content.
        self.spec = spec
        # DEPENDENCY-INJECTED. In tests this is a NoopSandbox that records the spec
        # and returns a canned result without executing anything. This session
        # never constructs a real executing backend.
        self.sandbox = sandbox
        # A demonstration run that mutates the finding NOWHERE: it exercises the
        # gate + the (Noop) sandbox seam and reports the typed verdict, but pages
        # no evidence, attempts no transition, and writes no audit entry — so the
        # finding is left exactly as it was. The CLI's default `playbook verify`
        # uses this so a dry-run cannot pollute a real candidate's lifecycle or
        # audit history with a canned, no-execution verdict.
        self.dry_run = dry_run
        # Exposed after run() for inspection: the typed SandboxResult (never raw
        # output) and the teach-back outcome.
        self.sandbox_result: SandboxResult | None = None
        self.outcome: SessionOutcome | None = None

    # --- gate context ------------------------------------------------------

    def _project(self, store: Store) -> Project:
        project = store.get_project(self.project_id)
        if project is None:
            raise NotFoundError(f"project {self.project_id!r} not found")
        return project

    def build_gate_context(self, store: Store) -> GateContext:
        # Built from the stored project, like every non-registration session, so
        # the unchanged gate governs: no basis -> refuse, empty scope -> hold.
        return GateContext.from_project(self._project(store), self.type)

    # --- scoped work -------------------------------------------------------

    def run(self, store: Store, session_id: str) -> SessionOutcome:
        finding = store.get_finding(self.finding_id)
        if finding is None:
            raise NotFoundError(f"finding {self.finding_id!r} not found")

        # Refuse a finding that belongs to a DIFFERENT project. The gate was
        # evaluated for self.project_id only; promoting another project's finding
        # under this project's gate would widen scope and corrupt that project's
        # lifecycle. Refuse BEFORE running the sandbox — least privilege.
        if finding.project != self.project_id:
            return self._record(
                SessionOutcome(
                    summary=(
                        f"VERIFY on {self.project_id!r}: finding {finding.id!r} "
                        f"belongs to project {finding.project!r}, not "
                        f"{self.project_id!r} — refusing. No repro was run; scope "
                        f"unchanged."
                    ),
                    next_steps=(
                        f"Run VERIFY under the finding's own project "
                        f"({finding.project!r}) so its gate governs, or pass a "
                        f"finding that belongs to {self.project_id!r}."
                    ),
                )
            )

        # Refuse anything that is not a candidate. VERIFY promotes candidate ->
        # verified only; it never re-verifies, and it does not run the sandbox for
        # a finding it cannot promote.
        if finding.status is not FindingStatus.candidate:
            return self._record(
                SessionOutcome(
                    summary=(
                        f"VERIFY on {self.project_id!r}: finding {finding.id!r} is "
                        f"{finding.status.value!r}, not a candidate — refusing to "
                        f"verify. No repro was run; scope unchanged."
                    ),
                    next_steps=(
                        f"VERIFY only promotes a candidate. {finding.id!r} is "
                        f"{finding.status.value!r}; nothing to do. If it must be "
                        f"re-examined, move it back to candidate through the Store "
                        f"lifecycle guard first, then re-run VERIFY."
                    ),
                )
            )

        # --- the ONLY door to execution: the injected Sandbox seam ---
        # Enter the sandbox's context so a real backend's setup()/teardown()
        # lifecycle runs: the ephemeral environment is built before the run and
        # ALWAYS torn down after, even if run() raises. Hand it the hardened spec
        # and read back ONLY the typed result. With a NoopSandbox this executes
        # nothing. There is no subprocess, no shell, and no in-process run of
        # target code here.
        with self.sandbox as sandbox:
            result = sandbox.run(self.spec)
        if result is None:
            # Defensive: the Sandbox contract returns a typed SandboxResult. A
            # buggy backend returning None must not AttributeError downstream.
            raise SandboxError(
                f"sandbox {type(self.sandbox).__name__} returned no SandboxResult"
            )
        self.sandbox_result = result

        # --- dry-run: report the verdict, mutate the finding NOWHERE ---
        # A demonstration only (the CLI's default). The sandbox executed nothing;
        # we page no evidence, attempt no transition, and write no audit entry, so
        # the finding is unchanged. This keeps a canned, no-execution verdict from
        # polluting a real candidate's lifecycle or transition_log.
        if self.dry_run:
            return self._record(self._dry_run_outcome(finding, result))

        # --- page the evidence artifact (the firewall boundary) ---
        # Page a short, typed summary of the run to the Store. Only the pointers
        # (stdout_ref/stderr_ref) are recorded — the raw target output stays in the
        # Store, out of orchestrator context, and is never inlined here.
        evidence_ref = store.write_detail(
            session_id, _EVIDENCE_NAME, _evidence_body(finding, self.spec, result)
        )

        if result.reproduced:
            return self._record(
                self._promote(store, finding, evidence_ref, result)
            )
        return self._record(
            self._leave_candidate(store, finding, evidence_ref, result)
        )

    # --- promotion (through the guard) -------------------------------------

    def _promote(
        self,
        store: Store,
        finding: Finding,
        evidence_ref: str,
        result: SandboxResult,
    ) -> SessionOutcome:
        """Set the resolving ``evidence_ref`` and promote THROUGH the guard.

        Promotion is not a field write: VERIFY sets ``finding.evidence_ref`` to the
        resolving detail ref, saves the finding, and asks the Store to transition
        it. The lifecycle guard requires the ref to be non-empty AND to resolve —
        both true by construction — and it owns the decision. VERIFY never assigns
        ``status = verified`` directly.
        """
        original_evidence_ref = finding.evidence_ref
        finding.evidence_ref = evidence_ref
        store.save_finding(finding)
        transition = store.transition_finding(finding.id, FindingStatus.verified)

        if transition.ok:
            summary = (
                f"VERIFY on {self.project_id!r}: repro for {finding.id!r} "
                f"REPRODUCED (exit_code={result.exit_code}, "
                f"wall_seconds={result.wall_seconds}). Paged the typed result as "
                f"evidence ({evidence_ref}) and promoted candidate -> verified "
                f"through the Store lifecycle guard. No untrusted code executed in "
                f"this slice; the sandbox seam was a NoopSandbox in tests."
            )
            next_steps = (
                f"{finding.id!r} is now verified on resolving evidence. Run `check` "
                f"(it stays green: a verified finding carries a resolving "
                f"evidence_ref), then queue disclosure preparation once a CVE and "
                f"advisory reference are available."
            )
        else:
            # Defensive: the guard rejected despite a resolving ref. Never
            # promoted; report the guard's reason. (Not expected in this slice.)
            # Revert the evidence_ref so a still-candidate finding is not left
            # pointing at evidence for a promotion that did not happen.
            finding.evidence_ref = original_evidence_ref
            store.save_finding(finding)
            summary = (
                f"VERIFY on {self.project_id!r}: repro for {finding.id!r} reproduced "
                f"but the Store lifecycle guard rejected the promotion: "
                f"{transition.reason}. Finding remains "
                f"{transition.status.value!r}; evidence paged at {evidence_ref}."
            )
            next_steps = (
                f"The guard blocked candidate -> verified ({transition.reason}). "
                f"Inspect the paged evidence ({evidence_ref}) and the finding's "
                f"transition log, resolve the block, and re-run VERIFY on "
                f"{finding.id!r}."
            )
        return SessionOutcome(
            summary=summary,
            next_steps=next_steps,
            findings_touched=[finding.id],
        )

    def _leave_candidate(
        self,
        store: Store,
        finding: Finding,
        evidence_ref: str,
        result: SandboxResult,
    ) -> SessionOutcome:
        """Repro did not reproduce: page the negative artifact, promote nothing.

        A failed repro is durable *verification history*, so besides paging the
        negative artifact we record a rejected ``candidate -> verified`` attempt in
        the finding's ``transition_log`` (the data model promises verification
        history lives on the finding, not only in the session detail). This sets NO
        resolving ``evidence_ref`` — that would let the guard promote a
        non-reproducing finding — and changes NO status: the finding stays
        ``candidate``.
        """
        finding.transition_log.append(
            TransitionLogEntry(
                at=iso_z(utcnow()),
                from_status=finding.status.value,
                to_status=FindingStatus.verified.value,
                accepted=False,
                reason=(
                    f"VERIFY: repro did not reproduce (exit_code={result.exit_code}, "
                    f"timed_out={result.timed_out}); no resolving evidence, not "
                    f"promoted. Negative result paged at {evidence_ref}."
                ),
            )
        )
        store.save_finding(finding)

        summary = (
            f"VERIFY on {self.project_id!r}: repro for {finding.id!r} did NOT "
            f"reproduce (exit_code={result.exit_code}, "
            f"wall_seconds={result.wall_seconds}, timed_out={result.timed_out}). "
            f"Paged the negative result as durable state ({evidence_ref}) and "
            f"recorded the blocked attempt on the finding; left it a candidate — no "
            f"evidence_ref set, so the lifecycle guard promotes nothing. No "
            f"untrusted code executed in this slice."
        )
        next_steps = (
            f"{finding.id!r} stays a candidate: the minimized repro did not "
            f"reproduce the behavior. Refine the repro (the paged negative result "
            f"is at {evidence_ref}) and re-run VERIFY, or move the finding back if "
            f"the candidate no longer holds."
        )
        return SessionOutcome(
            summary=summary,
            next_steps=next_steps,
            findings_touched=[finding.id],
        )

    def _dry_run_outcome(
        self, finding: Finding, result: SandboxResult
    ) -> SessionOutcome:
        """A demonstration outcome that changes the finding NOWHERE.

        The (Noop) sandbox executed nothing; this reports the typed verdict but
        pages no evidence, attempts no transition, and writes no audit entry, so
        ``findings_touched`` is empty and the finding is left exactly as it was.
        """
        summary = (
            f"VERIFY dry-run on {self.project_id!r}: the sandbox executed nothing "
            f"(NoopSandbox; reproduced={result.reproduced}, "
            f"exit_code={result.exit_code}). The finding {finding.id!r} is UNCHANGED "
            f"— no evidence paged, no lifecycle transition, no audit entry. Real "
            f"execution is the hard stop (sandbox sign-off pending)."
        )
        next_steps = (
            f"When a signed-off sandbox backend is wired, run VERIFY for real to "
            f"reproduce {finding.id!r} in isolation and promote it through the Store "
            f"lifecycle guard on resolving evidence."
        )
        return SessionOutcome(summary=summary, next_steps=next_steps, findings_touched=[])

    def _record(self, outcome: SessionOutcome) -> SessionOutcome:
        """Store the teach-back outcome for inspection, then return it."""
        self.outcome = outcome
        return outcome


def _evidence_body(finding: Finding, spec: SandboxSpec, result: SandboxResult) -> str:
    """A short evidence artifact: the TYPED SandboxResult summary and pointers.

    This is what is paged to the Store and what the finding's ``evidence_ref``
    resolves to. It records the verdict, the run's typed counters, the isolation
    the run enforced (the policy), and *pointers* to the raw stdout/stderr — never
    the raw output itself. Raw target output lives under the ``stdout_ref`` /
    ``stderr_ref`` the sandbox paged separately; it is never inlined here.
    """
    lines = [
        f"# VERIFY evidence for {finding.id}",
        "",
        f"Project: {finding.project}",
        f"Summary: {finding.summary}",
        "",
        "## Sandbox result (typed — the only thing the orchestrator reads)",
        f"- reproduced: {result.reproduced}",
        f"- exit_code: {result.exit_code}",
        f"- timed_out: {result.timed_out}",
        f"- wall_seconds: {result.wall_seconds}",
        f"- stdout_ref: {result.stdout_ref or '(none)'}",
        f"- stderr_ref: {result.stderr_ref or '(none)'}",
        "",
        "## Enforced isolation (the policy the run ran under)",
        f"- image: {spec.image}",
        f"- network: {spec.policy.network}",
        f"- read_only_rootfs: {spec.policy.read_only_rootfs}",
        f"- drop_all_caps: {spec.policy.drop_all_caps}",
        f"- no_new_privileges: {spec.policy.no_new_privileges}",
        f"- run_as_non_root: {spec.policy.run_as_non_root} (user {spec.policy.user})",
        f"- pids_limit: {spec.policy.pids_limit}",
        f"- memory_mib: {spec.policy.memory_mib}",
        f"- cpus: {spec.policy.cpus}",
        f"- wall_timeout_seconds: {spec.policy.wall_timeout_seconds}",
        f"- ephemeral: {spec.policy.ephemeral}",
        "",
        "Raw target stdout/stderr is paged separately under the refs above and is "
        "never inlined into orchestrator context (Constitution Article VIII).",
        "",
    ]
    return "\n".join(lines)
