"""select_next_action — the loop's deterministic, monotonic selection policy.

A pure function of a store snapshot (plus the driver's in-run ``done`` set): it
proposes the single highest-priority *safe* action, a hard-stop *escalation*, or
``None`` at a fixed point. It reads coverage/findings/sessions and the project's
existing ``scope_allowlist``; it writes nothing, runs no session, and can propose
nothing that expands scope, executes target code, or transmits.
"""

from __future__ import annotations

from ..check import disclosure_drafts_ok
from ..schema import CloseState, FindingStatus, GateOutcome, Project, SessionType
from ..schema.loop import ActionKind, LoopAction
from ..store import Store

# A per-run key the driver marks once an action has been dispatched, so the same
# work is never re-proposed within a run (structural monotonicity, independent of
# whatever the ran session did or did not persist).
Done = set  # set[tuple[str, str]] of (ActionKind.value, target-id)


def _completed(record) -> bool:
    """A session/step genuinely COMPLETED its work: the gate PROCEEDED and it
    closed CLEAN. A gate-held/refused or interrupted attempt still persists a
    record but did no work, so it must not mark its rung done — else the loop
    could never resume that step after the operator fixes the cause."""
    return (record.gate_outcome is GateOutcome.proceed
            and record.close_state is CloseState.clean)


def _verify_escalation(pid: str, fid: str) -> LoopAction:
    return LoopAction(
        kind=ActionKind.verify_escalation, project=pid, finding=fid,
        human_action=f"{fid} needs VERIFY under a real sandbox — human sign-off required",
    )


def _send_escalation(pid: str, fid: str) -> LoopAction:
    return LoopAction(
        kind=ActionKind.disclosure_send, project=pid, finding=fid,
        human_action=(
            f"{fid} disclosure drafted — human review and send required "
            f"(Article V); Deep Thought drafts only, never transmits"
        ),
    )


def _drafted_findings(store: Store, sessions: list) -> set[str]:
    """Findings whose disclosure a COMPLETED session drafted AND whose four
    persisted drafts resolve AND VALIDATE (the same checks the `check` gate
    applies), so deleted/corrupt drafts trigger a re-draft."""
    return {
        fid
        for s in sessions
        if s.type is SessionType.disclosure and _completed(s) and disclosure_drafts_ok(store, s.id)
        for fid in s.findings_touched
    }


def pending_escalations(store: Store, project: Project) -> list[LoopAction]:
    """Every outstanding human hard stop for the project, in ONE bounded pass: a
    SEND escalation (Article V) per verified finding with valid drafts, then a
    VERIFY escalation (Article III) per candidate. Never performed — recorded for a
    human. The driver enumerates these once at the hard-stop boundary rather than
    looping the selector per escalation."""
    pid = project.id
    findings = store.list_findings(pid)
    drafted = _drafted_findings(store, store.list_sessions(pid))
    sends = [_send_escalation(pid, f.id) for f in findings
             if f.status is FindingStatus.verified and f.id in drafted]
    verifies = [_verify_escalation(pid, f.id) for f in findings
                if f.status is FindingStatus.candidate]
    return sends + verifies


def select_next_action(
    store: Store, project: Project, *, done: "set[tuple[str, str]] | None" = None
) -> LoopAction | None:
    done = done or set()
    pid = project.id
    sessions = store.list_sessions(pid)
    completed = _completed
    succeeded = {s.type for s in sessions if completed(s)}

    def fresh(kind: ActionKind, target: str) -> bool:
        return (kind.value, target) not in done

    # 1. STATUS — a cheap situational baseline, once per project.
    if SessionType.status not in succeeded and fresh(ActionKind.status, pid):
        return LoopAction(kind=ActionKind.status, project=pid)

    # Progress, not mere session existence, is the completion signal for the recon
    # rungs. MAP is done PER AREA: it is complete only when every in-scope area has
    # a Coverage record — so a MAP that recorded nothing (no checkout yet) re-runs,
    # AND broadening the scope (a human action outside the loop) re-triggers MAP for
    # the newly in-scope areas rather than being masked by one existing coverage
    # file. The in-run `done` set still bounds it to one MAP per run.
    coverage = store.list_coverage(pid)
    covered_areas = {c.area for c in coverage}
    in_scope = [a.strip() for a in project.scope_allowlist if a.strip()]
    has_coverage = bool(covered_areas)
    unmapped = [area for area in in_scope if area not in covered_areas]

    # 2. MAP — map the in-scope surface while any in-scope area lacks Coverage.
    if unmapped and fresh(ActionKind.map, pid):
        return LoopAction(kind=ActionKind.map, project=pid)

    # 3. DISCOVER — produce candidates over the MAPPED surface. Gated on Coverage
    #    (never runs pre-map), and STALE once new Coverage post-dates the last
    #    successful DISCOVER — so broadening the scope and re-mapping re-triggers
    #    DISCOVER over the newly-mapped area. Session ids share a monotonic daily
    #    counter, so a lexical id compare is creation order (no timestamp parsing).
    last_map_id = max((c.last_session for c in coverage if c.last_session), default="")
    last_discover_id = max(
        (s.id for s in sessions if s.type is SessionType.discover and completed(s)),
        default="",
    )
    discover_current = bool(last_discover_id) and last_discover_id >= last_map_id
    if has_coverage and not discover_current and fresh(ActionKind.discover, pid):
        return LoopAction(kind=ActionKind.discover, project=pid)

    findings = store.list_findings(pid)
    verified = [f for f in findings if f.status is FindingStatus.verified]

    # A verified finding SUCCESSFULLY hunted in a PRIOR loop run is recorded in
    # that run's trace — the cross-run "done" signal, so repeated `deepthought
    # loop` invocations converge instead of re-hunting forever. A gate-refused
    # hunt step is not progress and is excluded, so the loop resumes it once the
    # gate is fixed.
    hunted_before = {
        step.finding
        for run in store.list_loop_runs(pid)
        for step in run.trace
        if step.kind is ActionKind.sibling_hunt and step.finding and completed(step)
    }

    # 4. SIBLING HUNT — variants of the first verified finding not yet hunted.
    for f in verified:
        if f.id not in hunted_before and fresh(ActionKind.sibling_hunt, f.id):
            return LoopAction(kind=ActionKind.sibling_hunt, project=pid, finding=f.id)

    drafted = _drafted_findings(store, sessions)

    # 5. DISCLOSURE (draft) — for the first verified finding without valid drafts.
    for f in verified:
        if f.id not in drafted and fresh(ActionKind.disclosure, f.id):
            return LoopAction(kind=ActionKind.disclosure, project=pid, finding=f.id)

    # 6. DISCLOSURE SEND escalation — a verified finding WITH valid drafts still
    #    needs a human to review and SEND it (Article V). Surfaced on every run
    #    (state-based) until the finding moves past `verified`; never performed.
    for f in verified:
        if f.id in drafted and fresh(ActionKind.disclosure_send, f.id):
            return _send_escalation(pid, f.id)

    # 7. VERIFY escalation — a candidate can only advance by real reproduction,
    #    which is a human-signed hard stop. Never run; recorded for a human.
    for f in findings:
        if f.status is FindingStatus.candidate and fresh(ActionKind.verify_escalation, f.id):
            return _verify_escalation(pid, f.id)

    # 8. Nothing safe remains.
    return None
