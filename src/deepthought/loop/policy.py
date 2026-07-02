"""select_next_action — the loop's deterministic, monotonic selection policy.

A pure function of a store snapshot (plus the driver's in-run ``done`` set): it
proposes the single highest-priority *safe* action, a hard-stop *escalation*, or
``None`` at a fixed point. It reads coverage/findings/sessions and the project's
existing ``scope_allowlist``; it writes nothing, runs no session, and can propose
nothing that expands scope, executes target code, or transmits.
"""

from __future__ import annotations

from ..schema import FindingStatus, Project, SessionType
from ..schema.loop import ActionKind, LoopAction
from ..store import Store

# A per-run key the driver marks once an action has been dispatched, so the same
# work is never re-proposed within a run (structural monotonicity, independent of
# whatever the ran session did or did not persist).
Done = set  # set[tuple[str, str]] of (ActionKind.value, target-id)


def select_next_action(
    store: Store, project: Project, *, done: "set[tuple[str, str]] | None" = None
) -> LoopAction | None:
    done = done or set()
    pid = project.id
    sessions = store.list_sessions(pid)
    types_run = {s.type for s in sessions}

    def fresh(kind: ActionKind, target: str) -> bool:
        return (kind.value, target) not in done

    # 1. STATUS — a cheap situational baseline, once per project.
    if SessionType.status not in types_run and fresh(ActionKind.status, pid):
        return LoopAction(kind=ActionKind.status, project=pid)

    # 2. MAP — expand the mapped surface, once per project. Needs an in-scope
    #    surface to map (an empty allowlist means nothing is in scope).
    if project.scope_allowlist and SessionType.map not in types_run and fresh(ActionKind.map, pid):
        return LoopAction(kind=ActionKind.map, project=pid)

    # 3. DISCOVER — produce candidates over the mapped surface, once per project.
    if SessionType.map in types_run and SessionType.discover not in types_run and fresh(ActionKind.discover, pid):
        return LoopAction(kind=ActionKind.discover, project=pid)

    findings = store.list_findings(pid)
    verified = [f for f in findings if f.status is FindingStatus.verified]

    # A verified finding hunted in a PRIOR loop run is recorded in that run's
    # trace — the cross-run "done" signal, so repeated `deepthought loop`
    # invocations converge instead of re-hunting the same finding forever.
    hunted_before = {
        step.finding
        for run in store.list_loop_runs(pid)
        for step in run.trace
        if step.kind is ActionKind.sibling_hunt and step.finding
    }

    # 4. SIBLING HUNT — variants of the first verified finding not yet hunted.
    for f in verified:
        if f.id not in hunted_before and fresh(ActionKind.sibling_hunt, f.id):
            return LoopAction(kind=ActionKind.sibling_hunt, project=pid, finding=f.id)

    # 5. DISCLOSURE (draft) — for the first verified finding lacking drafts. A
    #    disclosure session records its drafted finding in findings_touched, the
    #    cross-run signal that drafts already exist.
    drafted = {
        fid
        for s in sessions
        if s.type is SessionType.disclosure
        for fid in s.findings_touched
    }
    for f in verified:
        if f.id not in drafted and fresh(ActionKind.disclosure, f.id):
            return LoopAction(kind=ActionKind.disclosure, project=pid, finding=f.id)

    # 6. VERIFY escalation — a candidate can only advance by real reproduction,
    #    which is a human-signed hard stop. Never run; recorded for a human.
    for f in findings:
        if f.status is FindingStatus.candidate and fresh(ActionKind.verify_escalation, f.id):
            return LoopAction(
                kind=ActionKind.verify_escalation,
                project=pid,
                finding=f.id,
                human_action=(
                    f"{f.id} needs VERIFY under a real sandbox — human sign-off required"
                ),
            )

    # 7. Nothing safe remains.
    return None
