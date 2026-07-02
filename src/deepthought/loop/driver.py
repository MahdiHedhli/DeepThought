"""run_loop — the autonomous loop's driver (feature 006).

Deterministic, bounded, and gated. It asks the policy for the next safe action,
runs it through the existing ``run_session`` harness (so the Gate is evaluated
first), accumulates each session's cost against the budget, and stops for exactly
one recorded reason. It builds only safe sessions — never a NEW PROJECT (which
would expand scope) and never a verify session (which would execute target code);
a candidate that can only advance by real reproduction is an escalation for a
human, not a loop action. It writes one durable ``LoopRun``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from ..protocol import run_session
from ..protocol.gate import Gate
from ..schema import GateOutcome
from ..schema.common import ContextCost, iso_z, safe_record_id, utcnow
from ..schema.loop import ActionKind, LoopAction, LoopRun, LoopStep, StopReason
from ..sessions import (
    DiscoverSession,
    DisclosureSession,
    MapSession,
    SiblingHuntSession,
    StatusSession,
)
from ..store import Store
from .budget import LoopBudget, LoopSpend
from .policy import select_next_action


def generate_loop_run_id(store: Store, now: datetime) -> str:
    """A stable, human-readable loop-run id: ``L-YYYY-MM-DD-NNNN``."""
    date = now.strftime("%Y-%m-%d")
    prefix = f"L-{date}-"
    used = [r.id for r in store.list_loop_runs() if r.id.startswith(prefix)]
    return f"{prefix}{len(used) + 1:04d}"


# The loop's runnable repertoire. NEW PROJECT (scope) and verify (execution) are
# deliberately absent — a candidate needing real reproduction is escalated, not run.
def _build_session(action: LoopAction):
    kind = action.kind
    if kind is ActionKind.status:
        return StatusSession(action.project)
    if kind is ActionKind.map:
        return MapSession(action.project)
    if kind is ActionKind.discover:
        return DiscoverSession(action.project)
    if kind is ActionKind.sibling_hunt:
        return SiblingHuntSession(action.project, action.finding)
    if kind is ActionKind.disclosure:
        return DisclosureSession(action.project, action.finding)
    raise ValueError(f"kind {kind.value!r} is not a runnable loop session")


def _key(action: LoopAction) -> tuple[str, str]:
    return (action.kind.value, action.finding or action.project)


def _teach_back(stop_reason: StopReason, sessions_run: int,
                outstanding: list[str], planned: LoopAction | None) -> str:
    summary = f"Loop ran {sessions_run} session(s); stopped: {stop_reason.value}."
    lines = list(outstanding)
    if planned is not None:
        lines.append(
            f"Budget exhausted before the next action ({planned.kind.value}); "
            f"raise the budget and re-run the loop to continue."
        )
    if not lines:
        lines.append(
            "No further safe work — the loop reached a fixed point. Any candidate "
            "findings need real reproduction (human sign-off); any verified "
            "findings' disclosure drafts need a human to review and send."
        )
    steps = "\n".join(f"- {line}" for line in lines)
    return f"## Summary\n\n{summary}\n\n## Next steps\n\n{steps}"


def run_loop(
    store: Store,
    gate: Gate,
    project_id: str,
    budget: LoopBudget,
    *,
    clock: Callable[[], datetime] = utcnow,
) -> LoopRun:
    now = clock()
    project = store.get_project(project_id)
    if project is None:
        return _persist(
            store, safe_record_id(project_id, fallback="unknown"), budget, now, clock,
            stop_reason=StopReason.gate_refused, spent=LoopSpend(), trace=[],
            outstanding=[
                f"Project {project_id!r} is not registered — register and authorize "
                f"it (a gated NEW PROJECT session), then re-run the loop."
            ],
            planned=None,
        )

    spent = LoopSpend()
    done: set[tuple[str, str]] = set()
    trace: list[LoopStep] = []
    outstanding: list[str] = []
    planned: LoopAction | None = None
    stop_reason: StopReason | None = None

    while True:
        action = select_next_action(store, project, done=done)
        if action is None:
            stop_reason = StopReason.hard_stop if outstanding else StopReason.fixed_point
            break
        if action.is_escalation:
            # A hard stop — recorded for a human, never run. No session, no budget.
            outstanding.append(action.human_action)
            trace.append(LoopStep(kind=action.kind, finding=action.finding))
            done.add(_key(action))
            continue
        if budget.would_exceed(spent):
            planned = action
            stop_reason = StopReason.budget_exhausted
            break
        record = run_session(store, gate, _build_session(action), clock=clock)
        done.add(_key(action))
        trace.append(LoopStep(
            kind=action.kind, session_id=record.id, area=action.area,
            finding=action.finding, gate_outcome=record.gate_outcome,
            close_state=record.close_state,
        ))
        spent = spent.plus(record.context_cost)
        if record.gate_outcome is not GateOutcome.proceed:
            stop_reason = (
                StopReason.gate_held if record.gate_outcome is GateOutcome.hold
                else StopReason.gate_refused
            )
            break

    return _persist(store, project.id, budget, now, clock, stop_reason, spent,
                    trace, outstanding, planned)


def _persist(store, project_ref, budget, now, clock, stop_reason, spent, trace,
             outstanding, planned) -> LoopRun:
    run = LoopRun(
        id=generate_loop_run_id(store, now),
        project=project_ref,
        started=iso_z(now),
        stopped=iso_z(clock()),
        stop_reason=stop_reason,
        sessions_run=spent.sessions,
        context_cost=ContextCost(tokens=spent.tokens, wall_seconds=spent.wall_seconds),
        budget=budget,
        trace=trace,
        outstanding_actions=outstanding,
        body=_teach_back(stop_reason, spent.sessions, outstanding, planned),
    )
    store.save_loop_run(run)
    return run
