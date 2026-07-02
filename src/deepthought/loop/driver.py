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
from ..protocol.gate import Gate, GateContext
from ..schema import GateOutcome, SessionType
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
from .policy import pending_escalations, select_next_action


def generate_loop_run_id(store: Store, now: datetime) -> str:
    """A stable, human-readable loop-run id: ``L-YYYY-MM-DD-NNNN``.

    Uses the MAX existing sequence + 1 (not the count), so a deleted run leaves a
    gap rather than making the next id collide with — and silently overwrite — an
    existing higher-numbered run.
    """
    date = now.strftime("%Y-%m-%d")
    prefix = f"L-{date}-"
    max_seq = 0
    for run in store.list_loop_runs():
        if run.id.startswith(prefix):
            try:
                max_seq = max(max_seq, int(run.id[len(prefix):]))
            except ValueError:
                pass
    return f"{prefix}{max_seq + 1:04d}"


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
        # A loop on a non-existent project is a no-op refusal — there is nothing to
        # durably audit, and persisting a LoopRun whose `project` does not resolve
        # would leave the store failing `check` (orphan). Return it UNPERSISTED so a
        # typo'd id is a clean, stateless refusal.
        return _build_run(
            store, safe_record_id(project_id, fallback="unknown"), budget, now, clock,
            stop_reason=StopReason.gate_refused, spent=LoopSpend(), trace=[],
            outstanding=[
                f"Project {project_id!r} is not registered — register and authorize "
                f"it (a gated NEW PROJECT session), then re-run the loop."
            ],
            planned=None,
        )

    # Gate the project ONCE up front (Article I — the Gate runs before ANY work,
    # including an escalation-only or fixed-point run). The loop changes no
    # authorization/scope, so the decision holds for the whole run; without this an
    # unauthorized project in an escalation-only state would never be re-gated.
    decision = gate.evaluate(GateContext.from_project(project, SessionType.status))
    if not decision.proceeds:
        run = _build_run(
            store, project.id, budget, now, clock,
            stop_reason=(StopReason.gate_held if decision.outcome is GateOutcome.hold
                         else StopReason.gate_refused),
            spent=LoopSpend(), trace=[],
            outstanding=[
                f"Gate {decision.outcome.value} on {project.id!r}: {decision.reason} "
                f"— resolve authorization/scope, then re-run the loop."
            ],
            planned=None,
        )
        store.save_loop_run(run)   # the project exists, so this audit resolves
        return run

    spent = LoopSpend()
    done: set[tuple[str, str]] = set()
    trace: list[LoopStep] = []
    outstanding: list[str] = []
    planned: LoopAction | None = None
    stop_reason: StopReason | None = None

    # Real elapsed wall-clock time, measured HERE — a bound the loop can enforce
    # even while stub sessions report a zero context_cost.
    def _live_spend() -> LoopSpend:
        return LoopSpend(
            sessions=spent.sessions,
            wall_seconds=(clock() - now).total_seconds(),
            tokens=spent.tokens,
        )

    def _wall_exceeded() -> bool:
        return (budget.max_wall_seconds is not None
                and (clock() - now).total_seconds() >= budget.max_wall_seconds)

    while True:
        action = select_next_action(store, project, done=done)
        if action is None:
            stop_reason = StopReason.hard_stop if outstanding else StopReason.fixed_point
            break
        # Wall time is consumed by EVERY iteration — escalation collection included —
        # so the wall cap is enforced before any action (the session/token caps apply
        # only to actual runs, below).
        if _wall_exceeded():
            planned = action
            stop_reason = StopReason.budget_exhausted
            break
        if action.is_escalation:
            # Hard-stop boundary reached (no safe runnable work left). Enumerate ALL
            # outstanding human actions in ONE bounded pass and stop — do NOT loop
            # the selector per escalation, which (since escalations consume no
            # session/token budget) would ignore a --max-sessions/--max-tokens cap.
            for esc in pending_escalations(store, project):
                outstanding.append(esc.human_action)
                trace.append(LoopStep(kind=esc.kind, finding=esc.finding))
            stop_reason = StopReason.hard_stop
            break
        if budget.would_exceed(_live_spend()):
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
            # Carry the gate's own remediation reason into the teach-back rather
            # than falling back to the generic fixed-point message.
            outcome = record.gate_outcome.value if record.gate_outcome else "unknown"
            outstanding.append(
                f"Gate {outcome} on {action.project!r}: "
                f"{record.gate_reason} — resolve authorization/scope, then re-run."
            )
            stop_reason = (
                StopReason.gate_held if record.gate_outcome is GateOutcome.hold
                else StopReason.gate_refused
            )
            break
        # (The Article V "review and send" hard stop for a drafted finding is
        # surfaced by the policy's disclosure_send escalation — state-based, so it
        # persists on every run until the finding moves past `verified`.)

    run = _build_run(store, project.id, budget, now, clock, stop_reason, spent,
                     trace, outstanding, planned)
    store.save_loop_run(run)   # a real project ran — persist the durable audit
    return run


def _build_run(store, project_ref, budget, now, clock, stop_reason, spent, trace,
               outstanding, planned) -> LoopRun:
    stopped = clock()
    return LoopRun(
        id=generate_loop_run_id(store, now),
        project=project_ref,
        started=iso_z(now),
        stopped=iso_z(stopped),
        stop_reason=stop_reason,
        sessions_run=spent.sessions,
        # Real elapsed wall-clock time (session-reported cost is currently zero);
        # tokens are the sum of session context_cost, populated when real workers run.
        context_cost=ContextCost(
            tokens=spent.tokens, wall_seconds=(stopped - now).total_seconds()
        ),
        budget=budget,
        trace=trace,
        outstanding_actions=outstanding,
        body=_teach_back(stop_reason, spent.sessions, outstanding, planned),
    )
