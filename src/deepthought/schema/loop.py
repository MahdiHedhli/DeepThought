"""Loop records — the autonomous loop's typed vocabulary (feature 006).

``LoopAction`` is what the deterministic policy proposes (transient, never worker
free-text); ``LoopStep``/``LoopRun`` are the durable, human-readable audit of a
loop run. Every id is a ``RecordId`` (a safe path segment). The loop never has a
``send`` or a scope-expanding action — those kinds do not exist here.
"""

from __future__ import annotations

import math
import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, model_validator

from .common import ContextCost, Record, RecordId
from .session import CloseState, GateOutcome


class LoopSpend(BaseModel):
    """What the loop has spent so far: a session count and summed session cost.

    Lives here (not in the ``loop`` package) so ``LoopRun`` and ``LoopBudget`` can
    reference it without the schema layer depending on the loop package — the loop
    depends on schema, never the reverse.
    """

    model_config = ConfigDict(extra="forbid")

    sessions: int = 0
    wall_seconds: float = 0.0
    tokens: int = 0

    def plus(self, cost: ContextCost) -> "LoopSpend":
        """Return a NEW accumulator with one more session's cost folded in."""
        return LoopSpend(
            sessions=self.sessions + 1,
            wall_seconds=self.wall_seconds + cost.wall_seconds,
            tokens=self.tokens + cost.tokens,
        )


class LoopBudget(BaseModel):
    """The loop's resource envelope (limit awareness). At least one limit must be
    set and positive; the model is frozen so the loop cannot grow its own budget
    mid-run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_sessions: int | None = None
    max_wall_seconds: float | None = None
    max_context_tokens: int | None = None

    @model_validator(mode="after")
    def _at_least_one_positive_limit(self) -> "LoopBudget":
        limits = (self.max_sessions, self.max_wall_seconds, self.max_context_tokens)
        if all(limit is None for limit in limits):
            raise ValueError(
                "LoopBudget requires at least one limit — the loop is never unbounded"
            )
        for limit in limits:
            if limit is None:
                continue
            # A non-finite (NaN/inf) wall/token limit would pass a ``> 0`` check but
            # make ``would_exceed`` never trip (``x >= NaN`` is always False), giving
            # NO effective cap — reject it so a budget is always a real bound.
            if isinstance(limit, float) and not math.isfinite(limit):
                raise ValueError("every set LoopBudget limit must be finite")
            if limit <= 0:
                raise ValueError("every set LoopBudget limit must be > 0")
        return self

    def would_exceed(self, spent: LoopSpend) -> bool:
        """Whether running one more session could cross any SET limit.

        Checked before each iteration so the loop stops AT the boundary, not over
        it. The session count is known ahead of the next run (so ``+1`` would-be),
        while wall/token cost is only known after — for those we stop once the
        accumulated spend has reached the limit.
        """
        if self.max_sessions is not None and spent.sessions + 1 > self.max_sessions:
            return True
        if self.max_wall_seconds is not None and spent.wall_seconds >= self.max_wall_seconds:
            return True
        if self.max_context_tokens is not None and spent.tokens >= self.max_context_tokens:
            return True
        return False


class ActionKind(str, Enum):
    status = "status"
    map = "map"
    discover = "discover"
    sibling_hunt = "sibling_hunt"
    disclosure = "disclosure"
    # Not a runnable session: a candidate that can only advance by real
    # reproduction, which is a human-signed hard stop (Article III).
    verify_escalation = "verify_escalation"


class StopReason(str, Enum):
    fixed_point = "fixed_point"          # no safe progress remains
    budget_exhausted = "budget_exhausted"  # the next action could exceed a limit
    hard_stop = "hard_stop"              # only an escalation remains
    gate_held = "gate_held"              # a session's gate held
    gate_refused = "gate_refused"        # gate refused / project missing / unauthorized


_NEXT_STEPS = re.compile(r"^##\s+Next steps\s*$(.*?)(?=^##\s|\Z)", re.MULTILINE | re.DOTALL)


class LoopAction(BaseModel):
    """A single action the policy proposes. Transient — never persisted directly."""

    model_config = ConfigDict(extra="forbid")

    kind: ActionKind
    project: RecordId
    area: str | None = None
    finding: RecordId | None = None
    human_action: str | None = None

    @property
    def is_escalation(self) -> bool:
        return self.kind is ActionKind.verify_escalation

    @model_validator(mode="after")
    def _escalation_carries_a_human_action(self) -> "LoopAction":
        if self.kind is ActionKind.verify_escalation:
            if not self.human_action:
                raise ValueError("a verify_escalation action must carry a human_action")
        elif self.human_action is not None:
            raise ValueError("only a verify_escalation action carries a human_action")
        return self


class LoopStep(BaseModel):
    """One row of a loop's trace — the session it ran (or the escalation it hit)."""

    model_config = ConfigDict(extra="forbid")

    kind: ActionKind
    session_id: RecordId | None = None      # None for a pure escalation row
    area: str | None = None
    finding: RecordId | None = None
    gate_outcome: GateOutcome | None = None
    close_state: CloseState | None = None


class LoopRun(Record):
    """Durable audit of one loop run: its trace, cost, stop reason, and the human
    actions it escalated to."""

    id: RecordId
    project: RecordId
    started: str
    stopped: str | None = None
    stop_reason: StopReason
    sessions_run: int = 0
    context_cost: ContextCost = ContextCost()
    budget: LoopBudget
    trace: list[LoopStep] = []
    outstanding_actions: list[str] = []

    def next_steps(self) -> str:
        match = _NEXT_STEPS.search(self.body)
        return match.group(1).strip() if match else ""

    def has_next_steps(self) -> bool:
        return bool(self.next_steps())
