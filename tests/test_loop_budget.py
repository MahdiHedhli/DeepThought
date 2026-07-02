"""T601 — LoopBudget & LoopSpend (limit awareness core, feature 006).

A budget must be explicit (never all-None), positive, checked BEFORE each
iteration, and read-only for the run. LoopSpend accumulates one session's cost
immutably. Unset limits never trigger.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from deepthought.loop import LoopBudget, LoopSpend
from deepthought.schema.common import ContextCost


def test_all_none_budget_is_refused():
    """The loop is never unbounded — a budget with no limit set is rejected."""
    with pytest.raises(ValidationError):
        LoopBudget()


def test_any_single_limit_is_accepted():
    assert LoopBudget(max_sessions=5).max_sessions == 5
    assert LoopBudget(max_wall_seconds=1.0).max_wall_seconds == 1.0
    assert LoopBudget(max_context_tokens=100).max_context_tokens == 100


def test_non_positive_limits_are_refused():
    for kw in ({"max_sessions": 0}, {"max_sessions": -1},
               {"max_wall_seconds": 0.0}, {"max_wall_seconds": -0.5},
               {"max_context_tokens": 0}, {"max_context_tokens": -10}):
        with pytest.raises(ValidationError):
            LoopBudget(**kw)


def test_non_finite_limits_are_refused():
    """A NaN/inf wall limit would pass a '> 0' check but make would_exceed never
    trip (x >= NaN is always False), leaving no effective cap — reject it."""
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValidationError):
            LoopBudget(max_wall_seconds=bad)


def test_budget_is_immutable():
    """The loop never raises its own budget mid-run — the model is frozen."""
    b = LoopBudget(max_sessions=3)
    with pytest.raises(ValidationError):
        b.max_sessions = 99


def test_would_exceed_on_session_count():
    """Checked before a run: with max_sessions=N, exactly N sessions may run."""
    b = LoopBudget(max_sessions=2)
    assert b.would_exceed(LoopSpend(sessions=0)) is False
    assert b.would_exceed(LoopSpend(sessions=1)) is False
    assert b.would_exceed(LoopSpend(sessions=2)) is True  # the 3rd cannot start
    assert b.would_exceed(LoopSpend(sessions=5)) is True


def test_would_exceed_on_wall_seconds():
    b = LoopBudget(max_wall_seconds=1.0)
    assert b.would_exceed(LoopSpend(wall_seconds=0.5)) is False
    assert b.would_exceed(LoopSpend(wall_seconds=1.0)) is True
    assert b.would_exceed(LoopSpend(wall_seconds=1.5)) is True


def test_would_exceed_on_tokens():
    b = LoopBudget(max_context_tokens=100)
    assert b.would_exceed(LoopSpend(tokens=50)) is False
    assert b.would_exceed(LoopSpend(tokens=100)) is True
    assert b.would_exceed(LoopSpend(tokens=150)) is True


def test_unset_limits_never_trigger():
    """A limit left None is ignored — a huge spend on an unmetered dimension does
    not stop the loop."""
    b = LoopBudget(max_sessions=2)
    assert b.would_exceed(LoopSpend(sessions=0, tokens=10**9, wall_seconds=10**9)) is False


def test_any_set_limit_triggers_independently():
    b = LoopBudget(max_sessions=10, max_context_tokens=100)
    # Under the session cap but over the token cap -> still exceeds.
    assert b.would_exceed(LoopSpend(sessions=1, tokens=100)) is True


def test_loop_spend_plus_accumulates_one_session_immutably():
    base = LoopSpend()
    nxt = base.plus(ContextCost(tokens=10, wall_seconds=1.5))
    # A new accumulator is returned; the original is unchanged.
    assert base.sessions == 0 and base.tokens == 0 and base.wall_seconds == 0.0
    assert nxt.sessions == 1 and nxt.tokens == 10 and nxt.wall_seconds == 1.5
    # Chaining sums cost and increments the session count each time.
    nxt2 = nxt.plus(ContextCost(tokens=5, wall_seconds=0.5))
    assert nxt2.sessions == 2 and nxt2.tokens == 15 and nxt2.wall_seconds == 2.0
