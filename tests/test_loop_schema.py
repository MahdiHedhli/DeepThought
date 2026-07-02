"""T602 — Loop schema records (feature 006).

ActionKind/StopReason are closed enums; LoopAction marks an escalation only for a
verify escalation (and demands a human action for it); LoopRun round-trips through
Markdown, forbids stray keys, constrains its ids, and exposes next-steps like a
Session.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from deepthought.loop import LoopBudget
from deepthought.schema.loop import (
    ActionKind,
    LoopAction,
    LoopRun,
    LoopStep,
    StopReason,
)


def test_action_and_stop_enums_are_closed():
    for good in ("status", "map", "discover", "sibling_hunt", "disclosure",
                 "verify_escalation", "disclosure_send"):
        assert ActionKind(good).value == good
    for good in ("fixed_point", "budget_exhausted", "hard_stop", "gate_held", "gate_refused"):
        assert StopReason(good).value == good
    with pytest.raises(ValueError):
        ActionKind("send_disclosure")   # transmission is not a loop action
    with pytest.raises(ValueError):
        StopReason("crashed")


def test_loop_action_escalation_flag_tracks_kind():
    safe = LoopAction(kind="map", project="php-src", area="ext/soap")
    assert safe.is_escalation is False
    for kind in ("verify_escalation", "disclosure_send"):
        esc = LoopAction(kind=kind, project="php-src", finding="F-0007",
                         human_action="a human must act")
        assert esc.is_escalation is True


def test_verify_escalation_requires_a_human_action():
    with pytest.raises(ValidationError):
        LoopAction(kind="verify_escalation", project="php-src", finding="F-0007")
    # a non-escalation action must NOT carry a human_action
    with pytest.raises(ValidationError):
        LoopAction(kind="map", project="php-src", area="a", human_action="nope")


def test_loop_action_ids_are_constrained():
    with pytest.raises(ValidationError):
        LoopAction(kind="map", project="../../x", area="a")
    with pytest.raises(ValidationError):
        LoopAction(kind="disclosure", project="p", finding="a/b")


def _sample_run() -> LoopRun:
    return LoopRun(
        id="L-2026-07-02-0001",
        project="php-src",
        started="2026-07-02T00:00:00Z",
        stopped="2026-07-02T00:01:00Z",
        stop_reason="hard_stop",
        sessions_run=2,
        budget=LoopBudget(max_sessions=10),
        trace=[
            LoopStep(kind="status", session_id="S-2026-07-02-0001",
                     gate_outcome="proceed", close_state="clean"),
            LoopStep(kind="map", session_id="S-2026-07-02-0002", area="ext/soap",
                     gate_outcome="proceed", close_state="clean"),
            LoopStep(kind="verify_escalation", finding="F-0007"),
        ],
        outstanding_actions=[
            "F-0007 needs VERIFY under a real sandbox — human sign-off required",
        ],
        body="## Summary\n\nRan 2 sessions.\n\n## Next steps\n\nHuman: verify F-0007.",
    )


def test_loop_run_round_trips_through_markdown():
    run = _sample_run()
    text = run.to_markdown()
    assert text.startswith("---\n")
    reloaded = LoopRun.from_markdown(text)
    assert reloaded == run
    # the nested step / budget / outstanding actions survive the round trip
    assert reloaded.trace[2].kind is ActionKind.verify_escalation
    assert reloaded.budget.max_sessions == 10
    assert reloaded.outstanding_actions == run.outstanding_actions


def test_loop_run_forbids_stray_keys_and_constrains_ids():
    with pytest.raises(ValidationError):
        LoopRun(id="L-1", project="p", started="t", stop_reason="fixed_point",
                budget=LoopBudget(max_sessions=1), bogus="x")
    with pytest.raises(ValidationError):
        LoopRun(id="a/b", project="p", started="t", stop_reason="fixed_point",
                budget=LoopBudget(max_sessions=1))


def test_loop_run_exposes_next_steps():
    run = _sample_run()
    assert run.has_next_steps()
    assert "verify F-0007" in run.next_steps()
    barren = run.model_copy(update={"body": "## Summary\n\nnothing"})
    assert not barren.has_next_steps()
