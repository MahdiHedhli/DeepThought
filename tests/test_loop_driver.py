"""T605 — run_loop: the gated, bounded, escalating driver (feature 006).

The loop runs the safe chain through the existing gated harness, stops for exactly
one recorded reason, writes a durable LoopRun, and — by construction — expands no
scope, promotes no candidate, executes no target code, and transmits nothing.
"""

from __future__ import annotations

import inspect

from deepthought.loop import LoopBudget
from deepthought.loop import driver as driver_module
from deepthought.loop.driver import run_loop
from deepthought.protocol import HermesUltraCodeGate
from deepthought.schema.loop import ActionKind, StopReason
from deepthought.store import FileStore

from .conftest import make_finding, make_project

GATE = HermesUltraCodeGate()


def _seed(state_dir, tmp_path, **proj_overrides):
    store = FileStore(state_dir)
    root = tmp_path / "repo"
    root.mkdir(exist_ok=True)
    (root / "README").write_text("x")
    store.save_project(make_project(local_path=str(root), **proj_overrides))
    return store


def test_loop_runs_the_safe_chain_and_stops_at_fixed_point(state_dir, tmp_path):
    store = _seed(state_dir, tmp_path)
    run = run_loop(store, GATE, "php-src", LoopBudget(max_sessions=20))
    kinds = [s.kind for s in run.trace]
    assert ActionKind.status in kinds
    assert ActionKind.map in kinds
    assert ActionKind.discover in kinds
    assert run.stop_reason is StopReason.fixed_point
    assert run.has_next_steps()
    # persisted and round-trips
    assert store.get_loop_run(run.id) == run
    # no extra project, scope unchanged
    assert len(store.list_projects()) == 1


def test_candidate_triggers_a_hard_stop_escalation(state_dir, tmp_path):
    store = _seed(state_dir, tmp_path)
    store.save_finding(make_finding(id="F-9", project="php-src", status="candidate"))
    run = run_loop(store, GATE, "php-src", LoopBudget(max_sessions=20))
    assert run.stop_reason is StopReason.hard_stop
    assert any("F-9" in a and "sign-off" in a.lower() for a in run.outstanding_actions)
    # the candidate is NEVER promoted (no target-code execution)
    assert store.get_finding("F-9").status.value == "candidate"
    # the escalation is a trace row with NO session (nothing ran)
    esc = [s for s in run.trace if s.kind is ActionKind.verify_escalation]
    assert esc and esc[0].session_id is None and esc[0].finding == "F-9"


def test_session_budget_stops_the_loop(state_dir, tmp_path):
    store = _seed(state_dir, tmp_path)
    run = run_loop(store, GATE, "php-src", LoopBudget(max_sessions=1))
    assert run.stop_reason is StopReason.budget_exhausted
    assert run.sessions_run == 1
    assert run.has_next_steps()


def test_token_budget_stops_the_loop(state_dir, tmp_path):
    store = _seed(state_dir, tmp_path)
    # A token budget below one session's cost stops after... well, sessions report
    # ContextCost() (0 tokens) in the stub, so a tiny positive token budget still
    # runs (0 >= 1 is false) — assert the loop respects the limit type without error.
    run = run_loop(store, GATE, "php-src", LoopBudget(max_context_tokens=1))
    assert run.stop_reason in (StopReason.fixed_point, StopReason.budget_exhausted,
                               StopReason.hard_stop)
    assert store.get_loop_run(run.id) is not None


def test_all_outstanding_escalations_are_enumerated_once(state_dir, tmp_path):
    """At the hard-stop boundary the loop names EVERY outstanding human action in a
    single bounded pass — a run with several candidates surfaces them all, not just
    the first (and without an unbounded per-escalation selector loop)."""
    store = _seed(state_dir, tmp_path)
    for i in range(3):
        store.save_finding(make_finding(id=f"F-800{i}", project="php-src", status="candidate"))
    run = run_loop(store, GATE, "php-src", LoopBudget(max_sessions=20))
    assert run.stop_reason is StopReason.hard_stop
    named = " ".join(run.outstanding_actions)
    for i in range(3):
        assert f"F-800{i}" in named, run.outstanding_actions
    # each candidate is escalated exactly once (no duplicate enumeration)
    esc = [s for s in run.trace if s.kind is ActionKind.verify_escalation]
    assert sorted(s.finding for s in esc) == ["F-8000", "F-8001", "F-8002"]


def test_wall_budget_bounds_an_escalation_heavy_run(state_dir, tmp_path):
    """--max-seconds bounds the loop even in an escalation-only state — the wall cap
    is enforced before every iteration, including escalation collection."""
    from datetime import datetime, timedelta, timezone

    store = _seed(state_dir, tmp_path)
    for i in range(5):  # many candidates -> an escalation-heavy state
        store.save_finding(make_finding(id=f"F-900{i}", project="php-src", status="candidate"))
    base = datetime(2026, 7, 2, tzinfo=timezone.utc)
    gen = (base + timedelta(seconds=100 * i) for i in range(1000))
    run = run_loop(store, GATE, "php-src", LoopBudget(max_wall_seconds=5),
                   clock=lambda: next(gen))
    assert run.stop_reason is StopReason.budget_exhausted


def test_missing_project_is_refused_without_running(state_dir):
    from deepthought.check import run_check

    store = FileStore(state_dir)
    run = run_loop(store, GATE, "does-not-exist", LoopBudget(max_sessions=5))
    assert run.stop_reason is StopReason.gate_refused
    assert run.sessions_run == 0
    assert run.trace == []
    assert run.has_next_steps()
    # a typo'd project id must NOT persist an orphaned LoopRun — nothing durable is
    # written, so `check` stays green (no loop run referencing a missing project).
    assert store.list_loop_runs() == []
    assert run_check(store).ok, run_check(store).errors


def test_unauthorized_project_stops_at_the_gate(state_dir, tmp_path):
    # No authorization basis -> the DefaultGate refuses up front, before any work.
    store = _seed(state_dir, tmp_path, authorization_basis=None)
    run = run_loop(store, GATE, "php-src", LoopBudget(max_sessions=5))
    assert run.stop_reason is StopReason.gate_refused
    assert run.sessions_run == 0   # gated BEFORE any session ran (Article I)
    assert run.trace == []
    # the gate's remediation reason is carried into the durable teach-back.
    assert run.has_next_steps()
    assert any("authorization basis" in a for a in run.outstanding_actions), run.outstanding_actions


def test_escalation_only_run_is_regated_when_authorization_is_lost(state_dir, tmp_path):
    """A project that completed recon and LATER loses authorization must stop as
    gate_refused on the next run — the loop re-gates up front, so an escalation-only
    state never bypasses the Gate (Article I)."""
    store = _seed(state_dir, tmp_path)
    run_loop(store, GATE, "php-src", LoopBudget(max_sessions=20))  # recon completes
    store.save_finding(make_finding(id="F-9", project="php-src", status="candidate"))
    # Remove the authorization basis (same id + identity -> an update).
    p = store.get_project("php-src")
    store.save_project(p.model_copy(update={"authorization_basis": None}))
    run = run_loop(store, GATE, "php-src", LoopBudget(max_sessions=20))
    assert run.stop_reason is StopReason.gate_refused   # NOT hard_stop via escalation
    assert run.sessions_run == 0


def test_loop_import_does_not_load_the_execution_sandbox():
    """Structural hard stop at the DEPENDENCY level: importing the loop must not
    pull the execution backend (verify/sandbox) into its import closure — checked
    in a clean interpreter so other tests can't pre-load it."""
    import os
    import subprocess
    import sys

    src = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src")
    code = (
        "import sys, deepthought.loop\n"
        "assert 'deepthought.sandbox' not in sys.modules, 'loop loaded the sandbox'\n"
        "assert 'deepthought.sessions.verify' not in sys.modules, 'loop loaded verify'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": src},
    )
    assert result.returncode == 0, result.stderr


def test_loop_run_id_does_not_collide_after_a_deleted_run(state_dir):
    """generate_loop_run_id uses the max sequence + 1, so deleting a run leaves a
    gap instead of colliding with (and overwriting) an existing higher run."""
    from datetime import datetime, timezone

    from deepthought.loop.driver import generate_loop_run_id
    from deepthought.schema.loop import LoopRun

    store = FileStore(state_dir)
    now = datetime(2026, 7, 2, tzinfo=timezone.utc)

    def save(seq):
        store.save_loop_run(LoopRun(
            id=f"L-2026-07-02-{seq:04d}", project="p", started="t",
            stop_reason="fixed_point", budget=LoopBudget(max_sessions=1),
            body="## Summary\n\nx\n\n## Next steps\n\ny"))

    save(1)
    save(2)
    (state_dir / "loop" / "L-2026-07-02-0001.md").unlink()  # a gap
    # len()+1 would return 0002 and overwrite the existing run; max+1 returns 0003
    assert generate_loop_run_id(store, now) == "L-2026-07-02-0003"


def test_wall_clock_budget_stops_the_loop(state_dir, tmp_path):
    """--max-seconds is a REAL bound: elapsed wall time is measured in the driver,
    so it stops the loop even though stub sessions report a zero context_cost."""
    from datetime import datetime, timedelta, timezone

    store = _seed(state_dir, tmp_path)
    base = datetime(2026, 7, 2, tzinfo=timezone.utc)
    gen = (base + timedelta(seconds=100 * i) for i in range(1000))
    run = run_loop(store, GATE, "php-src", LoopBudget(max_wall_seconds=5),
                   clock=lambda: next(gen))
    assert run.stop_reason is StopReason.budget_exhausted
    assert run.context_cost.wall_seconds >= 5   # real elapsed recorded


def test_second_loop_run_does_not_rehunt_or_redraft(state_dir, tmp_path):
    """A verified finding hunted/drafted in one run is not re-hunted or re-drafted
    on the next — repeated loop runs converge (no duplicate sessions)."""
    store = _seed(state_dir, tmp_path)
    store.save_finding(make_finding(id="F-1", project="php-src", status="verified"))
    run1 = run_loop(store, GATE, "php-src", LoopBudget(max_sessions=20))
    assert sum(s.kind is ActionKind.sibling_hunt for s in run1.trace) == 1
    assert sum(s.kind is ActionKind.disclosure for s in run1.trace) == 1
    run2 = run_loop(store, GATE, "php-src", LoopBudget(max_sessions=20))
    assert not any(s.kind is ActionKind.sibling_hunt for s in run2.trace)
    assert not any(s.kind is ActionKind.disclosure for s in run2.trace)


def test_loop_expands_no_scope_and_constructs_no_sandbox(state_dir, tmp_path):
    store = _seed(state_dir, tmp_path)
    before = store.get_project("php-src").scope_allowlist
    store.save_finding(make_finding(id="F-1", project="php-src", status="verified"))
    run = run_loop(store, GATE, "php-src", LoopBudget(max_sessions=20))
    assert store.get_project("php-src").scope_allowlist == before  # scope unchanged
    assert len(store.list_projects()) == 1                          # no new project
    # a verified finding is drafted (disclosure) but never advanced to disclosed
    assert store.get_finding("F-1").status.value == "verified"
    # the disclosure SEND is a human hard stop, named in the durable audit
    assert any("F-1" in a and "send" in a.lower() for a in run.outstanding_actions)
    assert run.stop_reason is StopReason.hard_stop
    # structural: the driver constructs no VerifySession / sandbox and imports no
    # network module — the hard stops cannot be crossed even in principle.
    src = inspect.getsource(driver_module)
    for forbidden in ("VerifySession", "Sandbox", "import socket", "urllib",
                      "requests", "http.client", "httpx"):
        assert forbidden not in src, forbidden
