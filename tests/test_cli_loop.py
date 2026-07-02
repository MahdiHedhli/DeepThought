"""T606 — the `deepthought loop` verb (feature 006).

Runs the bounded, gated autonomous loop and prints its trace and governed stop
reason. A missing budget is refused; a missing project is a governed refusal
(exit 0). The command drives the existing verbs — it transmits nothing.
"""

from __future__ import annotations

from typer.testing import CliRunner

from deepthought.cli import app
from deepthought.store import FileStore

runner = CliRunner()


def _register(state, target_dir):
    return runner.invoke(
        app,
        [
            "playbook", "new-project", "--state", str(state),
            "--name", "Local target", "--source-type", "open_source",
            "--local-path", str(target_dir), "--basis", "own_code", "--scope", "src",
        ],
    )


def test_loop_runs_and_reports_a_governed_stop(tmp_path):
    state = tmp_path / "state"
    target = tmp_path / "repo"
    target.mkdir()
    (target / "README").write_text("x")
    assert _register(state, target).exit_code == 0
    pid = FileStore(state).list_projects()[0].id  # derived from the local_path tail

    result = runner.invoke(
        app, ["loop", "--project", pid, "--state", str(state), "--max-sessions", "20"]
    )
    assert result.exit_code == 0, result.output
    out = result.output.lower()
    assert "stop" in out and ("fixed_point" in out or "hard_stop" in out)
    assert "status" in out  # the trace lists the sessions it ran
    # a LoopRun was persisted
    assert FileStore(state).list_loop_runs()


def test_loop_requires_a_budget(tmp_path):
    state = tmp_path / "state"
    target = tmp_path / "repo"
    target.mkdir()
    _register(state, target)
    result = runner.invoke(app, ["loop", "--project", "local-target", "--state", str(state)])
    assert result.exit_code != 0
    assert "budget" in result.output.lower() or "limit" in result.output.lower()


def test_loop_missing_project_is_a_governed_refusal(tmp_path):
    state = tmp_path / "state"
    (tmp_path / "repo").mkdir()
    _register(state, tmp_path / "repo")
    result = runner.invoke(
        app, ["loop", "--project", "nope", "--state", str(state), "--max-sessions", "5"]
    )
    # a governed refusal is a normal (exit 0) outcome, not an error
    assert result.exit_code == 0, result.output
    assert "gate_refused" in result.output or "not registered" in result.output.lower()
