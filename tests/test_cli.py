"""T014 — the three verbs wired in the CLI.

playbook runs the protocol for a chosen type and lists findings; check validates
and fails hard; publish emits local artifacts only and asserts the human gate,
transmitting nothing.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from deepthought.cli import app
from deepthought.store import FileStore

from .conftest import make_finding, make_project

runner = CliRunner()


def _register(state, target_dir):
    return runner.invoke(
        app,
        [
            "playbook", "new-project",
            "--state", str(state),
            "--name", "Local target",
            "--source-type", "open_source",
            "--local-path", str(target_dir),
            "--basis", "own_code",
            "--scope", "src",
        ],
    )


def test_playbook_new_project_registers(tmp_path):
    state = tmp_path / "state"
    target = tmp_path / "repo"
    target.mkdir()
    result = _register(state, target)
    assert result.exit_code == 0, result.output
    assert "proceed" in result.output
    assert FileStore(state).list_projects()[0].authorization_basis.value == "own_code"


def test_playbook_new_project_gate_refuses_without_basis(tmp_path):
    state = tmp_path / "state"
    target = tmp_path / "repo"
    target.mkdir()
    result = runner.invoke(
        app,
        [
            "playbook", "new-project",
            "--state", str(state),
            "--name", "No basis",
            "--local-path", str(target),
            "--scope", "src",
        ],
    )
    assert result.exit_code == 0
    assert "refuse" in result.output
    assert FileStore(state).list_projects() == []


def test_playbook_status(tmp_path):
    state = tmp_path / "state"
    target = tmp_path / "repo"
    target.mkdir()
    _register(state, target)
    project_id = FileStore(state).list_projects()[0].id
    result = runner.invoke(
        app, ["playbook", "status", "--state", str(state), "--project", project_id]
    )
    assert result.exit_code == 0
    assert "No finding status was changed" in result.output


def test_playbook_findings_list(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())
    store.save_finding(make_finding(id="F-0001"))
    result = runner.invoke(app, ["playbook", "findings", "--state", str(state)])
    assert result.exit_code == 0
    assert "F-0001" in result.output
    assert "candidate" in result.output


def test_check_passes_and_fails(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())
    store.save_finding(make_finding())

    ok = runner.invoke(app, ["check", "--state", str(state)])
    assert ok.exit_code == 0
    assert "OK" in ok.output

    # Corrupt a record; check must fail hard.
    path = state / "findings" / "F-0007.md"
    path.write_text(path.read_text().replace("status: candidate", "status: bogus"))
    bad = runner.invoke(app, ["check", "--state", str(state)])
    assert bad.exit_code == 1
    assert "FAILED" in bad.output


def test_publish_emits_local_artifacts_and_asserts_human_gate(tmp_path):
    state = tmp_path / "state"
    out = tmp_path / "out"
    store = FileStore(state)
    store.save_project(make_project())
    store.save_finding(make_finding())

    result = runner.invoke(
        app, ["publish", "--state", str(state), "--out", str(out)]
    )
    assert result.exit_code == 0
    assert "HUMAN GATE" in result.output
    assert "nothing was transmitted" in result.output

    artifact = out / "x_F-0007.json"
    assert artifact.exists()
    osv = json.loads(artifact.read_text())
    assert osv["id"] == "x_F-0007"


def test_publish_refuses_when_check_is_red(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    # Orphan finding: no project → check fails → publish refused.
    store.save_finding(make_finding(project="ghost"))
    result = runner.invoke(app, ["publish", "--state", str(state)])
    assert result.exit_code == 1
    assert "refused" in result.output
