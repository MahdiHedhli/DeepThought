"""Feature 002 slice 4 — CLI wiring for ``playbook map`` and ``playbook discover``.

Both run their session through the harness with the DefaultGate, follow the
existing ``_echo_session`` output shape, and leave ``check`` green. MAP records
coverage READ-ONLY; DISCOVER creates candidate findings from SARIF. Neither
executes target code nor widens scope.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from deepthought.cli import app
from deepthought.store import FileStore

from .conftest import make_project

runner = CliRunner()
FIXTURE = str(Path(__file__).parent / "fixtures" / "sample.sarif")


def _repo_with_scope(tmp_path):
    """A local repo with two in-scope dirs holding files."""
    repo = tmp_path / "repo"
    (repo / "ext" / "soap").mkdir(parents=True)
    (repo / "ext" / "soap" / "soap.c").write_text("int main(){}\n", encoding="utf-8")
    (repo / "ext" / "standard").mkdir(parents=True)
    (repo / "ext" / "standard" / "string.c").write_text("char* s;\n", encoding="utf-8")
    return repo


def _seed_project(state, repo):
    store = FileStore(state)
    store.save_project(
        make_project(
            local_path=str(repo),
            git_url=None,
            scope_allowlist=["ext/soap", "ext/standard"],
        )
    )
    return store


# --- playbook map -----------------------------------------------------------


def test_playbook_map_records_coverage(tmp_path):
    state = tmp_path / "state"
    repo = _repo_with_scope(tmp_path)
    store = _seed_project(state, repo)

    result = runner.invoke(
        app,
        ["playbook", "map", "--state", str(state), "--project", "php-src"],
    )
    assert result.exit_code == 0, result.output
    # Follows the _echo_session shape.
    assert "gate    : proceed" in result.output
    assert "close   : clean" in result.output

    coverage = {c.area for c in store.list_coverage(project="php-src")}
    assert coverage == {"ext/soap", "ext/standard"}


def test_playbook_map_with_explicit_root(tmp_path):
    state = tmp_path / "state"
    repo = _repo_with_scope(tmp_path)
    # Seed the project with NO local_path; supply the checkout via --root.
    store = FileStore(state)
    store.save_project(
        make_project(
            local_path=None,
            git_url="https://github.com/php/php-src",
            scope_allowlist=["ext/soap", "ext/standard"],
        )
    )

    result = runner.invoke(
        app,
        [
            "playbook", "map",
            "--state", str(state),
            "--project", "php-src",
            "--root", str(repo),
        ],
    )
    assert result.exit_code == 0, result.output
    assert {c.area for c in store.list_coverage(project="php-src")} == {
        "ext/soap",
        "ext/standard",
    }


def test_playbook_map_unknown_project_errors(tmp_path):
    state = tmp_path / "state"
    FileStore(state)  # empty store
    result = runner.invoke(
        app,
        ["playbook", "map", "--state", str(state), "--project", "ghost"],
    )
    assert result.exit_code != 0


# --- playbook discover ------------------------------------------------------


def test_playbook_discover_creates_candidate_findings(tmp_path):
    state = tmp_path / "state"
    repo = _repo_with_scope(tmp_path)
    store = _seed_project(state, repo)

    result = runner.invoke(
        app,
        [
            "playbook", "discover",
            "--state", str(state),
            "--project", "php-src",
            "--sarif", FIXTURE,
        ],
    )
    assert result.exit_code == 0, result.output
    assert "gate    : proceed" in result.output
    assert "close   : clean" in result.output

    findings = store.list_findings(project="php-src")
    assert len(findings) == 3
    assert all(f.status.value == "candidate" for f in findings)


def test_playbook_discover_without_sarif_closes_clean(tmp_path):
    state = tmp_path / "state"
    repo = _repo_with_scope(tmp_path)
    store = _seed_project(state, repo)

    result = runner.invoke(
        app,
        ["playbook", "discover", "--state", str(state), "--project", "php-src"],
    )
    assert result.exit_code == 0, result.output
    assert "close   : clean" in result.output
    assert store.list_findings(project="php-src") == []


def test_playbook_discover_unknown_project_errors(tmp_path):
    state = tmp_path / "state"
    FileStore(state)
    result = runner.invoke(
        app,
        ["playbook", "discover", "--state", str(state), "--project", "ghost"],
    )
    assert result.exit_code != 0


# --- check stays green after discover ---------------------------------------


def test_check_green_after_discover(tmp_path):
    state = tmp_path / "state"
    repo = _repo_with_scope(tmp_path)
    _seed_project(state, repo)

    discover = runner.invoke(
        app,
        [
            "playbook", "discover",
            "--state", str(state),
            "--project", "php-src",
            "--sarif", FIXTURE,
        ],
    )
    assert discover.exit_code == 0, discover.output

    checked = runner.invoke(app, ["check", "--state", str(state)])
    assert checked.exit_code == 0, checked.output
    assert "OK" in checked.output


def test_map_then_discover_then_check_green(tmp_path):
    """The full 002 read-only pipeline end to end through the CLI stays clean."""
    state = tmp_path / "state"
    repo = _repo_with_scope(tmp_path)
    _seed_project(state, repo)

    mapped = runner.invoke(
        app, ["playbook", "map", "--state", str(state), "--project", "php-src"]
    )
    assert mapped.exit_code == 0, mapped.output

    discovered = runner.invoke(
        app,
        [
            "playbook", "discover",
            "--state", str(state),
            "--project", "php-src",
            "--sarif", FIXTURE,
        ],
    )
    assert discovered.exit_code == 0, discovered.output

    checked = runner.invoke(app, ["check", "--state", str(state)])
    assert checked.exit_code == 0, checked.output
