"""Feature 004 slice T007 — CLI wiring for ``playbook sibling-hunt``.

Test-first and HERMETIC: SIBLING HUNT is read-only, so every test here passes
with no Docker, no network, and nothing executes untrusted target code. The
command mirrors ``playbook discover``/``verify``: it runs a ``SiblingHuntSession``
through ``run_session`` behind the ``HermesUltraCodeGate`` and prints the record
via ``_echo_session``. ``--sibling`` is repeatable. A ``StoreError`` (unknown
project or finding) exits non-zero with a message, matching existing handling.

No CLI path enables execution or widens authority.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from deepthought.cli import app
from deepthought.schema import FindingStatus
from deepthought.store import FileStore

from .conftest import make_finding, make_project

runner = CliRunner()
SIBLINGS = str(Path(__file__).parent / "fixtures" / "siblings.sarif")


def _seeded_state(tmp_path, *, with_sibling=False):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(
        make_project(
            id="src-proj",
            git_url="https://example.test/src-proj",
            authorization_basis="permissive_oss",
            scope_allowlist=["app"],
        )
    )
    # A verified source finding whose typed summary derives inject:sql.
    finding = make_finding(
        id="F-0007",
        project="src-proj",
        status="verified",
        summary="py/sql-injection: user input reaches a SQL query in app/db.py",
        body="## Root cause\n\nA query.\n\n**Location:** `app/db.py:42`",
        evidence_ref=None,
    )
    ref = store.write_detail("S-seed", "evidence.txt", "seed evidence")
    finding.evidence_ref = ref
    store.save_finding(finding)
    if with_sibling:
        store.save_project(
            make_project(
                id="sib-proj",
                name="Sibling",
                git_url="https://example.test/sib-proj",
                authorization_basis="permissive_oss",
                scope_allowlist=["app"],
            )
        )
    return state, store


def test_sibling_hunt_runs_and_prints_the_record(tmp_path):
    state, store = _seeded_state(tmp_path)

    result = runner.invoke(
        app,
        ["playbook", "sibling-hunt", "--state", str(state),
         "--project", "src-proj", "--finding", "F-0007", "--sarif", SIBLINGS],
    )

    assert result.exit_code == 0, result.output
    assert "gate    : proceed" in result.output
    assert "close   : clean" in result.output
    # Two same-class in-scope variants written.
    variants = [
        f for f in store.list_findings(project="src-proj")
        if f.status is FindingStatus.candidate
    ]
    assert len(variants) == 2


def test_sibling_flag_is_repeatable(tmp_path):
    state, store = _seeded_state(tmp_path, with_sibling=True)

    result = runner.invoke(
        app,
        ["playbook", "sibling-hunt", "--state", str(state),
         "--project", "src-proj", "--finding", "F-0007",
         "--sibling", "sib-proj", "--sarif", SIBLINGS],
    )

    assert result.exit_code == 0, result.output
    assert store.list_findings(project="sib-proj")


def test_unknown_project_exits_non_zero(tmp_path):
    state = tmp_path / "state"
    FileStore(state)  # empty store

    result = runner.invoke(
        app,
        ["playbook", "sibling-hunt", "--state", str(state),
         "--project", "nope", "--finding", "F-0007"],
    )

    assert result.exit_code == 2
    assert "error" in result.output.lower()
