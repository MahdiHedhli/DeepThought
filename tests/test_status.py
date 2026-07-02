"""T013 — STATUS session.

Loads and summarizes findings and coverage; writes a session log with next
steps; changes no finding status.
"""

from __future__ import annotations

from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.schema import CloseState, FindingStatus, GateOutcome
from deepthought.sessions import StatusSession
from deepthought.store import FileStore

from .conftest import make_coverage, make_finding, make_project

GATE = HermesUltraCodeGate()


def _seeded_store(state_dir) -> FileStore:
    store = FileStore(state_dir)
    store.save_project(make_project())
    store.save_finding(make_finding(id="F-0001", status="candidate"))
    store.save_finding(make_finding(id="F-0002", status="candidate"))
    store.save_coverage(make_coverage())
    return store


def test_summarizes_findings_and_coverage(state_dir):
    store = _seeded_store(state_dir)
    record = run_session(store, GATE, StatusSession("php-src"))
    assert record.gate_outcome is GateOutcome.proceed
    assert record.close_state is CloseState.clean
    assert "2 finding(s)" in record.body
    assert "candidate" in record.body
    assert "1 coverage area(s)" in record.body


def test_unsafe_project_id_is_refused_not_crashed(state_dir):
    """A raw --project id that is not a safe record id (``../x``, ``org/repo``, a
    trailing newline) must produce a controlled refusal — never an unhandled
    Pydantic ValidationError from building the Session record."""
    store = _seeded_store(state_dir)
    for bad in ("../x", "org/repo", "a b", "F-0001\n", ".."):
        record = run_session(store, GATE, StatusSession(bad))
        assert record.gate_outcome is GateOutcome.refuse, bad
        assert "invalid project id" in (record.body or "").lower(), bad
        # the refused session logged nothing about a real project
        assert record.project is None, bad


def test_writes_next_steps(state_dir):
    store = _seeded_store(state_dir)
    record = run_session(store, GATE, StatusSession("php-src"))
    assert record.has_next_steps()
    assert record.next_steps()


def test_changes_no_finding_status(state_dir):
    store = _seeded_store(state_dir)
    before = {f.id: f.status for f in store.list_findings(project="php-src")}
    run_session(store, GATE, StatusSession("php-src"))
    after = {f.id: f.status for f in store.list_findings(project="php-src")}
    assert before == after
    assert all(s is FindingStatus.candidate for s in after.values())


def test_status_links_session_to_project(state_dir):
    store = _seeded_store(state_dir)
    record = run_session(store, GATE, StatusSession("php-src"))
    assert record.project == "php-src"
    # No findings were touched by a read-only status session.
    assert record.findings_touched == []
