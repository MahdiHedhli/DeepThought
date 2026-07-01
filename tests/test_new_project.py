"""T012 — NEW PROJECT session.

Registers a project with basis and scope allowlist; refuses an unresolvable git
URL; refuses blackbox without authorization_ref; resolves to one project on a
repeat.
"""

from __future__ import annotations

from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.schema import CloseState, GateOutcome
from deepthought.sessions import NewProjectSession
from deepthought.store import FileStore

GATE = HermesUltraCodeGate()


def _resolves(_url: str) -> bool:
    return True


def _unresolvable(_url: str) -> bool:
    return False


def test_registers_project_with_basis_and_scope(state_dir):
    store = FileStore(state_dir)
    session = NewProjectSession(
        name="PHP src",
        source_type="open_source",
        git_url="https://github.com/php/php-src",
        authorization_basis="permissive_oss",
        scope_allowlist=["ext/soap", "ext/standard"],
        verify_url=_resolves,
    )
    record = run_session(store, GATE, session)
    assert record.gate_outcome is GateOutcome.proceed
    assert record.close_state is CloseState.clean

    project = store.get_project("php-src")
    assert project is not None
    assert project.authorization_basis.value == "permissive_oss"
    assert project.scope_allowlist == ["ext/soap", "ext/standard"]


def test_refuses_unresolvable_git_url(state_dir):
    store = FileStore(state_dir)
    session = NewProjectSession(
        name="Ghost",
        source_type="open_source",
        git_url="https://github.com/nope/does-not-exist",
        authorization_basis="permissive_oss",
        scope_allowlist=["src"],
        verify_url=_unresolvable,
    )
    record = run_session(store, GATE, session)
    # Authorization was fine (gate proceeds), but the work refuses and writes
    # nothing.
    assert "does not resolve" in record.body
    assert store.list_projects() == []


def test_refuses_blackbox_without_authorization_ref(state_dir):
    store = FileStore(state_dir)
    session = NewProjectSession(
        name="Target API",
        source_type="blackbox",
        git_url="https://api.example.test",
        authorization_basis="scoped_engagement",
        authorization_ref=None,
        scope_allowlist=["/v1"],
        verify_url=_resolves,
    )
    record = run_session(store, GATE, session)
    assert record.gate_outcome is GateOutcome.refuse
    assert store.list_projects() == []


def test_missing_basis_is_refused_by_gate(state_dir):
    store = FileStore(state_dir)
    session = NewProjectSession(
        name="No basis",
        source_type="open_source",
        git_url="https://github.com/x/y",
        authorization_basis=None,
        scope_allowlist=["src"],
        verify_url=_resolves,
    )
    record = run_session(store, GATE, session)
    assert record.gate_outcome is GateOutcome.refuse
    assert store.list_projects() == []


def test_resolves_to_one_project_on_repeat(state_dir):
    store = FileStore(state_dir)

    def make():
        return NewProjectSession(
            name="PHP src",
            source_type="open_source",
            git_url="https://github.com/php/php-src",
            authorization_basis="permissive_oss",
            scope_allowlist=["ext/soap"],
            verify_url=_resolves,
        )

    run_session(store, GATE, make())
    second = run_session(store, GATE, make())

    assert len(store.list_projects()) == 1
    assert "already registered" in second.body
