"""T012 — NEW PROJECT session.

Registers a project with basis and scope allowlist; refuses an unresolvable git
URL; refuses blackbox without authorization_ref; resolves to one project on a
repeat.
"""

from __future__ import annotations

from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.schema import CloseState, GateOutcome
from deepthought.sessions import NewProjectSession
from deepthought.sessions.new_project import default_verify_git_url
from deepthought.store import FileStore

GATE = HermesUltraCodeGate()


def _resolves(_url: str) -> bool:
    return True


def _unresolvable(_url: str) -> bool:
    return False


def test_default_verify_git_url_refuses_option_like_urls(monkeypatch):
    """The url is passed to ``git ls-remote``; a value starting with ``-`` would be
    parsed as a git OPTION rather than a repository (argument injection — e.g.
    ``--upload-pack=<cmd>`` can run a command). Such a url is refused WITHOUT ever
    spawning git."""
    import subprocess

    def _must_not_run(*_a, **_k):
        raise AssertionError("git must not be spawned for an option-like url")

    monkeypatch.setattr(subprocess, "run", _must_not_run)
    for hostile in ("--upload-pack=touch /tmp/pwned", "-x", "--output=/etc/cron.d/x", "-"):
        assert default_verify_git_url(hostile) is False


def test_default_verify_git_url_passes_url_positionally(monkeypatch):
    """A benign (non-existent) url reaches ``git ls-remote`` as a POSITIONAL arg
    after a ``--`` terminator, so it can never be reinterpreted as an option."""
    import subprocess

    captured = {}

    class _R:
        returncode = 2

    def _fake_run(argv, **_k):
        captured["argv"] = argv
        return _R()

    monkeypatch.setattr(subprocess, "run", _fake_run)
    assert default_verify_git_url("https://example.test/does-not-exist.git") is False
    argv = captured["argv"]
    assert "--" in argv
    assert argv.index("--") < argv.index("https://example.test/does-not-exist.git")


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


def test_derived_id_collision_is_refused_not_silently_overwritten(state_dir):
    """Two DISTINCT identities whose derived id collides (``_repo`` and ``repo``
    both normalise to ``repo``) must not silently overwrite: the first registers,
    the second is refused with a hint to disambiguate, and the first survives."""
    store = FileStore(state_dir)
    first = NewProjectSession(
        name="first", source_type="open_source", local_path="/repos/_repo",
        authorization_basis="permissive_oss", scope_allowlist=["app"], verify_url=_resolves,
    )
    run_session(store, GATE, first)
    second = NewProjectSession(
        name="second", source_type="open_source", local_path="/repos/repo",
        authorization_basis="permissive_oss", scope_allowlist=["app"], verify_url=_resolves,
    )
    record = run_session(store, GATE, second)
    assert "already registered" in record.body.lower()
    assert len(store.list_projects()) == 1
    assert store.get_project("repo").local_path == "/repos/_repo"  # first survived


def test_explicit_unsafe_project_id_is_refused_not_crashed(state_dir):
    """An explicit --project-id that is not a safe record id must produce a clean
    refusal, not a bare ValidationError from constructing the Project record."""
    store = FileStore(state_dir)
    for bad in ("org/repo", "../x", "a b", "-lead"):
        record = run_session(
            store, GATE,
            NewProjectSession(
                name="n", source_type="open_source", local_path="/repos/ok",
                authorization_basis="permissive_oss", scope_allowlist=["app"],
                project_id=bad, verify_url=_resolves,
            ),
        )
        assert "invalid project id" in record.body.lower(), bad
        assert store.list_projects() == [], bad


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
