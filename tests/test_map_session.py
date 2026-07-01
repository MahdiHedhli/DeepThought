"""Feature 002 slice 2 — MAP session.

MAP reasons over code READ-ONLY: it walks the in-scope areas of a project under
a root and records Coverage with ``method='read'``. It executes nothing, fetches
nothing, and never widens scope. It runs through the harness like any session:
it passes the gate, teaches back coverage and next steps, and closes clean.
"""

from __future__ import annotations

from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.schema import (
    CloseState,
    CoverageDepth,
    CoverageMethod,
    GateOutcome,
    SessionType,
)
from deepthought.sessions import MapSession
from deepthought.store import FileStore

from .conftest import make_project

GATE = HermesUltraCodeGate()


def _repo_with_scope(tmp_path):
    """A local repo whose two in-scope dirs hold files and a third is empty."""
    repo = tmp_path / "repo"
    (repo / "ext" / "soap").mkdir(parents=True)
    (repo / "ext" / "soap" / "soap.c").write_text("int main(){}\n", encoding="utf-8")
    (repo / "ext" / "soap" / "php_encoding.c").write_text("/* x */\n", encoding="utf-8")
    (repo / "ext" / "standard").mkdir(parents=True)
    (repo / "ext" / "standard" / "string.c").write_text("char* s;\n", encoding="utf-8")
    # An out-of-scope dir that MUST NOT be mapped.
    (repo / "ext" / "secret").mkdir(parents=True)
    (repo / "ext" / "secret" / "keys.c").write_text("secret\n", encoding="utf-8")
    return repo


def _seeded_store(state_dir, repo):
    store = FileStore(state_dir)
    store.save_project(
        make_project(
            local_path=str(repo),
            git_url=None,
            scope_allowlist=["ext/soap", "ext/standard"],
        )
    )
    return store


def test_map_records_coverage_read_over_in_scope_dirs(tmp_path, state_dir):
    repo = _repo_with_scope(tmp_path)
    store = _seeded_store(state_dir, repo)

    run_session(store, GATE, MapSession("php-src", root=str(repo)))

    coverage = {c.area: c for c in store.list_coverage(project="php-src")}
    # Exactly the two in-scope areas were mapped; the out-of-scope dir was not.
    assert set(coverage) == {"ext/soap", "ext/standard"}
    for cov in coverage.values():
        assert cov.method is CoverageMethod.read
        assert cov.project == "php-src"


def test_map_depth_reflects_files_found(tmp_path, state_dir):
    repo = _repo_with_scope(tmp_path)
    store = _seeded_store(state_dir, repo)

    run_session(store, GATE, MapSession("php-src", root=str(repo)))

    coverage = {c.area: c for c in store.list_coverage(project="php-src")}
    # Both in-scope dirs hold files, so both are 'explored'.
    assert coverage["ext/soap"].depth is CoverageDepth.explored
    assert coverage["ext/standard"].depth is CoverageDepth.explored


def test_map_touches_empty_in_scope_area(tmp_path, state_dir):
    repo = tmp_path / "repo"
    (repo / "ext" / "soap").mkdir(parents=True)
    (repo / "ext" / "soap" / "soap.c").write_text("x\n", encoding="utf-8")
    # An in-scope area that exists but holds no files.
    (repo / "ext" / "empty").mkdir(parents=True)
    store = FileStore(state_dir)
    store.save_project(
        make_project(
            local_path=str(repo),
            git_url=None,
            scope_allowlist=["ext/soap", "ext/empty"],
        )
    )

    run_session(store, GATE, MapSession("php-src", root=str(repo)))

    coverage = {c.area: c for c in store.list_coverage(project="php-src")}
    assert coverage["ext/soap"].depth is CoverageDepth.explored
    assert coverage["ext/empty"].depth is CoverageDepth.touched


def test_map_runs_through_harness_gate_proceeds_and_closes_clean(tmp_path, state_dir):
    repo = _repo_with_scope(tmp_path)
    store = _seeded_store(state_dir, repo)

    record = run_session(store, GATE, MapSession("php-src", root=str(repo)))

    assert record.type is SessionType.map
    assert record.gate_outcome is GateOutcome.proceed
    assert record.close_state is CloseState.clean
    assert record.project == "php-src"
    assert record.has_next_steps()


def test_map_sets_coverage_changed_refs(tmp_path, state_dir):
    repo = _repo_with_scope(tmp_path)
    store = _seeded_store(state_dir, repo)

    record = run_session(store, GATE, MapSession("php-src", root=str(repo)))

    persisted = {c.ref for c in store.list_coverage(project="php-src")}
    assert set(record.coverage_changed) == persisted
    assert persisted  # non-empty


def test_map_last_session_links_to_the_running_session(tmp_path, state_dir):
    repo = _repo_with_scope(tmp_path)
    store = _seeded_store(state_dir, repo)

    record = run_session(store, GATE, MapSession("php-src", root=str(repo)))

    for cov in store.list_coverage(project="php-src"):
        assert cov.last_session == record.id


def test_map_root_defaults_to_project_local_path(tmp_path, state_dir):
    repo = _repo_with_scope(tmp_path)
    store = _seeded_store(state_dir, repo)

    # No explicit root: MapSession must fall back to the project's local_path.
    record = run_session(store, GATE, MapSession("php-src"))

    assert record.close_state is CloseState.clean
    assert {c.area for c in store.list_coverage(project="php-src")} == {
        "ext/soap",
        "ext/standard",
    }


def test_map_missing_root_closes_with_gap_in_next_steps(state_dir, tmp_path):
    """A project with no resolvable root must not crash: MAP records the gap."""
    store = FileStore(state_dir)
    missing = tmp_path / "does-not-exist"
    store.save_project(
        make_project(
            local_path=str(missing),
            git_url=None,
            scope_allowlist=["ext/soap"],
        )
    )

    record = run_session(store, GATE, MapSession("php-src", root=str(missing)))

    # Closeable outcome (has next steps) that records the gap; no coverage written.
    assert record.gate_outcome is GateOutcome.proceed
    assert record.close_state is CloseState.clean
    assert record.has_next_steps()
    assert store.list_coverage(project="php-src") == []


def test_map_none_root_and_no_local_path_records_gap(state_dir):
    """No root argument and no project local_path: still closeable, no crash."""
    store = FileStore(state_dir)
    # A git-only project (no local_path) gives MapSession nothing to walk.
    store.save_project(
        make_project(
            git_url="https://github.com/php/php-src",
            local_path=None,
            scope_allowlist=["ext/soap"],
        )
    )

    record = run_session(store, GATE, MapSession("php-src"))

    assert record.close_state is CloseState.clean
    assert record.has_next_steps()
    assert store.list_coverage(project="php-src") == []
