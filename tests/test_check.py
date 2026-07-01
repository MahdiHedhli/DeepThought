"""T008 — the ``check`` command logic.

Passes on consistent state; fails on schema violation, illegal lifecycle state,
orphan reference, duplicate project identity, and any finding whose OSV does not
conform. A check that raises is a failed check.
"""

from __future__ import annotations

from deepthought.check import run_check
from deepthought.schema import FindingStatus
from deepthought.store import FileStore

from .conftest import make_finding, make_project


def _consistent_store(state_dir) -> FileStore:
    store = FileStore(state_dir)
    store.save_project(make_project())
    store.save_finding(make_finding(status="candidate"))
    return store


def test_passes_on_consistent_state(state_dir):
    store = _consistent_store(state_dir)
    report = run_check(store)
    assert report.ok, report.errors


def test_fails_on_schema_violation(state_dir):
    store = _consistent_store(state_dir)
    # Hand-corrupt a record: an invalid enum value.
    path = state_dir / "findings" / "F-0007.md"
    path.write_text(path.read_text().replace("status: candidate", "status: bogus"))
    report = run_check(store)
    assert not report.ok
    assert any("schema violation" in e for e in report.errors)


def test_fails_on_illegal_lifecycle_state(state_dir):
    store = FileStore(state_dir)
    store.save_project(make_project())
    # A verified finding whose evidence_ref does not resolve is illegal at rest.
    store.save_finding(
        make_finding(status="verified", evidence_ref="detail/S-x/missing.txt")
    )
    report = run_check(store)
    assert not report.ok
    assert any("verified" in e and "evidence_ref" in e for e in report.errors)


def test_fails_on_orphan_reference(state_dir):
    store = FileStore(state_dir)
    # Finding with no matching project.
    store.save_finding(make_finding(project="ghost"))
    report = run_check(store)
    assert not report.ok
    assert any("unknown project" in e for e in report.errors)


def test_fails_on_duplicate_project_identity(state_dir):
    store = FileStore(state_dir)
    store.save_project(make_project(id="php-src"))
    # Write a second project file directly with the same git_url identity,
    # bypassing the save guard, to simulate a corrupted store.
    dupe = make_project(id="php-src-2")
    (state_dir / "projects" / "php-src-2.md").write_text(dupe.to_markdown())
    report = run_check(store)
    assert not report.ok
    assert any("duplicate project identity" in e for e in report.errors)


def test_fails_on_non_conformant_osv(state_dir):
    store = FileStore(state_dir)
    store.save_project(make_project())
    # An ecosystem that is not in the OSV enum makes the OSV non-conformant.
    store.save_finding(
        make_finding(
            affected=[
                {"ecosystem": "NotARealEcosystem", "package": "x", "versions": ["1"]}
            ]
        )
    )
    report = run_check(store)
    assert not report.ok
    assert any("OSV non-conformance" in e for e in report.errors)


def test_check_that_raises_is_a_failed_check(state_dir):
    store = FileStore(state_dir)

    def boom():
        raise RuntimeError("store exploded")

    store.raw_records = boom  # type: ignore[assignment]
    report = run_check(store)
    assert not report.ok
    assert any("check raised" in e for e in report.errors)


def test_disclosed_without_cve_is_illegal_at_rest(state_dir):
    store = FileStore(state_dir)
    store.save_project(make_project())
    ref = store.write_detail("S-x", "repro.txt", "trace")
    store.save_finding(
        make_finding(status="disclosed", evidence_ref=ref, cve=None)
    )
    report = run_check(store)
    assert not report.ok
    assert any("disclosed without a cve" in e for e in report.errors)
