"""T008 — the ``check`` command logic.

Passes on consistent state; fails on schema violation, illegal lifecycle state,
orphan reference, duplicate project identity, and any finding whose OSV does not
conform. A check that raises is a failed check.
"""

from __future__ import annotations

import deepthought.check as check_mod
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


# --- 005: disclosure-draft conformance is part of the gate ------------------


def test_passes_validates_csaf_and_openvex(state_dir):
    """A consistent finding also produces conformant CSAF and OpenVEX drafts, so
    the gate (which now validates both) stays green."""
    store = _consistent_store(state_dir)
    report = run_check(store)
    assert report.ok, report.errors


def test_fails_on_malformed_csaf_draft(state_dir, monkeypatch):
    store = _consistent_store(state_dir)
    monkeypatch.setattr(check_mod, "finding_to_csaf", lambda f: {"document": {}})
    report = run_check(store)
    assert not report.ok
    assert any("CSAF non-conformance" in e for e in report.errors)


def test_fails_on_malformed_openvex_draft(state_dir, monkeypatch):
    store = _consistent_store(state_dir)
    monkeypatch.setattr(check_mod, "finding_to_openvex", lambda f: {"statements": []})
    report = run_check(store)
    assert not report.ok
    assert any("OpenVEX non-conformance" in e for e in report.errors)


def test_raising_disclosure_exporter_is_a_failed_check_not_a_crash(state_dir, monkeypatch):
    store = _consistent_store(state_dir)

    def _boom(_f):
        raise RuntimeError("exporter exploded")

    monkeypatch.setattr(check_mod, "finding_to_csaf", _boom)
    report = run_check(store)
    assert not report.ok
    assert any("check raised" in e for e in report.errors)


def test_check_validates_persisted_disclosure_drafts(state_dir):
    """A corrupted PERSISTED disclosure draft (not just a re-derivation) fails the
    gate — check reads the actual detail artifacts the session wrote."""
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.sessions import DisclosureSession

    store = FileStore(state_dir)
    store.save_project(make_project())
    ev = store.write_detail("S-seed", "evidence.txt", "resolving evidence")
    store.save_finding(make_finding(status="verified", evidence_ref=ev))

    session = DisclosureSession("php-src", "F-0007")
    run_session(store, HermesUltraCodeGate(), session)
    assert run_check(store).ok, run_check(store).errors  # fresh drafts are conformant

    # Corrupt the persisted CSAF draft to a valid-JSON but schema-invalid doc.
    ref = session.artifact_refs["disclosure-csaf.json"]
    (store.root / ref).write_text('{"document": {}}', encoding="utf-8")
    report = run_check(store)
    assert not report.ok
    assert any("disclosure draft" in e for e in report.errors)


def test_check_fails_when_a_persisted_disclosure_draft_is_deleted(state_dir):
    """A drafting session (artifacts present) whose CSAF/OpenVEX draft was DELETED
    fails the gate — a missing expected draft is distinguished from a refusal."""
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.sessions import DisclosureSession

    store = FileStore(state_dir)
    store.save_project(make_project())
    ev = store.write_detail("S-seed", "evidence.txt", "resolving evidence")
    store.save_finding(make_finding(status="verified", evidence_ref=ev))

    session = DisclosureSession("php-src", "F-0007")
    run_session(store, HermesUltraCodeGate(), session)
    assert run_check(store).ok

    # Delete just the OpenVEX draft; the session's record still shows it drafted.
    (store.root / session.artifact_refs["disclosure-openvex.json"]).unlink()
    report = run_check(store)
    assert not report.ok
    assert any("missing expected draft" in e for e in report.errors)


def test_check_fails_when_all_disclosure_drafts_are_deleted(state_dir):
    """Even deleting the ENTIRE draft set fails the gate — the record-level
    findings_touched signal (not artifact presence) marks the drafting session."""
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.sessions import DisclosureSession

    store = FileStore(state_dir)
    store.save_project(make_project())
    ev = store.write_detail("S-seed", "evidence.txt", "resolving evidence")
    store.save_finding(make_finding(status="verified", evidence_ref=ev))

    session = DisclosureSession("php-src", "F-0007")
    record = run_session(store, HermesUltraCodeGate(), session)
    assert run_check(store).ok

    # Wipe every persisted draft; the Session record still says it drafted.
    for ref in session.artifact_refs.values():
        (store.root / ref).unlink()
    report = run_check(store)
    assert not report.ok
    assert any("missing expected draft" in e for e in report.errors)


def test_check_requires_the_non_schema_disclosure_artifacts_too(state_dir):
    """Deleting the advisory or CVE-draft artifact (not schema-gated, but part of
    the human-review set) still fails the gate via the existence check."""
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.sessions import DisclosureSession

    for name in ("disclosure-advisory.md", "disclosure-cve-draft.json"):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            store = FileStore(Path(d) / "state")
            store.save_project(make_project())
            ev = store.write_detail("S-seed", "evidence.txt", "resolving evidence")
            store.save_finding(make_finding(status="verified", evidence_ref=ev))
            session = DisclosureSession("php-src", "F-0007")
            run_session(store, HermesUltraCodeGate(), session)
            assert run_check(store).ok

            (store.root / session.artifact_refs[name]).unlink()
            report = run_check(store)
            assert not report.ok, name
            assert any("missing expected draft" in e for e in report.errors)


def test_check_validates_the_persisted_cve_draft_json(state_dir):
    """The persisted CVE draft is parsed + validated (tolerant of the sentinel):
    corrupt JSON there fails the gate, even though it is not schema-submittable."""
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.sessions import DisclosureSession

    store = FileStore(state_dir)
    store.save_project(make_project())
    ev = store.write_detail("S-seed", "evidence.txt", "resolving evidence")
    store.save_finding(make_finding(status="verified", evidence_ref=ev))

    session = DisclosureSession("php-src", "F-0007")
    run_session(store, HermesUltraCodeGate(), session)
    assert run_check(store).ok  # the well-formed cve draft (with sentinel) passes

    (store.root / session.artifact_refs["disclosure-cve-draft.json"]).write_text(
        "{ not json", encoding="utf-8"
    )
    report = run_check(store)
    assert not report.ok
    assert any("cve-draft" in e for e in report.errors)
