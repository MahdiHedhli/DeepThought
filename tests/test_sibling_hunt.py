"""Feature 004 — SIBLING HUNT session (read-only variant analysis).

SIBLING HUNT takes a VERIFIED finding, derives a variant signature from its typed
fields, gates EACH target independently, and hunts read-only for sibling
instances of the same bug class — writing candidate variant findings and read
coverage, ingesting exactly one worker envelope per gated-proceed target. It
mirrors DISCOVER's shape and reuses its firewall, adding a same-class filter and
a per-project authority firewall.

Structure of this file:
* T003 — same-project path (gate, refuse rules, variants, same-class filter,
  scope containment, coverage, injection inertness).
* T004 — cross-project path (per-sibling gate, authority invariants).
* T005 — package exports.
* T006 — OSV-validity of every variant.
* T008 — the `check` gate holds over variant output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deepthought.export.osv import finding_to_osv, validate_osv
from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.schema import (
    CloseState,
    CoverageMethod,
    FindingStatus,
    GateOutcome,
    SessionType,
)
from deepthought.store import FileStore

from .conftest import make_finding, make_project

GATE = HermesUltraCodeGate()
SIBLINGS = str(Path(__file__).parent / "fixtures" / "siblings.sarif")


# --- helpers ----------------------------------------------------------------


def _verified_sql_finding(project: str = "src-proj", finding_id: str = "F-0007"):
    """A VERIFIED source finding whose typed fields derive an inject:sql class.

    The summary carries the py/sql-injection ruleId token, so the session's
    source-signature derivation (closed lookup over the typed summary) yields the
    inject:sql capability WITHOUT needing a persisted primitive.
    """
    return make_finding(
        id=finding_id,
        project=project,
        status="verified",
        summary="py/sql-injection: user input reaches a SQL query in app/db.py",
        body="## Root cause\n\nUser input reaches a query.\n\n**Location:** `app/db.py:42`",
        # A verified finding at rest needs a resolving evidence_ref for check; but
        # the source is only READ here, so we leave it candidate-shaped for the
        # in-memory tests and rely on the store seeding below to set it verified.
        evidence_ref=None,
    )


def _seed_source(store: FileStore, project_id: str = "src-proj") -> None:
    """Register the source project (scope app) and a verified source finding.

    The verified finding is written directly at status=verified with a resolving
    evidence_ref so `check` stays green; SIBLING HUNT only reads it.
    """
    store.save_project(
        make_project(
            id=project_id,
            git_url=f"https://example.test/{project_id}",
            authorization_basis="permissive_oss",
            scope_allowlist=["app"],
        )
    )
    finding = _verified_sql_finding(project=project_id)
    # Page a resolving evidence artifact so a verified finding is check-clean.
    ref = store.write_detail("S-seed", "evidence.txt", "seed evidence for the source")
    finding.evidence_ref = ref
    store.save_finding(finding)


def _run(store, **kwargs):
    from deepthought.sessions import SiblingHuntSession

    return run_session(store, GATE, SiblingHuntSession(**kwargs))


# --- gate: proceed / hold / refuse ------------------------------------------


def test_sibling_hunt_runs_through_harness_and_closes_clean(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)

    record = _run(
        store,
        project_id="src-proj",
        finding_id="F-0007",
        sarif_path=SIBLINGS,
        root=None,
    )

    assert record.type is SessionType.sibling_hunt
    assert record.gate_outcome is GateOutcome.proceed
    assert record.close_state is CloseState.clean
    assert record.project == "src-proj"
    assert record.has_next_steps()


def test_empty_scope_source_holds_at_gate(state_dir):
    store = FileStore(state_dir)
    store.save_project(
        make_project(id="src-proj", git_url="https://example.test/x", scope_allowlist=[])
    )
    finding = _verified_sql_finding()
    store.save_finding(finding)

    record = _run(store, project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)
    assert record.gate_outcome is GateOutcome.hold
    # A held gate writes no findings.
    assert store.list_findings(project="src-proj") == [finding] or all(
        f.status is FindingStatus.verified for f in store.list_findings()
    )


def test_no_basis_source_refuses_at_gate(state_dir):
    store = FileStore(state_dir)
    store.save_project(
        make_project(
            id="src-proj",
            git_url="https://example.test/x",
            authorization_basis=None,
            scope_allowlist=["app"],
        )
    )
    store.save_finding(_verified_sql_finding())

    record = _run(store, project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)
    assert record.gate_outcome is GateOutcome.refuse


# --- refuse (in run): missing / wrong-project / not-verified source ----------


def test_refuses_when_source_finding_missing(state_dir):
    store = FileStore(state_dir)
    store.save_project(
        make_project(id="src-proj", git_url="https://example.test/x", scope_allowlist=["app"])
    )
    record = _run(store, project_id="src-proj", finding_id="F-9999", sarif_path=SIBLINGS)
    assert record.gate_outcome is GateOutcome.proceed
    assert record.close_state is CloseState.clean
    # No worker, no variants written.
    assert store.list_findings(project="src-proj") == []


def test_refuses_when_source_belongs_to_another_project(state_dir):
    store = FileStore(state_dir)
    _seed_source(store, project_id="src-proj")
    # A second project whose gate we run, but the finding belongs to src-proj.
    store.save_project(
        make_project(id="other", git_url="https://example.test/other", scope_allowlist=["app"])
    )
    record = _run(store, project_id="other", finding_id="F-0007", sarif_path=SIBLINGS)
    assert record.close_state is CloseState.clean
    # No variants written for 'other'.
    assert store.list_findings(project="other") == []


def test_refuses_when_source_is_not_verified(state_dir):
    store = FileStore(state_dir)
    store.save_project(
        make_project(id="src-proj", git_url="https://example.test/x", scope_allowlist=["app"])
    )
    # A candidate (not verified) source — SIBLING HUNT only hunts from verified.
    store.save_finding(_verified_sql_finding())  # written as verified? no:
    cand = make_finding(id="F-0100", project="src-proj", status="candidate")
    store.save_finding(cand)

    record = _run(store, project_id="src-proj", finding_id="F-0100", sarif_path=SIBLINGS)
    assert record.close_state is CloseState.clean
    # No new variants written beyond the seeded findings.
    ids_before = {"F-0007", "F-0100"}
    ids_after = {f.id for f in store.list_findings(project="src-proj")}
    assert ids_after == ids_before


def test_refuses_when_no_signature_can_be_derived(state_dir):
    # FIX 6: a VERIFIED source finding whose typed summary maps to no capability
    # in the closed lookup yields NO signature. The session closes clean, runs no
    # worker, and writes nothing.
    store = FileStore(state_dir)
    store.save_project(
        make_project(
            id="src-proj",
            git_url="https://example.test/x",
            authorization_basis="permissive_oss",
            scope_allowlist=["app"],
        )
    )
    finding = make_finding(
        id="F-0007",
        project="src-proj",
        status="verified",
        summary="a nondescript confirmed issue",
        body="## Root cause\n\nnothing that maps to a capability.",
        references=[],
        evidence_ref=None,
    )
    ref = store.write_detail("S-seed", "evidence.txt", "seed evidence")
    finding.evidence_ref = ref
    store.save_finding(finding)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS
    )
    record = run_session(store, GATE, session)

    assert record.close_state is CloseState.clean
    # No signature derived -> no class to hunt.
    assert session.signature is None
    # No worker ran: no envelope was ingested.
    assert session.envelopes == []
    # Nothing written for the project beyond the seeded source finding.
    variants = [
        f for f in store.list_findings(project="src-proj")
        if f.status is FindingStatus.candidate
    ]
    assert variants == []
    assert store.list_coverage(project="src-proj") == []


# --- the hunt: variants, same-class filter, scope containment ----------------


def test_writes_candidate_variants_for_same_class_siblings(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS
    )
    record = run_session(store, GATE, session)

    variants = [
        f
        for f in store.list_findings(project="src-proj")
        if f.status is FindingStatus.candidate
    ]
    # siblings.sarif has 2 in-scope inject:sql results (app/reports.py, app/search.py),
    # 1 different-class (app/files.py -> write:arbitrary-file, dropped by same-class
    # filter), 1 out-of-scope inject:sql (vendor/..., dropped by scope containment).
    assert len(variants) == 2
    assert all(f.project == "src-proj" for f in variants)
    # fresh ids past the store max (source is F-0007).
    assert all(int(f.id.split("-")[1]) > 7 for f in variants)
    # the different-class file is not present.
    assert not any("files.py" in (f.body or "") for f in variants)
    # the out-of-scope vendor instance is not present.
    assert not any("vendor" in (f.body or "") for f in variants)


def test_same_class_filter_drops_different_capability(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS
    )
    run_session(store, GATE, session)
    # signature capability is inject:sql; the path-injection (write:arbitrary-file)
    # instance must be dropped.
    assert session.signature is not None
    assert session.signature.capability == "inject:sql"
    variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    assert all("sql" in f.summary.lower() for f in variants)


def test_ledger_holds_sibling_primitives_and_envelope_validated(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS
    )
    run_session(store, GATE, session)

    # The conductor ingested the worker envelope; the ledger holds the sibling
    # primitives (same-class, so inject:sql), and self.envelopes holds validated
    # envelope(s).
    assert session.conductor is not None
    assert len(session.conductor.ledger) == 2
    assert session.envelopes
    for env in session.envelopes:
        assert env is not None
        assert all(p.kind == "inject:sql" for p in env.primitives)


def test_teaches_back_read_coverage(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    record = _run(store, project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)

    cov = store.list_coverage(project="src-proj")
    assert cov
    assert all(c.method is CoverageMethod.read for c in cov)
    assert record.coverage_changed


def test_injection_in_sarif_and_hint_changes_nothing_structural(state_dir, tmp_path):
    store = FileStore(state_dir)
    _seed_source(store)
    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS
    )
    run_session(store, GATE, session)
    # Poisoned SARIF message text lands only in a data field (the finding body),
    # never as an instruction; capability of every ingested primitive is inject:sql.
    for env in session.envelopes:
        assert all(p.kind == "inject:sql" for p in env.primitives)


# --- T005: exports ----------------------------------------------------------


def test_signature_exports_from_sibling_package():
    from deepthought.sibling import Signature, signature_from_finding  # noqa: F401

    assert Signature.__name__ == "Signature"


def test_session_exports_from_sessions_package():
    from deepthought.sessions import SiblingHuntSession  # noqa: F401

    assert SiblingHuntSession.type is SessionType.sibling_hunt


# --- T006: OSV validity -----------------------------------------------------


def test_source_target_excludes_the_source_findings_own_instance(state_dir):
    """On the source project, the source finding's OWN location is NOT re-saved as a
    variant (it is the already-verified source, not a sibling of itself); a genuine
    sibling at a different location IS kept."""
    store = FileStore(state_dir)
    store.save_project(make_project(
        id="src-proj", git_url="https://example.test/src-proj",
        authorization_basis="permissive_oss", scope_allowlist=["app"],
    ))
    # Source finding located at app/reports.py:88 — a location present in SIBLINGS.
    finding = make_finding(
        id="F-0007", project="src-proj", status="verified",
        summary="py/sql-injection: user input reaches a SQL query",
        body="## Root cause\n\nx\n\n**Location:** `app/reports.py:88`", evidence_ref=None,
    )
    finding.evidence_ref = store.write_detail("S-seed", "evidence.txt", "seed")
    store.save_finding(finding)

    _run(store, project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)

    variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    bodies = [f.body or "" for f in variants]
    assert not any("app/reports.py:88" in b for b in bodies)   # source instance excluded
    assert any("app/search.py:21" in b for b in bodies)        # genuine sibling kept
    assert len(variants) == 1


def test_every_variant_is_osv_valid(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    _run(store, project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)

    variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    assert variants
    for f in variants:
        assert validate_osv(finding_to_osv(f)) == []


# --- T004: cross-project path (authority firewall) --------------------------


def _register_sibling(store, sibling_id="sib-proj", *, basis="permissive_oss", scope=("app",)):
    store.save_project(
        make_project(
            id=sibling_id,
            name=f"Sibling {sibling_id}",
            git_url=f"https://example.test/{sibling_id}",
            authorization_basis=basis,
            scope_allowlist=list(scope),
        )
    )


def test_one_target_worker_failure_does_not_abort_the_whole_hunt(state_dir, monkeypatch):
    """PER-TARGET ISOLATION: if a worker raises for one target (e.g. an over-cap
    field the Envelope rejects), that target is recorded blocked and the OTHER
    authorized targets still run — one target must not deny service to the rest."""
    import deepthought.sessions.sibling_hunt as sh

    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")

    real_worker = sh._run_marvin_worker

    def _flaky(session_id, target, signature, sarif_path, root, id_start):
        # A NON-(OSError/ValidationError) exception (ValueError) must still be
        # isolated to this target — the per-target guard catches any Exception.
        if target.id == "src-proj":
            raise ValueError("boom in the source worker")
        return real_worker(session_id, target, signature, sarif_path, root, id_start)

    monkeypatch.setattr(sh, "_run_marvin_worker", _flaky)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007",
        sibling_project_ids=["sib-proj"], sarif_path=SIBLINGS,
    )
    record = run_session(store, GATE, session)

    # The session closed cleanly; the source is recorded as a failed/blocked target
    # while the sibling still produced its variants.
    assert record.close_state.value == "clean"
    src_variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    sib_variants = [
        f for f in store.list_findings(project="sib-proj") if f.status is FindingStatus.candidate
    ]
    assert src_variants == []            # the failing target wrote nothing
    assert len(sib_variants) == 2        # the healthy sibling still ran
    reasons = " ".join(o.reason or "" for o in session.target_outcomes)
    assert "worker failed" in reasons
    # The failure is SURFACED in the teach-back (not silently swallowed).
    surfaced = (record.body + record.next_steps()).upper()
    assert "BLOCKED" in surfaced or "FAILED" in surfaced


def test_nonexistent_sarif_surfaces_a_blocked_target_not_silent_zero(state_dir):
    """A missing/unreadable SARIF is a BLOCKED scan (load_sarif wraps OSError ->
    SarifError), surfaced distinctly in the teach-back — never a silent 'no
    variants found'."""
    store = FileStore(state_dir)
    _seed_source(store)

    record = _run(
        store, project_id="src-proj", finding_id="F-0007",
        sarif_path=str(Path(state_dir) / "does-not-exist.sarif"),
    )

    # The source target proceeded at its gate but its worker was blocked; the
    # teach-back must say so rather than report a clean empty hunt.
    surfaced = (record.body + record.next_steps()).upper()
    assert "BLOCKED" in surfaced or "FAILED" in surfaced
    # No variant candidates were written (only the pre-seeded verified source
    # finding remains).
    variants = [
        f for f in store.list_findings(project="src-proj")
        if f.status is FindingStatus.candidate
    ]
    assert variants == []


def test_store_read_failure_during_firewall_is_isolated(state_dir, monkeypatch):
    """A Store READ error during the firewall (store.get_finding) — which runs
    inside the consolidated per-target guard — is isolated: the target is recorded
    failed and the OTHER authorized targets still run (no whole-session crash)."""
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")

    real_get = store.get_finding
    calls = {"n": 0}

    def _flaky_get(fid):
        # run() reads the source finding F-0007 first; the FIRST firewall novelty
        # check for a variant id then raises (the source target), the sibling's
        # later checks succeed.
        if fid != "F-0007":
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("transient store read error")
        return real_get(fid)

    monkeypatch.setattr(store, "get_finding", _flaky_get)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007",
        sibling_project_ids=["sib-proj"], sarif_path=SIBLINGS,
    )
    record = run_session(store, GATE, session)

    assert record.close_state.value == "clean"   # did NOT crash the whole hunt
    src_variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    sib_variants = [
        f for f in store.list_findings(project="sib-proj") if f.status is FindingStatus.candidate
    ]
    assert src_variants == []             # source firewall read failed
    assert len(sib_variants) == 2         # sibling unaffected
    src_out = next(t for t in session.target_outcomes if t.project_id == "src-proj")
    assert "worker failed" in (src_out.reason or "")


def test_post_ingest_store_write_failure_is_isolated_and_surfaced(state_dir, monkeypatch):
    """A Store write failure AFTER a successful ingest (e.g. a disk/permission error
    persisting a variant) must be contained to that target — recorded and surfaced
    as its failure — never aborting the whole hunt or silently losing the report."""
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")

    real_save = store.save_finding

    def _flaky_save(finding):
        # Fail persisting the SOURCE target's variant candidates; the sibling saves
        # fine.
        if finding.project == "src-proj" and finding.status is FindingStatus.candidate:
            raise OSError("disk full writing variant")
        return real_save(finding)

    monkeypatch.setattr(store, "save_finding", _flaky_save)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007",
        sibling_project_ids=["sib-proj"], sarif_path=SIBLINGS,
    )
    record = run_session(store, GATE, session)

    assert record.close_state.value == "clean"   # the hunt did NOT crash
    src_variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    sib_variants = [
        f for f in store.list_findings(project="sib-proj") if f.status is FindingStatus.candidate
    ]
    assert src_variants == []            # source variant writes failed
    assert len(sib_variants) == 2        # the healthy sibling still ran
    surfaced = (record.body + record.next_steps()).upper()
    assert "FAILED" in surfaced or "BLOCKED" in surfaced
    src_out = next(t for t in session.target_outcomes if t.project_id == "src-proj")
    assert "persisted before the failure" in (src_out.reason or "")


def test_partial_store_write_failure_reports_the_persisted_variants(state_dir, monkeypatch):
    """If a write fails MID-batch (some variants already persisted), the session log
    must MATCH Store state: the persisted variants are reported in findings_touched,
    never left silently behind, and the target is surfaced as a partial failure."""
    store = FileStore(state_dir)
    _seed_source(store)

    real_save = store.save_finding
    calls = {"n": 0}

    def _fail_second(finding):
        if finding.project == "src-proj" and finding.status is FindingStatus.candidate:
            calls["n"] += 1
            if calls["n"] >= 2:
                raise OSError("disk full on the 2nd variant")
        return real_save(finding)

    monkeypatch.setattr(store, "save_finding", _fail_second)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS
    )
    record = run_session(store, GATE, session)

    src_variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    # Exactly ONE variant persisted before the failure — and it IS reported, so the
    # session log does not diverge from Store state.
    assert len(src_variants) == 1
    persisted_id = src_variants[0].id
    assert persisted_id in record.findings_touched
    src_out = next(t for t in session.target_outcomes if t.project_id == "src-proj")
    assert src_out.findings == [persisted_id]
    assert "persisted before the failure" in (src_out.reason or "")
    surfaced = (record.body + record.next_steps()).upper()
    assert "FAILED" in surfaced or "BLOCKED" in surfaced


def test_worker_side_channel_findings_are_filtered_to_the_validated_envelope(state_dir, monkeypatch):
    """FIREWALL: the worker returns Finding OBJECTS alongside the envelope. Only
    findings the VALIDATED envelope attests (id in findings_written) AND bound to
    the target are persisted; smuggled findings — for another project, or with an
    id the envelope never listed — are dropped, never saved."""
    store = FileStore(state_dir)
    _seed_source(store)

    import deepthought.sessions.sibling_hunt as sh

    real_worker = sh._run_marvin_worker

    def _smuggling(session_id, target, signature, sarif_path, root, id_start):
        envelope, findings, detail_body = real_worker(
            session_id, target, signature, sarif_path, root, id_start
        )
        # Smuggle two unattested findings: one for ANOTHER project, one whose id is
        # NOT in the envelope's findings_written. Neither is attested.
        smuggled = [
            make_finding(id="F-9001", project="evil-proj", status="candidate", evidence_ref=None),
            make_finding(id="F-9002", project=target.id, status="candidate", evidence_ref=None),
        ]
        return envelope, findings + smuggled, detail_body

    monkeypatch.setattr(sh, "_run_marvin_worker", _smuggling)

    from deepthought.sessions import SiblingHuntSession

    run_session(
        store, GATE,
        SiblingHuntSession(project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS),
    )

    # The smuggled findings were NOT persisted (unattested / wrong project).
    assert store.get_finding("F-9001") is None
    assert store.get_finding("F-9002") is None
    assert store.list_findings(project="evil-proj") == []
    # The legitimate, envelope-attested src variants ARE persisted.
    src_variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    assert len(src_variants) == 2


def test_worker_cannot_overwrite_an_existing_finding_by_id_reuse(state_dir, monkeypatch):
    """A side-channel finding whose id ALREADY exists in the Store is DROPPED — a
    worker cannot hijack/overwrite an existing (e.g. verified) finding by reusing
    its id, even if it lists that id in the envelope's findings_written."""
    store = FileStore(state_dir)
    _seed_source(store)  # writes verified F-0007
    before = store.get_finding("F-0007")

    import deepthought.sessions.sibling_hunt as sh

    real_worker = sh._run_marvin_worker

    def _hijacker(session_id, target, signature, sarif_path, root, id_start):
        env, findings, detail = real_worker(session_id, target, signature, sarif_path, root, id_start)
        # Attest F-0007 (an existing verified finding) and provide a candidate object
        # that would overwrite it if not id-guarded.
        env = env.model_copy(update={"findings_written": list(env.findings_written) + ["F-0007"]})
        hijack = make_finding(id="F-0007", project=target.id, status="candidate",
                              evidence_ref=None, summary="HIJACKED")
        return env, findings + [hijack], detail

    monkeypatch.setattr(sh, "_run_marvin_worker", _hijacker)

    from deepthought.sessions import SiblingHuntSession

    run_session(store, GATE, SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS))

    after = store.get_finding("F-0007")
    assert after.status is before.status          # still verified — NOT overwritten
    assert after.summary == before.summary        # untouched


def test_worker_out_of_scope_finding_location_is_dropped(state_dir, monkeypatch):
    """A side-channel finding whose claimed location is OUTSIDE the target's scope
    is dropped — a worker cannot smuggle a persisted finding for an out-of-scope
    area of an otherwise-authorized project."""
    store = FileStore(state_dir)
    _seed_source(store)  # scope = ["app"]

    import deepthought.sessions.sibling_hunt as sh

    real_worker = sh._run_marvin_worker

    def _smuggle_oos(session_id, target, signature, sarif_path, root, id_start):
        env, findings, detail = real_worker(session_id, target, signature, sarif_path, root, id_start)
        env = env.model_copy(update={"findings_written": list(env.findings_written) + ["F-8000"]})
        oos = make_finding(
            id="F-8000", project=target.id, status="candidate", evidence_ref=None,
            summary="out of scope variant",
            body="## Root cause\n\nx\n\n**Location:** `secret/keys.txt:1`",
        )
        return env, findings + [oos], detail

    monkeypatch.setattr(sh, "_run_marvin_worker", _smuggle_oos)

    from deepthought.sessions import SiblingHuntSession

    run_session(store, GATE, SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS))

    assert store.get_finding("F-8000") is None    # out-of-scope location -> dropped
    # The in-scope (app/...) variants are still persisted.
    src_variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    assert src_variants and all("app" in (f.body or "") for f in src_variants)


def test_ledger_drops_primitives_for_findings_the_orchestrator_filters(state_dir, monkeypatch):
    """When the orchestrator drops a finding (here: out-of-scope), the ledger must
    NOT retain that finding's primitive — the filtered envelope is ingested, so no
    dangling ledger primitive points at a dropped/non-persisted finding."""
    store = FileStore(state_dir)
    _seed_source(store)  # scope ["app"]

    import deepthought.sessions.sibling_hunt as sh
    from deepthought.schema.envelope import Primitive

    real_worker = sh._run_marvin_worker

    def _smuggle(session_id, target, signature, sarif_path, root, id_start):
        env, findings, detail = real_worker(session_id, target, signature, sarif_path, root, id_start)
        oos = make_finding(
            id="F-8000", project=target.id, status="candidate", evidence_ref=None,
            summary="oos", body="**Location:** `secret/x.py:1`",
        )
        smuggled_prim = Primitive(
            kind=signature.capability, target_locus="secret/x.py", preconditions=[],
            grants=[signature.capability], confidence="suspected", finding_ref="F-8000",
        )
        env = env.model_copy(update={
            "findings_written": list(env.findings_written) + ["F-8000"],
            "primitives": list(env.primitives) + [smuggled_prim],
        })
        return env, findings + [oos], detail

    monkeypatch.setattr(sh, "_run_marvin_worker", _smuggle)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)
    run_session(store, GATE, session)

    assert store.get_finding("F-8000") is None
    ledger_refs = {n.finding_ref for n in session.conductor.ledger.nodes()}
    assert "F-8000" not in ledger_refs   # no dangling ledger primitive


def test_worker_returning_duplicate_ids_in_a_batch_persists_only_one(state_dir, monkeypatch):
    """Two side-channel findings with the SAME new id both pass the not-in-store
    check pre-save; dedupe-by-id ensures only ONE is persisted, no overwrite."""
    store = FileStore(state_dir)
    _seed_source(store)

    import deepthought.sessions.sibling_hunt as sh

    real_worker = sh._run_marvin_worker

    def _dupes(session_id, target, signature, sarif_path, root, id_start):
        env, findings, detail = real_worker(session_id, target, signature, sarif_path, root, id_start)
        a = make_finding(id="F-8000", project=target.id, status="candidate", evidence_ref=None,
                         summary="A", body="**Location:** `app/a.py:1`")
        b = make_finding(id="F-8000", project=target.id, status="candidate", evidence_ref=None,
                         summary="B", body="**Location:** `app/b.py:1`")
        env = env.model_copy(update={"findings_written": list(env.findings_written) + ["F-8000"]})
        return env, findings + [a, b], detail

    monkeypatch.setattr(sh, "_run_marvin_worker", _dupes)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)
    run_session(store, GATE, session)

    f = store.get_finding("F-8000")
    assert f is not None and f.summary == "A"   # first kept, not overwritten by B
    src_out = next(t for t in session.target_outcomes if t.project_id == "src-proj")
    assert src_out.findings.count("F-8000") == 1


def test_locus_uses_the_last_appended_location_not_message_text():
    """INPUT FIREWALL: sarif_to_findings appends the real **Location:** AFTER the
    untrusted message text, so the LAST match wins. A message body that embeds its
    own **Location:** (an earlier match) cannot steer the signature's locus."""
    from deepthought.sibling.signature import signature_from_finding

    finding = make_finding(
        id="F-1", project="p", status="verified", summary="py/sql-injection",
        body=(
            "attacker message with **Location:** `evil/fake.py:1` embedded\n\n"
            "**Location:** `app/real.py:9`"
        ),
        evidence_ref=None,
    )
    sig = signature_from_finding(finding)
    assert sig is not None
    assert sig.locus_pattern == "app/real.py:9"   # the last, structured match


def test_same_class_drops_primitives_binding_to_filtered_findings():
    """_same_class keeps a primitive only if it is same-class AND binds to a KEPT
    finding — never a finding id that no returned finding provides (no dangling
    ledger primitives)."""
    from deepthought.schema.envelope import Primitive
    from deepthought.sessions.sibling_hunt import _same_class

    f1 = make_finding(id="F-1", project="p", status="candidate", evidence_ref=None)
    prims = [
        Primitive(kind="inject:sql", target_locus="app/a.py", preconditions=[],
                  grants=["inject:sql"], confidence="suspected", finding_ref="F-1"),
        # same-class primitive bound to a finding id NOT among the findings.
        Primitive(kind="inject:sql", target_locus="app/b.py", preconditions=[],
                  grants=["inject:sql"], confidence="suspected", finding_ref="F-404"),
    ]
    kept_findings, kept_primitives = _same_class([f1], prims, "inject:sql")

    assert [f.id for f in kept_findings] == ["F-1"]
    assert [p.finding_ref for p in kept_primitives] == ["F-1"]  # F-404 dropped


def test_partial_coverage_write_failure_reports_the_persisted_coverage(state_dir, monkeypatch):
    """Symmetric to variants: if save_coverage fails MID-batch (some areas saved),
    the persisted coverage refs are reported (coverage_changed matches Store state)
    and the target is surfaced as a partial failure."""
    store = FileStore(state_dir)
    # Source with TWO in-scope areas -> two coverage deltas.
    store.save_project(
        make_project(
            id="src-proj", git_url="https://example.test/src-proj",
            authorization_basis="permissive_oss", scope_allowlist=["app", "lib"],
        )
    )
    finding = _verified_sql_finding(project="src-proj")
    finding.evidence_ref = store.write_detail("S-seed", "evidence.txt", "seed")
    store.save_finding(finding)

    real_cov = store.save_coverage
    calls = {"n": 0}

    def _fail_second_cov(coverage):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise OSError("disk full on the 2nd coverage area")
        return real_cov(coverage)

    monkeypatch.setattr(store, "save_coverage", _fail_second_cov)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS
    )
    record = run_session(store, GATE, session)

    persisted_cov = store.list_coverage(project="src-proj")
    assert len(persisted_cov) == 1                       # one area saved pre-failure
    # The persisted coverage is REPORTED — coverage_changed matches Store state.
    assert len(record.coverage_changed) == 1
    src_out = next(t for t in session.target_outcomes if t.project_id == "src-proj")
    assert len(src_out.coverage) == 1
    assert "coverage record(s) persisted" in (src_out.reason or "")


def test_siblings_are_gated_by_the_harness_gate_not_a_hardcoded_default(state_dir):
    """AUTHORITY EDGE: a sibling is gated by the SAME gate the harness ran the
    source through (injected as self.harness_gate), not a hardcoded DefaultGate —
    so a stricter deployment gate governs every sibling too."""
    from deepthought.protocol.gate import DefaultGate

    evaluated: list[str | None] = []

    class _SpyGate(DefaultGate):
        def evaluate(self, ctx):
            evaluated.append(ctx.project_id)
            return super().evaluate(ctx)

    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")

    from deepthought.sessions import SiblingHuntSession

    run_session(
        store,
        _SpyGate(),
        SiblingHuntSession(
            project_id="src-proj", finding_id="F-0007",
            sibling_project_ids=["sib-proj"], sarif_path=SIBLINGS,
        ),
    )
    # The harness gate (the passed instance) evaluated BOTH the source and the
    # sibling. If the sibling used a separate hardcoded gate, the spy would not have
    # seen 'sib-proj'.
    assert "src-proj" in evaluated
    assert "sib-proj" in evaluated


def test_locus_derivation_tolerates_none_references():
    """Defensive: a finding whose references is None (not a list) must not crash
    signature derivation — the reference loop is guarded."""
    from deepthought.sibling.signature import _locus_pattern

    finding = _verified_sql_finding()
    object.__setattr__(finding, "references", None)
    object.__setattr__(finding, "body", "no location line here")
    assert _locus_pattern(finding) is None   # falls through, does not raise


def test_authorized_in_scope_sibling_is_hunted_and_variants_bound_to_it(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
    )
    run_session(store, GATE, session)

    # Variants written for BOTH the source and the sibling, each bound to its
    # OWN project, over its OWN in-scope areas.
    src_variants = [
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    ]
    sib_variants = [
        f for f in store.list_findings(project="sib-proj") if f.status is FindingStatus.candidate
    ]
    assert len(src_variants) == 2
    assert len(sib_variants) == 2
    assert all(f.project == "sib-proj" for f in sib_variants)
    # Coverage attributed to the sibling.
    assert store.list_coverage(project="sib-proj")
    # Fresh, non-colliding ids across both targets.
    all_ids = [f.id for f in src_variants + sib_variants]
    assert len(all_ids) == len(set(all_ids))


def test_sibling_with_no_basis_is_refused_no_records(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj", basis=None)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
    )
    record = run_session(store, GATE, session)

    # Refused at its OWN gate: no worker, no findings, no coverage.
    assert store.list_findings(project="sib-proj") == []
    assert store.list_coverage(project="sib-proj") == []
    outcome = next(t for t in session.target_outcomes if t.project_id == "sib-proj")
    assert not outcome.proceeded
    assert outcome.gate_outcome == "refuse"
    # The persisted session records WHY (the gate reason), not just the outcome.
    assert "sib-proj" in record.body
    assert (outcome.reason or "") in record.body
    assert outcome.reason  # a non-empty gate reason was captured


def test_sibling_with_empty_scope_is_held_no_records(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj", scope=())

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
    )
    run_session(store, GATE, session)

    assert store.list_findings(project="sib-proj") == []
    assert store.list_coverage(project="sib-proj") == []
    outcome = next(t for t in session.target_outcomes if t.project_id == "sib-proj")
    assert not outcome.proceeded
    assert outcome.gate_outcome == "hold"


def test_unregistered_named_sibling_is_skipped_never_created(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    projects_before = {p.id for p in store.list_projects()}

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["ghost-proj"],
        sarif_path=SIBLINGS,
    )
    run_session(store, GATE, session)

    # The named-but-unregistered sibling was never created.
    assert {p.id for p in store.list_projects()} == projects_before
    assert store.get_project("ghost-proj") is None
    outcome = next(t for t in session.target_outcomes if t.project_id == "ghost-proj")
    assert outcome.gate_outcome == "skipped"
    assert not outcome.proceeded


def test_authority_invariant_never_widens_scope_or_creates_projects(state_dir, monkeypatch):
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")
    # A named unauthorized sibling and an unregistered one, to exercise every path.
    _register_sibling(store, "unauth-proj", basis=None)

    # Spy on save_project: it must NEVER be called during a hunt.
    calls = {"save_project": 0}
    real_save = store.save_project

    def spy_save(project):
        calls["save_project"] += 1
        return real_save(project)

    monkeypatch.setattr(store, "save_project", spy_save)

    # Snapshot each project's scope/basis to assert they are untouched.
    before = {
        p.id: (tuple(p.scope_allowlist), p.authorization_basis)
        for p in store.list_projects()
    }

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj", "unauth-proj", "ghost-proj"],
        sarif_path=SIBLINGS,
    )
    run_session(store, GATE, session)

    # Never created or mutated a project.
    assert calls["save_project"] == 0
    after = {
        p.id: (tuple(p.scope_allowlist), p.authorization_basis)
        for p in store.list_projects()
    }
    assert after == before

    # Every finding/coverage written is for a target that proceeded at its gate:
    # subset of {source} union {authorized in-scope named siblings}.
    proceeded_projects = {t.project_id for t in session.target_outcomes if t.proceeded}
    assert proceeded_projects <= {"src-proj", "sib-proj"}
    written_projects = {f.project for f in store.list_findings() if f.status is FindingStatus.candidate}
    assert written_projects <= {"src-proj", "sib-proj"}
    cov_projects = {c.project for c in store.list_coverage()}
    assert cov_projects <= {"src-proj", "sib-proj"}


def test_rejected_target_envelope_persists_nothing_and_ids_stay_fresh(state_dir, monkeypatch):
    # MUTATE-ONLY-ON-ACCEPT: a target whose worker envelope is REJECTED at ingest
    # persists NOTHING (the worker builds but does not save; the orchestrator saves
    # only after a successful ingest). So the rejected source strands no findings,
    # and the later sibling — allocating ids fresh from persisted Store state — gets
    # clean, non-colliding ids.
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")

    import deepthought.sessions.sibling_hunt as sh

    real_worker = sh._run_marvin_worker

    def flaky_worker(session_id, target, signature, sarif_path, root, id_start):
        envelope, findings, detail_body = real_worker(
            session_id, target, signature, sarif_path, root, id_start
        )
        # For the SOURCE target, corrupt the envelope into a malformed dict so the
        # Conductor REJECTS it at ingest. The worker persisted nothing, so nothing
        # is stranded.
        if target.id == "src-proj":
            return {"garbage": "not a valid envelope", "outcome": "???"}, findings, detail_body
        return envelope, findings, detail_body

    monkeypatch.setattr(sh, "_run_marvin_worker", flaky_worker)

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
    )
    run_session(store, GATE, session)

    # The rejected source target persisted NO findings (mutate-only-on-accept).
    src_variants = [
        f for f in store.list_findings(project="src-proj")
        if f.status is FindingStatus.candidate
    ]
    sib_variants = [
        f for f in store.list_findings(project="sib-proj")
        if f.status is FindingStatus.candidate
    ]
    assert src_variants == []       # rejected -> nothing stranded
    assert len(sib_variants) == 2   # the healthy sibling still ran
    # Every sibling id is distinct.
    all_ids = [f.id for f in sib_variants]
    assert len(all_ids) == len(set(all_ids))
    # The source is recorded proceeded-but-rejected at ingest.
    src_out = next(t for t in session.target_outcomes if t.project_id == "src-proj")
    assert src_out.proceeded and "rejected" in (src_out.reason or "")


def test_root_is_source_only_sibling_resolves_against_its_own_local_path(state_dir, tmp_path):
    # FIX 3: the CLI --root applies ONLY to the source project. A named sibling
    # resolves its SARIF/coverage against its OWN local_path, not the shared root.
    store = FileStore(state_dir)

    # A real checkout for the SOURCE that DOES have an app/ dir.
    src_root = tmp_path / "src-checkout"
    (src_root / "app").mkdir(parents=True)
    # A separate checkout for the SIBLING that also has app/.
    sib_root = tmp_path / "sib-checkout"
    (sib_root / "app").mkdir(parents=True)

    store.save_project(
        make_project(
            id="src-proj",
            git_url="https://example.test/src-proj",
            local_path=str(src_root),
            authorization_basis="permissive_oss",
            scope_allowlist=["app"],
        )
    )
    finding = _verified_sql_finding(project="src-proj")
    ref = store.write_detail("S-seed", "evidence.txt", "seed evidence")
    finding.evidence_ref = ref
    store.save_finding(finding)

    store.save_project(
        make_project(
            id="sib-proj",
            name="Sibling",
            git_url="https://example.test/sib-proj",
            local_path=str(sib_root),
            authorization_basis="permissive_oss",
            scope_allowlist=["app"],
        )
    )

    from deepthought.sessions import SiblingHuntSession

    # --root points at the SOURCE checkout. If it were (wrongly) applied to the
    # sibling, the sibling's `app` area would resolve against src_root — but the
    # sibling must resolve against its OWN local_path (sib_root), which has app/.
    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
        root=str(src_root),
    )
    run_session(store, GATE, session)

    # The sibling resolved against its own local_path and recorded coverage +
    # variants for its own in-scope app/ area.
    assert store.list_coverage(project="sib-proj")
    sib_variants = [
        f for f in store.list_findings(project="sib-proj")
        if f.status is FindingStatus.candidate
    ]
    assert len(sib_variants) == 2


def test_blocked_target_is_surfaced_in_teach_back(state_dir, tmp_path):
    # FIX 4: a target whose SARIF fails to load yields a `blocked` worker outcome;
    # the teach-back must surface it distinctly (not read it as a clean empty run),
    # mirroring DISCOVER.
    store = FileStore(state_dir)
    _seed_source(store)

    bad_sarif = tmp_path / "malformed.sarif"
    bad_sarif.write_text("{ this is not valid json ", encoding="utf-8")

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj", finding_id="F-0007", sarif_path=str(bad_sarif)
    )
    record = run_session(store, GATE, session)

    # The source target was blocked (SARIF failed to load).
    src_out = next(t for t in session.target_outcomes if t.project_id == "src-proj")
    assert src_out.reason == "blocked"
    # The teach-back surfaces the block distinctly and points at the paged detail.
    blob = (record.body + " " + record.next_steps()).lower()
    assert "block" in blob
    assert "detail" in blob


def test_scanned_but_empty_target_records_read_coverage(state_dir, tmp_path):
    # FIX 5: a pre-authorized target scanned with SARIF but ZERO same-class
    # variants still attests read Coverage for its in-scope areas (mirroring
    # DISCOVER's `if sarif_path` coverage gate).
    store = FileStore(state_dir)
    _seed_source(store)

    # A sibling scoped to an area the SARIF has NO in-scope same-class results for,
    # so the worker runs, finds nothing, but must still record read coverage.
    _register_sibling(store, "sib-proj", scope=("lib",))

    from deepthought.sessions import SiblingHuntSession

    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
    )
    run_session(store, GATE, session)

    # No variants for the sibling (its `lib` scope holds none of the SARIF's app/*
    # results), but its in-scope `lib` area is attested as read coverage.
    sib_variants = [
        f for f in store.list_findings(project="sib-proj")
        if f.status is FindingStatus.candidate
    ]
    assert sib_variants == []
    sib_cov = store.list_coverage(project="sib-proj")
    assert sib_cov
    assert all(c.method is CoverageMethod.read for c in sib_cov)
    assert {c.area for c in sib_cov} == {"lib"}


def test_cross_project_variants_are_all_osv_valid(state_dir):
    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")
    _run(
        store,
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
    )
    variants = [f for f in store.list_findings() if f.status is FindingStatus.candidate]
    assert variants
    for f in variants:
        assert validate_osv(finding_to_osv(f)) == []


# --- T008: check stays a hard gate over SIBLING HUNT output -----------------


def test_check_is_green_on_hunt_output(state_dir):
    from deepthought.check import run_check

    store = FileStore(state_dir)
    _seed_source(store)
    _register_sibling(store, "sib-proj")
    _run(
        store,
        project_id="src-proj",
        finding_id="F-0007",
        sibling_project_ids=["sib-proj"],
        sarif_path=SIBLINGS,
    )
    report = run_check(store)
    assert report.ok, report.errors


def test_check_fails_on_a_corrupted_variant(state_dir):
    from deepthought.check import run_check

    store = FileStore(state_dir)
    _seed_source(store)
    _run(store, project_id="src-proj", finding_id="F-0007", sarif_path=SIBLINGS)

    variant = next(
        f for f in store.list_findings(project="src-proj") if f.status is FindingStatus.candidate
    )
    # Hand-corrupt the variant into a state that cannot export to valid OSV: a
    # verified finding with no resolving evidence_ref is lifecycle-illegal at rest.
    variant.status = FindingStatus.verified
    variant.evidence_ref = None
    store.save_finding(variant)

    report = run_check(store)
    assert not report.ok
