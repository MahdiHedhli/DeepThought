"""Tests for feature 009 — the aggregate class-manifest.

The aggregate certify binds the SET of classes feeding the headline mean to a committed, monotonic
manifest, loads its trust anchor from COMMITTED state (never a caller argument), requires every
in-mean class to be registry-pinned and to carry a valid signed per-class attestation, authorizes
every departure via a COMMITTED ClassExit embedded in the manifest, and RECOMPUTES the mean. These
tests assert the honest aggregate certifies and every guard fails closed. Hermetic: a fixed test
ed25519 key + a monkeypatched committed-state loader; no network.
"""

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "harness"))

import aggregate  # noqa: E402  (module handle for monkeypatching the committed-state loader)
from contract import (  # noqa: E402
    Attestation,
    CommittedGenesisState,
    Report,
    RecallReport,
    ViolationReason,
    _EMPTY_ROOT,
    ed25519_public_key,
    leaf_hash,
    sign,
)
from aggregate import (  # noqa: E402
    AggregateReport,
    CertifiedClassResult,
    ClassCorrectionReason,
    ClassExit,
    ClassManifest,
    ClassManifestEntry,
    ClassManifestHistory,
    ClassStatus,
    certify_aggregate,
)

KEY = hashlib.sha256(b"deepthought-aggregate-test-ed25519-seed/v1").digest()
PUB = ed25519_public_key(KEY)
WRONG_KEY = hashlib.sha256(b"attacker-aggregate-seed").digest()
EVAL = "curator-not-subject"
Z = "0" * 64
TS = "2026-07-18T00:00:00Z"
HA, HB = "1" * 64, "2" * 64


def _reasons(report):
    return {v.reason for v in report.violations}


def _install(monkeypatch, manifest_root=_EMPTY_ROOT, class_registry=None):
    """008 R5: certify_aggregate loads committed state INTERNALLY. Tests monkeypatch the loader with
    a hermetic state, so a caller can NEVER substitute the trust anchor."""
    state = CommittedGenesisState(
        genesis_history_root="a" * 64,
        latest_history_root="a" * 64,
        latest_attestation_root="b" * 64,
        latest_evaluation_root=_EMPTY_ROOT,
        latest_exposure_root=_EMPTY_ROOT,
        latest_class_manifest_root=manifest_root,
        evaluator_id=EVAL,
        verify_key=PUB,
        adjudicator_roster={},
        class_registry=class_registry or {},
    )
    monkeypatch.setattr(aggregate, "load_committed_genesis_state", lambda path=None: state)
    return state


def _report(rediscovered, total):
    return Report(
        blind_recall=RecallReport(rediscovered=rediscovered, total=total),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
    )


def _result(class_id, head_history_root, rediscovered, total, *, sign_key=KEY, evaluator_id=EVAL, report=None):
    rep = report if report is not None else _report(rediscovered, total)
    att = Attestation(
        history_root=head_history_root, exclusion_root=Z, exposure_root=Z, evaluation_root=Z,
        achievability_root=Z, freeze_hash=Z, pool_root=Z, run_id="r",
        report_hash=leaf_hash(rep.model_dump(mode="json")), evaluator_id=evaluator_id,
        attested_at=TS, prior_attestation_root=Z, signature="",
    )
    att = att.model_copy(update={"signature": sign(att.attestation_root, sign_key)})
    return CertifiedClassResult(class_id=class_id, attestation=att, report=rep)


def _entry(class_id, head_history_root, status=ClassStatus.ACTIVE):
    return ClassManifestEntry(class_id=class_id, cwe="CWE-1", detector_id="d", head_history_root=head_history_root, status=status)


def _reg(**kw):
    return dict(kw)


# --------------------------------------------------------------------------- #
# Honest path + committed-state loading (008 R5)
# --------------------------------------------------------------------------- #
def test_honest_aggregate_certifies(monkeypatch):
    _install(monkeypatch, class_registry=_reg(A=HA, B=HB))
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])])
    results = [_result("A", HA, 1, 2), _result("B", HB, 1, 1)]  # 0.5 and 1.0 -> 0.75
    rep = certify_aggregate(manifest=manifest, results=results, aggregate=AggregateReport(mean=0.75, n_classes=2))
    assert rep.ok, _reasons(rep)


def test_certify_loads_committed_state_internally_no_caller_anchor(monkeypatch):
    # a caller CANNOT substitute the trust anchor — certify_aggregate takes no `committed`/`events`
    # argument. Even with a self-minted key, the attestation must verify against the COMMITTED key.
    _install(monkeypatch, class_registry=_reg(A=HA))
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", HA)])])
    self_signed = _result("A", HA, 2, 2, sign_key=WRONG_KEY)  # signed with a non-committed key
    rep = certify_aggregate(manifest=manifest, results=[self_signed], aggregate=AggregateReport(mean=1.0, n_classes=1))
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


def test_wrong_reported_mean_unverified(monkeypatch):
    _install(monkeypatch, class_registry=_reg(A=HA, B=HB))
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])])
    results = [_result("A", HA, 1, 2), _result("B", HB, 1, 1)]
    rep = certify_aggregate(manifest=manifest, results=results, aggregate=AggregateReport(mean=0.9, n_classes=2))
    assert not rep.ok and ViolationReason.AGGREGATE_UNVERIFIED in _reasons(rep)


def test_wrong_n_classes_unverified(monkeypatch):
    _install(monkeypatch, class_registry=_reg(A=HA))
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", HA)])])
    rep = certify_aggregate(manifest=manifest, results=[_result("A", HA, 1, 2)], aggregate=AggregateReport(mean=0.5, n_classes=2))
    assert not rep.ok and ViolationReason.AGGREGATE_UNVERIFIED in _reasons(rep)


# --------------------------------------------------------------------------- #
# No class silently dropped from the mean — authorized only by a COMMITTED exit
# --------------------------------------------------------------------------- #
def test_drop_class_without_exit_is_silently_dropped(monkeypatch):
    _install(monkeypatch, class_registry=_reg(A=HA, B=HB))
    v1 = ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])
    v2 = ClassManifest(version="v2", entries=[_entry("A", HA)], parent_version="v1")  # B dropped, NO exit
    rep = certify_aggregate(manifest=ClassManifestHistory(versions=[v1, v2]), results=[_result("A", HA, 1, 2)], aggregate=AggregateReport(mean=0.5, n_classes=1))
    assert not rep.ok and ViolationReason.CLASS_SILENTLY_DROPPED in _reasons(rep)


def test_drop_class_with_committed_exit_is_allowed(monkeypatch):
    _install(monkeypatch, class_registry=_reg(A=HA, B=HB))
    v1 = ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])
    v2 = ClassManifest(version="v2", entries=[_entry("A", HA)], exits=[ClassExit(class_id="B", reason=ClassCorrectionReason.RETIRED)], parent_version="v1")
    rep = certify_aggregate(manifest=ClassManifestHistory(versions=[v1, v2]), results=[_result("A", HA, 1, 2)], aggregate=AggregateReport(mean=0.5, n_classes=1))
    assert rep.ok, _reasons(rep)


def test_status_downgrade_without_exit_is_silently_dropped(monkeypatch):
    _install(monkeypatch, class_registry=_reg(A=HA, B=HB))
    v1 = ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])
    v2 = ClassManifest(version="v2", entries=[_entry("A", HA), _entry("B", HB, status=ClassStatus.NA)], parent_version="v1")
    rep = certify_aggregate(manifest=ClassManifestHistory(versions=[v1, v2]), results=[_result("A", HA, 1, 2)], aggregate=AggregateReport(mean=0.5, n_classes=1))
    assert not rep.ok and ViolationReason.CLASS_SILENTLY_DROPPED in _reasons(rep)


def test_split_readd_out_of_mean_without_any_exit_is_silently_dropped(monkeypatch):
    _install(monkeypatch, class_registry=_reg(A=HA, B=HB))
    v1 = ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])
    v2 = ClassManifest(version="v2", entries=[_entry("A", HA), _entry("B", HB, status=ClassStatus.RETIRED)], parent_version="v1")
    rep = certify_aggregate(manifest=ClassManifestHistory(versions=[v1, v2]), results=[_result("A", HA, 1, 2)], aggregate=AggregateReport(mean=0.5, n_classes=1))
    assert not rep.ok and ViolationReason.CLASS_SILENTLY_DROPPED in _reasons(rep)


# --------------------------------------------------------------------------- #
# Per-class attestation integrity + registry pin
# --------------------------------------------------------------------------- #
def test_missing_per_class_attestation(monkeypatch):
    _install(monkeypatch, class_registry=_reg(A=HA, B=HB))
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])])
    rep = certify_aggregate(manifest=manifest, results=[_result("A", HA, 1, 2)], aggregate=AggregateReport(mean=0.75, n_classes=2))
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_MISSING in _reasons(rep)


def test_tampered_report_breaks_report_hash(monkeypatch):
    _install(monkeypatch, class_registry=_reg(A=HA))
    good = _result("A", HA, 1, 2)
    tampered = CertifiedClassResult(class_id="A", attestation=good.attestation, report=_report(2, 2))
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", HA)])])
    rep = certify_aggregate(manifest=manifest, results=[tampered], aggregate=AggregateReport(mean=1.0, n_classes=1))
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


def test_forged_signature(monkeypatch):
    _install(monkeypatch, class_registry=_reg(A=HA))
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", HA)])])
    rep = certify_aggregate(manifest=manifest, results=[_result("A", HA, 1, 2, sign_key=WRONG_KEY)], aggregate=AggregateReport(mean=0.5, n_classes=1))
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


def test_wrong_evaluator_id(monkeypatch):
    _install(monkeypatch, class_registry=_reg(A=HA))
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", HA)])])
    rep = certify_aggregate(manifest=manifest, results=[_result("A", HA, 1, 2, evaluator_id="the-subject")], aggregate=AggregateReport(mean=0.5, n_classes=1))
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


def test_cross_class_swap_pinned_by_registry(monkeypatch):
    # weak class B's entry re-pointed at strong A's root (HA) with A's genuine signed attestation.
    # att.history_root == entry.head_history_root would pass, but the committed registry pins B -> HB.
    _install(monkeypatch, class_registry=_reg(B=HB))
    swapped = CertifiedClassResult(class_id="B", attestation=_result("A", HA, 2, 2).attestation, report=_report(2, 2))
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("B", HA)])])
    rep = certify_aggregate(manifest=manifest, results=[swapped], aggregate=AggregateReport(mean=1.0, n_classes=1))
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


def test_in_mean_class_absent_from_registry_is_invalid(monkeypatch):
    # a partial registry (A pinned, B omitted) must NOT wave B through — an unpinned in-mean class
    # reopens the swap, so it fails closed.
    _install(monkeypatch, class_registry=_reg(A=HA))
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])])
    rep = certify_aggregate(manifest=manifest, results=[_result("A", HA, 1, 2), _result("B", HB, 1, 1)], aggregate=AggregateReport(mean=0.75, n_classes=2))
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


def test_appended_version_repointing_a_class_is_pinned(monkeypatch):
    # AUDIT/CR: an APPENDED version tries to re-point B.head_history_root to A's root and submit A's
    # attestation under B. The committed registry pins B -> HB, so the appended re-point fails closed.
    _install(monkeypatch, class_registry=_reg(A=HA, B=HB))
    v1 = ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])
    v2 = ClassManifest(version="v2", entries=[_entry("A", HA), _entry("B", HA)], parent_version="v1")  # B re-pointed to HA
    swapped_b = CertifiedClassResult(class_id="B", attestation=_result("A", HA, 2, 2).attestation, report=_report(2, 2))
    rep = certify_aggregate(manifest=ClassManifestHistory(versions=[v1, v2]), results=[_result("A", HA, 2, 2), swapped_b], aggregate=AggregateReport(mean=1.0, n_classes=2))
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


# --------------------------------------------------------------------------- #
# Committed-monotonic manifest root
# --------------------------------------------------------------------------- #
def test_manifest_truncation_against_a_real_committed_root(monkeypatch):
    baseline = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])])
    _install(monkeypatch, manifest_root=baseline.root, class_registry=_reg(A=HA, B=HB))
    presented = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", HA)])])  # drops B, wrong root
    rep = certify_aggregate(manifest=presented, results=[_result("A", HA, 1, 2)], aggregate=AggregateReport(mean=0.5, n_classes=1))
    assert not rep.ok and ViolationReason.CLASS_MANIFEST_TRUNCATED in _reasons(rep)


def test_honest_extension_of_committed_root_certifies(monkeypatch):
    v1 = ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])
    _install(monkeypatch, manifest_root=ClassManifestHistory(versions=[v1]).root, class_registry=_reg(A=HA, B=HB))
    v2 = ClassManifest(version="v2", entries=[_entry("A", HA), _entry("B", HB)], parent_version="v1")
    presented = ClassManifestHistory(versions=[v1, v2])
    rep = certify_aggregate(manifest=presented, results=[_result("A", HA, 1, 2), _result("B", HB, 1, 1)], aggregate=AggregateReport(mean=0.75, n_classes=2))
    assert rep.ok, _reasons(rep)


# --------------------------------------------------------------------------- #
# Empty in-mean set: the headline is validated UNCONDITIONALLY
# --------------------------------------------------------------------------- #
def test_empty_in_mean_fabricated_headline_is_unverified(monkeypatch):
    _install(monkeypatch)
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("B", HB, status=ClassStatus.NA)])])
    rep = certify_aggregate(manifest=manifest, results=[], aggregate=AggregateReport(mean=1.0, n_classes=999))
    assert not rep.ok and ViolationReason.AGGREGATE_UNVERIFIED in _reasons(rep)


def test_empty_in_mean_honest_vacuous_headline_certifies(monkeypatch):
    _install(monkeypatch)
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("B", HB, status=ClassStatus.NA)])])
    rep = certify_aggregate(manifest=manifest, results=[], aggregate=AggregateReport(mean=0.0, n_classes=0))
    assert rep.ok, _reasons(rep)


def test_pin_mandatory_once_a_committed_manifest_baseline_exists(monkeypatch):
    # REAUDIT: advance_committed_root advances the manifest root to non-empty while never writing the
    # registry, so a real committed baseline + EMPTY registry is reachable. In that state the pin must
    # NOT be skipped — an unpinned in-mean class fails closed (else the cross-class re-point reopens).
    v1 = ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])
    _install(monkeypatch, manifest_root=ClassManifestHistory(versions=[v1]).root, class_registry={})  # real baseline, empty registry
    rep = certify_aggregate(manifest=ClassManifestHistory(versions=[v1]), results=[_result("A", HA, 1, 2), _result("B", HB, 1, 1)], aggregate=AggregateReport(mean=0.75, n_classes=2))
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


def test_repoint_swap_with_empty_registry_but_committed_baseline_fails(monkeypatch):
    # the exact re-audit attack: real committed baseline, empty registry, B re-pointed to A's root +
    # A's genuine signed attestation. The mandatory-pin-once-committed rule catches it.
    v1 = ClassManifest(version="v1", entries=[_entry("A", HA), _entry("B", HB)])
    _install(monkeypatch, manifest_root=ClassManifestHistory(versions=[v1]).root, class_registry={})
    v2 = ClassManifest(version="v2", entries=[_entry("A", HA), _entry("B", HA)], parent_version="v1")  # B -> HA
    swapped_b = CertifiedClassResult(class_id="B", attestation=_result("A", HA, 2, 2).attestation, report=_report(2, 2))
    rep = certify_aggregate(manifest=ClassManifestHistory(versions=[v1, v2]), results=[_result("A", HA, 2, 2), swapped_b], aggregate=AggregateReport(mean=1.0, n_classes=2))
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


def test_aggregate_mean_rejects_inf_nan():
    with pytest.raises(Exception):
        AggregateReport(mean=float("inf"), n_classes=1)
    with pytest.raises(Exception):
        AggregateReport(mean=2.0, n_classes=1)  # out of [0,1]
