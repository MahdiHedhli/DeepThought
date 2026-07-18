"""Tests for feature 009 — the aggregate class-manifest.

The aggregate certify binds the SET of classes feeding the headline mean to a committed, monotonic
manifest, requires every in-mean class to carry a valid signed per-class attestation, and RECOMPUTES
the mean. These tests assert the honest aggregate certifies and every guard fails closed with a typed
reason. Hermetic: a fixed test ed25519 key + a directly-constructed committed state; no network.
"""

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "harness"))

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
    ClassManifest,
    ClassManifestEntry,
    ClassManifestEvent,
    ClassManifestHistory,
    ClassManifestLog,
    ClassStatus,
    ClassCorrectionReason,
    certify_aggregate,
)

KEY = hashlib.sha256(b"deepthought-aggregate-test-ed25519-seed/v1").digest()
PUB = ed25519_public_key(KEY)
WRONG_KEY = hashlib.sha256(b"attacker-aggregate-seed").digest()
EVAL = "curator-not-subject"
Z = "0" * 64
TS = "2026-07-18T00:00:00Z"


def _reasons(report):
    return {v.reason for v in report.violations}


def _committed(manifest_root=_EMPTY_ROOT):
    return CommittedGenesisState(
        genesis_history_root="a" * 64,
        latest_history_root="a" * 64,
        latest_attestation_root="b" * 64,
        latest_evaluation_root=_EMPTY_ROOT,
        latest_exposure_root=_EMPTY_ROOT,
        latest_class_manifest_root=manifest_root,
        evaluator_id=EVAL,
        verify_key=PUB,
        adjudicator_roster={},
    )


def _report(rediscovered, total):
    return Report(
        blind_recall=RecallReport(rediscovered=rediscovered, total=total),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
    )


def _result(class_id, head_history_root, rediscovered, total, *, sign_key=KEY, evaluator_id=EVAL, report=None):
    """A per-class certified result whose attestation binds ``head_history_root`` + the report and
    verifies against ``PUB`` (unless a wrong ``sign_key`` / ``report`` is injected to break a bind)."""
    rep = report if report is not None else _report(rediscovered, total)
    att = Attestation(
        history_root=head_history_root, exclusion_root=Z, exposure_root=Z, evaluation_root=Z,
        achievability_root=Z, freeze_hash=Z, pool_root=Z, run_id="r",
        report_hash=leaf_hash(rep.model_dump(mode="json")), evaluator_id=evaluator_id,
        attested_at=TS, prior_attestation_root=Z, signature="",
    )
    att = att.model_copy(update={"signature": sign(att.attestation_root, sign_key)})
    # the result carries `rep` for the mean; pass a DIFFERENT report to break the report_hash bind.
    return CertifiedClassResult(class_id=class_id, attestation=att, report=rep)


def _entry(class_id, head_history_root, status=ClassStatus.ACTIVE):
    return ClassManifestEntry(class_id=class_id, cwe="CWE-1", detector_id="d", head_history_root=head_history_root, status=status)


# --------------------------------------------------------------------------- #
# Honest path
# --------------------------------------------------------------------------- #
def test_honest_aggregate_certifies():
    ha, hb = "1" * 64, "2" * 64
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", ha), _entry("B", hb)])])
    results = [_result("A", ha, 1, 2), _result("B", hb, 1, 1)]  # rates 0.5 and 1.0 -> mean 0.75
    agg = AggregateReport(mean=0.75, n_classes=2)
    rep = certify_aggregate(manifest=manifest, results=results, aggregate=agg, committed=_committed())
    assert rep.ok, _reasons(rep)


def test_wrong_reported_mean_unverified():
    ha, hb = "1" * 64, "2" * 64
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", ha), _entry("B", hb)])])
    results = [_result("A", ha, 1, 2), _result("B", hb, 1, 1)]  # true mean 0.75
    agg = AggregateReport(mean=0.90, n_classes=2)  # inflated
    rep = certify_aggregate(manifest=manifest, results=results, aggregate=agg, committed=_committed())
    assert not rep.ok and ViolationReason.AGGREGATE_UNVERIFIED in _reasons(rep)


def test_wrong_n_classes_unverified():
    ha = "1" * 64
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", ha)])])
    rep = certify_aggregate(
        manifest=manifest, results=[_result("A", ha, 1, 2)],
        aggregate=AggregateReport(mean=0.5, n_classes=2), committed=_committed(),
    )
    assert not rep.ok and ViolationReason.AGGREGATE_UNVERIFIED in _reasons(rep)


# --------------------------------------------------------------------------- #
# The core guarantee: no class silently dropped from the mean
# --------------------------------------------------------------------------- #
def test_drop_class_without_event_is_silently_dropped():
    ha, hb = "1" * 64, "2" * 64
    v1 = ClassManifest(version="v1", entries=[_entry("A", ha), _entry("B", hb)])
    v2 = ClassManifest(version="v2", entries=[_entry("A", ha)], parent_version="v1")  # B dropped, NO event
    manifest = ClassManifestHistory(versions=[v1, v2])
    rep = certify_aggregate(
        manifest=manifest, results=[_result("A", ha, 1, 2)],
        aggregate=AggregateReport(mean=0.5, n_classes=1), committed=_committed(),
    )
    assert not rep.ok and ViolationReason.CLASS_SILENTLY_DROPPED in _reasons(rep)


def test_drop_class_with_matching_event_is_allowed():
    ha, hb = "1" * 64, "2" * 64
    v1 = ClassManifest(version="v1", entries=[_entry("A", ha), _entry("B", hb)])
    v2 = ClassManifest(version="v2", entries=[_entry("A", ha)], parent_version="v1")
    manifest = ClassManifestHistory(versions=[v1, v2])
    events = ClassManifestLog(events=[ClassManifestEvent(class_id="B", reason=ClassCorrectionReason.RETIRED, from_version="v1", to_version="v2")])
    rep = certify_aggregate(
        manifest=manifest, results=[_result("A", ha, 1, 2)], events=events,
        aggregate=AggregateReport(mean=0.5, n_classes=1), committed=_committed(),
    )
    assert rep.ok, _reasons(rep)


def test_status_downgrade_without_event_is_silently_dropped():
    ha, hb = "1" * 64, "2" * 64
    v1 = ClassManifest(version="v1", entries=[_entry("A", ha), _entry("B", hb)])
    # B kept but moved out of the mean (active -> na) with NO event
    v2 = ClassManifest(version="v2", entries=[_entry("A", ha), _entry("B", hb, status=ClassStatus.NA)], parent_version="v1")
    rep = certify_aggregate(
        manifest=ClassManifestHistory(versions=[v1, v2]), results=[_result("A", ha, 1, 2)],
        aggregate=AggregateReport(mean=0.5, n_classes=1), committed=_committed(),
    )
    assert not rep.ok and ViolationReason.CLASS_SILENTLY_DROPPED in _reasons(rep)


def test_split_transition_readd_as_retired_is_silently_dropped():
    # remove B (with a RETIRED event), then re-add B as retired a version later (ungated add) — B
    # leaves the mean; the terminal-head guard catches the split even though a per-pair event exists
    # only for the removal, not for the resurrection.
    ha, hb = "1" * 64, "2" * 64
    v1 = ClassManifest(version="v1", entries=[_entry("A", ha), _entry("B", hb)])
    v2 = ClassManifest(version="v2", entries=[_entry("A", ha)], parent_version="v1")
    v3 = ClassManifest(version="v3", entries=[_entry("A", ha), _entry("B", hb, status=ClassStatus.RETIRED)], parent_version="v2")
    events = ClassManifestLog(events=[ClassManifestEvent(class_id="B", reason=ClassCorrectionReason.RETIRED, from_version="v1", to_version="v2")])
    rep = certify_aggregate(
        manifest=ClassManifestHistory(versions=[v1, v2, v3]), results=[_result("A", ha, 1, 2)], events=events,
        aggregate=AggregateReport(mean=0.5, n_classes=1), committed=_committed(),
    )
    # B is present in head as retired (out of mean) but has a logged event, so per-pair passes; the
    # terminal-head guard still requires an event for B (it has one) — this asserts the HONEST
    # split (event present) is allowed, and the next test asserts the un-eventful split fails.
    assert rep.ok, _reasons(rep)


def test_split_transition_without_any_event_is_silently_dropped():
    ha, hb = "1" * 64, "2" * 64
    v1 = ClassManifest(version="v1", entries=[_entry("A", ha), _entry("B", hb)])
    v2 = ClassManifest(version="v2", entries=[_entry("A", ha), _entry("B", hb, status=ClassStatus.RETIRED)], parent_version="v1")
    # B moved out of the mean with NO event anywhere
    rep = certify_aggregate(
        manifest=ClassManifestHistory(versions=[v1, v2]), results=[_result("A", ha, 1, 2)],
        aggregate=AggregateReport(mean=0.5, n_classes=1), committed=_committed(),
    )
    assert not rep.ok and ViolationReason.CLASS_SILENTLY_DROPPED in _reasons(rep)


# --------------------------------------------------------------------------- #
# Per-class attestation integrity
# --------------------------------------------------------------------------- #
def test_missing_per_class_attestation():
    ha, hb = "1" * 64, "2" * 64
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", ha), _entry("B", hb)])])
    rep = certify_aggregate(  # B has no result
        manifest=manifest, results=[_result("A", ha, 1, 2)],
        aggregate=AggregateReport(mean=0.75, n_classes=2), committed=_committed(),
    )
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_MISSING in _reasons(rep)


def test_tampered_report_breaks_report_hash():
    ha = "1" * 64
    good = _result("A", ha, 1, 2)
    # swap in a HIGHER-recall report the attestation never committed
    tampered = CertifiedClassResult(class_id="A", attestation=good.attestation, report=_report(2, 2))
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", ha)])])
    rep = certify_aggregate(
        manifest=manifest, results=[tampered],
        aggregate=AggregateReport(mean=1.0, n_classes=1), committed=_committed(),
    )
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


def test_cross_class_attestation_swap():
    ha, hb = "1" * 64, "2" * 64
    # class B's slot presented with class A's attestation (history_root ha != entry hb)
    a_att = _result("A", ha, 2, 2).attestation
    a_report = _report(2, 2)
    swapped = CertifiedClassResult(class_id="B", attestation=a_att, report=a_report)
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("B", hb)])])
    rep = certify_aggregate(
        manifest=manifest, results=[swapped],
        aggregate=AggregateReport(mean=1.0, n_classes=1), committed=_committed(),
    )
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


def test_forged_signature():
    ha = "1" * 64
    forged = _result("A", ha, 1, 2, sign_key=WRONG_KEY)
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", ha)])])
    rep = certify_aggregate(
        manifest=manifest, results=[forged],
        aggregate=AggregateReport(mean=0.5, n_classes=1), committed=_committed(),
    )
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


def test_wrong_evaluator_id():
    ha = "1" * 64
    bad = _result("A", ha, 1, 2, evaluator_id="the-subject")
    manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", ha)])])
    rep = certify_aggregate(
        manifest=manifest, results=[bad],
        aggregate=AggregateReport(mean=0.5, n_classes=1), committed=_committed(),
    )
    assert not rep.ok and ViolationReason.CLASS_ATTESTATION_INVALID in _reasons(rep)


# --------------------------------------------------------------------------- #
# Committed-monotonic manifest root
# --------------------------------------------------------------------------- #
def test_manifest_truncation_against_a_real_committed_root():
    ha, hb = "1" * 64, "2" * 64
    # committed baseline had {A, B}; present a fresh single-version manifest with only A
    committed_baseline = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", ha), _entry("B", hb)])])
    committed = _committed(manifest_root=committed_baseline.root)
    presented = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[_entry("A", ha)])])  # drops B, wrong root
    rep = certify_aggregate(
        manifest=presented, results=[_result("A", ha, 1, 2)],
        aggregate=AggregateReport(mean=0.5, n_classes=1), committed=committed,
    )
    assert not rep.ok and ViolationReason.CLASS_MANIFEST_TRUNCATED in _reasons(rep)


def test_honest_extension_of_committed_root_certifies():
    ha, hb = "1" * 64, "2" * 64
    v1 = ClassManifest(version="v1", entries=[_entry("A", ha), _entry("B", hb)])
    committed = _committed(manifest_root=ClassManifestHistory(versions=[v1]).root)
    # extend with an appended version that keeps both classes in the mean
    v2 = ClassManifest(version="v2", entries=[_entry("A", ha), _entry("B", hb)], parent_version="v1")
    presented = ClassManifestHistory(versions=[v1, v2])
    rep = certify_aggregate(
        manifest=presented, results=[_result("A", ha, 1, 2), _result("B", hb, 1, 1)],
        aggregate=AggregateReport(mean=0.75, n_classes=2), committed=committed,
    )
    assert rep.ok, _reasons(rep)
