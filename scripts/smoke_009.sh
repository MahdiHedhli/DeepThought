#!/usr/bin/env bash
# Feature 009 — aggregate class-manifest smoke.
#
# Demonstrates one HONEST aggregate certify plus each guard failing closed with a typed reason:
# the SET of classes feeding the headline mean is a committed, monotonic manifest, every in-mean
# class carries a valid signed per-class attestation, and the reported mean is RECOMPUTED. So no
# whole class can be silently dropped from the headline to inflate the mean.
#
# SAFETY (Article III): nothing fetched or target-side is executed — the aggregate binds already
# certified per-class attestations and the committed manifest; it re-runs no detector.
set -euo pipefail
cd "$(dirname "$0")/.."

.venv/bin/python - "$@" <<'PYEOF'
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path("benchmarks/harness").resolve()))

from contract import (
    Attestation, CommittedGenesisState, Report, RecallReport, ViolationReason,
    _EMPTY_ROOT, ed25519_public_key, leaf_hash, sign,
)
from aggregate import (
    AggregateReport, CertifiedClassResult, ClassManifest, ClassManifestEntry,
    ClassManifestEvent, ClassManifestHistory, ClassManifestLog, ClassStatus,
    ClassCorrectionReason, certify_aggregate,
)

KEY = hashlib.sha256(b"deepthought-aggregate-smoke-ed25519-seed/v1").digest()
PUB = ed25519_public_key(KEY)
WRONG = hashlib.sha256(b"attacker").digest()
EVAL = "curator-not-subject"
Z = "0" * 64
TS = "2026-07-18T00:00:00Z"

failures = []
def expect(label, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)

def committed(root=_EMPTY_ROOT):
    return CommittedGenesisState(
        genesis_history_root="a"*64, latest_history_root="a"*64, latest_attestation_root="b"*64,
        latest_evaluation_root=_EMPTY_ROOT, latest_exposure_root=_EMPTY_ROOT,
        latest_class_manifest_root=root, evaluator_id=EVAL, verify_key=PUB, adjudicator_roster={},
    )

def report(red, tot):
    return Report(blind_recall=RecallReport(rediscovered=red, total=tot),
                  fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
                  patched_alert_density=0.0, adjudicated_precision=1.0)

def result(cid, hroot, red, tot, *, key=KEY, ev=EVAL, rep=None):
    rep = rep if rep is not None else report(red, tot)
    att = Attestation(history_root=hroot, exclusion_root=Z, exposure_root=Z, evaluation_root=Z,
                      achievability_root=Z, freeze_hash=Z, pool_root=Z, run_id="r",
                      report_hash=leaf_hash(rep.model_dump(mode="json")), evaluator_id=ev,
                      attested_at=TS, prior_attestation_root=Z, signature="")
    att = att.model_copy(update={"signature": sign(att.attestation_root, key)})
    return CertifiedClassResult(class_id=cid, attestation=att, report=rep)

def entry(cid, hroot, status=ClassStatus.ACTIVE):
    return ClassManifestEntry(class_id=cid, cwe="CWE-1", detector_id="d", head_history_root=hroot, status=status)

ha, hb = "1"*64, "2"*64

print("== positive: honest aggregate over a committed manifest certifies ==")
manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("A", ha), entry("B", hb)])])
results = [result("A", ha, 1, 2), result("B", hb, 1, 1)]  # 0.5 and 1.0 -> mean 0.75
rep0 = certify_aggregate(manifest=manifest, results=results, aggregate=AggregateReport(mean=0.75, n_classes=2), committed=committed())
expect("honest aggregate certifies", rep0.ok)
print(f"        -> ok={rep0.ok} reasons={sorted(v.reason.value for v in rep0.violations)}")

print("== guard 1: an inflated reported mean fails closed ==")
rep1 = certify_aggregate(manifest=manifest, results=results, aggregate=AggregateReport(mean=0.90, n_classes=2), committed=committed())
expect("inflated mean trips AGGREGATE_UNVERIFIED", ViolationReason.AGGREGATE_UNVERIFIED in {v.reason for v in rep1.violations})

print("== guard 2: dropping a class with NO event fails closed ==")
v1 = ClassManifest(version="v1", entries=[entry("A", ha), entry("B", hb)])
v2 = ClassManifest(version="v2", entries=[entry("A", ha)], parent_version="v1")
rep2 = certify_aggregate(manifest=ClassManifestHistory(versions=[v1, v2]), results=[result("A", ha, 1, 2)],
                         aggregate=AggregateReport(mean=0.5, n_classes=1), committed=committed())
expect("silent class drop trips CLASS_SILENTLY_DROPPED", ViolationReason.CLASS_SILENTLY_DROPPED in {v.reason for v in rep2.violations})

print("== guard 3: a status-downgrade out of the mean with NO event fails closed ==")
v2d = ClassManifest(version="v2", entries=[entry("A", ha), entry("B", hb, status=ClassStatus.NA)], parent_version="v1")
rep3 = certify_aggregate(manifest=ClassManifestHistory(versions=[v1, v2d]), results=[result("A", ha, 1, 2)],
                         aggregate=AggregateReport(mean=0.5, n_classes=1), committed=committed())
expect("status-downgrade drop trips CLASS_SILENTLY_DROPPED", ViolationReason.CLASS_SILENTLY_DROPPED in {v.reason for v in rep3.violations})

print("== guard 4: an in-mean class with a missing attestation fails closed ==")
rep4 = certify_aggregate(manifest=manifest, results=[result("A", ha, 1, 2)],
                         aggregate=AggregateReport(mean=0.75, n_classes=2), committed=committed())
expect("missing per-class attestation trips CLASS_ATTESTATION_MISSING", ViolationReason.CLASS_ATTESTATION_MISSING in {v.reason for v in rep4.violations})

print("== guard 5: a cross-class attestation swap fails closed ==")
swapped = CertifiedClassResult(class_id="B", attestation=result("A", ha, 2, 2).attestation, report=report(2, 2))
m_b = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("B", hb)])])
rep5 = certify_aggregate(manifest=m_b, results=[swapped], aggregate=AggregateReport(mean=1.0, n_classes=1), committed=committed())
expect("cross-class attestation swap trips CLASS_ATTESTATION_INVALID", ViolationReason.CLASS_ATTESTATION_INVALID in {v.reason for v in rep5.violations})

print("== guard 6: a forged signature fails closed ==")
m_a = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("A", ha)])])
rep6 = certify_aggregate(manifest=m_a, results=[result("A", ha, 1, 2, key=WRONG)],
                         aggregate=AggregateReport(mean=0.5, n_classes=1), committed=committed())
expect("forged signature trips CLASS_ATTESTATION_INVALID", ViolationReason.CLASS_ATTESTATION_INVALID in {v.reason for v in rep6.violations})

print("== guard 7: a truncated manifest vs a real committed root fails closed ==")
baseline = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("A", ha), entry("B", hb)])])
presented = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("A", ha)])])
rep7 = certify_aggregate(manifest=presented, results=[result("A", ha, 1, 2)],
                         aggregate=AggregateReport(mean=0.5, n_classes=1), committed=committed(root=baseline.root))
expect("truncated manifest trips CLASS_MANIFEST_TRUNCATED", ViolationReason.CLASS_MANIFEST_TRUNCATED in {v.reason for v in rep7.violations})

print("== guard 8: a fabricated headline over ZERO in-mean classes fails closed (AUDIT-009-1) ==")
# an all-na head has no in-mean classes; a fabricated mean/n_classes must NOT ride through the
# recompute (the integrity check is unconditional, not gated on a non-empty in-mean set).
m_na = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("B", hb, status=ClassStatus.NA)])])
rep_na = certify_aggregate(manifest=m_na, results=[], aggregate=AggregateReport(mean=42.0, n_classes=999), committed=committed())
expect("empty-in-mean fabricated headline trips AGGREGATE_UNVERIFIED", ViolationReason.AGGREGATE_UNVERIFIED in {v.reason for v in rep_na.violations})

print("== guard 9: a cross-class swap pinned by the committed class registry fails closed (AUDIT-009-2) ==")
# weak class B's entry points at strong A's root (ha) with A's genuine signed attestation; the
# committed registry pins B -> hb, so the operator-controlled manifest binding cannot swap.
swap = CertifiedClassResult(class_id="B", attestation=result("A", ha, 2, 2).attestation, report=report(2, 2))
m_swap = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("B", ha)])])
com_reg = CommittedGenesisState(
    genesis_history_root="a"*64, latest_history_root="a"*64, latest_attestation_root="b"*64,
    latest_evaluation_root=_EMPTY_ROOT, latest_exposure_root=_EMPTY_ROOT, latest_class_manifest_root=_EMPTY_ROOT,
    evaluator_id=EVAL, verify_key=PUB, adjudicator_roster={}, class_registry={"B": hb})
rep_swap = certify_aggregate(manifest=m_swap, results=[swap], aggregate=AggregateReport(mean=1.0, n_classes=1), committed=com_reg)
expect("registry-pinned cross-class swap trips CLASS_ATTESTATION_INVALID", ViolationReason.CLASS_ATTESTATION_INVALID in {v.reason for v in rep_swap.violations})

print("== positive: a LOGGED class retirement is allowed (the mean legitimately shrinks) ==")
events = ClassManifestLog(events=[ClassManifestEvent(class_id="B", reason=ClassCorrectionReason.RETIRED, from_version="v1", to_version="v2")])
rep8 = certify_aggregate(manifest=ClassManifestHistory(versions=[v1, v2]), results=[result("A", ha, 1, 2)], events=events,
                         aggregate=AggregateReport(mean=0.5, n_classes=1), committed=committed())
expect("logged retirement certifies", rep8.ok)
print(f"        -> ok={rep8.ok} reasons={sorted(v.reason.value for v in rep8.violations)}")

print()
if failures:
    print(f"SMOKE 009 FAILED: {len(failures)} check(s): {failures}")
    sys.exit(1)
print("SMOKE 009 OK: the aggregate mean is a total function of the committed class set — no class can be silently dropped, every in-mean class is signed, and the mean is recomputed.")
PYEOF
