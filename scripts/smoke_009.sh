#!/usr/bin/env bash
# Feature 009 — aggregate class-manifest smoke.
#
# One HONEST aggregate certify plus each guard failing closed with a typed reason. The SET of classes
# feeding the headline mean is a committed, monotonic manifest; the trust anchor is loaded from
# COMMITTED state (never a caller argument); every in-mean class is registry-pinned and signed; every
# departure is authorized by a COMMITTED ClassExit; and the mean is RECOMPUTED. So no whole class can
# be silently dropped from the headline to inflate the mean.
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

import aggregate
from contract import (
    Attestation, CommittedGenesisState, Report, RecallReport, ViolationReason,
    _EMPTY_ROOT, ed25519_public_key, leaf_hash, sign,
)
from aggregate import (
    AggregateReport, CertifiedClassResult, ClassCorrectionReason, ClassExit, ClassManifest,
    ClassManifestEntry, ClassManifestHistory, ClassStatus, certify_aggregate,
)

KEY = hashlib.sha256(b"deepthought-aggregate-smoke-ed25519-seed/v1").digest()
PUB = ed25519_public_key(KEY)
WRONG = hashlib.sha256(b"attacker").digest()
EVAL = "curator-not-subject"
Z = "0" * 64
TS = "2026-07-18T00:00:00Z"
ha, hb = "1" * 64, "2" * 64

failures = []
def expect(label, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)

def install(manifest_root=_EMPTY_ROOT, registry=None):
    """008 R5: certify_aggregate loads committed state INTERNALLY; the smoke reassigns the loader
    with a hermetic state (a caller cannot pass the trust anchor in)."""
    state = CommittedGenesisState(
        genesis_history_root="a"*64, latest_history_root="a"*64, latest_attestation_root="b"*64,
        latest_evaluation_root=_EMPTY_ROOT, latest_exposure_root=_EMPTY_ROOT,
        latest_class_manifest_root=manifest_root, evaluator_id=EVAL, verify_key=PUB,
        adjudicator_roster={}, class_registry=registry or {},
    )
    aggregate.load_committed_genesis_state = lambda path=None: state

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

print("== positive: honest aggregate over a committed, registry-pinned manifest certifies ==")
install(registry={"A": ha, "B": hb})
manifest = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("A", ha), entry("B", hb)])])
results = [result("A", ha, 1, 2), result("B", hb, 1, 1)]  # 0.5 and 1.0 -> mean 0.75
rep0 = certify_aggregate(manifest=manifest, results=results, aggregate=AggregateReport(mean=0.75, n_classes=2))
expect("honest aggregate certifies", rep0.ok)
print(f"        -> ok={rep0.ok} reasons={sorted(v.reason.value for v in rep0.violations)}")

print("== guard 1: an inflated reported mean fails closed ==")
rep1 = certify_aggregate(manifest=manifest, results=results, aggregate=AggregateReport(mean=0.9, n_classes=2))
expect("inflated mean trips AGGREGATE_UNVERIFIED", ViolationReason.AGGREGATE_UNVERIFIED in {v.reason for v in rep1.violations})

print("== guard 2: dropping a class with NO committed exit fails closed ==")
v1 = ClassManifest(version="v1", entries=[entry("A", ha), entry("B", hb)])
v2 = ClassManifest(version="v2", entries=[entry("A", ha)], parent_version="v1")
rep2 = certify_aggregate(manifest=ClassManifestHistory(versions=[v1, v2]), results=[result("A", ha, 1, 2)], aggregate=AggregateReport(mean=0.5, n_classes=1))
expect("silent class drop trips CLASS_SILENTLY_DROPPED", ViolationReason.CLASS_SILENTLY_DROPPED in {v.reason for v in rep2.violations})

print("== guard 3: a cross-class swap re-pointed to a strong root, pinned by the registry, fails closed ==")
swap = CertifiedClassResult(class_id="B", attestation=result("A", ha, 2, 2).attestation, report=report(2, 2))
m_swap = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("B", ha)])])
install(registry={"B": hb})
rep3 = certify_aggregate(manifest=m_swap, results=[swap], aggregate=AggregateReport(mean=1.0, n_classes=1))
expect("registry-pinned cross-class swap trips CLASS_ATTESTATION_INVALID", ViolationReason.CLASS_ATTESTATION_INVALID in {v.reason for v in rep3.violations})

print("== guard 4: an in-mean class absent from the registry fails closed ==")
install(registry={"A": ha})  # B omitted
m_ab = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("A", ha), entry("B", hb)])])
rep4 = certify_aggregate(manifest=m_ab, results=[result("A", ha, 1, 2), result("B", hb, 1, 1)], aggregate=AggregateReport(mean=0.75, n_classes=2))
expect("unpinned in-mean class trips CLASS_ATTESTATION_INVALID", ViolationReason.CLASS_ATTESTATION_INVALID in {v.reason for v in rep4.violations})

print("== guard 5: a forged signature fails closed ==")
install(registry={"A": ha})
m_a = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("A", ha)])])
rep5 = certify_aggregate(manifest=m_a, results=[result("A", ha, 1, 2, key=WRONG)], aggregate=AggregateReport(mean=0.5, n_classes=1))
expect("forged signature trips CLASS_ATTESTATION_INVALID", ViolationReason.CLASS_ATTESTATION_INVALID in {v.reason for v in rep5.violations})

print("== guard 6: a truncated manifest vs a real committed root fails closed ==")
baseline = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("A", ha), entry("B", hb)])])
install(manifest_root=baseline.root, registry={"A": ha, "B": hb})
presented = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("A", ha)])])
rep6 = certify_aggregate(manifest=presented, results=[result("A", ha, 1, 2)], aggregate=AggregateReport(mean=0.5, n_classes=1))
expect("truncated manifest trips CLASS_MANIFEST_TRUNCATED", ViolationReason.CLASS_MANIFEST_TRUNCATED in {v.reason for v in rep6.violations})

print("== guard 7: a fabricated headline over ZERO in-mean classes fails closed ==")
install()
m_na = ClassManifestHistory(versions=[ClassManifest(version="v1", entries=[entry("B", hb, status=ClassStatus.NA)])])
rep7 = certify_aggregate(manifest=m_na, results=[], aggregate=AggregateReport(mean=1.0, n_classes=999))
expect("empty-in-mean fabricated headline trips AGGREGATE_UNVERIFIED", ViolationReason.AGGREGATE_UNVERIFIED in {v.reason for v in rep7.violations})

print("== positive: a COMMITTED class retirement is allowed (the mean legitimately shrinks) ==")
install(registry={"A": ha, "B": hb})
v2e = ClassManifest(version="v2", entries=[entry("A", ha)], exits=[ClassExit(class_id="B", reason=ClassCorrectionReason.RETIRED)], parent_version="v1")
rep8 = certify_aggregate(manifest=ClassManifestHistory(versions=[v1, v2e]), results=[result("A", ha, 1, 2)], aggregate=AggregateReport(mean=0.5, n_classes=1))
expect("committed retirement certifies", rep8.ok)
print(f"        -> ok={rep8.ok} reasons={sorted(v.reason.value for v in rep8.violations)}")

print()
if failures:
    print(f"SMOKE 009 FAILED: {len(failures)} check(s): {failures}")
    sys.exit(1)
print("SMOKE 009 OK: the aggregate mean is a total function of the committed class set — trust anchor loaded from committed state, no class silently dropped, every in-mean class registry-pinned + signed, mean recomputed.")
PYEOF
