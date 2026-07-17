#!/usr/bin/env bash
# Smoke test for feature 008 — the typed EvaluationContract.
#
# Builds a 2-entry cohort v1, freezes a dummy detector (committing the confusion
# pool root AND the precision sample size k), records exactly one blind evaluation,
# binds a Report + a panel-adjudicated precision, RECOMPUTES the numerator with a
# (fake, deterministic) frozen detector re-run, builds and SIGNS an Attestation
# chained to the git-committed genesis root, and passes strict certification. Then
# demonstrates each guard FAILING with a typed reason: an in-place entry edit, a
# silent denominator shrink, a second blind evaluation, a curator==subject score,
# the cryptographic-anchoring fail-closed cases (forged signature, omitted
# component, no attestation), a PART-2 numerator claim the frozen detector does not
# reproduce (NUMERATOR_UNVERIFIED, via a fake detector), and a PART-3 chain base not
# rooted in the committed genesis (GENESIS_UNANCHORED). Finally prints the Report
# with blind recall as the headline plus the four labelled secondaries. Exit 0 on
# success (all positives pass AND all guards trip with the expected reason).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="python3"

"$PY" - <<'PYEOF'
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "benchmarks" / "harness"))

from contract import (
    Adjudication,
    AdjudicatedPrecision,
    AdjudicatorVerdict,
    Attestation,
    Cohort,
    CohortEntry,
    CohortHistory,
    DetectorBundle,
    EvaluationLedger,
    EvaluationRun,
    ExclusionEvent,
    ExclusionLog,
    ExclusionReason,
    ExposureLedger,
    FreezeManifest,
    RecallReport,
    Report,
    Role,
    ViolationReason,
    ContractViolation,
    _canonical_run_id,
    build_attestation,
    load_committed_genesis_root,
    pool_root_of,
    precision_sample_seed,
    sample_confusion_pairs,
    validate,
)
from verifier import recompute_rediscovered

# A fixed evaluator key — DETERMINISTIC (never read from os.urandom). PRODUCTION
# swaps HMAC for ed25519 with the private key held by a party != the scored builder.
KEY = b"deepthought-smoke-evaluator-key-0123456789"


def entry(vuln, probe, role=Role.BLIND):
    return CohortEntry(
        repo="https://github.com/langgenius/dify",
        vuln_ref=vuln,
        patched_ref="c135ec4b08d946a1a1d3a198a1d72c1ccf47250f",
        target_paths=["api/core/rag/extractor/word_extractor.py"],
        sink_probe=probe,
        status="pinned",
        role=role,
    ).sealed()


failures = []


def expect(label, ok):
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {label}")
    if not ok:
        failures.append(label)


print("== positive: cohort v1, freeze (pool committed), one blind eval, SIGNED attestation, strict certify ==")
e1 = entry("8ab05d4c36b4720dc3f1f654564745f47c5034cd", "requests.get(url, stream=True)", Role.CALIBRATION)
e2 = entry("819a80836e991ca3f427b0e85faca159083d3d40", "client.get(url_spec.geturl()", Role.BLIND)
v1 = Cohort(version="v1", entries=[e1, e2], reason="initial cohort").sealed()
history = CohortHistory(versions=[v1])

# B4: the confusion-pair pool membership is committed in the freeze, BEFORE the seed
# is derivable, as a Merkle pool_root. P1d: the sample size k is committed alongside it.
pool = [f"p{i:02d}" for i in range(12)]
COMMITTED_K = 3
bundle = DetectorBundle(
    detector_id="DT-SSRF-TAINT",
    module_hashes={"ssrf_detector.py": "deadbeef"},
    rules_config_hash="rules-v1",
    lockfile_hash="lock-v1",
    interpreter_version="cpython-3.14",
    parser_versions={"tree-sitter-python": "0.23"},
    entrypoint="ssrf_detector:scan_source",
    params={"budget": 100},
    calibration_seed_ids=[e1.identity_hash],
    pool_root=pool_root_of(pool),
    committed_k=COMMITTED_K,
)
freeze = FreezeManifest(bundle=bundle, timestamp="2026-07-16T10:00:00Z")

ledger = ExposureLedger()
ledger.record(cohort_content_hash=v1.content_hash, actor="claude", activity="curated")

# R5: the run_id is the ONE canonical hash of (cohort, freeze, subject) — not a free string.
run_id = _canonical_run_id(v1.content_hash, freeze.freeze_hash, "codex")
run = EvaluationRun(run_id=run_id, subject="codex", cohort_content_hash=v1.content_hash, freeze_hash=freeze.freeze_hash)
run.attempt_evaluation(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E")

# A1/A2: a produced run MUST present a Report bound to the RUN's evaluated cohort.
report_view = Report(
    blind_recall=RecallReport(rediscovered=1, total=1),  # v1 has exactly one BLIND entry (e2)
    fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
    coverage=1.0,
    patched_alert_density=0.0,
    adjudicated_precision=1.0,
    cohort_content_hash=v1.content_hash,
    rediscovered_blind_ids=[e2.identity_hash],
)
evaluations = EvaluationLedger()  # an empty, honest evaluate-once ledger

# P1c/P1d: a real, panel-adjudicated precision bound to (cohort, freeze, run), drawn
# with the committed k. All-TP -> precision 1.0, matching the report's headline.
seed = precision_sample_seed(v1.content_hash, freeze.freeze_hash, run.run_id)
sampled = sample_confusion_pairs(pool, COMMITTED_K, seed)
precision_view = AdjudicatedPrecision(
    seed=seed,
    sampled_pairs=sampled,
    pool=pool,
    k=COMMITTED_K,
    cohort_hash=v1.content_hash,
    freeze_hash=freeze.freeze_hash,
    run_id=run.run_id,
    adjudications=[
        Adjudication(
            pair_id=p,
            verdicts=[
                AdjudicatorVerdict(adjudicator="A", is_builder=False, is_curator=False, decision="true-positive"),
                AdjudicatorVerdict(adjudicator="B", is_builder=False, is_curator=True, decision="true-positive"),
            ],
        )
        for p in sampled
    ],
)

# PART 2: RECOMPUTE the numerator by re-running a (here fake, deterministic) frozen
# detector on the pinned SHAs. A marker-driven fake detector flags the blind sink in
# the vuln tree and not in the patched tree, so the recompute confirms e2 -> the
# claimed rediscovery is VERIFIED, not trusted. (Article III: the detector parses the
# fetched source as DATA; it is never executed.)
_FILES = {
    (e2.vuln_ref, "api/core/rag/extractor/word_extractor.py"): "def f(url_spec):\n    client.get(url_spec.geturl(), timeout=5)  # FLAG\n",
    (e2.patched_ref, "api/core/rag/extractor/word_extractor.py"): "def f(url_spec):\n    ssrf_proxy.validate(url_spec)\n    client.get(url_spec.geturl(), timeout=5)\n",
}
def _fake_fetch(repo, ref, path):
    return _FILES[(ref, path)]
def _fake_scan(source, uri):
    return [
        {"locations": [{"physicalLocation": {"region": {"startLine": i}}}]}
        for i, line in enumerate(source.splitlines(), 1) if "FLAG" in line
    ]
def _fake_scan_blind(source, uri):
    return []  # a fake detector that produces NOTHING -> confirms no rediscovery
recomputed = recompute_rediscovered([e2], fetch_fn=_fake_fetch, scan_fn=_fake_scan)

# B5: bind every component root into one signed Attestation (chained to the committed genesis).
attestation = build_attestation(
    history=history,
    freeze=freeze,
    run=run,
    report=report_view,
    evaluator_id="curator-not-subject",
    attested_at="2026-07-16T12:00:00Z",
    key=KEY,
    prior_attestation_root=load_committed_genesis_root(),  # P1a/PART3: chain base roots in the committed genesis
    exclusions=None,
    ledger=ledger,
    evaluation_ledger=evaluations,
    achievability=None,
)

# R6: a run with post-freeze attempts is validated against its FreezeManifest (freeze=).
certified = validate(
    history=history,
    ledger=ledger,
    run=run,
    freeze=freeze,
    report=report_view,
    precision=precision_view,
    prior_evaluations=evaluations,
    attestation=attestation,
    verify_key=KEY,
    recomputed_rediscovered=recomputed,
    strict=True,
)
expect("honest signed attestation certifies (strict)", certified.ok)
expect("exactly one semantic evaluation recorded", run.semantic_evaluation_count == 1)
expect("numerator recompute confirms the claimed rediscovery", recomputed == {e2.identity_hash})

print()
print("== guard 1: in-place entry edit without a version bump ==")
tampered_entry = e2.model_copy(update={"sink_probe": "open(p)"}).sealed()
v1_tampered = v1.model_copy(update={"entries": [e1, tampered_entry]})  # keeps v1's sealed content hash
rep1 = validate(history=CohortHistory(versions=[v1_tampered]))
expect("in-place edit trips IN_PLACE_EDIT", ViolationReason.IN_PLACE_EDIT in rep1.reasons())
print(f"        -> {rep1.summary()}")

print()
print("== guard 2: silent denominator shrink (drop a hard case, no exclusion event) ==")
v2_shrunk = Cohort(version="v2", entries=[e1], reason="dropped the blind case", parent_version="v1").sealed()
rep2 = validate(history=CohortHistory(versions=[v1, v2_shrunk]))
expect("silent shrink trips DENOMINATOR_SHRINK", ViolationReason.DENOMINATOR_SHRINK in rep2.reasons())
print(f"        -> {rep2.summary()}")
# and it is allowed once the removal is logged
excl = ExclusionLog(events=[ExclusionEvent(reason=ExclusionReason.ALIAS_DUPE, entry_identity=e2.identity_hash, from_version="v1", to_version="v2")])
rep2b = validate(history=CohortHistory(versions=[v1, v2_shrunk]), exclusions=excl)
expect("the same removal validates once logged", rep2b.ok)

print()
print("== guard 3: a second post-freeze blind evaluation ==")
tripped = False
try:
    run.attempt_evaluation(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E")
except ContractViolation as exc:
    tripped = exc.reason is ViolationReason.BLIND_ACCESS_EXCEEDED
    print(f"        -> refused: {exc}")
expect("second blind eval refused with BLIND_ACCESS_EXCEEDED", tripped)

print()
print("== guard 4: curator == subject ==")
run_self_id = _canonical_run_id(v1.content_hash, freeze.freeze_hash, "claude")
run_self = EvaluationRun(run_id=run_self_id, subject="claude", cohort_content_hash=v1.content_hash, freeze_hash=freeze.freeze_hash)
rep4 = validate(run=run_self, ledger=ledger)
expect("curator scoring itself trips CURATOR_IS_SUBJECT", ViolationReason.CURATOR_IS_SUBJECT in rep4.reasons())
print(f"        -> {rep4.summary()}")

print()
print("== guard 5: cryptographic anchoring fails closed (forged / omitted / unanchored) ==")
# a forged signature cannot certify
forged = attestation.model_copy(update={"signature": "00" * 32})
rep5a = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    prior_evaluations=evaluations, attestation=forged, verify_key=KEY, strict=True,
)
expect("forged signature trips ATTESTATION_INVALID", ViolationReason.ATTESTATION_INVALID in rep5a.reasons())
print(f"        -> {rep5a.summary()}")

# omitting a referenced component (the history) fails closed
rep5b = validate(
    history=None, ledger=ledger, run=run, freeze=freeze, report=report_view,
    prior_evaluations=evaluations, attestation=attestation, verify_key=KEY, strict=True,
)
expect("omitted history component trips ATTESTATION_INCOMPLETE", ViolationReason.ATTESTATION_INCOMPLETE in rep5b.reasons())
print(f"        -> {rep5b.summary()}")

# certifying with NO attestation at all is UNANCHORED
rep5c = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    prior_evaluations=evaluations, strict=True,
)
expect("certify with no attestation trips UNANCHORED", ViolationReason.UNANCHORED in rep5c.reasons())
print(f"        -> {rep5c.summary()}")

print()
print("== guard 6: PART 2 numerator verifier — a claim the frozen detector does not reproduce ==")
# a fake frozen detector that produces NOTHING on the real code: the report still
# CLAIMS e2 rediscovered, but the recompute does not confirm it -> NUMERATOR_UNVERIFIED
recomputed_blind = recompute_rediscovered([e2], fetch_fn=_fake_fetch, scan_fn=_fake_scan_blind)
rep6 = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=precision_view, prior_evaluations=evaluations, attestation=attestation,
    verify_key=KEY, recomputed_rediscovered=recomputed_blind, strict=True,
)
expect("unconfirmed rediscovery trips NUMERATOR_UNVERIFIED", ViolationReason.NUMERATOR_UNVERIFIED in rep6.reasons())
expect("the fake detector reproduced nothing", recomputed_blind == set())
print(f"        -> {rep6.summary()}")

print()
print("== guard 7: PART 3 genesis anchoring — a chain base not rooted in the committed genesis ==")
# an attestation whose prior_attestation_root is NOT the committed genesis root
unrooted_att = build_attestation(
    history=history, freeze=freeze, run=run, report=report_view,
    evaluator_id="curator-not-subject", attested_at="2026-07-16T12:00:00Z", key=KEY,
    prior_attestation_root="deadbeef" * 8,  # a fresh, unreviewable, un-anchored genesis
    exclusions=None, ledger=ledger, evaluation_ledger=evaluations, achievability=None,
)
rep7 = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=precision_view, prior_evaluations=evaluations, attestation=unrooted_att,
    verify_key=KEY, recomputed_rediscovered=recomputed, strict=True,
)
expect("un-anchored chain base trips GENESIS_UNANCHORED", ViolationReason.GENESIS_UNANCHORED in rep7.reasons())
print(f"        -> {rep7.summary()}")

print()
print("== report: blind recall is the headline, four labelled secondaries ==")
rep = Report(
    blind_recall=RecallReport(rediscovered=3, total=4, patched_alert_density=1.2),
    fixed_cohort_recall=RecallReport(rediscovered=9, total=10),
    coverage=0.95,
    patched_alert_density=1.2,
    adjudicated_precision=0.8,
    achievable_recall=0.9,
)
for line in rep.lines():
    print(f"  {line}")
lines = rep.lines()
expect("headline line is blind recall", "blind recall" in lines[0].lower())
for label in ("fixed-cohort recall", "coverage", "patched-alert density", "adjudicated precision"):
    expect(f"secondary present: {label}", label in rep.render())
expect("authoritative recall is the blind number", rep.authoritative_recall is rep.blind_recall)

print()
if failures:
    print(f"SMOKE FAILED: {len(failures)} check(s) failed: {failures}")
    sys.exit(1)
print("SMOKE 008 OK: contract certifies the signed run and every guard (incl. anchoring) trips with a typed reason.")
PYEOF
