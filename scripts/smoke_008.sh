#!/usr/bin/env bash
# Smoke test for feature 008 — the typed EvaluationContract.
#
# Builds a 2-entry cohort v1, freezes a dummy detector, records exactly one blind
# evaluation, and passes validate(). Then demonstrates each guard FAILING with a
# typed reason: an in-place entry edit, a silent denominator shrink, a second
# blind evaluation, and a curator==subject score. Finally prints the Report with
# blind recall as the headline plus the four labelled secondaries. Exit 0 on
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
    Cohort,
    CohortEntry,
    CohortHistory,
    DetectorBundle,
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
    validate,
)


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


print("== positive: a clean 2-entry cohort v1, freeze, one blind eval, validate ==")
e1 = entry("8ab05d4c36b4720dc3f1f654564745f47c5034cd", "requests.get(url, stream=True)", Role.CALIBRATION)
e2 = entry("819a80836e991ca3f427b0e85faca159083d3d40", "client.get(url_spec.geturl()", Role.BLIND)
v1 = Cohort(version="v1", entries=[e1, e2], reason="initial cohort").sealed()
history = CohortHistory(versions=[v1])

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
)
freeze = FreezeManifest(bundle=bundle, timestamp="2026-07-16T10:00:00Z")

ledger = ExposureLedger()
ledger.record(cohort_content_hash=v1.content_hash, actor="claude", activity="curated")

# R5: the run_id is the ONE canonical hash of (cohort, freeze, subject) — not a free string.
run_id = _canonical_run_id(v1.content_hash, freeze.freeze_hash, "codex")
run = EvaluationRun(run_id=run_id, subject="codex", cohort_content_hash=v1.content_hash, freeze_hash=freeze.freeze_hash)
run.attempt_evaluation(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E")
# R6: a run with post-freeze attempts is validated against its FreezeManifest (freeze=).
report = validate(history=history, ledger=ledger, run=run, freeze=freeze)
expect("clean cohort + one blind eval validates", report.ok)
expect("exactly one semantic evaluation recorded", run.semantic_evaluation_count == 1)

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
print("SMOKE 008 OK: contract validates the clean run and every guard trips with a typed reason.")
PYEOF
