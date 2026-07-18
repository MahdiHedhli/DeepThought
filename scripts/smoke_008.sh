#!/usr/bin/env bash
# Smoke test for feature 008 — the typed EvaluationContract.
#
# Builds a 2-entry cohort v1, freezes a dummy detector (committing the confusion
# pool root AND the precision sample size k), records exactly one blind evaluation,
# binds a Report + a panel-adjudicated precision, RECOMPUTES the numerator with a
# (fake, deterministic) frozen detector re-run, builds and ed25519-SIGNS an Attestation
# (with the test/build signing seed whose PUBLIC key is committed in genesis_root.json)
# chained to the git-committed genesis root, and passes strict certification. Then
# demonstrates each guard FAILING with a typed reason: an in-place entry edit, a
# silent denominator shrink, a second blind evaluation, a curator==subject score,
# the cryptographic-anchoring fail-closed cases (forged signature, omitted
# component, no attestation), a PART-2 numerator claim the frozen detector does not
# reproduce (NUMERATOR_UNVERIFIED, via a fake detector), a PART-3 chain base not
# rooted in the committed genesis (GENESIS_UNANCHORED), and the round-6 floor seals:
# a stale non-head run (F1, DENOMINATOR_SHRINK), a prior_evaluations that does not
# reproduce the committed eval-ledger root (F2, EVALUATED_MORE_THAN_ONCE), and a
# produced+reported run with no certification (F3, UNANCHORED), the round-7 structural
# seals — the default `check` REFUSING an unanchored Report headline (R7-1, UNANCHORED)
# and a certified report carrying a FREE secondary numeric failing closed (R7-2,
# COVERAGE_UNBOUND), the round-8 seals — a DOCTORED fetch whose bytes do not reproduce the
# committed per-target blob sha256 (R8-1, INPUT_BYTES_UNVERIFIED) and a re-rolled precision
# sample that does not reproduce the committed freeze sample_root (R8-2, PRECISION_SAMPLE_UNBOUND),
# and the round-9 final per-cohort seals — an operator-CHERRY-PICKED precision sample that is not
# the CANONICAL draw from committed state (R9-1, PRECISION_SAMPLE_UNBOUND) and a version-bumped
# curator whose non-empty curated_entry_ids miss the head yet whose cohort shares entries with the
# scored head (R9-2, CURATOR_IS_SUBJECT), and the round-10 comprehensive final seals — a detector
# CODE swap under a preserved name/freeze (R10-1, DETECTOR_BUNDLE_UNVERIFIED), a truncated
# committed-monotonic exposure ledger (R10-2, EXPOSURE_LEDGER_TRUNCATED), and a from-storage
# precision panel with a builder adjudicator re-enforced on the certify path (R10-5,
# PRECISION_PANEL_INVALID).
# Finally prints the Report with blind recall as the headline plus the four labelled secondaries.
# Exit 0 on success (all positives pass AND all guards trip with the expected reason).
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
    blob_sha256,
    build_attestation,
    check,
    ed25519_public_key,
    load_committed_evaluator_id,
    load_committed_genesis_root,
    load_committed_verify_key,
    pool_root_of,
    precision_sample_seed,
    sample_confusion_pairs,
    sample_root_of,
    validate,
)
import hashlib

import contract
import verifier
from verifier import recompute_certified_numerator

# The FIXED test/build ed25519 SIGNING seed (the PRIVATE key) — DETERMINISTIC (never read
# from os.urandom). It lives ONLY here in the smoke (a test/build helper), NEVER in
# genesis_root.json: the committed file holds ONLY the derived PUBLIC key (F4). validate()
# verifies the attestation against that committed public key; a repo reader can verify but
# cannot forge. PRODUCTION holds the private key externally (curator != subject) — the
# organizational key-custody floor. The sanity assert confirms the committed public key is
# exactly the one this signing seed corresponds to.
SIGNING_KEY = hashlib.sha256(b"deepthought/evaluation-contract/committed-test-ed25519-seed/v1").digest()
EVALUATOR_ID = load_committed_evaluator_id()
assert ed25519_public_key(SIGNING_KEY) == load_committed_verify_key(), (
    "the committed ed25519 public key must match the test/build signing seed"
)


PATCHED_REF = "c135ec4b08d946a1a1d3a198a1d72c1ccf47250f"
TARGET_PATH = "api/core/rag/extractor/word_extractor.py"
E2_VULN_REF = "819a80836e991ca3f427b0e85faca159083d3d40"

# PART 2 / R5-1: the certify path RECOMPUTES the numerator ITSELF by re-running the COMMITTED
# detector on the pinned SHAs. R8-1: each blind CohortEntry commits the per-target sha256 of the
# bytes at (vuln_ref/patched_ref, path); the recompute requires the fetched bytes to reproduce it.
# Here we use a (fake, deterministic) frozen detector + fetcher so the smoke is hermetic (production
# resolves the real ssrf_detector + GitHub-raw fetcher). A marker-driven fake detector flags the
# blind sink in the vuln tree and not in the patched tree, so validate()'s own recompute confirms
# e2. (Article III: the detector parses the fetched source as DATA; it is never executed.)
_FILES = {
    (E2_VULN_REF, TARGET_PATH): "def f(url_spec):\n    client.get(url_spec.geturl(), timeout=5)  # FLAG\n",
    (PATCHED_REF, TARGET_PATH): "def f(url_spec):\n    ssrf_proxy.validate(url_spec)\n    client.get(url_spec.geturl(), timeout=5)\n",
}


def entry(vuln, probe, role=Role.BLIND):
    # R8-1: commit the per-target blob sha256 from the pinned bytes when they are known (the blind
    # target); a calibration seed whose bytes are not in the fake corpus keeps empty blobs.
    paths = [TARGET_PATH]
    vuln_blobs = {p: blob_sha256(_FILES[(vuln, p)]) for p in paths if (vuln, p) in _FILES}
    patched_blobs = {p: blob_sha256(_FILES[(PATCHED_REF, p)]) for p in paths if (PATCHED_REF, p) in _FILES}
    return CohortEntry(
        repo="https://github.com/langgenius/dify",
        vuln_ref=vuln,
        patched_ref=PATCHED_REF,
        target_paths=paths,
        sink_probe=probe,
        status="pinned",
        vuln_blob_sha256=vuln_blobs,
        patched_blob_sha256=patched_blobs,
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
# R8-2: the precision SAMPLE itself is committed inside the frozen bundle as a sample_root —
# drawn from committed, NON-grindable inputs (cohort identity + canonical pool + k), NOT the
# grindable freeze_hash — so grinding an inert bundle param can no longer re-roll the sample.
pool = [f"p{i:02d}" for i in range(12)]
COMMITTED_K = 3
SAMPLE_SEED = precision_sample_seed(v1.content_hash, pool_root_of(pool), str(COMMITTED_K))
sampled = sample_confusion_pairs(pool, COMMITTED_K, SAMPLE_SEED)
COMMITTED_SAMPLE_ROOT = sample_root_of(sampled)
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
    committed_sample_root=COMMITTED_SAMPLE_ROOT,
)
freeze = FreezeManifest(bundle=bundle, timestamp="2026-07-16T10:00:00Z")

ledger = ExposureLedger()
ledger.record(cohort_content_hash=v1.content_hash, actor="claude", activity="curated")

# R5: the run_id is the ONE canonical hash of (cohort, freeze, subject) — not a free string.
run_id = _canonical_run_id(v1.content_hash, freeze.freeze_hash, "codex")
run = EvaluationRun(run_id=run_id, subject="codex", cohort_content_hash=v1.content_hash, freeze_hash=freeze.freeze_hash)
# R8-5: a producing attempt carries a non-empty results_hash binding produced_results.
run.attempt_evaluation(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E", results_hash="R1")

# A1/A2: a produced run MUST present a Report bound to the RUN's evaluated cohort.
# R7-2: a certified report carries NO free coverage (None) and its patched_alert_density /
# fixed_cohort_recall are exactly what validate() recomputes from the committed detector.
report_view = Report(
    blind_recall=RecallReport(rediscovered=1, total=1),  # v1 has exactly one BLIND entry (e2)
    fixed_cohort_recall=RecallReport(rediscovered=0, total=0),  # no REGRESSION entries -> (0, 0)
    coverage=None,  # R7-2: forbidden on a certified report
    patched_alert_density=0.0,  # e2's patched tree flags nothing -> density 0.0
    adjudicated_precision=1.0,
    cohort_content_hash=v1.content_hash,
    rediscovered_blind_ids=[e2.identity_hash],
)
evaluations = EvaluationLedger()  # an empty, honest evaluate-once ledger

# P1c/R8-2: a real, panel-adjudicated precision whose sampled_pairs reproduce the freeze's
# committed sample_root. All-TP -> precision 1.0, matching the report's headline.
precision_view = AdjudicatedPrecision(
    seed=SAMPLE_SEED,
    sampled_pairs=sampled,
    pool=pool,
    k=COMMITTED_K,
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

def _fake_fetch(repo, ref, path):
    return _FILES[(ref, path)]
def _fake_scan(source, uri):
    return [
        {"locations": [{"physicalLocation": {"region": {"startLine": i}}}]}
        for i, line in enumerate(source.splitlines(), 1) if "FLAG" in line
    ]
def _fake_scan_blind(source, uri):
    return []  # a fake detector that produces NOTHING -> confirms no rediscovery

# Install the committed detector + fetcher (module-level, monkeypatchable): validate()
# resolves DT-SSRF-TAINT's scan_source from DETECTOR_REGISTRY and the fetcher from FETCH_FN.
# R10-1: validate() ALSO recomputes the loaded detector module's CONTENT HASH from
# DETECTOR_MODULE_HASHES (keyed by the frozen detector_id) and binds it to the frozen bundle's
# module_hashes — trust the CODE HASH, not the name. The hermetic smoke installs a matching
# committed hash (production hashes the real ssrf_detector.py source).
verifier.FETCH_FN = _fake_fetch
verifier.DETECTOR_REGISTRY["DT-SSRF-TAINT"] = lambda: _fake_scan
verifier.DETECTOR_MODULE_HASHES["DT-SSRF-TAINT"] = lambda: {"ssrf_detector.py": "deadbeef"}

# B5: bind every component root into one signed Attestation (chained to the committed genesis).
attestation = build_attestation(
    history=history,
    freeze=freeze,
    run=run,
    report=report_view,
    evaluator_id=EVALUATOR_ID,  # the COMMITTED evaluator id (curator != subject)
    attested_at="2026-07-16T12:00:00Z",
    key=SIGNING_KEY,
    prior_attestation_root=load_committed_genesis_root(),  # R5-2/PART3: chain from the committed latest attestation root
    exclusions=None,
    ledger=ledger,
    evaluation_ledger=evaluations,
    achievability=None,
)

# R6: a run with post-freeze attempts is validated against its FreezeManifest (freeze=).
# The verify-key + evaluator id + genesis chain + numerator recompute are all loaded/RUN
# from committed state — no verify_key / recomputed_rediscovered caller args (R5-1/R5-4).
certified = validate(
    history=history,
    ledger=ledger,
    run=run,
    freeze=freeze,
    report=report_view,
    precision=precision_view,
    prior_evaluations=evaluations,
    attestation=attestation,
    strict=True,
)
expect("honest signed attestation certifies (strict)", certified.ok)
if not certified.ok:
    print(f"        -> {certified.summary()}")
expect("exactly one semantic evaluation recorded", run.semantic_evaluation_count == 1)
expect(
    "committed detector re-run confirms the claimed rediscovery",
    recompute_certified_numerator([e2], detector_id="DT-SSRF-TAINT") == {e2.identity_hash},
)

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
# a forged signature cannot certify (verified against the COMMITTED evaluator key; no
# verify_key caller arg — R5-4)
forged = attestation.model_copy(update={"signature": "00" * 32})
rep5a = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=precision_view, prior_evaluations=evaluations, attestation=forged, strict=True,
)
expect("forged signature trips ATTESTATION_INVALID", ViolationReason.ATTESTATION_INVALID in rep5a.reasons())
print(f"        -> {rep5a.summary()}")

# omitting a referenced component (the history) fails closed
rep5b = validate(
    history=None, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=precision_view, prior_evaluations=evaluations, attestation=attestation, strict=True,
)
expect("omitted history component trips ATTESTATION_INCOMPLETE", ViolationReason.ATTESTATION_INCOMPLETE in rep5b.reasons())
print(f"        -> {rep5b.summary()}")

# certifying with NO attestation at all is UNANCHORED
rep5c = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=precision_view, prior_evaluations=evaluations, strict=True,
)
expect("certify with no attestation trips UNANCHORED", ViolationReason.UNANCHORED in rep5c.reasons())
print(f"        -> {rep5c.summary()}")

print()
print("== guard 6: PART 2 numerator verifier — a claim the committed detector does not reproduce ==")
# swap the committed detector for a fake that produces NOTHING on the real code: the report
# still CLAIMS e2 rediscovered, but validate()'s own recompute does not confirm it ->
# NUMERATOR_UNVERIFIED. The recompute is RUN from committed state, not a caller arg (R5-1).
verifier.DETECTOR_REGISTRY["DT-SSRF-TAINT"] = lambda: _fake_scan_blind
rep6 = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=precision_view, prior_evaluations=evaluations, attestation=attestation,
    strict=True,
)
expect("unconfirmed rediscovery trips NUMERATOR_UNVERIFIED", ViolationReason.NUMERATOR_UNVERIFIED in rep6.reasons())
expect("the fake detector reproduced nothing", recompute_certified_numerator([e2], detector_id="DT-SSRF-TAINT") == set())
print(f"        -> {rep6.summary()}")
# restore the honest committed detector for the remaining guards
verifier.DETECTOR_REGISTRY["DT-SSRF-TAINT"] = lambda: _fake_scan

print()
print("== guard 7: PART 3 genesis anchoring — a chain base not rooted in the committed genesis ==")
# an attestation whose prior_attestation_root is NOT the committed latest-attestation root
unrooted_att = build_attestation(
    history=history, freeze=freeze, run=run, report=report_view,
    evaluator_id=EVALUATOR_ID, attested_at="2026-07-16T12:00:00Z", key=SIGNING_KEY,
    prior_attestation_root="deadbeef" * 8,  # a fresh, unreviewable, un-anchored genesis
    exclusions=None, ledger=ledger, evaluation_ledger=evaluations, achievability=None,
)
rep7 = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=precision_view, prior_evaluations=evaluations, attestation=unrooted_att,
    strict=True,
)
expect("un-anchored chain base trips GENESIS_UNANCHORED", ViolationReason.GENESIS_UNANCHORED in rep7.reasons())
print(f"        -> {rep7.summary()}")

print()
print("== guard 8: F1 head-binding — a certified run bound to a stale (non-head) cohort ==")
# the head appends a hard case (e3); the run is still bound to the STALE v1, silently dropping
# it — validate() binds the denominator to the HEAD, so a non-head run trips DENOMINATOR_SHRINK
e3 = entry("3" * 40, "sinkc(url)", Role.BLIND)
v2_head = Cohort(version="v2", entries=[e1, e2, e3], reason="append a hard case at the head", parent_version="v1").sealed()
rep8 = validate(
    history=CohortHistory(versions=[v1, v2_head]), ledger=ledger, run=run, freeze=freeze,
    report=report_view, precision=precision_view, prior_evaluations=evaluations,
    attestation=attestation, strict=True,
)
expect("stale non-head run trips DENOMINATOR_SHRINK", ViolationReason.DENOMINATOR_SHRINK in rep8.reasons())
print(f"        -> {rep8.summary()}")

print()
print("== guard 9: F2 committed eval-ledger — an empty prior_evaluations cannot dodge a committed prior eval ==")
# the committed evaluation-ledger already records a prior evaluation (evaluate-once is COMMITTED
# monotonic state). Presenting an EMPTY prior_evaluations to dodge the re-roll check does not
# reproduce the committed non-empty eval root -> EVALUATED_MORE_THAN_ONCE. We install a committed
# state whose evaluation_root reflects that prior eval (the smoke otherwise uses the real file).
prior_committed = EvaluationLedger()
prior_committed.record(
    cohort_content_hash=v1.content_hash, freeze_hash="an-earlier-freeze",
    subject="codex", blind_ids=[e2.identity_hash],
)
_orig_loader = contract.load_committed_genesis_state
_committed_with_prior_eval = _orig_loader().model_copy(
    update={"latest_evaluation_root": prior_committed.root}
)
contract.load_committed_genesis_state = lambda *a, **k: _committed_with_prior_eval
try:
    rep9 = validate(
        history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
        precision=precision_view, prior_evaluations=EvaluationLedger(),  # the dodge: an empty ledger
        attestation=attestation, strict=True,
    )
finally:
    contract.load_committed_genesis_state = _orig_loader  # restore the real committed loader
expect("empty prior_evaluations dodging a committed prior eval trips EVALUATED_MORE_THAN_ONCE", ViolationReason.EVALUATED_MORE_THAN_ONCE in rep9.reasons())
print(f"        -> {rep9.summary()}")

print()
print("== guard 10: F3 structural certify — a produced+reported run WITHOUT certification is UNANCHORED ==")
# a producing run + a headline Report presented with NO strict/attestation can never be blessed
# unanchored; certification is mandatory for a produced+reported result
rep10 = validate(history=history, ledger=ledger, run=run, freeze=freeze, report=report_view)
expect("produced+reported run without certification trips UNANCHORED", ViolationReason.UNANCHORED in rep10.reasons())
print(f"        -> {rep10.summary()}")

print()
print("== guard 11: R7-1 structural certify — the DEFAULT check refuses an unanchored Report headline ==")
# certification is STRUCTURAL on the REPORT: a Report asserting a numerator presented through the
# plain default `check` (no run, no strict, no attestation) can never be blessed — UNANCHORED. Even
# the default `check = validate` alias cannot bless an unanchored/truncated headline.
rep11 = check(history=history, report=report_view)
expect("default check refuses an unanchored Report headline (UNANCHORED)", ViolationReason.UNANCHORED in rep11.reasons())
print(f"        -> {rep11.summary()}")

print()
print("== guard 12: R7-2 bind-every-numeric — a certified report with a FREE secondary numeric fails closed ==")
# every certified numeric is recomputed from committed state or FORBIDDEN. A certified report
# carrying a free `coverage` (pinned/all — not recomputable from committed state) fails closed.
bad_report = report_view.model_copy(update={"coverage": 0.9})
bad_att = build_attestation(
    history=history, freeze=freeze, run=run, report=bad_report,
    evaluator_id=EVALUATOR_ID, attested_at="2026-07-16T12:00:00Z", key=SIGNING_KEY,
    prior_attestation_root=load_committed_genesis_root(),
    exclusions=None, ledger=ledger, evaluation_ledger=evaluations, achievability=None,
)
rep12 = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=bad_report,
    precision=precision_view, prior_evaluations=evaluations, attestation=bad_att, strict=True,
)
expect("certified report with a free coverage numeric trips COVERAGE_UNBOUND", ViolationReason.COVERAGE_UNBOUND in rep12.reasons())
print(f"        -> {rep12.summary()}")

print()
print("== guard 13: R8-1 input-bytes truthfulness — a DOCTORED fetch fails closed ==")
# the numerator recompute runs on the EXACT committed pinned bytes: each entry commits the
# per-target sha256 of the bytes at its vuln/patched SHA, folded into identity + the signed
# attestation. An attacker controlling the fetch source/cache who returns DOCTORED bytes (that
# do not reproduce the committed blob) is caught -> INPUT_BYTES_UNVERIFIED. (Article III: the
# doctored source is only ever PARSED as data; it is never executed.)
def _doctored_fetch(repo, ref, path):
    return _FILES[(ref, path)] + "\n# attacker-injected tail that changes the bytes\n"
verifier.FETCH_FN = _doctored_fetch
rep13 = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=precision_view, prior_evaluations=evaluations, attestation=attestation, strict=True,
)
expect("doctored fetch bytes trip INPUT_BYTES_UNVERIFIED", ViolationReason.INPUT_BYTES_UNVERIFIED in rep13.reasons())
print(f"        -> {rep13.summary()}")
verifier.FETCH_FN = _fake_fetch  # restore the honest committed fetcher

print()
print("== guard 14: R8-2 committed precision sample — a sample not reproducing the committed sample_root fails closed ==")
# the precision sample is committed inside the frozen bundle as a sample_root (drawn before
# adjudication, decoupled from the grindable freeze_hash). A DIFFERENT valid draw (a ground/re-rolled
# sample) does not reproduce the committed sample_root -> PRECISION_SAMPLE_UNBOUND.
_other_seed = precision_sample_seed(v1.content_hash, pool_root_of(pool), "different-salt")
_other_sampled = sample_confusion_pairs(pool, COMMITTED_K, _other_seed)
assert sample_root_of(_other_sampled) != COMMITTED_SAMPLE_ROOT, "the alternate draw must differ"
rerolled_precision = AdjudicatedPrecision(
    seed=_other_seed,
    sampled_pairs=_other_sampled,
    pool=pool,
    k=COMMITTED_K,
    adjudications=[
        Adjudication(
            pair_id=p,
            verdicts=[
                AdjudicatorVerdict(adjudicator="A", is_builder=False, is_curator=False, decision="true-positive"),
                AdjudicatorVerdict(adjudicator="B", is_builder=False, is_curator=True, decision="true-positive"),
            ],
        )
        for p in _other_sampled
    ],
)
rep14 = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=rerolled_precision, prior_evaluations=evaluations, attestation=attestation, strict=True,
)
expect("a re-rolled precision sample trips PRECISION_SAMPLE_UNBOUND", ViolationReason.PRECISION_SAMPLE_UNBOUND in rep14.reasons())
print(f"        -> {rep14.summary()}")

print()
print("== guard 15: R9-1 canonical precision sample — an operator-CHERRY-PICKED sample fails closed ==")
# the committed precision sample must be the CANONICAL draw from committed, non-grindable state
# (cohort identity + committed pool_root + committed k), with NO operator degree of freedom. A
# cherry-picked sample (a favorable operator-chosen draw whose sample_root is committed inside the
# bundle AND reproduced by the presented precision) passes R8-2's reproduce-the-committed-root check
# but is NOT the canonical draw -> R9-1 rejects it (PRECISION_SAMPLE_UNBOUND). We rebuild the freeze
# (its hash changes with the sample), the canonical run_id, precision, and a signed attestation.
from contract import canonical_sample_root  # R9-1 canonical recompute
_cherry_seed = precision_sample_seed(v1.content_hash, pool_root_of(pool), "cherry-picked-favorable-salt")
_cherry_sampled = sample_confusion_pairs(pool, COMMITTED_K, _cherry_seed)
_cherry_sample_root = sample_root_of(_cherry_sampled)
assert _cherry_sample_root != COMMITTED_SAMPLE_ROOT, "the cherry-picked draw must differ from the canonical one"
assert _cherry_sample_root != canonical_sample_root(v1.content_hash, pool, COMMITTED_K), "cherry != canonical"
cherry_bundle = bundle.model_copy(update={"committed_sample_root": _cherry_sample_root})
cherry_freeze = FreezeManifest(bundle=cherry_bundle, timestamp="2026-07-16T10:00:00Z")
cherry_run_id = _canonical_run_id(v1.content_hash, cherry_freeze.freeze_hash, "codex")
cherry_run = EvaluationRun(
    run_id=cherry_run_id, subject="codex", cohort_content_hash=v1.content_hash, freeze_hash=cherry_freeze.freeze_hash
)
cherry_run.attempt_evaluation(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E", results_hash="R1")
cherry_precision = AdjudicatedPrecision(
    seed=_cherry_seed, sampled_pairs=_cherry_sampled, pool=pool, k=COMMITTED_K,
    adjudications=[
        Adjudication(
            pair_id=p,
            verdicts=[
                AdjudicatorVerdict(adjudicator="A", is_builder=False, is_curator=False, decision="true-positive"),
                AdjudicatorVerdict(adjudicator="B", is_builder=False, is_curator=True, decision="true-positive"),
            ],
        )
        for p in _cherry_sampled
    ],
)
cherry_att = build_attestation(
    history=history, freeze=cherry_freeze, run=cherry_run, report=report_view,
    evaluator_id=EVALUATOR_ID, attested_at="2026-07-16T12:00:00Z", key=SIGNING_KEY,
    prior_attestation_root=load_committed_genesis_root(),
    exclusions=None, ledger=ledger, evaluation_ledger=evaluations, achievability=None,
)
rep15 = validate(
    history=history, ledger=ledger, run=cherry_run, freeze=cherry_freeze, report=report_view,
    precision=cherry_precision, prior_evaluations=evaluations, attestation=cherry_att, strict=True,
)
expect("cherry-picked precision sample trips PRECISION_SAMPLE_UNBOUND", ViolationReason.PRECISION_SAMPLE_UNBOUND in rep15.reasons())
print(f"        -> {rep15.summary()}")

print()
print("== guard 16: R9-2 exposure fallback — a non-empty curated_entry_ids does not skip the content-hash bar ==")
# a version bump (same entries, new content hash) must not launder a curator into a subject: even
# when the curated_entry_ids miss the presented head, the content-hash fallback still bars the
# subject (the record's cohort resolves in history and shares an entry identity with the scored head).
v2_bump = Cohort(version="v2", entries=[e1, e2], reason="version bump, same entries", parent_version="v1").sealed()
hist_bump = CohortHistory(versions=[v1, v2_bump])
ledger_fallback = ExposureLedger()
ledger_fallback.record(
    cohort_content_hash=v1.content_hash, actor="codex", activity="curated",
    curated_entry_ids=["an-unrelated-identity"],  # disjoint from the scored blind set
)
run_fallback_id = _canonical_run_id(v2_bump.content_hash, "fz", "codex")
run_fallback = EvaluationRun(
    run_id=run_fallback_id, subject="codex", cohort_content_hash=v2_bump.content_hash, freeze_hash="fz"
)
rep16 = validate(history=hist_bump, run=run_fallback, ledger=ledger_fallback)
expect("version-bumped curated record trips CURATOR_IS_SUBJECT", ViolationReason.CURATOR_IS_SUBJECT in rep16.reasons())
print(f"        -> {rep16.summary()}")

print()
print("== guard 17: R10-1 detector CODE-HASH binding — swapping the loaded module fails closed ==")
# the certify path recomputes the loaded detector module's CONTENT HASH (from DETECTOR_MODULE_HASHES,
# keyed by the frozen detector_id) and binds it to the frozen bundle's module_hashes — trust the CODE
# HASH, not the mutable name. Swapping the detector CODE (a DIFFERENT loaded hash) under a preserved
# name/freeze no longer matches -> DETECTOR_BUNDLE_UNVERIFIED. (SAFETY: the module source is read as
# TEXT and hashed; nothing fetched or target is executed.)
verifier.DETECTOR_MODULE_HASHES["DT-SSRF-TAINT"] = lambda: {"ssrf_detector.py": "5wapped-code-hash"}
rep17 = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=precision_view, prior_evaluations=evaluations, attestation=attestation, strict=True,
)
expect("swapped detector module hash trips DETECTOR_BUNDLE_UNVERIFIED", ViolationReason.DETECTOR_BUNDLE_UNVERIFIED in rep17.reasons())
print(f"        -> {rep17.summary()}")
verifier.DETECTOR_MODULE_HASHES["DT-SSRF-TAINT"] = lambda: {"ssrf_detector.py": "deadbeef"}  # restore

print()
print("== guard 18: R10-2 committed-monotonic exposure ledger — a truncated curator ledger fails closed ==")
# the exposure ledger is COMMITTED-monotonic state (parity with history/evaluation). Advance the
# committed exposure baseline to the honest ledger root, then present a TRUNCATED ledger (the
# incriminating curator record dropped) re-signed over its own root: it no longer reproduces the
# committed baseline -> EXPOSURE_LEDGER_TRUNCATED.
_orig_loader2 = contract.load_committed_genesis_state
_committed_with_exposure = _orig_loader2().model_copy(update={"latest_exposure_root": ledger.root})
contract.load_committed_genesis_state = lambda *a, **k: _committed_with_exposure
try:
    truncated_ledger = ExposureLedger()  # the incriminating curator record dropped
    truncated_att = build_attestation(
        history=history, freeze=freeze, run=run, report=report_view,
        evaluator_id=EVALUATOR_ID, attested_at="2026-07-16T12:00:00Z", key=SIGNING_KEY,
        prior_attestation_root=load_committed_genesis_root(),
        exclusions=None, ledger=truncated_ledger, evaluation_ledger=evaluations, achievability=None,
    )
    rep18 = validate(
        history=history, ledger=truncated_ledger, run=run, freeze=freeze, report=report_view,
        precision=precision_view, prior_evaluations=evaluations, attestation=truncated_att, strict=True,
    )
finally:
    contract.load_committed_genesis_state = _orig_loader2  # restore the real committed loader
expect("truncated exposure ledger trips EXPOSURE_LEDGER_TRUNCATED", ViolationReason.EXPOSURE_LEDGER_TRUNCATED in rep18.reasons())
print(f"        -> {rep18.summary()}")

print()
print("== guard 19: R10-5 precision panel re-enforced on certify — a from-storage panel fails closed ==")
# a from-storage AdjudicatedPrecision (model_construct bypasses the constructor validator) with a
# BUILDER adjudicator — precision 1.0 with no honest panel — is RE-ENFORCED on the certify path
# (P-A: every constructor invariant is re-checked because from-storage objects bypass constructors).
from_storage_precision = AdjudicatedPrecision.model_construct(
    seed=SAMPLE_SEED, sampled_pairs=sampled, pool=pool, k=COMMITTED_K,
    adjudications=[
        Adjudication(
            pair_id=p,
            verdicts=[
                AdjudicatorVerdict(adjudicator="A", is_builder=True, is_curator=False, decision="true-positive"),
                AdjudicatorVerdict(adjudicator="B", is_builder=False, is_curator=True, decision="true-positive"),
            ],
        )
        for p in sampled
    ],
)
rep19 = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=from_storage_precision, prior_evaluations=evaluations, attestation=attestation, strict=True,
)
expect("from-storage precision panel trips PRECISION_PANEL_INVALID", ViolationReason.PRECISION_PANEL_INVALID in rep19.reasons())
print(f"        -> {rep19.summary()}")

print()
print("== guard 20: R11-1 a non-guided blind entry role-downgraded under a NON-ROLE_DOWNGRADE reason fails closed ==")
# FR-4 legitimizes a blind->regression role-downgrade ONLY for an entry that guided a fix. Binding
# that precondition to the ROLE_DOWNGRADE reason LABEL let the identical move relabel as
# ALIAS_DUPE/TARGET_PATHS_NARROWING/etc. and launder a hard blind MISS out of the authoritative
# denominator. R11-1 binds it to the STRUCTURAL role-downgrade (in left_blind AND kept in curr),
# so the mislabel no longer passes.
e_keep = entry("819a80836e991ca3f427b0e85faca159083d3d40", "client.get(url_spec.geturl()", Role.BLIND)
e_drop = entry("8ab05d4c36b4720dc3f1f654564745f47c5034cd", "requests.get(url, stream=True)", Role.BLIND)
tv1 = Cohort(version="v1", entries=[e_keep, e_drop], reason="two blind entries").sealed()
e_drop_reg = e_drop.model_copy(update={"role": Role.REGRESSION}).sealed()  # role is NOT part of identity
tv2 = Cohort(version="v2", entries=[e_keep, e_drop_reg], reason="relabel-launder e_drop", parent_version="v1").sealed()
relabel = ExclusionLog(events=[ExclusionEvent(
    reason=ExclusionReason.ALIAS_DUPE, entry_identity=e_drop.identity_hash, from_version="v1", to_version="v2")])
rep20 = validate(history=CohortHistory(versions=[tv1, tv2]), exclusions=relabel)
expect("relabeled non-guided blind role-downgrade trips DENOMINATOR_SHRINK", ViolationReason.DENOMINATOR_SHRINK in rep20.reasons())
print(f"        -> {rep20.summary()}")

print()
print("== guard 21: R11-2 a from-storage precision with DUPLICATE adjudications fails closed ==")
# Duplicating favorable (true-positive) adjudications inflates tp/len(adjudications) toward 1.0 while
# the coverage SET of pair_ids is unchanged. R11-2 pins the precision denominator to |sample| (exactly
# one adjudication per sampled pair), re-enforced on the certify path (P-A).
honest_adjs = [
    Adjudication(pair_id=p, verdicts=[
        AdjudicatorVerdict(adjudicator="A", is_builder=False, is_curator=False, decision="true-positive"),
        AdjudicatorVerdict(adjudicator="B", is_builder=False, is_curator=True, decision="true-positive"),
    ])
    for p in sampled
]
dup_precision = AdjudicatedPrecision.model_construct(
    seed=SAMPLE_SEED, sampled_pairs=sampled, pool=pool, k=COMMITTED_K,
    adjudications=honest_adjs + [honest_adjs[0]],  # one duplicate copy of a covered TP pair
)
rep21 = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=dup_precision, prior_evaluations=evaluations, attestation=attestation, strict=True,
)
expect("duplicate-adjudication precision trips PRECISION_PANEL_INVALID", ViolationReason.PRECISION_PANEL_INVALID in rep21.reasons())
print(f"        -> {rep21.summary()}")

print()
print("== guard 22: R11-1b a SPLIT-TRANSITION (remove-then-readd-as-regression) fails closed ==")
# Split the departure across versions to dodge the adjacent-pair check: remove a non-guided blind
# MISS under a legit ALIAS_DUPE at v1->v2, then RE-ADD the same pinned identity as a regression at
# v2->v3. The entry survives in the HEAD as a formerly-blind, non-guided regression while the blind
# denominator silently shrinks. The terminal-head resurrection guard catches it.
s_keep = entry("819a80836e991ca3f427b0e85faca159083d3d40", "client.get(url_spec.geturl()", Role.BLIND)
s_drop = entry("8ab05d4c36b4720dc3f1f654564745f47c5034cd", "requests.get(url, stream=True)", Role.BLIND)
sv1 = Cohort(version="v1", entries=[s_keep, s_drop], reason="two blind").sealed()
sv2 = Cohort(version="v2", entries=[s_keep], reason="remove s_drop (claimed alias-dupe)", parent_version="v1").sealed()
s_drop_reg = s_drop.model_copy(update={"role": Role.REGRESSION}).sealed()
sv3 = Cohort(version="v3", entries=[s_keep, s_drop_reg], reason="re-add s_drop as regression", parent_version="v2").sealed()
split_excl = ExclusionLog(events=[ExclusionEvent(
    reason=ExclusionReason.ALIAS_DUPE, entry_identity=s_drop.identity_hash, from_version="v1", to_version="v2")])
rep22 = validate(history=CohortHistory(versions=[sv1, sv2, sv3]), exclusions=split_excl)
expect("split-transition resurrection trips DENOMINATOR_SHRINK", ViolationReason.DENOMINATOR_SHRINK in rep22.reasons())
print(f"        -> {rep22.summary()}")

print()
print("== guard 23: CR-1 a precision panel of one identity double-voting fails closed ==")
# Two verdicts from the SAME adjudicator are one person double-voting, not an independent panel.
one_voice_adjs = [
    Adjudication(pair_id=p, verdicts=[
        AdjudicatorVerdict(adjudicator="A", is_builder=False, is_curator=False, decision="true-positive"),
        AdjudicatorVerdict(adjudicator="A", is_builder=False, is_curator=True, decision="true-positive"),
    ])
    for p in sampled
]
one_voice = AdjudicatedPrecision.model_construct(
    seed=SAMPLE_SEED, sampled_pairs=sampled, pool=pool, k=COMMITTED_K, adjudications=one_voice_adjs,
)
rep23 = validate(
    history=history, ledger=ledger, run=run, freeze=freeze, report=report_view,
    precision=one_voice, prior_evaluations=evaluations, attestation=attestation, strict=True,
)
expect("single-identity precision panel trips PRECISION_PANEL_INVALID", ViolationReason.PRECISION_PANEL_INVALID in rep23.reasons())
print(f"        -> {rep23.summary()}")

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
print("SMOKE 008 OK: contract certifies the ed25519-signed run and every guard (anchoring + round-6..11 floor) trips with a typed reason.")
PYEOF
