"""Tests for the numerator VERIFIER (feature 008, round 4).

PART 2 closes the numerator's input-truthfulness: the reported rediscovery set must
MATCH a recompute of the frozen detector re-run on the real pinned code. Two layers:

  * DETERMINISTIC unit tests inject a fake ``fetch_fn`` (canned vuln/patched source) +
    fake ``scan_fn`` — asserting ``recompute_rediscovered`` returns the right set, and
    that ``validate(strict=...)`` rejects a Report that CLAIMS an unconfirmed
    rediscovery or OMITS a real one with ``NUMERATOR_UNVERIFIED``.
  * ONE NET-GATED integration test fetches a real pinned CVE pair from the corpus and
    runs a real detector's ``scan_source``, asserting the recompute matches the
    manifest's recorded result. Opt-in (``DEEPTHOUGHT_BENCHMARK_NET=1``).

SAFETY: the detector reads fetched files as DATA (``scan_source`` parses text); no
target code is executed here — Article III stays intact.
"""

import json
import os
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "harness"))

import contract  # noqa: E402
from contract import (  # noqa: E402
    AdjudicatedPrecision,
    Adjudication,
    AdjudicatorVerdict,
    Cohort,
    CohortEntry,
    CohortHistory,
    DetectorBundle,
    EvaluationLedger,
    EvaluationRun,
    ExposureLedger,
    FreezeManifest,
    RecallReport,
    Report,
    ViolationReason,
    _canonical_run_id,
    build_attestation,
    load_committed_genesis_root,
    pool_root_of,
    precision_sample_seed,
    sample_confusion_pairs,
    validate,
)
from verifier import recompute_rediscovered  # noqa: E402

KEY = b"deepthought-verifier-test-key-0123456789"


def _reasons(report):
    return {v.reason for v in report.violations}


def _entry(vuln, patched, *, probe="sink(x)", repo="https://github.com/o/r", paths=("f.py",)):
    return CohortEntry(
        repo=repo,
        vuln_ref=vuln,
        patched_ref=patched,
        target_paths=list(paths),
        sink_probe=probe,
        status="pinned",
        role="blind",
    ).sealed()


# --------------------------------------------------------------------------- #
# a fake corpus: a dict-backed fetcher + a marker-driven scanner
# --------------------------------------------------------------------------- #
# ``FLAG`` on a line means "the detector emits a finding at this line". The
# line-precise rule then also requires the flagged line's OWN text to contain the
# sink probe. This is the exact contract corpus_measure._sink_is_flagged applies.
FILES = {
    # entry_A: sink FLAGged in vuln, guarded (not flagged) in patched -> REDISCOVERED
    ("vulnA", "f.py"): "def f(url):\n    sink(x)  # FLAG\n",
    ("patchedA", "f.py"): "def f(url):\n    guard(url)\n    sink(x)\n",  # no FLAG -> fixed
    # entry_B: sink FLAGged in BOTH trees (detector can't discriminate) -> NOT rediscovered
    ("vulnB", "f.py"): "def g(url):\n    sink(x)  # FLAG\n",
    ("patchedB", "f.py"): "def g(url):\n    sink(x)  # FLAG\n",
    # entry_C: sink present but never FLAGged (detector misses it) -> NOT rediscovered
    ("vulnC", "f.py"): "def h(url):\n    sink(x)\n",
    ("patchedC", "f.py"): "def h(url):\n    sink(x)\n",
}


def fake_fetch(repo, ref, path):
    return FILES[(ref, path)]


def fake_scan(source, uri):
    """A marker-driven fake detector: emit a SARIF-ish finding for each line whose text
    contains ``FLAG``. It PARSES the string; it never executes it."""
    out = []
    for i, line in enumerate(source.splitlines(), 1):
        if "FLAG" in line:
            out.append({"locations": [{"physicalLocation": {"region": {"startLine": i}}}]})
    return out


ENTRY_A = _entry("vulnA", "patchedA")
ENTRY_B = _entry("vulnB", "patchedB")
ENTRY_C = _entry("vulnC", "patchedC")


# --------------------------------------------------------------------------- #
# recompute_rediscovered — the pure function
# --------------------------------------------------------------------------- #
def test_recompute_identifies_only_the_confirmed_rediscovery():
    got = recompute_rediscovered([ENTRY_A, ENTRY_B, ENTRY_C], fetch_fn=fake_fetch, scan_fn=fake_scan)
    # only A is flagged-in-vuln AND not-flagged-in-patched
    assert got == {ENTRY_A.computed_identity_hash}


def test_recompute_is_deterministic_and_order_independent():
    a = recompute_rediscovered([ENTRY_A, ENTRY_B, ENTRY_C], fetch_fn=fake_fetch, scan_fn=fake_scan)
    b = recompute_rediscovered([ENTRY_C, ENTRY_B, ENTRY_A], fetch_fn=fake_fetch, scan_fn=fake_scan)
    assert a == b == {ENTRY_A.computed_identity_hash}


# --------------------------------------------------------------------------- #
# wiring into the certify path — a claimed set that the recompute does not
# confirm (over-claim), or that omits a real rediscovery, is NUMERATOR_UNVERIFIED
# --------------------------------------------------------------------------- #
def _certify_with_claim(cohort, claimed_entries, *, recomputed):
    """A fully honest, anchored strict-certify over ``cohort`` whose Report claims
    ``claimed_entries`` as rediscovered, with an injected ``recomputed`` set. Only the
    numerator claim varies between cases."""
    hist = CohortHistory(versions=[cohort])
    blind = sorted(e.computed_identity_hash for e in cohort.entries)
    pool = [f"p{i:02d}" for i in range(12)]
    committed_k = 3
    bundle = DetectorBundle(
        detector_id="d", lockfile_hash="L", pool_root=pool_root_of(pool), committed_k=committed_k
    )
    freeze = FreezeManifest(bundle=bundle, timestamp="2026-07-16T10:00:00Z")
    rid = _canonical_run_id(cohort.content_hash, freeze.freeze_hash, "codex")
    run = EvaluationRun(
        run_id=rid, subject="codex", cohort_content_hash=cohort.content_hash, freeze_hash=freeze.freeze_hash
    )
    run.attempt_evaluation(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E")
    report = Report(
        blind_recall=RecallReport(rediscovered=len(claimed_entries), total=len(blind)),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        coverage=1.0,
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
        cohort_content_hash=cohort.content_hash,
        rediscovered_blind_ids=[e.identity_hash for e in claimed_entries],
    )
    seed = precision_sample_seed(cohort.content_hash, freeze.freeze_hash, rid)
    sampled = sample_confusion_pairs(pool, committed_k, seed)
    precision = AdjudicatedPrecision(
        seed=seed,
        sampled_pairs=sampled,
        pool=pool,
        k=committed_k,
        cohort_hash=cohort.content_hash,
        freeze_hash=freeze.freeze_hash,
        run_id=rid,
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
    evln = EvaluationLedger()
    att = build_attestation(
        history=hist,
        freeze=freeze,
        run=run,
        report=report,
        evaluator_id="curator-not-subject",
        attested_at="2026-07-16T12:00:00Z",
        key=KEY,
        prior_attestation_root=load_committed_genesis_root(),
        evaluation_ledger=evln,
    )
    return validate(
        history=hist,
        freeze=freeze,
        run=run,
        report=report,
        precision=precision,
        prior_evaluations=evln,
        attestation=att,
        verify_key=KEY,
        recomputed_rediscovered=recomputed,
        strict=True,
    )


def test_certify_numerator_matches_recompute_passes():
    cohort = Cohort(version="v1", entries=[ENTRY_A, ENTRY_B, ENTRY_C]).sealed()
    recomputed = recompute_rediscovered([ENTRY_A, ENTRY_B, ENTRY_C], fetch_fn=fake_fetch, scan_fn=fake_scan)
    # the honest report claims exactly what the frozen detector reproduces on real code
    rep = _certify_with_claim(cohort, [ENTRY_A], recomputed=recomputed)
    assert rep.ok, _reasons(rep)


def test_certify_over_claimed_rediscovery_is_numerator_unverified():
    cohort = Cohort(version="v1", entries=[ENTRY_A, ENTRY_B, ENTRY_C]).sealed()
    recomputed = recompute_rediscovered([ENTRY_A, ENTRY_B, ENTRY_C], fetch_fn=fake_fetch, scan_fn=fake_scan)
    # the report CLAIMS B as rediscovered, but the recompute only confirms A
    rep = _certify_with_claim(cohort, [ENTRY_A, ENTRY_B], recomputed=recomputed)
    assert not rep.ok and ViolationReason.NUMERATOR_UNVERIFIED in _reasons(rep)


def test_certify_omitting_a_real_rediscovery_is_numerator_unverified():
    cohort = Cohort(version="v1", entries=[ENTRY_A, ENTRY_B, ENTRY_C]).sealed()
    recomputed = recompute_rediscovered([ENTRY_A, ENTRY_B, ENTRY_C], fetch_fn=fake_fetch, scan_fn=fake_scan)
    # the report OMITS A (claims nothing), but the recompute confirms A -> mismatch
    rep = _certify_with_claim(cohort, [], recomputed=recomputed)
    assert not rep.ok and ViolationReason.NUMERATOR_UNVERIFIED in _reasons(rep)


def test_certify_without_a_recompute_is_fail_closed_unverified():
    cohort = Cohort(version="v1", entries=[ENTRY_A, ENTRY_B, ENTRY_C]).sealed()
    # no recompute supplied at all: the numerator is unverifiable -> fail closed
    rep = _certify_with_claim(cohort, [ENTRY_A], recomputed=None)
    assert not rep.ok and ViolationReason.NUMERATOR_UNVERIFIED in _reasons(rep)


# --------------------------------------------------------------------------- #
# NET-GATED: recompute one real pinned CVE pair and match the corpus manifest
# --------------------------------------------------------------------------- #
MANIFEST = Path(__file__).parent.parent / "corpus" / "ssrf" / "manifest.json"


def _net() -> bool:
    if os.environ.get("DEEPTHOUGHT_BENCHMARK_NET") != "1":
        return False
    try:
        socket.create_connection(("raw.githubusercontent.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


requires_net = pytest.mark.skipif(
    not _net(), reason="held-out re-run needs DEEPTHOUGHT_BENCHMARK_NET=1 and network"
)


@requires_net
def test_recompute_matches_manifest_on_one_real_pinned_pair():
    """Fetch ONE real pinned CVE pair (gradio CVE-2024-4325, recorded as rediscovered)
    at its vuln/patched SHAs and run the REAL DT-SSRF-TAINT ``scan_source``; the
    recompute must reproduce the manifest's recorded rediscovery. The detector only
    parses the fetched source into an AST — it never executes it."""
    import corpus_measure
    from ssrf_detector import scan_source

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    heldout = {h["cve"]: h for h in manifest["heldout"]}
    recorded_rediscovered = set(manifest["result"]["heldout_rediscovered"])

    gradio = heldout["CVE-2024-4325"]
    assert "CVE-2024-4325" in recorded_rediscovered  # manifest records it as rediscovered
    entry = CohortEntry(
        repo=gradio["repo"],
        vuln_ref=gradio["vuln_ref"],
        patched_ref=gradio["patched_ref"],
        target_paths=gradio["target_paths"],
        sink_probe=gradio["sink_probe"],
        status="pinned",
        role="blind",
    ).sealed()

    recomputed = recompute_rediscovered([entry], fetch_fn=corpus_measure.fetch, scan_fn=scan_source)
    assert recomputed == {entry.computed_identity_hash}
