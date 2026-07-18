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

import hashlib
import json
import os
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "harness"))

import contract  # noqa: E402
import verifier  # noqa: E402  (module handle for monkeypatching the committed detector registry + fetcher)
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
    blob_sha256,
    build_attestation,
    ed25519_public_key,
    pool_root_of,
    precision_sample_seed,
    sample_confusion_pairs,
    sample_root_of,
    validate,
)
from verifier import InputBytesUnverified, recompute_rediscovered  # noqa: E402

# A FIXED test ed25519 keypair (F4): the PRIVATE seed signs, the derived PUBLIC key is what
# the hermetic committed-state fixture commits and ``validate`` verifies against.
KEY = hashlib.sha256(b"deepthought-verifier-test-ed25519-seed/v1").digest()  # 32-byte private seed
_TEST_PUB = ed25519_public_key(KEY)  # the committed ed25519 PUBLIC key
EVALUATOR_ID = "curator-not-subject"
CHAIN_BASE = "abad1dea" * 8  # a fixed committed latest-attestation root for the hermetic fixtures
# R10-1: the fake detector's committed module-hash (bundle commits it; certify recomputes + binds).
_MODULE_HASHES = {"d_detector.py": "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"}


def _reasons(report):
    return {v.reason for v in report.violations}


def _entry(vuln, patched, *, probe="sink(x)", repo="https://github.com/o/r", paths=("f.py",), files=None):
    paths = list(paths)
    # R8-1: commit the per-target blob sha256 from the fake corpus so the recompute's blob
    # verification (default on) has a committed content address to check the fetched bytes against.
    vuln_blobs = {p: blob_sha256(files[(vuln, p)]) for p in paths} if files is not None else {}
    patched_blobs = {p: blob_sha256(files[(patched, p)]) for p in paths} if files is not None else {}
    return CohortEntry(
        repo=repo,
        vuln_ref=vuln,
        patched_ref=patched,
        target_paths=paths,
        sink_probe=probe,
        status="pinned",
        vuln_blob_sha256=vuln_blobs,
        patched_blob_sha256=patched_blobs,
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


ENTRY_A = _entry("vulnA", "patchedA", files=FILES)
ENTRY_B = _entry("vulnB", "patchedB", files=FILES)
ENTRY_C = _entry("vulnC", "patchedC", files=FILES)


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
# R8-1 — the recompute runs on the EXACT committed pinned bytes. Each entry commits the
# per-target blob sha256 (folded into identity); the recompute requires each fetched source to
# reproduce it, so a doctored fetch source/cache cannot feed the detector altered bytes.
# --------------------------------------------------------------------------- #
def test_r8_1_recompute_rejects_doctored_input_bytes():
    # matching bytes → the recompute proceeds and identifies the confirmed rediscovery
    assert recompute_rediscovered([ENTRY_A], fetch_fn=fake_fetch, scan_fn=fake_scan) == {
        ENTRY_A.computed_identity_hash
    }

    # a doctored fetch that returns bytes NOT reproducing the committed blob → InputBytesUnverified
    def doctored_fetch(repo, ref, path):
        return fake_fetch(repo, ref, path) + "\n# attacker-injected tail\n"

    with pytest.raises(InputBytesUnverified):
        recompute_rediscovered([ENTRY_A], fetch_fn=doctored_fetch, scan_fn=fake_scan)

    # an entry that committed NO blob for a scored target also fails closed — the binding is not
    # skippable by leaving the committed hash empty
    naked = _entry("vulnA", "patchedA")  # files=None → no committed blobs
    with pytest.raises(InputBytesUnverified):
        recompute_rediscovered([naked], fetch_fn=fake_fetch, scan_fn=fake_scan)

    # verify_blobs=False is the ONLY escape (legacy pure-function use; the certify path never uses it)
    assert recompute_rediscovered(
        [naked], fetch_fn=fake_fetch, scan_fn=fake_scan, verify_blobs=False
    ) == {naked.computed_identity_hash}


# --------------------------------------------------------------------------- #
# wiring into the certify path — a claimed set that the recompute does not
# confirm (over-claim), or that omits a real rediscovery, is NUMERATOR_UNVERIFIED
# --------------------------------------------------------------------------- #
def _install_committed(monkeypatch, hist, *, detector_id="d", scan=fake_scan, register=True):
    """Install the COMMITTED anchor state + the committed detector/fetcher so a strict
    certify RUNS its numerator recompute from committed state (R5-1): ``validate`` resolves
    ``scan_fn`` from ``verifier.DETECTOR_REGISTRY`` keyed by the frozen ``detector_id`` and
    ``fetch_fn`` from ``verifier.FETCH_FN`` — neither is a caller argument. When
    ``register`` is False the detector is intentionally left UNREGISTERED so the certify
    fails closed on a numerator it cannot recompute."""
    phr = hist.history_root
    state = contract.CommittedGenesisState(
        genesis_history_root=phr,
        latest_history_root=phr,
        latest_attestation_root=CHAIN_BASE,
        evaluator_id=EVALUATOR_ID,
        verify_key=_TEST_PUB,
        adjudicator_roster={  # R10-6: the committed roster matching the A/B panel below
            "A": {"is_builder": False, "is_curator": False},
            "B": {"is_builder": False, "is_curator": True},
        },
    )
    monkeypatch.setattr(contract, "load_committed_genesis_state", lambda *a, **k: state)
    monkeypatch.setattr(verifier, "FETCH_FN", fake_fetch)
    if register:
        monkeypatch.setitem(verifier.DETECTOR_REGISTRY, detector_id, lambda: scan)
        # R10-1: the committed loaded-module hash the certify path binds against the frozen bundle.
        monkeypatch.setitem(verifier.DETECTOR_MODULE_HASHES, detector_id, lambda: dict(_MODULE_HASHES))


def _certify_with_claim(monkeypatch, cohort, claimed_entries, *, detector_id="d", register=True):
    """A fully honest, anchored strict-certify over ``cohort`` whose Report claims
    ``claimed_entries`` as rediscovered. The numerator is RECOMPUTED by ``validate`` running
    the COMMITTED detector (the marker-driven fake, registered by ``_install_committed``) on
    the fake corpus — not a caller-supplied set. Only the numerator claim (and, for the
    fail-closed case, whether the detector is registered) varies between cases."""
    hist = CohortHistory(versions=[cohort])
    blind = sorted(e.computed_identity_hash for e in cohort.entries)
    pool = [f"p{i:02d}" for i in range(12)]
    committed_k = 3
    # R8-2: commit the precision sample_root in the frozen bundle (decoupled from freeze_hash).
    sample_seed = precision_sample_seed(cohort.content_hash, pool_root_of(pool), str(committed_k))
    sampled = sample_confusion_pairs(pool, committed_k, sample_seed)
    bundle = DetectorBundle(
        detector_id=detector_id, lockfile_hash="L", pool_root=pool_root_of(pool), committed_k=committed_k,
        committed_sample_root=sample_root_of(sampled), module_hashes=dict(_MODULE_HASHES),  # R10-1
    )
    freeze = FreezeManifest(bundle=bundle, timestamp="2026-07-16T10:00:00Z")
    rid = _canonical_run_id(cohort.content_hash, freeze.freeze_hash, "codex")
    run = EvaluationRun(
        run_id=rid, subject="codex", cohort_content_hash=cohort.content_hash, freeze_hash=freeze.freeze_hash
    )
    # R8-5: a producing attempt carries a non-empty results_hash.
    run.attempt_evaluation(
        phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E", results_hash="R1"
    )
    report = Report(
        blind_recall=RecallReport(rediscovered=len(claimed_entries), total=len(blind)),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        coverage=None,  # R7-2: forbidden on a certified report
        patched_alert_density=0.0,  # recomputed below (when the detector is resolvable)
        adjudicated_precision=1.0,
        cohort_content_hash=cohort.content_hash,
        rediscovered_blind_ids=[e.identity_hash for e in claimed_entries],
    )
    precision = AdjudicatedPrecision(
        seed=sample_seed,
        sampled_pairs=sampled,
        pool=pool,
        k=committed_k,
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
    ledger = ExposureLedger()
    evln = EvaluationLedger()
    _install_committed(monkeypatch, hist, detector_id=detector_id, register=register)
    # R7-2: bind the certified secondary numerics to what validate() recomputes. Only possible
    # when the detector is resolvable; the unregistered case fails closed on the recompute.
    if register:
        report = report.model_copy(
            update={
                "patched_alert_density": verifier.recompute_patched_alert_density(
                    cohort.entries, detector_id=detector_id
                ),
            }
        )
    att = build_attestation(
        history=hist,
        freeze=freeze,
        run=run,
        report=report,
        evaluator_id=EVALUATOR_ID,
        attested_at="2026-07-16T12:00:00Z",
        key=KEY,
        prior_attestation_root=CHAIN_BASE,
        ledger=ledger,
        evaluation_ledger=evln,
    )
    return validate(
        history=hist,
        freeze=freeze,
        run=run,
        report=report,
        precision=precision,
        ledger=ledger,
        prior_evaluations=evln,
        attestation=att,
        strict=True,
    )


def test_certify_numerator_matches_recompute_passes(monkeypatch):
    cohort = Cohort(version="v1", entries=[ENTRY_A, ENTRY_B, ENTRY_C]).sealed()
    # the honest report claims exactly what the committed detector reproduces on real code
    rep = _certify_with_claim(monkeypatch, cohort, [ENTRY_A])
    assert rep.ok, _reasons(rep)


def test_certify_over_claimed_rediscovery_is_numerator_unverified(monkeypatch):
    cohort = Cohort(version="v1", entries=[ENTRY_A, ENTRY_B, ENTRY_C]).sealed()
    # the report CLAIMS B as rediscovered, but the committed detector re-run only confirms A
    rep = _certify_with_claim(monkeypatch, cohort, [ENTRY_A, ENTRY_B])
    assert not rep.ok and ViolationReason.NUMERATOR_UNVERIFIED in _reasons(rep)


def test_certify_omitting_a_real_rediscovery_is_numerator_unverified(monkeypatch):
    cohort = Cohort(version="v1", entries=[ENTRY_A, ENTRY_B, ENTRY_C]).sealed()
    # the report OMITS A (claims nothing), but the committed detector re-run confirms A
    rep = _certify_with_claim(monkeypatch, cohort, [])
    assert not rep.ok and ViolationReason.NUMERATOR_UNVERIFIED in _reasons(rep)


def test_certify_with_an_unrecomputable_detector_is_fail_closed_unverified(monkeypatch):
    cohort = Cohort(version="v1", entries=[ENTRY_A, ENTRY_B, ENTRY_C]).sealed()
    # the frozen detector_id has no committed registry entry: the numerator cannot be
    # recomputed from committed state, so certification fails closed
    rep = _certify_with_claim(monkeypatch, cohort, [ENTRY_A], detector_id="ghost-unregistered", register=False)
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
    # R8-1: commit the per-target blob sha256 from the REAL fetched pinned bytes, then recompute
    # with blob verification ON — proving the real GitHub bytes hash to the committed value.
    vuln_blobs = {p: blob_sha256(corpus_measure.fetch(gradio["repo"], gradio["vuln_ref"], p)) for p in gradio["target_paths"]}
    patched_blobs = {p: blob_sha256(corpus_measure.fetch(gradio["repo"], gradio["patched_ref"], p)) for p in gradio["target_paths"]}
    entry = CohortEntry(
        repo=gradio["repo"],
        vuln_ref=gradio["vuln_ref"],
        patched_ref=gradio["patched_ref"],
        target_paths=gradio["target_paths"],
        sink_probe=gradio["sink_probe"],
        status="pinned",
        vuln_blob_sha256=vuln_blobs,
        patched_blob_sha256=patched_blobs,
        role="blind",
    ).sealed()

    recomputed = recompute_rediscovered([entry], fetch_fn=corpus_measure.fetch, scan_fn=scan_source)
    assert recomputed == {entry.computed_identity_hash}
