"""Acceptance tests for the typed EvaluationContract (feature 008).

One test per acceptance criterion (AC-1..AC-14) in
``specs/008-evaluation-contract/spec.md``, plus a few targeted sub-behaviour
tests. Everything is DETERMINISTIC: timestamps and sample seeds are passed in,
never read from the wall clock or an RNG the test does not control.
"""

import hashlib
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent / "harness"))

import contract  # noqa: E402  (module handle for monkeypatching the committed-state loaders)
import verifier  # noqa: E402  (module handle for monkeypatching the committed detector registry + fetcher)
from contract import (  # noqa: E402
    AchievabilityLog,
    AchievabilityPrediction,
    Adjudication,
    AdjudicatedPrecision,
    AdjudicatorVerdict,
    Cohort,
    CohortEntry,
    CohortHistory,
    ContractViolation,
    DetectorBundle,
    EvalAttempt,
    EvaluationLedger,
    EvaluationRun,
    ExclusionClass,
    ExclusionEvent,
    ExclusionLog,
    ExclusionReason,
    ExposureLedger,
    FreezeManifest,
    LocalCandidate,
    RealCVEAggregate,
    RecallReport,
    Report,
    Role,
    SyntheticSuite,
    SyntheticVariant,
    ViolationReason,
    _canonical_run_id,
    blob_sha256,
    build_attestation,
    candidates_from_adjudications,
    chain_root,
    check_report,
    ed25519_public_key,
    leaf_hash,
    merkle_root,
    pool_root_of,
    precision_sample_seed,
    sample_confusion_pairs,
    sample_root_of,
    sign,
    validate,
    verify,
)
from roundrecord import ClassRate  # noqa: E402

A40 = "a" * 40
B40 = "b" * 40
C40 = "c" * 40

# A FIXED test ed25519 keypair (F4). Deterministic (derived from a fixed seed, never
# os.urandom). The PRIVATE seed (``KEY``) is the test/build signing key — it lives ONLY in
# this test helper, never in genesis_root.json; the PUBLIC key (``_TEST_PUB``) is what the
# hermetic committed-state fixture commits and ``validate`` verifies attestations against. So
# the tests demonstrate the ed25519 mechanism: an attestation signed with the test PRIVATE key
# verifies against the committed PUBLIC key, and a signature made with any non-committed key is
# ``ATTESTATION_INVALID``.
KEY = hashlib.sha256(b"deepthought-test-evaluator-ed25519-seed/v1").digest()  # 32-byte private seed
_TEST_PUB = ed25519_public_key(KEY)  # the committed ed25519 PUBLIC key

# The committed evaluator id + the attestation-chain base the hermetic certify fixtures
# use. Round-5 loads the verify-key, evaluator id, genesis root, and prior history baseline
# from COMMITTED state, never from caller args, so the certify tests monkeypatch
# ``contract.load_committed_genesis_state`` with a hermetic fixture (via
# :func:`_install_committed`) consistent with each presented history instead of depending
# on the real committed file's values.
EVALUATOR_ID = "curator-not-subject"
ATT_CHAIN_BASE = "c0ffee00" * 8  # a fixed committed latest-attestation root for the fixtures

# R10-1: the fake detector's committed module-hash. The freeze commits this in ``module_hashes``
# and the certify path RECOMPUTES the loaded module's hash from the committed registry (hermetic
# tests inject a matching canned value). A tamper (swap the loaded hash) trips DETECTOR_BUNDLE_UNVERIFIED.
_FAKE_MODULE_HASHES = {"d_detector.py": "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"}

# R10-6: the committed adjudicator roster matching ``_good_panel`` (A is a non-curator, B is a
# curator; neither is a builder). The certify path validates each verdict's self-asserted
# is_builder/is_curator against THIS and requires independence from the scored subject.
_ADJ_ROSTER = {
    "A": {"is_builder": False, "is_curator": False},
    "B": {"is_builder": False, "is_curator": True},
}


def _pool(n):
    """A canonical (sorted, unique) confusion-pair pool (A6)."""
    return [f"p{i:02d}" for i in range(n)]


def _entry(
    *,
    repo="https://github.com/o/r",
    vuln=A40,
    patched=B40,
    paths=None,
    probe="requests.get(url)",
    status="pinned",
    drop_reason=None,
    role="blind",
    guided_fix=False,
    seal=True,
    files=None,
):
    paths = paths or ["a/x.py"]
    # R8-1: when a fake-corpus ``files`` map is supplied, commit the per-target blob sha256 of the
    # bytes at (vuln_ref/patched_ref, path). The certify recompute then requires the fetched bytes
    # to reproduce these, so an entry built from a corpus carries its committed content address.
    vuln_blobs = {p: blob_sha256(files[(vuln, p)]) for p in paths} if files is not None else {}
    patched_blobs = {p: blob_sha256(files[(patched, p)]) for p in paths} if files is not None else {}
    e = CohortEntry(
        repo=repo,
        vuln_ref=vuln,
        patched_ref=patched,
        target_paths=paths,
        sink_probe=probe,
        status=status,
        drop_reason=drop_reason,
        vuln_blob_sha256=vuln_blobs,
        patched_blob_sha256=patched_blobs,
        role=role,
        guided_fix=guided_fix,
    )
    return e.sealed() if seal else e


def _cohort(version, entries, *, reason="", parent=None, seal=True):
    c = Cohort(version=version, entries=list(entries), reason=reason, parent_version=parent)
    return c.sealed() if seal else c


def _reasons(report):
    return {v.reason for v in report.violations}


def _run(subject, cohort_hash, freeze_hash, **kw):
    """An EvaluationRun with the canonical run_id for its (cohort, freeze, subject)
    (R5) — the honest bound form now that a free-string run_id is rejected."""
    return EvaluationRun(
        run_id=_canonical_run_id(cohort_hash, freeze_hash, subject),
        subject=subject,
        cohort_content_hash=cohort_hash,
        freeze_hash=freeze_hash,
        **kw,
    )


def _good_panel(pair_id, decision, *, curator_second=True):
    return Adjudication(
        pair_id=pair_id,
        verdicts=[
            AdjudicatorVerdict(adjudicator="A", is_builder=False, is_curator=False, decision=decision),
            AdjudicatorVerdict(adjudicator="B", is_builder=False, is_curator=curator_second, decision=decision),
        ],
    )


def _committed_sample(pool, k, cohort_hash):
    """R8-2: the precision sample committed at freeze time. It is drawn from committed,
    NON-grindable inputs (cohort identity + canonical pool + k) rather than the grindable
    freeze_hash, and its ``sample_root`` is committed inside the frozen bundle. Returns
    ``(seed, sampled, sample_root)``; the certify builders put the sample_root in the bundle and
    present a precision whose ``sampled_pairs`` reproduce it."""
    seed = precision_sample_seed(cohort_hash, pool_root_of(pool), str(k))
    sampled = sample_confusion_pairs(pool, k, seed)
    return seed, sampled, sample_root_of(sampled)


def _reg_files_of(regression):
    """Merge the fake-corpus fragments of a list of ``(entry, files_fragment)`` regression rows."""
    reg_files = {}
    for _, frag in (regression or []):
        reg_files.update(frag)
    return reg_files


# --------------------------------------------------------------------------- #
# AC-1 — canonical entry identity
# --------------------------------------------------------------------------- #
def test_ac1_canonical_fields_changed_without_new_hash_fails():
    e = _entry()  # declared == computed
    # canonical field changed, but the declared identity hash is stale
    stale = e.model_copy(update={"sink_probe": "eval(x)"})
    assert stale.declared_identity_hash != stale.computed_identity_hash
    hist = CohortHistory(versions=[Cohort(version="v1", entries=[stale]).sealed()])
    report = validate(history=hist)
    assert not report.ok
    assert ViolationReason.BAD_ENTRY_HASH in _reasons(report)
    # a properly sealed entry passes the integrity check
    assert validate(history=CohortHistory(versions=[_cohort("v1", [e])])).ok
    # sorted target_paths are canonical: order does not change identity
    p1 = _entry(paths=["a/x.py", "b/y.py"]).computed_identity_hash
    p2 = _entry(paths=["b/y.py", "a/x.py"]).computed_identity_hash
    assert p1 == p2


# --------------------------------------------------------------------------- #
# AC-2 — cohort versioning, history immutable
# --------------------------------------------------------------------------- #
def test_ac2_in_place_edit_fails_new_version_passes_history_readable():
    e1 = _entry(probe="requests.get(url)")
    v1 = _cohort("v1", [e1])
    # in-place edit: entry re-sealed (entry-hash ok) but the cohort keeps v1's seal
    edited = e1.model_copy(update={"sink_probe": "open(p)"}).sealed()
    v1_tampered = v1.model_copy(update={"entries": [edited]})  # declared_content_hash still v1's
    bad = validate(history=CohortHistory(versions=[v1_tampered]))
    assert not bad.ok and ViolationReason.IN_PLACE_EDIT in _reasons(bad)

    # correction: a NEW version, with the removal of e1's identity logged
    v2 = _cohort("v2", [edited], reason="re-pin sink_probe", parent="v1")
    excl = ExclusionLog(
        events=[
            ExclusionEvent(
                reason=ExclusionReason.SINK_PROBE_EDIT,
                entry_identity=e1.identity_hash,
                from_version="v1",
                to_version="v2",
            )
        ]
    )
    hist = CohortHistory(versions=[v1, v2])
    ok = validate(history=hist, exclusions=excl)
    assert ok.ok, _reasons(ok)
    # prior version and its entry stay readable and unchanged
    assert hist.versions[0].version == "v1"
    assert hist.versions[0].entries[0].sink_probe == "requests.get(url)"


# --------------------------------------------------------------------------- #
# AC-3 — denominator preservation + unsupported-analysis is an in-denominator miss
# --------------------------------------------------------------------------- #
def test_ac3_silent_shrink_fails_and_unsupported_is_miss():
    a = _entry(vuln=A40)
    b = _entry(vuln=C40)  # distinct identity
    v1 = _cohort("v1", [a, b])
    v2 = _cohort("v2", [a], reason="dropped b", parent="v1")  # b removed, NO event
    shrink = validate(history=CohortHistory(versions=[v1, v2]))
    assert not shrink.ok and ViolationReason.DENOMINATOR_SHRINK in _reasons(shrink)

    # legitimate removal: a logged exclusion referencing b's identity
    excl = ExclusionLog(
        events=[
            ExclusionEvent(
                reason=ExclusionReason.ALIAS_DUPE,
                entry_identity=b.identity_hash,
                from_version="v1",
                to_version="v2",
            )
        ]
    )
    ok = validate(history=CohortHistory(versions=[v1, v2]), exclusions=excl)
    assert ok.ok, _reasons(ok)

    # unsupported analysis is a MISS inside the denominator, never a run-invalidator
    ev = ExclusionEvent(reason=ExclusionReason.UNSUPPORTED_LANGUAGE)
    assert ev.is_miss and not ev.invalidates_run
    assert ev.classification is ExclusionClass.ANALYSIS_LIMITATION


# --------------------------------------------------------------------------- #
# AC-4 — blind never silently reused after guiding a fix
# --------------------------------------------------------------------------- #
def test_ac4_blind_reused_after_fix_fails_unless_moved_to_regression():
    g = _entry(role="blind", guided_fix=True)
    solo = validate(history=CohortHistory(versions=[_cohort("v1", [g])]))
    assert not solo.ok and ViolationReason.BLIND_REUSED_AFTER_FIX in _reasons(solo)

    # role is NOT part of entry identity: moving blind -> regression keeps the
    # identity. But it DOES leave the blind denominator, so (R2) it must be authorized
    # by a matched ROLE_DOWNGRADE cohort-correction event, in a new version.
    g_reg = g.model_copy(update={"role": "regression"}).sealed()
    assert g_reg.identity_hash == g.identity_hash
    v1 = _cohort("v1", [g])
    v2 = _cohort("v2", [g_reg], reason="blind guided a fix -> regression", parent="v1")
    # without the event, the blind-set shrink is a violation
    unlogged = validate(history=CohortHistory(versions=[v1, v2]))
    assert not unlogged.ok and ViolationReason.DENOMINATOR_SHRINK in _reasons(unlogged)
    # with the matched correction event, the move is legitimate
    excl = ExclusionLog(
        events=[
            ExclusionEvent(
                reason=ExclusionReason.ROLE_DOWNGRADE,
                entry_identity=g.identity_hash,
                from_version="v1",
                to_version="v2",
            )
        ]
    )
    fixed = validate(history=CohortHistory(versions=[v1, v2]), exclusions=excl)
    assert fixed.ok, _reasons(fixed)


# --------------------------------------------------------------------------- #
# AC-5 — freeze presence + freeze-hash sensitivity
# --------------------------------------------------------------------------- #
def test_ac5_missing_freeze_fails_and_bundle_change_moves_hash():
    run = EvaluationRun(run_id="r1", subject="claude", cohort_content_hash="H")
    with pytest.raises(ContractViolation) as ei:
        run.attempt_evaluation(phase="post_freeze", produced_results=True)
    assert ei.value.reason is ViolationReason.MISSING_FREEZE

    run_bad = EvaluationRun(
        run_id="r2",
        subject="s",
        cohort_content_hash="H",
        attempts=[EvalAttempt(phase="post_freeze", produced_results=True)],
    )
    assert ViolationReason.MISSING_FREEZE in _reasons(validate(run=run_bad))

    b1 = DetectorBundle(
        detector_id="d",
        parser_versions={"tree-sitter-python": "0.23"},
        lockfile_hash="L1",
        params={"budget": 100},
    )
    f1 = FreezeManifest(bundle=b1, timestamp="2026-07-16T10:00:00Z")
    # timestamp alone does NOT change the content hash (content-addressed bundle)
    f1_later = FreezeManifest(bundle=b1, timestamp="2026-07-16T12:00:00Z")
    assert f1.freeze_hash == f1_later.freeze_hash
    # each bundle component moves the hash
    for update in (
        {"parser_versions": {"tree-sitter-python": "0.24"}},
        {"lockfile_hash": "L2"},
        {"params": {"budget": 200}},
    ):
        other = FreezeManifest(bundle=b1.model_copy(update=update), timestamp="t")
        assert other.freeze_hash != f1.freeze_hash


# --------------------------------------------------------------------------- #
# AC-6 — exposure ledger: curator != subject
# --------------------------------------------------------------------------- #
def test_ac6_curator_cannot_score_itself():
    ledger = ExposureLedger()
    ledger.record(cohort_content_hash="H", actor="claude", activity="curated")
    run = _run("claude", "H", "fz")
    bad = validate(run=run, ledger=ledger)
    assert not bad.ok and ViolationReason.CURATOR_IS_SUBJECT in _reasons(bad)
    # a non-exposed subject is fine; rotation surfaces one
    ok = validate(run=_run("codex", "H", "fz"), ledger=ledger)
    assert ok.ok, _reasons(ok)
    assert ledger.rotate_subject(["claude", "codex"], "H") == "codex"


# --------------------------------------------------------------------------- #
# AC-7 — blind-access discipline
# --------------------------------------------------------------------------- #
def test_ac7_one_post_freeze_no_pre_freeze_and_infra_retry_rules():
    run = EvaluationRun(run_id="r", subject="s", cohort_content_hash="H", freeze_hash="fz")
    run.attempt_evaluation(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E")
    with pytest.raises(ContractViolation) as second:
        run.attempt_evaluation(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E")
    assert second.value.reason is ViolationReason.BLIND_ACCESS_EXCEEDED

    pre = EvaluationRun(run_id="r2", subject="s", cohort_content_hash="H", freeze_hash="fz")
    with pytest.raises(ContractViolation) as pf:
        pre.attempt_evaluation(phase="pre_freeze", produced_results=False)
    assert pf.value.reason is ViolationReason.BLIND_ACCESS_PRE_FREEZE

    # infra retry allowed: first attempt produced NO results, hashes unchanged
    retry = EvaluationRun(run_id="r3", subject="s", cohort_content_hash="H", freeze_hash="fz")
    retry.attempt_evaluation(phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E")
    retry.attempt_evaluation(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E")
    assert retry.semantic_evaluation_count == 1

    # infra retry refused if a hash changed
    bad_retry = EvaluationRun(run_id="r4", subject="s", cohort_content_hash="H", freeze_hash="fz")
    bad_retry.attempt_evaluation(phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E")
    with pytest.raises(ContractViolation) as ir:
        bad_retry.attempt_evaluation(phase="post_freeze", produced_results=True, artifact_hash="A2", env_hash="E")
    assert ir.value.reason is ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED


# --------------------------------------------------------------------------- #
# AC-8 — exclusion taxonomy typed, classified, append-only
# --------------------------------------------------------------------------- #
def test_ac8_exclusion_taxonomy_typed_classified_append_only():
    # closed taxonomy: an unknown reason is rejected at the type boundary
    with pytest.raises(ValidationError):
        ExclusionEvent(reason="totally-made-up")
    # every member carries a classification
    for reason in ExclusionReason:
        assert ExclusionEvent(reason=reason).classification in set(ExclusionClass)
    # infrastructure invalidates the run; analysis-limitation is a miss
    assert ExclusionEvent(reason=ExclusionReason.CRASH).invalidates_run
    assert not ExclusionEvent(reason=ExclusionReason.CRASH).is_miss
    assert ExclusionEvent(reason=ExclusionReason.UNSUPPORTED_LANGUAGE).is_miss
    assert not ExclusionEvent(reason=ExclusionReason.UNSUPPORTED_LANGUAGE).invalidates_run
    # append-only: prior events stay a stable prefix
    log = ExclusionLog()
    e1 = ExclusionEvent(reason=ExclusionReason.SEED_SWAP)
    log.append(e1)
    prefix = list(log.events)
    e2 = ExclusionEvent(reason=ExclusionReason.ALIAS_DUPE)
    log.append(e2)
    assert log.events[0] == e1 and log.events[: len(prefix)] == prefix
    assert log.is_extension_of(ExclusionLog(events=prefix))
    assert not ExclusionLog(events=[e2]).is_extension_of(ExclusionLog(events=prefix))


# --------------------------------------------------------------------------- #
# AC-9 — recall and precision are separate metrics
# --------------------------------------------------------------------------- #
def test_ac9_recall_independent_of_density_precision_needs_blind_sample():
    lo = RecallReport(rediscovered=3, total=4, patched_alert_density=0.0)
    hi = RecallReport(rediscovered=3, total=4, patched_alert_density=99.0)
    assert lo.recall == hi.recall == 0.75  # density never moves recall

    seed = precision_sample_seed("cohortH", "freezeF", "run1")
    assert seed == precision_sample_seed("cohortH", "freezeF", "run1")  # deterministic
    pairs = [f"p{i:02d}" for i in range(20)]
    assert sample_confusion_pairs(pairs, 5, seed) == sample_confusion_pairs(pairs, 5, seed)

    # a builder on the panel is invalid
    with pytest.raises(ValidationError):
        AdjudicatedPrecision(
            seed=seed,
            sampled_pairs=["p0"],
            pool=["p0"],
            k=1,
            adjudications=[
                Adjudication(
                    pair_id="p0",
                    verdicts=[
                        AdjudicatorVerdict(adjudicator="A", is_builder=True, is_curator=False, decision="true-positive"),
                        AdjudicatorVerdict(adjudicator="B", is_builder=False, is_curator=False, decision="true-positive"),
                    ],
                )
            ],
        )
    # fewer than two adjudicators is invalid
    with pytest.raises(ValidationError):
        AdjudicatedPrecision(
            seed=seed,
            sampled_pairs=["p0"],
            pool=["p0"],
            k=1,
            adjudications=[
                Adjudication(
                    pair_id="p0",
                    verdicts=[AdjudicatorVerdict(adjudicator="A", is_builder=False, is_curator=False, decision="true-positive")],
                )
            ],
        )
    # all-curator panel is invalid (need >= 1 non-curator)
    with pytest.raises(ValidationError):
        AdjudicatedPrecision(
            seed=seed,
            sampled_pairs=["p0"],
            pool=["p0"],
            k=1,
            adjudications=[
                Adjudication(
                    pair_id="p0",
                    verdicts=[
                        AdjudicatorVerdict(adjudicator="A", is_builder=False, is_curator=True, decision="true-positive"),
                        AdjudicatorVerdict(adjudicator="B", is_builder=False, is_curator=True, decision="true-positive"),
                    ],
                )
            ],
        )
    # ambiguous counts AGAINST precision (sample derived from the deterministic draw)
    amb_sample = sample_confusion_pairs(pairs, 2, seed)
    ap = AdjudicatedPrecision(
        seed=seed,
        sampled_pairs=amb_sample,
        pool=pairs,
        k=2,
        adjudications=[_good_panel(amb_sample[0], "true-positive"), _good_panel(amb_sample[1], "ambiguous")],
    )
    assert ap.precision == 0.5


# --------------------------------------------------------------------------- #
# AC-10 — real-other-finding re-gating
# --------------------------------------------------------------------------- #
def test_ac10_real_other_finding_becomes_gated_candidate():
    adj = _good_panel("p3", "real-other-finding")
    cands = candidates_from_adjudications([adj], cohort_content_hash="H")
    assert len(cands) == 1
    assert cands[0].requires_authorization is True
    assert cands[0].auto_investigated is False
    # a candidate can never be marked auto-investigated
    with pytest.raises(ValidationError):
        LocalCandidate(origin_pair_id="p3", cohort_content_hash="H", auto_investigated=True)


# --------------------------------------------------------------------------- #
# AC-11 — synthetic separation + removal proof + sandbox gate
# --------------------------------------------------------------------------- #
def test_ac11_synthetic_never_in_real_aggregate_and_proof_required():
    with pytest.raises(ValidationError):  # removal proof required
        SyntheticVariant(variant_id="s1", base_cve="CVE-x", removal_proof="", proof_kind="static")
    with pytest.raises(ValidationError):  # execution proof gated behind the sandbox
        SyntheticVariant(variant_id="s2", base_cve="CVE-x", removal_proof="ran it", proof_kind="execution", sandbox_attested=False)

    sv = SyntheticVariant(variant_id="s3", base_cve="CVE-x", removal_proof="static AST removal", proof_kind="static")
    agg = RealCVEAggregate(label="real")
    agg.add(ClassRate(bug_class="ssrf", rediscovered=3, total=4))  # real numbers ok
    with pytest.raises(ContractViolation) as ei:
        agg.add(sv)
    assert ei.value.reason is ViolationReason.SYNTHETIC_IN_REAL_AGGREGATE
    # a loudly-labeled robustness suite holds it instead
    suite = SyntheticSuite(label="ROBUSTNESS (synthetic; not a real-CVE number)", variants=[sv])
    assert suite.variants[0] is sv


# --------------------------------------------------------------------------- #
# AC-12 — achievability is append-only + pre-freeze + falsifiable
# --------------------------------------------------------------------------- #
def test_ac12_achievability_append_only_prefreeze_falsifiable():
    log = AchievabilityLog(freeze_timestamp="2026-07-16T12:00:00Z")
    p = AchievabilityPrediction(entry_identity="E1", predicted_achievable=False, registered_at="2026-07-16T09:00:00Z")
    log.append(p)  # pre-freeze OK
    with pytest.raises(ContractViolation) as ei:  # post-freeze registration refused
        log.append(AchievabilityPrediction(entry_identity="E2", predicted_achievable=False, registered_at="2026-07-16T13:00:00Z"))
    assert ei.value.reason is ViolationReason.ACHIEVABILITY_NOT_PRE_FREEZE

    # a later rediscovery falsifies the prediction WITHOUT rewriting the record
    fals = log.falsifications({"E1"})
    assert p in fals
    assert p.predicted_achievable is False and p.registered_at == "2026-07-16T09:00:00Z"

    # the authoritative rate stays blind/all-pinned; achievable is only a secondary
    rep = Report(
        blind_recall=RecallReport(rediscovered=3, total=4),
        fixed_cohort_recall=RecallReport(rediscovered=9, total=10),
        coverage=0.95,
        patched_alert_density=1.2,
        adjudicated_precision=0.8,
        achievable_recall=0.9,
    )
    assert rep.authoritative_recall is rep.blind_recall


# --------------------------------------------------------------------------- #
# AC-13 — blind-led, multi-number reporting
# --------------------------------------------------------------------------- #
def test_ac13_report_leads_with_blind_and_labels_five_numbers():
    rep = Report(
        blind_recall=RecallReport(rediscovered=3, total=4),
        fixed_cohort_recall=RecallReport(rediscovered=9, total=10),
        coverage=0.95,
        patched_alert_density=1.2,
        adjudicated_precision=0.8,
    )
    lines = rep.lines()
    assert "blind recall" in lines[0].lower()  # headline first
    text = rep.render()
    for label in ("blind recall", "fixed-cohort recall", "coverage", "patched-alert density", "adjudicated precision"):
        assert label in text
    assert "blind recall" in rep.headline().lower()
    assert rep.authoritative_recall is rep.blind_recall


# --------------------------------------------------------------------------- #
# AC-14 — check enforces the whole contract
# --------------------------------------------------------------------------- #
def test_ac14_check_fails_on_each_violation_class():
    # bad entry hash
    e = _entry()
    e_bad = e.model_copy(update={"declared_identity_hash": "0" * 64})
    bad_hash = validate(history=CohortHistory(versions=[Cohort(version="v1", entries=[e_bad]).sealed()]))
    assert ViolationReason.BAD_ENTRY_HASH in _reasons(bad_hash)

    # non-monotone version
    nonmono = validate(history=CohortHistory(versions=[_cohort("v2", [_entry()]), _cohort("v1", [_entry()])]))
    assert ViolationReason.NON_MONOTONE_VERSION in _reasons(nonmono)

    # silent denominator shrink
    a, b = _entry(vuln=A40), _entry(vuln=C40)
    shrink = validate(history=CohortHistory(versions=[_cohort("v1", [a, b]), _cohort("v2", [a])]))
    assert ViolationReason.DENOMINATOR_SHRINK in _reasons(shrink)

    # curator == subject
    ledger = ExposureLedger()
    ledger.record(cohort_content_hash="H", actor="claude", activity="inspected")
    csub = validate(
        run=_run("claude", "H", "fz"),
        ledger=ledger,
    )
    assert ViolationReason.CURATOR_IS_SUBJECT in _reasons(csub)

    # missing freeze
    missing = validate(
        run=EvaluationRun(
            run_id="r",
            subject="s",
            cohort_content_hash="H",
            attempts=[EvalAttempt(phase="post_freeze", produced_results=True)],
        )
    )
    assert ViolationReason.MISSING_FREEZE in _reasons(missing)

    # blind-access > 1
    over = validate(
        run=EvaluationRun(
            run_id="r",
            subject="s",
            cohort_content_hash="H",
            freeze_hash="fz",
            attempts=[
                EvalAttempt(phase="post_freeze", produced_results=True),
                EvalAttempt(phase="post_freeze", produced_results=True),
            ],
        )
    )
    assert ViolationReason.BLIND_ACCESS_EXCEEDED in _reasons(over)

    # a fully consistent bundle passes everything
    good = validate(
        history=CohortHistory(versions=[_cohort("v1", [_entry()])]),
        run=_run("codex", "H", "fz"),
        ledger=ExposureLedger(),
    )
    assert good.ok, _reasons(good)


# --------------------------------------------------------------------------- #
# Adversarial-audit regression floor (H1..H9). Each case dishonestly passed
# validate() before the fix; validate() must now REJECT it. See
# scratchpad/contract-fix-spec.md and specs/008-evaluation-contract/threat-model.md.
# --------------------------------------------------------------------------- #


# H1 — a removal is legitimate ONLY when covered by a COHORT_CORRECTION-class event.
def test_h1_removal_requires_cohort_correction_class():
    a = _entry(vuln=A40)
    b = _entry(vuln=C40)  # distinct identity, the case being dropped
    v1 = _cohort("v1", [a, b])
    v2 = _cohort("v2", [a], reason="dropped b", parent="v1")
    hist = CohortHistory(versions=[v1, v2])

    # An ANALYSIS_LIMITATION event referencing b must NOT legitimize the removal
    # (this is the discriminator: class-blind removed_identities() wrongly did).
    excl_analysis = ExclusionLog(
        events=[
            ExclusionEvent(
                reason=ExclusionReason.UNSUPPORTED_LANGUAGE,
                entry_identity=b.identity_hash,
                from_version="v1",
                to_version="v2",
            )
        ]
    )
    rep = validate(history=hist, exclusions=excl_analysis)
    assert not rep.ok and ViolationReason.DENOMINATOR_SHRINK in _reasons(rep)

    # A run-level POLICY_REFUSAL event cannot cover a removal either.
    excl_policy = ExclusionLog(
        events=[ExclusionEvent(reason=ExclusionReason.POLICY_REFUSAL, from_version="v1", to_version="v2")]
    )
    rep2 = validate(history=hist, exclusions=excl_policy)
    assert not rep2.ok and ViolationReason.DENOMINATOR_SHRINK in _reasons(rep2)

    # Only a COHORT_CORRECTION event matching the transition legitimizes it.
    excl_ok = ExclusionLog(
        events=[
            ExclusionEvent(
                reason=ExclusionReason.ALIAS_DUPE,
                entry_identity=b.identity_hash,
                from_version="v1",
                to_version="v2",
            )
        ]
    )
    assert validate(history=hist, exclusions=excl_ok).ok


# H2 — any INFRASTRUCTURE-class exclusion invalidates the run.
def test_h2_infrastructure_exclusion_invalidates_run():
    excl = ExclusionLog(events=[ExclusionEvent(reason=ExclusionReason.CRASH)])
    rep = validate(exclusions=excl)
    assert not rep.ok and ViolationReason.RUN_INVALID in _reasons(rep)


# H3 — POLICY_REFUSAL / INFRASTRUCTURE reasons are run-level: no entry_identity.
def test_h3_run_level_reasons_forbid_entry_identity():
    with pytest.raises(ValidationError):
        ExclusionEvent(reason=ExclusionReason.POLICY_REFUSAL, entry_identity="x")
    with pytest.raises(ValidationError):
        ExclusionEvent(reason=ExclusionReason.CRASH, entry_identity="x")
    # analysis-limitation and correction reasons MAY carry an entry identity
    ExclusionEvent(reason=ExclusionReason.UNSUPPORTED_LANGUAGE, entry_identity="x")
    ExclusionEvent(reason=ExclusionReason.ALIAS_DUPE, entry_identity="x")


# H4 — a stale event cannot launder a later same-identity removal (exact transition).
def test_h4_stale_event_cannot_launder_later_transition():
    x = _entry(vuln=A40)
    anchor = _entry(vuln=B40, probe="other.call()")  # keeps cohorts non-empty across versions
    v1 = _cohort("v1", [x, anchor])
    v2 = _cohort("v2", [anchor], reason="drop x", parent="v1")
    v3 = _cohort("v3", [x, anchor], reason="re-add x", parent="v2")
    v4 = _cohort("v4", [anchor], reason="silently drop x again", parent="v3")
    hist = CohortHistory(versions=[v1, v2, v3, v4])
    # one event authorizes exactly the v1->v2 removal, NOT the later v3->v4 one
    excl = ExclusionLog(
        events=[
            ExclusionEvent(
                reason=ExclusionReason.ALIAS_DUPE,
                entry_identity=x.identity_hash,
                from_version="v1",
                to_version="v2",
            )
        ]
    )
    rep = validate(history=hist, exclusions=excl)
    assert not rep.ok and ViolationReason.DENOMINATOR_SHRINK in _reasons(rep)


# H5 — the infra-retry invariant is enforced in validate(), not just attempt_evaluation().
def test_h5_infra_retry_invariant_enforced_in_validate():
    run = EvaluationRun(
        run_id="r",
        subject="s",
        cohort_content_hash="H",
        freeze_hash="fz",
        attempts=[
            EvalAttempt(phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E", logs_intact=False),
            EvalAttempt(phase="post_freeze", produced_results=False, artifact_hash="A2", env_hash="E2"),
            EvalAttempt(phase="post_freeze", produced_results=True, artifact_hash="A3", env_hash="E3"),
        ],
    )
    rep = validate(run=run)
    assert not rep.ok and ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED in _reasons(rep)


# H6 — the freeze must bind a real bundle; calibration seeds disjoint from blind.
def test_h6_freeze_binding_and_seed_disjointness():
    blind = _entry(vuln=A40, role="blind")
    v1 = _cohort("v1", [blind])
    hist = CohortHistory(versions=[v1])

    bundle = DetectorBundle(detector_id="d", lockfile_hash="L")
    freeze = FreezeManifest(bundle=bundle, timestamp="2026-07-16T10:00:00Z")
    run = EvaluationRun(run_id="r", subject="s", cohort_content_hash=v1.content_hash, freeze_hash="fabricated")
    rep = validate(history=hist, run=run, freeze=freeze)
    assert not rep.ok and ViolationReason.BAD_FREEZE_BINDING in _reasons(rep)

    # a calibration seed that is also a blind entry identity is rejected
    bundle2 = DetectorBundle(detector_id="d", lockfile_hash="L", calibration_seed_ids=[blind.identity_hash])
    freeze2 = FreezeManifest(bundle=bundle2, timestamp="2026-07-16T10:00:00Z")
    run2 = EvaluationRun(run_id="r2", subject="s", cohort_content_hash=v1.content_hash, freeze_hash=freeze2.freeze_hash)
    rep2 = validate(history=hist, run=run2, freeze=freeze2)
    assert not rep2.ok and ViolationReason.SEED_IN_BLIND in _reasons(rep2)

    # a correctly-bound freeze with a disjoint seed passes (canonical run_id, R5)
    bundle3 = DetectorBundle(detector_id="d", lockfile_hash="L")
    freeze3 = FreezeManifest(bundle=bundle3, timestamp="2026-07-16T10:00:00Z")
    run3 = _run("s", v1.content_hash, freeze3.freeze_hash)
    assert validate(history=hist, run=run3, freeze=freeze3).ok


# H7 — the Report's blind denominator is recomputed from the frozen cohort's blind entries.
def test_h7_report_bound_to_cohort_denominator():
    blinds = [_entry(vuln=letter * 40, role="blind") for letter in ("a", "b", "c")]
    v1 = _cohort("v1", blinds)
    hist = CohortHistory(versions=[v1])

    rep_under = Report(
        blind_recall=RecallReport(rediscovered=2, total=2),  # true blind count is 3
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        coverage=1.0,
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
        cohort_content_hash=v1.content_hash,
    )
    out = validate(history=hist, report=rep_under)
    assert not out.ok and ViolationReason.REPORT_DENOMINATOR_MISMATCH in _reasons(out)

    # a report whose per-entry rediscovered set and total match the cohort passes
    rep_ok = Report(
        blind_recall=RecallReport(rediscovered=2, total=3),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        coverage=1.0,
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
        cohort_content_hash=v1.content_hash,
        rediscovered_blind_ids=[blinds[0].identity_hash, blinds[1].identity_hash],
    )
    # the binding itself is honest (check_report only exercises the denominator/numerator
    # binding); the full validate() now additionally requires certification (R7-1), tested
    # separately — so this asserts the binding via check_report.
    assert check_report(rep_ok, hist).ok
    # and a numerator-asserting Report through the default check is UNANCHORED without cert
    assert ViolationReason.UNANCHORED in _reasons(validate(history=hist, report=rep_ok))

    # a rediscovered set that disagrees with the reported count is rejected
    rep_bad_set = rep_ok.model_copy(update={"rediscovered_blind_ids": [blinds[0].identity_hash]})
    out2 = validate(history=hist, report=rep_bad_set)
    assert not out2.ok and ViolationReason.REPORT_DENOMINATOR_MISMATCH in _reasons(out2)


# H8 — precision requires full coverage and a seed/sample bound to precision_sample_seed.
def test_h8_precision_coverage_and_sample_binding():
    seed = precision_sample_seed("cohortH", "freezeF", "run1")
    pool = [f"p{i:02d}" for i in range(20)]
    sample = sample_confusion_pairs(pool, 3, seed)

    # coverage: adjudicating only a favorable subset is rejected
    with pytest.raises(ValidationError):
        AdjudicatedPrecision(
            seed=seed,
            sampled_pairs=sample,
            pool=pool,
            k=3,
            cohort_hash="cohortH",
            freeze_hash="freezeF",
            run_id="run1",
            adjudications=[_good_panel(sample[0], "true-positive")],
        )

    # arbitrary seed unbound from precision_sample_seed is rejected
    with pytest.raises(ValidationError):
        AdjudicatedPrecision(
            seed=12345,
            sampled_pairs=sample,
            pool=pool,
            k=3,
            cohort_hash="cohortH",
            freeze_hash="freezeF",
            run_id="run1",
            adjudications=[_good_panel(s, "true-positive") for s in sample],
        )

    # arbitrary sample not drawn by sample_confusion_pairs(pool, k, seed) is rejected
    with pytest.raises(ValidationError):
        AdjudicatedPrecision(
            seed=seed,
            sampled_pairs=["p0", "p1", "p2"],
            pool=pool,
            k=3,
            cohort_hash="cohortH",
            freeze_hash="freezeF",
            run_id="run1",
            adjudications=[_good_panel(s, "true-positive") for s in ["p0", "p1", "p2"]],
        )

    # full coverage with a correctly-bound seed and sample passes
    ap = AdjudicatedPrecision(
        seed=seed,
        sampled_pairs=sample,
        pool=pool,
        k=3,
        cohort_hash="cohortH",
        freeze_hash="freezeF",
        run_id="run1",
        adjudications=[_good_panel(s, "true-positive") for s in sample],
    )
    assert ap.precision == 1.0

    # routing through validate(): a precision bound to a different run context is rejected.
    # The run's run_id must itself be canonical (R5), so the bound seed derives from it.
    bundle = DetectorBundle(detector_id="d")
    freeze = FreezeManifest(bundle=bundle, timestamp="2026-07-16T10:00:00Z")
    rid = _canonical_run_id("CH", freeze.freeze_hash, "s")
    run = EvaluationRun(run_id=rid, subject="s", cohort_content_hash="CH", freeze_hash=freeze.freeze_hash)
    seed_rp = precision_sample_seed("CH", freeze.freeze_hash, rid)
    ap_bound = AdjudicatedPrecision(
        seed=seed_rp,
        sampled_pairs=sample_confusion_pairs(pool, 3, seed_rp),
        pool=pool,
        k=3,
        cohort_hash="CH",
        freeze_hash=freeze.freeze_hash,
        run_id=rid,
        adjudications=[_good_panel(s, "true-positive") for s in sample_confusion_pairs(pool, 3, seed_rp)],
    )
    assert validate(run=run, freeze=freeze, precision=ap_bound).ok

    seed_other = precision_sample_seed("CH", freeze.freeze_hash, "other")
    ap_mismatch = AdjudicatedPrecision(
        seed=seed_other,
        sampled_pairs=sample_confusion_pairs(pool, 3, seed_other),
        pool=pool,
        k=3,
        cohort_hash="CH",
        freeze_hash=freeze.freeze_hash,
        run_id="other",
        adjudications=[_good_panel(s, "true-positive") for s in sample_confusion_pairs(pool, 3, seed_other)],
    )
    outp = validate(run=run, freeze=freeze, precision=ap_mismatch)
    assert not outp.ok and ViolationReason.PRECISION_SAMPLE_UNBOUND in _reasons(outp)


# H9 — the achievability log is sealed and append-only, enforced by validate().
def test_h9_achievability_sealed_and_append_only():
    # direct construction bypasses append()'s guard; validate must still reject hindsight
    log = AchievabilityLog(
        freeze_timestamp="2026-07-16T12:00:00Z",
        predictions=[
            AchievabilityPrediction(
                entry_identity="E1", predicted_achievable=False, registered_at="2026-07-16T13:00:00Z"
            )
        ],
    )
    rep = validate(achievability=log)
    assert not rep.ok and ViolationReason.ACHIEVABILITY_NOT_PRE_FREEZE in _reasons(rep)

    # an in-place rewrite after sealing trips the seal
    good = AchievabilityLog(
        freeze_timestamp="2026-07-16T12:00:00Z",
        predictions=[
            AchievabilityPrediction(
                entry_identity="E1", predicted_achievable=False, registered_at="2026-07-16T09:00:00Z"
            )
        ],
    ).sealed()
    tampered = good.model_copy(
        update={
            "predictions": [
                AchievabilityPrediction(
                    entry_identity="E2", predicted_achievable=True, registered_at="2026-07-16T09:00:00Z"
                )
            ]
        }
    )
    rep2 = validate(achievability=tampered)
    assert not rep2.ok and ViolationReason.IN_PLACE_EDIT in _reasons(rep2)

    # a sealed, pre-freeze, append-only log passes
    assert validate(achievability=good).ok


# --------------------------------------------------------------------------- #
# Round-2 adversarial-audit regression floor (R1..R8). Each case dishonestly
# passed validate() AFTER the round-1 (H1..H9) seals held; validate() must now
# REJECT it. See scratchpad/contract-fix-spec-r2.md and
# specs/008-evaluation-contract/threat-model.md. Two governing principles:
# P1 — no binding check is skippable by omitting a sibling arg / leaving an
# Optional None; P2 — seal every denominator-affecting field AND preserve it
# across versions via a matched COHORT_CORRECTION event.
# --------------------------------------------------------------------------- #


# R1 — role + guided_fix are sealed into the cohort content hash: an in-place flip breaks it.
def test_r1_inplace_role_flip_breaks_content_seal():
    # a BLIND miss sealed at v1, flipped to REGRESSION in place (same version) → seal breaks
    m = _entry(vuln=A40, role="blind")
    v1 = _cohort("v1", [m])
    flipped = m.model_copy(update={"role": "regression"}).sealed()  # identity is preserved
    assert flipped.identity_hash == m.identity_hash
    v1_tampered = v1.model_copy(update={"entries": [flipped]})  # keeps v1's declared_content_hash
    rep = validate(history=CohortHistory(versions=[v1_tampered]))
    assert not rep.ok and ViolationReason.IN_PLACE_EDIT in _reasons(rep)

    # a guided_fix BLIND entry flipped to REGRESSION in place still fails (no version bump) —
    # this is the AC-4 dodge the seal now closes
    g = _entry(vuln=B40, role="blind", guided_fix=True)
    vg = _cohort("v1", [g])
    g_flipped = g.model_copy(update={"role": "regression"}).sealed()
    vg_tampered = vg.model_copy(update={"entries": [g_flipped]})
    repg = validate(history=CohortHistory(versions=[vg_tampered]))
    assert not repg.ok and ViolationReason.IN_PLACE_EDIT in _reasons(repg)


# R2 — a cross-version BLIND->regression downgrade (identity preserved) still needs an event.
def test_r2_blind_role_downgrade_needs_correction_event():
    a = _entry(vuln=A40, role="blind")
    b = _entry(vuln=B40, role="blind")
    # R9-4: a legitimate blind->regression ROLE_DOWNGRADE is authorized for an entry that GUIDED A
    # FIX (FR-4); c carries guided_fix=True in v1 (its from_version) so the downgrade is allowed.
    c = _entry(vuln=C40, role="blind", guided_fix=True)
    v1 = _cohort("v1", [a, b, c])
    c_reg = c.model_copy(update={"role": "regression"}).sealed()  # identity preserved
    assert c_reg.identity_hash == c.identity_hash
    v2 = _cohort("v2", [a, b, c_reg], reason="downgrade c out of blind", parent="v1")
    # NO event: leaving the blind set (even with identity preserved) is a shrink
    rep = validate(history=CohortHistory(versions=[v1, v2]))
    assert not rep.ok and ViolationReason.DENOMINATOR_SHRINK in _reasons(rep)
    # WITH a matched COHORT_CORRECTION event for c's exact transition → allowed
    excl = ExclusionLog(
        events=[
            ExclusionEvent(
                reason=ExclusionReason.ROLE_DOWNGRADE,
                entry_identity=c.identity_hash,
                from_version="v1",
                to_version="v2",
            )
        ]
    )
    assert validate(history=CohortHistory(versions=[v1, v2]), exclusions=excl).ok


# R3 — the presented history must be an append-only extension of a prior_history baseline.
def test_r3_prior_history_must_be_append_only_extension():
    a = _entry(vuln=A40, role="blind")
    b = _entry(vuln=B40, role="blind")
    v1 = _cohort("v1", [a, b])
    prior = CohortHistory(versions=[v1])

    # a from-storage rebuild that DROPS v1 and presents only a later single version
    # (single version → the consecutive-pair denominator check never even fires)
    v7 = _cohort("v7", [a], reason="rebuild dropping b", parent="v1")
    truncated = CohortHistory(versions=[v7])
    rep = validate(history=truncated, prior_history=prior)
    assert not rep.ok and ViolationReason.HISTORY_TRUNCATED in _reasons(rep)

    # altering a baseline version's content in place (same tag, fewer entries) is rejected
    v1_alt = _cohort("v1", [a])
    c = _entry(vuln=C40, role="blind")
    v2 = _cohort("v2", [a, b, c], reason="add c", parent="v1")
    altered = CohortHistory(versions=[v1_alt, v2])
    rep2 = validate(history=altered, prior_history=prior)
    assert not rep2.ok and ViolationReason.IN_PLACE_EDIT in _reasons(rep2)

    # an honest append: prior stays at index 0 unchanged, a new version is appended
    extended = CohortHistory(versions=[v1, v2])
    assert validate(history=extended, prior_history=prior).ok


# R4 — the Report numerator + cohort binding are MANDATORY (P1); no silent unbound pass.
def test_r4_report_numerator_and_binding_mandatory():
    blinds = [_entry(vuln=x * 40, role="blind") for x in ("a", "b", "c", "d")]
    v1 = _cohort("v1", blinds)
    hist = CohortHistory(versions=[v1])

    # a headline 4/4 with the numerator UNBOUND (rediscovered_blind_ids=None) is rejected,
    # even though the total matches the cohort — the per-entry numerator binding is mandatory
    liar = Report(
        blind_recall=RecallReport(rediscovered=4, total=4),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        coverage=1.0,
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
        cohort_content_hash=v1.content_hash,
    )
    out = validate(history=hist, report=liar)
    assert not out.ok and ViolationReason.REPORT_DENOMINATOR_MISMATCH in _reasons(out)

    # a Report with NO cohort/history to bind against is REPORT_UNBOUND, never a silent pass
    unbound = Report(
        blind_recall=RecallReport(rediscovered=4, total=4),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        coverage=1.0,
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
    )
    out2 = validate(report=unbound)
    assert not out2.ok and ViolationReason.REPORT_UNBOUND in _reasons(out2)

    # the honest bound form (numerator present, subset of blind, matching count) passes
    bound = Report(
        blind_recall=RecallReport(rediscovered=1, total=4),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        coverage=1.0,
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
        cohort_content_hash=v1.content_hash,
        rediscovered_blind_ids=[blinds[0].identity_hash],
    )
    # the honest bound form passes the binding check; full validate() additionally requires
    # certification for a numerator-asserting Report (R7-1), verified separately.
    assert check_report(bound, hist).ok
    assert ViolationReason.UNANCHORED in _reasons(validate(history=hist, report=bound))


# R5 — a canonical, non-re-rollable run_id + evaluate-once ledger.
def test_r5_canonical_run_id_and_evaluate_once():
    a = _entry(vuln=A40, role="blind")
    v1 = _cohort("v1", [a])
    hist = CohortHistory(versions=[v1])
    freeze = FreezeManifest(
        bundle=DetectorBundle(detector_id="d", lockfile_hash="L"), timestamp="2026-07-16T10:00:00Z"
    )
    ch, fz = v1.content_hash, freeze.freeze_hash

    # a free-string run_id (re-rollable to re-draw the precision sample) is rejected
    rerollable = EvaluationRun(
        run_id="hand-picked-favorable", subject="s", cohort_content_hash=ch, freeze_hash=fz
    )
    rep = validate(history=hist, run=rerollable, freeze=freeze)
    assert not rep.ok and ViolationReason.NON_CANONICAL_RUN_ID in _reasons(rep)

    # the one canonical run_id for (cohort, freeze, subject) passes
    good = _run("s", ch, fz)
    assert validate(history=hist, run=good, freeze=freeze).ok

    # a SECOND evaluation of the same (cohort, freeze, subject) across a prior ledger is flagged
    prior = EvaluationLedger()
    prior.record(cohort_content_hash=ch, freeze_hash=fz, subject="s")
    rep2 = validate(history=hist, run=good, freeze=freeze, prior_evaluations=prior)
    assert not rep2.ok and ViolationReason.EVALUATED_MORE_THAN_ONCE in _reasons(rep2)


# R6 — freeze is mandatory for any run that recorded post-freeze attempts (P1).
def test_r6_freeze_mandatory_for_post_freeze_run():
    # a run with a post-freeze attempt and a FABRICATED freeze_hash, validated with NO
    # freeze manifest → the fabricated hash cannot stand in; a freeze is mandatory
    run = EvaluationRun(
        run_id="r",
        subject="s",
        cohort_content_hash="H",
        freeze_hash="fabricated",
        attempts=[EvalAttempt(phase="post_freeze", produced_results=True)],
    )
    rep = validate(run=run)  # no freeze=
    assert not rep.ok and ViolationReason.MISSING_FREEZE in _reasons(rep)


# R7 — exposure resolves by ENTRY IDENTITY across versions, not by version-scoped hash.
def test_r7_exposure_resolved_by_entry_identity_across_versions():
    a = _entry(vuln=A40, role="blind")
    b = _entry(vuln=B40, role="blind")
    v1 = _cohort("v1", [a, b])
    v2 = _cohort("v2", [a, b], reason="version bump, same entries", parent="v1")  # new content hash
    hist = CohortHistory(versions=[v1, v2])
    ledger = ExposureLedger()
    ledger.record(cohort_content_hash=v1.content_hash, actor="claude", activity="curated")

    # claude curated v1; scoring claude on v2 (same entries, bumped version) must be barred
    run = _run("claude", v2.content_hash, "fz")
    rep = validate(history=hist, run=run, ledger=ledger)
    assert not rep.ok and ViolationReason.CURATOR_IS_SUBJECT in _reasons(rep)

    # a subject that never touched any version sharing an entry identity is fine
    ok = _run("codex", v2.content_hash, "fz")
    assert validate(history=hist, run=ok, ledger=ledger).ok


# R8 — precision draw is ALWAYS verified: pool/k mandatory; no run/freeze → unbound.
def test_r8_precision_pool_k_mandatory_and_binding_required():
    seed = precision_sample_seed("cohortH", "freezeF", "run1")
    pool = [f"p{i:02d}" for i in range(20)]
    sample = sample_confusion_pairs(pool, 3, seed)

    # pool/k are MANDATORY: omitting them is rejected at the type boundary (P1)
    with pytest.raises(ValidationError):
        AdjudicatedPrecision(
            seed=seed,
            sampled_pairs=sample,
            adjudications=[_good_panel(s, "true-positive") for s in sample],
        )

    # a hand-picked favorable subset (not the deterministic draw) with pool/k is rejected
    with pytest.raises(ValidationError):
        AdjudicatedPrecision(
            seed=seed,
            sampled_pairs=["p0", "p1", "p2"],
            pool=pool,
            k=3,
            adjudications=[_good_panel(s, "true-positive") for s in ["p0", "p1", "p2"]],
        )

    # a precision presented with no run/freeze to bind to is PRECISION_SAMPLE_UNBOUND
    ap = AdjudicatedPrecision(
        seed=seed,
        sampled_pairs=sample,
        pool=pool,
        k=3,
        adjudications=[_good_panel(s, "true-positive") for s in sample],
    )
    out = validate(precision=ap)
    assert not out.ok and ViolationReason.PRECISION_SAMPLE_UNBOUND in _reasons(out)


# --------------------------------------------------------------------------- #
# Round-3 Class-1 silent-bug regression floor (A1..A6). Each case dishonestly
# passed validate() (or a constructor) AFTER the R1..R8 seals held; the contract
# must now REJECT it. See scratchpad/contract-fix-spec-r3-crypto.md and
# specs/008-evaluation-contract/threat-model.md.
# --------------------------------------------------------------------------- #


# A1 — the Report binds to the RUN's evaluated cohort, not an easier earlier one.
def test_a1_report_binds_to_runs_evaluated_cohort():
    v1_blinds = [_entry(vuln=x * 40, role="blind") for x in ("a", "b")]
    v2_blinds = v1_blinds + [_entry(vuln=x * 40, role="blind") for x in ("c", "d", "e")]
    v1 = _cohort("v1", v1_blinds)
    v2 = _cohort("v2", v2_blinds, reason="add 3 blind", parent="v1")  # superset: no shrink
    hist = CohortHistory(versions=[v1, v2])
    freeze = FreezeManifest(
        bundle=DetectorBundle(detector_id="d", lockfile_hash="L"), timestamp="2026-07-16T10:00:00Z"
    )
    run = _run("s", v2.content_hash, freeze.freeze_hash)  # the run evaluated v2 (5 blind)

    # a report bound to the EASIER v1 (2/2) while the run evaluated v2 → reject
    liar = Report(
        blind_recall=RecallReport(rediscovered=2, total=2),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        coverage=1.0,
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
        cohort_content_hash=v1.content_hash,
        rediscovered_blind_ids=[v1_blinds[0].identity_hash, v1_blinds[1].identity_hash],
    )
    rep = validate(history=hist, run=run, freeze=freeze, report=liar)
    assert not rep.ok and ViolationReason.REPORT_DENOMINATOR_MISMATCH in _reasons(rep)

    # the honest form: bound to v2 (the run's cohort), numerator a subset of v2's blind
    honest = Report(
        blind_recall=RecallReport(rediscovered=1, total=5),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        coverage=1.0,
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
        cohort_content_hash=v2.content_hash,
        rediscovered_blind_ids=[v2_blinds[0].identity_hash],
    )
    # the honest report binds correctly to the run's evaluated cohort (check_report); full
    # certification is required separately for a numerator-asserting Report (R7-1).
    assert check_report(honest, hist, run=run, freeze=freeze).ok


# A2 — POLICY_REFUSAL cannot launder a produced run to N/A; a produced run needs a Report.
def test_a2_policy_refusal_on_produced_run_and_produced_needs_report():
    a = _entry(vuln=A40, role="blind")
    v1 = _cohort("v1", [a])
    hist = CohortHistory(versions=[v1])
    freeze = FreezeManifest(
        bundle=DetectorBundle(detector_id="d", lockfile_hash="L"), timestamp="2026-07-16T10:00:00Z"
    )
    run = _run("s", v1.content_hash, freeze.freeze_hash)
    run.attempt_evaluation(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E")

    # a produced run + a run-level POLICY_REFUSAL exclusion (scored N/A) → reject
    excl = ExclusionLog(events=[ExclusionEvent(reason=ExclusionReason.POLICY_REFUSAL)])
    rep = validate(history=hist, run=run, freeze=freeze, exclusions=excl)
    assert not rep.ok and ViolationReason.POLICY_REFUSAL_ON_PRODUCED_RUN in _reasons(rep)

    # a produced run that presents NO bound Report → REPORT_UNBOUND
    rep2 = validate(history=hist, run=run, freeze=freeze)
    assert not rep2.ok and ViolationReason.REPORT_UNBOUND in _reasons(rep2)


# A3 — evaluate-once is BLIND-SET scoped: a re-freeze cannot re-roll the same blind cohort.
def test_a3_evaluate_once_is_blind_set_scoped_across_freezes():
    a = _entry(vuln=A40, role="blind")
    v1 = _cohort("v1", [a])
    hist = CohortHistory(versions=[v1])
    f1 = FreezeManifest(
        bundle=DetectorBundle(detector_id="d", lockfile_hash="L", params={"budget": 100}),
        timestamp="2026-07-16T10:00:00Z",
    )
    f2 = FreezeManifest(
        bundle=DetectorBundle(detector_id="d", lockfile_hash="L", params={"budget": 200}),
        timestamp="2026-07-16T10:00:00Z",
    )
    assert f1.freeze_hash != f2.freeze_hash  # a trivial re-freeze mints a new ledger key

    # the first eval under f1 is already recorded WITH its scored blind identities
    prior = EvaluationLedger()
    prior.record(
        cohort_content_hash=v1.content_hash,
        freeze_hash=f1.freeze_hash,
        subject="s",
        blind_ids=[a.identity_hash],
    )
    # the second eval re-freezes (f2) and re-scores the SAME blind cohort+subject → reject
    run2 = _run("s", v1.content_hash, f2.freeze_hash)
    rep = validate(history=hist, run=run2, freeze=f2, prior_evaluations=prior)
    assert not rep.ok and ViolationReason.BLIND_REEVALUATED in _reasons(rep)

    # a disjoint blind cohort (b) for the same subject is fine
    b = _entry(vuln=B40, role="blind")
    v2 = _cohort("v1b", [b])
    hist2 = CohortHistory(versions=[v2])
    run3 = _run("s", v2.content_hash, f2.freeze_hash)
    assert validate(history=hist2, run=run3, freeze=f2, prior_evaluations=prior).ok


# A4 — the first post-freeze attempt is bound to the freeze (freeze B, evaluate B' → reject).
def test_a4_evaluated_artifact_bound_to_freeze():
    a = _entry(vuln=A40, role="blind")
    v1 = _cohort("v1", [a])
    hist = CohortHistory(versions=[v1])
    freeze = FreezeManifest(
        bundle=DetectorBundle(detector_id="d", lockfile_hash="L"), timestamp="2026-07-16T10:00:00Z"
    )
    # a post-freeze attempt whose freeze_hash is NOT the frozen bundle's hash
    run = _run("s", v1.content_hash, freeze.freeze_hash)
    run.attempts.append(
        EvalAttempt(
            phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E", freeze_hash="unrelated"
        )
    )
    rep = validate(history=hist, run=run, freeze=freeze)
    assert not rep.ok and ViolationReason.BAD_FREEZE_BINDING in _reasons(rep)

    # the honest bound form (attempt.freeze_hash == freeze.freeze_hash) does not trip it
    run_ok = _run("s", v1.content_hash, freeze.freeze_hash)
    run_ok.attempt_evaluation(phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E")
    assert ViolationReason.BAD_FREEZE_BINDING not in _reasons(validate(history=hist, run=run_ok, freeze=freeze))


# A5 — validate() mirrors the ordering invariant: no attempt may follow a producing one.
def test_a5_producing_attempt_must_be_terminal_in_validate():
    run = EvaluationRun(
        run_id="r",
        subject="s",
        cohort_content_hash="H",
        freeze_hash="fz",
        attempts=[
            EvalAttempt(
                phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E",
                freeze_hash="fz", results_hash="R1",  # R8-5: producing attempt binds a results_hash
            ),
            EvalAttempt(phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E", freeze_hash="fz"),
        ],
    )
    rep = validate(run=run)
    assert not rep.ok and ViolationReason.BLIND_ACCESS_EXCEEDED in _reasons(rep)


# A6 — the precision pool must be canonical (sorted, unique) with a minimum k.
def test_a6_precision_pool_must_be_canonical_and_min_k():
    seed = precision_sample_seed("cohortH", "freezeF", "run1")
    canonical = _pool(10)

    # a permuted pool (same set, attacker-favorable order) is rejected
    permuted = list(reversed(canonical))
    perm_sample = sample_confusion_pairs(permuted, 3, seed)
    with pytest.raises(ValidationError):
        AdjudicatedPrecision(
            seed=seed,
            sampled_pairs=perm_sample,
            pool=permuted,
            k=3,
            adjudications=[_good_panel(s, "true-positive") for s in perm_sample],
        )

    # a duplicate in the pool is rejected
    dup = canonical + [canonical[0]]
    dup_sample = sample_confusion_pairs(dup, 3, seed)
    with pytest.raises(ValidationError):
        AdjudicatedPrecision(
            seed=seed,
            sampled_pairs=dup_sample,
            pool=dup,
            k=3,
            adjudications=[_good_panel(s, "true-positive") for s in dup_sample],
        )

    # a too-small k relative to |pool| is rejected
    k1_sample = sample_confusion_pairs(canonical, 1, seed)
    with pytest.raises(ValidationError):
        AdjudicatedPrecision(
            seed=seed,
            sampled_pairs=k1_sample,
            pool=canonical,
            k=1,
            adjudications=[_good_panel(s, "true-positive") for s in k1_sample],
        )

    # the canonical pool with k >= 2 passes and draws from sorted(set(pool))
    good = sample_confusion_pairs(canonical, 3, seed)
    assert good == sample_confusion_pairs(list(reversed(canonical)), 3, seed)  # order-independent draw
    ap = AdjudicatedPrecision(
        seed=seed,
        sampled_pairs=good,
        pool=canonical,
        k=3,
        adjudications=[_good_panel(s, "true-positive") for s in good],
    )
    assert ap.precision == 1.0


# --------------------------------------------------------------------------- #
# Round-3 cryptographic-anchoring regression floor (B1..B5). The "omit the
# baseline" class becomes impossible: a certified score is bound to a single
# committed, signed attestation root; validate(strict=...) fails closed unless
# the presented state reproduces every root and the signature verifies.
# --------------------------------------------------------------------------- #


# B1/B2 primitives — append-only + order-independent, deterministic sign/verify.
def test_b1_b2_anchoring_primitives_are_deterministic():
    # leaf_hash: canonical-JSON sha256 — deterministic and membership-sensitive.
    assert leaf_hash({"a": 1, "b": 2}) == leaf_hash({"b": 2, "a": 1})  # key order irrelevant
    assert leaf_hash({"a": 1}) != leaf_hash({"a": 2})
    # chain_root: append-only. Drop / reorder / rewrite ANY entry changes the root.
    base = chain_root(["x", "y", "z"])
    assert base == chain_root(["x", "y", "z"])  # deterministic
    assert base != chain_root(["x", "z"])  # drop
    assert base != chain_root(["x", "z", "y"])  # reorder
    assert base != chain_root(["x", "y", "Z"])  # rewrite
    # merkle_root: order-independent over the SAME set; membership-sensitive.
    assert merkle_root(["a", "b", "c"]) == merkle_root(["c", "b", "a"])
    assert merkle_root(["a", "b", "c"]) != merkle_root(["a", "b"])
    # sign/verify: ed25519 round-trips; a signature made with a non-committed key, or a
    # garbage signature, fails against the committed PUBLIC key (F4).
    root = merkle_root(["a", "b"])
    sig = sign(root, KEY)  # signed with the test PRIVATE seed
    assert verify(root, sig, _TEST_PUB)  # verifies against the matching PUBLIC key
    other_pub = ed25519_public_key(hashlib.sha256(b"a-different-seed").digest())
    assert not verify(root, sig, other_pub)  # a different (non-committed) key fails
    assert not verify(root, "00" * 32, _TEST_PUB)  # a malformed signature fails


# B1 — history_root closes truncation/omission/reorder.
def test_b1_history_root_detects_truncation_and_reorder():
    a = _entry(vuln=A40, role="blind")
    b = _entry(vuln=B40, role="blind")
    c = _entry(vuln=C40, role="blind")
    v1 = _cohort("v1", [a, b])
    v2 = _cohort("v2", [a, b, c], reason="add c", parent="v1")
    full = CohortHistory(versions=[v1, v2])
    assert full.history_root != CohortHistory(versions=[v1]).history_root  # truncation
    assert full.history_root != CohortHistory(versions=[v2, v1]).history_root  # reorder


# B2 — each ledger/log exposes a chain root that a rewrite/omission breaks.
def test_b2_ledger_and_log_roots_detect_rewrite():
    excl1 = ExclusionLog(events=[ExclusionEvent(reason=ExclusionReason.ALIAS_DUPE, entry_identity="x")])
    excl2 = ExclusionLog(events=[ExclusionEvent(reason=ExclusionReason.ALIAS_DUPE, entry_identity="y")])
    assert excl1.root != excl2.root
    assert excl1.root == ExclusionLog(events=list(excl1.events)).root  # deterministic

    led1 = ExposureLedger()
    led1.record(cohort_content_hash="H", actor="a", activity="curated")
    led2 = ExposureLedger()
    led2.record(cohort_content_hash="H", actor="b", activity="curated")
    assert led1.root != led2.root

    ev1 = EvaluationLedger()
    ev1.record(cohort_content_hash="H", freeze_hash="F", subject="s", blind_ids=["i"])
    ev2 = EvaluationLedger()
    ev2.record(cohort_content_hash="H", freeze_hash="F", subject="s", blind_ids=["j"])
    assert ev1.root != ev2.root

    ach1 = AchievabilityLog(
        freeze_timestamp="2026-07-16T12:00:00Z",
        predictions=[AchievabilityPrediction(entry_identity="E1", predicted_achievable=False, registered_at="2026-07-16T09:00:00Z")],
    )
    ach2 = AchievabilityLog(
        freeze_timestamp="2026-07-16T12:00:00Z",
        predictions=[AchievabilityPrediction(entry_identity="E2", predicted_achievable=False, registered_at="2026-07-16T09:00:00Z")],
    )
    assert ach1.root != ach2.root


# B3 — exposure resolves by entry identity (no old version needed); unresolvable == HARD FAIL.
def test_b3_exposure_by_curated_entry_ids_and_unresolvable_hard_fail():
    a = _entry(vuln=A40, role="blind")
    b = _entry(vuln=B40, role="blind")
    scored = _cohort("v1", [a, b])
    hist = CohortHistory(versions=[scored])

    # the subject curated entry 'a' under an OLD cohort version that is NOT presented;
    # recorded by IDENTITY, exposure still bars it — no old version needed
    ledger = ExposureLedger()
    ledger.record(
        cohort_content_hash="old-cohort-not-presented",
        actor="claude",
        activity="curated",
        curated_entry_ids=[a.identity_hash],
    )
    run = _run("claude", scored.content_hash, "fz")
    rep = validate(history=hist, run=run, ledger=ledger)
    assert not rep.ok and ViolationReason.CURATOR_IS_SUBJECT in _reasons(rep)

    # an UNRESOLVABLE record whose actor == subject is a HARD FAILURE (fail closed)
    ledger2 = ExposureLedger()
    ledger2.record(cohort_content_hash="unresolvable", actor="claude", activity="curated")
    run2 = _run("claude", scored.content_hash, "fz")
    rep2 = validate(history=hist, run=run2, ledger=ledger2)
    assert not rep2.ok and ViolationReason.CURATOR_IS_SUBJECT in _reasons(rep2)

    # a subject whose curated identities are disjoint from the scored blind set is fine
    ledger3 = ExposureLedger()
    ledger3.record(
        cohort_content_hash="old", actor="codex", activity="curated", curated_entry_ids=["some-other-identity"]
    )
    run3 = _run("codex", scored.content_hash, "fz")
    assert validate(history=hist, run=run3, ledger=ledger3).ok


# B4 — the precision pool must reproduce the committed freeze pool_root.
def test_b4_precision_pool_must_reproduce_committed_pool_root():
    pool = _pool(20)
    committed = pool_root_of(pool)
    bundle = DetectorBundle(detector_id="d", lockfile_hash="L", pool_root=committed)
    freeze = FreezeManifest(bundle=bundle, timestamp="2026-07-16T10:00:00Z")
    rid = _canonical_run_id("CH", freeze.freeze_hash, "s")
    run = EvaluationRun(run_id=rid, subject="s", cohort_content_hash="CH", freeze_hash=freeze.freeze_hash)
    seed = precision_sample_seed("CH", freeze.freeze_hash, rid)

    def mk(p):
        s = sample_confusion_pairs(p, 3, seed)
        return AdjudicatedPrecision(
            seed=seed,
            sampled_pairs=s,
            pool=p,
            k=3,
            cohort_hash="CH",
            freeze_hash=freeze.freeze_hash,
            run_id=rid,
            adjudications=[_good_panel(x, "true-positive") for x in s],
        )

    # the honest pool reproduces the committed root
    assert validate(run=run, freeze=freeze, precision=mk(pool)).ok
    # a swapped (canonical but different-membership) pool does NOT reproduce it → reject
    swapped = [f"q{i:02d}" for i in range(20)]
    rep = validate(run=run, freeze=freeze, precision=mk(swapped))
    assert not rep.ok and ViolationReason.PRECISION_SAMPLE_UNBOUND in _reasons(rep)


# --------------------------------------------------------------------------- #
# Round-3 cryptographic-anchoring + Round-4/5 certify regression floor. Round-5
# closes the round-4 bypasses that were OPT-IN / caller-supplied: ``validate`` RUNS
# each verification itself and LOADS every trusted root / key / detector from
# COMMITTED, git-tracked state (monkeypatched here with hermetic fixtures via
# :func:`_install_committed`) — never a caller argument the scored party could forge.
# The "omit the baseline" class becomes impossible: a certified score is bound to a
# single committed, signed attestation root and the committed monotonic genesis chain.
# --------------------------------------------------------------------------- #

# Distinct fake-corpus keys for the two honest blind entries. A ``FLAG`` marker on a
# line makes the fake detector emit a finding there; the line-precise rule then also
# requires the flagged line's own text to contain the sink probe.
_A_VULN, _A_PATCHED = "va" + "0" * 38, "pa" + "0" * 38
_B_VULN, _B_PATCHED = "vb" + "0" * 38, "pb" + "0" * 38


def _fake_scan(source, uri):
    """A marker-driven fake detector: emit a SARIF-ish finding for each line whose text
    contains ``FLAG``. It PARSES the string; it never executes it."""
    return [
        {"locations": [{"physicalLocation": {"region": {"startLine": i}}}]}
        for i, line in enumerate(source.splitlines(), 1)
        if "FLAG" in line
    ]


def _default_files():
    """Fake corpus where blind entry 'a' is REDISCOVERED (flagged in vuln, not in patched)
    and 'b' is NOT (flagged in both trees)."""
    return {
        (_A_VULN, "a.py"): "def f():\n    sinka(x)  # FLAG\n",
        (_A_PATCHED, "a.py"): "def f():\n    guard()\n    sinka(x)\n",
        (_B_VULN, "b.py"): "def g():\n    sinkb(x)  # FLAG\n",
        (_B_PATCHED, "b.py"): "def g():\n    sinkb(x)  # FLAG\n",
    }


def _files_rediscover_b():
    """Fake corpus where 'b' is the rediscovery and 'a' is not — the committed detector
    confirms a DIFFERENT entry than the honest report claims."""
    return {
        (_A_VULN, "a.py"): "def f():\n    sinka(x)  # FLAG\n",
        (_A_PATCHED, "a.py"): "def f():\n    sinka(x)  # FLAG\n",  # flagged in both -> not rediscovered
        (_B_VULN, "b.py"): "def g():\n    sinkb(x)  # FLAG\n",
        (_B_PATCHED, "b.py"): "def g():\n    sinkb(x)\n",  # rediscovered
    }


def _install_committed(
    monkeypatch,
    *,
    presented_history,
    files,
    chain_from=ATT_CHAIN_BASE,
    prior_history_root=None,
    detector_id="d",
    scan=None,
    verify_key=_TEST_PUB,
    evaluator_id=EVALUATOR_ID,
    evaluation_root=None,
    exposure_root=None,
    adjudicator_roster=None,
    module_hashes=None,
):
    """Install the COMMITTED anchor state + committed detector/fetcher so a strict certify
    RUNS its verifications hermetically from committed state (R5-1..R5-4, F1, F2, F4, R10-1/2/6).
    ``validate`` resolves the verify-key (ed25519 PUBLIC key), evaluator id, prior history
    root, committed evaluation-ledger root, committed exposure-ledger root (R10-2), adjudicator
    roster (R10-6), and chain root from ``contract.load_committed_genesis_state`` and the
    detector / fetcher / module-hash from ``verifier``; all are monkeypatched here.
    ``prior_history_root`` defaults to the presented history's full root (a valid append-only
    extension by zero); ``evaluation_root`` (F2) and ``exposure_root`` (R10-2) default to the
    reproducible empty-ledger root."""
    phr = prior_history_root if prior_history_root is not None else presented_history.history_root
    state = contract.CommittedGenesisState(
        genesis_history_root=phr,
        latest_history_root=phr,
        latest_attestation_root=chain_from,
        latest_evaluation_root=evaluation_root if evaluation_root is not None else contract._EMPTY_ROOT,
        latest_exposure_root=exposure_root if exposure_root is not None else contract._EMPTY_ROOT,
        evaluator_id=evaluator_id,
        verify_key=verify_key,
        adjudicator_roster=adjudicator_roster if adjudicator_roster is not None else dict(_ADJ_ROSTER),
    )
    monkeypatch.setattr(contract, "load_committed_genesis_state", lambda *a, **k: state)

    def _fetch(repo, ref, path):
        return files[(ref, path)]

    monkeypatch.setattr(verifier, "FETCH_FN", _fetch)
    monkeypatch.setitem(verifier.DETECTOR_REGISTRY, detector_id, lambda: (scan or _fake_scan))
    # R10-1: the committed loaded-module hash the certify path recomputes and binds against the
    # frozen ``module_hashes``. Defaults to the fake module hash the certify builders commit.
    _mh = module_hashes if module_hashes is not None else dict(_FAKE_MODULE_HASHES)
    monkeypatch.setitem(verifier.DETECTOR_MODULE_HASHES, detector_id, lambda: _mh)


def _anchored(
    monkeypatch,
    *,
    prior_attestation_root=None,
    files=None,
    scan=None,
    chain_from=ATT_CHAIN_BASE,
    evln=None,
    committed_evaluation_root=None,
    regression=None,
    cherry_pick_sample=False,
):
    """A fully honest, anchored evaluation bundle plus its signed Attestation, with the
    COMMITTED state + committed detector/fetcher installed to match it. Reused by the B5
    fail-closed cases and the Round-4/5/7 certify cases (each tampers exactly one thing). The
    freeze commits ``committed_k`` (R5-3/P1d), the certify binds a real
    ``AdjudicatedPrecision`` (P1c), the chain roots in the committed latest attestation root
    (R5-2/PART3, overridable via ``prior_attestation_root``), and the numerator is
    RECOMPUTED by ``validate`` running the committed detector (R5-1/PART2).

    R7-2: every certified secondary numeric is bound. ``coverage`` is forbidden (None on a
    certified report); ``patched_alert_density`` and ``fixed_cohort_recall`` are set to the
    values ``validate`` itself recomputes from the committed detector, so the honest bundle
    passes and any tamper fails closed. ``regression`` is an optional list of
    ``(CohortEntry, files_fragment)`` REGRESSION entries added to the head cohort so a
    non-empty ``fixed_cohort_recall`` can be exercised."""
    base_files = {**(files or _default_files()), **_reg_files_of(regression)}
    a_entry = _entry(vuln=_A_VULN, patched=_A_PATCHED, paths=["a.py"], probe="sinka(x)", role="blind", files=base_files)
    b_entry = _entry(vuln=_B_VULN, patched=_B_PATCHED, paths=["b.py"], probe="sinkb(x)", role="blind", files=base_files)
    blinds = [a_entry, b_entry]
    reg_entries = [e for e, _ in (regression or [])]
    reg_files = _reg_files_of(regression)
    v1 = _cohort("v1", blinds + reg_entries)
    hist = CohortHistory(versions=[v1])
    pool = _pool(12)
    committed_k = 3
    # R8-2/R9-1: draw + commit the precision sample at freeze time. The CANONICAL sample is derived
    # from committed, non-grindable state (cohort identity + committed pool_root + k). When
    # ``cherry_pick_sample`` is set the builder instead commits an OPERATOR-CHOSEN draw (a different
    # seed) whose sample_root is still committed + reproduced by the presented precision — R8-2's
    # reproduce-the-committed-root check passes, but R9-1's canonical recompute rejects it.
    if cherry_pick_sample:
        sample_seed = precision_sample_seed(v1.content_hash, pool_root_of(pool), "cherry-picked-salt")
        sampled = sample_confusion_pairs(pool, committed_k, sample_seed)
        committed_sample_root = sample_root_of(sampled)
    else:
        sample_seed, sampled, committed_sample_root = _committed_sample(pool, committed_k, v1.content_hash)
    bundle = DetectorBundle(
        detector_id="d", lockfile_hash="L", pool_root=pool_root_of(pool), committed_k=committed_k,
        committed_sample_root=committed_sample_root, module_hashes=dict(_FAKE_MODULE_HASHES),  # R10-1
    )
    freeze = FreezeManifest(bundle=bundle, timestamp="2026-07-16T10:00:00Z")
    run = _run("codex", v1.content_hash, freeze.freeze_hash)
    # R8-5: a producing attempt carries a non-empty results_hash binding produced_results.
    run.attempt_evaluation(
        phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E", results_hash="R1"
    )
    report = Report(
        blind_recall=RecallReport(rediscovered=1, total=2),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        coverage=None,  # R7-2: forbidden on a certified report
        patched_alert_density=0.0,  # recomputed below from the committed detector
        adjudicated_precision=1.0,
        cohort_content_hash=v1.content_hash,
        rediscovered_blind_ids=[a_entry.identity_hash],
    )
    precision = AdjudicatedPrecision(
        seed=sample_seed,
        sampled_pairs=sampled,
        pool=pool,
        k=committed_k,
        adjudications=[_good_panel(p, "true-positive") for p in sampled],
    )
    ledger = ExposureLedger()
    ledger.record(
        cohort_content_hash=v1.content_hash,
        actor="claude",  # a curator that is NOT the subject (codex)
        activity="curated",
        curated_entry_ids=[e.identity_hash for e in blinds],
    )
    excl = ExclusionLog(
        events=[ExclusionEvent(reason=ExclusionReason.ALIAS_DUPE, entry_identity="z", from_version="v0", to_version="v1")]
    )
    evln = EvaluationLedger() if evln is None else evln
    _install_committed(
        monkeypatch, presented_history=hist, files={**(files or _default_files()), **reg_files},
        chain_from=chain_from, scan=scan, evaluation_root=committed_evaluation_root,
    )
    # R7-2: set the certified secondary numerics to exactly what validate() recomputes from the
    # committed detector, so the honest bundle passes (a tamper in a test then fails closed).
    fc_rediscovered, fc_total = verifier.recompute_fixed_cohort_recall(reg_entries, detector_id="d")
    density = verifier.recompute_patched_alert_density(blinds, detector_id="d")
    report = report.model_copy(
        update={
            "fixed_cohort_recall": RecallReport(rediscovered=fc_rediscovered, total=fc_total),
            "patched_alert_density": density,
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
        prior_attestation_root=prior_attestation_root if prior_attestation_root is not None else chain_from,
        exclusions=excl,
        ledger=ledger,
        evaluation_ledger=evln,
        achievability=None,
    )
    return dict(
        hist=hist, freeze=freeze, run=run, report=report, precision=precision, ledger=ledger,
        excl=excl, evln=evln, blinds=blinds, reg_entries=reg_entries, att=att,
    )


def _certify(a, **overrides):
    kw = dict(
        history=a["hist"],
        freeze=a["freeze"],
        run=a["run"],
        report=a["report"],
        precision=a["precision"],
        exclusions=a["excl"],
        ledger=a["ledger"],
        prior_evaluations=a["evln"],
        attestation=a["att"],
        strict=True,
    )
    kw.update(overrides)
    return validate(**kw)


# B5 — a fully honest, signed attestation is ACCEPTED under strict certification.
def test_b5_honest_signed_attestation_accepted(monkeypatch):
    a = _anchored(monkeypatch)
    rep = _certify(a)
    assert rep.ok, _reasons(rep)


# B5 — a forged signature is rejected (verified against the COMMITTED evaluator key).
def test_b5_forged_signature_rejected(monkeypatch):
    a = _anchored(monkeypatch)
    forged = a["att"].model_copy(update={"signature": "00" * 32})
    rep = _certify(a, attestation=forged)
    assert not rep.ok and ViolationReason.ATTESTATION_INVALID in _reasons(rep)


# B5 — a tampered/omitted history version (root mismatch) is rejected.
def test_b5_tampered_history_root_mismatch(monkeypatch):
    a = _anchored(monkeypatch)
    extra = _entry(vuln=C40, role="blind")
    v2 = _cohort("v2", a["blinds"] + [extra], reason="append not attested", parent="v1")
    tampered = CohortHistory(versions=[a["hist"].versions[0], v2])
    rep = _certify(a, history=tampered)
    assert not rep.ok and ViolationReason.ATTESTATION_MISMATCH in _reasons(rep)


# B5 — a rewritten ledger entry (chain-root mismatch) is rejected.
def test_b5_rewritten_ledger_entry_root_mismatch(monkeypatch):
    a = _anchored(monkeypatch)
    rewritten = ExclusionLog(
        events=[
            ExclusionEvent(
                reason=ExclusionReason.ALIAS_DUPE,
                entry_identity="z",
                from_version="v0",
                to_version="v1",
                detail="TAMPERED",
            )
        ]
    )
    rep = _certify(a, exclusions=rewritten)
    assert not rep.ok and ViolationReason.ATTESTATION_MISMATCH in _reasons(rep)


# B5 — a swapped pool (pool_root mismatch) is rejected.
def test_b5_swapped_pool_root_mismatch(monkeypatch):
    a = _anchored(monkeypatch)
    swapped_bundle = a["freeze"].bundle.model_copy(update={"pool_root": pool_root_of(_pool(20))})
    swapped_freeze = FreezeManifest(bundle=swapped_bundle, timestamp=a["freeze"].timestamp)
    rep = _certify(a, freeze=swapped_freeze)
    assert not rep.ok and ViolationReason.ATTESTATION_MISMATCH in _reasons(rep)


# B5 — an attestation that references a component not presented is rejected (fail closed).
def test_b5_missing_component_incomplete(monkeypatch):
    a = _anchored(monkeypatch)
    rep = _certify(a, history=None)
    assert not rep.ok and ViolationReason.ATTESTATION_INCOMPLETE in _reasons(rep)


# B5 — a certify path with NO attestation is UNANCHORED (fail closed).
def test_b5_certify_without_attestation_unanchored(monkeypatch):
    a = _anchored(monkeypatch)
    rep = validate(
        history=a["hist"],
        freeze=a["freeze"],
        run=a["run"],
        report=a["report"],
        exclusions=a["excl"],
        ledger=a["ledger"],
        prior_evaluations=a["evln"],
        strict=True,  # no attestation (the verify-key is committed, not a caller arg)
    )
    assert not rep.ok and ViolationReason.UNANCHORED in _reasons(rep)


# --------------------------------------------------------------------------- #
# Round-5 fail-closed certify seals — verifications RUN from committed state, and
# every completeness input a strict certify needs is MANDATORY (R5-1..R5-6).
# --------------------------------------------------------------------------- #


# R5-1 / PART 2 — the certify path RECOMPUTES the numerator by RUNNING the committed
# detector (resolved from the frozen detector_id) on the real pinned code; no caller set.
def test_part2_numerator_must_match_the_recompute(monkeypatch):
    a = _anchored(monkeypatch)  # default corpus: only entry 'a' is rediscovered
    # the committed detector re-run confirms exactly the claim -> certifies
    assert _certify(a).ok, _reasons(_certify(a))

    # the committed detector produces NOTHING on the real code (claim unconfirmed) -> reject
    a_none = _anchored(monkeypatch, scan=lambda source, uri: [])
    rep = _certify(a_none)
    assert not rep.ok and ViolationReason.NUMERATOR_UNVERIFIED in _reasons(rep)

    # the committed detector confirms a DIFFERENT entry than claimed -> reject
    a_other = _anchored(monkeypatch, files=_files_rediscover_b())
    rep2 = _certify(a_other)
    assert not rep2.ok and ViolationReason.NUMERATOR_UNVERIFIED in _reasons(rep2)


# R5-1 — the recompute is NOT a caller argument: `validate` no longer accepts one.
def test_r5_1_validate_rejects_a_caller_supplied_recompute(monkeypatch):
    a = _anchored(monkeypatch)
    with pytest.raises(TypeError):
        validate(
            history=a["hist"], freeze=a["freeze"], run=a["run"], report=a["report"],
            precision=a["precision"], exclusions=a["excl"], ledger=a["ledger"],
            prior_evaluations=a["evln"], attestation=a["att"], strict=True,
            recomputed_rediscovered={a["blinds"][0].identity_hash},  # no longer a parameter
        )


# R5-3 — the mandatory certify bindings fail closed when omitted (no opt-in skips).
def test_r5_3_certify_bindings_are_mandatory(monkeypatch):
    a = _anchored(monkeypatch)
    # a curator==subject scenario: with the ledger PRESENT the exposure check runs and bars it
    subj_ledger = ExposureLedger()
    subj_ledger.record(cohort_content_hash=a["run"].cohort_content_hash, actor="codex", activity="curated")
    rep_self = _certify(a, ledger=subj_ledger)
    assert not rep_self.ok and ViolationReason.CURATOR_IS_SUBJECT in _reasons(rep_self)

    # omitting the exposure ledger fails closed (curator != subject becomes unverifiable)
    rep_no_ledger = _certify(a, ledger=None)
    assert not rep_no_ledger.ok and ViolationReason.MISSING_LEDGER in _reasons(rep_no_ledger)

    # omitting the prior_evaluations ledger fails closed (evaluate-once unverifiable)
    rep_no_evln = _certify(a, prior_evaluations=None)
    assert not rep_no_evln.ok and ViolationReason.MISSING_LEDGER in _reasons(rep_no_evln)

    # an inert (empty) committed pool_root fails closed
    inert_pool = a["freeze"].bundle.model_copy(update={"pool_root": ""})
    inert_freeze = FreezeManifest(bundle=inert_pool, timestamp=a["freeze"].timestamp)
    rep_pool = _certify(a, freeze=inert_freeze)
    assert not rep_pool.ok and ViolationReason.PRECISION_SAMPLE_UNBOUND in _reasons(rep_pool)

    # an inert committed_k (0) fails closed
    inert_k = a["freeze"].bundle.model_copy(update={"committed_k": 0})
    inert_k_freeze = FreezeManifest(bundle=inert_k, timestamp=a["freeze"].timestamp)
    rep_k = _certify(a, freeze=inert_k_freeze)
    assert not rep_k.ok and ViolationReason.PRECISION_SAMPLE_UNBOUND in _reasons(rep_k)


# R5-4 — the verify-key + evaluator id come from COMMITTED state. A subject-minted key,
# signed and passed by the subject, cannot certify (validate uses the committed key).
def test_r5_4_verify_key_and_evaluator_from_committed_state(monkeypatch):
    a = _anchored(monkeypatch)
    # a 32-byte ed25519 seed the SUBJECT mints — a valid key, but NOT the committed one
    subject_key = hashlib.sha256(b"subject-minted-key-attacker-controls/v1").digest()
    self_signed = build_attestation(
        history=a["hist"], freeze=a["freeze"], run=a["run"], report=a["report"],
        evaluator_id=EVALUATOR_ID, attested_at="2026-07-16T12:00:00Z", key=subject_key,
        prior_attestation_root=ATT_CHAIN_BASE,
        exclusions=a["excl"], ledger=a["ledger"], evaluation_ledger=a["evln"], achievability=None,
    )
    rep = _certify(a, attestation=self_signed)
    assert not rep.ok and ViolationReason.ATTESTATION_INVALID in _reasons(rep)

    # an attestation minted by an evaluator id that is not the committed one is rejected
    wrong_evaluator = build_attestation(
        history=a["hist"], freeze=a["freeze"], run=a["run"], report=a["report"],
        evaluator_id="some-other-evaluator", attested_at="2026-07-16T12:00:00Z", key=KEY,
        prior_attestation_root=ATT_CHAIN_BASE,
        exclusions=a["excl"], ledger=a["ledger"], evaluation_ledger=a["evln"], achievability=None,
    )
    rep2 = _certify(a, attestation=wrong_evaluator)
    assert not rep2.ok and ViolationReason.ATTESTATION_INVALID in _reasons(rep2)


# R5-5 — the freeze binds the PRODUCING attempt: a producing attempt with a forged
# freeze_hash is caught even when the first attempt is honestly bound.
def test_r5_5_freeze_binds_the_producing_attempt(monkeypatch):
    a = _entry(vuln=A40, role="blind")
    v1 = _cohort("v1", [a])
    hist = CohortHistory(versions=[v1])
    freeze = FreezeManifest(bundle=DetectorBundle(detector_id="d", lockfile_hash="L"), timestamp="2026-07-16T10:00:00Z")
    run = _run("s", v1.content_hash, freeze.freeze_hash)
    # a non-producing first attempt honestly bound, then a PRODUCING attempt with a forged hash
    run.attempts.append(
        EvalAttempt(phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E", freeze_hash=freeze.freeze_hash)
    )
    run.attempts.append(
        EvalAttempt(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E", freeze_hash="forged")
    )
    rep = validate(history=hist, run=run, freeze=freeze)
    assert not rep.ok and ViolationReason.BAD_FREEZE_BINDING in _reasons(rep)


# R5-6 — a certified report must not carry a free achievable_recall diagnostic.
def test_r5_6_certified_report_forbids_achievable_recall(monkeypatch):
    a = _anchored(monkeypatch)
    diag = a["report"].model_copy(update={"achievable_recall": 0.9})
    att = build_attestation(
        history=a["hist"], freeze=a["freeze"], run=a["run"], report=diag,
        evaluator_id=EVALUATOR_ID, attested_at="2026-07-16T12:00:00Z", key=KEY,
        prior_attestation_root=ATT_CHAIN_BASE,
        exclusions=a["excl"], ledger=a["ledger"], evaluation_ledger=a["evln"], achievability=None,
    )
    rep = _certify(a, report=diag, attestation=att)
    assert not rep.ok and ViolationReason.ACHIEVABLE_UNBOUND in _reasons(rep)


# R5-2 — advance_committed_root persists the advancing roots; genesis stays immutable.
def test_r5_2_advance_committed_root_persists(tmp_path):
    import json as _json

    p = tmp_path / "genesis_root.json"
    p.write_text(
        _json.dumps(
            {
                "genesis_history_root": "aa" * 32,
                "evaluator": {"id": EVALUATOR_ID, "verify_key_pub_hex": _TEST_PUB.hex()},
            }
        ),
        encoding="utf-8",
    )
    # before any advance: latest defaults to the genesis / attestation-chain / empty-eval base
    before = contract.load_committed_genesis_state(p)
    assert before.latest_history_root == "aa" * 32
    assert before.latest_attestation_root == contract._ATTESTATION_CHAIN_GENESIS
    assert before.latest_evaluation_root == contract._EMPTY_ROOT  # F2: empty-ledger baseline
    assert before.latest_exposure_root == contract._EMPTY_ROOT  # R10-2: empty-ledger baseline

    contract.advance_committed_root(
        history_root="bb" * 32, attestation_root="cc" * 32, evaluation_root="dd" * 32,
        exposure_root="ee" * 32, path=p,
    )
    after = contract.load_committed_genesis_state(p)
    assert after.genesis_history_root == "aa" * 32  # immutable
    assert after.latest_history_root == "bb" * 32  # advanced
    assert after.latest_attestation_root == "cc" * 32
    assert after.latest_evaluation_root == "dd" * 32  # F2: the eval root advances too
    assert after.latest_exposure_root == "ee" * 32  # R10-2: the exposure root advances too


# --------------------------------------------------------------------------- #
# Round-4 out-of-contract verification (P1a..P1e + PART 3), now RUN from committed
# state per Round-5. The certify path RECOMPUTES the numerator (test_part2), CHAINS
# attestations to the committed monotonic genesis, and demands a producing eval, a
# bound precision, a committed k, and a certifier that is not the subject.
# --------------------------------------------------------------------------- #


def _chain_certify(
    monkeypatch, presented_versions, scored_cohort, *, rediscovered_entries, files, prior_history,
    chain_from=ATT_CHAIN_BASE, prior_attestation_root=None,
):
    """A fully honest, anchored strict-certify whose run/report/attestation bind to
    ``scored_cohort`` and whose presented history is ``presented_versions``, validated
    against a ``prior_history`` COMMITTED baseline (the chain predecessor loaded from
    committed state, never the caller)."""
    hist = CohortHistory(versions=presented_versions)
    pool = _pool(12)
    committed_k = 3
    # R8-2: commit the precision sample_root in the frozen bundle (decoupled from freeze_hash).
    sample_seed, sampled, committed_sample_root = _committed_sample(pool, committed_k, scored_cohort.content_hash)
    bundle = DetectorBundle(
        detector_id="d", lockfile_hash="L", pool_root=pool_root_of(pool), committed_k=committed_k,
        committed_sample_root=committed_sample_root, module_hashes=dict(_FAKE_MODULE_HASHES),  # R10-1
    )
    freeze = FreezeManifest(bundle=bundle, timestamp="2026-07-16T10:00:00Z")
    run = _run("codex", scored_cohort.content_hash, freeze.freeze_hash)
    run.attempt_evaluation(
        phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E", results_hash="R1"
    )
    scored_blind = scored_cohort.by_role(Role.BLIND)
    report = Report(
        blind_recall=RecallReport(rediscovered=len(rediscovered_entries), total=len(scored_blind)),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        coverage=None,  # R7-2: forbidden on a certified report
        patched_alert_density=0.0,  # recomputed below from the committed detector
        adjudicated_precision=1.0,
        cohort_content_hash=scored_cohort.content_hash,
        rediscovered_blind_ids=[e.identity_hash for e in rediscovered_entries],
    )
    precision = AdjudicatedPrecision(
        seed=sample_seed, sampled_pairs=sampled, pool=pool, k=committed_k,
        adjudications=[_good_panel(p, "true-positive") for p in sampled],
    )
    ledger = ExposureLedger()
    ledger.record(
        cohort_content_hash=scored_cohort.content_hash, actor="claude", activity="curated",
        curated_entry_ids=[e.identity_hash for e in scored_blind],
    )
    evln = EvaluationLedger()
    _install_committed(
        monkeypatch, presented_history=hist, files=files, chain_from=chain_from,
        prior_history_root=prior_history.history_root,
    )
    # R7-2: bind the certified secondary numerics to what validate() recomputes. The scored
    # head cohort here holds only BLIND entries, so fixed_cohort_recall recomputes to (0, 0);
    # density is the committed detector's patched-tree flag density over the blind set.
    report = report.model_copy(
        update={
            "patched_alert_density": verifier.recompute_patched_alert_density(
                scored_blind, detector_id="d"
            ),
        }
    )
    att = build_attestation(
        history=hist, freeze=freeze, run=run, report=report,
        evaluator_id=EVALUATOR_ID, attested_at="2026-07-16T12:00:00Z", key=KEY,
        prior_attestation_root=prior_attestation_root if prior_attestation_root is not None else chain_from,
        ledger=ledger, evaluation_ledger=evln,
    )
    return validate(
        history=hist, freeze=freeze, run=run, report=report, precision=precision,
        ledger=ledger, prior_evaluations=evln, attestation=att, strict=True,
    )


def _rc_entry(tag, *, rediscovered):
    """A blind entry with distinct fake-corpus keys, plus its files fragment. When
    ``rediscovered`` the patched file drops the FLAG (rediscovered); else it keeps it."""
    vuln = f"v{tag}" + "0" * (40 - len(f"v{tag}"))
    patched = f"p{tag}" + "0" * (40 - len(f"p{tag}"))
    path, probe = f"{tag}.py", f"sink{tag}(x)"
    frag = {
        (vuln, path): f"def fn():\n    {probe}  # FLAG\n",
        (patched, path): (
            f"def fn():\n    guard()\n    {probe}\n" if rediscovered else f"def fn():\n    {probe}  # FLAG\n"
        ),
    }
    entry = _entry(vuln=vuln, patched=patched, paths=[path], probe=probe, role="blind", files=frag)
    return entry, frag


# P1a / R5-2 — the certification history must append-only-EXTEND the COMMITTED prior root.
def test_p1a_certify_history_must_extend_prior_committed_root(monkeypatch):
    ea, fa = _rc_entry("a", rediscovered=True)
    eb, fb = _rc_entry("b", rediscovered=False)
    ec, fc = _rc_entry("c", rediscovered=False)
    files = {**fa, **fb, **fc}
    v1 = _cohort("v1", [ea, eb])
    v2 = _cohort("v2", [ea, eb, ec], reason="append c", parent="v1")  # superset extension
    prior = CohortHistory(versions=[v1])

    # honest append-only extension: presented [v1, v2] extends the committed prior [v1]
    ok = _chain_certify(monkeypatch, [v1, v2], v2, rediscovered_entries=[ea], files=files, prior_history=prior)
    assert ok.ok, _reasons(ok)

    # a from-storage rebuild that DROPS v1 and re-anchors on a fresh single version whose
    # content does not reproduce the committed prior root is rejected
    v2_solo = _cohort("v2", [ea, eb], reason="rebuild dropping v1", parent="v1")
    bad = _chain_certify(monkeypatch, [v2_solo], v2_solo, rediscovered_entries=[ea], files=files, prior_history=prior)
    assert not bad.ok and ViolationReason.ATTESTATION_NOT_EXTENDING in _reasons(bad)


# P1b — certification requires exactly one producing post-freeze evaluation.
def test_p1b_certify_requires_a_producing_evaluation(monkeypatch):
    a = _anchored(monkeypatch)
    ch = a["hist"].versions[0].content_hash
    # a run with the SAME canonical run_id but NO producing evaluation (attempts == [])
    no_eval = _run("codex", ch, a["freeze"].freeze_hash)
    assert no_eval.semantic_evaluation_count == 0
    rep = _certify(a, run=no_eval)
    assert not rep.ok and ViolationReason.CERTIFY_WITHOUT_EVALUATION in _reasons(rep)
    # the honest bundle (one producing evaluation) certifies
    assert _certify(a).ok


# P1c — the headline precision must be bound to a real AdjudicatedPrecision.
def test_p1c_certify_requires_bound_adjudicated_precision(monkeypatch):
    a = _anchored(monkeypatch)
    # (1) a free adjudicated_precision float with NO bound AdjudicatedPrecision
    rep = _certify(a, precision=None)
    assert not rep.ok and ViolationReason.PRECISION_UNBOUND in _reasons(rep)

    # (2) a bound precision whose value disagrees with the report's headline (1.0)
    ch = a["hist"].versions[0].content_hash
    fz = a["freeze"].freeze_hash
    rid = a["run"].run_id
    pool = _pool(12)
    seed = precision_sample_seed(ch, fz, rid)
    sampled = sample_confusion_pairs(pool, 3, seed)
    low = AdjudicatedPrecision(
        seed=seed, sampled_pairs=sampled, pool=pool, k=3,
        cohort_hash=ch, freeze_hash=fz, run_id=rid,
        adjudications=[
            _good_panel(sampled[0], "true-positive"),
            _good_panel(sampled[1], "true-positive"),
            _good_panel(sampled[2], "ambiguous"),  # drags precision to 2/3
        ],
    )
    assert low.precision == 0.667  # 2/3, rounded to 3 decimals; != the report's 1.0
    rep2 = _certify(a, precision=low)
    assert not rep2.ok and ViolationReason.PRECISION_UNBOUND in _reasons(rep2)


# P1d — the precision sample size k must equal the k committed inside the freeze.
def test_p1d_precision_k_must_equal_committed_freeze_k(monkeypatch):
    a = _anchored(monkeypatch)  # committed_k == 3
    ch = a["hist"].versions[0].content_hash
    fz = a["freeze"].freeze_hash
    rid = a["run"].run_id
    pool = _pool(12)
    seed = precision_sample_seed(ch, fz, rid)
    # a valid all-TP precision (value 1.0 matches the report) but k == 4 != committed 3
    sampled4 = sample_confusion_pairs(pool, 4, seed)
    p4 = AdjudicatedPrecision(
        seed=seed, sampled_pairs=sampled4, pool=pool, k=4,
        cohort_hash=ch, freeze_hash=fz, run_id=rid,
        adjudications=[_good_panel(x, "true-positive") for x in sampled4],
    )
    assert p4.precision == 1.0
    rep = _certify(a, precision=p4)
    assert not rep.ok and ViolationReason.PRECISION_SAMPLE_UNBOUND in _reasons(rep)
    # the committed k passes
    assert _certify(a).ok


# P1e — the certifier (attestation.evaluator_id) must not be the scored subject.
def test_p1e_certifier_must_not_be_the_scored_subject(monkeypatch):
    a = _anchored(monkeypatch)
    self_att = build_attestation(
        history=a["hist"], freeze=a["freeze"], run=a["run"], report=a["report"],
        evaluator_id=a["run"].subject,  # == "codex", the scored subject
        attested_at="2026-07-16T12:00:00Z", key=KEY, prior_attestation_root=ATT_CHAIN_BASE,
        exclusions=a["excl"], ledger=a["ledger"], evaluation_ledger=a["evln"], achievability=None,
    )
    rep = _certify(a, attestation=self_att)
    assert not rep.ok and ViolationReason.CURATOR_IS_SUBJECT in _reasons(rep)


# PART 3 / R5-2 — the attestation chain must root in the COMMITTED latest-attestation root.
def test_part3_certify_chain_base_must_root_in_committed_genesis(monkeypatch):
    # a chain whose prior_attestation_root is NOT the committed root is refused
    unrooted = _anchored(monkeypatch, prior_attestation_root="deadbeef" * 8)
    rep = _certify(unrooted)
    assert not rep.ok and ViolationReason.GENESIS_UNANCHORED in _reasons(rep)

    # the honest chain, rooted in the committed latest-attestation root, is accepted
    rooted = _anchored(monkeypatch)
    assert _certify(rooted).ok, _reasons(_certify(rooted))


# --------------------------------------------------------------------------- #
# Round-6 (the floor): bind-to-head (F1), committed eval-ledger (F2), structural
# certify (F3), ed25519 key custody (F4). After these the only residual is the
# irreducible floor — genesis-commit completeness (git-reviewable) + ed25519
# private-key custody (organizational, curator != subject).
# --------------------------------------------------------------------------- #


# F1 — the certified run MUST bind to the terminal HEAD cohort. A run bound to a stale
# earlier version (honest full history presented) or an unresolvable hash is rejected.
def test_f1_certify_run_must_bind_the_head_cohort(monkeypatch):
    ea, fa = _rc_entry("a", rediscovered=True)
    eb, fb = _rc_entry("b", rediscovered=False)
    ec, fc = _rc_entry("c", rediscovered=False)
    files = {**fa, **fb, **fc}
    v1 = _cohort("v1", [ea, eb])
    v2 = _cohort("v2", [ea, eb, ec], reason="append hard case c", parent="v1")  # head adds a case
    full = CohortHistory(versions=[v1, v2])  # the committed head-extended history

    # head-bound run (v2) with the honest full history certifies
    ok = _chain_certify(monkeypatch, [v1, v2], v2, rediscovered_entries=[ea], files=files, prior_history=full)
    assert ok.ok, _reasons(ok)

    # a run bound to the STALE earlier version v1 (honest full history presented) is rejected:
    # v1 is not the head, so it silently drops the hard case appended at v2
    stale = _chain_certify(monkeypatch, [v1, v2], v1, rediscovered_entries=[ea], files=files, prior_history=full)
    assert not stale.ok and ViolationReason.DENOMINATOR_SHRINK in _reasons(stale)

    # a run bound to an UNRESOLVABLE cohort hash (a version never appended to history) is
    # likewise rejected — it is not the head either
    v3_unpresented = _cohort("v3", [ea, eb, ec], reason="never appended", parent="v2")
    unresolvable = _chain_certify(
        monkeypatch, [v1, v2], v3_unpresented, rediscovered_entries=[ea], files=files, prior_history=full
    )
    assert not unresolvable.ok and ViolationReason.DENOMINATOR_SHRINK in _reasons(unresolvable)


# F2 — the EvaluationLedger is COMMITTED monotonic state: the presented prior_evaluations
# must reproduce the committed evaluation-ledger root. Evaluate-once cannot be dodged with an
# empty ledger across a re-freeze.
def test_f2_evaluation_ledger_is_committed_monotonic_state(monkeypatch):
    # (1) honest FIRST eval: empty prior_evaluations, committed eval root = empty → accept
    a = _anchored(monkeypatch)
    assert _certify(a).ok, _reasons(_certify(a))

    # the blind cohort + subject a second eval would re-roll (fixed identities matching _anchored,
    # which builds its blinds from _default_files() — so the committed blob hashes fold into
    # identity the same way and the recorded blind_ids overlap the scored cohort).
    _bf = _default_files()
    a_entry = _entry(vuln=_A_VULN, patched=_A_PATCHED, paths=["a.py"], probe="sinka(x)", role="blind", files=_bf)
    b_entry = _entry(vuln=_B_VULN, patched=_B_PATCHED, paths=["b.py"], probe="sinkb(x)", role="blind", files=_bf)
    v1 = _cohort("v1", [a_entry, b_entry])
    # the TRUTHFUL committed evaluation-ledger already records a prior eval of this blind set
    prior = EvaluationLedger()
    prior.record(
        cohort_content_hash=v1.content_hash,
        freeze_hash="an-earlier-freeze",
        subject="codex",
        blind_ids=[a_entry.identity_hash, b_entry.identity_hash],
    )

    # (2a) presenting the TRUTHFUL committed ledger reproduces the committed eval root (F2
    #      passes), but A3's blind-set overlap catches the re-roll → BLIND_REEVALUATED
    a_truthful = _anchored(monkeypatch, evln=prior, committed_evaluation_root=prior.root)
    truthful = _certify(a_truthful)
    assert not truthful.ok and ViolationReason.BLIND_REEVALUATED in _reasons(truthful)

    # (2b) presenting an EMPTY prior_evaluations to DODGE the re-roll check does not reproduce
    #      the committed (non-empty) eval root → EVALUATED_MORE_THAN_ONCE (F2)
    a_dodge = _anchored(monkeypatch, evln=EvaluationLedger(), committed_evaluation_root=prior.root)
    dodge = _certify(a_dodge)
    assert not dodge.ok and ViolationReason.EVALUATED_MORE_THAN_ONCE in _reasons(dodge)


# F3 — certification is STRUCTURAL, not opt-in. A producing run presented together with a
# headline Report WITHOUT strict/attestation is UNANCHORED.
def test_f3_produced_and_reported_run_requires_certification(monkeypatch):
    a = _anchored(monkeypatch)
    # a producing run + a headline Report, validated WITHOUT strict/attestation → UNANCHORED
    rep = validate(
        history=a["hist"], run=a["run"], freeze=a["freeze"], report=a["report"], ledger=a["ledger"]
    )
    assert not rep.ok and ViolationReason.UNANCHORED in _reasons(rep)
    # the SAME bundle, certified (strict + signed attestation), is accepted
    assert _certify(a).ok, _reasons(_certify(a))


# F4 — ed25519 key custody: an attestation signed with a non-committed key is
# ATTESTATION_INVALID; the honest attestation (test private key) verifies vs the committed
# public key; and the committed genesis_root.json commits ONLY the ed25519 PUBLIC key.
def test_f4_ed25519_signatures_and_private_key_never_committed(monkeypatch):
    import json as _json

    # (1) an attestation signed with a NON-committed private key → ATTESTATION_INVALID
    a = _anchored(monkeypatch)
    non_committed = hashlib.sha256(b"not-the-committed-signing-key/v1").digest()
    forged = build_attestation(
        history=a["hist"], freeze=a["freeze"], run=a["run"], report=a["report"],
        evaluator_id=EVALUATOR_ID, attested_at="2026-07-16T12:00:00Z", key=non_committed,
        prior_attestation_root=ATT_CHAIN_BASE,
        exclusions=a["excl"], ledger=a["ledger"], evaluation_ledger=a["evln"], achievability=None,
    )
    rep = _certify(a, attestation=forged)
    assert not rep.ok and ViolationReason.ATTESTATION_INVALID in _reasons(rep)

    # (2) the honest attestation, signed with the test PRIVATE key, verifies against the
    #     committed PUBLIC key → accept
    assert _certify(a).ok, _reasons(_certify(a))

    # (3) the committed genesis_root.json commits ONLY the ed25519 PUBLIC key — no private
    #     signing key (and no old symmetric verify_key_hex) is present anywhere in the file
    genesis = Path(__file__).parent.parent / "harness" / "genesis_root.json"
    raw = genesis.read_text(encoding="utf-8")
    data = _json.loads(raw)
    assert "verify_key_pub_hex" in data["evaluator"]
    assert "verify_key_hex" not in data["evaluator"]  # no symmetric secret / private-key field
    committed_pub = bytes.fromhex(data["evaluator"]["verify_key_pub_hex"])
    assert len(committed_pub) == 32  # a valid 32-byte ed25519 public key
    # the fixed committed test SIGNING seed (the private key) is NOT present in the file, yet
    # its derived public key IS the committed one — proving the private key stayed external
    committed_seed = hashlib.sha256(
        b"deepthought/evaluation-contract/committed-test-ed25519-seed/v1"
    ).digest()
    assert committed_seed.hex() not in raw
    assert ed25519_public_key(committed_seed) == committed_pub


# --------------------------------------------------------------------------- #
# Round-7 (last code-closable): certification is STRUCTURAL on the REPORT's numeric
# claims (R7-1), and EVERY certified numeric is recomputed or forbidden (R7-2). After
# these the only residual is the irreducible floor — genesis-commit completeness
# (git-reviewable) + ed25519 private-key custody (organizational).
# --------------------------------------------------------------------------- #


def _reg_entry(tag, *, rediscovered):
    """A REGRESSION-role entry plus its fake-corpus fragment. When ``rediscovered`` the
    patched file drops the FLAG (the fix is confirmed); else it keeps the FLAG."""
    vuln = f"vr{tag}" + "0" * (40 - len(f"vr{tag}"))
    patched = f"pr{tag}" + "0" * (40 - len(f"pr{tag}"))
    path, probe = f"r{tag}.py", f"sinkr{tag}(x)"
    frag = {
        (vuln, path): f"def fr():\n    {probe}  # FLAG\n",
        (patched, path): (
            f"def fr():\n    guard()\n    {probe}\n" if rediscovered else f"def fr():\n    {probe}  # FLAG\n"
        ),
    }
    entry = _entry(vuln=vuln, patched=patched, paths=[path], probe=probe, role="regression", files=frag)
    return entry, frag


# R7-1 — certification is STRUCTURAL on the Report: ANY Report asserting a numerator
# requires full signed certification, so even the default ``check`` cannot bless an
# unanchored/truncated headline. No run, no strict, no attestation → UNANCHORED.
def test_r7_1_report_headline_is_structurally_certified(monkeypatch):
    blinds = [_entry(vuln=x * 40, role="blind") for x in ("a", "b")]
    # a "truncated" single version presented on its own (no prior baseline, no run/strict)
    v2 = _cohort("v2", blinds, reason="a truncated single version", parent="v1")
    hist = CohortHistory(versions=[v2])
    headline = Report(
        blind_recall=RecallReport(rediscovered=1, total=2),  # asserts a numerator
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
        cohort_content_hash=v2.content_hash,
        rediscovered_blind_ids=[blinds[0].identity_hash],  # binds honestly
    )
    # the default check (no run, no strict, no attestation) REFUSES the headline
    rep = validate(history=hist, report=headline)
    assert not rep.ok and ViolationReason.UNANCHORED in _reasons(rep)
    # the binding itself is honest — only the missing certification fails it
    assert check_report(headline, hist).ok

    # a genuinely EMPTY report (0/0, no rediscovered ids) asserts nothing → not forced to certify
    empty = Report(
        blind_recall=RecallReport(rediscovered=0, total=0),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        patched_alert_density=0.0,
        adjudicated_precision=0.0,
        cohort_content_hash=v2.content_hash,
        rediscovered_blind_ids=[],
    )
    # v2's blind count is 2, so this empty (0/0) report mismatches the denominator — but the
    # failure is the ordinary binding one, NOT UNANCHORED (an empty report is not a headline)
    empty_rep = validate(history=hist, report=empty)
    assert ViolationReason.UNANCHORED not in _reasons(empty_rep)


# R7-1 — a numerator-asserting Report riding a NON-producing run (the old F3 keyed on the
# run's produced flag and would have missed this) is UNANCHORED; a strict request with no
# signed attestation is likewise UNANCHORED; the honest strict-certified head still passes.
def test_r7_1_numerator_report_requires_signed_certification(monkeypatch):
    blinds = [_entry(vuln=x * 40, role="blind") for x in ("a", "b")]
    v1 = _cohort("v1", blinds)
    hist = CohortHistory(versions=[v1])
    freeze = FreezeManifest(
        bundle=DetectorBundle(detector_id="d", lockfile_hash="L"), timestamp="2026-07-16T10:00:00Z"
    )
    run = _run("codex", v1.content_hash, freeze.freeze_hash)  # a run with NO producing attempt
    assert not any(att.produced_results for att in run.post_freeze_attempts)
    headline = Report(
        blind_recall=RecallReport(rediscovered=2, total=2),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
        cohort_content_hash=v1.content_hash,
        rediscovered_blind_ids=[b.identity_hash for b in blinds],
    )
    # the numerator claim forces certification even though the run produced nothing → UNANCHORED
    rep = validate(history=hist, run=run, freeze=freeze, report=headline)
    assert not rep.ok and ViolationReason.UNANCHORED in _reasons(rep)
    # strict but with NO signed attestation is also UNANCHORED
    rep_strict = validate(history=hist, report=headline, strict=True)
    assert not rep_strict.ok and ViolationReason.UNANCHORED in _reasons(rep_strict)
    # the honest strict-certified head (full signed bundle) still passes
    assert _certify(_anchored(monkeypatch)).ok


# R7-2 — a certified report's fixed_cohort_recall must be RECOMPUTED over the head cohort's
# REGRESSION entries; an inflated value fails FIXED_COHORT_UNVERIFIED, the honest recompute passes.
def test_r7_2_certified_fixed_cohort_recall_is_recomputed(monkeypatch):
    reg = _reg_entry("x", rediscovered=True)  # a regression entry the committed detector rediscovers
    a = _anchored(monkeypatch, regression=[reg])
    # the honest bundle carries the recomputed fixed_cohort_recall (1/1) → passes
    assert a["report"].fixed_cohort_recall.rediscovered == 1
    assert a["report"].fixed_cohort_recall.total == 1
    assert _certify(a).ok, _reasons(_certify(a))

    # an inflated fixed_cohort_recall that the regression re-run does not reproduce → reject
    inflated = a["report"].model_copy(
        update={"fixed_cohort_recall": RecallReport(rediscovered=5, total=5)}
    )
    att = build_attestation(
        history=a["hist"], freeze=a["freeze"], run=a["run"], report=inflated,
        evaluator_id=EVALUATOR_ID, attested_at="2026-07-16T12:00:00Z", key=KEY,
        prior_attestation_root=ATT_CHAIN_BASE,
        exclusions=a["excl"], ledger=a["ledger"], evaluation_ledger=a["evln"], achievability=None,
    )
    rep = _certify(a, report=inflated, attestation=att)
    assert not rep.ok and ViolationReason.FIXED_COHORT_UNVERIFIED in _reasons(rep)


# R7-2 — a certified report's patched_alert_density must be RECOMPUTED from the committed
# detector's patched-tree flag counts; an inflated value fails DENSITY_UNVERIFIED.
def test_r7_2_certified_patched_alert_density_is_recomputed(monkeypatch):
    a = _anchored(monkeypatch)
    # the honest bundle carries the recomputed density → passes
    assert _certify(a).ok, _reasons(_certify(a))

    # a density the committed detector's patched-tree flags do not reproduce → reject
    wrong = a["report"].model_copy(update={"patched_alert_density": a["report"].patched_alert_density + 13.0})
    att = build_attestation(
        history=a["hist"], freeze=a["freeze"], run=a["run"], report=wrong,
        evaluator_id=EVALUATOR_ID, attested_at="2026-07-16T12:00:00Z", key=KEY,
        prior_attestation_root=ATT_CHAIN_BASE,
        exclusions=a["excl"], ledger=a["ledger"], evaluation_ledger=a["evln"], achievability=None,
    )
    rep = _certify(a, report=wrong, attestation=att)
    assert not rep.ok and ViolationReason.DENSITY_UNVERIFIED in _reasons(rep)


# R7-2 — a certified report must not carry a free ``coverage`` (not recomputable from committed
# state); the certified report must leave it None (COVERAGE_UNBOUND otherwise).
def test_r7_2_certified_report_forbids_free_coverage(monkeypatch):
    a = _anchored(monkeypatch)
    assert a["report"].coverage is None  # the honest certified report omits coverage
    assert _certify(a).ok, _reasons(_certify(a))

    # a certified report carrying a free coverage float → COVERAGE_UNBOUND
    with_coverage = a["report"].model_copy(update={"coverage": 0.9})
    att = build_attestation(
        history=a["hist"], freeze=a["freeze"], run=a["run"], report=with_coverage,
        evaluator_id=EVALUATOR_ID, attested_at="2026-07-16T12:00:00Z", key=KEY,
        prior_attestation_root=ATT_CHAIN_BASE,
        exclusions=a["excl"], ledger=a["ledger"], evaluation_ledger=a["evln"], achievability=None,
    )
    rep = _certify(a, report=with_coverage, attestation=att)
    assert not rep.ok and ViolationReason.COVERAGE_UNBOUND in _reasons(rep)
    # coverage stays available as a labelled diagnostic on a NON-certified report
    assert with_coverage.coverage == 0.9 and "coverage" in with_coverage.render()


# --------------------------------------------------------------------------- #
# Round-8 — pin the recompute's INPUT BYTES (R8-1), commit the precision sample (R8-2), certify
# EVERY scoring numeric (R8-3), POLICY_REFUSAL fails closed unless production is provably absent
# (R8-4), bind produced_results to a results_hash (R8-5), and fail closed on an inert committed
# HISTORY root (R8-6). The FINAL per-cohort residual is the irreducible floor — genesis-commit
# completeness (git-reviewable) + ed25519 private-key custody (organizational).
# --------------------------------------------------------------------------- #


# R8-1 — the certify numerator recompute runs on the EXACT committed pinned bytes; a doctored
# fetch source/cache whose bytes do not reproduce the committed per-target blob sha256 fails
# closed with INPUT_BYTES_UNVERIFIED (the detector never "confirms" a false rediscovery on
# altered bytes). The honest, matching bytes certify.
def test_r8_1_certify_rejects_doctored_input_bytes(monkeypatch):
    a = _anchored(monkeypatch)
    assert _certify(a).ok, _reasons(_certify(a))  # matching committed bytes → certifies

    # override the committed fetcher to return DOCTORED bytes (an attacker-controlled source/cache)
    def _doctored(repo, ref, path):
        return _default_files()[(ref, path)] + "\n# attacker-injected tail\n"

    monkeypatch.setattr(verifier, "FETCH_FN", _doctored)
    rep = _certify(a)
    assert not rep.ok and ViolationReason.INPUT_BYTES_UNVERIFIED in _reasons(rep)


# R8-2 — the precision sample is committed inside the frozen bundle as a sample_root (drawn before
# adjudication, decoupled from the grindable freeze_hash). A re-rolled sample not reproducing the
# committed sample_root fails PRECISION_SAMPLE_UNBOUND; an inert (empty) committed sample_root is
# rejected at certify time (the binding is mandatory).
def test_r8_2_precision_sample_committed_in_bundle(monkeypatch):
    a = _anchored(monkeypatch)
    assert a["freeze"].sample_root  # the freeze commits the sample_root
    assert _certify(a).ok, _reasons(_certify(a))  # the honest sample reproduces it

    # a DIFFERENT valid draw (a re-rolled sample) does not reproduce the committed sample_root
    ch = a["hist"].versions[0].content_hash
    pool = _pool(12)
    other_seed = precision_sample_seed(ch, pool_root_of(pool), "a-different-salt")
    other_sampled = sample_confusion_pairs(pool, 3, other_seed)
    assert sample_root_of(other_sampled) != a["freeze"].sample_root
    rerolled = AdjudicatedPrecision(
        seed=other_seed, sampled_pairs=other_sampled, pool=pool, k=3,
        adjudications=[_good_panel(p, "true-positive") for p in other_sampled],
    )
    rep = _certify(a, precision=rerolled)
    assert not rep.ok and ViolationReason.PRECISION_SAMPLE_UNBOUND in _reasons(rep)

    # an inert committed sample_root fails closed — the sample-commitment binding is mandatory
    naked_bundle = a["freeze"].bundle.model_copy(update={"committed_sample_root": ""})
    naked_freeze = FreezeManifest(bundle=naked_bundle, timestamp=a["freeze"].timestamp)
    rep2 = _certify(a, freeze=naked_freeze)
    assert not rep2.ok and ViolationReason.PRECISION_SAMPLE_UNBOUND in _reasons(rep2)


# R8-3 — certification is STRUCTURAL on EVERY scoring numeric, not only the blind headline. A
# Report with a zero blind headline but a non-zero secondary numeric (fixed_cohort_recall,
# patched_alert_density, or adjudicated_precision) still REQUIRES certification: through the
# default check it is UNANCHORED. A genuinely all-zero report asserts nothing and stays exempt.
def test_r8_3_secondary_scoring_numeric_forces_certification():
    reg = _entry(vuln=A40, role="regression")  # a cohort with NO blind entries → blind 0/0 is valid
    v1 = _cohort("v1", [reg])
    hist = CohortHistory(versions=[v1])

    def _rep(**over):
        base = dict(
            blind_recall=RecallReport(rediscovered=0, total=0),
            fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
            patched_alert_density=0.0,
            adjudicated_precision=0.0,
            cohort_content_hash=v1.content_hash,
            rediscovered_blind_ids=[],
        )
        base.update(over)
        return Report(**base)

    # a non-zero fixed_cohort_recall is a published number → UNANCHORED without certification
    rep_fixed = _rep(fixed_cohort_recall=RecallReport(rediscovered=9, total=10))
    out = validate(history=hist, report=rep_fixed)
    assert not out.ok and ViolationReason.UNANCHORED in _reasons(out)
    # the binding itself is honest — only the missing certification fails it
    assert check_report(rep_fixed, hist).ok

    # a set patched_alert_density and a set adjudicated_precision are equally scoring numerics
    assert ViolationReason.UNANCHORED in _reasons(validate(history=hist, report=_rep(patched_alert_density=1.5)))
    assert ViolationReason.UNANCHORED in _reasons(validate(history=hist, report=_rep(adjudicated_precision=0.8)))

    # a genuinely all-zero report asserts nothing → not forced to certify
    assert ViolationReason.UNANCHORED not in _reasons(validate(history=hist, report=_rep()))


# R8-4 — a POLICY_REFUSAL scores a class N/A only when production is PROVABLY absent. If the
# committed detector for the class produces a rediscovery on the head blind set, the run was
# produced, not refused → POLICY_REFUSAL_ON_PRODUCED_RUN, EVEN with the run object omitted. A
# genuine no-detector class is allowed; and an N/A POLICY_REFUSAL must be inside a certification.
def test_r8_4_policy_refusal_fails_closed_unless_production_absent(monkeypatch):
    files = _default_files()
    a_entry = _entry(vuln=_A_VULN, patched=_A_PATCHED, paths=["a.py"], probe="sinka(x)", role="blind", files=files)
    v1 = _cohort("v1", [a_entry])
    hist = CohortHistory(versions=[v1])
    freeze = FreezeManifest(
        bundle=DetectorBundle(detector_id="d", lockfile_hash="L"), timestamp="2026-07-16T10:00:00Z"
    )
    _install_committed(monkeypatch, presented_history=hist, files=files, detector_id="d")
    excl = ExclusionLog(events=[ExclusionEvent(reason=ExclusionReason.POLICY_REFUSAL)])

    # the committed detector PRODUCES a rediscovery on the head blind set → the class cannot be
    # laundered to N/A, EVEN with the run omitted (run is not passed here)
    rep = validate(history=hist, freeze=freeze, exclusions=excl)
    assert not rep.ok and ViolationReason.POLICY_REFUSAL_ON_PRODUCED_RUN in _reasons(rep)
    # and an N/A POLICY_REFUSAL presented without certification is UNANCHORED
    assert ViolationReason.UNANCHORED in _reasons(rep)

    # a genuine builder-declined class (no committed detector registered for the id) is allowed:
    # POLICY_REFUSAL_ON_PRODUCED_RUN does NOT fire
    freeze_ghost = FreezeManifest(
        bundle=DetectorBundle(detector_id="ghost-unregistered", lockfile_hash="L"),
        timestamp="2026-07-16T10:00:00Z",
    )
    rep_ghost = validate(history=hist, freeze=freeze_ghost, exclusions=excl, strict=True)
    assert ViolationReason.POLICY_REFUSAL_ON_PRODUCED_RUN not in _reasons(rep_ghost)


# R8-5 — a producing attempt binds a non-empty results_hash; a non-producing "infra retry" binds
# an empty one. So N-1 real evals cannot hide as produced_results=False "retries": a retry
# carrying a results_hash is a concealed real evaluation → INFRA_RETRY_REQUIRES_UNCHANGED.
def test_r8_5_results_hash_binds_produced_results():
    # record-time: a non-producing infra retry carrying a results_hash is refused
    run = EvaluationRun(run_id="r", subject="s", cohort_content_hash="H", freeze_hash="fz")
    with pytest.raises(ContractViolation) as ir:
        run.attempt_evaluation(
            phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E", results_hash="HIDDEN"
        )
    assert ir.value.reason is ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED

    # from storage: a non-producing attempt carrying a results_hash (a concealed real eval) → reject
    hidden = EvaluationRun(
        run_id="r2", subject="s", cohort_content_hash="H", freeze_hash="fz",
        attempts=[EvalAttempt(
            phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E",
            freeze_hash="fz", results_hash="HIDDEN",
        )],
    )
    rep = validate(run=hidden)
    assert not rep.ok and ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED in _reasons(rep)

    # from storage: a PRODUCING attempt with an empty results_hash is unbound → reject
    unbound = EvaluationRun(
        run_id="r3", subject="s", cohort_content_hash="H", freeze_hash="fz",
        attempts=[EvalAttempt(
            phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E", freeze_hash="fz",
        )],
    )
    assert ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED in _reasons(validate(run=unbound))

    # honest: a non-producing retry (empty results_hash) then a producing terminal (non-empty) passes
    honest = EvaluationRun(
        run_id="r4", subject="s", cohort_content_hash="H", freeze_hash="fz",
        attempts=[
            EvalAttempt(phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E", freeze_hash="fz"),
            EvalAttempt(
                phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E",
                freeze_hash="fz", results_hash="R1",
            ),
        ],
    )
    assert ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED not in _reasons(validate(run=honest))


# R8-6 — the committed genesis loader fails closed on an INERT history root: an inert (empty
# chain) genesis/latest history root would let a TRUNCATED cohort anchor against the empty prefix.
def test_r8_6_genesis_fails_closed_on_inert_history_root(tmp_path):
    import json as _json

    real = "a" * 64
    good = {
        "genesis_history_root": real,
        "latest": {
            "history_root": real,
            "attestation_root": contract._ATTESTATION_CHAIN_GENESIS,  # legit bootstrap base
            "evaluation_root": contract._EMPTY_ROOT,  # legit empty-ledger base
        },
        "evaluator": {"id": "curator-not-subject", "verify_key_pub_hex": _TEST_PUB.hex()},
    }

    def _write(data):
        p = tmp_path / f"g{len(list(tmp_path.iterdir()))}.json"
        p.write_text(_json.dumps(data), encoding="utf-8")
        return p

    # a real, non-inert committed state loads
    assert contract.load_committed_genesis_state(_write(good)).genesis_history_root == real

    # an inert genesis_history_root fails closed
    bad_genesis = {**good, "genesis_history_root": contract._CHAIN_GENESIS}
    with pytest.raises(ValueError):
        contract.load_committed_genesis_state(_write(bad_genesis))

    # an inert latest.history_root fails closed
    bad_latest = {**good, "latest": {**good["latest"], "history_root": contract._EMPTY_ROOT}}
    with pytest.raises(ValueError):
        contract.load_committed_genesis_state(_write(bad_latest))


# --------------------------------------------------------------------------- #
# Round-9 final per-cohort survivors (R9-1..R9-4). The last audit holes before
# 008 ships: an operator-chosen precision sample, an exposure fallback a curated
# record could skip, an unbound non-producing post-freeze attempt, and a
# ROLE_DOWNGRADE not backed by a guided_fix precondition.
# --------------------------------------------------------------------------- #


# R9-1 — the certified precision sample must be the CANONICAL draw from committed, non-grindable
# state (cohort_content_hash + committed pool_root + committed k), NOT an operator-chosen sample.
def test_r9_1_precision_sample_must_be_canonical(monkeypatch):
    # the canonical bundle certifies (sample derived from committed cohort + pool + k)
    assert _certify(_anchored(monkeypatch)).ok

    # a CHERRY-PICKED committed sample (a favorable operator-chosen draw whose sample_root is
    # committed inside the bundle AND reproduced by the presented precision) is rejected: it is not
    # the canonical draw from committed state -> PRECISION_SAMPLE_UNBOUND
    a = _anchored(monkeypatch, cherry_pick_sample=True)
    canonical_root = contract.canonical_sample_root(a["hist"].versions[0].content_hash, _pool(12), 3)
    assert a["freeze"].sample_root != canonical_root  # sanity: the committed sample is non-canonical
    rep = _certify(a)
    assert not rep.ok and ViolationReason.PRECISION_SAMPLE_UNBOUND in _reasons(rep)


# R9-2 — a NON-EMPTY curated_entry_ids must NOT short-circuit the content-hash exposure fallback: a
# version bump (same entries, new hash) cannot launder a curator into a subject.
def test_r9_2_curated_ids_do_not_skip_content_hash_fallback():
    a = _entry(vuln=A40, role="blind")
    b = _entry(vuln=B40, role="blind")
    v1 = _cohort("v1", [a, b])
    v2 = _cohort("v2", [a, b], reason="version bump, same entries", parent="v1")  # new content hash
    hist = CohortHistory(versions=[v1, v2])

    # the subject curated v1 (recorded by its content hash) with curated_entry_ids that are DISJOINT
    # from the presented head's blind set — but v1 shares entry identities with the scored head v2.
    # The curated_entry_ids bar (Bar 1) clears, yet the content-hash fallback (Bar 2) must STILL bar.
    ledger = ExposureLedger()
    ledger.record(
        cohort_content_hash=v1.content_hash,
        actor="claude",
        activity="curated",
        curated_entry_ids=["an-unrelated-identity"],  # disjoint from the scored blind set
    )
    run = _run("claude", v2.content_hash, "fz")
    rep = validate(history=hist, run=run, ledger=ledger)
    assert not rep.ok and ViolationReason.CURATOR_IS_SUBJECT in _reasons(rep)

    # a curated record whose identities AND cohort are both disjoint from the scored cohort clears
    other = _entry(vuln=C40, role="blind")
    v_other = _cohort("v9", [other])  # not in the presented history
    ledger_ok = ExposureLedger()
    ledger_ok.record(
        cohort_content_hash=v_other.content_hash,  # unresolvable in this history
        actor="codex",
        activity="curated",
        curated_entry_ids=[other.identity_hash],  # resolvable by identity, disjoint
    )
    run_ok = _run("codex", v2.content_hash, "fz")
    assert validate(history=hist, run=run_ok, ledger=ledger_ok).ok


# R9-3 — EVERY post-freeze attempt is bound to the freeze, not just the first + producing one. A
# non-first, non-producing "retry" carrying a forged freeze_hash (a hidden second eval of an
# unrelated bundle) is caught.
def test_r9_3_every_post_freeze_attempt_bound_to_freeze():
    a = _entry(vuln=A40, role="blind")
    v1 = _cohort("v1", [a])
    hist = CohortHistory(versions=[v1])
    freeze = FreezeManifest(
        bundle=DetectorBundle(detector_id="d", lockfile_hash="L"), timestamp="2026-07-16T10:00:00Z"
    )
    fz = freeze.freeze_hash

    # a honest bound retry, THEN a NON-first, NON-producing retry carrying a FORGED freeze_hash
    # (unbound to the frozen bundle — a hidden second evaluation), then the producing terminal. The
    # first-only + producing-only binding never inspected the middle attempt -> now BAD_FREEZE_BINDING.
    run = _run("s", v1.content_hash, fz)
    run.attempts.append(EvalAttempt(phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E", freeze_hash=fz))
    run.attempts.append(EvalAttempt(phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E", freeze_hash="forged"))
    run.attempts.append(
        EvalAttempt(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E", freeze_hash=fz, results_hash="R1")
    )
    rep = validate(history=hist, run=run, freeze=freeze)
    assert not rep.ok and ViolationReason.BAD_FREEZE_BINDING in _reasons(rep)

    # a non-producing retry whose artifact_hash differs from the PRODUCING evaluation is an
    # INFRA_RETRY_REQUIRES_UNCHANGED (the retry does not match the scored run)
    run2 = _run("s", v1.content_hash, fz)
    run2.attempts.append(EvalAttempt(phase="post_freeze", produced_results=False, artifact_hash="DIFF", env_hash="E", freeze_hash=fz))
    run2.attempts.append(
        EvalAttempt(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E", freeze_hash=fz, results_hash="R1")
    )
    rep2 = validate(history=hist, run=run2, freeze=freeze)
    assert not rep2.ok and ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED in _reasons(rep2)

    # honest: every attempt bound to the freeze with matching artifact/env -> no binding/retry error
    run3 = _run("s", v1.content_hash, fz)
    run3.attempts.append(EvalAttempt(phase="post_freeze", produced_results=False, artifact_hash="A", env_hash="E", freeze_hash=fz))
    run3.attempts.append(
        EvalAttempt(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E", freeze_hash=fz, results_hash="R1")
    )
    rep3 = validate(history=hist, run=run3, freeze=freeze)
    assert ViolationReason.BAD_FREEZE_BINDING not in _reasons(rep3)
    assert ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED not in _reasons(rep3)


# R9-4 — a ROLE_DOWNGRADE that moves an identity out of the blind set additionally requires that
# entry to have carried guided_fix==True in the from_version cohort (FR-4).
def test_r9_4_role_downgrade_requires_guided_fix_in_from_version():
    a = _entry(vuln=A40, role="blind")

    # a blind entry that NEVER guided a fix, downgraded out of blind WITH a matched ROLE_DOWNGRADE
    # event, still drops a hard case out of the denominator -> DENOMINATOR_SHRINK
    c = _entry(vuln=C40, role="blind", guided_fix=False)
    v1 = _cohort("v1", [a, c])
    c_reg = c.model_copy(update={"role": "regression"}).sealed()
    v2 = _cohort("v2", [a, c_reg], reason="downgrade c", parent="v1")
    excl = ExclusionLog(
        events=[ExclusionEvent(reason=ExclusionReason.ROLE_DOWNGRADE, entry_identity=c.identity_hash, from_version="v1", to_version="v2")]
    )
    rep = validate(history=CohortHistory(versions=[v1, v2]), exclusions=excl)
    assert not rep.ok and ViolationReason.DENOMINATOR_SHRINK in _reasons(rep)

    # the SAME downgrade of a guided_fix=True blind entry is allowed (a legitimate blind->regression
    # move after the entry guided a fix). guided_fix is NOT part of identity, so the event's
    # entry_identity matches either way — only the from_version guided_fix flag differs.
    cg = _entry(vuln=C40, role="blind", guided_fix=True)
    assert cg.identity_hash == c.identity_hash
    v1g = _cohort("v1", [a, cg])
    cg_reg = cg.model_copy(update={"role": "regression"}).sealed()
    v2g = _cohort("v2", [a, cg_reg], reason="downgrade c after it guided a fix", parent="v1")
    excl_g = ExclusionLog(
        events=[ExclusionEvent(reason=ExclusionReason.ROLE_DOWNGRADE, entry_identity=cg.identity_hash, from_version="v1", to_version="v2")]
    )
    assert validate(history=CohortHistory(versions=[v1g, v2g]), exclusions=excl_g).ok


# --------------------------------------------------------------------------- #
# Round-10 comprehensive final seals (R10-1..R10-7). Every survivor is the SAME
# recurring shape: re-enforce a constructor/type invariant ON the certify path,
# bind each ledger to a committed-monotonic root, and trust CODE HASHES not names.
# --------------------------------------------------------------------------- #


# R10-1 — the detector is bound by the CONTENT HASH of its loaded module, not the mutable
# detector_id. Swapping the detector CODE under a preserved name/freeze is DETECTOR_BUNDLE_UNVERIFIED.
def test_r10_1_detector_bound_by_module_code_hash(monkeypatch):
    a = _anchored(monkeypatch)
    assert _certify(a).ok, _reasons(_certify(a))  # frozen module_hashes == loaded module hash

    # the operator swaps the detector CODE (the loaded module hash changes) while keeping the
    # name + freeze: the recompute no longer matches the frozen module_hashes
    monkeypatch.setitem(
        verifier.DETECTOR_MODULE_HASHES, "d", lambda: {"d_detector.py": "swapped" + "0" * 57}
    )
    rep = _certify(a)
    assert not rep.ok and ViolationReason.DETECTOR_BUNDLE_UNVERIFIED in _reasons(rep)

    # an UNREGISTERED module hash (no committed source to hash) fails closed
    a2 = _anchored(monkeypatch)
    monkeypatch.delitem(verifier.DETECTOR_MODULE_HASHES, "d")
    rep2 = _certify(a2)
    assert not rep2.ok and ViolationReason.DETECTOR_BUNDLE_UNVERIFIED in _reasons(rep2)

    # an inert (empty) committed freeze module_hashes fails closed — the code is bound only by name
    a3 = _anchored(monkeypatch)
    inert_bundle = a3["freeze"].bundle.model_copy(update={"module_hashes": {}})
    inert_freeze = FreezeManifest(bundle=inert_bundle, timestamp=a3["freeze"].timestamp)
    rep3 = _certify(a3, freeze=inert_freeze)
    assert not rep3.ok and ViolationReason.DETECTOR_BUNDLE_UNVERIFIED in _reasons(rep3)


# R10-2 — the exposure ledger is COMMITTED-monotonic state (parity with history/evaluation): a
# truncated ledger that drops the incriminating curator record and re-signs cannot reproduce the
# committed exposure root -> EXPOSURE_LEDGER_TRUNCATED.
def test_r10_2_exposure_ledger_is_committed_monotonic(monkeypatch):
    a = _anchored(monkeypatch)
    honest = a["ledger"]  # one curator record (claude curated the blind set)
    # advance the committed exposure baseline to the honest ledger root (a real committed baseline)
    base = contract.load_committed_genesis_state()
    monkeypatch.setattr(
        contract,
        "load_committed_genesis_state",
        lambda *x, **k: base.model_copy(update={"latest_exposure_root": honest.root}),
    )
    # the honest ledger reproduces the committed baseline -> passes
    assert _certify(a).ok, _reasons(_certify(a))

    # a truncated ledger (curator record dropped), re-signed over its own root, does NOT reproduce
    # the committed exposure baseline -> EXPOSURE_LEDGER_TRUNCATED
    truncated = ExposureLedger()
    att = build_attestation(
        history=a["hist"], freeze=a["freeze"], run=a["run"], report=a["report"],
        evaluator_id=EVALUATOR_ID, attested_at="2026-07-16T12:00:00Z", key=KEY,
        prior_attestation_root=ATT_CHAIN_BASE, exclusions=a["excl"], ledger=truncated,
        evaluation_ledger=a["evln"], achievability=None,
    )
    rep = _certify(a, ledger=truncated, attestation=att)
    assert not rep.ok and ViolationReason.EXPOSURE_LEDGER_TRUNCATED in _reasons(rep)


# R10-3 — an EvaluationRecord's blind_ids must be BOUND to its resolved cohort: a record advertising
# a falsified (smaller/empty) blind set to dodge the A3 overlap check is EVALUATION_RECORD_UNBOUND.
def test_r10_3_evaluation_record_blind_ids_bound_to_cohort():
    a = _entry(vuln=A40, role="blind")
    b = _entry(vuln=B40, role="blind")
    v1 = _cohort("v1", [a, b])
    hist = CohortHistory(versions=[v1])
    freeze = FreezeManifest(
        bundle=DetectorBundle(detector_id="d", lockfile_hash="L"), timestamp="2026-07-16T10:00:00Z"
    )
    run = _run("s", v1.content_hash, freeze.freeze_hash)

    # a prior record that FALSIFIES its blind set (advertises only 'a', dropping 'b') for a DIFFERENT
    # subject (so A3's overlap does not fire) — the record's cohort resolves in history, so R10-3
    # binds its blind_ids to the cohort's actual blind set and rejects the falsification
    falsified = EvaluationLedger()
    falsified.record(
        cohort_content_hash=v1.content_hash, freeze_hash="earlier", subject="other",
        blind_ids=[a.identity_hash],  # the cohort's ACTUAL blind set is {a, b}
    )
    rep = validate(history=hist, run=run, freeze=freeze, prior_evaluations=falsified)
    assert not rep.ok and ViolationReason.EVALUATION_RECORD_UNBOUND in _reasons(rep)

    # the honest record (blind_ids == the cohort's actual blind set) is accepted
    honest = EvaluationLedger()
    honest.record(
        cohort_content_hash=v1.content_hash, freeze_hash="earlier", subject="other",
        blind_ids=[a.identity_hash, b.identity_hash],
    )
    assert ViolationReason.EVALUATION_RECORD_UNBOUND not in _reasons(
        validate(history=hist, run=run, freeze=freeze, prior_evaluations=honest)
    )


# R10-4 — the evaluation chain fails closed on the inert short-circuit (matching R8-6 for history):
# a NON-EMPTY prior_evaluations that "reproduces" the inert empty committed root via the empty prefix
# is rejected — the committed chain never advanced to record those evals.
def test_r10_4_evaluation_chain_fails_closed_on_inert_short_circuit(monkeypatch):
    # bootstrap: an EMPTY ledger + the inert empty committed eval root is the genuine first eval
    assert _certify(_anchored(monkeypatch)).ok

    # a NON-EMPTY prior_evaluations (referencing an unresolvable cohort + a different subject, so
    # R10-3 and A3 both skip) presented while the committed eval root is STILL the inert empty root
    # must NOT reproduce it -> EVALUATED_MORE_THAN_ONCE (no empty-prefix short-circuit past bootstrap)
    stale = EvaluationLedger()
    stale.record(
        cohort_content_hash="an-unresolvable-cohort", freeze_hash="fz", subject="not-codex", blind_ids=[]
    )
    a = _anchored(monkeypatch, evln=stale)  # committed eval root defaults to the inert empty root
    rep = _certify(a)
    assert not rep.ok and ViolationReason.EVALUATED_MORE_THAN_ONCE in _reasons(rep)


# R10-5 — the AdjudicatedPrecision panel + coverage invariants are RE-ENFORCED on the certify path,
# so a from-storage (model_construct) precision that bypasses the constructor validator is caught.
def test_r10_5_precision_panel_reenforced_on_certify(monkeypatch):
    a = _anchored(monkeypatch)
    assert _certify(a).ok
    good = a["precision"]

    # a from-storage precision with a BUILDER adjudicator (precision 1.0 with no honest panel)
    builder_adj = [
        Adjudication(
            pair_id=p,
            verdicts=[
                AdjudicatorVerdict(adjudicator="A", is_builder=True, is_curator=False, decision="true-positive"),
                AdjudicatorVerdict(adjudicator="B", is_builder=False, is_curator=True, decision="true-positive"),
            ],
        )
        for p in good.sampled_pairs
    ]
    tampered = AdjudicatedPrecision.model_construct(
        seed=good.seed, sampled_pairs=good.sampled_pairs, pool=good.pool, k=good.k, adjudications=builder_adj,
    )
    rep = _certify(a, precision=tampered)
    assert not rep.ok and ViolationReason.PRECISION_PANEL_INVALID in _reasons(rep)

    # a from-storage precision with PARTIAL coverage (one sampled pair unadjudicated)
    partial = AdjudicatedPrecision.model_construct(
        seed=good.seed, sampled_pairs=good.sampled_pairs, pool=good.pool, k=good.k,
        adjudications=good.adjudications[:-1],
    )
    rep2 = _certify(a, precision=partial)
    assert not rep2.ok and ViolationReason.PRECISION_PANEL_INVALID in _reasons(rep2)


# R10-6 — every adjudicator is bound to the committed roster and is independent of the scored
# subject; a self-asserted role or a non-independent/unrostered adjudicator is ADJUDICATOR_INVALID.
def test_r10_6_adjudicator_independent_and_rostered(monkeypatch):
    a = _anchored(monkeypatch)  # subject is "codex"
    good = a["precision"]

    # an adjudicator whose id equals the scored subject is not independent
    subj_adj = [
        Adjudication(
            pair_id=p,
            verdicts=[
                AdjudicatorVerdict(adjudicator="codex", is_builder=False, is_curator=False, decision="true-positive"),
                AdjudicatorVerdict(adjudicator="B", is_builder=False, is_curator=True, decision="true-positive"),
            ],
        )
        for p in good.sampled_pairs
    ]
    p_subj = AdjudicatedPrecision(
        seed=good.seed, sampled_pairs=good.sampled_pairs, pool=good.pool, k=good.k, adjudications=subj_adj
    )
    rep = _certify(a, precision=p_subj)
    assert not rep.ok and ViolationReason.ADJUDICATOR_INVALID in _reasons(rep)

    # an UNROSTERED adjudicator (not on the committed roster) is rejected
    unrostered = [
        Adjudication(
            pair_id=p,
            verdicts=[
                AdjudicatorVerdict(adjudicator="A", is_builder=False, is_curator=False, decision="true-positive"),
                AdjudicatorVerdict(adjudicator="C", is_builder=False, is_curator=False, decision="true-positive"),
            ],
        )
        for p in good.sampled_pairs
    ]
    p_unr = AdjudicatedPrecision(
        seed=good.seed, sampled_pairs=good.sampled_pairs, pool=good.pool, k=good.k, adjudications=unrostered
    )
    rep2 = _certify(a, precision=p_unr)
    assert not rep2.ok and ViolationReason.ADJUDICATOR_INVALID in _reasons(rep2)

    # a self-asserted role that does NOT match the committed roster is rejected (B claims non-curator)
    lying = [
        Adjudication(
            pair_id=p,
            verdicts=[
                AdjudicatorVerdict(adjudicator="A", is_builder=False, is_curator=False, decision="true-positive"),
                AdjudicatorVerdict(adjudicator="B", is_builder=False, is_curator=False, decision="true-positive"),
            ],
        )
        for p in good.sampled_pairs
    ]
    p_lie = AdjudicatedPrecision(
        seed=good.seed, sampled_pairs=good.sampled_pairs, pool=good.pool, k=good.k, adjudications=lying
    )
    rep3 = _certify(a, precision=p_lie)
    assert not rep3.ok and ViolationReason.ADJUDICATOR_INVALID in _reasons(rep3)


# R10-7 — merkle_root domain-separates leaves (0x00) from internal nodes (0x01), so a duplicate-leaf
# second preimage cannot collide with a shorter honest set (CVE-2012-2459).
def test_r10_7_merkle_domain_separation_cve_2012_2459():
    assert merkle_root(["a", "b"]) != merkle_root(["a", "b", "b"])
    assert merkle_root(["a", "b", "c"]) != merkle_root(["a", "b", "c", "c"])
    assert merkle_root(["x"]) != merkle_root(["x", "x"])
    # still order-independent over the same set and membership-sensitive
    assert merkle_root(["a", "b", "c"]) == merkle_root(["c", "b", "a"])
    assert merkle_root(["a", "b", "c"]) != merkle_root(["a", "b"])
