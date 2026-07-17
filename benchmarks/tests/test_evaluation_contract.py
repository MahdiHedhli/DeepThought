"""Acceptance tests for the typed EvaluationContract (feature 008).

One test per acceptance criterion (AC-1..AC-14) in
``specs/008-evaluation-contract/spec.md``, plus a few targeted sub-behaviour
tests. Everything is DETERMINISTIC: timestamps and sample seeds are passed in,
never read from the wall clock or an RNG the test does not control.
"""

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent / "harness"))

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
    SyntheticSuite,
    SyntheticVariant,
    ViolationReason,
    candidates_from_adjudications,
    precision_sample_seed,
    sample_confusion_pairs,
    validate,
)
from roundrecord import ClassRate  # noqa: E402

A40 = "a" * 40
B40 = "b" * 40
C40 = "c" * 40


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
):
    e = CohortEntry(
        repo=repo,
        vuln_ref=vuln,
        patched_ref=patched,
        target_paths=paths or ["a/x.py"],
        sink_probe=probe,
        status=status,
        drop_reason=drop_reason,
        role=role,
        guided_fix=guided_fix,
    )
    return e.sealed() if seal else e


def _cohort(version, entries, *, reason="", parent=None, seal=True):
    c = Cohort(version=version, entries=list(entries), reason=reason, parent_version=parent)
    return c.sealed() if seal else c


def _reasons(report):
    return {v.reason for v in report.violations}


def _good_panel(pair_id, decision, *, curator_second=True):
    return Adjudication(
        pair_id=pair_id,
        verdicts=[
            AdjudicatorVerdict(adjudicator="A", is_builder=False, is_curator=False, decision=decision),
            AdjudicatorVerdict(adjudicator="B", is_builder=False, is_curator=curator_second, decision=decision),
        ],
    )


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

    # role is NOT part of identity: moving blind -> regression keeps the identity,
    # so the denominator is preserved with no exclusion event needed
    g_reg = g.model_copy(update={"role": "regression"}).sealed()
    assert g_reg.identity_hash == g.identity_hash
    v1 = _cohort("v1", [g])
    v2 = _cohort("v2", [g_reg], reason="blind guided a fix -> regression", parent="v1")
    fixed = validate(history=CohortHistory(versions=[v1, v2]))
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
    run = EvaluationRun(run_id="r", subject="claude", cohort_content_hash="H", freeze_hash="fz")
    bad = validate(run=run, ledger=ledger)
    assert not bad.ok and ViolationReason.CURATOR_IS_SUBJECT in _reasons(bad)
    # a non-exposed subject is fine; rotation surfaces one
    ok = validate(run=run.model_copy(update={"subject": "codex"}), ledger=ledger)
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
    pairs = [f"p{i}" for i in range(20)]
    assert sample_confusion_pairs(pairs, 5, seed) == sample_confusion_pairs(pairs, 5, seed)

    # a builder on the panel is invalid
    with pytest.raises(ValidationError):
        AdjudicatedPrecision(
            seed=seed,
            sampled_pairs=["p0"],
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
    # ambiguous counts AGAINST precision
    ap = AdjudicatedPrecision(
        seed=seed,
        sampled_pairs=["p0", "p1"],
        adjudications=[_good_panel("p0", "true-positive"), _good_panel("p1", "ambiguous")],
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
        run=EvaluationRun(run_id="r", subject="claude", cohort_content_hash="H", freeze_hash="fz"),
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
        run=EvaluationRun(run_id="r", subject="codex", cohort_content_hash="H", freeze_hash="fz"),
        ledger=ExposureLedger(),
    )
    assert good.ok, _reasons(good)
