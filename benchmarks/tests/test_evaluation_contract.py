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
    SyntheticSuite,
    SyntheticVariant,
    ViolationReason,
    _canonical_run_id,
    build_attestation,
    candidates_from_adjudications,
    chain_root,
    leaf_hash,
    merkle_root,
    pool_root_of,
    precision_sample_seed,
    sample_confusion_pairs,
    sign,
    validate,
    verify,
)
from roundrecord import ClassRate  # noqa: E402

A40 = "a" * 40
B40 = "b" * 40
C40 = "c" * 40

# A fixed evaluator key (deterministic tests never read os.urandom).
KEY = b"deepthought-test-evaluator-key-0123456789"


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
    assert validate(history=hist, report=rep_ok).ok

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
    c = _entry(vuln=C40, role="blind")
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
    assert validate(history=hist, report=bound).ok


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
    assert validate(history=hist, run=run, freeze=freeze, report=honest).ok


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
            EvalAttempt(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E", freeze_hash="fz"),
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
    # sign/verify: round-trips; a forged signature or a wrong key fails (constant-time).
    root = merkle_root(["a", "b"])
    sig = sign(root, KEY)
    assert verify(root, sig, KEY)
    assert not verify(root, sig, b"a-different-key")
    assert not verify(root, "00" * 32, KEY)


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


def _anchored():
    """A fully honest, anchored evaluation bundle plus its signed Attestation.
    Reused by the B5 fail-closed cases (each tampers exactly one thing)."""
    blinds = [_entry(vuln=x * 40, role="blind") for x in ("a", "b")]
    v1 = _cohort("v1", blinds)
    hist = CohortHistory(versions=[v1])
    pool = _pool(12)
    bundle = DetectorBundle(detector_id="d", lockfile_hash="L", pool_root=pool_root_of(pool))
    freeze = FreezeManifest(bundle=bundle, timestamp="2026-07-16T10:00:00Z")
    run = _run("codex", v1.content_hash, freeze.freeze_hash)
    run.attempt_evaluation(phase="post_freeze", produced_results=True, artifact_hash="A", env_hash="E")
    report = Report(
        blind_recall=RecallReport(rediscovered=1, total=2),
        fixed_cohort_recall=RecallReport(rediscovered=0, total=0),
        coverage=1.0,
        patched_alert_density=0.0,
        adjudicated_precision=1.0,
        cohort_content_hash=v1.content_hash,
        rediscovered_blind_ids=[blinds[0].identity_hash],
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
    evln = EvaluationLedger()
    att = build_attestation(
        history=hist,
        freeze=freeze,
        run=run,
        report=report,
        evaluator_id="curator-not-subject",
        attested_at="2026-07-16T12:00:00Z",
        key=KEY,
        exclusions=excl,
        ledger=ledger,
        evaluation_ledger=evln,
        achievability=None,
    )
    return dict(hist=hist, freeze=freeze, run=run, report=report, ledger=ledger, excl=excl, evln=evln, blinds=blinds, att=att)


def _certify(a, **overrides):
    kw = dict(
        history=a["hist"],
        freeze=a["freeze"],
        run=a["run"],
        report=a["report"],
        exclusions=a["excl"],
        ledger=a["ledger"],
        prior_evaluations=a["evln"],
        attestation=a["att"],
        verify_key=KEY,
        strict=True,
    )
    kw.update(overrides)
    return validate(**kw)


# B5 — a fully honest, signed attestation is ACCEPTED under strict certification.
def test_b5_honest_signed_attestation_accepted():
    a = _anchored()
    rep = _certify(a)
    assert rep.ok, _reasons(rep)


# B5 — a forged signature is rejected.
def test_b5_forged_signature_rejected():
    a = _anchored()
    forged = a["att"].model_copy(update={"signature": "00" * 32})
    rep = _certify(a, attestation=forged)
    assert not rep.ok and ViolationReason.ATTESTATION_INVALID in _reasons(rep)


# B5 — a tampered/omitted history version (root mismatch) is rejected.
def test_b5_tampered_history_root_mismatch():
    a = _anchored()
    extra = _entry(vuln=C40, role="blind")
    v2 = _cohort("v2", a["blinds"] + [extra], reason="append not attested", parent="v1")
    tampered = CohortHistory(versions=[a["hist"].versions[0], v2])
    rep = _certify(a, history=tampered)
    assert not rep.ok and ViolationReason.ATTESTATION_MISMATCH in _reasons(rep)


# B5 — a rewritten ledger entry (chain-root mismatch) is rejected.
def test_b5_rewritten_ledger_entry_root_mismatch():
    a = _anchored()
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
def test_b5_swapped_pool_root_mismatch():
    a = _anchored()
    swapped_bundle = a["freeze"].bundle.model_copy(update={"pool_root": pool_root_of(_pool(20))})
    swapped_freeze = FreezeManifest(bundle=swapped_bundle, timestamp=a["freeze"].timestamp)
    rep = _certify(a, freeze=swapped_freeze)
    assert not rep.ok and ViolationReason.ATTESTATION_MISMATCH in _reasons(rep)


# B5 — an attestation that references a component not presented is rejected (fail closed).
def test_b5_missing_component_incomplete():
    a = _anchored()
    rep = _certify(a, history=None)
    assert not rep.ok and ViolationReason.ATTESTATION_INCOMPLETE in _reasons(rep)


# B5 — a certify path with NO attestation is UNANCHORED (fail closed).
def test_b5_certify_without_attestation_unanchored():
    a = _anchored()
    rep = validate(
        history=a["hist"],
        freeze=a["freeze"],
        run=a["run"],
        report=a["report"],
        exclusions=a["excl"],
        ledger=a["ledger"],
        prior_evaluations=a["evln"],
        strict=True,  # no attestation, no verify_key
    )
    assert not rep.ok and ViolationReason.UNANCHORED in _reasons(rep)
