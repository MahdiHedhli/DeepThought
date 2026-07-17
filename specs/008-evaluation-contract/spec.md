# Feature Spec: Evaluation Contract — Honest Measurement Spine (008)

**Feature Branch:** `008-evaluation-contract`
**Created:** 2026-07-16
**Status:** Draft

## Problem

The rediscovery benchmark's numbers are only as honest as the bookkeeping under
them, and today that bookkeeping is partial. `corpus_measure.py` correctly scores
rediscovery line-precisely and already reports patched-tree flag counts *separately*
as context — but the regression bar in `roundrecord.py` (`Snapshot` / `ClassRate`)
protects only a class's *rate* and *presence*. It does not protect **cohort
identity** or the **denominator**: a detector can "improve" a class by dropping the
hard case, re-pinning to an easier commit, or narrowing `target_paths`, and no
guard trips. There is no enforced separation of calibration / regression / blind
sets, no detector **freeze**, no **exposure ledger** (so a model that curated a
cohort could later be scored on it), and no typed **exclusion log** distinguishing
"we couldn't catch it" (a miss) from "the measurement itself failed" (an invalid
run).

A cross-model methodology review (Claude Opus 4.8 + Sol / GPT-5.6, recorded in the
vault note `measurement-honesty-contract`) locked a set of honesty invariants. This
feature turns them into a **typed, validated Evaluation Contract** that every
future measurement — and the shared flow kernel that comes after — must pass
through. It is deliberately the *first* build in the tranche: the contract lands
before any detector or kernel work, so improvements are measured on honest ground
from day one.

The single principle behind all of it: **every exclusion is a logged, reviewable,
versioned event — never a silent reclassification.**

## Goal

A typed `EvaluationContract` (Pydantic, beside `roundrecord.py`) plus validation
wired into `check`, enforcing:

- **canonical, immutable cohort-entry identity** and content hashing;
- **cohort versioning** — any correction creates a new version; history is never
  edited;
- **denominator preservation** — the authoritative rate is blind-rediscovered /
  all-pinned; entries leave only via a logged exclusion event;
- **calibration / regression / blind separation**, disjoint and typed;
- **artifact freeze** — a content hash of the whole executable detector bundle;
- an **exposure ledger** enforcing curator ≠ subject, with rotation;
- **blind-access discipline** — zero pre-freeze, exactly one post-freeze;
- a typed **exclusion-event log** with a closed taxonomy;
- **blind-led, multi-number reporting** — recall and precision kept separate.

## Scope

**In scope**

- The typed models: `CohortEntry` (canonical identity + hash), `Cohort` (versioned,
  role-tagged), `FreezeManifest`, `ExposureLedger`, `ExclusionEvent`,
  `EvaluationRun`, and a `Report` view.
- Hashing and version-monotonicity logic; denominator-preservation logic.
- Validation surfaced through `check` (a violation is a failed check).
- The exclusion-event taxonomy and its miss-vs-invalid classification.
- The reporting split (blind recall headline; fixed-cohort recall; coverage;
  patched-alert density; adjudicated precision).

**Out of scope** (later, behind their own gates)

- The shared flow-analysis kernel and any new/edited detector (this contract must
  land first, then they are measured through it).
- The sealed cross-model evaluator infrastructure (encrypted bundle / separate
  UID or container). The contract defines the exposure ledger, freeze, and
  blind-access rules it must satisfy; the OS-level capability boundary is an ops
  layer built on top.
- The synthetic patch-shape robustness suite's *contents* (the contract only fixes
  its separation and its proof obligation).
- Adjudication tooling UX; the contract fixes the protocol, not the interface.

## User scenarios

1. **A cohort correction is a new version, not an edit.** Re-pinning a CVE to a
   verified patched commit produces cohort `v-next` with a reason; `v-prev` and its
   recorded results are immutable and still readable.
2. **A hard case cannot be dropped to raise a rate.** Removing a pinned entry
   without a logged exclusion event fails `check`; an unsupported-language entry
   counts as a miss, staying in the denominator.
3. **The blind set is touched once.** The harness records zero blind evaluations
   before freeze and refuses a second after; an infra retry is allowed only when no
   results were produced and hashes are unchanged.
4. **A curator cannot grade itself.** A model listed as curator/inspector of a
   cohort in the exposure ledger is refused as that cohort's scored subject.
5. **The report leads with blind.** Output shows blind recall as the headline plus
   distinct, labeled fixed-cohort recall, coverage, patched-alert density, and
   adjudicated precision — no single number is presented as "the" score.

## Functional requirements

- **FR-1 — Canonical entry identity.** Each `CohortEntry` carries an immutable
  identity hash over its canonical fields: `repo`, `vuln_ref`, `patched_ref`,
  sorted `target_paths`, `sink_probe`, and `status`/`drop_reason`. `check`
  recomputes and verifies it; a mismatch is a failed check.

- **FR-2 — Cohort versioning, history immutable.** A `Cohort` is content-addressed
  by its sorted entry-identity hashes plus a version tag. Any correction (seed
  swap, re-pin, `target_paths` change, CWE reclassification, drop) creates a new
  version with a reason; prior versions and their results are never mutated.
  `check` rejects an in-place change that alters an entry hash without a version
  bump (Constitution VII).

- **FR-3 — Denominator preservation.** The authoritative metric is
  blind-rediscovered / all-pinned. An entry leaves the denominator only through a
  logged `ExclusionEvent`; it is never silently removed. A detector miss and an
  unsupported-analysis outcome both count as a **miss inside the denominator**, not
  an exclusion.

- **FR-4 — Calibration / regression / blind separation.** Each entry has an
  explicit disjoint role: `calibration` (seed), `regression` (former miss), or
  `blind` (never tuned on). A `blind` entry that ever guides a fix is moved to
  `regression` in a new cohort version — never silently reused as blind.

- **FR-5 — Freeze bundle hash.** Before any evaluation, a `FreezeManifest` records
  a content hash over the whole executable bundle: detector and transitive analysis
  modules, rules/config, dependency lockfile, interpreter and parser versions,
  entrypoint and invocation parameters, and calibration-seed identity — committed
  and timestamped.

- **FR-6 — Exposure ledger (curator ≠ subject).** An `ExposureLedger` records which
  model/harness curated or inspected each cohort. `check` refuses to record a score
  for a subject that appears as a curator or inspector of that cohort; ownership
  rotates so no model's pool ever grades itself.

- **FR-7 — Blind-access discipline.** Zero blind-cohort evaluation attempts before
  freeze; exactly one semantic evaluation after freeze. The harness counts
  evaluation *attempts* and refuses a second. An infrastructure retry is permitted
  only if no detector results were produced, all logs remain, and artifact/
  environment hashes are unchanged.

- **FR-8 — Exclusion-event log.** Every exclusion is a typed, append-only
  `ExclusionEvent` with a reason drawn from a closed taxonomy: unsupported
  language/parser, detector crash, timeout, malformed SARIF, budget truncation,
  fetch failure, repository disappearance, `target_paths` drift, unverified
  patched-file deletion, CWE reclassification, duplicate CVE/GHSA alias, seed swap,
  post-freeze `drop_reason` change, `target_paths` narrowing, `sink_probe`
  alteration, triage/dedup suppression, `role-downgrade` (a blind entry legitimately
  moved out of the blind set, FR-4), `policy_refusal`, and no-artifact.
  **Infrastructure-class** events invalidate the run; **analysis-limitation**
  events count as a miss. No exclusion edits history.

- **FR-9 — Recall and precision are separate metrics.** Rediscovery (recall) is
  decided only by the line-precise sink-probe rule already in `corpus_measure.py`.
  Patched-alert density (flags/KLOC on the fixed tree) is reported as operational
  context and never decides recall. Adjudicated precision requires a blind
  confusion-pair sample seeded by `hash(cohort_hash, freeze_hash, run_id)`,
  adjudicated by two non-builder adjudicators (at least one non-curator), blinded
  to builder identity and expected outcome; **ambiguous counts against precision**;
  disagreement gets human resolution (Constitution VII).

- **FR-10 — Real-other-finding re-gating.** A patched-tree flag adjudicated
  "real-other-finding" becomes a *local candidate* that must re-enter a fresh
  authorization gate; it is never auto-investigated or disclosed (Constitution II).

- **FR-11 — Synthetic separation.** Synthetic patch-shape variants never aggregate
  into any real-CVE number and are reported only in a loudly-labeled robustness
  suite. Each variant requires class-appropriate proof it removes the vulnerability
  — static where possible; execution-based proof stays behind the Article III
  sandbox (Constitution III).

- **FR-12 — Achievability is an append-only diagnostic.** An optional per-entry
  achievability prediction is pre-registered and frozen before unseal, append-only.
  A later rediscovery falsifies the prediction without rewriting history and without
  implying the earlier detector should have caught it. Blind-rediscovered /
  all-pinned stays authoritative; blind-rediscovered / predicted-achievable is a
  labeled secondary only.

- **FR-13 — Blind-led reporting.** The headline is blind recall. Fixed-cohort
  recall, coverage, patched-alert density, and adjudicated precision are reported as
  distinct, labeled numbers. No single figure is presented as "the" score.

- **FR-14 — `check` enforces the contract.** `check` validates entry-hash
  integrity, version monotonicity, denominator preservation, the exposure ledger
  (curator ≠ subject), freeze presence before any recorded evaluation, and the
  blind-access counter (≤ 1 post-freeze, 0 pre-freeze). Any violation is a failed
  check (Constitution VII).

- **FR-15 — Cryptographic anchoring (a certified score cannot be fabricated).** A
  certified score is bound to a single **committed, signed attestation root**
  covering ALL state, so it cannot be forged even by an operator who controls
  storage. Stdlib-only, deterministic primitives (`hashlib`/`hmac`, no wall clock,
  no randomness) provide: `leaf_hash` (sha256 of canonical JSON), `merkle_root`
  (order-independent root over a sorted leaf set), `chain_root` (an append-only fold
  from a fixed genesis — dropping, reordering, or rewriting ANY entry changes it),
  and `sign`/`verify` (constant-time HMAC-SHA256; **production swaps HMAC for
  ed25519** with a published verify-key and the private signing key held by a party
  that is **not** the scored builder — curator ≠ subject). Every append-only surface
  exposes its root: `CohortHistory.history_root`, and `.root` on `ExclusionLog`,
  `ExposureLedger`, `EvaluationLedger`, `AchievabilityLog`. The freeze commits the
  confusion-pair `pool_root` before the precision seed is derivable; exposure records
  carry `curated_entry_ids` so exposure resolves by entry identity without
  re-supplying old cohort versions. A frozen `Attestation` binds every component root
  plus `freeze_hash`, `pool_root`, canonical `run_id`, `report_hash`, `evaluator_id`,
  and `attested_at`, and is signed over the Merkle `attestation_root`. `validate`
  gains keyword-only `attestation`, `verify_key`, and `strict`: on the certify path it
  RECOMPUTES every root from the presented objects and fails closed unless each equals
  the attestation's committed root (`ATTESTATION_MISMATCH`), the signature verifies
  (`ATTESTATION_INVALID` / `ATTESTATION_UNSIGNED`), and every referenced component is
  present (`ATTESTATION_INCOMPLETE`); a Report / producing run offered for
  certification with no signed attestation + verify-key is `UNANCHORED`. The
  anti-omission guarantee comes from "the presented state must reproduce the committed
  root"; the signature adds non-repudiation and tamper-evidence. The non-strict path is
  unchanged, so every prior call site is unaffected.

- **FR-16 — Numerator verification (the reported rediscoveries are RECOMPUTED, not
  trusted).** A pure validator cannot check that the reported numerator is TRUE — it
  never sees the detector run on the real code. `benchmarks/harness/verifier.py`
  closes this for the numerator: `recompute_rediscovered(blind_entries, *, fetch_fn,
  scan_fn)` re-runs the frozen detector's `scan_source` over the vulnerable AND patched
  target files (fetched at the pinned SHAs) and applies `corpus_measure.py`'s EXACT
  line-precise rule — a FLAGGED line whose own text contains the `sink_probe` in the
  vulnerable tree and NOT in the patched tree — returning the set of rediscovered blind
  entry identities. It is a pure function of the injected `fetch_fn` / `scan_fn`
  (deterministic unit tests inject fakes; one net-gated test re-runs a real detector on
  a real pinned pair, reusing `corpus_measure.py`'s GitHub-raw fetcher + cache). Strict
  certification requires `set(report.rediscovered_blind_ids) == recompute_rediscovered(…)`
  → else `NUMERATOR_UNVERIFIED`: the operator can no longer CLAIM a rediscovery the
  frozen detector did not produce on the real code, nor OMIT a real one. **SAFETY
  (Article III):** the detector reads fetched files as DATA (`scan_source` parses them,
  e.g. `ast.parse`); no target code is executed — the module never `eval`/`exec`/imports
  fetched content.

- **FR-17 — Git-anchored genesis + attestation chaining (genesis completeness moves to
  git).** A pure validator cannot verify GENESIS COMPLETENESS — that the committed
  baseline is not itself a truncated, self-serving starting point. That check moves OUT
  of the validator and into git: `benchmarks/harness/genesis_root.json`
  (`{genesis_history_root, committed_at, note}`) is a committed, reviewable file whose
  git history supplies the external timestamp and review the validator cannot;
  `load_committed_genesis_root()` reads it. `Attestation` gains a required
  `prior_attestation_root` folded into `attestation_root`, chaining each certification
  to its committed predecessor. Strict certification requires the chain BASE (no
  `prior_history`) to root in the committed genesis → else `GENESIS_UNANCHORED`, and a
  chain EXTENSION (with `prior_history`) to append-only-EXTEND the prior committed
  history → else `ATTESTATION_NOT_EXTENDING` — so no operator can silently re-anchor a
  chain to a fresh, private genesis. Certification additionally requires a producing
  evaluation (`semantic_evaluation_count == 1`, else `CERTIFY_WITHOUT_EVALUATION`), the
  headline `adjudicated_precision` to be bound to a real `AdjudicatedPrecision` (else
  `PRECISION_UNBOUND`) whose `k` equals the freeze-committed `committed_k` (else
  `PRECISION_SAMPLE_UNBOUND`), and the certifier `evaluator_id` to differ from the
  scored subject (else `CURATOR_IS_SUBJECT`). **The remaining residual is documented,
  not code-closable:** the completeness of what the curator commits at genesis
  (reviewable in git) and key custody — that the private signing key is held by a party
  that is not the subject (organizational; the in-band `evaluator_id != subject` half is
  enforced).

- **FR-18 — Verifications RUN from committed state, never from caller args (the round-4
  layer was opt-in).** ONE governing principle hardens the whole certify path: **a trusted
  value or a verification RESULT must NEVER be a caller argument the scored party could
  forge.** `validate()` RUNS each verification itself and LOADS every trusted root / key /
  detector from COMMITTED, git-tracked state via module-level, monkeypatchable registries /
  loaders — not caller args — and every completeness input a strict certify needs is
  MANDATORY and resolved from committed state (omission or an inert default FAILS CLOSED).
  Concretely: the `recomputed_rediscovered` and `verify_key` parameters are REMOVED; strict
  certify RUNS `verifier.recompute_certified_numerator` (resolving the detector from a
  committed `DETECTOR_REGISTRY` keyed by the frozen `detector_id` and the fetcher from the
  committed `FETCH_FN`) and verifies the signature with the committed evaluator verify-key +
  evaluator id (`ATTESTATION_INVALID`); `genesis_root.json` is a REAL, non-empty, MONOTONIC
  committed chain (`genesis_history_root` + `latest.{history_root, attestation_root}`) that
  the presented history must append-only-EXTEND (`ATTESTATION_NOT_EXTENDING`) and the
  attestation chain from (`GENESIS_UNANCHORED`), advanced only via `advance_committed_root`;
  the exposure ledger + prior evaluations + a non-inert `pool_root` / `committed_k` are
  MANDATORY (`MISSING_LEDGER` / `PRECISION_SAMPLE_UNBOUND`); the freeze binds the PRODUCING
  attempt (`BAD_FREEZE_BINDING`); and a certified report must not carry a free
  `achievable_recall` (`ACHIEVABLE_UNBOUND`). **The FINAL residual is exactly (i)
  genesis-commit completeness (git-reviewable) and (ii) physical key custody (curator ≠
  subject, organizational)** — everything else a validator can run, it now runs from
  committed state.

## Acceptance criteria

1. An entry whose canonical fields change without a new identity hash fails `check`.
   (FR-1)
2. Editing an entry in place without a version bump fails `check`; a correction that
   creates a new version passes and leaves the prior version and its results
   readable and unchanged. (FR-2)
3. Removing a pinned entry without a logged `ExclusionEvent` fails `check`; an
   unsupported-analysis entry is scored as a miss and stays in the denominator.
   (FR-3, FR-8)
4. A `blind` entry reused after it guided a fix fails `check` unless it was moved to
   `regression` in a new version. (FR-4)
5. Recording an evaluation with no `FreezeManifest` fails `check`; the freeze hash
   changes when any bundle component (parser version, lockfile, params) changes.
   (FR-5)
6. Scoring a subject that appears as curator/inspector of the cohort fails `check`.
   (FR-6)
7. A second post-freeze blind evaluation is refused; a pre-freeze blind evaluation
   is refused; a permitted infra retry requires unchanged hashes and intact logs.
   (FR-7)
8. Each exclusion taxonomy member is typed; infrastructure-class events mark the run
   invalid, analysis-limitation events mark a miss; the log is append-only. (FR-8)
9. Recall is unchanged by patched-alert density; precision requires the seeded blind
   sample with ambiguous-counts-against and two adjudicators (≥ 1 non-curator).
   (FR-9)
10. A "real-other-finding" adjudication produces a candidate requiring a fresh
    authorization gate and is never auto-investigated. (FR-10)
11. Synthetic variants never enter any real-CVE aggregate and each carries a
    removal proof; execution-based proofs are gated behind the sandbox. (FR-11)
12. An achievability prediction is append-only and pre-freeze; a later rediscovery
    falsifies it without altering historical results; the authoritative rate stays
    blind/all-pinned. (FR-12)
13. `report` emits five distinct labeled numbers with blind recall as the headline.
    (FR-13)
14. `check` fails on each of: bad entry hash, non-monotone version, silent
    denominator shrink, curator==subject, missing freeze, blind-access > 1. (FR-14)

### Adversarial-audit acceptance criteria (the enforcement floor)

A 4-lens red-team of `validate()` found that the honesty invariants lived only in
constructor helpers (bypassed when a model is rebuilt from storage) and that
`validate()` never consulted `ExclusionClass` — so it accepted dishonest
measurements as `report.ok == True`. These criteria pin the now-enforced behaviour;
each maps to a threat-model leak vector and has a dedicated regression test
(`test_h1`..`test_h9` in `benchmarks/tests/test_evaluation_contract.py`). `validate()`
gained keyword-only, optional params (`freeze`, `report`, `precision`,
`achievability`, `prior_exclusions`, `prior_achievability`); every prior call site is
unchanged.

15. **(H1, L1)** A denominator removal is legitimized ONLY by a
    `COHORT_CORRECTION`-class event. A removal "covered" by an
    `ANALYSIS_LIMITATION` (e.g. `unsupported-language`), `INFRASTRUCTURE`, or
    `POLICY_REFUSAL` event still fails `check` with `DENOMINATOR_SHRINK`. (FR-3, FR-8)
16. **(H2, FR-8 infra rule)** Any `INFRASTRUCTURE`-class exclusion event fails
    `check` with `RUN_INVALID` — infrastructure failure invalidates the run rather
    than quietly leaving the denominator.
17. **(H3, L8)** A run-level reason (`POLICY_REFUSAL` / `INFRASTRUCTURE`) that carries
    an `entry_identity` is rejected at the type boundary — those reasons are never
    per-entry deletions.
18. **(H4, L1/L10)** A `COHORT_CORRECTION` event authorizes exactly its named
    `(entry_identity, from_version, to_version)` transition; a stale `v1→v2` event
    cannot launder a later `v3→v4` removal of the same re-added identity
    (`DENOMINATOR_SHRINK`).
19. **(H5, L4)** The infra-retry invariant is enforced in `validate()`, not only in
    `attempt_evaluation`: a run rebuilt from storage whose post-freeze attempts have
    broken logs or changed artifact/env hashes fails `check` with
    `INFRA_RETRY_REQUIRES_UNCHANGED`.
20. **(H6, L2/L4)** A supplied `FreezeManifest` binds the run: `run.freeze_hash` must
    equal the frozen bundle hash (`BAD_FREEZE_BINDING`), and calibration seeds must be
    disjoint from the scored cohort's blind entries (`SEED_IN_BLIND`).
21. **(H7, L1/L9)** A supplied `Report` is bound to the frozen cohort:
    `blind_recall.total` is recomputed from the cohort's BLIND entries, and the
    rediscovered set must be a subset of the actual blind identities with a matching
    count; otherwise `REPORT_DENOMINATOR_MISMATCH`.
22. **(H8, L6)** Adjudicated precision requires full coverage (every seeded pair
    adjudicated) and a seed/sample bound to `precision_sample_seed` /
    `sample_confusion_pairs`; an unfavorable-subset adjudication or a re-rolled sample
    is rejected, and routing through `validate()` rejects a precision bound to a
    different run context (`PRECISION_SAMPLE_UNBOUND`).
23. **(H9, L8)** The achievability log is sealed and append-only enforced by
    `validate()`: a prediction registered at/after the freeze timestamp
    (`ACHIEVABILITY_NOT_PRE_FREEZE`) or an in-place rewrite of a sealed log
    (`IN_PLACE_EDIT`) is rejected even when it bypassed `append`.

### Round-2 adversarial-audit acceptance criteria (the second wave)

A second red-team of `validate()` — run after the H1..H9 seals held — found a
second wave of holes governed by two principles: **P1** no binding check is
skippable by omitting a sibling argument or leaving an `Optional` `None`; **P2**
every denominator-affecting field is sealed into a content hash AND preserved across
versions via a matched `COHORT_CORRECTION` event. Each maps to a dedicated
regression test (`test_r1`..`test_r8`). `validate()` gained two more keyword-only,
optional baselines (`prior_history`, `prior_evaluations`); `AdjudicatedPrecision.pool`
/ `.k` became mandatory and `EvaluationRun.run_id` became the canonical
`sha256(cohort | freeze | subject)` — intended tightenings, so the existing tests and
`scripts/smoke_008.sh` were updated to the honest bound form.

24. **(R1, L1)** `role` and `guided_fix` are sealed into `Cohort.computed_content_hash`.
    An in-place role/`guided_fix` flip on a sealed cohort (shrinking the blind-role
    denominator or dodging AC-4 with no version bump) breaks the seal → `IN_PLACE_EDIT`.
    They remain OUTSIDE entry *identity*, so a role move across a new version preserves
    identity.
25. **(R2, L1)** Denominator preservation is BLIND-SET preserving, not merely
    identity-set preserving. An identity that leaves the blind set — by removal OR by a
    role-downgrade that keeps its identity — needs a `COHORT_CORRECTION` event matched to
    the exact `(identity, from_version, to_version)` transition, else `DENOMINATOR_SHRINK`.
26. **(R3, L1/L10)** With a `prior_history` baseline, the presented history must be an
    append-only extension: every baseline version appears at the same index with an
    identical content hash. A from-storage rebuild that drops an earlier version
    (`HISTORY_TRUNCATED`) or rewrites one in place (`IN_PLACE_EDIT`) is rejected.
27. **(R4, L1/L9, P1)** A `Report`'s numerator + cohort binding are MANDATORY. When a
    cohort resolves, `rediscovered_blind_ids` must be present (a free-int headline is
    unverifiable) — `REPORT_DENOMINATOR_MISMATCH` otherwise; a `Report` with no cohort to
    bind against is `REPORT_UNBOUND`, never a silent pass.
28. **(R5, L4)** `EvaluationRun.run_id` must equal the canonical
    `sha256(cohort_content_hash | freeze_hash | subject)` (`NON_CANONICAL_RUN_ID`), so the
    precision sample cannot be re-rolled via a fresh run_id; an append-only
    `EvaluationLedger` (`prior_evaluations` baseline) flags a second evaluation of the same
    `(cohort, freeze, subject)` → `EVALUATED_MORE_THAN_ONCE`.
29. **(R6, L4, P1)** A run that recorded post-freeze attempts but is validated with no
    `FreezeManifest` fails with `MISSING_FREEZE` — a fabricated `run.freeze_hash` cannot
    stand in for the freeze.
30. **(R7, L5)** Exposure resolves by ENTRY IDENTITY across versions, not by the
    version-scoped content hash: a curator/inspector of ANY cohort version sharing an entry
    identity with the scored cohort is barred (`CURATOR_IS_SUBJECT`) — a version bump cannot
    launder a curator into a subject.
31. **(R8, L6, P1)** `AdjudicatedPrecision.pool`/`.k` are mandatory and the sample is
    ALWAYS verified to be `sample_confusion_pairs(pool, k, seed)`; a hand-picked favorable
    subset is rejected at the type boundary, and a precision presented with no run/freeze to
    bind to is `PRECISION_SAMPLE_UNBOUND`.

### Round-3 acceptance criteria (Class-1 silent-bug seals + cryptographic anchoring)

A third red-team found a batch of **Class-1** holes — each fakeable in a single
honest `validate()` call, independent of storage — and motivated closing the
**Class-2** "omit the baseline" class outright with cryptographic anchoring (FR-15).
Each maps to a dedicated regression test (`test_a1`..`test_a6`, `test_b1`..`test_b5`).
Intended tightenings (a produced run must present a Report; the precision pool must be
canonical sorted-unique with a minimum k; certification requires a signed attestation)
updated the honest object-builders and `scripts/smoke_008.sh`, never by weakening a
check.

32. **(A1, L1/L9)** A `Report` denominates against exactly the RUN's evaluated cohort:
    when a run is present the binding cohort is resolved from `run.cohort_content_hash`
    FIRST, and a report bound to a different (e.g. easier, earlier) cohort than the run
    evaluated is `REPORT_DENOMINATOR_MISMATCH`; with no run, a report may only bind to the
    latest version.
33. **(A2, L8)** A run that demonstrably produced results cannot be laundered to N/A by a
    run-level `POLICY_REFUSAL` exclusion (`POLICY_REFUSAL_ON_PRODUCED_RUN`), and a produced
    run that presents no bound `Report` is `REPORT_UNBOUND`.
34. **(A3, L4)** Evaluate-once is BLIND-SET scoped, not freeze scoped: an
    `EvaluationRecord` carries the scored cohort's blind entry identities, and a second
    evaluation whose blind identities overlap any prior record's blind set for the same
    subject — even under a fresh `freeze_hash` from a trivial re-freeze — is
    `BLIND_REEVALUATED`.
35. **(A4, L2/L4)** The evaluated artifact is bound to the freeze: the first post-freeze
    `EvalAttempt.freeze_hash` must equal the frozen bundle hash, else `BAD_FREEZE_BINDING`
    — you cannot freeze bundle B and evaluate an unrelated B'.
36. **(A5, L4)** `validate()` mirrors the record-time ordering invariant: a from-storage
    run in which a producing post-freeze attempt is not the terminal one (an attempt follows
    a producing evaluation) is `BLIND_ACCESS_EXCEEDED`.
37. **(A6, L6)** The precision pool is canonicalized: `sample_confusion_pairs` draws from
    `sorted(set(pool))`, and `AdjudicatedPrecision` requires `pool == sorted(set(pool))`
    (unique, sorted) plus a minimum `k` relative to `|pool|` — so a public deterministic seed
    cannot be gamed by permuting the pool.
38. **(B1, L1/L10)** `CohortHistory.history_root` is an append-only `chain_root` over the
    version content hashes; omitting, reordering, or truncating any version changes the root.
39. **(B2, L1/L8/L10)** `ExclusionLog`, `ExposureLedger`, `EvaluationLedger`, and
    `AchievabilityLog` each expose a `chain_root` over their entries; rewriting or dropping
    any entry changes the root.
40. **(B3, L5)** Exposure resolves by entry identity via `ExposureRecord.curated_entry_ids`
    without re-supplying old cohort versions; a subject whose scored blind identities intersect
    a curated set is barred, and an unresolvable exposure record whose actor == subject is a
    HARD FAILURE (`CURATOR_IS_SUBJECT`), never a silent skip.
41. **(B4, L6)** The freeze commits `pool_root` (a Merkle root over the canonical pool) before
    the seed is derivable, and precision binding requires the presented pool to reproduce it —
    membership is pinned, so the sample is a pure function of committed membership.
42. **(B5, L1/L4/L9/L10)** A frozen, signed `Attestation` binds every component root; the
    strict/certify path RECOMPUTES each root and fails closed unless all match
    (`ATTESTATION_MISMATCH`), the signature verifies (`ATTESTATION_INVALID` /
    `ATTESTATION_UNSIGNED`), and every referenced component is present
    (`ATTESTATION_INCOMPLETE`); certification with no signed attestation + verify-key is
    `UNANCHORED`. A forged signature, an omitted/tampered history version, a rewritten ledger
    entry, and a swapped pool are each rejected; a fully honest signed attestation is accepted.

### Round-4 acceptance criteria (out-of-contract verification — attack the irreducible floor)

An audit proved the residual an in-contract validator cannot reach: it cannot verify
genesis completeness, input truthfulness (is the reported numerator TRUE?), or key
custody. Round-4 attacks that floor with measures OUTSIDE the pure validator (FR-16
verifier, FR-17 git-anchored genesis). Each maps to a dedicated regression test
(`test_p1a`..`test_p1e`, `test_part2_*`, `test_part3_*` in
`test_evaluation_contract.py`; the verifier's own tests in `test_verifier.py`). The
honest object-builders and `scripts/smoke_008.sh` were updated to construct the new
bound form, never by weakening a check.

43. **(P1a/FR-17)** `Attestation` carries a required `prior_attestation_root` folded into
    `attestation_root`. On the strict certify path a chain EXTENSION (with `prior_history`)
    must append-only-extend the prior committed history, else `ATTESTATION_NOT_EXTENDING`;
    an honest superset extension is accepted.
44. **(P1b/FR-17)** Certification requires exactly one producing post-freeze evaluation
    (`semantic_evaluation_count == 1`); a Report certified against a run with no producing
    evaluation is `CERTIFY_WITHOUT_EVALUATION`.
45. **(P1c/FR-17)** The certified `report.adjudicated_precision` must be bound to a presented,
    panel-validated `AdjudicatedPrecision` with an equal `precision`; a free float with no
    adjudication, or a bound value that disagrees, is `PRECISION_UNBOUND`.
46. **(P1d/FR-17)** The freeze commits the precision sample size `committed_k` (inside the
    bundle hash, before the seed is derivable); a precision whose `k` differs is
    `PRECISION_SAMPLE_UNBOUND`.
47. **(P1e/FR-17)** The certifier `attestation.evaluator_id` must differ from the scored
    `run.subject`, else `CURATOR_IS_SUBJECT` (the code-checkable half of key custody; the
    private-key holder remains an organizational, documented boundary).
48. **(PART 2/FR-16)** The numerator is RECOMPUTED, not trusted: strict certification requires
    `set(report.rediscovered_blind_ids)` to equal `recompute_rediscovered(blind, fetch_fn,
    scan_fn)` (the frozen detector re-run on the real pinned SHAs, line-precise rule); a claim
    the recompute does not confirm, an omission of a real rediscovery, or a missing recompute is
    `NUMERATOR_UNVERIFIED`. The detector reads fetched files as DATA only (Article III intact).
49. **(PART 3/FR-17)** `benchmarks/harness/genesis_root.json` is a git-committed genesis root;
    `load_committed_genesis_root()` reads it. A chain BASE whose `prior_attestation_root` is not
    the committed genesis is `GENESIS_UNANCHORED`; the honest chain rooted in it is accepted.

### Round-5 acceptance criteria (RUN from committed state — the round-4 layer was opt-in)

An audit proved the round-4 verification layer was bypassable because it was built as
OPT-IN / CALLER-SUPPLIED inputs. Round-5 applies ONE governing principle (FR-18): a trusted
value or a verification RESULT must never be a caller argument the scored party could forge;
`validate()` RUNS each verification and LOADS every trusted root / key / detector from
COMMITTED state. Each maps to a dedicated regression test (`test_r5_1`..`test_r5_6`, the
rewritten `test_part2_*` / `test_part3_*` / `test_b5_*` / `test_p1*`, and
`test_verifier.py`); the honest object-builders and `scripts/smoke_008.sh` were updated to
the committed-state form, never by weakening a check.

50. **(R5-1/FR-18)** The `recomputed_rediscovered` parameter is REMOVED; strict certify RUNS
    `verifier.recompute_certified_numerator`, resolving `scan_fn` from a committed
    `DETECTOR_REGISTRY` keyed by the frozen `detector_id` and `fetch_fn` from the committed
    `FETCH_FN`. A claim the recompute does not confirm, an omission, or an unresolvable
    detector is `NUMERATOR_UNVERIFIED`. Registry + fetcher are monkeypatchable; the net-gated
    real re-run stays.
51. **(R5-2/FR-18)** `genesis_root.json` holds a REAL non-empty `genesis_history_root` +
    `latest.{history_root, attestation_root}`; `load_committed_genesis_root()` returns the
    latest attestation root. The presented history must reproduce + append-only-extend the
    COMMITTED prior history root (`ATTESTATION_NOT_EXTENDING`) and the attestation chain from
    the committed latest attestation root (`GENESIS_UNANCHORED`); `prior_history` is never
    caller-trusted on the certify path. `advance_committed_root(...)` persists the advance and
    leaves `genesis_history_root` immutable.
52. **(R5-3/FR-18)** On strict certify the exposure ledger + prior evaluations are MANDATORY
    (`MISSING_LEDGER`) and `pool_root` (non-empty) / `committed_k` (≥ min(|pool|, 2)) are
    MANDATORY (`PRECISION_SAMPLE_UNBOUND`); the round-4 `if … is not None` opt-in guards are
    removed.
53. **(R5-4/FR-18)** The verify-key + evaluator id are LOADED from committed config; the
    `verify_key` parameter is REMOVED. A subject-minted key, or an evaluator id that is not
    the committed one, fails `ATTESTATION_INVALID`; `evaluator_id == subject` is
    `CURATOR_IS_SUBJECT`.
54. **(R5-5/FR-18)** The freeze binds the PRODUCING post-freeze attempt (not only
    `attempts[0]`): a producing attempt with a forged `freeze_hash` is `BAD_FREEZE_BINDING`.
55. **(R5-6/FR-18)** A certified report must not carry a free `achievable_recall`
    (`ACHIEVABLE_UNBOUND`); it stays a labelled diagnostic for non-certified reports.

## Open questions

- **Non-blocking.** Does the contract live in a new `benchmarks/harness/contract.py`
  or extend `roundrecord.py`? Lean: a new module, with `Snapshot`/`ClassRate`
  refactored to reference `CohortEntry` identity.
- **Non-blocking.** Is enforcement surfaced through the main `deepthought check` or a
  dedicated `benchmarks` check entrypoint? Lean: a benchmarks check that the main
  check invokes, so one command still gates everything.
- **Non-blocking.** In a mostly single-operator setting, who are the two non-builder
  adjudicators — distinct models, or one model plus the human? Fix the protocol here;
  defer the roster.
- **Non-blocking.** How does the freeze hash pin `parser versions` portably across
  machines (e.g. tree-sitter grammar builds)? Record the resolved versions in the
  manifest and treat a change as a new freeze.

## Success criteria

A smoke (`scripts/smoke_008.sh`) builds a two-entry cohort `v1` (reproducing the
committed `genesis_history_root`), freezes a dummy detector (committing the confusion
`pool_root` and the precision `committed_k`), records exactly one blind evaluation, binds
a `Report` and a panel-adjudicated precision, installs a fake frozen detector + fetcher
into the COMMITTED module-level `DETECTOR_REGISTRY` / `FETCH_FN` so `validate()` RUNS the
numerator recompute itself (FR-16/FR-18 — no caller `recomputed_rediscovered`), builds and
SIGNS an `Attestation` with the COMMITTED evaluator key + id chained to the committed
latest attestation root (FR-17/FR-18 — no caller `verify_key`), and passes strict
certification; then demonstrates each guard failing: an in-place entry edit, a silent
denominator shrink, a second blind evaluation, and a curator==subject score, plus the
cryptographic-anchoring fail-closed cases — a forged signature (`ATTESTATION_INVALID`, now
verified against the committed key), an omitted component (`ATTESTATION_INCOMPLETE`), and a
certify path with no attestation (`UNANCHORED`) — plus the out-of-contract guards: a
numerator the committed detector does not reproduce (`NUMERATOR_UNVERIFIED`, via swapping in
a fake detector that reproduces nothing) and a chain base not rooted in the committed
genesis (`GENESIS_UNANCHORED`) — each fail `check` with a typed reason. The `report` view
prints blind recall as the headline alongside the four labeled secondaries. Only after this
gate is green does the shared-kernel work in the tranche begin.
