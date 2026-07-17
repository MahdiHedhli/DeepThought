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
  alteration, triage/dedup suppression, `policy_refusal`, and no-artifact.
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

A smoke (`scripts/smoke_008.sh`) builds a two-entry cohort `v1`, freezes a dummy
detector, records exactly one blind evaluation, and passes `check`; then
demonstrates each guard failing: an in-place entry edit, a silent denominator
shrink, a second blind evaluation, and a curator==subject score each fail `check`
with a typed reason. The `report` view prints blind recall as the headline
alongside the four labeled secondaries. Only after this gate is green does the
shared-kernel work in the tranche begin.
