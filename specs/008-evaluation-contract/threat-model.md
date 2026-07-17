# Threat model — Evaluation Contract (008)

The threat here is not an attacker; it is **honest numbers quietly drifting**. A
benchmark degrades when an exclusion happens without a record: a hard case is
dropped, a cohort is re-pinned easier, a "blind" set is peeked at, a curator grades
its own work. This model enumerates the exclusion-leak vectors a cross-model review
(Claude + Sol / GPT-5.6) surfaced and maps each to the requirement that seals it.
The unifying rule: **every exclusion is a logged, reviewable, versioned event.**

## Exclusion-leak vectors → mitigations

| # | Leak | How the score drifts up | Sealed by |
|---|---|---|---|
| L1 | Drop a hard case | Denominator shrinks; rate rises | FR-3 denominator preservation; FR-8 exclusion log; AC-3 |
| L2 | Re-pin to an easier commit | Same class, weaker ground truth | FR-1 identity hash over `vuln_ref`/`patched_ref`; FR-2 version bump; AC-2 |
| L3 | Narrow `target_paths` / edit `sink_probe` | Detector's easy region only | FR-1 (both are canonical fields); AC-1 |
| L4 | Peek at the blind set while tuning | Blind becomes a tuning oracle | FR-7 zero pre-freeze, one post-freeze; AC-7 |
| L5 | Curator scores its own cohort | Subject has seen the answers | FR-6 exposure ledger, curator ≠ subject; AC-6 |
| L6 | Call patched-tree flags "false positives" | Inflates precision, or hides a real other bug | FR-9 recall/precision split + blind adjudication; FR-10 re-gate real-other-finding; AC-9, AC-10 |
| L7 | Slip synthetic mutations into the CVE metric | Real-code ground truth diluted | FR-11 synthetic separation + removal proof; AC-11 |
| L8 | Reclassify a miss as "unachievable" | Exclusion wearing a taxonomy | FR-12 append-only, falsifiable, authoritative stays all-pinned; AC-12 |
| L9 | Headline the fixed-cohort or achievable number | Inflation we already exposed | FR-13 blind-led reporting; AC-13 |
| L10 | Silent history edit on correction | Old results rewritten to match | FR-2 immutable versions; AC-2 |

## Two classification rules that do the heavy lifting

- **Unsupported analysis counts as a MISS**, inside the denominator — not an
  exclusion. "We don't parse this language" is a capability gap, not a reason the
  case stops counting. (FR-3, FR-8)
- **Infrastructure failure INVALIDATES the run** — it does not silently leave the
  denominator. Fetch failure, crash, timeout, malformed SARIF, budget truncation,
  repo disappearance are infrastructure-class `ExclusionEvent`s that block the run;
  they never quietly shrink the denominator. (FR-8, FR-7 infra-retry rule)

Any legitimate cohort correction creates a **new cohort version**; it never edits
history (FR-2).

## Enforcement is in `validate()`, not just the constructors (adversarial audit)

A 4-lens red-team of `validate()` found the leak vectors above were sealed only by
**constructor helpers** (`attempt_evaluation`, `ExclusionLog.append`,
`AchievabilityLog.append`, the panel validators) — every one of which is **bypassed
when a model is rebuilt from storage** — and that `validate()` never consulted
`ExclusionClass` at all. So a run reconstructed from persisted JSON could present a
dropped hard case, a cherry-picked blind evaluation, a re-rolled precision sample, or
a rewritten achievability log and still return `report.ok == True`. The gate now
re-derives and enforces these invariants itself (regression tests `test_h1`..`test_h9`):

| Hole | Leak it re-opened | Now sealed in `validate()` by |
|---|---|---|
| H1 | L1 — a miss/infra/policy event "authorizing" a removal | removal legitimized ONLY by a `COHORT_CORRECTION`-class event (`DENOMINATOR_SHRINK`) |
| H2 | infra rule — infra exclusion silently ignored | any `INFRASTRUCTURE`-class event ⇒ `RUN_INVALID` |
| H3 | L8 — run-level reason posing as a per-entry deletion | `POLICY_REFUSAL` / `INFRASTRUCTURE` must carry no `entry_identity` |
| H4 | L1/L10 — a stale event laundering a later removal | correction events matched to the exact `(identity, from, to)` transition and consumed |
| H5 | L4 — a from-storage run cherry-picking blind evals | infra-retry invariant mirrored from `attempt_evaluation` (`INFRA_RETRY_REQUIRES_UNCHANGED`) |
| H6 | L2/L4 — a free-string freeze / a seed inside blind | `run.freeze_hash == bundle hash` (`BAD_FREEZE_BINDING`); seeds disjoint from blind (`SEED_IN_BLIND`) |
| H7 | L1/L9 — a free-int blind denominator under-reporting | blind total recomputed from the frozen cohort's blind entries (`REPORT_DENOMINATOR_MISMATCH`) |
| H8 | L6 — dropping unfavorable pairs / re-rolling the sample | coverage + seed/sample bound to `precision_sample_seed` (`PRECISION_SAMPLE_UNBOUND`) |
| H9 | L8 — a rewritten "unachievable" reclassification | log sealed + append-only; post-freeze registration rejected (`ACHIEVABILITY_NOT_PRE_FREEZE` / `IN_PLACE_EDIT`) |

The new `validate()` parameters (`freeze`, `report`, `precision`, `achievability`,
`prior_exclusions`, `prior_achievability`) are keyword-only and optional, so the seal
is additive: existing callers are unaffected, and a caller that passes the artifacts
gets them checked.

## Second wave (round-2 adversarial audit)

A second red-team, run after the H1..H9 seals held, found a second wave of holes.
Two governing principles drove the fixes, applied systematically rather than only to
the listed repros:

- **P1 — no skippable binding.** If a `Report` / `AdjudicatedPrecision` /
  `FreezeManifest` / `EvaluationRun` is present, its binding checks are MANDATORY and
  must not be dodged by omitting a sibling argument or leaving an `Optional` `None`.
- **P2 — seal every denominator-affecting field.** Anything that changes the
  authoritative blind denominator or the numerator is sealed into a content hash (so
  in-place edits break the seal) AND preserved across versions via a logged, matched
  `COHORT_CORRECTION` event.

| Hole | Leak it re-opened | Now sealed in `validate()` by |
|---|---|---|
| R1 | L1 — in-place role/`guided_fix` flip shrinking the blind-role denominator with no version bump | `role`+`guided_fix` sealed into `Cohort.computed_content_hash` ⇒ `IN_PLACE_EDIT` |
| R2 | L1 — a cross-version BLIND→regression downgrade (identity kept) shrinking the blind set with no event | preservation is BLIND-SET preserving; a matched `COHORT_CORRECTION` (e.g. `role-downgrade`) required ⇒ `DENOMINATOR_SHRINK` |
| R3 | L1/L10 — a from-storage rebuild dropping an earlier version (single version dodges the consecutive-pair check) | `prior_history` baseline: history must be an append-only extension ⇒ `HISTORY_TRUNCATED` / `IN_PLACE_EDIT` |
| R4 | L1/L9 — a `Report` with an unbound numerator (`rediscovered_blind_ids=None`) or no cohort to bind | numerator + cohort binding MANDATORY (P1) ⇒ `REPORT_DENOMINATOR_MISMATCH` / `REPORT_UNBOUND` |
| R5 | L4 — a re-rollable free-string run_id re-drawing the precision sample; "evaluate N, keep the best" | canonical `run_id = sha256(cohort|freeze|subject)` (`NON_CANONICAL_RUN_ID`) + append-only `EvaluationLedger` (`EVALUATED_MORE_THAN_ONCE`) |
| R6 | L4 — a fabricated `run.freeze_hash` standing in for a real freeze | freeze mandatory for any run with post-freeze attempts (P1) ⇒ `MISSING_FREEZE` |
| R7 | L5 — a version bump laundering a curator into a subject (same entries, new hash) | exposure resolved by ENTRY IDENTITY across versions ⇒ `CURATOR_IS_SUBJECT` |
| R8 | L6 — a hand-picked favorable subset with `pool`/`k` omitted; a precision with no run/freeze | `pool`/`k` mandatory, draw ALWAYS verified; unbound precision ⇒ `PRECISION_SAMPLE_UNBOUND` |

The two additional `validate()` parameters (`prior_history`, `prior_evaluations`) are
likewise keyword-only and optional. Making `AdjudicatedPrecision.pool`/`.k` mandatory
and `EvaluationRun.run_id` canonical are intended tightenings of the honest bound
form; the existing tests and `scripts/smoke_008.sh` were updated to construct these
objects correctly, never by weakening a check.

## Sealing note (for the later cross-model evaluator)

The exposure ledger and freeze manifest are the in-contract guarantees. The OS-level
boundary they presuppose is out of scope here but stated so it is not forgotten: a
separate git worktree is **insufficient**, because a builder agent runs as the same
OS user and could read a cohort on disk. The evaluator cohort needs a capability
boundary — an encrypted bundle or an evaluator-only mount, ideally a separate UID or
container, with the decryption key never present in the builder environment. The
builder receives only the class contract, one calibration seed, the detector
interface, and regression fixtures. After the builder freezes, its environment is
hash-frozen and copied read-only to the evaluator, which unseals and evaluates once.

A `policy_refusal` (a builder declining on policy grounds) is recorded as a
task-completion failure with detector score **N/A** — never 0, which would falsely
imply a detector was measured.
