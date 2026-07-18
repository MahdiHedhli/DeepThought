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

## Third wave (round-3): Class-1 silent bugs SEALED, Class-2 CLOSED by anchoring

A third red-team separated the residue into two classes:

- **Class-1 — fakeable in a single honest `validate()` call**, independent of
  storage. These are outright bugs and are now sealed regardless of anchoring
  (regression tests `test_a1`..`test_a6`):

| Hole | Leak it re-opened | Now sealed in the contract by |
|---|---|---|
| A1 | L1/L9 — a Report pointing at an easier earlier cohort than the run evaluated | Report denominates against the RUN's cohort first; a mismatch ⇒ `REPORT_DENOMINATOR_MISMATCH` |
| A2 | L8 — a produced run laundered to N/A by `POLICY_REFUSAL`; a produced run carrying no Report | `POLICY_REFUSAL_ON_PRODUCED_RUN`; a produced run must present a bound Report ⇒ `REPORT_UNBOUND` |
| A3 | L4 — "freeze once, evaluate N, keep the best" via a trivial re-freeze | evaluate-once is BLIND-SET scoped (the record carries the scored blind identities) ⇒ `BLIND_REEVALUATED` |
| A4 | L2/L4 — freeze bundle B, evaluate B' (no attempt tied to the freeze) | the first post-freeze `EvalAttempt.freeze_hash` must equal the frozen bundle hash ⇒ `BAD_FREEZE_BINDING` |
| A5 | L4 — a from-storage `[produced, retry]` bypassing the record-time ordering guard | a producing attempt that is not terminal ⇒ `BLIND_ACCESS_EXCEEDED` in `validate()` |
| A6 | L6 — permuting a public-seed pool so favorable pairs land at sampled indices | the sample draws from `sorted(set(pool))` and the pool must be canonical (unique, sorted) with a minimum `k` |

- **Class-2 — the "omit / truncate / rewrite / reorder the baseline" class**, which
  an earlier wave only made *fail closed*. Round-3 makes it **impossible** with
  cryptographic anchoring (FR-15; regression tests `test_b1`..`test_b5`). A certified
  score is bound to one committed, signed `attestation_root`; `validate(strict=…)`
  RECOMPUTES every component root from the presented objects and refuses unless they
  all reproduce the committed roots AND the signature verifies:

| Anchor | Leak it closes | Mechanism |
|---|---|---|
| B1 | L1/L10 — truncate/omit/reorder a cohort version | `CohortHistory.history_root` = append-only `chain_root` of version hashes |
| B2 | L1/L8/L10 — rewrite/drop a ledger or log entry | `.root` = `chain_root` on `ExclusionLog` / `ExposureLedger` / `EvaluationLedger` / `AchievabilityLog` |
| B3 | L5 — a version bump laundering a curator, or a silently-skipped unresolvable record | exposure resolves by `curated_entry_ids` (entry identity); an unresolvable record with actor == subject is a HARD FAIL |
| B4 | L6 — swapping the confusion-pool membership | the freeze commits `pool_root` before the seed is derivable; precision must reproduce it |
| B5 | L1/L4/L9/L10 — omit/rewrite/re-point ANY component of a certified score | a signed `Attestation` binds every root; strict certify ⇒ `ATTESTATION_MISMATCH` / `ATTESTATION_INVALID` / `ATTESTATION_INCOMPLETE` / `UNANCHORED` |

**The anti-omission property does NOT depend on the signature** — it comes from "the
presented state must reproduce the committed root". The signature adds non-repudiation
and tamper-evidence. The signing primitive is **ed25519 (round-6, see the sixth wave):
`genesis_root.json` commits ONLY the PUBLIC verify-key**, so a *published* verify-key
lets any repo reader verify a certified score while the *private* signing key is held
by a party that is **not** the scored subject (curator ≠ subject). This is the same
custody boundary the exposure ledger enforces for cohorts, now extended to the
attestation: the party that can *mint* a certified score is separated from the party
being *scored*. The `attestation` / `strict` parameters are keyword-only and additive;
the non-strict path is otherwise unchanged.

## Fourth wave (round-4): out-of-contract verification — attack the irreducible floor

A fourth audit proved a floor a pure validator cannot reach: it can verify that the
presented state reproduces a committed root, but it **cannot verify (i) genesis
completeness** — that the committed baseline was not itself a truncated, self-serving
starting point; **(ii) input truthfulness of the numerator** — whether the reported
rediscoveries are TRUE, since the validator never sees the detector run on the real
code; or **(iii) key custody** — that the private signing key is held by a non-subject.
Round-4 attacks each with a measure OUTSIDE the pure validator (FR-16, FR-17;
regression tests `test_p1a`..`test_p1e`, `test_part2_*`, `test_part3_*`, and the
verifier's own `benchmarks/tests/test_verifier.py`):

| Seal | Floor it attacks | Now closed by |
|---|---|---|
| P1a | genesis re-anchoring — present a truncated predecessor | `Attestation.prior_attestation_root` folded into the root; a chain extension must append-only-extend the prior committed history ⇒ `ATTESTATION_NOT_EXTENDING` |
| P1b | a certified headline with no measurement behind it | certification requires exactly one producing evaluation ⇒ `CERTIFY_WITHOUT_EVALUATION` |
| P1c | a free `adjudicated_precision` float nobody adjudicated | the headline precision must equal a bound, panel-validated `AdjudicatedPrecision` ⇒ `PRECISION_UNBOUND` |
| P1d | choosing the precision `k` that flatters the sample | `k` committed inside the freeze bundle before the seed is derivable ⇒ `PRECISION_SAMPLE_UNBOUND` |
| P1e | the certifier scoring its own subject (key custody, in-band half) | `attestation.evaluator_id != run.subject` ⇒ `CURATOR_IS_SUBJECT` |
| PART 2 (FR-16) | **input truthfulness** — CLAIM a rediscovery the detector never produced, or OMIT a real one | the numerator is RECOMPUTED by re-running the frozen detector on the real pinned SHAs (`verifier.recompute_rediscovered`, `corpus_measure`'s line-precise rule); `set(report.rediscovered_blind_ids)` must equal it ⇒ `NUMERATOR_UNVERIFIED` |
| PART 3 (FR-17) | **genesis completeness** — re-anchor to a fresh, private genesis | a git-committed `genesis_root.json` (reviewable, git-timestamped) that the chain base must root in ⇒ `GENESIS_UNANCHORED` |

**The numerator is now RECOMPUTED, not trusted, and the genesis is git-anchored.** The
verifier re-runs OUR static analyzer over the fetched target files as **DATA**
(`scan_source` parses them, e.g. `ast.parse`); no target code is executed, so Article
III stays intact — the module never `eval`/`exec`/imports fetched content.

**The ONLY residual is now documented, not code-closable:** (i) the completeness of
what the curator commits at genesis — moved into git, where it is timestamped and
reviewable in history rather than asserted by the validator; and (ii) key custody —
that the *private* signing key is held by a party that is **not** the scored subject.
The in-band half of custody (`evaluator_id != subject`) is enforced; the physical
key-holding boundary is organizational, the same custody separation the exposure
ledger enforces for cohorts. This is the honest trust boundary: everything a validator
*can* check is checked; the two things it structurally cannot are pushed onto git
review and organizational key custody rather than silently assumed.

## Fifth wave (round-5): the round-4 layer was OPT-IN — make it RUN from committed state

A fifth audit proved the round-4 verification layer, while present, was **bypassable
because it was built as OPT-IN / CALLER-SUPPLIED inputs**: the numerator recompute, the
verify-key, the prior-history baseline, and several completeness inputs were passed IN to
`validate` by the very party being scored, who could therefore forge them. ONE governing
principle drove the fixes, applied everywhere rather than only to the listed repros:

- **A trusted value or a verification RESULT must NEVER be a caller argument the scored
  party could forge.** `validate()` RUNS each verification itself and LOADS every trusted
  root / key / detector from COMMITTED, git-tracked state (via module-level,
  monkeypatchable registries / loaders — not caller args). Every completeness input a
  strict certify needs is MANDATORY and resolved from committed state; omission or an inert
  default FAILS CLOSED.

| Hole | Bypass it re-opened (round-4 was opt-in) | Now sealed in `validate()` by |
|---|---|---|
| R5-1 | `recomputed_rediscovered=` was a caller set — the subject passed a recompute matching its own lie | the `recomputed_rediscovered` param is REMOVED; strict certify RUNS `verifier.recompute_certified_numerator`, resolving `scan_fn` from a committed `DETECTOR_REGISTRY` keyed by the frozen `detector_id` and `fetch_fn` from the committed fetcher (`NUMERATOR_UNVERIFIED`; a fail-closed miss when the detector cannot be resolved) |
| R5-2 | `load_committed_genesis_root()` was `chain_root([])` (empty) so any truncated cohort "anchored"; `prior_history` was a trusted caller arg | a REAL, non-empty, MONOTONIC committed genesis (`genesis_root.json` holds `genesis_history_root` + `latest.{history_root,attestation_root}`); the presented history must reproduce + append-only-extend the COMMITTED prior (`ATTESTATION_NOT_EXTENDING`) and the attestation must chain from the committed latest attestation root (`GENESIS_UNANCHORED`); `advance_committed_root(...)` persists the advance |
| R5-3 | `_check_exposure` / pool_root / committed_k were guarded by `if … is not None` — omit the arg, skip the check | on strict certify the exposure ledger + prior evaluations are MANDATORY (`MISSING_LEDGER`) and `pool_root` / `committed_k` must be non-inert (`PRECISION_SAMPLE_UNBOUND`); the opt-in guards are removed |
| R5-4 | `verify_key=` was a caller arg — a subject mints key K, signs, passes K | the verify-key + evaluator id are LOADED from committed config; a subject-minted key or a wrong evaluator id fails `ATTESTATION_INVALID`; the `verify_key` param is REMOVED |
| R5-5 | the freeze bound only `attempts[0]`, not the PRODUCING attempt | the producing post-freeze attempt's `freeze_hash` must equal the frozen bundle hash (`BAD_FREEZE_BINDING`) |
| R5-6 | a certified report could carry a free `achievable_recall` diagnostic as if bound | a certified report must not carry `achievable_recall` (`ACHIEVABLE_UNBOUND`); it stays a labelled diagnostic for non-certified reports |

The round-5 layer sealed the opt-in bypasses, but a sixth audit found four survivors (see
the sixth wave) before the residual was truly reached.

## Sixth wave (round-6): the floor seals — bind-to-head, committed eval-ledger, structural certify, ed25519

A sixth audit found four survivors that the round-5 layer still left open. All four are
now closed, and after them the ONLY residual is the irreducible floor. (Regression tests
`test_f1_*`..`test_f4_*`.)

| Hole | Bypass it left open | Now sealed in `validate()` by |
|---|---|---|
| F1 | a run bound to an OLDER, smaller committed cohort version (or an unresolvable hash) while presenting the honest full history — the denominator/recompute/exposure used the STALE version and silently dropped a hard miss appended to the head later | `_check_report`, the certification numerator recompute, and `_check_exposure` resolve the scored cohort as `history.latest()` (the head), never the run's declared hash; strict certify requires `run.cohort_content_hash == history.latest().content_hash` (`DENOMINATOR_SHRINK` / `REPORT_DENOMINATOR_MISMATCH`) |
| F2 | evaluate-once was defeated by presenting an EMPTY caller `prior_evaluations`, re-scoring the blind set across trivial re-freezes | `genesis_root.json` + `CommittedGenesisState` carry `latest_evaluation_root`; the presented `prior_evaluations` must reproduce + append-only-extend it (`EVALUATED_MORE_THAN_ONCE`), and `advance_committed_root` advances it; combined with A3's blind-set overlap on the truthful ledger (`BLIND_REEVALUATED`) a re-freeze re-score is caught either way |
| F3 | the whole certify path ran only under `strict or attestation`, so a producing run + a headline Report presented WITHOUT them skipped it | a producing run presented together with a headline Report WITHOUT `strict` or an `attestation` is `UNANCHORED` — certification is mandatory for a produced+reported result |
| F4 | `sign`/`verify` were symmetric HMAC over a plaintext-committed shared secret — any repo reader could sign a valid attestation | `sign`/`verify` are ed25519; `genesis_root.json` commits ONLY `verify_key_pub_hex` (the PUBLIC key) and NEVER the private key; certification verifies against the committed public key (`ATTESTATION_INVALID` for any non-committed key). A repo reader can verify but cannot forge |

**The FINAL residual is now exactly two things, both structurally outside a validator and
both pushed onto reviewable / organizational boundaries rather than silently assumed:**
(i) **genesis-commit completeness [git-reviewable]** — that what the curator commits at
genesis (`genesis_root.json`) is itself complete; this lives in git, timestamped and
reviewable in history; and (ii) **ed25519 private-key custody [curator ≠ subject,
organizational]** — that the *private* signing key is held by a party that is NOT the
scored subject. The in-band half of custody (`evaluator_id` == committed id, `!= subject`,
and the verify-key is the committed PUBLIC key so no repo reader can forge) is enforced in
code; the physical private-key-holding boundary is organizational. In this repo the
committed public key corresponds to a fixed test/smoke signing seed held in the test/build
helpers so the smoke and unit tests can produce honest attestations; a production deployment
commits the curator's real public key while the real private key stays external. Everything a
validator *can* run and check, it now RUNS and checks from committed state; the two things it
structurally cannot are git review and organizational key custody. (A seventh audit found five
more code-closable survivors — all medium, one shared root — sealed in the seventh wave below;
the two-part residual above is unchanged and is the true floor.)

## Seventh wave (round-7, last code-closable): structural-on-the-report + bind-every-numeric

A seventh audit found five survivors, all medium, sharing ONE root: certification triggered on
the RUN's `produced_results` flag / run presence, not on the REPORT's own numeric claims. So an
unbacked Report escaped recompute/anchoring on the non-strict default `check`, and a certified
report's SECONDARY numerics were free floats. All are now closed; after them, only the
irreducible two-part floor above remains. (Regression tests `test_r7_1_*`, `test_r7_2_*`.)

| Hole | Bypass it left open | Now sealed in `validate()` by |
|---|---|---|
| R7-1 | the default `check = validate` alias blessed a bare truncated Report + inflated numerator with no run; a Report asserting a numerator without a producing run skipped recompute + anchoring; N-times-keep-best was presentable as an unbacked claim | certification is STRUCTURAL on the Report: ANY presented Report asserting a numerator (`blind_recall.total > 0`, `blind_recall.rediscovered > 0`, or a non-empty `rediscovered_blind_ids`) REQUIRES `strict` + a signed `Attestation` (else `UNANCHORED`), whether or not a run/produced flag is present; under certification the committed-genesis anti-truncation (`_history_reproduces_committed`), head-binding, and numerator recompute fire unconditionally (a Report with no producing run → `CERTIFY_WITHOUT_EVALUATION` / `NUMERATOR_UNVERIFIED`). A Report headline is un-fakeable on EVERY entrypoint, including the default `check` |
| R7-2 | under strict certification the Report's OTHER numerics (`fixed_cohort_recall`, `coverage`, `patched_alert_density`) were free floats never recomputed — a certified report could carry arbitrary secondary numbers | every certified numeric is RECOMPUTED from the committed detector+cohort or FORBIDDEN (mirroring `ACHIEVABLE_UNBOUND`): `fixed_cohort_recall` recomputed over the head cohort's REGRESSION entries via the committed detector (`FIXED_COHORT_UNVERIFIED`); `patched_alert_density` recomputed from the committed detector's patched-tree flag counts (`corpus_measure.patched_flag_count`) over the head BLIND entries (`DENSITY_UNVERIFIED`); `coverage` (pinned/all — not recomputable from committed state) FORBIDDEN, a certified report leaves it `None` (`COVERAGE_UNBOUND`). `adjudicated_precision` already bound (P1c), `achievable_recall` already forbidden (R5-6) |

**The FINAL residual is unchanged and is exactly the two-part floor named above: (i)
genesis-commit completeness [git-reviewable] and (ii) ed25519 private-key custody [curator ≠
subject, organizational].** After round-7 every certified numeric a validator can recompute from
committed state is recomputed, and every Report headline is structurally forced through signed
certification; nothing code-closable remains.

## Eighth wave (round-8): pin the recompute's INPUT BYTES; commit the sample; close the N-A holes

An eighth audit found six survivors (one critical, one high, two medium, one low, one minor). The
recompute RAN the committed detector but did not bind the BYTES it ran on; the precision sample was
DERIVED from the grindable `freeze_hash`; certification was forced only on the blind headline; a
POLICY_REFUSAL could launder a produced class to N/A when the run object was omitted;
`produced_results` was unbound to any artifact; and an inert committed history root was not rejected.
All are now closed. (Regression tests `test_r8_1_*` … `test_r8_6_*` plus the verifier-level
`test_r8_1_recompute_rejects_doctored_input_bytes`.)

| Hole | Bypass it left open | Now sealed by |
|---|---|---|
| R8-1 (CRITICAL) | the numerator recompute ran the committed detector, but `fetch_fn` returned bytes with NOTHING binding them to the pinned SHA — an attacker controlling the fetch source/cache feeds DOCTORED files so the detector "confirms" a false rediscovery | each `CohortEntry` commits per-target `vuln_blob_sha256` / `patched_blob_sha256` (sha256 of the bytes at `vuln_ref` / `patched_ref`), FOLDED INTO its identity hash (so it rides inside `history_root` + the signed attestation); the recompute requires `sha256(fetched bytes) == committed hash` for each (path, ref), and a missing commitment for a scored target is itself a failure — else `INPUT_BYTES_UNVERIFIED`. The detector provably runs on the EXACT committed pinned bytes (Article III: parsed as data, never executed) |
| R8-2 (HIGH) | `precision_sample_seed = f(cohort, freeze_hash, run_id)` and `freeze_hash` is GRINDABLE (tweak an inert bundle param until the seed-derived sample is favorable, then honestly certify once, no re-eval) | the frozen bundle commits `committed_sample_root = merkle_root(sorted(sampled_pairs))` — drawn BEFORE adjudication from committed, non-grindable inputs (cohort identity, canonical pool, `k`), so it rides inside `bundle_hash` / `freeze_hash` + the attestation; `_check_precision_binding` requires the presented `sampled_pairs` to REPRODUCE it, and strict certification REQUIRES a non-empty committed sample_root — else `PRECISION_SAMPLE_UNBOUND`. Grinding the hash can no longer re-roll the sample |
| R8-3 (MEDIUM) | R7-1 forced certification only on the blind numerator, so a SECONDARY scoring number (`fixed_cohort_recall`, a set `patched_alert_density`, a set `adjudicated_precision`) could be published via the default `check == validate` with no certification | `_report_asserts_numerator` fires for ANY non-trivial scoring numeric, so any such Report REQUIRES full signed certification (`UNANCHORED` otherwise), where R7-2's recompute/forbid binds each. A genuinely all-zero report asserts nothing |
| R8-4 (MEDIUM) | the A2 guard fired only inside `if run is not None`, so a class whose committed detector actually RUNS and produces a mediocre result could be dropped to N/A by logging a POLICY_REFUSAL and OMITTING the run | a POLICY_REFUSAL is recompute-checked + certification-forced (symmetric to R7-1): VALID only if the committed detector for the class produces NOTHING on the head blind set (recompute, input-bytes-verified) OR no committed detector exists; else `POLICY_REFUSAL_ON_PRODUCED_RUN`, run object or not; an N/A POLICY_REFUSAL must be inside a signed certification (`UNANCHORED` otherwise). The AGGREGATE class-manifest completeness (no whole class silently omitted from the mean) is a documented follow-on, **feature 009** |
| R8-5 (LOW) | N-1 real post-freeze evals could hide as `produced_results=False` "infra retries" | `EvalAttempt.results_hash` binds `produced_results`: a producing attempt carries a non-empty one, a non-producing infra retry an empty one (a retry carrying a results_hash is a concealed real eval) — enforced at record time + in `validate` (`INFRA_RETRY_REQUIRES_UNCHANGED`) |
| R8-6 (minor) | `load_committed_genesis_state` claimed to fail closed on an inert root but only rejected the empty string | it rejects the inert `_CHAIN_GENESIS` / `_EMPTY_ROOT` sentinel for the `genesis_history_root` and `latest.history_root` (the truncation-anchor-critical roots `_history_reproduces_committed` binds against); the attestation/evaluation chain BASES stay their legitimate inert bootstrap sentinels until the first certify |

**The FINAL per-cohort residual is exactly the two-part floor named above: (i) genesis-commit
completeness — including, from feature 009, the AGGREGATE class-manifest that no whole class is
silently omitted from the mean — which is git-reviewable, not validator-checkable; and (ii) ed25519
private-key custody [curator ≠ subject, organizational].** After round-8 every certified numeric a
validator can recompute is recomputed on the EXACT committed pinned bytes, the precision sample is
committed rather than grindable, and no scoring number or N/A escapes signed certification; nothing
code-closable remains at the per-cohort level.

## Ninth wave (round-9): the last per-cohort survivors before ship

A ninth audit — with the denominator, taxonomy, and forgery/crypto lenses all HOLDING — found four
residual per-cohort holes, each a place where a committed binding still left the OPERATOR one degree
of freedom. All are now closed; after them the per-cohort contract is terminal and the ONLY residual
is the irreducible two-part floor named above. (Regression tests `test_r9_1_*` … `test_r9_4_*`, the
updated `test_r2_*`, and smoke guards 15–16.)

| Hole | Bypass it left open | Now sealed by |
|---|---|---|
| R9-1 (HIGH) | R8-2 committed the precision sample into the bundle, but the OPERATOR still chose WHICH pairs to commit — the sample seed was a free operator input: cherry-pick a favorable draw, commit its `sample_root`, present a precision that reproduces it, and R8-2's reproduce-the-committed-root check passes | the sample is DERIVED from committed, non-grindable state: `canonical_sample_seed(cohort_content_hash, pool_root, k)` and `canonical_sample_root(...) = sample_root_of(sample_confusion_pairs(sorted(pool), k, seed))`. The cohort is genesis-anchored and the pool + `k` are committed at freeze time, so the sample is a total function of committed state with NO operator choice. Strict certification RECOMPUTES the canonical sample and requires the committed freeze `sample_root` to EQUAL it — else `PRECISION_SAMPLE_UNBOUND` |
| R9-2 (MEDIUM) | in `_check_exposure`, a record whose `actor == subject` with a non-empty `curated_entry_ids` that missed the presented head short-circuited (via `continue`) the `cohort_content_hash` fallback — laundering a curator into a subject through a version bump (same entries, new content hash) | BOTH bars run for every actor==subject record: after the `curated_entry_ids & scored_blind` bar, the record's cohort is STILL resolved by content hash (via history) and the subject is barred on ANY overlap with the scored cohort's identities; a record resolvable by NEITHER mechanism (empty `curated_entry_ids` + an unresolvable content hash) is a HARD FAIL — `CURATOR_IS_SUBJECT`, never a silent skip |
| R9-3 (MEDIUM) | the freeze binding inspected only `attempts[0]` (A4) and the producing attempt(s) (R5-5), so a from-storage run could present a NON-first, NON-producing "retry" carrying a FORGED `freeze_hash` (a hidden second evaluation of an unrelated bundle B') that slipped through both | `_check_freeze_binding` binds EVERY post-freeze attempt's `freeze_hash` to the frozen bundle hash — else `BAD_FREEZE_BINDING`; and `_check_blind_access` anchors the retry invariant (identical `artifact_hash` + `env_hash`, empty `results_hash`) to THE PRODUCING attempt rather than `attempts[0]` — a retry that differs from the scored evaluation is `INFRA_RETRY_REQUIRES_UNCHANGED` |
| R9-4 (defense-in-depth) | ROLE_DOWNGRADE was the ONE correction reason legitimizing a blind departure without any other precondition, but FR-4 authorizes blind→regression ONLY for an entry that GUIDED A FIX — so a downgrade of a real MISS (`guided_fix == False`) inflated the rate behind a logged trail | `_check_denominator_preservation` additionally requires a ROLE_DOWNGRADE that moves an identity out of the blind set to have carried `guided_fix == True` in the `from_version` cohort — else `DENOMINATOR_SHRINK`. (`guided_fix` is not part of entry identity, so the event's `entry_identity` matches either way; the flag is read from the from_version entry) |

**The FINAL per-cohort residual is UNCHANGED and is exactly the two-part floor named above: (i)
genesis-commit completeness [git-reviewable, plus the feature-009 AGGREGATE class-manifest]; and
(ii) ed25519 private-key custody [curator ≠ subject, organizational].** After round-9 every
per-cohort binding is a total function of committed state; nothing code-closable remains at the
per-cohort level, and the aggregate class-manifest completeness is the sole follow-on (feature 009).

## Tenth wave (round-10): comprehensive final hardening — one recurring shape

A tenth audit found the last survivors were all ONE recurring shape and closed them comprehensively
under a governing meta-principle applied throughout (not only to the listed items): (P-A) EVERY
constructor/type-validator invariant is RE-ENFORCED on the certify path (from-storage objects bypass
constructors); (P-B) EVERY ledger has a committed-monotonic root advanced by `advance_committed_root`
and reproduced+extended on certify, with NO inert/empty short-circuit; (P-C) trust CODE HASHES, not
names. (Regression tests `test_r10_1_*` … `test_r10_7_*`, the updated `test_r5_2_*` / `test_verifier`
builders, and smoke guards 17–19.)

| Hole | Bypass it left open | Now sealed by |
|---|---|---|
| R10-1 (HIGH) | the freeze hashed `module_hashes`/`interpreter_version`/`parser_versions` but nothing READ them; the detector was resolved by the mutable `detector_id`, so the operator could swap the detector CODE while keeping the name/freeze | on certify, `validate` recomputes the sha256 of the source file(s) of the module the committed registry resolves for `freeze.bundle.detector_id` (`verifier.resolve_module_hashes`) and requires it to EQUAL the frozen `module_hashes`; a mismatch (swapped code), an unregistered module, or an inert (empty) commitment is `DETECTOR_BUNDLE_UNVERIFIED`. Trust the CODE HASH, not the name (SAFETY: the analyzer source is read as TEXT and hashed; nothing fetched/target is executed) |
| R10-2 (HIGH) | `_check_certification` verified exposure only against the freshly-signed attestation's OWN `exposure_root`, so a truncated ledger (drop the incriminating curator record), re-signed, passed | `CommittedGenesisState`/`genesis_root.json` carries `latest_exposure_root`, `advance_committed_root` advances it, and certify requires the presented `ExposureLedger` to reproduce + append-only-extend the committed root — else `EXPOSURE_LEDGER_TRUNCATED` (parity with history/evaluation) |
| R10-3 (MEDIUM) | `_check_evaluation_ledger` read `record.blind_ids` verbatim, so a record could advertise a fake (smaller/empty) blind set to dodge the A3 blind-set overlap | when the record's `cohort_content_hash` resolves in history, its `blind_ids` must equal that cohort's actual BLIND identity set — else `EVALUATION_RECORD_UNBOUND` |
| R10-4 (MEDIUM) | `_evaluation_reproduces_committed` returned True for the inert/empty committed root (short-circuit), and the eval chain never advanced, so a re-eval passed | `advance_committed_root` persists the new `evaluation_root` (and `exposure_root`) on a successful certify, and `_evaluation_reproduces_committed` rejects the inert `_CHAIN_GENESIS`/`_EMPTY_ROOT` once past bootstrap (a NON-EMPTY ledger cannot reproduce it via the empty prefix) — matching R8-6 for history; a re-eval under a truthful advanced committed root is `BLIND_REEVALUATED`/`EVALUATED_MORE_THAN_ONCE` |
| R10-5 (HIGH) | a from-storage `AdjudicatedPrecision` (`model_construct`) bypassed `_panel_and_sample_are_valid` (coverage + panel composition), so precision 1.0 was presentable with no honest adjudication | `_check_precision_panel` RE-ENFORCES the full structural invariants on the certify path — non-empty sample, canonical pool, the k floor, FULL coverage, the deterministic draw, and per-pair panel composition (≥2 verdicts, no builder, ≥1 non-curator) — else `PRECISION_PANEL_INVALID` |
| R10-6 (MEDIUM) | the panel trusted self-asserted `is_builder`/`is_curator` and never checked the adjudicator against the scored subject | every `AdjudicatorVerdict.adjudicator` must differ from `run.subject`, be on the committed roster (`genesis_root.json` → `adjudicators`), and carry the roster's `is_builder`/`is_curator` — else `ADJUDICATOR_INVALID`. That the rostered adjudicators are genuinely independent people is the irreducible organizational remainder |
| R10-7 (LOW) | `merkle_root` duplicated the last node on an odd level with no leaf/node domain separation — the classic duplicate-leaf second-preimage collision (CVE-2012-2459): `merkle_root([…,x]) == merkle_root([…,x,x])` | leaves are hashed under a `0x00` prefix and internal nodes under `0x01`, and an odd level is split at the largest power of two below the count (RFC 6962-style, never duplicate-last), so a duplicate-leaf second preimage can no longer collide. The committed roots in `genesis_root.json` are chain/sha256 based, so only the dynamically-recomputed attestation/pool/sample roots change |

## Eleventh wave (round-11): the two pre-ship survivors — bind the guard to the STRUCTURE, not the label/set

A final re-confirm audit (five lenses, each trying to get `validate()` to ACCEPT a dishonest
measurement) reported the denominator-shrink, blind-freeze-bypass, and attestation-forgery lenses
HOLDING, and surfaced two remaining code-closable holes — each an instance of a guard that checked a
NAME or a SET where it needed the STRUCTURAL transition or the MULTISET. Both are closed before ship;
the round-10 residual is unchanged. (Regression tests `test_r11_1_*` / `test_r11_2_*`, and smoke
guards 20–21.)

| Hole | Bypass it left open | Now sealed by |
|---|---|---|
| R11-1 (MEDIUM) | the R9-4 guided_fix precondition for a blind→regression role-downgrade only inspected events LABELED `ROLE_DOWNGRADE`, so relabeling the identical move as any other cohort-correction reason (`ALIAS_DUPE`, `TARGET_PATHS_NARROWING`, `SEED_SWAP`, …) laundered a hard blind MISS out of the authoritative denominator behind a mislabeled correction event | `_check_denominator_preservation` binds the guided_fix precondition to the STRUCTURAL transition — an identity in `left_blind` that is still KEPT in the head is legitimate ONLY if it guided a fix, regardless of which cohort-correction reason authorizes it — else `DENOMINATOR_SHRINK`. Full removals (identity absent from the head) are unaffected: a genuine alias/dup removal under a matched event stays legitimate |
| R11-2 (HIGH) | precision coverage was checked as a SET (`{pair_ids} == {sampled}`) but `precision` divided `tp` by `len(adjudications)`, so appending duplicate favorable (true-positive) adjudications for already-covered pairs inflated `tp/len` toward 1.0 while the coverage set was unchanged (honest 0.50 → 0.969), certified | both `AdjudicatedPrecision._panel_and_sample_are_valid` (constructor) and `_check_precision_panel` (certify-path re-enforcement, P-A) require the MULTISET of adjudicated pair_ids to equal the sampled draw exactly (no duplicates) — else a constructor `ValueError` / `PRECISION_PANEL_INVALID` — pinning the precision denominator to `|sample|` |

**The FINAL residual after round-11 is exactly: (i) genesis-commit completeness [git-reviewable, plus
the feature-009 AGGREGATE class-manifest]; (ii) ed25519 private-key custody [curator ≠ subject];
(iii) adjudicator independence [the committed-rostered adjudicators are genuinely independent
people]; and (iv) operator commit-honesty of the git-committed ledgers — all four organizational /
git-reviewable, not validator-checkable.** After round-11 every per-cohort binding is a total
function of committed state, every ledger is committed-monotonic, the detector is bound by code hash,
and each guard binds to the structural transition/multiset it means (not a reason label or a
coverage set); the aggregate class-manifest completeness is the sole code-closable follow-on
(feature 009).

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
