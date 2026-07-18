# Feature 009 — threat model (aggregate class-manifest)

The attacker is a dishonest operator who wants a HIGHER headline mean than the honest per-class
numbers support, while every per-class attestation (008) stays perfectly valid. 008 already makes
each per-class number tamper-evident; 009 binds the SET of classes that feed the mean. The gate is
`aggregate.certify_aggregate(manifest, results, aggregate, events, committed)`.

## Assets

- **The aggregate mean** — the headline `AggregateReport.mean`, a mean of per-class blind-recall
  rates over the in-mean (ACTIVE) classes.
- **The committed class set** — `committed.latest_class_manifest_root` in `genesis_root.json`, the
  git-anchored, monotonic root of the append-only `ClassManifestHistory`.
- **Per-class certified results** — each class's 008 `Attestation` + the `Report` it committed.

## Attack vectors and seals

| Vector | Attack | Seal |
|---|---|---|
| Silent drop | omit a weak class from the head manifest with no event | `_check_manifest_preservation` adjacent-pair: `removed | left_mean` needs a matched `ClassManifestEvent` consumed per exact `(class_id, from, to)` — else `CLASS_SILENTLY_DROPPED` |
| Status downgrade | keep the class but move it `active -> na/retired/merged/reclassed` with no event | same seal — `left_mean = prev.active_ids - curr.active_ids` covers a kept-but-downgraded class |
| Split departure | remove-then-readd-out-of-mean (or vice-versa) across versions to dodge the per-pair consume | terminal-head guard: any class ever in the mean, not in the head mean, needs ≥1 event for it anywhere in the log (008 R11-1b lesson) |
| Manifest truncation | present a fresh, shorter manifest that never carried the weak class | `_manifest_reproduces_committed`: the presented chain must reproduce + append-only-extend `committed.latest_class_manifest_root` — else `CLASS_MANIFEST_TRUNCATED` |
| Missing result | omit an in-mean class's per-class attestation | every in-mean head class must have a present result — else `CLASS_ATTESTATION_MISSING` |
| Cross-class swap | present class B's slot with class A's higher-recall signed attestation | the result's `attestation.history_root` must equal the manifest entry's committed `head_history_root` — else `CLASS_ATTESTATION_INVALID` |
| Report tamper | reuse a valid attestation but read a higher-recall report | `attestation.report_hash == leaf_hash(report)` — else `CLASS_ATTESTATION_INVALID` |
| Signature forgery | sign with a non-committed key | `verify(attestation_root, signature, committed.verify_key)` — else `CLASS_ATTESTATION_INVALID` |
| Evaluator spoof | certify a class as the scored subject | `attestation.evaluator_id == committed.evaluator_id` — else `CLASS_ATTESTATION_INVALID` |
| Mean lie | report a mean the per-class rates do not support | the mean + `n_classes` are RECOMPUTED as an exact `Fraction` over the in-mean head classes — else `AGGREGATE_UNVERIFIED` |
| Padding | add a result for a class not in the head mean | an out-of-mean result is `CLASS_ATTESTATION_INVALID`; the mean is computed only over the committed head active set |

## Residual (organizational / git-reviewable — a validator cannot reach these)

Unchanged from 008: (i) genesis-commit completeness — that the FIRST committed manifest is itself
complete (a class never committed cannot be missed); (ii) ed25519 private-key custody (curator ≠
subject); (iii) adjudicator independence; (iv) operator commit-honesty of the git-committed ledgers.
The manifest's first commit and every class-manifest event are git-reviewable; 009 makes the set a
total function of that committed, reviewable state so a *silent* drop is impossible — a reviewer
sees every retirement.

## Sealing note

`certify_aggregate` is PURE (no file writes). On a clean report the harness advances the committed
manifest root via `advance_committed_root(class_manifest_root=manifest.root)`, which preserves the
four 008 roots (each root is preserve-when-omitted), so a 009 advance and an 008 certify never
disturb each other's committed state. Article III: the aggregate binds already-certified
attestations and the committed manifest; it re-runs no detector and executes nothing fetched.
