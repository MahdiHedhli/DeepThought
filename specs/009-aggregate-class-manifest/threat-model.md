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

## Adversarial-audit fixes (3-lens red-team, before merge)

| Finding | Bug | Seal |
|---|---|---|
| AUDIT-009-1 (empty in-mean, fail-open) | the mean + `n_classes` checks were nested under `if head_active`, so an all-retired / all-na / empty head skipped them and a fabricated `mean=42.0, n_classes=999` certified clean | the headline is validated UNCONDITIONALLY — `n_classes == len(head_active)` always, and an empty in-mean set forces the vacuous `mean == 0.0`; else `AGGREGATE_UNVERIFIED` |
| AUDIT-009-2 (circular class binding, HIGH) | `att.history_root == entry.head_history_root` is CIRCULAR — the operator controls both sides (set a weak class's manifest `head_history_root` to a strong class's root, attach the strong class's genuine signed attestation), so a high number lands in a weak slot at the empty bootstrap | a committed per-class registry `committed.class_registry {class_id: head_history_root}` pins each class's root in git-reviewable state; when populated (production posture) the manifest entry MUST match it — else `CLASS_ATTESTATION_INVALID`. Post-bootstrap the committed manifest root also pins it via reproduction; the registry closes the bootstrap window. An empty registry is the genesis-completeness floor below |

## Dual-gate review fixes (CodeRabbit — three Criticals the 3-lens audit missed)

The adversarial audit passed `committed=` and trusted the event log, so it did not attack those
surfaces. CodeRabbit did, and was right:

| Finding | Bug | Seal |
|---|---|---|
| CR-A (Critical) | `certify_aggregate` took `committed` as a CALLER argument — a caller could pass their own evaluator key + manifest root and self-sign every result | the committed trust anchor is loaded INTERNALLY via `load_committed_genesis_state()` (008 R5: "verifications RUN from committed state, never passed in"); there is no `committed` parameter. Tests monkeypatch the loader |
| CR-B (Critical) | manifest events were a caller-supplied, unsigned, uncommitted `ClassManifestLog` — an operator could fabricate a `(B, v1, v2)` retirement to drop any class | authorizations are now `ClassExit` entries EMBEDDED in the manifest version that performs the departure, folded into the version `content_hash` (and thus the committed, reproduced manifest root). There is no caller event log; a fabricated exit changes the manifest root |
| CR-C (Critical) | the registry pin was applied only to classes the registry contained — a class ABSENT from the registry was waved through, reopening the swap | every in-mean class MUST be pinned in the committed registry (when a registry exists); an unpinned in-mean class is `CLASS_ATTESTATION_INVALID`. An entirely empty registry is the documented bootstrap floor |
| CR-D (Major) | `AggregateReport.mean` allowed inf/nan and out-of-range values | `mean` is `Field(ge=0.0, le=1.0, allow_inf_nan=False)` |
| REAUDIT (HIGH) | the registry pin was gated on `if registry` — but `advance_committed_root` advances the manifest root to non-empty while never writing the registry, so a REACHABLE state (real committed manifest baseline + empty registry) skipped the pin and the cross-class re-point swap silently worked again | the pin is MANDATORY once a real committed manifest baseline exists (`latest_class_manifest_root != _EMPTY_ROOT`), not merely when the registry is non-empty; the only pin-free window is the true bootstrap (empty manifest root AND no registry) — the genesis-completeness floor. So the curator must commit the per-class registry before the first *advanced* aggregate |
| CR (one attestation, two classes) | with a malformed registry mapping two classes to the SAME `head_history_root`, one strong per-class attestation satisfied both slots (counted twice) | distinct in-mean classes must have DISTINCT `head_history_root`s — a shared root is `CLASS_ATTESTATION_INVALID`, so a single attestation can never count for two classes (the deeper alternative — binding `class_id` into the signed 008 `Attestation` — is deferred; the committed registry + distinct-root guard is the chosen committed anchor) |

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
