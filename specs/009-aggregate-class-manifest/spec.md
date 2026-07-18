# Feature 009 — Aggregate class-manifest (no class silently dropped from the mean)

> Status: **built, test-first** (tracked follow-on from feature 008). Kernel:
> `benchmarks/harness/aggregate.py` + the committed-state seam in `contract.py` /
> `genesis_root.json`; tests: `benchmarks/tests/test_aggregate.py`; demo: `scripts/smoke_009.sh`;
> threat model: [`threat-model.md`](threat-model.md).

## Why (the one code-closable residual from 008)

Feature [008](../008-evaluation-contract/spec.md) makes each **per-class** number tamper-evident:
the blind denominator cannot shrink (even via a split remove-then-readd), the numerator is
recomputed on committed pinned bytes, precision is duplicate-proof, and every attestation is
ed25519-signed and git-anchored. But the **headline** DeepThought number is an AGGREGATE — the
mean rediscovery rate across the measured classes (v12 = 79.2% across twelve classes). 008 does
not yet bind the SET of classes that feed that mean.

So the residual the 008 threat-model names first — "genesis-commit completeness … plus the
feature-009 AGGREGATE class-manifest — that no whole class is silently omitted from the mean" —
is that an operator could **drop a weak class** from the aggregate and report a higher mean, with
every surviving per-class attestation still perfectly honest. 009 closes exactly that: a committed,
monotonic **class manifest** so the aggregate is a total function of a git-anchored set, and
omitting a class fails closed.

This is the LAST code-closable inflation surface; after 009 the remaining residual is entirely
organizational (key custody, adjudicator independence, genesis completeness, ledger commit-honesty).

## What (scope boundary)

- **`ClassManifest`** — a typed, versioned record of every class in scope for the aggregate:
  per class `{class_id, cwe, detector_id, cohort_content_hash (head), status}`, with a
  `manifest_root = merkle_root(sorted(per-class leaves))` using the domain-separated scheme from
  008 R10-7 (0x00 leaf / 0x01 node).
- **Committed-monotonic root (P-B parity with 008's ledgers)** — add `latest_class_manifest_root`
  to `genesis_root.json` / `CommittedGenesisState`, advanced by `advance_committed_root` on a
  successful aggregate certify, and reproduced + append-only-extended on certify (NO inert/empty
  short-circuit). A class may leave the aggregate ONLY via a COMMITTED `ClassExit` (reason `RETIRED`
  / `MERGED` / `RECLASSED` / `NA`) EMBEDDED in the manifest version that performs the departure —
  folded into the version `content_hash` and thus the committed, reproduced manifest root, so it
  cannot be a caller-supplied, unsigned event (which an operator could fabricate). Never a silent
  omission.
- **`certify_aggregate(manifest, results, aggregate)`** — the committed trust anchor is loaded
  INTERNALLY (008 R5: never a caller argument, so the scored party cannot substitute the evaluator
  key / manifest root / registry) —
  1. the presented manifest reproduces + append-only-extends the committed
     `latest_class_manifest_root` (else `CLASS_MANIFEST_TRUNCATED`);
  2. EVERY in-mean head class has a present per-class result (else `CLASS_ATTESTATION_MISSING`), is
     PINNED in the committed per-class registry `class_registry` and its manifest entry matches that
     pin, and carries a signature verifying against the committed evaluator key + id + a `report_hash`
     reproducing its report (else `CLASS_ATTESTATION_INVALID`);
  3. the reported mean + class count are RECOMPUTED (exact `Fraction`) over the in-mean head classes,
     UNCONDITIONALLY — an empty in-mean set forces the vacuous `mean == 0.0` (else `AGGREGATE_UNVERIFIED`);
  4. a class that left the mean without a committed `ClassExit` → `CLASS_SILENTLY_DROPPED` (adjacent
     pair + terminal head, so a split remove-then-readd cannot launder it).
- **N/A taxonomy for classes** — a class scored N/A (e.g., a genuine no-detector class) must carry a
  committed `ClassExit` (reason `NA`), symmetric to 008 R8-4's per-class `POLICY_REFUSAL`, so the
  aggregate denominator (# classes) cannot shrink silently either.

## Non-goals / residual after 009

- No new detector classes and no re-measurement of existing classes (009 is the aggregation
  binding only).
- The irreducible organizational floor is unchanged: genesis-commit completeness of the FIRST
  manifest (git-reviewable), ed25519 private-key custody (curator ≠ subject), adjudicator
  independence, and operator commit-honesty of the git-committed ledgers. After 009 the aggregate
  is a total function of committed state, so the last code-closable inflation surface is closed.

## Acceptance criteria (to be met test-first at build)

1. An honest aggregate over the full committed manifest with all per-class attestations present
   certifies, and the recomputed mean equals the reported mean.
2. Dropping a class from the presented aggregate set with no committed `ClassExit` →
   `CLASS_SILENTLY_DROPPED`.
3. A class present in the committed manifest with a missing/invalid per-class attestation →
   `CLASS_ATTESTATION_MISSING`.
4. A reported aggregate mean that does not equal the recompute over the full manifest →
   `AGGREGATE_UNVERIFIED`.
5. A presented manifest that does not reproduce + extend the committed `latest_class_manifest_root`
   → `CLASS_MANIFEST_TRUNCATED` / `GENESIS_UNANCHORED`; a successful certify advances the committed
   root.
6. A class scored N/A without a committed `ClassExit` fails closed.

## Discipline

Test-first; hermetic monkeypatched committed state; keep the whole suite + all smokes green; a
`scripts/smoke_009.sh` demonstrates one honest aggregate certify plus each guard
(`CLASS_ATTESTATION_MISSING`, `CLASS_SILENTLY_DROPPED`, `AGGREGATE_UNVERIFIED`, manifest truncation)
failing closed with a typed reason. Reuse 008's `merkle_root` / `chain_root` / `advance_committed_root`
/ attestation machinery rather than re-implementing. A `threat-model.md` accompanies the build.
Article III unchanged: nothing fetched or target-side is executed. Commit as MahdiHedhli.
