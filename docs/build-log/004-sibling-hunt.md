# Build Session Log — Feature 004, Sibling Hunt (variant analysis)

> **STATUS: MERGED to `main` (PR #3, squash `93ce057`, 2026-07-02).** READ-ONLY
> feature — SIBLING HUNT executes nothing. It derives a variant signature from a
> *verified* finding's typed fields, gates each target independently, and writes
> candidate variant findings for the source and any pre-authorized sibling project.
> `execution_enabled` stays `False`; `DockerSandbox.run()` is untouched. **380 tests
> green (310 baseline + 70 new); all four smokes (`smoke.sh`, `smoke_002.sh`,
> `smoke_003.sh`, `smoke_004.sh`) pass.** Reviewed to a clean dual-gate (codex
> gpt-5.5 + agy/Gemini adversarial) on the same HEAD before merge.

**Feature:** 004-sibling-hunt
**Branch:** `004-sibling-hunt` (merged and deleted)
**Predecessor gate:** 003 merged to `main` (PR #2, squash `440485a`).
**Merge:** PR #3, squash `93ce057`, 2026-07-02 — dual-gate clean (codex + agy).

## What shipped

SIBLING HUNT — read-only variant analysis that mirrors DISCOVER's shape and reuses
its firewalls, adding a same-class filter and a per-target authority firewall.

- **Variant `Signature`** (`sibling/signature.py`): a runtime Pydantic model
  (`extra='forbid'`, length-capped, `capability` must be a `CAPABILITY_TAXONOMY`
  member, `match_terms` must be closed-lookup keys). `signature_from_finding(finding,
  primitives)` derives it from **typed fields only** — the bound `Primitive.kind`
  (or the same closed-lookup over the finding's typed `summary` as a fallback), a
  normalized `locus_pattern` from the finding's typed `**Location:**` reference, and
  the reverse of the SARIF heuristic table as `match_terms`. The finding's free-text
  `body` is never read as instruction: a poisoned body derives the *identical*
  signature, and an underivable class returns `None` (never invents a capability).

- **`SiblingHuntSession`** (`sessions/sibling_hunt.py`): subclasses `BaseSession`,
  `type = SessionType.sibling_hunt`. Refuses (close clean, no worker, no records)
  when the source finding is missing, belongs to another project, or is not
  verified, or when no signature can be derived. Fixes the huntable target list at
  dispatch (source + named, pre-registered siblings) and **gates each target
  independently** with `GateContext.from_project` + `DefaultGate` (no basis →
  refuse, empty scope → hold, unregistered name → skipped/logged, never created).
  Dispatches one stub Marvin (`marvin-sibling-hunt`) per gated-proceed target that
  reuses the DISCOVER/SARIF path with the target's own scope/root containment, then
  applies the **same-class filter** (keep only instances whose capability equals the
  signature's). The orchestrator ingests only the typed envelope through a shared
  `Conductor`, writes candidate variant `Finding`s (fresh non-colliding ids, bound
  to the *target* project, OSV-valid by construction) and re-validated
  `Coverage(method='read')`.

- **CLI** (`cli.py`): `playbook sibling-hunt --project <id> --finding <F-NNNN>
  [--sibling <id> ...] [--sarif <path>] [--root <path>]`, mirroring `playbook
  discover`/`verify` (`HermesUltraCodeGate`, `run_session`, `_echo_session`,
  `StoreError → Exit(2)`). `--sibling` is repeatable.

- **Exports**: `Signature`/`signature_from_finding` from `deepthought.sibling`;
  `SiblingHuntSession` from `deepthought.sessions`.

- **Fixture**: `tests/fixtures/siblings.sarif` — two in-scope `inject:sql` results
  (same class, kept), one `path-injection` result (different class, dropped by the
  same-class filter), one out-of-scope `vendor/` `inject:sql` result (dropped by
  scope containment).

- **Smoke**: `scripts/smoke_004.sh` (+ hermetic `tests/test_smoke_004.py`) drives
  the loop through the CLI: register source + authorized sibling + an unauthorized
  (no-basis) sibling → DISCOVER a candidate → VERIFY it to `verified` (Noop-backed)
  → SIBLING HUNT (variants in source + authorized sibling, REFUSED for the
  unauthorized sibling, SKIPPED for an unregistered name) → `check` green → corrupt
  a variant → `check` fails. Asserts `save_project` is never called during the hunt
  and no scope/basis is mutated.

## Safety invariants (structural, not by filtering)

1. **READ-ONLY.** No subprocess, exec/eval, socket, urllib/requests, or Docker in
   the sibling-hunt code. `execution_enabled` stays `False`; `DockerSandbox.run()`
   is untouched. Nothing is transmitted.
2. **Per-project authority gate.** Cross-project reach is only ever downward through
   the same three-outcome gate. The session only ever *loads* projects
   (`get_project`); it never calls `save_project`, mutates a `scope_allowlist`, or
   sets an `authorization_basis`. The target set is fixed at dispatch and never
   grows. (Asserted directly by a Store spy in `test_sibling_hunt.py` and the smoke.)
3. **Envelope firewall (Article VIII)** reused unchanged: one `Envelope` per
   worker, ingested only via `Conductor.ingest`; hints inert; `detail_ref` never
   loaded; the coverage delta re-validated against each target's own authorization.
4. **Input firewall.** The signature is derived from typed fields; the finding body
   is never interpreted.
5. **OSV-valid by construction**; out-of-scope instances dropped before creation;
   candidates start `status=candidate` with fresh ids.

## Tests

- `tests/test_signature.py` — Signature model + typed-only derivation + injection
  inertness (11 tests).
- `tests/test_sibling_hunt.py` — gate, refusal rules, same-project variants,
  same-class filter, scope containment, cross-project per-target gating, authority
  invariants (Store spy), exports, OSV validity, and the `check` gate — plus the
  worker side-channel firewall hardening added across review (envelope + finding
  re-validation, id/lifecycle/scope/dedup rules, per-target isolation incl. the
  sibling gate step, ledger primitive normalization, concrete-locus requirement)
  (55 tests).
- `tests/test_cli_004.py` — CLI wiring, repeatable `--sibling`, `StoreError` exit
  (3 tests).
- `tests/test_smoke_004.py` — the hermetic end-to-end loop (1 test).

**380 passed** (310 baseline + 70 new). All four smokes pass.

## Review & merge

Reviewed under the standing dual-gate (both must be clean on the same HEAD):
**codex** (gpt-5.5, via the GitHub bot and — when the bot lagged — the local
`codex review --base main` CLI) and **agy** (Antigravity/Gemini adversarial CLI,
standing in for the quota-blocked `gemini-code-assist` bot). The review was
deliberately deep on the forward-looking threat model of an out-of-process /
compromised Marvin worker: the worker returns `(envelope, findings, detail)` and
the orchestrator must admit nothing it has not independently re-validated. Hardening
that landed across the rounds — envelope re-validation reused from the conductor,
per-finding `Finding.model_validate` re-validation, `F-\d+` id shape, candidate +
evidence-free lifecycle, attestation, same-class-primitive backing, NEW + dedup,
full-untruncated-locus scope containment, concrete (non-empty) locus requirement,
ledger primitive normalization to suspected same-class, and one per-target isolation
guard covering even the sibling gate step. Merged at squash `93ce057` with both
gates clean on `2202aa4`, 380 tests + four smokes green, zero unresolved threads.
