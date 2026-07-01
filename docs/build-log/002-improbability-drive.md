# Build Session Log — Feature 002, Improbability Drive (DISCOVER + MAP)

**Feature:** 002-improbability-drive
**Branch:** `002-improbability-drive`
**Date:** 2026-07-01
**Orchestrator:** Deep Thought core. **Workers:** 8 dispatched (design, 4 implement
slices, verify, independent review, fix). **Gate:** running on the **default gate**
(real HermesUltraCode interface unconfirmed — phase-0 decision 0.1).

## What shipped

Read-only discovery and attack-surface mapping. No code execution, no
transmission, no scope widening.

- **SARIF ingest** (`src/deepthought/ingest/sarif.py`): `load_sarif` (JSON parse
  only, rejects non-2.1.0), `sarif_to_findings` (candidate Findings, OSV-valid by
  construction), `sarif_to_primitives` (conservative closed ruleId/CWE→capability
  table, `suspected` confidence). SARIF strings are treated as data only.
- **MAP session** (`sessions/map.py`): read-only walk of in-scope areas; writes
  `Coverage(method='read')`; executes nothing; never covers outside the allowlist.
- **DISCOVER session** (`sessions/discover.py`): dispatches one stub Marvin that
  writes candidate Findings and pages detail to the Store, and returns exactly one
  Envelope. The orchestrator ingests **only** that envelope through the Conductor
  (the injection firewall), so the Ledger holds the discovered primitives; it
  never reads the worker's free-text or the paged detail. Also teaches back
  `Coverage(method='read')` per in-scope area (FR-6).
- **DefaultGate honesty** (`protocol/gate.py`): `DefaultGate` is the concrete
  always-present adapter; `HermesUltraCodeGate` is a thin subclass delegating to
  it until the real interface is confirmed.
- **CLI**: `playbook map`, `playbook discover`. **Smoke**: `scripts/smoke_002.sh`.
- **Spec Kit artifacts**: `specs/002-improbability-drive/{spec,plan,data-model,tasks}.md`
  and `contracts/sarif-ingest.md`.

## Gate results (the done-gate)

| Gate | Result |
| --- | --- |
| Tests written first, `pytest -q` green | **151 passed** (99 across the 001 baseline files preserved, none weakened; +52 for 002) |
| Feature smoke end to end | `scripts/smoke_002.sh` **PASS** — MAP coverage(read)=1 area; DISCOVER=3 candidates; `check` OK; ledger holds 2 primitives (`inject:sql @ app/db.py:42`, `write:arbitrary-file @ app/files.py:17`) |
| 001 smoke still green | `scripts/smoke.sh` **PASS** |
| `/analyze` cross-artifact | **clean** (initial run flagged DISCOVER coverage drift; resolved in the fix pass — coverage now `method='read'` per data-model) |
| Constitution check | **pass** — II gate-first (no-basis refuses, empty-scope holds), III N/A (no execution), VI durable state, VII validate-first (check green), VIII injection firewall verified against hostile SARIF (injected message/ruleId, `javascript:` helpUri, 5000-char payload — orchestrator ingests only the typed envelope; detail never loaded; hints inert), IX least privilege |
| Independent review | Adversarial in-workflow review (non-author): **safety = pass**; verdict `changes_requested` was a soft flag for 3 spec-conformance/quality findings, **all fixed** in the fix pass |

## Acceptance criteria — all met

1. MAP records coverage for a real in-scope repo ✅ (this repo, `src/deepthought`)
2. DISCOVER produces candidate findings from static signals + SARIF ✅ (3)
3. Every finding exports to valid OSV ✅ (`check` OK)
4. Ledger holds the discovered primitives ✅ (2, via the envelope firewall)
5. Still no execution ✅ (grep-confirmed: no subprocess/exec/eval/socket/urllib)

## Review status & advance decision

**NOT merged.** The done-gate requires a real, independent *external* review; the
in-workflow adversarial review is a quality gate, not a substitute. Branch pushed
and a PR opened with `@codex review` / `/gemini review` requested. Per the
directive, silence / quota / error is an incomplete review, never a pass — so the
merge and the advance to 003 wait on a real review clearing **and** Mahdi's go.

## Next feature

**003 — Execution sandbox and VERIFY.** HARD STOP: the sandbox (ephemeral microVM,
default-deny egress — phase-0 decision 0.3) must be built, isolation-tested, and
**signed off by Mahdi** before any VERIFY executes target code. Awaiting sign-off.
