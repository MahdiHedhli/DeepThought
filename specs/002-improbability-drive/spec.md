# Feature Spec: Improbability Drive — DISCOVER and MAP (002)

**Feature Branch:** `002-improbability-drive`
**Created:** 2026-07-01
**Status:** Draft

## Problem

Feature 001 delivered the governed spine and proved it with the two lowest-risk
session types, `NEW PROJECT` and `STATUS`. It records nothing about a target's
attack surface and produces no findings of its own: there is no session that
reads a real repository, no way to turn a static-analysis tool's output into
findings, and no first worker (Marvin) that discovers anything. The spine is
safe but inert.

This feature is the first turn of the **Improbability Drive** — the discovery
and attack-surface-mapping engine. It is deliberately the read-only half. It
reasons over code and over SARIF that a tool already produced; it runs no target
code, transmits nothing, and cannot widen its own scope or authorization. The
dangerous capabilities — executing a repro, fuzzing, reaching the network — stay
behind the sandbox that lands in feature 003. This feature is what makes a
subsequent `VERIFY` have candidates worth verifying.

## Goal

Add two session types on top of the 001 harness:

- **MAP** — walk the in-scope paths of a real registered repository, read-only,
  and record `Coverage(method='read')` for what was surveyed.
- **DISCOVER** — run a stub Marvin worker that reasons over static signals and an
  ingested SARIF file, emits an `Envelope`, and produce candidate `Finding`s plus
  the suspected `Primitive`s the ledger holds. Every generated finding exports to
  valid OSV.

Prove the whole read-only loop end to end: a MAP session records coverage for a
real in-scope repo, a DISCOVER session produces candidate findings from static
signals and SARIF, every finding passes `check`, and the ledger holds the
discovered primitives. Still no execution, no transmission, no scope widening.

## Scope

**In scope**

- A SARIF ingest module (`deepthought.ingest.sarif`): parse an accepted subset of
  SARIF 2.1.0 into candidate `Finding`s and into suspected `Primitive`s via a
  conservative `ruleId`/tag → capability-taxonomy heuristic.
- The **MAP** session type: read-only traversal of in-scope paths, writing
  `Coverage(method='read')`.
- The **DISCOVER** session type: dispatch a stub Marvin that emits a conforming
  `Envelope`, ingest it through the `Conductor` (so the ledger holds the
  primitives), write candidate `Finding`s to the Store, and teach back.
- CLI wiring: `playbook map` and `playbook discover`.
- A `DefaultGate` honesty rename in `deepthought.protocol.gate`: make the
  built-in default adapter the canonically named class, with
  `HermesUltraCodeGate` retained as a subclass that currently delegates to it
  (its real interface is still unconfirmed — see `docs/phase-0-decisions.md`
  §0.1).
- A 002 smoke script that drives the read-only loop through the CLI.

**Out of scope** (later features, behind their own gates)

- Any target-code execution and the sandbox (003). DISCOVER and MAP only read and
  reason; they never run a repro, a fuzzer, or the target.
- Network transmission of any kind (disclosure is 005; `publish` still only emits
  local artifacts and asserts the human gate).
- `VERIFY`, `SIBLING HUNT`, `DISCLOSURE` (003–005).
- The autonomous loop and limit awareness (006).
- New record types. DISCOVER/MAP reuse `Finding`, `Coverage`, and `Session`
  unchanged; the capability taxonomy vocabulary may grow but its shape is fixed.
- Scope or authorization widening of any kind. A DISCOVER or MAP session against
  an out-of-scope path is refused or held at the Gate, never silently expanded.

## User scenarios

1. **Map a real target.** An operator runs a `MAP` session on a registered,
   in-scope repository. The session walks the in-scope paths read-only and writes
   `Coverage(method='read', depth='touched')` records for the areas it surveyed.
   No finding is created and no code runs. A path outside the scope allowlist is
   not surveyed.
2. **Discover from static signals and SARIF.** An operator runs a `DISCOVER`
   session, optionally handing it a SARIF file from a static-analysis tool. A stub
   Marvin reasons over the signals, returns one `Envelope`, and the session writes
   candidate `Finding`s (status `candidate`) to the Store. The ledger holds the
   suspected primitives the worker reported. `self.conductor` is available after
   the run for inspection.
3. **Every finding is OSV-valid.** `check` passes on the state DISCOVER produced:
   every candidate finding's OSV validates against the pinned schema. A finding
   that could not be made OSV-valid is not written.
4. **Injection stays contained.** A SARIF file whose `message.text` or `ruleId`
   carries an injected instruction, and a Marvin whose free-text is hostile,
   change nothing beyond the typed structures. The orchestrator ingests only the
   `Envelope`; SARIF text lands only in finding fields that are data, never
   interpreted as instruction; `detail_ref` content is never loaded.
5. **The gate still governs.** A DISCOVER or MAP session against a project with no
   authorization basis is refused; a project with an empty scope allowlist is held
   (nothing is in scope). No session widens scope or authorization to proceed.

## Functional requirements

Each requirement names the constitution article it serves.

- **FR-1** Every DISCOVER and MAP session passes the Gate before any work; the
  outcome and reason are logged on the session. (Constitution I)
- **FR-2** DISCOVER and MAP run only against a project that carries an
  authorization basis and a scope allowlist; an out-of-scope path is never
  surveyed or reported, and no session widens its own scope or authorization.
  (Constitution II, IX)
- **FR-3** No target code executes in this feature. MAP reads files; DISCOVER
  reasons over static signals and SARIF a tool already produced. Capability that
  needs the sandbox does not exist here — it lands in 003. (Constitution III,
  honored by sequencing — N/A because nothing executes)
- **FR-4** Every candidate `Finding` DISCOVER writes enters at status `candidate`;
  it advances no further, because advancement requires evidence that only a
  sandboxed `VERIFY` can produce. (Constitution IV)
- **FR-5** Every generated `Finding` exports to OSV that passes `validate_osv`;
  `check` is green on the state DISCOVER and MAP produce. A finding that cannot be
  made OSV-valid is not written. (Constitution VII)
- **FR-6** Each MAP and DISCOVER session teaches back: MAP writes coverage,
  DISCOVER writes findings and coverage, and both write a session log with
  explicit `## Next steps`. A session with no next steps does not close.
  (Constitution VI)
- **FR-7** The orchestrator ingests only the schema-validated, length-capped
  `Envelope` the Marvin emits; SARIF free-text is treated as data, mapped only
  into finding fields, never interpreted as instruction; a hint never acts and
  `detail_ref` content is never loaded. (Constitution VIII)
- **FR-8** Nothing leaves the machine. DISCOVER and MAP transmit nothing; there is
  no network path in this feature. (Constitution V)
- **FR-9** Workers hold the minimum context for one task and the orchestrator
  keeps its bounded working set (the ledger); the SARIF ingest and the Marvin
  stub add structure only where it buys the discovery capability or an injection
  boundary. (Constitution IX)

## Acceptance criteria

The five roadmap criteria for 002, each a check the 002 smoke and test suite
assert:

1. A **MAP** session records coverage (`method='read'`) for a real, in-scope
   repository.
2. A **DISCOVER** session produces candidate findings from static signals and
   SARIF.
3. **Every finding exports to valid OSV** (passes `validate_osv`; `check` is
   green).
4. **The ledger holds the discovered primitives** after a DISCOVER session
   (inspectable via `self.conductor`).
5. **Still no execution** — no target code runs anywhere in the build; MAP and
   DISCOVER are read-and-reason only.

## Open questions

- **SARIF-to-Primitive fidelity.** The `ruleId`/tag → capability heuristic is
  deliberately conservative: an unmapped rule yields a candidate finding but no
  primitive (a finding without a suspected primitive is allowed). The starter
  mapping table in `contracts/sarif-ingest.md` is expected to grow as real tool
  output is seen; the *shape* is fixed here. Non-blocking.
- **Coverage depth from a read-only pass.** MAP records `depth='touched'` for a
  surveyed path. Whether a static reasoning pass ever earns `explored` versus
  `touched` without executing anything is left to the implementer's judgment and
  refined against real runs. Non-blocking.
- **Real Marvin runtime.** DISCOVER dispatches a *stub* Marvin in 002; the real
  worker runs on the abundant pool (Codex) later. The envelope contract is the
  fixed seam, so swapping the stub for the real worker changes no caller.
  Non-blocking, carried from 001.
- Carried from 001, still non-blocking for this feature: the Threatpedia/Store
  repository boundary and the disclosure export templates (both feature 005).

## Success criteria

The 002 smoke in `plan.md` passes end to end: register a real in-scope target
(001 `NEW PROJECT`), MAP it and see `read` coverage, DISCOVER over a bundled SARIF
fixture and see candidate findings plus ledger primitives, `check` green, and
`publish` still transmitting nothing. `check` stays green on the produced state
and red on a hand-corrupted finding. No target code executes anywhere. Every 001
test stays green.
