# Feature Spec: Sibling Hunt — variant analysis (004)

**Feature Branch:** `004-sibling-hunt`
**Created:** 2026-07-01
**Status:** Draft

## Problem

Features 001–003 built the governed spine, the read-only Improbability Drive
(MAP/DISCOVER), and the execution boundary (the sandbox and VERIFY). A candidate
can now be promoted to `verified` on sandboxed evidence. But a single verified
bug is rarely the only instance of its class: the same mistake tends to recur —
the same unsafe sink called from three other call sites, the same missing check
in a sibling module, the same pattern copied into a sibling project. Today the
platform learns nothing from a confirmation. Once VERIFY confirms a bug, the
knowledge that "this bug class exists here, in this shape" evaporates; a human
has to notice the pattern and re-run DISCOVER by hand.

This feature is **SIBLING HUNT** — variant analysis. It takes a *verified*
finding (a confirmed bug class), derives a **variant signature** from it (its
capability/`Primitive` plus the code-pattern/location shape that produced it),
and hunts for **sibling instances** of the same bug class — first across the
in-scope areas of the finding's own project, then across *sibling projects* that
are already registered with their own authorization. Each sibling instance
becomes a new candidate `Finding` (a variant), OSV-valid by construction, at
status `candidate`, waiting for its own VERIFY.

SIBLING HUNT is deliberately the **read-only** half of variant analysis, exactly
as DISCOVER is the read-only half of discovery. It reasons over code and over the
signals a tool already produced; it executes nothing, transmits nothing, and —
the sharp edge of this feature — it **cannot widen its own authority**. Hunting a
sibling project requires that project to *already* exist in the Store with its
*own* authorization basis, and the hunt passes the *same* Gate for it. SIBLING
HUNT never creates a project, never widens a scope allowlist, and never hunts a
target that lacks an authorization basis. It mirrors the DISCOVER session's shape
and reuses its firewall, its scope containment, and its OSV guarantee wholesale.

## Goal

Add one session type on top of the 001–003 harness:

- **SIBLING HUNT** — take a `verified` finding, derive a variant `Signature` from
  its typed summary (closed lookup) and its location/pattern shape, gate each target,
  dispatch a stub Marvin worker per target that reasons over static signals (and
  an optional SARIF) for sibling instances, ingest exactly one `Envelope` per
  worker through the `Conductor`, write the new candidate `Finding`s (the
  variants) to the Store, and teach back `Coverage(method='read')` for the areas
  reasoned over. Every generated variant exports to valid OSV.

Prove the whole read-only variant loop end to end: a SIBLING HUNT session started
from a verified finding derives a signature, finds sibling candidates in the
finding's own in-scope areas, finds sibling candidates in a *pre-registered,
authorized* sibling project (and is *refused/held at the gate* for a sibling
project lacking a basis or scope), writes the variants as candidates, `check` is
green, and the ledger holds the sibling primitives. Still no execution, no
transmission, and — critically — no authorization or scope widening.

## Scope

**In scope**

- A **variant `Signature`** model (`deepthought.sibling.signature`): a runtime
  (non-`Record`) type derived from a verified `Finding`'s typed summary (closed
  lookup). It carries the bug class's `capability` (a `CAPABILITY_TAXONOMY`
  member), the location/pattern shape (a normalized `locus_pattern` and the source
  `ruleId`/tag hints where present), and a bounded set of `match_terms` (the closed
  lookup keys the hunt matches on). (`signature_from_finding` also supports a
  bound-`Primitive.kind` path for direct callers/tests, but primitives are not
  persisted across sessions, so the session derives from the summary.) The
  signature is **derived**, never free-text authored — it is built from the typed
  summary via a closed lookup, so a hostile finding body can never become a hunt
  instruction.
- The **`SiblingHuntSession`** (`deepthought.sessions.sibling_hunt`): subclasses
  `BaseSession`, `.type = SessionType.sibling_hunt` (already in the enum), runs
  through the unchanged `run_session` harness and Gate. It loads a *verified*
  source finding, derives the signature, gates the source project, and (for each
  requested, pre-registered sibling project) gates that project independently;
  dispatches one stub Marvin per gated-proceed target; ingests only the typed
  `Envelope` per worker through a `Conductor`; writes the variant candidate
  findings; and teaches back read coverage plus next steps.
- **Reuse, not reinvention.** SIBLING HUNT reuses `Finding` (status `candidate`),
  `Coverage` (`method='read'`), `Session`, the `Envelope`/`Primitive`/`Conductor`
  firewall, `deepthought.scope` containment, and the `ingest.sarif` closed lookup
  and OSV guarantee. No new record type, no new Store method, no new gate.
- **CLI wiring:** `playbook sibling-hunt --project <id> --finding <F-NNNN>
  [--sibling <id> ...] [--sarif <path>] [--root <path>]`.
- A **004 smoke** (`scripts/smoke_004.sh` + a test) that drives the read-only
  variant loop through the CLI, including the gate refusal for an unauthorized
  sibling.

**Out of scope** (later features, behind their own gates)

- Any target-code execution. SIBLING HUNT reasons and reads only; it never runs a
  repro, a fuzzer, or the target. Promotion of a variant to `verified` is a
  sandboxed VERIFY (003) concern, unchanged. It never enables the sandbox
  (`execution_enabled` stays `False`; `DockerSandbox.run()` is the untouched hard
  stop).
- Network transmission of any kind. There is no network path in this feature.
- Creating or registering a project, widening a scope allowlist, or minting an
  authorization basis. A sibling project that is not already registered with its
  own basis is simply not hunted — never auto-created. Registration stays a gated
  `NEW PROJECT`.
- New record types. SIBLING HUNT reuses `Finding`, `Coverage`, `Session`; the
  `Signature` is a runtime type, not a persisted `Record`. The capability
  taxonomy is reused unchanged.
- `DISCLOSURE`, the autonomous loop and limit awareness (005–006).

## User scenarios

1. **Derive a signature from a confirmed bug.** An operator runs a SIBLING HUNT
   session naming a project and one of its `verified` findings. The session
   derives a variant `Signature` from the finding's typed summary (closed lookup)
   and its location/pattern shape — a typed, bounded structure. The signature is
   built from typed fields only; the finding's free-text body is never read as an
   instruction. A finding that is not `verified` is refused (there is no confirmed
   class to hunt).
2. **Hunt siblings in the finding's own project.** The session gates the source
   project (unchanged Gate), then dispatches a stub Marvin over the in-scope areas
   (and any SARIF) that reasons for other instances of the signature's bug class.
   Each in-scope sibling instance becomes a new candidate `Finding` (a variant)
   with a fresh, non-colliding id, at status `candidate`. A sibling instance whose
   location is out of scope is dropped before the finding is created.
3. **Hunt a pre-registered, authorized sibling project.** The operator names one
   or more sibling project ids. For each, the session loads the *already
   registered* project, builds a `GateContext.from_project`, and gates it
   **independently**. Only a sibling that proceeds is hunted, over *its own*
   in-scope areas; its sibling instances become candidate findings *bound to that
   sibling project*.
4. **A sibling without authorization is never hunted.** A named sibling project
   with no `authorization_basis` is refused at its own gate; a sibling with an
   empty scope allowlist is held (nothing is in scope). Either way, no worker is
   dispatched for it, no finding is created for it, and the session records the
   gate outcome and closes clean. **No project is created and no scope is widened
   to make a sibling huntable.**
5. **Every variant is OSV-valid.** `check` passes on the state SIBLING HUNT
   produced: every variant candidate's OSV validates against the pinned schema. A
   sibling instance that could not be made OSV-valid is not written.
6. **Injection stays contained.** A source finding whose body carries an injected
   instruction, a SARIF file whose `message.text`/`ruleId` is hostile, and a
   Marvin whose free-text is hostile all change nothing beyond the typed
   structures. The signature is derived from typed fields only; the orchestrator
   ingests only the `Envelope`; SARIF text lands only in finding data fields;
   `detail_ref` content is never loaded.
7. **The gate still governs, per target.** SIBLING HUNT gates the source project
   and *each* sibling project independently. No session widens scope or
   authorization to proceed, and no target is hunted without passing its own gate.

## Functional requirements

Each requirement names the constitution article it serves.

- **FR-1** Every SIBLING HUNT session passes the Gate before any work, and gates
  **each** target (the source project and every named sibling project)
  independently before any worker is dispatched for that target; every outcome and
  reason is logged on the session. (Constitution I)
- **FR-2** SIBLING HUNT hunts only a project that carries an authorization basis
  and a scope allowlist. It hunts a sibling project **only if that project already
  exists in the Store with its own `authorization_basis`** and passes the same
  Gate; an out-of-scope location is never surveyed or reported; and **no session
  creates a project, widens a scope allowlist, or mints an authorization basis**.
  (Constitution II, IX)
- **FR-3** No target code executes in this feature. SIBLING HUNT reads files and
  reasons over static signals and SARIF a tool already produced; it never enables
  the sandbox and never runs a repro. The sandbox hard stop (`DockerSandbox.run()`)
  is untouched. (Constitution III, honored by sequencing — nothing executes)
- **FR-4** Every variant `Finding` SIBLING HUNT writes enters at status
  `candidate` and advances no further; promotion of a variant requires evidence
  that only a sandboxed VERIFY can produce. SIBLING HUNT writes no `evidence_ref`.
  (Constitution IV)
- **FR-5** Every generated variant exports to OSV that passes `validate_osv`;
  `check` is green on the state SIBLING HUNT produces. A sibling instance that
  cannot be made OSV-valid is not written. (Constitution VII)
- **FR-6** Each SIBLING HUNT session teaches back: it writes the variant findings
  and `Coverage(method='read')` for the areas reasoned over, and a session log with
  explicit `## Next steps`. A session with no next steps does not close.
  (Constitution VI)
- **FR-7** The orchestrator ingests only the schema-validated, length-capped
  `Envelope` each Marvin emits; the source finding's body and SARIF free-text are
  treated as data, mapped only into signature `match_terms` (a closed lookup) and
  finding data fields, never interpreted as instruction; a hint never acts and
  `detail_ref` content is never loaded. (Constitution VIII)
- **FR-8** Nothing leaves the machine. SIBLING HUNT transmits nothing; there is no
  network path in this feature. (Constitution V)
- **FR-9** Workers hold the minimum context for one hunt task and the orchestrator
  keeps its bounded ledger; the signature model and the session add structure only
  where it buys the variant-analysis capability or a safety boundary. The hunt
  never auto-expands the loop's authority: the set of huntable targets is exactly
  the source project plus the *named, pre-authorized* siblings that pass their own
  gate. (Constitution IX)

## Acceptance criteria

The criteria for 004, each a check the 004 smoke and test suite assert:

1. A **SIBLING HUNT** session started from a `verified` finding **derives a
   variant `Signature`** from the finding's typed summary (closed lookup) and its
   location/pattern shape (typed fields only).
2. The session **produces new candidate variant findings** for sibling instances
   in the source project's in-scope areas (status `candidate`, fresh ids).
3. The session **hunts a pre-registered, authorized sibling project** and produces
   variant candidates bound to that sibling — and is **refused/held at the gate**
   for a sibling project lacking a basis (refuse) or scope (hold), creating no
   project and widening no scope.
4. **Every generated variant exports to valid OSV** (passes `validate_osv`;
   `check` is green).
5. **The ledger holds the sibling primitives** after the hunt (inspectable via
   `self.conductor`).
6. **Still no execution and no authority widening** — no target code runs anywhere
   in the build; SIBLING HUNT is read-and-reason only and never creates a project,
   widens a scope, or hunts an unauthorized target.

## Open questions

- **Signature fidelity.** The variant signature is derived conservatively: it uses
  the source finding's capability (from its typed summary via the closed lookup)
  and its location/pattern shape as the `match_terms` for the closed lookup,
  reusing the `ingest.sarif` heuristic
  vocabulary so a variant is only ever matched to a capability the taxonomy already
  defines. How rich the pattern shape becomes (AST/structural signatures vs. the
  ruleId/tag/CWE terms used here) is refined against real runs. The *shape* of the
  `Signature` is fixed here. Non-blocking.
- **Sibling-project discovery.** In 004 the sibling projects are *named* by the
  operator (or the CLI/caller). Auto-suggesting siblings from the Store (e.g. by
  shared ecosystem or fork lineage) is a later convenience — and even then, a
  suggested sibling is only ever hunted after it passes its own gate; suggestion
  never implies authorization. Non-blocking.
- **Coverage depth from a variant pass.** SIBLING HUNT records `depth='touched'`
  for a reasoned-over area, exactly like DISCOVER. Whether a variant pass ever
  earns `explored` without executing is left to the implementer's judgment and
  refined against real runs. Non-blocking.
- **Real Marvin runtime.** SIBLING HUNT dispatches a *stub* Marvin in 004; the real
  worker runs on the abundant pool later. The envelope contract is the fixed seam,
  so swapping the stub for the real worker changes no caller. Non-blocking, carried
  from 002.
- Carried from earlier features, still non-blocking: the confirmed HermesUltraCode
  gate interface (Phase 0 §0.1) and the Threatpedia/Store repository boundary.

## Success criteria

The 004 smoke passes end to end: register a real in-scope target and a second,
independently-authorized sibling target (001 `NEW PROJECT` ×2); DISCOVER a
candidate on the source and VERIFY it to `verified` (Noop-backed, 002+003); run a
SIBLING HUNT from the verified finding that derives a signature, produces variant
candidates in the source's in-scope areas and in the authorized sibling, and is
**refused at the gate** for a third, unauthorized sibling (no project created, no
scope widened); `check` green; the ledger holds the sibling primitives
(`self.conductor`); and `publish` still transmitting nothing. `check` stays green
on the produced state and red on a hand-corrupted variant. No target code executes
anywhere, and no authorization or scope is widened. Every 001–003 test stays green.
