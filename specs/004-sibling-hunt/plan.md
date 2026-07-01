# Implementation Plan: Sibling Hunt — variant analysis

**Feature Branch:** `004-sibling-hunt`
**Spec:** `specs/004-sibling-hunt/spec.md`
**Created:** 2026-07-01

## Summary

Add the read-only half of variant analysis on top of the 001–003 harness: a
`SIBLING HUNT` session that takes a *verified* finding, derives a variant
`Signature` from its typed summary (closed lookup) and its location/pattern shape, gates
each target (the source project and every named, pre-registered sibling project)
independently, dispatches a stub Marvin per gated-proceed target, ingests only the
typed `Envelope` through the `Conductor`, writes the sibling instances as candidate
variant `Finding`s, and teaches back `Coverage(method='read')`. It mirrors DISCOVER
and reuses its firewall, its scope containment, its closed-lookup discipline, and
its OSV guarantee wholesale. No target code executes, no network path exists, and —
the sharp edge of this feature — **no session can create a project, widen a scope,
or hunt a target that lacks its own authorization basis.** This is what makes a
single confirmed bug find its whole family, safely.

## Decisions

1. **No new record types.** SIBLING HUNT reuses `Finding` (status `candidate`),
   `Coverage` (`method='read'`), and `Session`. Variant instances map *into* these
   existing shapes exactly as SARIF results do in DISCOVER. The variant `Signature`
   is a **runtime type**, not a persisted `Record` — like `SandboxSpec`/
   `SandboxResult` in 003, it is a typed value the session passes to the worker, not
   state on disk. Added structure that does not buy a capability or a safety
   property does not earn its place (Article IX).
2. **The signature is derived, never authored.** The variant `Signature` is built
   from *typed fields* of the source finding: `capability` from the finding's typed
   summary (closed lookup) — a `CAPABILITY_TAXONOMY` member — the finding's location
   shape, and the closed-lookup `match_terms` drawn from the same `ingest.sarif`
   heuristic vocabulary. (`signature_from_finding` also supports a bound-`Primitive.kind`
   path for direct callers/tests, but primitives are not persisted across sessions,
   so the session derives from the summary.) The finding's free-text body is
   **never** read as a hunt instruction. This is the injection boundary applied to the *input* side of the
   hunt: a hostile source finding can, at worst, fail to derive a usable signature —
   it can never mint a capability or a command.
3. **Scope and authorization are gated per target — never widened.** The source
   project is gated through the unchanged `run_session` harness. Each *named*
   sibling project is loaded from the Store (it must already exist), a
   `GateContext.from_project` is built for it, and it is gated **independently**
   with the same `DefaultGate`: no basis → refuse, empty scope → hold, clean → hunt.
   A sibling that is not registered, or that refuses/holds, is simply not hunted.
   **SIBLING HUNT never calls `save_project`, never mutates a `scope_allowlist`, and
   never sets an `authorization_basis`.** The set of huntable targets is exactly the
   source plus the named, pre-authorized siblings that pass their own gate.
4. **The Marvin is real in role, stubbed in runtime.** SIBLING HUNT dispatches one
   worker per gated-proceed target that returns exactly one `Envelope`, ingested
   through the existing `Conductor`. In 004 each worker is a deterministic stub
   (mirroring the DISCOVER stub); the envelope contract is the fixed seam, so the
   real pooled worker swaps in later with no caller change. The stub reasons over
   the signature + the target's in-scope areas (and any SARIF) for sibling
   instances, writes the candidate variants, pages detail, and returns the typed
   envelope.
5. **The ledger is the primitive home.** Suspected sibling primitives from a hunt
   enter the orchestrator's bounded ledger through envelope ingest, exactly as in
   DISCOVER. The session exposes `self.conductor` after `run` so a caller (and the
   acceptance test) can inspect the sibling primitives held.
6. **Reuse the DISCOVER machinery.** Finding-id allocation past the store max
   (`_next_finding_index` logic), the scope-contained-areas computation
   (`_coverage_areas`), the `sarif_to_findings`/`sarif_to_primitives` closed lookup
   with `scope`/`root` containment, the envelope construction, and the
   coverage-delta re-validation against the orchestrator's own authorization are all
   reused (extracted to a shared helper where DISCOVER already has it, or imported).
   SIBLING HUNT is a thin variant-analysis orchestration over the same parts.

## Technical Context

- **Language:** Python 3.12, matching 001–003.
- **Schema and validation:** Pydantic v2 models are unchanged. No new record types;
  `Finding`, `Coverage`, `Session` are reused as-is. The `Envelope`/`Primitive`
  contract from 001 is the worker boundary, unchanged. The `Signature` is a new
  runtime Pydantic model with `extra='forbid'`, not a `Record`.
- **New module:** `deepthought.sibling.signature` with the `Signature` model and
  `signature_from_finding(finding, primitives=None) -> Signature` (the session
  derives from the typed summary; the bound-primitive path stays for direct callers).
- **New session:** `deepthought.sessions.sibling_hunt.SiblingHuntSession`,
  subclassing `BaseSession` and run through `run_session`.
- **Reused modules:** `deepthought.scope` (`resolve_within`/`area_in_scope`),
  `deepthought.ingest.sarif` (closed lookup + OSV-valid finding construction),
  `deepthought.orchestrator` (`Conductor`/`Ledger`), `deepthought.protocol`
  (`Gate`/`GateContext`/`run_session`).
- **CLI:** one new Typer subcommand, `playbook sibling-hunt`.
- **Store:** unchanged interface. SIBLING HUNT writes `Finding`s and `Coverage`, and
  pages worker detail to `state/detail/`. All access goes through the `Store` —
  nothing reads or writes `state/` directly. It **reads** projects
  (`get_project`) but never writes one.
- **Gate:** `DefaultGate`/`HermesUltraCodeGate` unchanged. The three-outcome
  contract is used per target.
- **Execution / sandbox:** none. No target code runs; `execution_enabled` stays
  `False`; `DockerSandbox.run()` is untouched. This feature reads and reasons only.
- **Network:** none. No transmission path is added.
- **Testing:** pytest, test-first per Article VII. The 002 SARIF fixture is reused;
  a small second fixture and a second registered project drive the sibling-project
  and gate-refusal paths. `check` remains a runtime gate and is tested against
  SIBLING HUNT output.
- **Target platform:** the operator's Mac Studio dev lab.

## Constitution Check

Each of the nine articles, and how this design satisfies it.

- **I, gate-first.** The session runs through the same `run_session` harness that
  gates the source project before work. Each named sibling project is *also* gated
  independently (`GateContext.from_project` + `DefaultGate`) before any worker is
  dispatched for it; `hold`/`refuse` are logged with reasons. Pass.
- **II, authorization and scope. Highlighted.** SIBLING HUNT hunts only a project
  with an authorization basis and a scope allowlist. A sibling project is hunted
  *only if it already exists in the Store with its own basis* and passes the same
  gate. An out-of-scope location is never surveyed or reported (the `scope`/`root`
  containment in `ingest.sarif` and `deepthought.scope`). No session creates a
  project, widens a scope allowlist, or mints a basis — a scope/authority change is
  a new gated `NEW PROJECT`, never an in-session or cross-project expansion. This is
  the article this feature most directly stresses, and the mitigation is structural
  (see below). Pass, and a highlight.
- **III, sandbox. N/A for this feature.** Nothing executes target code — SIBLING
  HUNT reads files and reasons over static signals and SARIF a tool already
  produced. There is nothing to sandbox. The sandbox and its `execution_enabled`
  hard stop (003) are untouched; a variant is promoted only by a later sandboxed
  VERIFY. N/A (no execution).
- **IV, evidence and lifecycle.** Every variant SIBLING HUNT writes enters at
  `candidate` and advances no further: promotion needs a resolving `evidence_ref`
  that only a sandboxed VERIFY can produce. The lifecycle guard at the Store
  boundary is unchanged and untouched by this feature. Pass.
- **V, coordinated disclosure.** Nothing leaves the machine. There is no network
  path in SIBLING HUNT; `publish` still emits local artifacts and asserts the human
  gate. Pass.
- **VI, durable state.** SIBLING HUNT teaches back variant findings and coverage,
  and writes a session log with `## Next steps`. A session with no next steps does
  not close. Pass.
- **VII, validate-first.** Test-first: the signature derivation, the session, the
  CLI, and the gate-per-sibling behavior arrive with the tests that constrain them,
  written to fail first. Every generated variant's OSV passes `validate_osv`, and
  `check` is a required gate before `publish`. A variant that cannot be made
  OSV-valid is not written. Pass.
- **VIII, injection resistance. Highlighted.** Three hostile surfaces exist here and
  all three are contained structurally, not by filtering:
  - *The source finding as input.* The finding that seeds the hunt is
    attacker-influenceable (its body narrative came from untrusted SARIF in
    DISCOVER). The `Signature` is derived from **typed fields only** — the
    finding's typed summary (closed lookup, yielding a taxonomy member), the
    location shape, and closed-lookup `match_terms`. The finding body is never read
    as a hunt instruction. A hostile finding can, at worst, fail to yield a usable
    signature.
  - *SARIF as untrusted input.* Reused unchanged from DISCOVER: every SARIF string
    is data, copied only into finding fields, length-bounded, and the `ruleId` →
    capability mapping is a closed lookup an injected rule can only miss.
  - *The worker envelope.* The orchestrator ingests only the schema-validated,
    length-capped `Envelope` (the 001 firewall, unchanged). A prompt-injected
    Marvin can return nothing but this typed structure; hints never act;
    `detail_ref` content is never loaded; and the coverage delta is re-validated
    against the orchestrator's *own* authorization, so a worker cannot widen scope
    through the coverage channel. Pass, and a highlight.
- **IX, minimalism and least privilege. Highlighted.** The Marvin holds the minimum
  context for one hunt task; the orchestrator keeps its bounded ledger. The two new
  units (the `Signature` model, the session) each buy a concrete capability or a
  safety boundary. The hunt **never auto-expands the loop's authority**: the set of
  huntable targets is exactly the source project plus the *named, pre-authorized*
  siblings that pass their own gate — the session cannot invent a target, cannot
  register one, and cannot widen one. Pass, and a highlight.

Tension noted: SIBLING HUNT is the first session that reasons across *more than one
project*, which is exactly where an authority-widening bug would hide. The
mitigation is that cross-project reach is *only ever downward through the same
gate*: every sibling is loaded from the Store (must pre-exist), gated
independently, and hunted only on proceed — with no code path that writes a
project or a scope. See Complexity Tracking.

## Architecture

### Read-only variant-analysis flow

```
        operator
           │
   launcher (SIBLING HUNT: source project + verified finding + named siblings)
           │
           ▼
  ┌──────────────────────────────────────┐
  │  Deep Thought core (orchestrator)     │
  │  bounded ledger + exploit graph       │
  └──────────────────────────────────────┘
     │  derive Signature (typed fields only)
     │
     │  for EACH target (source, then each NAMED sibling):
     │     GateContext.from_project(target) ── DefaultGate ──▶ proceed | hold | refuse
     │        │ proceed                              │ hold/refuse → log, no worker, no finding
     ▼        ▼
  ┌───────────────┐   dispatch one worker per gated-proceed target
  │ Marvin (stub) │ ── reasons over signature + target in-scope areas (+ SARIF)
  └───────────────┘
     │  detail → Store          ▲  envelope only
     ▼                          │
  ┌────────────────────────────────────────┐
  │ Conductor.ingest(envelope)  (firewall)  │ ── primitives → Ledger
  └────────────────────────────────────────┘
     │  variant findings(status=candidate) + read coverage
     ▼
   version-controlled state (the Store)
```

- SIBLING HUNT loads the *verified* source finding, derives the `Signature`, and
  builds the target list: the source project, then each *named, pre-registered*
  sibling project (loaded via `get_project`; a missing one is skipped and logged).
- Each target is gated independently. Only a `proceed` target gets a worker.
- Each worker reasons over the signature and its target's in-scope areas (and any
  SARIF), writes the sibling instances as candidate variant findings *bound to that
  target's project id*, pages detail, and returns one `Envelope`.
- The orchestrator ingests each envelope through the `Conductor` (primitives land
  in the shared ledger), then teaches back read coverage for the areas reasoned
  over and the variants touched.

### The signature boundary (input firewall)

The source finding and its SARIF-derived body are untrusted. The `Signature` is
built from typed fields only: `capability` from the finding's typed summary
(closed lookup, a `CAPABILITY_TAXONOMY` member), `locus_pattern` from the finding's
location shape, and `match_terms` drawn from the same closed heuristic vocabulary
`ingest.sarif` uses. (The bound-`Primitive.kind` path stays supported for direct
callers/tests, but primitives are not persisted across sessions, so the session
derives from the summary.) No free-text is interpreted. Full model,
derivation, and outputs are in `contracts/sibling-hunt.md`.

### The per-target gate (authority firewall)

Cross-project reach is the feature's sharpest edge. Every target is gated through
the *same* three-outcome `DefaultGate` on a `GateContext.from_project`. A sibling
must pre-exist in the Store with its own basis; the session never writes a project
or a scope. The set of targets is fixed at dispatch time and never grows.

## Project structure (delta from 001–003)

New and changed paths only; everything else in the tree is unchanged.

```
src/deepthought/
  sibling/
    __init__.py            # NEW — exposes Signature, signature_from_finding
    signature.py           # NEW — Signature runtime model + derivation from a verified Finding
  sessions/
    sibling_hunt.py        # NEW — SiblingHuntSession: verified finding -> signature -> per-target gate+worker -> variants
    __init__.py            # CHANGED — export SiblingHuntSession
  cli.py                   # CHANGED — add `playbook sibling-hunt`
tests/
  fixtures/
    siblings.sarif         # NEW — a small SARIF fixture for the sibling-hunt tests + smoke (optional input)
  test_signature.py        # NEW — signature derivation (typed fields only; hostile body inert)
  test_sibling_hunt.py     # NEW — the session: same-project + sibling-project + gate refusal + OSV + ledger + firewall
  test_cli_004.py          # NEW — `playbook sibling-hunt` wiring and error handling
scripts/
  smoke_004.sh             # NEW — the 004 read-only variant smoke
specs/004-sibling-hunt/{spec.md, plan.md, data-model.md, contracts/, tasks.md}
```

The `.claude/skills/deep-thought-protocol/SKILL.md` session-type playbook gains a
SIBLING HUNT entry (documentation, not code).

## Phase 0 — unknowns

All 004 blockers were resolved before this feature (see `docs/phase-0-decisions.md`
and the 002/003 plans): the gate is the confirmed-unconfirmed default adapter, OSV
is pinned, the capability taxonomy shape is fixed, and the envelope/scope/SARIF
machinery this feature reuses is already tested. Nothing new blocks 004. The open
questions in `spec.md` (signature fidelity, sibling-project discovery, coverage
depth, real Marvin runtime) are non-blocking and refined against real runs.

## Phase 1 — design outputs

- `data-model.md`: how SIBLING HUNT reuses `Finding` (candidate), `Coverage`, and
  `Session` with no new record types; the runtime `Signature` model and its
  derivation from a verified `Finding` + its `Primitive`s; the variant-instance →
  `Finding` and variant-instance → suspected `Primitive` mappings (reusing the
  DISCOVER/SARIF path); and the OSV-validity guarantee.
- `contracts/sibling-hunt.md`: the `SiblingHuntSession` flow, the signature
  contract (derived-from-typed-fields property), the per-target gate rules
  (same-project vs sibling-project; pre-exist + own basis + same gate; never
  create/widen), the envelope firewall reuse, and how variants and primitives flow
  to the Store and the Ledger.

## Complexity Tracking

| Added complexity | Why it is justified | How it is bounded |
| --- | --- | --- |
| A variant `Signature` runtime type | Variant analysis needs a typed description of the bug class to hunt for — the roadmap's "derive a signature from a verified finding" | Runtime type, not a `Record`; derived from typed fields only (`Primitive.kind`, location shape, closed-lookup `match_terms`); the finding body is never read as instruction. |
| Cross-project reach (sibling projects) | Real variant analysis finds the same bug copied into sibling projects | Each sibling must pre-exist in the Store with its own basis and pass the *same* gate independently; the session never writes a project or a scope; the target set is fixed at dispatch and never grows. |
| A new session type | SIBLING HUNT is the roadmap's variant-analysis session | Read-only; runs through the unchanged gate + harness; reuses the DISCOVER firewall, scope containment, and OSV guarantee; cannot execute code or widen authority. |
| A third untrusted input surface (the source finding) | The hunt is seeded by a finding whose body came from untrusted SARIF | Same discipline as the envelope firewall — the signature is derived from typed fields only; a hostile finding can at worst fail to yield a usable signature. |

## Validation — the 004 smoke

1. Register a real in-scope source target and a second, *independently authorized*
   sibling target with `NEW PROJECT` sessions (reuse the 001 path: real
   local_path/permissive-OSS basis, scope allowlist each). Also register (or name)
   a third sibling with **no basis** to prove the gate refusal.
2. DISCOVER a candidate on the source over the bundled SARIF, then VERIFY it to
   `verified` (Noop-backed, 002+003), so there is a confirmed bug class to hunt.
3. Run a SIBLING HUNT from the verified finding. It derives a signature, produces
   variant candidates in the source's in-scope areas and in the authorized sibling,
   and is **refused at the gate** for the unauthorized sibling — creating no project
   and widening no scope. The ledger holds the sibling primitives (`self.conductor`).
4. `check` is green: every variant candidate's OSV validates. Then hand-corrupt a
   variant and confirm `check` fails hard.
5. `publish` prepares local OSV artifacts and asserts the human gate — nothing is
   transmitted.

Passing all five proves the read-only variant loop: a signature derived from a
confirmed bug, variant candidates across the source and an *authorized* sibling, a
sibling refused for lack of authorization (no widening), OSV-valid variants, the
ledger holding sibling primitives, and still no execution.
