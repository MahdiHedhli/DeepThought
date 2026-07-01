# Implementation Plan: Improbability Drive — DISCOVER and MAP

**Feature Branch:** `002-improbability-drive`
**Spec:** `specs/002-improbability-drive/spec.md`
**Created:** 2026-07-01

## Summary

Turn the inert 001 spine into the read-only half of the Improbability Drive. Add
two typed session types — `MAP` (read-only attack-surface coverage of a real
repo) and `DISCOVER` (candidate findings from static signals and ingested SARIF,
with the discovered primitives held in the ledger) — plus a SARIF ingest module
and the CLI wiring for both verbs. Rename the built-in gate adapter to
`DefaultGate` for honesty about what actually runs. No target code executes, no
network path exists, and no session can widen its own scope or authorization.
This is what gives a later `VERIFY` candidates worth verifying.

## Decisions

1. **No new record types.** DISCOVER and MAP reuse `Finding` (status
   `candidate`), `Coverage` (`method='read'`), and `Session`. SARIF results map
   *into* these existing shapes. The capability-taxonomy vocabulary may grow; its
   shape is fixed. Added structure that does not buy a capability or a safety
   property does not earn its place (Article IX).
2. **SARIF is ingest-only, read-only, and untrusted input.** We accept a small,
   explicit subset of SARIF 2.1.0 (`runs[].results[]` with `ruleId`,
   `message.text`, `level`, `locations[].physicalLocation`). SARIF text is data:
   it lands only in finding fields, never in a channel the orchestrator
   interprets as instruction. Unknown fields are ignored, not trusted.
3. **The Marvin is real in role, stubbed in runtime.** DISCOVER dispatches a
   worker that returns exactly one `Envelope`, ingested through the existing
   `Conductor`. In 002 the worker is a deterministic stub (extending the 001
   `marvin_stub`); the envelope contract is the fixed seam, so the real
   pooled worker swaps in later with no caller change.
4. **The ledger is the primitive home.** Suspected primitives from a DISCOVER run
   enter the orchestrator's bounded ledger through envelope ingest, exactly as in
   001. The session exposes `self.conductor` after `run` so a caller (and the
   acceptance test) can inspect the discovered primitives.
5. **Gate honesty rename.** The class that actually runs is the built-in default
   adapter, so it becomes `DefaultGate`, the canonical unconfirmed-default gate.
   `HermesUltraCodeGate` stays importable as a subclass that currently delegates
   to `DefaultGate`, its docstring stating the real interface is unconfirmed.
   This matches `docs/phase-0-decisions.md` §0.1 and keeps every 001 caller and
   test green.

## Technical Context

- **Language:** Python 3.12, matching 001.
- **Schema and validation:** Pydantic v2 models are unchanged. No new record
  types; `Finding`, `Coverage`, `Session` are reused as-is. The `Envelope` and
  `Primitive` contracts from 001 are the worker boundary.
- **SARIF:** parsed as a plain `dict` (via `json`), then a hand-written subset
  reader — no SARIF SDK dependency, so the accepted surface is small, explicit,
  and auditable. Nothing beyond the documented subset is read.
- **New module:** `deepthought.ingest.sarif` with `sarif_to_findings`,
  `sarif_to_primitives`, and `load_sarif`.
- **New sessions:** `deepthought.sessions.map.MapSession` and
  `deepthought.sessions.discover.DiscoverSession`, both subclassing
  `BaseSession` and run through `run_session`.
- **CLI:** two new Typer subcommands, `playbook map` and `playbook discover`.
- **Store:** unchanged interface. MAP writes `Coverage`; DISCOVER writes
  `Finding`s and `Coverage`, and pages worker detail to `state/detail/`. All
  access goes through the `Store` — nothing reads or writes `state/` directly.
- **Gate:** `DefaultGate` (renamed) + `HermesUltraCodeGate` (subclass,
  delegates). The three-outcome contract is unchanged.
- **Execution / sandbox:** none. No target code runs. This feature reads and
  reasons only.
- **Network:** none. No transmission path is added.
- **Testing:** pytest, test-first per Article VII. A bundled SARIF fixture drives
  the DISCOVER tests and the smoke. `check` remains a runtime gate and is tested
  against DISCOVER/MAP output.
- **Target platform:** the operator's Mac Studio dev lab.

## Constitution Check

Each of the nine articles, and how this design satisfies it.

- **I, gate-first.** Both new session types run through the same `run_session`
  harness that gates before work. `MapSession` and `DiscoverSession` build a
  `GateContext` from the stored project; `hold`/`refuse` are logged with reasons.
  Pass.
- **II, authorization and scope.** DISCOVER and MAP run only against a project
  with an authorization basis and a scope allowlist. MAP surveys only in-scope
  paths; an out-of-scope path is never walked or reported. An empty allowlist is
  held (nothing is in scope). Pass.
- **III, sandbox. N/A for this feature.** Nothing executes target code — MAP
  reads files, DISCOVER reasons over static signals and a SARIF file a tool
  already produced. There is nothing to sandbox. The sandbox lands in 003 before
  any `VERIFY` runs code; this feature is honored by the same sequencing 001 used.
  N/A (no execution).
- **IV, evidence and lifecycle.** Every finding DISCOVER writes enters at
  `candidate` and advances no further: promotion needs a resolving `evidence_ref`
  that only a sandboxed `VERIFY` can produce. The lifecycle guard at the Store
  boundary is unchanged and untouched by this feature. Pass.
- **V, coordinated disclosure.** Nothing leaves the machine. There is no network
  path in DISCOVER or MAP; `publish` still emits local artifacts and asserts the
  human gate. Pass.
- **VI, durable state.** MAP teaches back coverage; DISCOVER teaches back findings
  and coverage; both write a session log with `## Next steps`. A session with no
  next steps does not close. Pass.
- **VII, validate-first.** Test-first: the SARIF ingest, both sessions, the CLI,
  and the gate rename arrive with the tests that constrain them, written to fail
  first. Every generated finding's OSV passes `validate_osv`, and `check` is a
  required gate before `publish`. A finding that cannot be made OSV-valid is not
  written. Pass.
- **VIII, injection resistance. Highlighted.** Two hostile surfaces exist here and
  both are contained structurally, not by filtering:
  - *The worker envelope.* The orchestrator ingests only the schema-validated,
    length-capped `Envelope` (the 001 firewall, unchanged). A prompt-injected
    Marvin can return nothing but this typed structure; hints never act;
    `detail_ref` content is never loaded.
  - *SARIF as untrusted input.* A SARIF file is attacker-influenceable (its
    `message.text`, `ruleId`, and locations can carry injected instructions). The
    ingest treats every SARIF string as **data**: it is copied only into finding
    fields (`summary`, body narrative, references), never into a field the
    orchestrator or the harness interprets as instruction, and it is length-bounded
    on the way into the length-capped envelope/finding fields. The `ruleId` → 
    capability mapping is a fixed lookup table, so an injected `ruleId` yields, at
    worst, an unmapped rule (a finding with no primitive) — it cannot mint an
    arbitrary capability or a command. Pass, and a highlight.
- **IX, minimalism and least privilege.** The Marvin holds the minimum context for
  one discovery task; the orchestrator keeps its bounded ledger. The two new
  modules (SARIF ingest, two sessions) each buy a concrete capability or a safety
  boundary. No session can widen its own scope or authorization — a scope change
  is a new gated `NEW PROJECT`, never an in-session expansion. Pass.

Tension noted: DISCOVER introduces a second untrusted input surface (SARIF) on
top of the worker plane. The mitigation is the same discipline as the envelope —
SARIF text is data mapped into fixed fields and the `ruleId` mapping is a closed
lookup — so the added surface buys the discovery capability without opening a new
instruction channel. See Complexity Tracking.

## Architecture

### Read-only discovery flow

```
        operator
           │
   launcher (MAP | DISCOVER + config)
           │
           ▼
  ┌──────────────────────────────────────┐
  │  Deep Thought core (orchestrator)     │
  │  bounded ledger + exploit graph       │
  └──────────────────────────────────────┘
     │  dispatch          ▲  envelope only
     ▼                    │
  ┌───────────────┐   ┌────────────────────────┐
  │ Marvin (stub) │   │ SARIF ingest            │
  │ static reason │   │ runs[].results[] subset │
  └───────────────┘   └────────────────────────┘
     │  detail → Store        │  findings + suspected primitives
     ▼                        ▼
   version-controlled state (the Store)
   coverage(method=read) │ findings(status=candidate) │ sessions
```

- **MAP** walks the in-scope paths read-only and writes `Coverage(method='read')`.
  It dispatches no worker and reads no SARIF; it is the simpler of the two.
- **DISCOVER** optionally loads a SARIF file, runs a stub Marvin over the static
  signals, ingests the returned envelope through the `Conductor` (primitives land
  in the ledger), writes the candidate findings to the Store, and teaches back.
  SARIF results map to candidate findings and, via the conservative heuristic, to
  suspected primitives.

### SARIF ingest boundary

SARIF is the second untrusted surface. The ingest module reads only the
documented subset, maps each result to a candidate `Finding` (data only) and,
where the `ruleId`/tags match the fixed heuristic table, to a suspected
`Primitive` at `confidence: suspected` (never `demonstrated` — nothing was
executed). Full mapping, table, and outputs are in
`contracts/sarif-ingest.md`.

### The gate seam, made honest

001 shipped `HermesUltraCodeGate` as the named seam that actually ran the default
local rules. Phase 0 §0.1 recorded that the real HermesUltraCode interface is
unconfirmed and the platform runs on the default adapter. 002 makes the code say
what is true: `DefaultGate` is the canonical class; `HermesUltraCodeGate`
subclasses it and currently delegates, with a docstring noting the real interface
is unconfirmed. The three-outcome contract and every existing import stay intact.

## Project structure (delta from 001)

New and changed paths only; everything else in the 001 tree is unchanged.

```
src/deepthought/
  ingest/
    __init__.py           # NEW — exposes sarif_to_findings, sarif_to_primitives, load_sarif
    sarif.py              # NEW — accepted SARIF 2.1.0 subset -> Finding/Primitive
  sessions/
    map.py                # NEW — MapSession: read-only coverage
    discover.py           # NEW — DiscoverSession: SARIF + stub Marvin -> candidate findings
    __init__.py           # CHANGED — export MapSession, DiscoverSession
  protocol/
    gate.py               # CHANGED — DefaultGate (canonical) + HermesUltraCodeGate (subclass, delegates)
    __init__.py           # CHANGED — export DefaultGate; keep HermesUltraCodeGate
  cli.py                  # CHANGED — add `playbook map` and `playbook discover`
tests/
  fixtures/
    sample.sarif          # NEW — a small SARIF 2.1.0 fixture for tests + smoke
  test_sarif_ingest.py    # NEW
  test_map.py             # NEW
  test_discover.py        # NEW
  test_gate.py            # CHANGED — DefaultGate is canonical; HermesUltraCodeGate still passes
scripts/
  smoke_002.sh            # NEW — the 002 read-only smoke
specs/002-improbability-drive/{spec.md, plan.md, data-model.md, contracts/, tasks.md}
```

The `.claude/skills/deep-thought-protocol/SKILL.md` session-type playbook gains
DISCOVER and MAP entries (documentation, not code).

## Phase 0 — unknowns

All 002 blockers were resolved before this feature (see
`docs/phase-0-decisions.md`): the gate is the confirmed-unconfirmed default
adapter, OSV is pinned at 1.7.0, and the 003 sandbox is chosen but not built.
Nothing new blocks 002. The open questions in `spec.md` (SARIF→primitive
fidelity, coverage depth, real Marvin runtime) are non-blocking and refined
against real runs.

## Phase 1 — design outputs

- `data-model.md`: how DISCOVER/MAP reuse `Finding` (candidate), `Coverage`, and
  `Session` with no new record types; the SARIF-result → `Finding` and SARIF-result
  → suspected `Primitive` mappings; the OSV-validity guarantee.
- `contracts/sarif-ingest.md`: the accepted SARIF 2.1.0 subset, the outputs, the
  rule → capability heuristic table, and how findings and primitives flow to the
  Store and the Ledger.

## Complexity Tracking

| Added complexity | Why it is justified | How it is bounded |
| --- | --- | --- |
| SARIF ingest module | Turns existing tool output into findings — the roadmap's "SARIF ingest into findings" | Reads a small documented subset only; SARIF text is data mapped into fixed finding fields; `ruleId` → capability is a closed lookup table. |
| A second untrusted input surface (SARIF) | Real discovery must consume tools it did not run | Same discipline as the envelope firewall — no SARIF string is ever interpreted as instruction; length-bounded into capped fields. |
| Two new session types | MAP and DISCOVER are the roadmap's "first real Marvins" and coverage | Both are read-only, both run through the unchanged gate + harness, neither can widen scope or execute code. |
| `DefaultGate` rename | Honesty: the code should name what actually runs (Phase 0 §0.1) | Pure rename + subclass; three-outcome contract and all 001 imports unchanged; 001 tests stay green. |

## Validation — the 002 smoke

1. Register a real in-scope target with a `NEW PROJECT` session (reuse the 001
   path: real git URL, permissive-OSS basis, scope allowlist).
2. Run a `MAP` session on it. `Coverage(method='read')` records appear for the
   in-scope areas. No finding, no code execution.
3. Run a `DISCOVER` session with the bundled SARIF fixture. Candidate findings
   appear in the Store; the ledger holds the suspected primitives
   (`self.conductor`).
4. `check` is green: every candidate finding's OSV validates. Then hand-corrupt a
   finding and confirm `check` fails hard.
5. `publish` prepares local OSV artifacts and asserts the human gate — nothing is
   transmitted.

Passing all five proves the read-only Improbability Drive: coverage of a real
target, candidate findings from static signals and SARIF, OSV-valid findings, the
ledger holding discovered primitives, and still no execution.
