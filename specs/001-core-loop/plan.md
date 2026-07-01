# Implementation Plan: Platform Spine and Agent Session Protocol

**Feature Branch:** `001-core-loop`
**Spec:** `specs/001-core-loop/spec.md`
**Working name:** Deep Thought (proposed). Constitution and spec still say Anvil pending sign-off.
**Created:** 2026-06-30

## Summary

Build the governed spine of an autonomous security-research platform: durable
file-based state, a typed Agent Session Protocol, an orchestrator-plus-workers
execution model, and the three operator verbs. Prove it end to end with the two
lowest-risk session types. No code execution, no discovery, no disclosure yet.
This feature makes those safe to add.

## Decisions locked

1. State is flat files in git behind a store interface. Vector DB is a later, contained swap.
2. Schema aligns to standards. SARIF in, OSV for the finding record, CSAF and OpenVEX out.
3. Topology is an orchestrator plus a worker pool. Workers keep their own context. The orchestrator captures only distilled results.
4. Runtime is Python for the core. The three verbs stay the contract.

## Technical Context

- **Language:** Python 3.12.
- **Schema and validation:** Pydantic v2. The models are the canonical schema. They serialize to JSON for OSV export and validate front-matter on read.
- **CLI:** Typer. Exposes the three verbs: `playbook`, `check`, `publish`.
- **State store:** filesystem, Markdown plus YAML front-matter, version-controlled in the same repo. Accessed only through a `Store` interface (repository pattern).
- **Standards libraries:** `jsonschema` against the OSV schema for `check`. CSAF and OpenVEX generation deferred to feature 005. SARIF ingest deferred to features 002 and 003.
- **Templating:** Jinja2 for generated artifacts (advisories, OSV JSON) in later features. Not needed for 001 beyond OSV serialization.
- **Agent layer:** orchestrator runs on Claude Code (scarce, high quality). Workers run on Codex (abundant pool). This is the agent runtime and is independent of the Python core.
- **Pre-dispatch gate:** reuse HermesUltraCode as the gate and observability layer rather than rebuild. The platform calls it through a `Gate` adapter. Confirm the interface during Phase 0.
- **Target platform:** operator's Mac Studio dev lab.
- **Project type:** single project, CLI plus an agent-facing skill.
- **Testing:** pytest. Test-first per the constitution. `check` is a runtime gate and is itself tested.

## Naming map (proposed)

Deep Thought is the platform and the orchestrator core. Marvins are the workers.
Improbability Drive is the discovery and fuzzing engine (feature 002 onward).
Megadodo is the publish pipeline (feature 005). Magrathea remains the general
topology above all of this. None of these names are load-bearing in code for
001, so adopting or changing them is cheap.

## Constitution Check

Each relevant article, and how this design satisfies it.

- **I, gate-first.** Every session passes the `Gate` before work. Three outcomes, reasons logged. The harness enforces it. Pass.
- **II, authorization and scope.** `Project` carries an authorization basis and a scope allowlist. The gate refuses sessions against projects lacking a basis. Pass.
- **III, sandbox.** No code execution in 001, so nothing to sandbox yet. The sandbox lands in feature 003 before VERIFY can run code. Honored by sequencing. Pass for scope.
- **IV, evidence and lifecycle.** The lifecycle guard is implemented in 001 even though discovery and disclosure arrive later. Illegal transitions are rejected at the store boundary, not at the session. Pass.
- **V, coordinated disclosure.** `publish` emits local artifacts only and asserts a human gate. Nothing leaves the machine. Pass.
- **VI, durable state.** Every session writes findings, coverage, and a session log with next steps. State is the source of truth, read through the store. Pass.
- **VII, validate-first.** Test-first. `check` is a required gate before `publish`, and a `check` that errors counts as failed. Pass.
- **VIII, injection resistance.** Workers return only a schema-validated envelope. The orchestrator ingests the envelope, never worker free-text. A prompt-injected worker cannot propagate the injection past the typed boundary. The envelope schema is the firewall. This is a structural property of the topology, not a filter. Pass, and a highlight.
- **IX, minimalism and least privilege.** Workers hold the minimum context and capability for one task. The orchestrator's compact-state rule bounds its working set. The autonomous loop cannot expand its own scope (enforced from feature 006, scaffolded here). Pass.

Tension noted: a multi-agent topology adds moving parts versus a single agent
(Article IX favors small). The envelope discipline is the mitigation. It keeps
the orchestrator's context bounded and the worker surface narrow, so the added
structure buys context economy and an injection firewall rather than sprawl. See
Complexity Tracking.

## Architecture

### Execution model

```
                         operator
                            |
                  launcher (session type + config)
                            |
                            v
           +------------------------------------+
           |  Deep Thought core (orchestrator)  |   on Claude Code
           |  compact state: primitive ledger   |
           |  + exploit graph                   |
           +------------------------------------+
              |   ^                         |   teach back
   dispatch   |   | distilled envelope only |
              v   |                         v
        +---------------+            version-controlled state
        |   Marvins     |  on Codex   findings | coverage | sessions
        | (worker pool) |            (the Store, files in git)
        +---------------+
              |
        full detail paged to the Store, never inlined to the orchestrator
```

The orchestrator holds a small working set: a primitive ledger (what capability
each finding grants) and an exploit graph (how primitives compose). Workers do
deep narrow work in isolated context and return a typed envelope. The
orchestrator reads the envelope, updates the ledger, proposes compositions, and
dispatches follow-up workers. Full worker detail lives in the Store and is
retrieved on demand. This is what lets the orchestrator chain exploits without
drowning in context. Semantic retrieval over that detail is the future
vector-DB swap.

For 001 the two session types use zero or one worker. The plumbing is what 001
delivers: the envelope contract, the ingest boundary, and the compact-state
structure, all tested.

### State and standards

The Store persists four record types as files: Project, Finding, Session,
Coverage, plus Methodology as versioned reference data. See `data-model.md` for
the concrete schemas and the Finding-to-OSV field map.

Standards flow: SARIF is the ingest format when tools and the Improbability
Drive produce results (features 002 and 003). OSV is the canonical finding
record, generated and schema-validated by `check`. CSAF and OpenVEX are the
disclosure exports (feature 005). Defining the Finding-to-OSV map now gives the
later features a fixed target and lets `check` validate from day one.

### The three verbs

- `playbook` runs the Agent Session Protocol for a chosen session type, and lists or operates on findings.
- `check` validates state consistency: schema, lifecycle legality, no orphan references, no duplicate project identity, and OSV-conformance of every finding. Required before `publish`. An error or timeout is a failed check.
- `publish` emits prepared local artifacts. In 001 it is close to a no-op and asserts the human gate. It never transmits.

### Reuse

HermesUltraCode already implements a pre-dispatch prompt gate and observability.
The platform adapts to it rather than rebuilding the gate. The Agent Session
Protocol, the file the infographic calls CLAUDE.md, becomes a Claude Code skill
that loads the constitution, the session-type playbook, and the Store interface.

## Project structure

```
deep-thought/
  pyproject.toml
  src/deepthought/
    cli.py                  # playbook, check, publish
    protocol/
      session.py            # load -> gate -> work -> teach back -> validate -> close
      gate.py               # Gate interface + HermesUltraCode adapter
    store/
      base.py               # Store interface (repository pattern)
      filestore.py          # files-in-git implementation
    schema/
      project.py
      finding.py            # canonical model + OSV mapping
      session.py
      coverage.py
      envelope.py           # worker -> orchestrator contract
    orchestrator/
      conductor.py          # compact state, dispatch, ingest
      ledger.py             # primitive ledger + exploit graph
    export/
      osv.py                # Finding -> OSV, used by check
    sessions/
      new_project.py
      status.py
  .claude/skills/           # Spec Kit Claude integration + the protocol skill
  state/                    # the version-controlled store
    projects/  findings/  sessions/  coverage/  methodology/
  .specify/memory/constitution.md
  specs/001-core-loop/{spec.md, plan.md, data-model.md, contracts/, tasks.md}
```

## Phase 0, unknowns to confirm

- HermesUltraCode gate interface: inputs, outputs, how the platform passes session context and receives the proceed, hold, or refuse decision.
- OSV schema version to pin, and the validation library choice.
- Whether the Store writes into a dedicated repo or a subtree of an existing one. Relates to the Threatpedia boundary question, feature 005.
- macOS sandbox options for feature 003 (container, VM, or ephemeral), noted now so 001 does not paint 003 into a corner. Not built in 001.

## Phase 1, design outputs

- `data-model.md`: Project, Finding with OSV map, Session, Coverage, Methodology, and the state directory layout.
- `contracts/worker-envelope.md`: the Marvin-to-orchestrator envelope, the primitive object and starter capability taxonomy, the ingest rule, and the injection-firewall property.

## Complexity Tracking

| Added complexity | Why it is justified | How it is bounded |
| --- | --- | --- |
| Orchestrator plus worker pool, versus one agent | Required to chain exploits across findings and to keep per-task context clean | The envelope is the only channel. Orchestrator never reads worker free-text. |
| A compact-state ledger and graph | The orchestrator must hold primitives and their compositions to reason about chains | Bounded working set. Detail pages to the Store. |
| A store interface in front of flat files | Enables the vector-DB swap without touching callers | One interface, two future implementations. |

## Validation, the 001 smoke

1. Init the Spec Kit scaffold, drop in the constitution and this feature.
2. `playbook` NEW PROJECT with a real git URL, an open-source basis, a scope allowlist. State shows a new Project file.
3. `playbook` STATUS. A session log appears with next steps. No finding status changed.
4. Attempt to set a fabricated `verified` finding to `disclosed` with no CVE. Rejected, reason recorded.
5. `check` passes on the consistent state, then fails when a finding is hand-corrupted. Diffs are clean and readable in git.

Passing all five proves the spine: durable state, the protocol, the gate, the
lifecycle guard, and the envelope boundary, with nothing dangerous wired yet.
