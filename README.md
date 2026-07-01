# Deep Thought

**The governed spine of an autonomous security-research platform.**

Deep Thought runs typed agent sessions that discover, map, verify, and prepare
disclosure for vulnerabilities, keeping every result in a durable,
version-controlled knowledge base. An autonomous loop is only safe behind gates,
so authorization, scope, sandboxing, and a strict finding lifecycle are
non-negotiable and live in a constitution the platform enforces.

This repository is **feature 001, the platform spine**: durable file-based
state, a typed Agent Session Protocol, an orchestrator-plus-workers execution
model, and the three operator verbs. It is proven end to end with the two
lowest-risk session types — `NEW PROJECT` and `STATUS`. There is no code
execution, no discovery, and no disclosure transmission in this build. Those
arrive behind their own gates in later features. This feature is what makes them
safe to add.

> Built with GitHub Spec Kit. Intent is the source of truth (`specs/`,
> `.specify/memory/constitution.md`); the platform is the regenerated output.

---

## The three verbs

```
deepthought playbook   # run the Agent Session Protocol for a session type; list findings
deepthought check      # validate state: schema, lifecycle, orphans, identity, OSV conformance
deepthought publish    # emit prepared local artifacts, assert the human gate, transmit nothing
```

## Quickstart

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv -e ".[dev]"

# 1. Register a project (NEW PROJECT session). Authorization basis + scope required.
.venv/bin/deepthought playbook new-project \
  --name "PHP src" --git-url https://github.com/php/php-src \
  --source-type open_source --basis permissive_oss \
  --scope ext/soap --scope ext/standard

# 2. Summarize state (STATUS session). Changes no finding status.
.venv/bin/deepthought playbook status --project php-src

# 3. Validate the whole store. Hard gate before publish.
.venv/bin/deepthought check

# 4. Emit local artifacts. Nothing leaves the machine.
.venv/bin/deepthought publish
```

State lands as clean, reviewable Markdown under `state/`. Read the work from the
repository alone.

## Architecture

```
        operator
           │
   launcher (session type + config)
           │
           ▼
  ┌──────────────────────────────┐
  │  Deep Thought core           │   the orchestrator
  │  compact state:              │   holds a small working set —
  │  primitive ledger +          │   what each finding grants and
  │  exploit graph               │   how primitives compose
  └──────────────────────────────┘
     │   ▲                    │
 dispatch │ distilled         │  version-controlled state
     ▼   │ envelope only      ▼  findings │ coverage │ sessions
  ┌─────────────┐        (the Store, files in git)
  │   Marvins   │  workers
  │ (one/task)  │
  └─────────────┘
     │
  full detail paged to the Store, never inlined to the orchestrator
```

The orchestrator reads only a typed, length-capped **envelope** from each
worker. A prompt-injected worker cannot propagate the injection past that
boundary — the envelope schema is the firewall. See
[`specs/001-core-loop/contracts/worker-envelope.md`](specs/001-core-loop/contracts/worker-envelope.md).

## Layout

```
src/deepthought/
  cli.py                 # playbook, check, publish
  protocol/              # session.py (the protocol), gate.py (Gate + HermesUltraCode adapter)
  store/                 # base.py (Store interface), filestore.py (files in git)
  schema/                # Pydantic canonical models incl. worker envelope
  orchestrator/          # conductor.py (envelope ingest), ledger.py (primitive ledger + exploit graph)
  export/                # osv.py (Finding -> OSV) + pinned OSV schema
  sessions/              # new_project.py, status.py
.claude/skills/          # the orchestrator protocol skill + a Marvin worker stub
state/                   # the version-controlled store
.specify/memory/         # the constitution
specs/001-core-loop/     # spec, plan, data model, contracts, tasks
```

## Design decisions

1. **State** is flat files in git behind a `Store` interface. A vector DB is a
   later, contained swap — one interface, a second implementation.
2. **Schema aligns to standards.** SARIF in (features 002/003), OSV for the
   finding record, CSAF and OpenVEX out (feature 005). `check` validates every
   finding's OSV against a pinned schema from day one.
3. **Topology** is an orchestrator plus a worker pool. Workers keep their own
   context; the orchestrator captures only distilled envelopes, so it holds the
   working memory to chain exploits. The envelope doubles as an injection
   firewall.
4. **Runtime** is Python for the core. The three verbs stay the contract.

## Development

```bash
uv pip install --python .venv -e ".[dev]"
.venv/bin/pytest            # test-first, per constitution Article VII
```

`check` is itself a runtime gate and is tested. A `check` that errors counts as
a failed check.

## Naming (Hitchhiker's namespace)

The platform is **Deep Thought** — the computer built to compute the Answer; it
produced 42. The orchestrator is **Deep Thought core**. The workers are
**Marvins**, brilliant minds set to grind narrow tedious work, one per task. The
discovery/fuzzing engine (feature 002+) is the **Improbability Drive**; the
publish pipeline (feature 005) is **Megadodo**. All sit under **Magrathea**, the
general topology.

## License

Apache-2.0. See [LICENSE](LICENSE).

Ship safer code. Fix more bugs. Make the internet better.
