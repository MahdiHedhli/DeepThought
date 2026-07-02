# Deep Thought

**The governed spine of an autonomous security-research platform.**

Deep Thought runs typed agent sessions that discover, map, verify, and prepare
disclosure for vulnerabilities, keeping every result in a durable,
version-controlled knowledge base. An autonomous loop is only safe behind gates,
so authorization, scope, sandboxing, and a strict finding lifecycle are
non-negotiable and live in a constitution the platform enforces.

It began as **feature 001, the platform spine**: durable file-based state, a
typed Agent Session Protocol, an orchestrator-plus-workers execution model, and
the three operator verbs. Later features add capability behind their own gates —
each proven test-first and merged only after an independent adversarial review.
Shipped so far:

| Feature | Session / capability | Risk posture |
|---|---|---|
| **001** | `NEW PROJECT`, `STATUS` — the spine | read-only |
| **002** | `MAP`, `DISCOVER` — static reasoning → candidate findings | read-only |
| **003** | `VERIFY` — sandboxed reproduction | execution behind a hard stop; `NoopSandbox` dry-run only, real execution needs sign-off |
| **004** | `SIBLING HUNT` — cross-project variant analysis | read-only |
| **005** | `DISCLOSURE` — draft advisory + CVE + CSAF + OpenVEX | **draft-only; transmits nothing** |
| **006** | `loop` — autonomous driver + limit awareness | **bounded & gated; escalates the hard stops** |

No untrusted target code executes without an explicit human sign-off, and no
disclosure ever leaves the machine — drafting is done by an agent, sending by a
person (Constitution Article V). The autonomous loop (feature 006) chains the
safe, read-only, draft-only sessions behind the same gates: it runs only under an
explicit budget, cannot expand its own scope, and advances work up to the
target-execution and disclosure-transmission hard stops, then hands them to a
human.

> Built with GitHub Spec Kit. Intent is the source of truth (`specs/`,
> `.specify/memory/constitution.md`); the platform is the regenerated output.

---

## The three verbs

```
deepthought playbook   # run the Agent Session Protocol for a session type; list findings
deepthought check      # validate state: schema, lifecycle, orphans, identity, OSV/CSAF/OpenVEX conformance
deepthought publish    # emit prepared local artifacts, assert the human gate, transmit nothing
```

`playbook` fans out to the typed sessions:

```
deepthought playbook new-project ...                                   # register a target (gate: basis + scope)
deepthought playbook status  --project <id>
deepthought playbook map     --project <id>                            # 002, read-only coverage
deepthought playbook discover --project <id> [--sarif <path>]          # 002, candidate findings
deepthought playbook verify  --project <id> --finding <F-NNNN>         # 003, NoopSandbox dry-run (no execution)
deepthought playbook sibling-hunt --project <id> --finding <F-NNNN> [--sibling <id> ...]  # 004, read-only variants
deepthought playbook disclose --project <id> --finding <F-NNNN>        # 005, draft-only advisory/CVE/CSAF/OpenVEX
deepthought publish --format osv|csaf|openvex|cve-draft|advisory|all   # local artifacts only
```

`loop` is the autonomous driver (feature 006) — it runs the safe chain above
behind the gates, under an explicit budget, and escalates the hard stops:

```
deepthought loop --project <id> --max-sessions N [--max-seconds S] [--max-tokens T]
# deterministic: status -> map -> discover -> sibling-hunt/disclose (per verified finding),
# then stops (fixed point / budget / gate). Never runs NEW PROJECT or VERIFY: a candidate
# needing real reproduction, and a disclosure needing to be sent, are escalated to a human.
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
  ingest/                # sarif.py (SARIF -> findings, in-scope containment)
  sandbox/               # base.py, docker.py (config-only argv builder), noop.py (003; no execution)
  sibling/               # signature.py (variant signature, input firewall) (004)
  export/                # osv.py + csaf.py + openvex.py + cve.py + advisory.py + pinned schemas (005)
  sessions/              # new_project, status, map, discover, verify, sibling_hunt, disclosure
.claude/skills/          # the orchestrator protocol skill + a Marvin worker stub
scripts/                 # smoke.sh, smoke_002..005.sh (hermetic end-to-end)
state/                   # the version-controlled store
.specify/memory/         # the constitution
specs/                   # 001-core-loop … 005-disclosure (spec, plan, data model, contracts, tasks)
docs/build-log/          # a per-feature build log
```

## Design decisions

1. **State** is flat files in git behind a `Store` interface. A vector DB is a
   later, contained swap — one interface, a second implementation.
2. **Schema aligns to standards.** SARIF in (features 002/003); OSV for the
   finding record; CSAF, OpenVEX, and a CVE 5.1 draft out (feature 005). `check`
   validates every finding's OSV, CSAF, and OpenVEX against pinned schemas.
3. **Topology** is an orchestrator plus a worker pool. Workers keep their own
   context; the orchestrator captures only distilled envelopes, so it holds the
   working memory to chain exploits. The envelope doubles as an injection
   firewall.
4. **Identifiers are safe by construction.** A record id is a file name in the
   store, so every id is a single safe path segment enforced at the model boundary
   (`RecordId`) — no traversal, separators, or control characters. The `Store`
   guards its raw lookups, keeps detail access inside `detail/` (symlinks and
   `..` included), and refuses a same-id/different-identity overwrite; unsafe
   operator input becomes a controlled refusal, never a crash.
5. **Runtime** is Python for the core. The three verbs stay the contract.

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
