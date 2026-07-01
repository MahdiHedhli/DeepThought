# Anvil (working title) — Spec Kit

Autonomous research agents for code analysis, fuzzing, crash triage, and
vulnerability validation, with a coordinated-disclosure pipeline and a durable,
version-controlled knowledge base.

This repository is the spec-driven definition of the platform, structured to
drop into GitHub Spec Kit. Intent is the source of truth. The platform is the
regenerated output.

> **Name:** "Anvil" is a working title only. Final name is being chosen. See the
> options in the working notes. When chosen, it is a single find-and-replace.

---

## What this is

The infographic describes a launcher for typed agent sessions that run on Claude
Code. This spec turns that launcher into a real, governed system. Three ideas
carry the whole design:

- **Typed sessions.** Each session does one job: discover, map, verify, sibling
  hunt, or prep disclosure. One job per session means tighter prompts and
  cleaner state.
- **Durable state.** Findings, coverage, and session logs live in a
  version-controlled store. Each session learns current state, works, then
  teaches the platform back. The knowledge base is the asset, not the chat log.
- **Gates.** An autonomous loop is only safe behind gates. Authorization, scope,
  sandboxing, and a strict finding lifecycle are non-negotiable and live in the
  constitution.

## Operating model

```
operator  ->  launcher (session type + config)  ->  session prompt artifact
                                                        |
                                                        v
                            Claude Code session (Agent Session Protocol)
                            load state -> gate -> scoped work -> teach back -> validate -> close
                                                        |
                                                        v
                            version-controlled state:  findings | coverage | sessions
                                                        |
                                                        v
                            check  (hard gate)  ->  publish  (human-gated send)
```

The learn-work-teach loop is the engine. Gates wrap it. Disclosure leaves the
machine only past a human.

---

## How this maps to GitHub Spec Kit

Spec Kit phases, and where this repo sits in each:

| Spec Kit phase | Artifact | Status here |
| --- | --- | --- |
| Constitution | `memory/constitution.md` | Drafted. Nine articles. Encodes scope, sandboxing, lifecycle, coordinated disclosure, durable state, validate-first, injection resistance, least privilege. |
| Specify | `specs/001-core-loop/spec.md` | Drafted. Feature 001 is the platform spine, tech-agnostic. |
| Clarify | spec "Open Questions" section | Four blockers resolved 2026-06-30. Two feature-005 questions remain, non-blocking. |
| Plan | `specs/001-core-loop/plan.md` | Drafted. Plus `data-model.md` and `contracts/worker-envelope.md`. |
| Tasks | `specs/001-core-loop/tasks.md` | Drafted. Test-first, gate-checked. |
| Analyze | cross-artifact check | Run after tasks, before implement. |
| Implement | the platform | Last mile. |

To initialize the real Spec Kit scaffold with Claude Code:

```
uvx --from git+https://github.com/github/spec-kit.git specify init . --integration claude
```

Spec Kit ships an `examples/bundles/` set that includes a **security researcher**
persona bundle. Worth reading before we finalize the plan. It may already
encode review gates we would otherwise hand-roll.

Then drop `memory/constitution.md` into `.specify/memory/`, and this feature
spec under `specs/001-core-loop/`. Run the Clarify phase against the open
questions, then Plan.

---

## Feature roadmap

Gate-first ordering. The safe spine lands first. Dangerous capability lands only
after the sandbox that contains it.

- **001 — Platform spine.** Session protocol, state model, the three verbs.
  Proven with `NEW PROJECT` and `STATUS`, the two lowest-risk session types.
  No code execution yet.
- **002 — Discovery cluster.** `DISCOVER` (find candidates) and `MAP` (attack
  surface coverage). Read and reason, do not execute.
- **003 — Execution sandbox plus VERIFY.** The isolated, egress-controlled
  sandbox lands first, then `VERIFY` promotes candidates to verified with a
  minimized reproducible PoC inside it.
- **004 — SIBLING HUNT.** Variant analysis. Spread a confirmed bug class across
  the codebase and across sibling projects.
- **005 — DISCLOSURE.** `verified` to advisory and CVE. Coordinated-disclosure
  pipeline. Drafting by agent, sending by human. This is the highlighted card
  in the infographic.
- **006 — Autonomous loop and limit awareness.** Unattended iteration behind
  the gates, with quota and budget awareness so the loop degrades safely.

---

## Decisions locked (2026-06-30)

1. **State.** Flat files in git, structured front-matter, behind a store interface. Vector DB is a later swap, not now.
2. **Schema.** Align to standards. SARIF in, OSV for the finding record, CSAF and OpenVEX out for disclosure.
3. **Topology.** Orchestrator plus a worker pool. Each worker keeps its own context. The orchestrator captures only distilled results, so it holds the working memory to chain exploits. The result envelope doubles as a prompt-injection firewall.
4. **Runtime.** Python core, on interop grounds (SARIF, fuzzers, PoC scripting, OSV and CSAF libraries). The three verbs stay the contract.

## Naming (Hitchhiker's namespace, proposed)

Sits under Magrathea, which stays the general three-tier topology. In the lore, Magrathea builds the computers. This platform is one such computer.

| Role | Name | Why |
| --- | --- | --- |
| The platform | **Deep Thought** | The computer built to compute the Answer. It produced 42, which ties it to 42 Holdings. The Answer here is the advisory. |
| The orchestrator | **Deep Thought core** | Holds the compact state and composes the exploit chain. |
| The worker agents | **Marvins** | Brilliant minds set to grind narrow, tedious work. One per task. |
| The discovery and fuzzing engine | **Improbability Drive** | Finds the improbable path and the unlikely crash. |
| The publish pipeline | **Megadodo** | Megadodo Publications publishes the Guide. Feeds the corpus, and Threatpedia. |

Working title in the constitution and spec is still "Anvil" pending your blessing on these. Renaming is one sweep.

---

Ship safer code. Fix more bugs. Make the internet better.
