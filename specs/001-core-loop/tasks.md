# Tasks: Platform Spine and Agent Session Protocol (001)

Test-first per constitution Article VII. For each task with tests, write the
tests, see them fail, then implement. `[P]` marks tasks that can run in parallel
because they touch different files. Dependencies are noted.

## Setup

- **T001** Spec Kit init with the Claude integration. Place `constitution.md` under `.specify/memory/`, this feature under `specs/001-core-loop/`. Scaffold the Python package, `pyproject.toml`, pytest. No app logic.

## Schema, the canonical models

- **T002** [P] Pydantic models for Project, Session, Coverage, Methodology. Tests first: valid records load, malformed front-matter fails, enums reject unknown values. Depends on T001.
- **T003** [P] Pydantic model for Finding plus the OSV export in `export/osv.py`. Tests first: a Finding serializes to OSV that validates against the pinned OSV schema, the field map round-trips, `cve` mirrors into `aliases`. Depends on T001.
- **T004** [P] Pydantic model for the worker Envelope and Primitive per `contracts/worker-envelope.md`. Tests first: valid envelope loads, oversized string fields fail, unknown `kind` or `grants` fail, missing `evidence_ref` on a demonstrated primitive fails. Depends on T001.

## Store, files in git

- **T005** `Store` interface in `store/base.py`, then `FileStore` in `store/filestore.py`. Tests first: create, read, update, list for each record type, diffs are clean text, project identity resolves on `git_url` with no duplicate. Depends on T002, T003.
- **T006** Lifecycle guard at the Store boundary. Tests first, one per transition: candidate to verified needs a resolving `evidence_ref`, verified to disclosed needs a `cve` and an advisory reference, verified to patched needs a `cve` and a fix reference, illegal transitions are rejected with the reason recorded, backward transitions log. Depends on T005.

## Gate and validation

- **T007** `Gate` interface in `protocol/gate.py` with three outcomes, plus the HermesUltraCode adapter stub. Tests first: refuse on missing `authorization_basis`, refuse on blackbox without `authorization_ref`, proceed on a clean in-scope project, every hold and refuse writes a reason. Depends on T002. Confirm the HermesUltraCode interface in Phase 0 before finalizing the adapter.
- **T008** `check` command logic. Tests first: passes on consistent state, fails on schema violation, fails on illegal lifecycle state, fails on orphan reference, fails on duplicate project identity, fails on any finding whose OSV does not conform. A check that raises is a failed check. Depends on T003, T005, T006.

## Orchestrator boundary

- **T009** Envelope ingest in `orchestrator/conductor.py`. Tests first: a valid envelope updates state, an invalid envelope is rejected and logged as error and does not touch the ledger, `detail_ref` content is never loaded into orchestrator state, a `next_step_hint` does not dispatch or mutate on its own. This is the injection-firewall test. Depends on T004, T005.
- **T010** Primitive ledger and exploit graph in `orchestrator/ledger.py`. Tests first: add a primitive from an envelope, detect a composition where one primitive's grants meet another's preconditions, the working set stays within a configured bound. Depends on T004, T009.

## Protocol and session types

- **T011** Agent Session Protocol harness in `protocol/session.py`: load state, gate, work, teach back, validate, close. Tests first: a session with no next steps does not close, an interrupted session is detectable and resumable, close writes findings touched and coverage changed. Depends on T005, T007.
- **T012** NEW PROJECT session in `sessions/new_project.py`. Tests first: registers a project with basis and scope allowlist, refuses an unresolvable git URL, refuses blackbox without `authorization_ref`, resolves to one project on a repeat. Depends on T011.
- **T013** STATUS session in `sessions/status.py`. Tests first: loads and summarizes findings and coverage, writes a session log with next steps, changes no finding status. Depends on T011.

## Verbs and agent surface

- **T014** Wire the three verbs in `cli.py`. `playbook` runs the protocol for a chosen type and lists findings, `check` calls T008, `publish` emits local artifacts only and asserts the human gate, transmitting nothing. Tests first for each. Depends on T008, T012, T013.
- **T015** The Claude Code skill for the orchestrator protocol under `.claude/skills/`. Loads the constitution, the session-type playbook, and the Store interface. Plus a Codex worker harness stub that produces a conforming envelope. Manual validation against the 001 smoke. Depends on T011, T009.

## Gate before done

- **T016** Run `/analyze` across constitution, spec, plan, data-model, contracts, and tasks. Resolve any drift. Then run the five-step 001 smoke from the plan end to end. Depends on all above.

## Definition of done for 001

- The five-step smoke passes.
- `check` is green on consistent state and red on a corrupted record.
- A fabricated disclosed-without-CVE transition is rejected with a recorded reason.
- An invalid or instruction-laden envelope is rejected at the orchestrator boundary.
- Every record reads and diffs as clean text in git.
- No code execution, no discovery, no transmission exists in the build. Those arrive behind their own gates in later features.
