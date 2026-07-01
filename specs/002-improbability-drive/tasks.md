# Tasks: Improbability Drive — DISCOVER and MAP (002)

Test-first per constitution Article VII. For each task with tests, write the
tests, see them fail, then implement to green. `[P]` marks tasks that can run in
parallel because they touch different files. Dependencies are noted. **Do not
weaken any 001 test.** Run the suite with `.venv/bin/pytest -q`; if
`import deepthought` fails, `uv pip install --python .venv -e ".[dev]"` first.

## Setup

- **T001** Feature scaffold. Create `specs/002-improbability-drive/` with
  `spec.md`, `plan.md`, `data-model.md`, `contracts/sarif-ingest.md`, and this
  `tasks.md` (this task — done). Add the `src/deepthought/ingest/` package with an
  `__init__.py`. Add `tests/fixtures/sample.sarif`, a small valid SARIF 2.1.0 file
  with a handful of `runs[].results[]` covering at least one mapped `ruleId`
  (e.g. a CWE-89 SQLi result) and one unmapped rule. No app logic. Depends on 001.

## Gate honesty rename (do first — everything else imports the gate)

- **T002** `DefaultGate` rename in `protocol/gate.py`. Tests first: `DefaultGate`
  is importable and evaluates the three outcomes exactly as the 001 rules require
  (refuse on missing basis, refuse on blackbox without ref, hold on empty scope,
  proceed on a clean in-scope project); `HermesUltraCodeGate` is still importable,
  is a subclass of `DefaultGate`, and produces identical decisions (it currently
  delegates; its docstring states the real interface is unconfirmed). Update
  `protocol/__init__.py` to export `DefaultGate` and keep `HermesUltraCodeGate`.
  **Every existing 001 gate/session/CLI test must stay green unchanged.** Depends
  on T001.

## SARIF ingest module

- **T003** [P] `load_sarif(path) -> dict` in `ingest/sarif.py`. Tests first: reads
  the fixture and returns a dict; a non-JSON file raises; a file that is not
  SARIF-2.1.0-shaped raises; nothing is executed or fetched. Depends on T001.
- **T004** `sarif_to_findings(sarif, *, project, id_start=1) -> list[Finding]` in
  `ingest/sarif.py`. Tests first: one candidate `Finding` per accepted result;
  ids assigned sequentially from `id_start` in `F-000N` form; `status` is always
  `candidate`; `summary` comes from `message.text` and is length-bounded; a result
  with no `message.text` is skipped; **every returned finding is OSV-valid**
  (`validate_osv(finding_to_osv(f))` is empty); a result that cannot be made
  OSV-valid is not emitted. Depends on T003.
- **T005** `sarif_to_primitives(sarif, *, finding_ids) -> list[Primitive]` in
  `ingest/sarif.py` plus the closed rule→capability table. Tests first: a mapped
  `ruleId` (CWE-89) yields a `Primitive(kind='inject:sql', confidence='suspected',
  finding_ref=<its finding id>)`; an unmapped `ruleId` yields no primitive; every
  table value is a member of `CAPABILITY_TAXONOMY` (assert over the whole table);
  the primitives align to `finding_ids` by result order; no primitive carries an
  `evidence_ref`. This is the injection-resistance test for SARIF: an injected
  `ruleId` string only ever misses the table. Depends on T004.

## Sessions

- **T006** `MapSession(project_id, root=None)` in `sessions/map.py`, subclassing
  `BaseSession` with `.type = SessionType.map`. Tests first: `build_gate_context`
  is built from the stored project; a read-only walk of the in-scope paths writes
  `Coverage(method='read', depth='touched')` for each surveyed area; a path
  outside `scope_allowlist` is never surveyed or recorded; no finding is created;
  no target code executes; the returned `SessionOutcome` has next steps and lists
  the coverage it changed; run through `run_session` it closes clean on a
  proceed and is held/refused per the gate otherwise. `root` overrides the target
  working-tree path for tests (no network, no real clone). Depends on T002.
- **T007** `DiscoverSession(project_id, sarif_path=None, root=None)` in
  `sessions/discover.py`, subclassing `BaseSession` with
  `.type = SessionType.discover`. Tests first: with the SARIF fixture, the session
  writes candidate `Finding`s to the Store (status `candidate`); it runs a stub
  Marvin that emits one `Envelope`, ingests it via a `Conductor`, and **the ledger
  holds the suspected primitives**; `self.conductor` is exposed after `run` for
  inspection; it teaches back findings touched + coverage + next steps and closes
  clean; SARIF/worker free-text never becomes instruction (a poisoned
  `message.text` and a hostile `next_step_hint` change nothing beyond data
  fields); with no `sarif_path` it still runs the stub Marvin over static signals
  and produces at least the stub's primitives. `root`/`sarif_path` injectable for
  tests. Depends on T002, T005.
- **T008** Wire both sessions into `sessions/__init__.py` (export `MapSession`,
  `DiscoverSession`). Extend the stub Marvin so DISCOVER can dispatch it and carry
  the SARIF-derived suspected primitives in the envelope it emits. Tests first for
  the exports. Depends on T006, T007.

## CLI wiring

- **T009** `playbook map` and `playbook discover` subcommands in `cli.py`. Tests
  first (Typer runner): `playbook map --project <id>` runs a MAP session and
  prints the session record; `playbook discover --project <id> [--sarif <path>]`
  runs a DISCOVER session; both go through `run_session` with the gate; a
  `StoreError` (e.g. unknown project) exits non-zero with a message, matching the
  existing `status` handling. Depends on T008.

## Validation and gate-before-done

- **T010** `check` stays a hard gate over DISCOVER/MAP output. Tests first: `check`
  is green on the state a DISCOVER + MAP run produces (every candidate finding's
  OSV validates; coverage and sessions have no orphans); `check` fails on a
  hand-corrupted finding; `publish` still refuses when `check` is red and
  transmits nothing when green. No change to `check.py` is expected — this task
  asserts the existing gate holds for the new output. Depends on T009.
- **T011** The 002 smoke script `scripts/smoke_002.sh` and `tests/test_smoke_002.py`
  (mirroring the 001 smoke). Drives the read-only loop through the CLI: NEW PROJECT
  (real in-scope target) → MAP (see `read` coverage) → DISCOVER (bundled SARIF
  fixture, see candidate findings + ledger primitives) → `check` green → corrupt a
  finding and see `check` fail → `publish` (local artifacts, human gate, nothing
  transmitted). Self-heals the editable install like the 001 smoke. Depends on
  T010.
- **T012** Update the session-type playbook in
  `.claude/skills/deep-thought-protocol/SKILL.md` with DISCOVER and MAP entries
  (documentation only): MAP is read-only coverage of in-scope paths; DISCOVER
  reasons over static signals and SARIF to produce candidate findings and suspected
  primitives, ingests the Marvin envelope, and runs no code. Depends on T008.
- **T013** Run `/analyze` across the constitution, this spec, plan, data-model, the
  SARIF-ingest contract, and these tasks; resolve any drift. Then run the full
  suite (`.venv/bin/pytest -q`) — 001 green and 002 green — and the 002 smoke end
  to end. Depends on all above.

## Definition of done for 002

- The five acceptance criteria hold: a MAP session records `read` coverage for a
  real in-scope repo; a DISCOVER session produces candidate findings from static
  signals and SARIF; every generated finding exports to valid OSV (`check` green);
  the ledger holds the discovered primitives (via `self.conductor`); and no target
  code executes anywhere.
- The 002 smoke passes end to end; `check` is green on produced state and red on a
  corrupted finding.
- SARIF is consumed as untrusted data: no SARIF string is interpreted as
  instruction, and the `ruleId`→capability map is a closed lookup an injected rule
  can only miss. The worker envelope firewall is unchanged.
- `DefaultGate` is the canonical gate; `HermesUltraCodeGate` is a delegating
  subclass and stays importable.
- Every 001 test is still green and unweakened. No target-code execution, no
  network transmission, and no scope/authorization widening exists in the build.
  Those still arrive behind their own gates (003+).
