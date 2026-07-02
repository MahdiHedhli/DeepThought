# Tasks: Autonomous loop & limit awareness (006)

Test-first (Constitution Article VII): each task writes its failing tests before
the code that satisfies them. Ordered so every task builds on green predecessors.
Baseline before starting: 513 tests, five smokes green.

## T601 — `LoopBudget` + `LoopSpend` (limit awareness core)

- **Tests** (`tests/loop/test_budget.py`): all-`None` budget raises; any single
  limit is accepted; a non-positive limit raises; `would_exceed` fires exactly at
  each set limit (sessions/wall/tokens) and never for unset limits; `LoopSpend.plus`
  accumulates a `ContextCost` immutably.
- **Code** (`loop/budget.py`): `LoopBudget`, `LoopSpend` per the contract.

## T602 — Loop schema records

- **Tests** (`tests/loop/test_schema_loop.py`): `ActionKind`/`StopReason` enums
  reject unknown values; `LoopAction` marks `is_escalation` only for
  `verify_escalation`; `LoopRun` round-trips through Markdown (front-matter + body)
  and rejects a stray key (`extra='forbid'`); `LoopRun.id`/`project` are `RecordId`
  (unsafe id rejected).
- **Code** (`schema/loop.py`, `schema/__init__.py`): `ActionKind`, `StopReason`,
  `LoopAction`, `LoopStep`, `LoopRun`; export them.

## T603 — Store persistence for `LoopRun`

- **Tests** (`tests/test_store.py`): `save_loop_run`/`get_loop_run` round-trip;
  `list_loop_runs(project=...)` filters; `get_loop_run` refuses a traversal/unsafe
  id (returns `None`), matching the other `get_*` guards.
- **Code** (`store/base.py`, `store/filestore.py`): the three methods; `loop/<id>.md`
  storage; `is_record_id` guard on `get_loop_run`.

## T604 — `select_next_action` policy (deterministic, monotonic)

- **Tests** (`tests/loop/test_policy.py`): on a fresh proceed-able project the
  ladder yields `status` → `map`(first uncovered area) → `discover`(first mapped
  area) in order as state advances; a `verified` finding with no prior sibling-hunt
  yields `sibling_hunt`; a `verified` finding with no drafts yields `disclosure`;
  remaining `candidate`s yield a `verify_escalation` (`is_escalation=True`,
  `human_action` set); a fully-progressed state yields `None`; **monotonicity** —
  re-invoking after an action's state change never re-proposes the same completed
  work (no infinite loop); `map`/`discover` areas come only from `scope_allowlist`.
- **Code** (`loop/policy.py`): `select_next_action` reading only coverage/findings/
  sessions + `scope_allowlist`.

## T605 — `run_loop` driver (gated, bounded, escalating)

- **Tests** (`tests/loop/test_driver.py`):
  - missing project → `LoopRun(stop_reason=gate_refused, sessions_run=0)`, nothing
    else written.
  - a proceed-gated project runs the safe chain and stops `fixed_point`/`hard_stop`;
    the `LoopRun` trace lists the sessions in order; every candidate stays
    `candidate` (no promotion); every `verified` finding gets drafts.
  - `max_sessions=1`/`max_seconds`/`max_tokens` each independently stop the loop at
    `budget_exhausted` with the planned next action recorded.
  - a project with authorization removed → first session `gate_refused`, loop stops,
    only the refused session log written.
  - **safety asserts**: no `Project` written beyond the seeded one; no scope change;
    `run_loop` uses a `NoopSandbox` for any VERIFY and executes no target code;
    `outstanding_actions` names the verify/send human steps; the loop package
    imports no network module.
  - the `LoopRun` teach-back has non-empty **Next steps**.
- **Code** (`loop/driver.py`, `loop/__init__.py`): `run_loop` per the contract,
  reusing `run_session`; `build_session` maps each `ActionKind` to its session
  (repertoire excludes `NEW PROJECT`); `NoopSandbox` for VERIFY.

## T606 — CLI verb `deepthought loop`

- **Tests** (`tests/test_cli.py`): `loop --project <id> --max-sessions N` prints the
  trace + stop reason and exits 0; **no budget flag** → clear error, non-zero exit;
  a missing project → governed refusal message, exit 0 (governed stop); the command
  imports/opens no network and prints no transmission.
- **Code** (`cli.py`): the `loop` command wiring `run_loop`; budget flags; trace
  rendering.

## T607 — Smoke `scripts/smoke_006.sh`

- Hermetic end-to-end on a fresh state: register a project (basis + scope) → run
  `deepthought loop --project <id> --max-sessions <n>` → assert a governed stop, a
  `LoopRun` record, the safe-chain trace, and named VERIFY escalations → assert no
  extra `Project`, no scope change, `check` still green → negatives: all-`None`
  budget refused, authorization-removed project stops at `gate_refused`. Grep the
  output/touched files to assert nothing executed and nothing transmitted.

## T608 — Green + reconcile + done-gate

- `pytest` green (existing 513 + new); all six smokes (`smoke.sh` … `smoke_006.sh`)
  pass. Update `README.md` (mark 006 shipped; the loop is bounded/gated) and add
  `docs/build-log/006-autonomous-loop.md`. Commit test-first increments (author
  `MahdiHedhli`), open the PR, run the dual-gate (codex + agy) to a clean same-HEAD
  pass, merge-on-clean, NTFY, reconcile docs.

## Ordering & dependencies

`T601 → T602 → T603 → T604 → T605 → T606 → T607 → T608`. T601/T602 are independent
of the driver; T604 (policy) and T605 (driver) are the substance; T603 must precede
T605 (the driver persists a `LoopRun`). No task executes target code or adds a
transmit path; the two hard stops remain human-signed throughout.
