# Build Session Log — Feature 006, Autonomous loop & limit awareness

> **STATUS: built, green, in dual-gate review.** The last numbered feature: a
> deterministic, bounded, gated driver over the existing sessions. It chains the
> safe, read-only, draft-only work (STATUS → MAP → DISCOVER → SIBLING HUNT /
> DISCLOSURE) behind the Gate, under a required budget, and stops for exactly one
> recorded reason. It **cannot expand its own scope** (no NEW PROJECT, no scope
> write — Article IX), **executes no target code** (it constructs no verify
> session and no sandbox — a candidate needing real reproduction is an escalation,
> Article III), and **transmits nothing** (disclosure stays draft-only, Article V).
> **549 tests green (513 baseline + 36 new); all six smokes pass.**

**Feature:** 006-autonomous-loop
**Branch:** `006-autonomous-loop`
**Predecessor gate:** the safe-id/FileStore hardening merged to `main` (PR #5,
squash `40031de`).

## What shipped

`run_loop(store, gate, project_id, budget)` — the autonomous driver:

- **`schema/loop.py`** — `LoopBudget`/`LoopSpend` (limit awareness: refuses an
  all-`None` budget, frozen so it can't grow mid-run, `would_exceed` checked before
  each iteration), `ActionKind`/`StopReason` enums, `LoopAction` (transient policy
  output; `is_escalation` iff `verify_escalation`, which must carry a `human_action`),
  `LoopStep`, and the durable `LoopRun` record (trace, cost, stop reason, outstanding
  actions, teach-back body). Budget/spend live in `schema` (they are `LoopRun` field
  types) so the schema layer never depends on the loop package; `loop/budget.py`
  re-exports them — keeps the import graph acyclic.
- **`loop/policy.py`** — `select_next_action`, a pure, priority-ordered, **monotonic**
  function of `(store snapshot, in-run done set)`: STATUS → MAP → DISCOVER (once per
  project, via session-existence signals) → SIBLING HUNT → DISCLOSURE (per verified
  finding) → `verify_escalation` (per candidate) → `None` (fixed point). Each rung
  fires only while it makes new progress, so the loop terminates independently of
  the budget.
- **`loop/driver.py`** — `run_loop` runs each safe action through the existing
  `run_session` (so Article I's gate and Article VI's teach-back are reused
  unchanged), accumulates `ContextCost` + a session count against the budget,
  collects escalations without running them, and stops on the first of:
  `fixed_point` / `hard_stop` / `budget_exhausted` / `gate_held` / `gate_refused`.
  It builds only `{Status, Map, Discover, SiblingHunt, Disclosure}` sessions — no
  NEW PROJECT, no verify session, no sandbox.
- **Store** — `save_loop_run` / `get_loop_run` (`is_record_id`-guarded) /
  `list_loop_runs`; `LoopRun` persists as `loop/<id>.md`.
- **CLI** — `deepthought loop --project <id> --max-sessions N [--max-seconds S]
  [--max-tokens T]`; a missing budget is refused (never unbounded); a governed stop
  (fixed point / budget / gate) exits 0.
- **`scripts/smoke_006.sh`** — end-to-end: an authorized project → a bounded loop
  that runs status→map→discover, escalates a seeded candidate (`hard_stop`), leaves
  it unpromoted, keeps scope unchanged, writes a `LoopRun`, `check` green; negatives
  for a missing budget and an unauthorized (gate-refused) project.

## Design decisions (see `specs/006-autonomous-loop/plan.md`)

Deterministic driver (not a planner); monotonic selection ⇒ structural termination
(budget is a second backstop); budget required, checked pre-iteration, never raised;
repertoire excludes NEW PROJECT and VERIFY **by omission**; the two hard stops are
recorded escalations, not actions; the Gate stays the first thing every session
does; `LoopRun` is a durable, human-readable audit record.

## Tests (test-first, +36)

`test_loop_budget.py` (budget/spend), `test_loop_schema.py` (records + round-trip),
`test_loop_policy.py` (the ladder + monotonicity + read-only), `test_loop_driver.py`
(the safe chain, escalation-not-execution, each budget dimension, missing/
unauthorized project, and the structural no-scope/no-sandbox/no-network asserts),
`test_cli_loop.py` (the verb), plus Store persistence tests.
