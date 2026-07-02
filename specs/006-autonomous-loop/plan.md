# Implementation Plan: Autonomous loop & limit awareness

> Bounded and gated. The plan below adds a deterministic driver over the existing
> gated sessions. It adds no way to expand scope, execute target code, or transmit
> — the loop escalates to those and stops. It always runs under an explicit budget.

## Summary

Feature 006 adds `run_loop(store, gate, project_id, budget)`: a deterministic
driver that repeatedly asks `select_next_action(store, project)` for the next
*safe* session, runs it through the existing `run_session` harness (so the gate
and teach-back are reused unchanged), accumulates each session's `ContextCost`
and a session count against a required `LoopBudget`, and stops for exactly one
recorded reason — `fixed_point`, `budget_exhausted`, `gate_held`/`gate_refused`,
or `hard_stop`. It writes one durable `LoopRun` record. The only new behavioural
surface is the `loop` package, the `LoopRun` schema record, and a `deepthought
loop` verb. No network code, no new sandbox, no `Project` write.

## Decisions

1. **Deterministic driver, not a planner.** `select_next_action` is a pure,
   priority-ordered function of store state — no LLM, no free-text plan. Rationale:
   reproducible and testable, and structurally unable to invent scope (Article IX).
2. **Monotonic selection ⇒ structural termination.** The policy proposes an action
   only if it makes *new* progress (an uncovered in-scope area to map/discover, a
   verified finding not yet hunted, a verified finding not yet drafted). It never
   re-proposes completed work, so it reaches a fixed point on its own; the budget
   is a second, independent backstop. Rationale: a loop must terminate for reasons
   other than "ran out of money".
3. **Budget required, checked pre-iteration, never raised.** `LoopBudget` rejects
   all-`None`; the loop checks the accumulated session count / wall-seconds /
   context tokens *before* running the next session and never mutates the budget
   upward. Rationale: no unbounded or self-growing loop.
4. **Repertoire excludes `NEW PROJECT` and `VERIFY` by omission.** The driver can
   only construct `{STATUS, MAP, DISCOVER, SIBLING HUNT, DISCLOSURE}` sessions — no
   `NewProjectSession` (scope), no `VerifySession`/sandbox (execution). It writes no
   `Project` and mutates no `scope_allowlist`/`authorization_*`. Rationale: scope
   changes and target-code execution are gated human acts (Articles IX, III),
   enforced the same way 005 enforces no-transmit — the affordance does not exist.
5. **The hard stops are escalations, not actions.** Advancing a `candidate` by
   real reproduction (Article III) and sending a disclosure (Article V) are
   recorded as `outstanding_actions` for a human; the loop never performs them. Any
   `VERIFY` it runs uses the injected `NoopSandbox` (executes nothing) and does not
   promote the finding. Rationale: the loop advances work up to the boundary and
   hands the boundary to a human.
6. **Gate stays the first thing every session does.** The loop does not re-implement
   gating; it calls `run_session`, which evaluates the gate before `run`. A
   non-`proceed` outcome stops the loop. Rationale: Article I is enforced once, in
   one place, and reused.
7. **`LoopRun` is a durable Store record.** The trace, budget consumed, stop
   reason, and outstanding actions are persisted through the `Store` as a
   human-readable record (Article VI), so a loop run is auditable after the fact
   like any session.

## Technical Context

- **Language/runtime:** Python 3.12+ (running 3.14), Pydantic v2.
- **New deps:** none.
- **Reuse anchors:** `protocol/session.py` (`run_session`, `find_resumable`,
  `SessionOutcome`, `ContextCost`); `schema/session.py` (`SessionType`,
  `CloseState`, `Session.next_steps()`); `store/base.py` + `filestore.py` (Store
  interface, `save_*`/`get_*`, `RecordId`, the new `is_record_id`); the six session
  classes in `sessions/`; `sessions/verify.py` + `sandbox/` (`NoopSandbox` seam);
  `cli.py` (verb wiring, `check` hard-gate pattern).
- **Selection inputs:** `store.get_project`, `store.list_coverage(project)`,
  `store.list_findings(project)` (status buckets), `store.list_sessions(project)`
  (what has already run — sibling-hunt/disclosure completion signals),
  `project.scope_allowlist` (the in-scope surface; never widened).

## Constitution Check

- **Article I (Gate-first).** Every loop iteration runs its session via
  `run_session`, which gates before work; a `hold`/`refuse` stops the loop with the
  reason recorded. The loop adds no path that bypasses the gate. ✔
- **Article II (Authorization & scope).** The loop reads the project's basis and
  scope; it never sets or widens them. An unauthorized project is refused at the
  gate on the first session, stopping the loop. ✔
- **Article III (Sandbox).** The loop constructs no `VerifySession` and no sandbox
  at all; advancing a candidate by real reproduction is an escalation, not a loop
  action — so the loop cannot execute target code even in principle. ✔
- **Article IV (Evidence & lifecycle).** The loop never forces a transition; each
  session's Store-boundary lifecycle guard is unchanged. It proposes `DISCLOSURE`
  only for already-`verified` findings and never itself promotes to `disclosed`. ✔
- **Article V (Coordinated disclosure).** Disclosure steps are draft-only; the loop
  introduces no transmit path and records "send" as a human action. ✔
- **Article VI (Durable state).** Each session teaches back as today; the loop adds
  one durable `LoopRun` record with explicit outstanding-action next steps and so
  "closes" only with next steps. ✔
- **Article VII (Validate-first).** Tests precede code; `run_loop`,
  `select_next_action`, `LoopBudget`, and the `LoopRun` record each arrive with the
  tests that constrain them. `check` remains the hard gate and is unaffected. ✔
- **Article VIII (Injection resistance).** The loop reads only typed Store records
  and typed `SessionOutcome`s; it interprets no worker free-text (the envelope
  firewall is untouched). ✔
- **Article IX (Minimalism & least privilege).** This is the article the feature
  most directly serves: *the autonomous loop cannot expand its own scope.* Enforced
  by omission (no `NEW PROJECT`, no scope write) and by the required, non-growable
  budget. Added structure (the driver, `LoopRun`) buys the chaining capability and
  the safety envelope, so it earns its place. ✔

No article requires an exception; Complexity Tracking is empty.

## Architecture

### The loop

```
run_loop(store, gate, project_id, budget)
   │  project missing?            → refuse (nothing run)
   │  budget all-None?            → refuse (never unbounded)
   ▼
repeat:
   budget.would_exceed(next)?     → stop: budget_exhausted (record planned action)
   action = select_next_action(store, project)
   action is None                 → stop: fixed_point
   action.is_escalation           → record outstanding_action; stop: hard_stop
   session = build_session(action)                     # repertoire excludes NEW PROJECT
   record  = run_session(store, gate, session)         # Article I gate + Article VI teach-back
   record.gate_outcome != proceed → stop: gate_held / gate_refused
   accumulate(record.context_cost); sessions_run += 1
   trace.append((action.type, record.id, outcome, close_state))
   ▼
write LoopRun(trace, sessions_run, cost, stop_reason, outstanding_actions)
teach-back: outstanding human actions (verify-under-real-sandbox, send-disclosure)
```

### Selection policy (priority ladder, monotonic)

`select_next_action(store, project)` returns the first that applies:

1. **STATUS** — if no `status` session has run yet for the project (cheap
   situational baseline). Runs at most once per loop.
2. **MAP** — for the first in-scope `scope_allowlist` area with no coverage record
   (expand the mapped surface). New progress = a previously-uncovered area.
3. **DISCOVER** — for the first mapped area not yet discovered over (produce
   candidates). New progress = a mapped-but-undiscovered area.
4. **SIBLING HUNT** — for the first `verified` finding with no prior sibling-hunt
   session. New progress = variants of a confirmed bug.
5. **DISCLOSURE (draft)** — for the first `verified` finding lacking drafts. New
   progress = a disclosure package prepared.
6. **VERIFY escalation** — if `candidate` findings remain, emit an *escalation*
   (not a run): each needs real reproduction behind a human sign-off.
7. otherwise `None` → fixed point.

Each rung is guarded so it fires only while it makes new progress; when all rungs
are exhausted the policy returns `None`. The escalation rung is terminal for the
autonomous phase — it never executes.

### Limit awareness

`LoopBudget(max_sessions, max_wall_seconds, max_context_tokens)` with a
`would_exceed(spent)` check. `spent` accumulates: `sessions_run`, the sum of each
session's `ContextCost.wall_seconds`, and the sum of each `ContextCost.tokens`.
The check runs *before* each session so the loop stops *at* the boundary, never
over it. At least one limit must be non-`None` (constructor refuses all-`None`).

## Project structure (delta from 001–005)

```
src/deepthought/loop/
  __init__.py         # NEW  re-export run_loop, LoopBudget, select_next_action
  budget.py           # NEW  LoopBudget (+ would_exceed, all-None refusal)
  policy.py           # NEW  select_next_action(store, project) -> LoopAction | None
  driver.py           # NEW  run_loop(store, gate, project_id, budget) -> LoopResult
src/deepthought/schema/
  loop.py             # NEW  LoopRun record + StopReason enum + LoopAction/kind
  __init__.py         # EDIT export LoopRun / StopReason
src/deepthought/store/
  base.py, filestore.py  # EDIT save_loop_run / get_loop_run / list_loop_runs
src/deepthought/
  cli.py              # EDIT `deepthought loop --project ...` verb
scripts/smoke_006.sh  # NEW
tests/loop/test_budget.py, test_policy.py, test_driver.py   # NEW
tests/test_store.py, tests/test_cli.py                       # EDIT (persistence + verb)
```

## Phase 0 — unknowns

Resolved by the understand phase (this plan): the selection inputs available on
the Store, the `NoopSandbox` seam for VERIFY, the `ContextCost` shape for the
budget, and the seven decisions above. The one genuinely open sub-question —
whether `LoopRun` is a first-class Store record or a session-detail artifact — is
settled in `data-model.md` (first-class record, for `check`-ability and listing).

## Phase 1 — design outputs

- `data-model.md` — `LoopBudget`, `LoopAction`/`ActionKind`, `StopReason`,
  `LoopRun` record shape, the selection-input mapping, and the termination /
  no-scope-expansion / no-execution guarantees.
- `contracts/loop.md` — exact public signatures (`run_loop`, `select_next_action`,
  `LoopBudget`), the stop-reason contract, and the Store persistence methods.
- `tasks.md` — the ordered, test-first task list.

## Complexity Tracking

None. No constitutional exception; no new dependency.

## Validation — the 006 smoke

`scripts/smoke_006.sh` runs on a fresh state: register a project (basis + scope so
the gate proceeds) → `deepthought loop --project <id> --max-sessions <n>` → assert
the trace ran the safe chain (status → map → discover → any sibling/disclose),
stopped with a governed reason, and wrote a `LoopRun` record naming the
outstanding VERIFY escalations → assert no `Project` beyond the one registered, no
scope change, and `check` still green. Negative cases: an all-`None` budget is
refused before any session; a project with authorization removed stops the loop at
`gate_refused`. The run's output and touched files are grepped to assert no target
code executed and nothing was transmitted.
