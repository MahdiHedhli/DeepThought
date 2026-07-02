# Feature Spec: Autonomous loop & limit awareness (006)

> **BOUNDED & GATED.** The loop drives the platform's own sessions autonomously,
> but it is a *deterministic* driver behind every existing gate. It cannot expand
> its own scope (Constitution Article IX), it runs no session ahead of a `proceed`
> (Article I), it executes no target code and transmits no disclosure — it advances
> work up to those hard-stop boundaries and **escalates** with explicit human-action
> next steps. It always runs under an explicit budget and always stops for a
> recorded reason.

## Problem

The platform has six session types (`STATUS`, `MAP`, `DISCOVER`, `SIBLING HUNT`,
`VERIFY`, `DISCLOSURE`) and an operator who must run them one at a time, in the
right order, deciding after each what to do next. That defeats the purpose of an
autonomous research platform: the value is in *chaining* — map an in-scope area,
discover candidates in it, hunt their variants, draft disclosure for what is
verified — without a human in the inner loop for the safe, read-only, draft-only
work.

But an autonomous loop is exactly where a security platform gets dangerous. An
unbounded or ungoverned loop can: expand its own scope, run forever, burn an
unbounded token/time budget, execute untrusted target code chasing a
"verification", or transmit a half-baked disclosure. Three failure modes matter
more than convenience:

1. **Runaway.** A loop with no budget, or no fixed point, never stops — it spins,
   re-runs the same work, or exhausts resources.
2. **Scope creep.** A loop that can register a target or widen an allowlist grants
   itself authority no human approved (Article IX).
3. **Crossing a hard stop.** A loop that executes target code or sends a disclosure
   crosses a boundary the constitution reserves for a human (Articles III, V).

Feature 006 delivers the chaining value while structurally refusing all three.

## Goal

A deterministic `run_loop(store, gate, project_id, budget)` that, for one
**already-authorized** project, repeatedly selects the next *safe* session from
current state, runs it through the existing gated harness, accumulates durable
state, and stops for exactly one recorded reason: **budget exhausted**, **fixed
point** (no safe progress left), **gate held/refused**, or **hard-stop boundary
reached**. It writes a durable loop record — the ordered sessions it ran, the
budget it consumed, its stop reason, and the outstanding human actions — and
teaches back next steps. It never runs `NEW PROJECT`, never widens scope, never
executes target code, and never transmits.

## Scope

### In scope

- A **deterministic selection policy** `select_next_action(store, project)` that
  inspects state (coverage, findings by status, prior loop/session records) and
  returns the single highest-priority *safe* action, an *escalation* (a
  hard-stop item for a human), or `None` (fixed point). The policy is
  priority-ordered, monotonic (it only proposes an action that would make **new**
  progress), and pure/testable.
- A **`LoopBudget`** (`max_sessions`, `max_wall_seconds`, `max_context_tokens`)
  with **at least one limit required** — an all-`None` budget is refused, so the
  loop is never unbounded. The loop accumulates each session's existing
  `ContextCost` (tokens, wall-seconds) and its own session count, and checks the
  budget **before** each iteration.
- A **`run_loop`** driver that runs each selected session via the existing
  `run_session` (so Article I's gate ordering and Article VI's teach-back are
  reused unchanged), stops on the first non-`proceed` gate outcome, and halts at
  the first escalation with the outstanding action recorded.
- A durable **`LoopRun`** record (or session-detail artifact) capturing the
  ordered `(session_type, session_id, outcome)` trace, budget consumed, stop
  reason, and the list of outstanding human actions.
- A **`deepthought loop --project <id>`** verb with budget flags
  (`--max-sessions`, `--max-seconds`, `--max-tokens`), printing the trace and the
  stop reason, exiting non-zero only on an internal error (a refusal/fixed-point/
  budget stop is a normal exit).
- `scripts/smoke_006.sh` — a hermetic end-to-end loop run.

### Out of scope (and the named HARD STOPS)

These are refusals the loop enforces, not deferred features. Each stays a human
act; the loop escalates to it and never performs it:

- **Scope expansion.** The loop never runs `NEW PROJECT` and never mutates a
  project's `scope_allowlist` or `authorization_*`. Registering a target or
  widening scope is a gated human act (Article IX). Enforced by **omission** — the
  loop's session repertoire excludes `NEW PROJECT`, and it writes no `Project`.
- **Target-code execution.** The loop advances a `candidate` only up to the
  `VERIFY` boundary and never crosses it. Real reproduction executes target code
  and needs Mahdi's sign-off (Article III); the loop records `"F-NNNN needs VERIFY
  under a real sandbox — human sign-off required"` and does not run it. Enforced by
  **omission** — the loop constructs no `VerifySession` and no sandbox at all, so
  it cannot execute target code even in principle.
- **Disclosure transmission.** The loop may *draft* disclosure (feature 005 is
  draft-only and safe) but never sends. Enforced by **omission** — it introduces
  no network code and calls no transmit path.
- **Self-authored budget growth.** The loop cannot raise its own budget mid-run;
  the budget is an input, checked each iteration, never mutated upward.

## User scenarios

1. **Chain the safe work.** An operator has project `acme` gated to proceed. They
   run `deepthought loop --project acme --max-sessions 20`. The loop runs
   `STATUS`, then `MAP` (the in-scope surface), then `DISCOVER` (over the mapped
   surface), then `SIBLING HUNT`/`DISCLOSE` for anything already verified — each
   gated, each logged — then reaches a fixed point (no safe progress left) and
   stops clean, teaching back that the remaining candidates need human-signed
   `VERIFY`.

2. **Budget stop.** The same project with `--max-sessions 3`. The loop runs three
   sessions, sees the next action would exceed the session budget, and stops with
   reason `budget_exhausted`, listing the planned-but-unrun next action.

3. **Escalate at the hard stop.** The loop reaches a state whose only remaining
   progress is verifying a candidate. It does not execute target code; it stops
   (or continues only with other safe work) and records the outstanding action
   `"F-0007 needs VERIFY under a real sandbox — human sign-off required"`.

4. **Gate refusal stops the loop.** The project's authorization is removed (empty
   scope / no basis). The first session the loop starts is gate-`refuse`d; the
   loop stops immediately with reason `gate_refused` and the gate's reason, having
   written nothing but the refused session log.

5. **No unbounded loop.** `deepthought loop --project acme` with no budget flag is
   refused before any session runs: at least one limit is required.

## Functional requirements

- **FR-1** `run_loop(store, gate, project_id, budget)` runs only on an existing
  project; a missing project is a clean refusal (no session run).
- **FR-2** `LoopBudget` with all limits `None` is rejected (the loop is never
  unbounded). Any single limit set is sufficient.
- **FR-3** Every session the loop runs goes through `run_session` (Article I): the
  gate is evaluated first, and a `hold`/`refuse` stops the loop with reason
  `gate_held`/`gate_refused` and the gate's reason recorded.
- **FR-4** The budget is checked **before** each iteration against the accumulated
  session count, wall-seconds, and context tokens. If the next action cannot run
  within the remaining budget, the loop stops with reason `budget_exhausted` and
  records the planned next action.
- **FR-5** `select_next_action` is deterministic, pure w.r.t. the store, and
  **monotonic**: it proposes an action only if that action would make *new*
  progress (an uncovered in-scope area, an un-hunted verified finding, an
  un-drafted verified finding). When none remain it returns `None` and the loop
  stops with reason `fixed_point`. This guarantees termination independent of the
  budget.
- **FR-6** The loop's *runnable* session repertoire is exactly `{STATUS, MAP,
  DISCOVER, SIBLING HUNT, DISCLOSURE}`. It never constructs a `NewProjectSession`,
  never writes a `Project`, and never mutates `scope_allowlist`/`authorization_*`
  (Article IX).
- **FR-7** A `candidate` that can only advance by real reproduction produces an
  **escalation** item, never autonomous execution. The loop **never constructs a
  `VerifySession` or any sandbox** — verify is escalation-only: the loop records
  the human action ("needs VERIFY under a real sandbox — human sign-off") and does
  not promote the finding. Executing no target code is thus a structural property
  of the loop, not a runtime check (Article III).
- **FR-8** The loop introduces no network code and never calls a transmit path;
  `DISCLOSURE` steps are draft-only (Article V). Disclosure is proposed only for
  `verified` findings that lack drafts.
- **FR-9** The loop writes a durable `LoopRun` record: the ordered
  `(session_type, session_id, gate_outcome, close_state)` trace, `sessions_run`,
  accumulated `ContextCost`, `stop_reason`, and `outstanding_actions[]`. The
  record is written through the `Store` and is human-readable (Article VI).
- **FR-10** The loop's teach-back always has non-empty next steps: the outstanding
  human actions, or (at a fixed point with none) an explicit "no further safe work"
  statement with the escalations that remain.
- **FR-11** `deepthought loop --project <id>` runs the loop, prints the trace and
  the stop reason, and exits 0 for every *governed* stop (refusal, fixed point,
  budget). A non-zero exit is reserved for an internal error, and — like every
  verb — it never runs ahead of `check`-able state.

## Acceptance criteria

- A loop over a proceed-gated project runs the safe chain and stops at a fixed
  point, leaving every candidate un-verified (no target-code execution) and every
  verified finding drafted-but-unsent.
- An all-`None` budget is refused; a session/time/token budget each independently
  bounds the run and yields a `budget_exhausted` stop with the planned next action.
- A gate `refuse` stops the loop immediately with the gate reason; nothing but the
  refused session log is written.
- The loop writes no `Project`, mutates no scope, imports no network module, and
  constructs no executing sandbox anywhere in its path.
- The `LoopRun` record round-trips through the `Store` and names every outstanding
  human action (verify-under-real-sandbox, send-disclosure).
- `pytest` is green (all new tests plus the existing suite), and all smokes
  (`smoke.sh` … `smoke_006.sh`) pass.

## Open questions

Resolved as locked decisions for this build (rationale in `plan.md`):

1. **Driver, not planner.** Selection is a deterministic priority ladder over
   state, not an LLM/planner — testable, reproducible, and it cannot invent
   scope. (Article IX minimalism.)
2. **Per-project core.** `run_loop` drives one authorized project; iterating
   several registered projects is a thin, later outer layer, not this feature.
3. **Termination is structural, not just budgetary.** Monotonic selection reaches
   a fixed point on its own; the budget is a second, independent backstop.
4. **`VERIFY` in the loop is Noop-only.** Running the dry-run to produce the
   escalation artifact is safe (feature 003 already makes Noop the only backend);
   real execution stays a human-signed hard stop and the finding is not promoted.
5. **Budget dimensions.** Sessions, wall-seconds, and context tokens (reusing the
   existing `ContextCost`); at least one required.
6. **`LoopRun` persistence.** A durable record through the `Store` (its exact
   record shape vs. a session-detail artifact is settled in `data-model.md`).

## Success criteria

`smoke_006.sh` passes end to end: a fresh state, a project gated to proceed, a
bounded `deepthought loop` that runs the safe chain (status → map → discover →
sibling/disclose for any verified) and stops at a fixed point or budget with a
`LoopRun` record; a negative case where an all-`None` budget is refused and a
gate-refused project stops the loop immediately. Across the whole run: no
`Project` is written, no scope is widened, no target code executes, and nothing is
transmitted — the loop advances to the hard-stop boundaries and hands them back to
a human.
