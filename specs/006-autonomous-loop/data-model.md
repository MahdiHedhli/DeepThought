# Data Model: Autonomous loop & limit awareness

All new types are Pydantic v2 models with `extra='forbid'` (like every schema
record). Ids reuse the `RecordId` constrained type (feature: hardening-safe-ids),
so a `LoopRun` id is a safe path segment. Nothing here holds worker free-text.

## `LoopBudget` (`loop/budget.py`)

The limit-awareness envelope. A plain value object (not a Store record).

| Field | Type | Meaning |
|---|---|---|
| `max_sessions` | `int \| None` | max sessions the loop may run |
| `max_wall_seconds` | `float \| None` | max summed session wall-time |
| `max_context_tokens` | `int \| None` | max summed session `ContextCost.tokens` |

- **Invariant:** at least one field is non-`None` — the constructor **raises** on
  an all-`None` budget. There is no unbounded loop.
- **Invariant:** every set limit is `> 0`.
- `would_exceed(spent: LoopSpend) -> bool` — `True` if running one more session
  could cross any set limit (`spent.sessions + 1 > max_sessions`, or
  `spent.wall_seconds >= max_wall_seconds`, or `spent.tokens >= max_context_tokens`).
  Checked **before** each iteration; the budget is read-only for the loop's life.

`LoopSpend` is the running accumulator: `sessions: int`, `wall_seconds: float`,
`tokens: int`, summed from each ran session's `ContextCost` plus the count.

## `ActionKind` + `LoopAction` (`schema/loop.py`)

What the policy proposes. `LoopAction` is a typed value, never free-text.

`ActionKind` (str enum): `status`, `map`, `discover`, `sibling_hunt`,
`disclosure`, `verify_escalation`.

| `LoopAction` field | Type | Meaning |
|---|---|---|
| `kind` | `ActionKind` | which rung fired |
| `project` | `RecordId` | the (existing) project id |
| `area` | `str \| None` | in-scope area, for `map`/`discover` |
| `finding` | `RecordId \| None` | target finding, for `sibling_hunt`/`disclosure` |
| `is_escalation` | `bool` | `True` only for `verify_escalation` |
| `human_action` | `str \| None` | the outstanding-action text when escalating |

- A `verify_escalation` carries `is_escalation=True` and a `human_action`
  ("F-NNNN needs VERIFY under a real sandbox — human sign-off required"); every
  other kind carries `is_escalation=False`.
- `map`/`discover` carry an `area` drawn only from `project.scope_allowlist` (never
  a widened surface). `sibling_hunt`/`disclosure` carry a `finding` that is already
  `verified`.

## `StopReason` (`schema/loop.py`)

Exactly one reason ends a loop (str enum):

| Value | When |
|---|---|
| `fixed_point` | `select_next_action` returned `None` — no safe progress remains |
| `budget_exhausted` | the next action could exceed a budget limit |
| `hard_stop` | the only remaining progress is an escalation (verify/send) |
| `gate_held` | a session's gate returned `hold` |
| `gate_refused` | a session's gate returned `refuse`, or the project is missing/unauthorized |

`fixed_point` and `hard_stop` can co-occur conceptually; the loop records
`hard_stop` when it halts specifically because the next action is an escalation,
and `fixed_point` when nothing (not even an escalation) remains.

## `LoopRun` record (`schema/loop.py`, persisted via Store)

A first-class, durable, human-readable Store record — chosen over a session-detail
artifact so a loop run is listable and `check`-visible like any record.

| Field | Type | Meaning |
|---|---|---|
| `id` | `RecordId` | e.g. `L-2026-07-02-0001` |
| `project` | `RecordId` | the driven project |
| `started` | `str` (RFC3339 Z) | loop start |
| `stopped` | `str \| None` | loop end |
| `stop_reason` | `StopReason` | why it stopped |
| `sessions_run` | `int` | count of sessions executed |
| `context_cost` | `ContextCost` | accumulated tokens + wall-seconds |
| `budget` | `LoopBudget` | the input budget (audit of the limits used) |
| `trace` | `list[LoopStep]` | ordered record of each session run |
| `outstanding_actions` | `list[str]` | human actions the loop escalated to |
| `body` | `str` | Markdown teach-back (summary + next steps) |

`LoopStep`: `{kind: ActionKind, session_id: RecordId | None, area: str | None,
finding: RecordId | None, gate_outcome: GateOutcome | None, close_state:
CloseState | None}` — one row per iteration. `session_id` is `None` for a pure
escalation row (no session was run).

Round-trips through the Store as Markdown-with-front-matter like every record.

## Selection inputs (read-only, from the Store)

`select_next_action(store, project)` reads only:

- `project.scope_allowlist` — the in-scope surface (never widened).
- `store.list_coverage(project.id)` — which areas are mapped, at what depth.
- `store.list_findings(project.id)` — status buckets (`candidate` / `verified` / …).
- `store.list_sessions(project.id)` — what has already run (a `status` baseline
  exists?, which findings have a completed `sibling_hunt`, which `verified`
  findings already have `disclosure` drafts via `findings_touched`).

It writes nothing and calls no session; it is a pure function of the snapshot.

## Guarantees (enforced by construction)

1. **Termination.** Monotonic selection (each rung fires only while it makes *new*
   progress) reaches `fixed_point`/`hard_stop` in bounded steps independent of the
   budget; the budget is a second backstop.
2. **No scope expansion.** No type here can register a project or widen a scope
   allowlist; `map`/`discover` areas are drawn only from the existing allowlist,
   and the loop writes only `LoopRun` (+ the sessions' own records) — never a
   `Project`.
3. **No execution / no transmission.** `verify_escalation` is a recorded action,
   not a run; the loop constructs no `VerifySession` and no sandbox at all, and no
   disclosure `send` type exists. The hard stops are data, handed to a human.
4. **Bounded by design.** `LoopBudget` refuses all-`None`; `would_exceed` is
   checked before every iteration and the budget is immutable for the run.
