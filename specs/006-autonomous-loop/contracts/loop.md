# Contract: Autonomous loop

Public surface of feature 006. Signatures are stable; the loop reuses the existing
gated harness and adds no bypass.

## `loop/budget.py`

```python
class LoopBudget(BaseModel):
    max_sessions: int | None = None
    max_wall_seconds: float | None = None
    max_context_tokens: int | None = None
    # constructor RAISES (ValueError) if all three are None, or any set limit <= 0

    def would_exceed(self, spent: "LoopSpend") -> bool: ...

class LoopSpend(BaseModel):
    sessions: int = 0
    wall_seconds: float = 0.0
    tokens: int = 0
    def plus(self, cost: ContextCost) -> "LoopSpend": ...   # returns a new accumulator
```

- `would_exceed(spent)` → `True` if one more session could cross any *set* limit.
  Unset (`None`) limits never trigger. Checked **before** each iteration.

## `loop/policy.py`

```python
def select_next_action(
    store: Store, project: Project, *, done: set[tuple[str, str]] | None = None
) -> LoopAction | None: ...
```

- **Pure** w.r.t. `(store, done)` (reads findings/sessions + `scope_allowlist`;
  writes nothing). `done` is the driver's in-run set of dispatched
  `(kind, target)` actions.
- **Deterministic** and **priority-ordered** (the ladder in `plan.md`).
- **Monotonic**: returns an action only if it makes *new* progress; returns `None`
  at a fixed point.
- Returns a `verify_escalation` `LoopAction` (with `is_escalation=True` and a
  `human_action`) when the only remaining progress is verifying a candidate; the
  driver records it and does not run a promoting session.

## `loop/driver.py`

```python
def run_loop(
    store: Store,
    gate: Gate,
    project_id: str,
    budget: LoopBudget,
    *,
    clock: Callable[[], datetime] = utcnow,
) -> LoopRun: ...
```

Behaviour (see `plan.md` for the flow):

1. Missing project → return an **UNPERSISTED** `LoopRun` with
   `stop_reason=gate_refused`, `sessions_run=0` (nothing to audit, and a persisted
   record would orphan `check`).
2. Gate the project **once up front** (Article I — the Gate runs before ANY work,
   including an escalation-only or fixed-point run; the loop changes no
   authorization/scope, so the decision holds for the whole run). A non-`proceed`
   decision → persist a `LoopRun` with `gate_held`/`gate_refused`, `sessions_run=0`.
3. Loop: `would_exceed` (against a live spend whose `wall_seconds` is the REAL
   elapsed wall-clock time, measured in the driver) → `budget_exhausted`;
   `select_next_action` is `None` → `fixed_point`; action `is_escalation` → append
   `outstanding_actions`, stop with `hard_stop`; else build the session (repertoire
   **excludes** `NEW PROJECT`), run it via `run_session`.
4. Accumulate session count + token `ContextCost` into `LoopSpend`; append a `LoopStep`.
4. On stop, persist the `LoopRun` (via `store.save_loop_run`) with the trace,
   accumulated cost, stop reason, outstanding actions, and a teach-back `body`
   whose **Next steps** section is non-empty (the outstanding human actions, or an
   explicit "no further safe work" line).

Invariants the driver upholds:

- Never constructs a `NewProjectSession`; never calls `store.save_project`; never
  mutates `scope_allowlist`/`authorization_*`.
- Never constructs a `VerifySession` or any sandbox — verify is escalation-only, so
  the loop cannot execute target code even in principle.
- Imports/uses no network module; performs no disclosure transmission.
- Never raises `LoopBudget` upward; the budget is read-only for the run.

## `store` additions (`base.py`, `filestore.py`)

```python
def save_loop_run(self, run: LoopRun) -> LoopRun: ...
def get_loop_run(self, run_id: str) -> LoopRun | None: ...          # _safe_id-guarded
def list_loop_runs(self, project: str | None = None) -> list[LoopRun]: ...
```

- `LoopRun` persists as `loop/<id>.md` (Markdown + front-matter), like every
  record. `get_loop_run` guards its raw id with `is_record_id` (defence-in-depth,
  same as the other `get_*`).

## CLI (`cli.py`)

```
deepthought loop --project <id> [--max-sessions N] [--max-seconds S] [--max-tokens T]
```

- Requires at least one budget flag (mirrors `LoopBudget`'s all-`None` refusal);
  missing all three prints a clear error and exits non-zero.
- Runs `run_loop`, prints the ordered trace, the stop reason, and the outstanding
  actions. Exit 0 for every *governed* stop (refusal, fixed point, budget,
  hard-stop); non-zero only on an internal error.
- Prints no disclosure content and triggers no transmission; it is a driver over
  the existing verbs.

## Boundaries this contract must NOT cross

- No `NEW PROJECT` in the repertoire; no `Project` write; no scope mutation.
- No target-code execution; `verify_escalation` is data, not a run.
- No network / transmit path anywhere in the loop package.
- No self-growing or absent budget.
