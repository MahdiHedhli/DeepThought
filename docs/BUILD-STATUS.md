# DeepThought — Build Status Report

_As of 2026-07-02._

## TL;DR
DeepThought is a **governed, autonomous security-research platform**. Its entire
numbered feature roadmap — **001 → 006 — is built, reviewed, and merged to
`main`.** Repo: **`MahdiHedhli/DeepThought`** (public). State on `main`: **570
tests green; all six smoke scripts pass.** No further numbered feature remains;
next work needs a human decision.

Every feature was built **gate-first / test-first** and merged only after an
independent **dual-gate review** (both reviewers clean on the same HEAD). All
commits are authored `MahdiHedhli`.

## What it is
"An autonomous loop is only safe behind gates." DeepThought runs **typed agent
sessions** that discover, map, verify, and prepare disclosure for vulnerabilities,
keeping every result in a **durable, version-controlled, human-readable knowledge
base** (Markdown + YAML front-matter, read/written only through a `Store`
interface). A **Constitution** (9 articles, `.specify/memory/constitution.md`) is
governing law and loads into every session.

Built with the **GitHub Spec Kit** layout: intent is the source of truth
(`specs/`, `.specify/memory/constitution.md`); the platform is the regenerated
output. Python 3.12+ (running 3.14), Pydantic v2 (`extra='forbid'`), Typer CLI,
hatchling/uv, pytest.

## The verbs
```
deepthought playbook   # run the Agent Session Protocol for a session type; list findings
deepthought check      # validate state: schema, lifecycle, orphans, identity, OSV/CSAF/OpenVEX
deepthought publish    # emit prepared LOCAL artifacts, assert the human gate, transmit nothing
deepthought loop       # (006) drive the safe session chain autonomously under a budget
```

## Feature roadmap — all merged

| Feature | Capability | Risk posture | Merge |
|---|---|---|---|
| **001** core-loop | `NEW PROJECT`, `STATUS`, the spine (Store, Gate, Agent Session Protocol, orchestrator+workers) | read-only | initial publish |
| **002** improbability-drive | `MAP`, `DISCOVER` — static reasoning → candidate findings | read-only | PR #1 |
| **003** execution-sandbox | `VERIFY` — sandboxed reproduction | **execution behind a HARD STOP**; `NoopSandbox` dry-run only | `440485a` (#2) |
| **004** sibling-hunt | `SIBLING HUNT` — cross-project variant analysis | read-only | `93ce057` (#3) |
| **005** disclosure | `DISCLOSURE` — draft advisory + CVE 5.1 + CSAF 2.0 + OpenVEX | **draft-only; transmits nothing** | `a99340f` (#4) |
| — security root-fix | `RecordId` constrained type + FileStore path/identity hardening (closed a **real path traversal**) | hardening | `40031de` (#5) |
| **006** autonomous-loop | `loop` — deterministic bounded gated driver + limit awareness | **bounded & gated; escalates the hard stops** | `69c8fc1` (#6) |

## Architecture (`src/deepthought/`)
- **`schema/`** — canonical records (`Project`, `Finding`, `Session`, `Coverage`,
  `Methodology`, `Envelope`, `Primitive`, `LoopRun`); `common.py` has the `Record`
  base and the `RecordId` safe-id type. Standards-aligned: OSV (finding record),
  CSAF 2.0 / OpenVEX / CVE 5.1 (disclosure, draft-only).
- **`store/`** — `Store` interface + `FileStore` (files-in-git; lifecycle guard at
  the boundary; path/identity hardened).
- **`protocol/`** — the Agent Session Protocol (`run_session`, `Gate` with
  `proceed/hold/refuse`).
- **`sessions/`** — the typed sessions (status, map, discover, sibling_hunt,
  verify, disclosure, new_project). `VerifySession` is a **lazy** export so
  importing the loop never loads the sandbox.
- **`orchestrator/` + `ingest/`** — the conductor with the **Envelope injection
  firewall** (workers return only a schema-validated, length-capped envelope).
- **`sandbox/`** — the `Sandbox` seam; only `NoopSandbox` (executes nothing) is
  ever constructed.
- **`export/`** — OSV/CSAF/OpenVEX/CVE/advisory exporters + validators.
- **`loop/`** — **feature 006**: `budget.py`, `policy.py` (`select_next_action`,
  `pending_escalations`), `driver.py` (`run_loop`).
- **`check.py`, `cli.py`** — the gate command and the Typer CLI.

## The Constitution (9 articles) & the two HARD STOPS
I (Gate-first), II (Authorization & scope), III (Sandbox), IV (Evidence &
lifecycle), V (Coordinated disclosure), VI (Durable state), VII (Validate-first),
VIII (Injection resistance), IX (Minimalism & least privilege).

**Two hard stops require an explicit human sign-off and have never been crossed
autonomously:**
1. **Real target-code execution** (feature 003 VERIFY) — only `NoopSandbox`
   exists; no executing backend is wired.
2. **Disclosure transmission** (feature 005) — everything is draft-only; there is
   no network/transmit code anywhere.

## Feature 006 — the autonomous loop
```
deepthought loop --project <id> --max-sessions N [--max-seconds S] [--max-tokens T]
```
A **deterministic** driver (not a planner): it repeatedly asks `select_next_action`
for the next safe action and runs it through the existing gated `run_session`.
Ladder: **STATUS → MAP → DISCOVER (per project) → SIBLING HUNT → DISCLOSURE (draft)
per verified finding**, then stops for one recorded `StopReason` (`fixed_point` /
`budget_exhausted` / `gate_held` / `gate_refused` / `hard_stop`) and writes a
durable, `check`-visible **`LoopRun`** audit record.

Safety envelope, enforced by construction:
- **No scope expansion** (Art. IX): builds no `NEW PROJECT`, writes no `Project`,
  never mutates scope/authorization. Budget is **required** (all-`None`,
  non-positive, and non-finite all refused) and **frozen**.
- **Gate-first** (Art. I): the project is gated **once up front** (covers
  escalation-only/fixed-point runs), and every session re-gates via `run_session`.
- **No target-code execution** (Art. III): constructs no verify session/sandbox —
  a candidate is a `verify_escalation`, never a run — and the loop's **import
  closure excludes verify/sandbox entirely**.
- **No transmission** (Art. V): disclosure is draft-only; the human review-and-send
  is a **persistent `disclosure_send` escalation**, never performed.
- **Bounded & terminating**: completion signals are progress-based (a rung is done
  only on gate-**proceed + clean-close**; MAP is per-area; DISCOVER goes stale once
  coverage post-dates it; "drafted" requires drafts that **resolve AND validate**
  via the check gate's own logic). At the hard-stop boundary all outstanding human
  actions are enumerated in **one bounded pass**.

## Review process used (repeatable)
Because the GitHub review bots lag/quota-block, each PR was driven to a clean
**local dual-gate** on the same HEAD:
- **codex** — `codex review --base main` (OpenAI Codex CLI, gpt-5.5).
- **agy** — Antigravity/Gemini adversarial CLI, fed the full diff **plus the
  complete text of every changed source file** (it reasons only from pasted code;
  timeouts/errors count as *incomplete*, never a pass).

Both must return CLEAN on the same commit before merge. Feature 006 took **11
rounds** — every codex finding was a real, distinct correctness bug in the loop's
state machine, each fixed test-first; agy was clean the last four rounds.

## Open follow-ups (tracked; NOT done, not blocking)
1. **Legacy-store `RecordId` migration** — a graceful `migrate`/repair path so a
   `FileStore` written before ids were tightened doesn't fail strict-on-read after
   upgrade. (Shipped repo has no populated state, so impact is nil today.)
2. **`generate_session_id` gap-collision fix** — it uses `len()+1`, which can
   collide/overwrite after a deleted record; apply the same `max(seq)+1` fix
   already made to `generate_loop_run_id`.

## Standing operating agreement
- **Merge-on-clean**: once BOTH gates are clean on the same HEAD with zero real
  findings, squash-merge (`gh pr merge <n> --squash --delete-branch`, author
  MahdiHedhli) and proceed. Only stop for: reviewers can't reach consensus, a real
  design decision, or a constitution hard stop.
- **NTFY** to `ntfy.sh/Mahdi-Dev` on every hard stop (urgent) and every merge.

## What needs a decision next
The numbered roadmap is complete, so there is nothing left to build autonomously.
Options: (a) the two follow-ups above, (b) a new numbered feature (needs a spec),
or (c) a real **authorized** engagement — which immediately hits the
target-code-execution / disclosure-transmission hard stops that need a human
sign-off.

## Run it
```bash
uv venv --python 3.12 .venv
uv pip install --python .venv -e ".[dev]"
.venv/bin/pytest                          # 570 tests
for s in scripts/smoke*.sh; do bash "$s"; done   # 6 smokes
.venv/bin/deepthought --help
```
