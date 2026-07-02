#!/usr/bin/env bash
# The feature-006 AUTONOMOUS LOOP smoke, driven through the real CLI.
#
# Proves the loop drives the safe session chain end to end while STAYING behind
# every gate: it never expands scope, never executes target code, and never
# transmits. It advances work up to the hard-stop boundaries (a candidate needing
# real reproduction; a disclosure needing to be sent) and ESCALATES them to a
# human. It always runs under an explicit budget and stops for a recorded reason.
#
# Steps:
#   1. NEW PROJECT — an authorized source (basis + scope so the gate proceeds),
#      with a small in-scope checkout so MAP has a real area to walk.
#   2. Seed a candidate finding — the loop must ESCALATE it, never execute it.
#   3. loop --project ... --max-sessions N -> assert a governed stop (hard_stop),
#      the safe chain in the trace (status -> map -> discover), and the candidate
#      named as an outstanding human action.
#   4. Assert: candidate NOT promoted, scope unchanged, no extra project written,
#      a durable LoopRun persisted.
#   5. check -> green after the loop.
#   6. Negative: no budget flag is refused (the loop is never unbounded).
#   7. Negative: an unauthorized project stops the loop at the gate (gate_refused).
#
# Uses a throwaway state dir. Exits 0 on success.
#
# Usage:  ./scripts/smoke_006.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
DT="${ROOT}/.venv/bin/deepthought"
STATE="$(mktemp -d)/state"
CHECKOUT="$(mktemp -d)/repo"
CHECKOUT2="$(mktemp -d)/repo2"
export DEEPTHOUGHT_STATE="$STATE"

if ! "$PY" -c "import deepthought" >/dev/null 2>&1; then
  echo "self-heal: reinstalling editable deepthought (import failed on cold checkout)"
  uv pip install --python "${ROOT}/.venv" -e "${ROOT}[dev]" >/dev/null
fi
export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"

say() { printf '\n=== %s ===\n' "$1"; }

# A small in-scope checkout so MAP has a real root/area to walk (read-only).
mkdir -p "$CHECKOUT/app"
echo "print('hi')" > "$CHECKOUT/app/main.py"
mkdir -p "$CHECKOUT2/app"   # a DISTINCT identity for the unauthorized-project case
echo "print('hi')" > "$CHECKOUT2/app/main.py"

say "0. Feature 006 AUTONOMOUS LOOP smoke — bounded, gated, no execution, no transmission"

say "1. Register an authorized project (basis + scope -> gate proceeds)"
"$PY" - "$STATE" "$CHECKOUT" <<'PY'
import sys
from deepthought.schema import Project
from deepthought.store import FileStore
store = FileStore(sys.argv[1])
store.save_project(Project.model_validate({
    "id": "loop-target", "name": "loop-target", "source_type": "open_source",
    "local_path": sys.argv[2],
    "authorization_basis": "own_code", "scope_allowlist": ["app"], "status": "active",
}))
print("registered loop-target (authorized, scope=[app])")
PY

say "2. Seed a candidate finding — the loop must ESCALATE it, never execute it"
"$PY" - "$STATE" <<'PY'
import sys
from deepthought.schema import Finding
from deepthought.store import FileStore
store = FileStore(sys.argv[1])
store.save_finding(Finding.model_validate({
    "id": "F-9001", "project": "loop-target",
    "summary": "seeded candidate for the loop to escalate (not execute)",
}))
print("seeded candidate F-9001")
PY

say "3. Run the bounded loop (--max-sessions 20)"
LOOP_OUT="$("$DT" loop --project loop-target --max-sessions 20)"
echo "$LOOP_OUT"
echo "$LOOP_OUT" | grep -q "stop     : hard_stop" || { echo "ERROR: expected a hard_stop escalation" >&2; exit 1; }
echo "$LOOP_OUT" | grep -q "status" || { echo "ERROR: STATUS did not run" >&2; exit 1; }
echo "$LOOP_OUT" | grep -q "map" || { echo "ERROR: MAP did not run" >&2; exit 1; }
echo "$LOOP_OUT" | grep -q "discover" || { echo "ERROR: DISCOVER did not run" >&2; exit 1; }
echo "$LOOP_OUT" | grep -q "F-9001 needs VERIFY under a real sandbox" || { echo "ERROR: candidate not escalated" >&2; exit 1; }

say "4. Assert: candidate UNPROMOTED, scope unchanged, one project, LoopRun persisted"
"$PY" - "$STATE" <<'PY'
import sys
from deepthought.store import FileStore
store = FileStore(sys.argv[1])
assert store.get_finding("F-9001").status.value == "candidate", "candidate was promoted — target code must not run"
assert store.get_project("loop-target").scope_allowlist == ["app"], "scope was widened"
assert len(store.list_projects()) == 1, "the loop wrote a new project"
runs = store.list_loop_runs(project="loop-target")
assert runs, "no LoopRun persisted"
run = runs[-1]
assert run.stop_reason.value == "hard_stop"
assert any("F-9001" in a for a in run.outstanding_actions), "escalation not recorded"
assert run.has_next_steps(), "LoopRun has no next steps"
print(f"candidate still candidate; scope unchanged; LoopRun {run.id!r} stop={run.stop_reason.value}")
PY

say "5. check — green after the loop"
"$DT" check

say "6. Negative: the loop requires a budget (never unbounded)"
if "$DT" loop --project loop-target >/dev/null 2>&1; then
  echo "ERROR: the loop ran with no budget" >&2
  exit 1
fi
echo "loop correctly REFUSED with no budget limit"

say "7. Negative: an unauthorized project stops the loop at the gate"
"$PY" - "$STATE" "$CHECKOUT2" <<'PY'
import sys
from deepthought.schema import Project
from deepthought.store import FileStore
store = FileStore(sys.argv[1])
# No authorization basis -> the gate refuses the first session.
store.save_project(Project.model_validate({
    "id": "no-basis", "name": "no-basis", "source_type": "open_source",
    "local_path": sys.argv[2], "scope_allowlist": ["app"], "status": "active",
}))
print("registered no-basis (no authorization basis)")
PY
UNAUTH_OUT="$("$DT" loop --project no-basis --max-sessions 5)"
echo "$UNAUTH_OUT"
echo "$UNAUTH_OUT" | grep -q "gate_refused" || { echo "ERROR: unauthorized loop did not stop at the gate" >&2; exit 1; }
echo "unauthorized project correctly stopped at gate_refused"

say "8. Acceptance summary"
echo "BOUNDED: the loop runs only under an explicit budget and stops for a recorded reason."
echo "GATED: every session passes the Gate; an unauthorized project is refused."
echo "NO EXECUTION: the candidate stays candidate — real reproduction is escalated, never run."
echo "NO SCOPE EXPANSION: no project written, scope allowlist unchanged."
echo "NO TRANSMISSION: the loop drives local verbs only; sending stays a human act."

say "smoke_006 complete — state at $STATE"
