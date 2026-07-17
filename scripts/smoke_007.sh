#!/usr/bin/env bash
# The feature-007 MOSTLY HARMLESS profile smoke, driven through the real CLI.
#
# Proves the low-friction `mostly_harmless` profile is PURELY ergonomic: it fills
# unset CLI defaults and trims informational output, and changes NONE of the four
# load-bearing stops. Two halves:
#
#   A. PROFILE OFF (byte-for-byte default mode, spec success criterion 1)
#      - `deepthought profiles` audits the profile without touching state.
#      - a read-only verb renders the FULL _echo_session header.
#      - the flag-free loop is still REFUSED (the loop is never unbounded).
#      - the existing 006 loop smoke still passes byte-for-byte.
#
#   B. PROFILE ON via DEEPTHOUGHT_PROFILE=mostly_harmless (spec success crit. 2)
#      - register an own_code project with an EXPLICIT --scope (never auto-filled).
#      - a FLAG-FREE loop bounds itself with the profile's finite default budget
#        (echoed), auto-advances only read-only sessions, escalates the seeded
#        candidate as a human verify_escalation, and transmits nothing.
#      - every stop still holds under the profile: empty scope HOLDs (with a
#        helpful pointer, never a default), a basis-less project REFUSES, verify
#        --i-have-sandbox-signoff REFUSES and runs nothing, and disclose drafts
#        locally while preserving the "nothing transmitted / a human must send"
#        notice.
#
# Uses throwaway state dirs. Exits 0 on success.
#
# Usage:  ./scripts/smoke_007.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
DT="${ROOT}/.venv/bin/deepthought"

if ! "$PY" -c "import deepthought" >/dev/null 2>&1; then
  echo "self-heal: reinstalling editable deepthought (import failed on cold checkout)"
  uv pip install --python "${ROOT}/.venv" -e "${ROOT}[dev]" >/dev/null
fi
# src for `deepthought`, repo root for `tests.conftest` (used to seed a fully
# formed verified finding for the disclose step).
export PYTHONPATH="${ROOT}/src:${ROOT}${PYTHONPATH:+:$PYTHONPATH}"

say()  { printf '\n=== %s ===\n' "$1"; }
fail() { echo "ERROR: $1" >&2; exit 1; }

CHECKOUT="$(mktemp -d)/repo"
mkdir -p "$CHECKOUT/app"
echo "print('hi')" > "$CHECKOUT/app/main.py"
CHECKOUT2="$(mktemp -d)/repo2"       # a DISTINCT identity for the no-basis case
mkdir -p "$CHECKOUT2/app"
echo "print('hi')" > "$CHECKOUT2/app/main.py"

say "0. Feature 007 MOSTLY HARMLESS smoke — ergonomic only; every stop preserved"

# ---------------------------------------------------------------------------
say "A. PROFILE OFF — default mode is unchanged"
# ---------------------------------------------------------------------------
unset DEEPTHOUGHT_PROFILE || true

say "A.1 deepthought profiles — read-only introspection (changes no state)"
PROFILES_OUT="$("$DT" profiles)"
echo "$PROFILES_OUT"
echo "$PROFILES_OUT" | grep -q "mostly_harmless"        || fail "profiles did not list mostly_harmless"
echo "$PROFILES_OUT" | grep -q "max_sessions=25"        || fail "profiles did not print the exact budget"
echo "$PROFILES_OUT" | grep -q "NEVER auto-filled"      || fail "profiles did not state scope is never auto-filled"
echo "$PROFILES_OUT" | grep -q "NEVER defaulted"        || fail "profiles did not state basis/path never defaulted"

STATE_A="$(mktemp -d)/state"
say "A.2 register (own_code + explicit scope) and MAP with NO profile"
"$DT" playbook new-project --state "$STATE_A" --name "off-target" \
  --source-type open_source --local-path "$CHECKOUT" --basis own_code --scope app >/dev/null
MAP_OFF="$("$DT" playbook map --state "$STATE_A" --project repo)"
echo "$MAP_OFF"
echo "$MAP_OFF" | grep -q "gate    : proceed" || fail "default map lost its full _echo_session header"
echo "$MAP_OFF" | grep -q "close   : clean"   || fail "default map lost its full _echo_session header"

say "A.3 flag-free loop is STILL refused with no profile (never unbounded)"
if "$DT" loop --project repo --state "$STATE_A" >/dev/null 2>&1; then
  fail "the loop ran flag-free with no profile"
fi
echo "loop correctly REFUSED a flag-free run in default mode"

say "A.4 the existing 006 loop smoke still passes byte-for-byte (default mode)"
( unset DEEPTHOUGHT_PROFILE; bash "${ROOT}/scripts/smoke_006.sh" >/dev/null ) \
  && echo "smoke_006 (default mode) PASSED" || fail "smoke_006 regressed under 007"

# ---------------------------------------------------------------------------
say "B. PROFILE ON — DEEPTHOUGHT_PROFILE=mostly_harmless"
# ---------------------------------------------------------------------------
export DEEPTHOUGHT_PROFILE=mostly_harmless
STATE_B="$(mktemp -d)/state"

say "B.1 register an own_code project with an EXPLICIT --scope (never auto-filled)"
"$DT" playbook new-project --state "$STATE_B" --name "loop-target" \
  --source-type open_source --local-path "$CHECKOUT" --basis own_code --scope app >/dev/null
PID="$("$PY" - "$STATE_B" <<'PY'
import sys
from deepthought.store import FileStore
print(FileStore(sys.argv[1]).list_projects()[0].id)
PY
)"
echo "registered ${PID} (own_code, scope=[app])"

say "B.2 seed a candidate — the loop must ESCALATE it, never execute it"
"$PY" - "$STATE_B" "$PID" <<'PY'
import sys
from deepthought.schema import Finding
from deepthought.store import FileStore
FileStore(sys.argv[1]).save_finding(Finding.model_validate({
    "id": "F-9001", "project": sys.argv[2],
    "summary": "seeded candidate for the profile loop to escalate (not execute)",
}))
print("seeded candidate F-9001")
PY

say "B.3 FLAG-FREE loop — bounds itself with the profile's finite default budget"
LOOP_OUT="$("$DT" loop --project "$PID" --state "$STATE_B")"   # NOTE: no --max-* flag
echo "$LOOP_OUT"
echo "$LOOP_OUT" | grep -q "requires at least one budget" && fail "flag-free loop was refused under the profile"
echo "$LOOP_OUT" | grep -q "stop     : hard_stop"                     || fail "expected a hard_stop escalation"
echo "$LOOP_OUT" | grep -q "budget   : profile 'mostly_harmless'"     || fail "effective budget was not echoed"
echo "$LOOP_OUT" | grep -q "max_sessions=25"                          || fail "profile default budget not applied"
echo "$LOOP_OUT" | grep -q "F-9001 needs VERIFY under a real sandbox" || fail "candidate not escalated to a human"

say "B.4 assert: candidate UNPROMOTED, scope unchanged, one project, LoopRun persisted"
"$PY" - "$STATE_B" "$PID" <<'PY'
import sys
from deepthought.store import FileStore
store = FileStore(sys.argv[1]); pid = sys.argv[2]
assert store.get_finding("F-9001").status.value == "candidate", "candidate was promoted — no target code may run"
assert store.get_project(pid).scope_allowlist == ["app"], "scope was widened"
assert len(store.list_projects()) == 1, "the loop wrote a new project"
run = store.list_loop_runs(project=pid)[-1]
assert run.stop_reason.value == "hard_stop"
assert run.budget.max_sessions == 25 and run.budget.max_wall_seconds == 1800.0
assert run.budget.max_context_tokens == 200000, "profile budget not persisted on the LoopRun"
print(f"candidate still candidate; scope unchanged; LoopRun {run.id!r} bounded by the profile budget")
PY

say "B.5 empty scope STILL HOLDs under the profile (never auto-filled) + helpful pointer"
HOLD_OUT="$("$DT" playbook new-project --state "$STATE_B" --name "no-scope" \
  --source-type open_source --local-path "$CHECKOUT" --basis own_code || true)"
echo "$HOLD_OUT"
echo "$HOLD_OUT" | grep -qi "hold"       || fail "empty scope did not HOLD under the profile"
echo "$HOLD_OUT" | grep -q  "\-\-scope"  || fail "no helpful --scope pointer under the profile"

say "B.6 a basis-less project STILL REFUSES under the profile"
"$PY" - "$STATE_B" "$CHECKOUT2" <<'PY'
import sys
from deepthought.schema import Project
from deepthought.store import FileStore
FileStore(sys.argv[1]).save_project(Project.model_validate({
    "id": "no-basis", "name": "no-basis", "source_type": "open_source",
    "local_path": sys.argv[2], "scope_allowlist": ["app"], "status": "active",
}))
PY
REFUSE_OUT="$("$DT" playbook status --state "$STATE_B" --project no-basis)"
echo "$REFUSE_OUT"
echo "$REFUSE_OUT" | grep -qi "refuse"                  || fail "basis-less project did not REFUSE under the profile"
echo "$REFUSE_OUT" | grep -q  "no authorization basis"  || fail "wrong refusal reason under the profile"

say "B.7 verify --i-have-sandbox-signoff STILL REFUSES and runs nothing under the profile"
"$PY" - "$STATE_B" "$PID" <<'PY'
import sys
from deepthought.schema import Finding
from deepthought.store import FileStore
FileStore(sys.argv[1]).save_finding(Finding.model_validate({
    "id": "F-9002", "project": sys.argv[2], "summary": "candidate for the verify hard stop"}))
PY
set +e
VERIFY_OUT="$("$DT" playbook verify --state "$STATE_B" --project "$PID" --finding F-9002 --i-have-sandbox-signoff 2>&1)"
VERIFY_RC=$?
set -e
[ "$VERIFY_RC" -eq 2 ] || fail "verify --i-have-sandbox-signoff wrong exit ($VERIFY_RC, expected 2) under the profile"
echo "$VERIFY_OUT" | grep -qi "verify refused"      || fail "verify refusal message missing under the profile"
echo "$VERIFY_OUT" | grep -qi "Nothing was executed" || fail "verify did not assert nothing executed under the profile"
echo "verify hard stop held under the profile (exit 2, refusal + 'nothing executed' asserted)"

say "B.8 disclose drafts LOCALLY and transmits nothing (human gate preserved)"
"$PY" - "$STATE_B" "$PID" <<'PY'
import sys
from deepthought.store import FileStore
from tests.conftest import make_finding   # a fully-formed verified finding
store = FileStore(sys.argv[1])
store.save_finding(make_finding(id="F-9100", project=sys.argv[2], status="verified"))
print("seeded verified finding F-9100")
PY
DISC_OUT="$("$DT" playbook disclose --state "$STATE_B" --project "$PID" --finding F-9100)"
echo "$DISC_OUT"
echo "$DISC_OUT" | grep -qi "nothing was transmitted"  || fail "disclose dropped the transmission notice under the profile"
echo "$DISC_OUT" | grep -q  "Sending is a human action" || fail "disclose dropped the human-send record under the profile"
"$PY" - "$STATE_B" <<'PY'
import sys
from deepthought.store import FileStore
f = FileStore(sys.argv[1]).get_finding("F-9100")
assert f.status.value == "verified", "disclose advanced the lifecycle"
assert f.cve is None, "disclose fabricated a CVE"
print("disclose left the finding verified; no CVE; drafts are local only")
PY

say "9. Acceptance summary"
echo "OPT-IN + INERT DEFAULT: profile off is byte-for-byte 001-006 (smoke_006 passed)."
echo "SCOPE: never auto-filled — empty stays a HOLD with a helpful pointer."
echo "BASIS: never defaulted — a basis-less project still REFUSES."
echo "EXECUTION: verify --i-have-sandbox-signoff still refuses; nothing runs."
echo "TRANSMISSION: disclose drafts locally; the human-send notice is preserved."
echo "BOUNDED: the flag-free loop self-bounds with a finite, echoed profile budget."

say "smoke_007 complete — profile is ergonomic only; every load-bearing stop held"
