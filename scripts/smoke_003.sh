#!/usr/bin/env bash
# The feature-003 VERIFY smoke, driven through the real CLI — Noop-backed.
#
# Proves the VERIFY lifecycle end to end WITHOUT ever executing untrusted target
# code and WITHOUT a running Docker daemon (Constitution Article III; Phase 0
# §0.3). VERIFY reaches execution only through the injected Sandbox seam, and the
# seam here is a NoopSandbox that RECORDS the requested run and returns a canned
# result — it runs nothing. No container is built, no subprocess is spawned, no
# DockerSandbox.run() is called, and nothing is transmitted.
#
# Steps:
#   1. NEW PROJECT   — register this repo as the in-scope target (basis own_code).
#   2. DISCOVER      — reason over the bundled SARIF fixture; seed candidate(s).
#   3. VERIFY (dry)  — default NoopSandbox dry-run: prints "no execution — sandbox
#                      sign-off pending" and leaves the candidate a candidate.
#   4. VERIFY (repro)— --noop-reproduced only changes the REPORTED verdict; the CLI
#                      still executes nothing AND mutates nothing (a synthetic Noop
#                      verdict must never write real verification state). Candidate
#                      stays a candidate.
#   5. Promote (API) — the internal VerifySession promote-through-guard path, driven
#                      directly (NOT the CLI): a NoopSandbox reproducing verdict
#                      pages resolving evidence and promotes candidate -> verified
#                      through store.transition_finding. Still executes nothing; this
#                      is the path a signed-off backend will drive.
#   6. check         — stays green on the produced state.
#
# Uses a throwaway state dir. Exits 0 on success.
#
# Usage:  ./scripts/smoke_003.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
DT="${ROOT}/.venv/bin/deepthought"
SARIF="${ROOT}/tests/fixtures/sample.sarif"
STATE="$(mktemp -d)/state"
export DEEPTHOUGHT_STATE="$STATE"
# The in-scope target is this repository itself. The SARIF fixture locates its
# results under app/, so app is in scope for DISCOVER to keep the candidates.
TARGET_ROOT="$ROOT"
PROJECT="deepthought"

# Robustness: a cold/stale editable .pth can drop src from sys.path (seen on
# Python 3.14). Self-heal the editable install if `import deepthought` fails, then
# put the package source on PYTHONPATH so every invocation below — the console
# script and the in-process python blocks — imports deepthought reliably.
if ! "$PY" -c "import deepthought" >/dev/null 2>&1; then
  echo "self-heal: reinstalling editable deepthought (import failed on cold checkout)"
  uv pip install --python "${ROOT}/.venv" -e "${ROOT}[dev]" >/dev/null
fi
export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"

say() { printf '\n=== %s ===\n' "$1"; }

say "0. Feature 003 VERIFY smoke — NO target code executes, NO Docker daemon"
test -f "$SARIF"
echo "target: this repo  |  local_path=${TARGET_ROOT}  |  sandbox=NoopSandbox (records, runs nothing)"

say "1. NEW PROJECT — register this repo as the in-scope target"
"$DT" playbook new-project \
  --name "Deep Thought (self)" \
  --local-path "$TARGET_ROOT" \
  --source-type open_source \
  --basis own_code \
  --scope app \
  --scope src/deepthought \
  --project-id "$PROJECT"
ls "$STATE/projects"

say "2. DISCOVER — reason over the bundled SARIF for candidate findings"
"$DT" playbook discover --project "$PROJECT" --sarif "$SARIF"
"$DT" playbook findings --project "$PROJECT"

# Pick the first candidate finding id — the one VERIFY will promote.
FINDING="$("$PY" - "$STATE" "$PROJECT" <<'PY'
import sys
from deepthought.store import FileStore
store = FileStore(sys.argv[1])
cands = [f for f in store.list_findings(project=sys.argv[2])
         if f.status.value == "candidate"]
assert cands, "DISCOVER seeded no candidate finding"
print(cands[0].id)
PY
)"
echo "candidate selected for VERIFY: ${FINDING}"

say "3. VERIFY (dry-run) — default NoopSandbox: NO execution, candidate untouched"
# No --noop-reproduced: a true dry-run. The candidate must stay a candidate and
# the output must state plainly that nothing executed.
DRY_OUT="$("$DT" playbook verify --project "$PROJECT" --finding "$FINDING")"
printf '%s\n' "$DRY_OUT"
printf '%s' "$DRY_OUT" | grep -qi "no execution" \
  || { echo "ERROR: dry-run did not report 'no execution'" >&2; exit 1; }
printf '%s' "$DRY_OUT" | grep -qi "sign-off pending" \
  || { echo "ERROR: dry-run did not report 'sign-off pending'" >&2; exit 1; }
"$PY" - "$STATE" "$FINDING" <<'PY'
import sys
from deepthought.store import FileStore
store = FileStore(sys.argv[1])
f = store.get_finding(sys.argv[2])
assert f.status.value == "candidate", f"dry-run changed status to {f.status.value!r}"
assert not f.evidence_ref, "dry-run set an evidence_ref; it must not"
print("dry-run left the finding a candidate with no evidence_ref — correct")
PY

say "4. VERIFY (--noop-reproduced) — still a DRY-RUN: reports reproduced, mutates nothing"
# In this slice the CLI NEVER writes verification state from a synthetic Noop
# verdict. --noop-reproduced only changes the REPORTED verdict; the candidate must
# stay a candidate with no evidence_ref.
"$DT" playbook verify --project "$PROJECT" --finding "$FINDING" --noop-reproduced
"$PY" - "$STATE" "$FINDING" <<'PY'
import sys
from deepthought.store import FileStore
store = FileStore(sys.argv[1])
f = store.get_finding(sys.argv[2])
assert f.status.value == "candidate", f"--noop-reproduced mutated status to {f.status.value!r}"
assert not f.evidence_ref, "--noop-reproduced set an evidence_ref; it must not"
assert not f.transition_log, "--noop-reproduced wrote a transition_log entry; it must not"
print("--noop-reproduced left the finding a candidate — the CLI mutates nothing here")
PY

say "5. Promote via the SESSION API (not the CLI) — the promote-through-guard path"
# This is the INTERNAL path a signed-off backend will drive: a VerifySession with a
# NoopSandbox reproducing verdict pages resolving evidence and promotes the
# candidate to verified THROUGH store.transition_finding. It executes NOTHING (Noop
# seam) — it demonstrates the guard, not real execution. This is what the unit
# tests exercise; here we drive it end to end for the smoke.
"$PY" - "$STATE" "$FINDING" <<'PY'
import sys
from pathlib import Path
from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.sandbox import NoopSandbox, SandboxPolicy, SandboxResult, SandboxSpec
from deepthought.sessions import VerifySession
from deepthought.store import FileStore

state, finding_id = sys.argv[1], sys.argv[2]
store = FileStore(state)
spec = SandboxSpec(
    image="ghcr.io/deepthought/repro-runner@sha256:" + "0" * 64,
    command=["/repro/run", "--input", "/work/case"],
    repro_ref="detail/seed/repro-01.bin",
    policy=SandboxPolicy(),
)
result = SandboxResult(exit_code=0, timed_out=False, wall_seconds=0.0, reproduced=True)
# dry_run defaults to False here: the REAL promote-through-guard path. NoopSandbox
# still executes nothing.
session = VerifySession("deepthought", finding_id, spec=spec, sandbox=NoopSandbox(result))
record = run_session(store, HermesUltraCodeGate(), session)

f = store.get_finding(finding_id)
assert f.status.value == "verified", f"expected verified, got {f.status.value!r}"
assert f.evidence_ref and store.detail_exists(f.evidence_ref), "evidence_ref missing/unresolved"
body = (Path(state) / f.evidence_ref).read_text(encoding="utf-8")
assert "reproduced: True" in body, "paged evidence missing the typed verdict"
assert session.sandbox.recorded, "the sandbox seam was never exercised"
print(f"promoted candidate -> verified via the lifecycle guard; evidence at {f.evidence_ref}")
PY
"$DT" playbook findings --project "$PROJECT"

say "6. check — must be OK (verified finding carries a resolving evidence_ref)"
"$DT" check

say "7. Acceptance summary"
echo "NO target code executed: the sandbox seam was a NoopSandbox (records, runs nothing)."
echo "NO Docker daemon required; NO subprocess spawned; NOTHING transmitted."
echo "CLI 'playbook verify' mutates NOTHING in this slice (dry-run only, both verdicts)."
echo "Promotion candidate -> verified is the internal session/guard path (signed-off"
echo "backend will drive it); demonstrated here via the session API on ${FINDING}."
echo "check              : OK"

say "smoke_003 complete — state at $STATE"
