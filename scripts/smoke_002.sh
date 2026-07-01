#!/usr/bin/env bash
# The feature-002 READ-ONLY smoke, driven through the real CLI.
#
# Demonstrates the 002 acceptance criteria end to end against THIS repository as
# the in-scope target: register a project, MAP the surface (coverage recorded),
# DISCOVER candidate findings from a SARIF (candidates created), prove `check`
# stays OK (all findings OSV-valid), and print the orchestrator's ledger /
# primitive summary. Nothing executes target code; nothing is transmitted; scope
# is never widened. Uses a throwaway state dir. Exits 0 on success.
#
# Usage:  ./scripts/smoke_002.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
DT="${ROOT}/.venv/bin/deepthought"
SARIF="${ROOT}/tests/fixtures/sample.sarif"
STATE="$(mktemp -d)/state"
export DEEPTHOUGHT_STATE="$STATE"
# The in-scope target is this repository itself: local_path = repo root, and the
# only in-scope area is the package source tree.
TARGET_ROOT="$ROOT"
SCOPE="src/deepthought"
PROJECT="deepthought"

# Robustness: a cold/stale editable .pth can drop src from sys.path (seen on
# Python 3.14). Put the package source on PYTHONPATH so every invocation below —
# the console script and the in-process python blocks — imports deepthought
# reliably, independent of the editable install's state.
export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"

say() { printf '\n=== %s ===\n' "$1"; }

say "0. Feature 002 is READ-ONLY (no code execution, no network, no scope widening)"
test -f "$SARIF"
echo "target: this repo  |  local_path=${TARGET_ROOT}  |  scope=${SCOPE}"

say "1. NEW PROJECT — register this repo as the in-scope target"
"$DT" playbook new-project \
  --name "Deep Thought (self)" \
  --local-path "$TARGET_ROOT" \
  --source-type open_source \
  --basis own_code \
  --scope "$SCOPE" \
  --scope app \
  --project-id "$PROJECT"
ls "$STATE/projects"

say "2. MAP — record the in-scope attack surface, READ-ONLY (coverage recorded)"
"$DT" playbook map --project "$PROJECT"
# Acceptance: at least one coverage record exists, method 'read'.
COV_COUNT="$("$PY" - "$STATE" "$PROJECT" <<'PY'
import sys
from deepthought.store import FileStore
store = FileStore(sys.argv[1])
cov = store.list_coverage(project=sys.argv[2])
assert cov, "MAP recorded no coverage"
assert all(c.method.value == "read" for c in cov), "coverage not READ-ONLY"
print(len(cov))
PY
)"
echo "coverage areas recorded (method=read): ${COV_COUNT}"

say "3. DISCOVER — reason over SARIF for candidate findings (candidates created)"
"$DT" playbook discover --project "$PROJECT" --sarif "$SARIF"
"$DT" playbook findings --project "$PROJECT"
# Acceptance: candidate findings now exist, all status 'candidate'.
FIND_COUNT="$("$PY" - "$STATE" "$PROJECT" <<'PY'
import sys
from deepthought.store import FileStore
store = FileStore(sys.argv[1])
findings = store.list_findings(project=sys.argv[2])
assert findings, "DISCOVER created no candidate findings"
assert all(f.status.value == "candidate" for f in findings), "not all candidates"
print(len(findings))
PY
)"
echo "candidate findings created: ${FIND_COUNT}"

say "4. check — must be OK (all findings OSV-valid, no orphans, lifecycle legal)"
"$DT" check

say "5. Ledger / primitive summary (the orchestrator's bounded working set)"
# Read-only: re-ingest the same SARIF through a fresh Conductor to surface the
# orchestrator's compact working set (primitive ledger + exploit graph). This
# writes nothing to the store; it only reports what the DISCOVER envelope fed
# into the ledger — the injection firewall in action.
"$PY" - "$SARIF" "$PROJECT" <<'PY'
import sys
from deepthought.ingest.sarif import (
    load_sarif,
    sarif_to_findings,
    sarif_to_primitives,
)
from deepthought.orchestrator import Conductor
from deepthought.schema import Envelope

sarif_path, project = sys.argv[1], sys.argv[2]
sarif = load_sarif(sarif_path)
findings = sarif_to_findings(sarif, project=project, id_start=1)
primitives = sarif_to_primitives(sarif, finding_ids=[f.id for f in findings])

envelope = Envelope(
    envelope_version="1.0",
    session_ref="S-smoke-002",
    worker_id="marvin-discover",
    task_ref=f"discover candidates for {project} from SARIF",
    outcome="resolved" if findings else "empty",
    primitives=primitives,
    findings_written=[f.id for f in findings],
    coverage_delta=[],
    next_step_hints=[],
    detail_ref=None,
    gate_attestation={"scope_ok": True, "authorization_ref": "own_code"},
)

conductor = Conductor()
result = conductor.ingest(envelope)
assert result.ok, "envelope rejected at ingest"
summary = conductor.state_summary()
print(f"ledger primitives : {summary['primitives']}")
print(f"compositions      : {summary['compositions']}")
print(f"ingest errors     : {summary['errors']}")
print("primitives:")
for node in conductor.ledger.nodes():
    print(
        f"  - {node.kind} @ {node.target_locus} "
        f"({node.confidence}) -> {node.finding_ref}"
    )
PY

say "6. Acceptance summary"
echo "READ-ONLY: no target code executed, nothing transmitted, scope unchanged."
echo "MAP coverage areas : ${COV_COUNT}"
echo "DISCOVER candidates : ${FIND_COUNT}"
echo "check              : OK (all findings OSV-valid)"

say "smoke_002 complete — state at $STATE"
