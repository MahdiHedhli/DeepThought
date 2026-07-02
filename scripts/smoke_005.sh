#!/usr/bin/env bash
# The feature-005 DISCLOSURE smoke, driven through the real CLI — DRAFT-ONLY.
#
# Proves the coordinated-disclosure DRAFTING pipeline end to end WITHOUT ever
# transmitting anything, WITHOUT advancing a finding to `disclosed`, and WITHOUT
# fabricating a CVE or advisory reference. From a VERIFIED finding, DISCLOSURE
# drafts four LOCAL artifacts (advisory, CSAF 2.0, OpenVEX, CVE 5.1 draft), writes
# them as session detail, and asserts the human gate. `publish --format all` then
# emits the same formats as a local bundle under the human gate. Sending is a
# human action performed outside this tool (Constitution Article V).
#
# Steps:
#   1. NEW PROJECT — an authorized source (basis + scope so the gate proceeds).
#   2. DISCOVER over the bundled SARIF -> candidate finding(s).
#   3. VERIFY (session API, Noop-backed reproducing) -> promote the SQL candidate
#      to verified THROUGH the lifecycle guard. Executes nothing (Noop seam).
#   4. DISCLOSE (CLI) -> draft four artifacts. Assert the session closes CLEAN,
#      the human gate is asserted, and the finding is STILL verified.
#   5. Assert the four drafts exist and each JSON draft validates; assert NO CVE
#      was assigned and NO advisory reference was added to the finding.
#   6. check -> green (drafts are schema-conformant).
#   7. publish --format all -> assert out/{,csaf,openvex,cve-draft,advisory}/ are
#      populated, the HUMAN GATE banner is printed, exit 0. Nothing transmitted.
#   8. Negative: corrupt state so check goes RED -> publish is REFUSED.
#
# Uses a throwaway state dir. Exits 0 on success.
#
# Usage:  ./scripts/smoke_005.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
DT="${ROOT}/.venv/bin/deepthought"
SAMPLE="${ROOT}/tests/fixtures/sample.sarif"
STATE="$(mktemp -d)/state"
OUT="$(mktemp -d)/out"
export DEEPTHOUGHT_STATE="$STATE"

# Self-heal a cold/stale editable install, then put the package source on
# PYTHONPATH so every invocation below imports deepthought reliably.
if ! "$PY" -c "import deepthought" >/dev/null 2>&1; then
  echo "self-heal: reinstalling editable deepthought (import failed on cold checkout)"
  uv pip install --python "${ROOT}/.venv" -e "${ROOT}[dev]" >/dev/null
fi
export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"

say() { printf '\n=== %s ===\n' "$1"; }

say "0. Feature 005 DISCLOSURE smoke — DRAFT-ONLY, nothing transmitted"
test -f "$SAMPLE"
echo "drafts advisory + CSAF + OpenVEX + CVE-draft locally; sending is a human act"

say "1. Register an authorized source project (basis + scope -> gate proceeds)"
"$PY" - "$STATE" <<'PY'
import sys
from deepthought.schema import Project
from deepthought.store import FileStore
store = FileStore(sys.argv[1])
store.save_project(Project.model_validate({
    "id": "src-proj", "name": "src-proj", "source_type": "open_source",
    "git_url": "https://example.test/src-proj",
    "authorization_basis": "permissive_oss", "scope_allowlist": ["app"], "status": "active",
}))
print("registered src-proj (authorized)")
PY

say "2. DISCOVER on the source over the bundled SARIF — seed candidate(s)"
"$DT" playbook discover --project src-proj --sarif "$SAMPLE"

FINDING="$("$PY" - "$STATE" <<'PY'
import sys
from deepthought.store import FileStore
store = FileStore(sys.argv[1])
cands = [f for f in store.list_findings(project="src-proj")
         if f.status.value == "candidate" and "sql" in f.summary.lower()]
assert cands, "DISCOVER seeded no SQL candidate"
print(cands[0].id)
PY
)"
echo "SQL candidate selected: ${FINDING}"

say "3. VERIFY (session API, Noop reproducing) — promote candidate -> verified"
"$PY" - "$STATE" "$FINDING" <<'PY'
import sys
from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.sandbox import NoopSandbox, SandboxPolicy, SandboxResult, SandboxSpec
from deepthought.sessions import VerifySession
from deepthought.store import FileStore

state, finding_id = sys.argv[1], sys.argv[2]
store = FileStore(state)
spec = SandboxSpec(
    image="ghcr.io/deepthought/repro-runner@sha256:" + "0" * 64,
    command=["/repro/run"], repro_ref="detail/seed/repro-01.bin", policy=SandboxPolicy(),
)
result = SandboxResult(exit_code=0, timed_out=False, wall_seconds=0.0, reproduced=True)
run_session(store, HermesUltraCodeGate(),
            VerifySession("src-proj", finding_id, spec=spec, sandbox=NoopSandbox(result)))
f = store.get_finding(finding_id)
assert f.status.value == "verified", f"expected verified, got {f.status.value!r}"
print(f"promoted {finding_id} candidate -> verified through the lifecycle guard")
PY

say "4. DISCLOSE (CLI) — draft four LOCAL artifacts; assert the human gate"
DISCLOSE_OUT="$("$DT" playbook disclose --project src-proj --finding "$FINDING")"
echo "$DISCLOSE_OUT"
echo "$DISCLOSE_OUT" | grep -q "close   : clean" || { echo "ERROR: disclose did not close clean" >&2; exit 1; }
echo "$DISCLOSE_OUT" | grep -q "HUMAN GATE" || { echo "ERROR: no human gate asserted" >&2; exit 1; }

say "5. Assert the four drafts exist + validate, and the finding is UNCHANGED"
"$PY" - "$STATE" "$FINDING" <<'PY'
import json, sys, pathlib
from deepthought.export.csaf import validate_csaf
from deepthought.export.openvex import validate_openvex
from deepthought.export.cve import validate_cve_draft
from deepthought.store import FileStore

state, finding_id = sys.argv[1], sys.argv[2]
detail = pathlib.Path(state) / "detail"
def find(name):
    hits = list(detail.glob(f"*/{name}"))
    assert hits, f"missing draft artifact {name}"
    return hits[0]

assert validate_csaf(json.loads(find("disclosure-csaf.json").read_text())) == []
assert validate_openvex(json.loads(find("disclosure-openvex.json").read_text())) == []
assert validate_cve_draft(json.loads(find("disclosure-cve-draft.json").read_text())) == []
advisory = find("disclosure-advisory.md").read_text()
assert advisory.startswith("# Advisory:") and "DRAFT" in advisory and "nothing transmitted" in advisory

# The CVE draft is deliberately non-submittable: its cveId fails the real pattern.
import re
cve = json.loads(find("disclosure-cve-draft.json").read_text())
assert not re.match(r"^CVE-[0-9]{4}-[0-9]{4,19}$", cve["cveMetadata"]["cveId"]), \
    "the CVE draft cveId must NOT be a submittable real CVE id"

# DRAFT-ONLY: the finding is untouched — still verified, no cve, no advisory ref.
store = FileStore(state)
f = store.get_finding(finding_id)
assert f.status.value == "verified", f"finding advanced to {f.status.value!r}"
assert f.cve is None, "a CVE was fabricated onto the finding"
assert not f.has_reference_type("advisory"), "an advisory reference was fabricated"
print("four drafts validate; cveId is non-submittable; finding still verified, no CVE, no advisory ref")
PY

say "6. check — green on the drafted state"
"$DT" check

say "7. publish --format all — local bundle under the HUMAN GATE, nothing transmitted"
PUB_OUT="$("$DT" publish --format all --out "$OUT")"
echo "$PUB_OUT"
echo "$PUB_OUT" | grep -q "HUMAN GATE" || { echo "ERROR: publish did not assert the human gate" >&2; exit 1; }
STEM="$("$PY" - "$STATE" "$FINDING" <<'PY'
import sys
from deepthought.export.osv import osv_id_for
print(osv_id_for(sys.argv[2]))
PY
)"
test -f "$OUT/${STEM}.json"            || { echo "ERROR: missing OSV artifact" >&2; exit 1; }
test -f "$OUT/csaf/${STEM}.json"       || { echo "ERROR: missing CSAF artifact" >&2; exit 1; }
test -f "$OUT/openvex/${STEM}.json"    || { echo "ERROR: missing OpenVEX artifact" >&2; exit 1; }
test -f "$OUT/cve-draft/${STEM}.json"  || { echo "ERROR: missing CVE-draft artifact" >&2; exit 1; }
test -f "$OUT/advisory/${STEM}.md"     || { echo "ERROR: missing advisory artifact" >&2; exit 1; }
echo "publish wrote OSV + csaf/openvex/cve-draft/advisory locally under ${OUT}/"

say "8. Negative: a red check must REFUSE publish"
"$PY" - "$STATE" "$FINDING" <<'PY'
import sys
from deepthought.schema import FindingStatus
from deepthought.store import FileStore
state, finding_id = sys.argv[1], sys.argv[2]
store = FileStore(state)
f = store.get_finding(finding_id)
f.status = FindingStatus.disclosed   # disclosed with no cve/advisory ref -> illegal at rest
store.save_finding(f)
print(f"corrupted {finding_id} into a lifecycle-illegal (disclosed, no cve) state")
PY
if "$DT" publish --format all --out "$OUT" 2>/dev/null; then
  echo "ERROR: publish succeeded on a red check" >&2
  exit 1
fi
echo "publish correctly REFUSED on a red check"

say "9. Acceptance summary"
echo "NOTHING transmitted: DISCLOSURE and publish emit LOCAL artifacts only."
echo "NO finding advanced to disclosed by the session; NO CVE or advisory ref fabricated."
echo "Four schema-conformant drafts produced; the CVE draft is non-submittable by design."
echo "publish              : bundle emitted under the human gate; REFUSED on a red check"

say "smoke_005 complete — state at $STATE, bundle at $OUT"
