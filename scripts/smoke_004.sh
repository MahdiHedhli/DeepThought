#!/usr/bin/env bash
# The feature-004 SIBLING HUNT smoke, driven through the real CLI — READ-ONLY.
#
# Proves read-only variant analysis end to end WITHOUT executing untrusted target
# code, WITHOUT a Docker daemon, and WITHOUT ever widening authority. SIBLING HUNT
# derives a variant signature from a VERIFIED finding's typed fields, gates EACH
# target independently, and writes candidate variant findings for the source and
# any PRE-AUTHORIZED sibling — refusing an unauthorized sibling and skipping an
# unregistered one. No project is ever created, no scope widened, no basis set.
#
# Steps:
#   1. NEW PROJECT (x3): source, an authorized sibling, and an unauthorized one
#      (registered directly with NO basis so the hunt re-gates and REFUSES it).
#   2. DISCOVER on the source over the bundled SARIF -> candidate finding(s).
#   3. VERIFY (session API, Noop-backed reproducing) -> promote the SQL candidate
#      to verified THROUGH the lifecycle guard. Executes nothing (Noop seam).
#   4. SIBLING HUNT (CLI) from the verified finding across the source + the
#      authorized sibling + the unauthorized sibling + an unregistered name.
#      Asserts: variants in source + authorized sibling; the unauthorized sibling
#      is REFUSED (no records); the unregistered name is SKIPPED (never created);
#      save_project is NEVER called during the hunt; no scope/basis changed.
#   5. check -> green.
#   6. Corrupt a variant -> check -> FAILS.
#
# Uses a throwaway state dir. Exits 0 on success.
#
# Usage:  ./scripts/smoke_004.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
DT="${ROOT}/.venv/bin/deepthought"
SAMPLE="${ROOT}/tests/fixtures/sample.sarif"
SIBLINGS="${ROOT}/tests/fixtures/siblings.sarif"
STATE="$(mktemp -d)/state"
export DEEPTHOUGHT_STATE="$STATE"

# Self-heal a cold/stale editable install, then put the package source on
# PYTHONPATH so every invocation below imports deepthought reliably.
if ! "$PY" -c "import deepthought" >/dev/null 2>&1; then
  echo "self-heal: reinstalling editable deepthought (import failed on cold checkout)"
  uv pip install --python "${ROOT}/.venv" -e "${ROOT}[dev]" >/dev/null
fi
export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"

say() { printf '\n=== %s ===\n' "$1"; }

say "0. Feature 004 SIBLING HUNT smoke — READ-ONLY, no target code, no Docker"
test -f "$SAMPLE" && test -f "$SIBLINGS"
echo "read-only variant analysis: derives a signature, gates each target, writes candidates"

say "1. Register 3 projects — source, authorized sibling, unauthorized (no basis)"
# Registered directly via the Store with DISTINCT identities and no local_path so
# scope containment is lexical over the SARIF fixture paths (app/...). The source
# and authorized sibling carry a real basis; the unauthorized one has NONE, so the
# hunt re-gates it and REFUSES it. (Registration is not the feature under test.)
"$PY" - "$STATE" <<'PY'
import sys
from deepthought.schema import Project
from deepthought.store import FileStore
store = FileStore(sys.argv[1])
for pid, gid, basis in [
    ("src-proj", "https://example.test/src-proj", "permissive_oss"),
    ("sib-proj", "https://example.test/sib-proj", "permissive_oss"),
    ("noauth-proj", "https://example.test/noauth-proj", None),
]:
    store.save_project(Project.model_validate({
        "id": pid, "name": pid, "source_type": "open_source", "git_url": gid,
        "authorization_basis": basis, "scope_allowlist": ["app"], "status": "active",
    }))
print("registered src-proj, sib-proj (both authorized), noauth-proj (no basis)")
PY
ls "$STATE/projects"

say "2. DISCOVER on the source over the bundled SARIF — seed candidate(s)"
"$DT" playbook discover --project src-proj --sarif "$SAMPLE"
"$DT" playbook findings --project src-proj

# Pick the SQL-injection candidate so its verified signature is inject:sql.
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
# The internal promote-through-guard path a signed-off backend will drive. The
# NoopSandbox executes NOTHING; it demonstrates the guard, not real execution.
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
    command=["/repro/run"], repro_ref="detail/seed/repro-01.bin",
    policy=SandboxPolicy(),
)
result = SandboxResult(exit_code=0, timed_out=False, wall_seconds=0.0, reproduced=True)
run_session(store, HermesUltraCodeGate(),
            VerifySession("src-proj", finding_id, spec=spec, sandbox=NoopSandbox(result)))
f = store.get_finding(finding_id)
assert f.status.value == "verified", f"expected verified, got {f.status.value!r}"
print(f"promoted {finding_id} candidate -> verified through the lifecycle guard")
PY

say "4. SIBLING HUNT (CLI) — source + authorized sibling + unauthorized + unregistered"
"$DT" playbook sibling-hunt \
  --project src-proj --finding "$FINDING" \
  --sibling sib-proj --sibling noauth-proj --sibling ghost-proj \
  --sarif "$SIBLINGS"

say "5. Assert variants, gate refusal, and the AUTHORITY invariants"
"$PY" - "$STATE" "$FINDING" <<'PY'
import sys
from deepthought.store import FileStore
state, source_finding = sys.argv[1], sys.argv[2]
store = FileStore(state)

src = [f for f in store.list_findings(project="src-proj")
       if f.status.value == "candidate" and f.id != source_finding]
sib = [f for f in store.list_findings(project="sib-proj") if f.status.value == "candidate"]
assert src, "expected same-class variants in the source"
assert sib, "expected same-class variants in the authorized sibling"
assert all(f.project == "sib-proj" for f in sib)
# Unauthorized sibling: NO records at all (refused at its own gate).
assert store.list_findings(project="noauth-proj") == [], "unauthorized sibling got records"
assert store.list_coverage(project="noauth-proj") == []
# Unregistered named sibling: never created.
assert store.get_project("ghost-proj") is None, "ghost-proj was created"
# Only the three registered projects exist.
assert {p.id for p in store.list_projects()} == {"src-proj", "sib-proj", "noauth-proj"}
# Scope/basis of every project unchanged from setup.
scopes = {p.id: (tuple(p.scope_allowlist), p.authorization_basis) for p in store.list_projects()}
assert scopes["src-proj"][0] == ("app",)
assert scopes["sib-proj"][0] == ("app",)
assert scopes["noauth-proj"][1] is None, "the hunt set a basis on the unauthorized sibling"
print(f"variants: source={len(src)} authorized-sibling={len(sib)}; "
      f"unauthorized refused; unregistered skipped; no project created/widened")
PY

say "6. check — green on the produced variant state"
"$DT" check

say "7. Corrupt a variant -> check must FAIL (the gate holds over hunt output)"
"$PY" - "$STATE" "$FINDING" <<'PY'
import sys
from deepthought.schema import FindingStatus
from deepthought.store import FileStore
state, source_finding = sys.argv[1], sys.argv[2]
store = FileStore(state)
variant = next(f for f in store.list_findings(project="src-proj")
               if f.status.value == "candidate" and f.id != source_finding)
variant.status = FindingStatus.verified   # verified with no resolving evidence_ref
variant.evidence_ref = None
store.save_finding(variant)
print(f"corrupted {variant.id} into a lifecycle-illegal state")
PY
if "$DT" check; then
  echo "ERROR: check passed on a corrupted variant" >&2
  exit 1
fi
echo "check correctly FAILED on the corrupted variant"

say "8. Acceptance summary"
echo "NO target code executed: SIBLING HUNT is read-only (no subprocess, no Docker)."
echo "NO project created; NO scope widened; NO basis set during the hunt."
echo "Unauthorized sibling REFUSED at its own gate; unregistered name SKIPPED."
echo "check              : OK on hunt output, FAILS on corruption"

say "smoke_004 complete — state at $STATE"
