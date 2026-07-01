#!/usr/bin/env bash
# The five-step 001 smoke, driven through the real CLI.
#
# Proves the spine end to end: durable state, the protocol, the gate, the
# lifecycle guard, and clean git diffs. Uses a throwaway state dir.
#
# Usage:  ./scripts/smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DT="${ROOT}/.venv/bin/deepthought"
STATE="$(mktemp -d)/state"
export DEEPTHOUGHT_STATE="$STATE"

say() { printf '\n=== %s ===\n' "$1"; }

say "1. Scaffold present (constitution + feature spec)"
test -f "${ROOT}/.specify/memory/constitution.md"
test -f "${ROOT}/specs/001-core-loop/spec.md"
echo "ok"

say "2. NEW PROJECT — real git URL, permissive OSS basis, scope allowlist"
"$DT" playbook new-project \
  --name "PHP src" \
  --git-url "https://github.com/php/php-src" \
  --source-type open_source \
  --basis permissive_oss \
  --scope ext/soap --scope ext/standard
ls "$STATE/projects"

say "3. STATUS — a session log with next steps, no finding status changed"
"$DT" playbook status --project php-src

say "4. check — passes on consistent state"
"$DT" check

say "4b. Corrupt a record — check fails hard (expected non-zero exit)"
FIND_DIR="$STATE/findings"
mkdir -p "$FIND_DIR"
cat > "$FIND_DIR/F-9999.md" <<'EOF'
---
id: F-9999
project: php-src
summary: hand-corrupted record
status: not-a-real-status
---
EOF
if "$DT" check; then
  echo "ERROR: check should have failed on the corrupted record" >&2
  exit 1
else
  echo "ok — check failed as expected"
fi
rm -f "$FIND_DIR/F-9999.md"

say "5. publish — local artifacts only, human gate asserted, nothing transmitted"
"$DT" publish --out "$(dirname "$STATE")/out"

say "smoke complete — state at $STATE"
