# Codex: smoke-test the DeepThought agent memory (BEFORE the 20-CVE run)

You are validating DeepThought's portable agent memory from **your** harness (Codex), to confirm
it works before the 20-CVE run. **Do NOT start any CVE / detector work.** This is a memory
dry-run only. **Do NOT commit anything** (the vault is gitignored on purpose). Touch only a
clearly-named throwaway note and clean it up at the end — leave every real note intact.

Working dir: `/Users/mhedhli/Documents/Coding/DeepThought`. The memory protocol is
`memory/AGENTS.md`; the CLI is `memory/mem.py` (dependency-free, stdlib). Use `python3` (fall
back to `python` if `python3` is absent — note which worked).

Run the checklist in order and record PASS/FAIL + the actual result for each. Expected results
assume Claude has already populated the shared vault.

## 0. Baseline (so you can prove nothing real was lost)
- `python3 memory/mem.py list` — record the exact note count and names. Call this BASELINE.
- `git status --porcelain` — record it (should have no *staged/modified tracked* memory files).

## 1. Environment + shared vault (cross-harness memory works)
- `python3 memory/mem.py --help` (or `... recall`) runs without error.
- `python3 memory/mem.py recall` (no args) prints the **index** (`MEMORY.md`) only — NOT every
  note body. PASS = you see the three sections "How to work (operator preferences)", "Distilled
  lessons (learned from the work)", "Project state & decisions".
- Confirm you can read notes Claude wrote (shared memory): the index lists lessons such as
  `vuln-rediscovery-what-generalizes`, `honest-measurement-methodology`, `ssrf-detection`,
  `command-injection-detection`, `codex-clobbers-venv`. PASS = present.

## 2. Scoped recall (the context-efficiency feature — pull only what's relevant)
- `python3 memory/mem.py recall --class methodology` — returns ONLY the ~5 methodology lessons
  (the always-load core), not the whole vault.
- `python3 memory/mem.py recall --class ssrf` — returns ONLY `ssrf-detection`.
- `python3 memory/mem.py recall --tag python` — returns the Python-surface notes across classes
  (ssrf/xxe/command-injection detection), NOT the JS-only ones.
- `python3 memory/mem.py recall --class ssrf --tag python` — the intersection.
PASS = each filter narrows the set as described (scoped recall works, so you never have to load
the entire notebook).

## 3. Backup (durability before writing)
- `python3 memory/mem.py backup` — prints a snapshot path under `memory/backups/<timestamp>/`.
- Confirm it is gitignored: `git check-ignore memory/backups` prints the path.
PASS = snapshot created and ignored.

## 4. Add + index + retrieve (write path, with classification)
- Add a THROWAWAY lesson:
  `python3 memory/mem.py add --type lesson --class test-smoke --tags "test,codex" --name test-memory-smoke --description "codex memory smoke test — safe to delete" --body "written by Codex to validate the memory system. [[honest-measurement-methodology]]"`
- Verify it was written + indexed: `python3 memory/mem.py list` shows `test-memory-smoke`, and
  `memory/vault/MEMORY.md` now lists it under "Distilled lessons" annotated with `` `test-smoke` ``.
- Verify scoped retrieval finds exactly it: `python3 memory/mem.py recall --class test-smoke`
  returns ONLY `test-memory-smoke`; `... recall --tag codex` includes it.
- Verify atomic writes left no temp junk: `ls memory/vault/*.tmp-* 2>/dev/null` returns nothing.
PASS = written, class-labeled in the index, retrievable by class and tag, no temp files.

## 5. Restore (corruption recovery)
- Snapshot the current state (now including the test note): `python3 memory/mem.py backup`.
- Corrupt the test note: append a garbage line to `memory/vault/test-memory-smoke.md`.
- `python3 memory/mem.py restore` — reverts the vault to the newest good snapshot.
- Confirm the corruption is gone (the garbage line is no longer in the file) and the note is
  back to its clean content.
PASS = restore reverted the corruption; the safety-snapshot of the corrupt state also exists in
`memory/backups/` (nothing is destroyed by restore).

## 6. Cleanup (leave the real vault exactly as you found it)
- Delete the throwaway note: `rm memory/vault/test-memory-smoke.md` then
  `python3 memory/mem.py index`.
- `python3 memory/mem.py list` — the note count and names must equal BASELINE from step 0
  (every real note intact; the test note gone).
- `git status --porcelain` — must equal step 0 (no memory data staged; vault/backups gitignored).
- (Optional) the extra backup snapshots you created are gitignored and rotate automatically;
  you may leave them.

## Report
Return a PASS/FAIL table for checks 1–6 with the actual result of each, which Python invocation
worked, and any deviation from the expected result. End with an explicit **GO / NO-GO** for
kicking off the 20-CVE run, and — if anything failed — the smallest fix needed. If everything
passes, also confirm in one line that scoped recall (`--class`/`--tag`) meaningfully reduces the
context you'd load per class (the reason the classification exists).

Guardrails (repeat): no CVE/detector work in this run; no commits; only the `test-memory-smoke`
note is created/edited/deleted; every real note must survive unchanged.
