# Build Session Log — Hardening: safe record ids & FileStore path/identity boundaries

> **STATUS: MERGED to `main` (PR #5, squash `40031de`, 2026-07-02).** The
> focused security follow-up the 005 review flagged: record ids were unconstrained,
> and the `FileStore` names every record file from the raw id — a genuine path
> traversal (`Finding.model_validate({'id':'../../pwned'})` was accepted, and
> `save_finding` wrote **two levels above the store root**). This closes the class
> at the source: a `RecordId` constrained type at the model boundary plus
> defence-in-depth at the `Store`. **513 tests green (500 baseline + 13 new); all
> five smokes pass.** Reviewed to a clean dual-gate (codex gpt-5.5 + agy/Gemini
> adversarial) on the same HEAD (`f42afc0`), over five review rounds.

**Change:** `hardening-safe-ids` (merged and deleted)
**Predecessor gate:** 005 merged to `main` (PR #4, squash `a99340f`).
**Merge:** PR #5, squash `40031de`, 2026-07-02 — dual-gate clean (codex + agy).

## What shipped

The root cause of a recurring 005-review class (pathological, model-valid finding
ids) was that `Finding.id` / `Project.id` were unconstrained strings used verbatim
as file names. The fix:

- **`RecordId` at the model boundary** (`schema/common.py`) —
  `^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`: a single safe path
  segment, ≤128 chars, no separators / `..` / whitespace / control /
  leading-trailing punctuation. Applied to `Finding.id`+`project`, `Project.id`,
  `Session.id`+`project`, `Coverage.project`, `Methodology.id`. A crafted id is
  rejected at construction **and** on-read. `is_record_id` / `safe_record_id`
  helpers are the single source of truth (predicate + coercion of a derived id).
- **FileStore path boundaries** — the `get_*` lookups and `list_coverage` guard
  the raw string arg (`fullmatch`, agreeing with the model); `_detail_path` keeps
  detail access inside the **canonical** `detail/` dir (lexical `detail/` prefix
  with no `..`, physical containment under `self.root.resolve()/"detail"` — so a
  `detail` dir symlinked outside the store / to an in-store sibling / to the root,
  or an inner symlink re-entering a sibling, is all rejected); `detail_exists`
  uses `is_file` so a directory ref can't satisfy the candidate→verified evidence
  gate.
- **Identity & input hardening** — `default_verify_git_url` refuses a leading-`-`
  url and uses a `--` terminator (git argument injection); `save_project` refuses
  a same-id/different-identity write (no silent overwrite); `derive_project_id`
  normalises via `safe_record_id`; the NEW PROJECT and non-NEW session entry
  points turn an unsafe operator-supplied id into a controlled refusal instead of
  a bare `ValidationError`.

## Review & merge (summary)

Five dual-gate rounds (codex CLI gpt-5.5 + agy/Gemini adversarial, both clean on
the same HEAD), **12 real defects found and fixed test-first**:

| Round | Findings (all real, all fixed test-first) |
|---|---|
| 1 | `_safe_id` newline bypass; `derive_project_id` emitting invalid ids; `list_coverage` raw-project traversal; `read_detail` escaping `detail/`. |
| 2 | git argument-injection (`default_verify_git_url`); `detail_exists` accepting a directory ref; `_detail_path` symlink-out; derived-id collision silently overwriting a project. |
| 3 | `_detail_path` symlink class made terminal (canonical detail anchor) — an inner symlink re-entering a sibling, and the `detail` dir itself symlinked to an in-store sibling / root. |
| 4 | agy CLEAN; codex: unsafe operator-supplied project id crashed at both CLI entry points (session `--project`, NEW PROJECT `--project-id`) → controlled refusal. |
| 5 | **codex CLEAN + agy CLEAN — consensus clean on the same HEAD.** |

Two round-2/3 findings were residuals of earlier fixes in this same change
(symlink containment, id-collision), caught and closed before merge. The symlink
guard is now provably terminal for the traversal/symlink class.

**Follow-up (tracked, not a defect):** a `RecordId`-tightening can make a
`FileStore` written by pre-`RecordId` code unreadable on strict read. This
strictness is intentional (an unsafe id is malformed by design). The shipped repo
ships no populated state (only `state/**/.gitkeep`), so impact is nil today; a
migration/repair path for legacy stores is a separate follow-up.
