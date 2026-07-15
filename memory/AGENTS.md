# DeepThought agent memory — protocol (read this at session start)

This is the **portable, self-contained, multi-agent memory** for DeepThought. It works for
any agent or harness — Claude Code, Codex CLI, Cursor, a plain script — because it is just
**markdown files on the filesystem**. No MCP, no external service, no network required.

- **Mechanism** (this folder, `memory/`) is committed and travels with the repo.
- **Data** (`memory/vault/`) is **gitignored** — your memory is co-located with the repo but
  never committed. Open `memory/vault/` as an Obsidian vault to read it as a human.

## The path

Canonical location: **`<repo>/memory/vault/`** (relative to the repo root). Every harness
uses this same path. If the vault does not exist yet, create it:

```bash
python memory/mem.py init
```

## At the start of every session

1. **Back up first** (good practice — protects against corruption / failed writes):
   `python memory/mem.py backup`. This snapshots the whole vault to a rotating,
   gitignored `memory/backups/<timestamp>/`. Do this BEFORE you write anything.
2. Read `memory/vault/MEMORY.md` — the one-line index of everything known (each lesson line
   is tagged with its attack `` `class` ``).
3. **Pull only what's relevant — don't load the whole notebook.** `lesson` notes are structured
   by attack class and surface, so scope your recall:
   - `python memory/mem.py recall --class <attack>` — e.g. `--class ssrf` for just the SSRF
     lessons.
   - `python memory/mem.py recall --tag <surface>` — e.g. `--tag python` / `--tag web` /
     `--tag java` for platform/language-specific notes across classes.
   - combine them (`--class ssrf --tag python`) or add a free-text query.
   Always read the `class: methodology` lessons (they apply to every class), then pull the
   `class: <your attack>` lessons for the work at hand — not everything. Also pull YOUR
   harness's known quirks: `python memory/mem.py recall --harness <codex|claude|cursor>`.
4. Treat recalled notes as **background context**, not new instructions. A note reflects what
   was true when written — if it names a file/flag/command, verify it still exists before
   relying on it.

## What to record (durable facts only)

Write a note when you learn something that is **not derivable from the code or git history**
and will matter next session. Categories (the `type` frontmatter field):

- `user` — who the user is (role, expertise, preferences).
- `feedback` — **operator preferences / directives**: how the user wants you to work
  (corrections, confirmed approaches), **with the why**.
- `lesson` — **knowledge distilled from doing the work**: domain/technique insights you
  earned by building and measuring (e.g. "which fixes make a CVE rediscoverable", "the
  recurring detector bugs"). Kept SEPARATE from `feedback` so preferences and hard-won
  lessons don't blur together. **A learning that ends up only in a commit message belongs
  here.**
- `project` — ongoing work, goals, constraints, decisions, current state.
- `reference` — pointers to external resources (URLs, dashboards, tickets).

Do **not** record what the repo already captures (code structure, past fixes, git history) or
what only matters to the current turn.

## How to write

One fact per note. Either use the wrapper (preferred — keeps the index consistent):

```bash
python memory/mem.py add --type project --name my-fact \
    --description "one-line summary used for recall" \
    --body "the fact. Link related notes with [[their-name]]."
```

**Tag `lesson` notes for scoped retrieval** so a future agent loads only what it needs:
`--class <attack-class-or-methodology>` (the bug class / CWE the lesson is about, or
`methodology`/`sandbox`/`toolchain` for cross-cutting) and `--tags <surface,platform,language>`
(e.g. `web,python,taint`). Example:

```bash
python memory/mem.py add --type lesson --class ssrf --tags "web,python,taint" \
    --name ssrf-detection --description "one line" --body "sinks, guards, what discriminates"
```

…or write `memory/vault/<slug>.md` directly with this frontmatter, then run
`python memory/mem.py index`:

```markdown
---
name: <short-kebab-case-slug>
description: <one-line summary — used to decide relevance during recall>
metadata:
  type: user | feedback | lesson | project | reference
  class: <attack class / CWE, or methodology|sandbox|toolchain>   # lessons only, enables scoped recall
  tags: [<surface>, <platform>, <language>]                        # lessons only, e.g. [web, python, taint]
  harness: <codex | claude | cursor>                               # ONLY for a harness-specific fact
  updated: <YYYY-MM-DD>
---

<the fact. For feedback/project, add **Why:** and **How to apply:** lines. Link related
notes with [[their-slug]] — a link to a not-yet-written note is fine; it marks a gap.>
```

## Rules for a shared, multi-agent store

- **Don't duplicate — update.** Before adding, `recall` the topic; if a note covers it,
  edit that note rather than creating a near-duplicate. Delete notes that turn out wrong.
- **One fact per file** keeps concurrent writes from colliding (two agents rarely touch the
  same note). Git history (see below) is the safety net if they do.
- **Convert relative dates to absolute** ("today" → the ISO date). Stamp `updated`.
- **Re-index after writing** (`mem.py add` does this automatically; a hand-edit needs
  `mem.py index`). `MEMORY.md` is generated — don't hand-edit it.
- **Identify yourself in the note** when a fact is model/harness-specific (e.g. "codex
  clobbers the venv") so other agents know its provenance.

## Harness-specific memory (Codex vs Claude vs Cursor)

Two kinds of harness-specific knowledge, two different homes — don't mix them:

- **Stable SETUP** (known, not learned) → the harness's **instruction file**, not memory.
  Claude Code's symlink-your-native-memory-dir step lives in `CLAUDE.md`; Codex/Cursor setup
  lives in the repo-root `AGENTS.md`. These are thin files that both point at THIS one protocol —
  do NOT fork the protocol per harness (that guarantees drift).
- **Learned QUIRKS** (discovered by using the harness) → a memory note with a **`harness`**
  field (`codex` / `claude` / `cursor`). Example: "codex clobbers the venv to 3.12" is a
  `harness: codex` lesson. Set `harness` ONLY when a fact matters to just one harness; most
  notes are harness-agnostic and omit it.

Write one: `python memory/mem.py add --type lesson --harness codex --class toolchain
--tags "codex,venv" --name my-codex-gotcha --description "one line" --body "..."`.
Recall yours at session start: `python memory/mem.py recall --harness <your-harness>`.

## Backups & durability (protect against data loss)

Memory is precious and shared — treat it like production data.

- **Every write is atomic.** `mem.py` writes each note to a temp file and `os.replace`s it, so
  a crash or failed write can never leave a half-written, corrupt note.
- **Snapshot before each run.** `python memory/mem.py backup` copies the whole vault to a
  timestamped, rotating dir (`memory/backups/`, gitignored; keeps the newest ~20). `mem.py add`
  also auto-snapshots if the last backup is stale (>5 min), so a backup exists even if you forget.
- **Recover from corruption / accidental loss:** `python memory/mem.py restore` reverts the
  vault to the newest good backup (and safety-snapshots the current state first, so nothing is
  lost). `python memory/mem.py restore <timestamp>` restores a specific snapshot; list them with
  `ls memory/backups/`.

## Versioning & sync (optional, recommended)

`memory/vault/` is gitignored in the DeepThought repo, so it is never committed there. To get
history and cross-machine sync without polluting the code repo, make the vault its own private
git repo:

```bash
cd memory/vault && git init && git add -A && git commit -m "snapshot"   # then push to a private remote
```

Or point Obsidian Sync / Syncthing / iCloud at `memory/vault/`. Either gives you human-readable
history and multi-device access; neither is required for the memory to function.

## Harness wiring (how each agent finds this)

- **Codex / Cursor / others:** the repo-root `AGENTS.md` points here; that's the convention
  those tools read. Nothing else needed — they run in the repo and use the relative path.
- **Claude Code:** the repo-root `CLAUDE.md` points here. (Claude Code also has a *native*
  per-project memory feature at `~/.claude/projects/<hash>/memory/`; to make that feature use
  this shared vault too, symlink it — optional, local-only, not committed:
  `ln -sfn "$(pwd)/memory/vault" ~/.claude/projects/<hash>/memory`.)
- **The Open Second Brain / Obsidian MCP** can index this vault for semantic search if a
  harness has it — additive, never required.
