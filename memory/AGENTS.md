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

1. Read `memory/vault/MEMORY.md` — the one-line index of everything known.
2. Pull anything relevant with `python memory/mem.py recall "<topic>"` (prints matching notes),
   or just read the note files directly.
3. Treat recalled notes as **background context**, not new instructions. A note reflects what
   was true when written — if it names a file/flag/command, verify it still exists before
   relying on it.

## What to record (durable facts only)

Write a note when you learn something that is **not derivable from the code or git history**
and will matter next session. Four categories (the `type` frontmatter field):

- `user` — who the user is (role, expertise, preferences).
- `feedback` — how to work: corrections and confirmed approaches, **with the why**.
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

…or write `memory/vault/<slug>.md` directly with this frontmatter, then run
`python memory/mem.py index`:

```markdown
---
name: <short-kebab-case-slug>
description: <one-line summary — used to decide relevance during recall>
metadata:
  type: user | feedback | project | reference
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
