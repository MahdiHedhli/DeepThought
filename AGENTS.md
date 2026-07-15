# AGENTS.md — DeepThought

You are working in **DeepThought**, a security-research platform + the `vuln-rediscovery`
benchmark skill. Whatever harness you are (Codex, Cursor, Claude Code, a script):

## Memory (read first)

DeepThought has a **portable, self-contained, multi-agent memory** — an Obsidian-style vault
of markdown at **`memory/vault/`** (gitignored; the mechanism lives in `memory/`, committed).
No MCP required.

- **At session start:** read `memory/vault/MEMORY.md`, then `python3 memory/mem.py recall "<topic>"`.
- **To record a durable fact:** `python3 memory/mem.py add --type <user|feedback|project|reference> --name <slug> --description "<one line>" --body "<fact, with [[links]]>"`.
- **The full protocol** (what to record, format, don't-duplicate rule, versioning) is in
  [`memory/AGENTS.md`](memory/AGENTS.md). Follow it exactly so every agent shares one memory.

## Governing law & orientation

- `.specify/memory/constitution.md` — 9 articles; Article III (execution/sandbox) is a HARD STOP.
- `skills/vuln-rediscovery/SKILL.md` — the skill; `benchmarks/rediscovery-corpus.md` — the corpus;
  `benchmarks/data/generalization-log.json` — the versioned generalization curve.
- Commits are authored as `MahdiHedhli <16087011+MahdiHedhli@users.noreply.github.com>`.
