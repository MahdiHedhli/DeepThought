# AGENTS.md — DeepThought

You are working in **DeepThought**, a security-research platform + the `vuln-rediscovery`
benchmark skill. Whatever harness you are (Codex, Cursor, Claude Code, a script):

## Memory (read first)

DeepThought has a **portable, self-contained, multi-agent memory** — an Obsidian-style vault
of markdown at **`memory/vault/`** (gitignored; the mechanism lives in `memory/`, committed).
No MCP required.

- **At session start:** back up (`python3 memory/mem.py backup`), read `memory/vault/MEMORY.md`,
  then recall **scoped** so you don't load the whole notebook —
  `python3 memory/mem.py recall --class methodology` (the always-load core) plus
  `python3 memory/mem.py recall --class <attack> --tag <surface>` for the work at hand
  (e.g. `--class ssrf --tag python`).
- **To record a durable fact:** `python3 memory/mem.py add --type <user|feedback|lesson|project|reference> --name <slug> --description "<one line>" --body "<fact, with [[links]]>"`.
  A `lesson` (knowledge earned by doing the work — a learning that would otherwise live only in
  a commit message) also takes `--class <attack-class|methodology|sandbox|toolchain>` and
  `--tags <surface,platform,language>` so future agents can recall it by class/surface.
- **The full protocol** (categories, format, scoped recall, don't-duplicate rule, backups,
  versioning) is in [`memory/AGENTS.md`](memory/AGENTS.md). Follow it exactly so every agent
  shares — and compounds — one memory.

## Governing law & orientation

- `.specify/memory/constitution.md` — 9 articles; Article III (execution/sandbox) is a HARD STOP.
- `skills/vuln-rediscovery/SKILL.md` — the skill; `benchmarks/rediscovery-corpus.md` — the corpus;
  `benchmarks/data/generalization-log.json` — the versioned generalization curve.
- Commits are authored as `MahdiHedhli <16087011+MahdiHedhli@users.noreply.github.com>`.
