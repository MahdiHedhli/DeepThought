# CLAUDE.md — DeepThought

See [`AGENTS.md`](AGENTS.md) for orientation and the shared, harness-agnostic protocol —
this project keeps one set of agent instructions for every model.

## Memory

DeepThought's memory is a **portable Obsidian-style vault at `memory/vault/`** (gitignored;
mechanism in `memory/`, committed). It replaces any harness-private memory location so Claude
Code, Codex, and any other agent compound into the SAME memory.

- **At session start:** `python3 memory/mem.py backup`, read `memory/vault/MEMORY.md`, then
  recall **scoped** — `recall --class methodology` (always-load) + `recall --class <attack> --tag
  <surface>` — instead of loading the whole notebook.
- **Record durable facts** per [`memory/AGENTS.md`](memory/AGENTS.md) via `python3 memory/mem.py
  add` (or by editing markdown + `mem.py index`). Notes are typed
  `user|feedback|lesson|project|reference`; a `lesson` also carries `class` + `tags` for scoped
  recall. Writes are atomic and auto-backed-up; `mem.py restore` recovers from corruption.

To make Claude Code's native per-project memory feature use this shared vault too (optional,
local-only), symlink it:
`ln -sfn "$(pwd)/memory/vault" ~/.claude/projects/-Users-mhedhli-Documents-Coding-DeepThought/memory`
