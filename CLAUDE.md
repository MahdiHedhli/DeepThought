# CLAUDE.md — DeepThought

See [`AGENTS.md`](AGENTS.md) for orientation and the shared, harness-agnostic protocol —
this project keeps one set of agent instructions for every model.

## Memory

DeepThought's memory is a **portable Obsidian-style vault at `memory/vault/`** (gitignored;
mechanism in `memory/`, committed). Read `memory/vault/MEMORY.md` at session start and record
durable facts per [`memory/AGENTS.md`](memory/AGENTS.md) — via `python3 memory/mem.py` or by
editing the markdown directly. This replaces any harness-private memory location: point here so
Claude Code, Codex, and any other agent compound into the SAME memory.

To make Claude Code's native per-project memory feature use this shared vault too (optional,
local-only), symlink it:
`ln -sfn "$(pwd)/memory/vault" ~/.claude/projects/-Users-mhedhli-Documents-Coding-DeepThought/memory`
