# DeepThought portable agent memory

A **self-contained, human-readable, multi-agent memory** that travels with this repo.

- It is an **Obsidian-style vault of markdown notes** — open `memory/vault/` in Obsidian to
  read, search, and follow `[[wikilinks]]` as a human.
- It is **portable**: the mechanism (template, protocol, wrapper) lives in the repo, so any
  clone has it. No MCP, no external service, no network.
- Your actual notes (`memory/vault/`) are **gitignored** — memory is co-located with the repo
  but never committed to it.
- It is **harness-agnostic**: Claude Code, Codex CLI, Cursor, or a plain script all read and
  write the same markdown at the same path.

## Layout

```
memory/
  README.md        # this file (human overview)
  AGENTS.md        # the read/write PROTOCOL every agent follows — the important one
  mem.py           # a tiny, dependency-free CLI: init / add / index / recall / list
  template/        # the seed the vault is created from
  vault/           # <-- GITIGNORED. Your notes: MEMORY.md (index) + one .md per fact
```

## Quick start

```bash
python memory/mem.py init                          # create memory/vault/ from the template
python memory/mem.py backup                        # snapshot before writing (do this each session)
python memory/mem.py recall --class methodology    # scoped recall: the always-load core
python memory/mem.py recall --class ssrf --tag python   # only the relevant attack + surface slice
python memory/mem.py add --type lesson --class ssrf --tags "web,python,taint" \
    --name a-lesson --description "one line" --body "the fact, with [[links]]"
python memory/mem.py list                          # every note + its description
python memory/mem.py restore                        # revert to the newest backup (corruption recovery)
```

**Note types:** `user`, `feedback` (operator preferences), `lesson` (knowledge distilled from
the work — also carries `class` + `tags` for scoped recall), `project`, `reference`.

**Durability:** every write is atomic (temp-file + `os.replace`), the vault auto-snapshots
before mutation, and `backup`/`restore` give rotating, gitignored history — so a failed write
or corruption never loses your memory.

See [`AGENTS.md`](AGENTS.md) for the full protocol (what to record, format, the
don't-duplicate rule, and optional git/Obsidian versioning).
