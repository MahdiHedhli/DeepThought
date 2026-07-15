#!/usr/bin/env python3
"""mem.py — a tiny, dependency-free wrapper for DeepThought's portable agent memory.

The memory is a self-contained Obsidian-style vault of markdown notes that travels WITH
this repo but is NOT committed (the ``memory/vault/`` data folder is gitignored). Any
agent or harness (Claude Code, Codex, Cursor, a plain script) reads and writes it through
the filesystem — no MCP, no external service. This wrapper just makes the common
operations consistent; agents may also edit the markdown directly per ``memory/AGENTS.md``.

Usage:
  python memory/mem.py init                         # create memory/vault/ from the template
  python memory/mem.py add --type project \\
      --name my-fact --description "one line" \\
      --body "the fact body, may use [[links]]"     # write a note + refresh the index
  python memory/mem.py index                        # rebuild MEMORY.md from the notes
  python memory/mem.py recall [query]               # print notes matching a query (or the index)
  python memory/mem.py list                         # list every note + its description

Notes are plain markdown with YAML-ish frontmatter (name, description, type). One fact per
file. See memory/AGENTS.md for the read/write protocol every agent follows.
"""
from __future__ import annotations

import argparse
import datetime
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent          # memory/
VAULT = ROOT / "vault"                           # gitignored data
TEMPLATE = ROOT / "template"
INDEX = "MEMORY.md"
TYPES = ("user", "feedback", "project", "reference")


def _fm(text: str) -> dict:
    """Parse the leading YAML-ish frontmatter block into a flat dict (name/description/type)."""
    out: dict = {}
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if not m:
        return out
    for line in m.group(1).splitlines():
        km = re.match(r"^\s*([A-Za-z_]+):\s*(.*)$", line)
        if km and km.group(2):
            out[km.group(1)] = km.group(2).strip()
    return out


def _notes() -> list[Path]:
    return sorted(p for p in VAULT.glob("*.md") if p.name != INDEX)


def cmd_init() -> int:
    if VAULT.exists():
        print(f"vault already exists: {VAULT}")
        return 0
    VAULT.mkdir(parents=True, exist_ok=True)
    tpl_index = TEMPLATE / INDEX
    (VAULT / INDEX).write_text(tpl_index.read_text() if tpl_index.exists() else "# Memory index\n",
                               encoding="utf-8")
    print(f"initialized vault: {VAULT}")
    return 0


def cmd_add(args) -> int:
    if args.type not in TYPES:
        print(f"--type must be one of {TYPES}", file=sys.stderr)
        return 2
    VAULT.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9-]+", "-", args.name.lower()).strip("-")
    body = args.body
    if args.body_file:
        body = sys.stdin.read() if args.body_file == "-" else Path(args.body_file).read_text(encoding="utf-8")
    date = args.date or datetime.date.today().isoformat()
    note = (
        f"---\nname: {slug}\ndescription: {args.description}\n"
        f"metadata:\n  type: {args.type}\n  updated: {date}\n---\n\n{body.rstrip()}\n"
    )
    path = VAULT / f"{slug}.md"
    existed = path.exists()
    path.write_text(note, encoding="utf-8")
    cmd_index(quiet=True)
    print(f"{'updated' if existed else 'wrote'} {path.relative_to(ROOT.parent)} + reindexed")
    return 0


def cmd_index(quiet: bool = False) -> int:
    if not VAULT.exists():
        print("no vault; run: python memory/mem.py init", file=sys.stderr)
        return 1
    by_type: dict[str, list[str]] = {t: [] for t in TYPES}
    for p in _notes():
        fm = _fm(p.read_text(encoding="utf-8"))
        t = fm.get("type") or (fm.get("metadata") and "") or "reference"
        # type may live under metadata: parse the nested form too
        if t not in TYPES:
            mt = re.search(r"type:\s*(\w+)", p.read_text(encoding="utf-8"))
            t = mt.group(1) if mt and mt.group(1) in TYPES else "reference"
        desc = fm.get("description", "")
        by_type.setdefault(t, []).append(f"- [{fm.get('name', p.stem)}]({p.name}) — {desc}")
    lines = ["# Memory index", "",
             "_DeepThought portable agent memory. One fact per note; this index is generated "
             "by `python memory/mem.py index`. See [AGENTS.md](../AGENTS.md) for the protocol._", ""]
    titles = {"user": "Who the user is", "feedback": "How to work (feedback)",
              "project": "Project state & decisions", "reference": "References"}
    for t in TYPES:
        if by_type.get(t):
            lines += [f"## {titles[t]}", *sorted(by_type[t]), ""]
    (VAULT / INDEX).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    if not quiet:
        print(f"indexed {sum(len(v) for v in by_type.values())} notes -> {VAULT / INDEX}")
    return 0


def cmd_recall(args) -> int:
    if not VAULT.exists():
        print("no vault; run: python memory/mem.py init", file=sys.stderr)
        return 1
    q = (args.query or "").lower()
    if not q:
        print((VAULT / INDEX).read_text(encoding="utf-8") if (VAULT / INDEX).exists() else "(empty)")
        return 0
    hits = 0
    for p in _notes():
        text = p.read_text(encoding="utf-8")
        if q in text.lower() or q in p.stem.lower():
            print(f"\n===== {p.name} =====\n{text.rstrip()}")
            hits += 1
    if not hits:
        print(f"no notes match {args.query!r}")
    return 0


def cmd_list(_args) -> int:
    if not VAULT.exists():
        print("no vault; run: python memory/mem.py init", file=sys.stderr)
        return 1
    for p in _notes():
        fm = _fm(p.read_text(encoding="utf-8"))
        print(f"{p.stem:32} {fm.get('description', '')}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="DeepThought portable agent memory")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    a = sub.add_parser("add")
    a.add_argument("--type", required=True)
    a.add_argument("--name", required=True)
    a.add_argument("--description", required=True)
    a.add_argument("--body", default="")
    a.add_argument("--body-file", default="")
    a.add_argument("--date", default="")
    sub.add_parser("index")
    r = sub.add_parser("recall")
    r.add_argument("query", nargs="?", default="")
    sub.add_parser("list")
    args = ap.parse_args()
    return {"init": lambda: cmd_init(), "add": lambda: cmd_add(args),
            "index": lambda: cmd_index(), "recall": lambda: cmd_recall(args),
            "list": lambda: cmd_list(args)}[args.cmd]()


if __name__ == "__main__":
    raise SystemExit(main())
