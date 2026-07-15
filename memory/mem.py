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
  python memory/mem.py backup                       # snapshot the vault (rotating, gitignored)
  python memory/mem.py restore [timestamp]          # revert to the newest (or a named) backup

Notes are plain markdown with YAML-ish frontmatter (name, description, type). One fact per
file. Writes are atomic and the vault is auto-snapshotted before mutation, so a failed write
cannot corrupt memory. See memory/AGENTS.md for the read/write protocol every agent follows.
"""
from __future__ import annotations

import argparse
import datetime
import os
import re
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent          # memory/
VAULT = ROOT / "vault"                           # gitignored data
TEMPLATE = ROOT / "template"
BACKUPS = ROOT / "backups"                        # gitignored rotating snapshots
INDEX = "MEMORY.md"
# lesson = knowledge distilled from doing the work (kept separate from feedback, which is
# operator preferences/directives about HOW to work).
TYPES = ("user", "feedback", "lesson", "project", "reference")
KEEP_BACKUPS = 20                                 # default rotation depth


def _atomic_write(path: Path, text: str) -> None:
    """Write via a temp file + os.replace so a crash/failed write can never leave a
    half-written (corrupt) note — the old file survives intact until the swap is atomic."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


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


def _note_meta(fm: dict) -> tuple[str, list[str]]:
    """(class, tags) from a note's frontmatter — for scoped recall by attack class / surface."""
    klass = fm.get("class", "").strip()
    tags = [t.strip().lower() for t in fm.get("tags", "").strip("[]").split(",") if t.strip()]
    return klass, tags


def _make_backup(keep: int = KEEP_BACKUPS) -> Path | None:
    """Snapshot the whole vault to a timestamped, rotating backup dir. Copy-then-swap and a
    rotation of the newest `keep` snapshots means a corrupted or truncated vault can always be
    restored from the last good copy. Backups live in memory/backups/ (gitignored)."""
    if not VAULT.exists() or not _notes():
        return None
    BACKUPS.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    dest = BACKUPS / stamp
    n = 0
    while dest.exists():
        n += 1
        dest = BACKUPS / f"{stamp}-{n}"
    tmp = BACKUPS / (dest.name + ".partial")
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(VAULT, tmp, ignore=shutil.ignore_patterns(".*", "*.tmp-*"))
    os.replace(tmp, dest)  # atomic promote — a half-copied snapshot never looks complete
    snaps = sorted(d for d in BACKUPS.iterdir() if d.is_dir())
    for old in snaps[:-keep] if keep > 0 else []:
        shutil.rmtree(old, ignore_errors=True)
    return dest


def _autobackup_if_stale(max_age_s: int = 300) -> None:
    """Snapshot before a write if the newest backup is missing or older than max_age_s — so
    'back up before each run' holds even when the caller forgets to run `backup` explicitly."""
    newest = 0.0
    if BACKUPS.exists():
        ages = [d.stat().st_mtime for d in BACKUPS.iterdir() if d.is_dir()]
        newest = max(ages) if ages else 0.0
    if time.time() - newest > max_age_s:
        _make_backup()


def cmd_init() -> int:
    if VAULT.exists():
        print(f"vault already exists: {VAULT}")
        return 0
    VAULT.mkdir(parents=True, exist_ok=True)
    tpl_index = TEMPLATE / INDEX
    _atomic_write(VAULT / INDEX, tpl_index.read_text() if tpl_index.exists() else "# Memory index\n")
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
    meta = [f"  type: {args.type}"]
    if getattr(args, "klass", ""):
        meta.append(f"  class: {args.klass}")          # the attack class / CWE this lesson is about
    tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]
    if tags:
        meta.append(f"  tags: [{', '.join(tags)}]")     # surface/platform/language for scoped recall
    meta.append(f"  updated: {date}")
    note = (
        f"---\nname: {slug}\ndescription: {args.description}\n"
        f"metadata:\n" + "\n".join(meta) + f"\n---\n\n{body.rstrip()}\n"
    )
    path = VAULT / f"{slug}.md"
    existed = path.exists()
    _autobackup_if_stale()   # a fresh snapshot exists before we mutate the vault
    _atomic_write(path, note)
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
        klass, _tags = _note_meta(fm)
        label = f"`{klass}` " if klass else ""
        by_type.setdefault(t, []).append(f"- [{fm.get('name', p.stem)}]({p.name}) {label}— {desc}")
    lines = ["# Memory index", "",
             "_DeepThought portable agent memory. One fact per note; this index is generated "
             "by `python memory/mem.py index`. See [AGENTS.md](../AGENTS.md) for the protocol._", ""]
    titles = {"user": "Who the user is", "feedback": "How to work (operator preferences)",
              "lesson": "Distilled lessons (learned from the work)",
              "project": "Project state & decisions", "reference": "References"}
    for t in TYPES:
        if by_type.get(t):
            lines += [f"## {titles[t]}", *sorted(by_type[t]), ""]
    _atomic_write(VAULT / INDEX, "\n".join(lines).rstrip() + "\n")
    if not quiet:
        print(f"indexed {sum(len(v) for v in by_type.values())} notes -> {VAULT / INDEX}")
    return 0


def cmd_recall(args) -> int:
    """Print notes, optionally SCOPED so an agent loads only what's relevant instead of the
    whole vault: --class <attack-class> and/or --tag <surface/platform/language>, and/or a
    free-text query. With no filters and no query, prints the index."""
    if not VAULT.exists():
        print("no vault; run: python memory/mem.py init", file=sys.stderr)
        return 1
    cls = (getattr(args, "klass", "") or "").strip().lower()
    tag = (getattr(args, "tag", "") or "").strip().lower()
    q = (args.query or "").lower()
    if not (cls or tag or q):
        print((VAULT / INDEX).read_text(encoding="utf-8") if (VAULT / INDEX).exists() else "(empty)")
        return 0
    hits = 0
    for p in _notes():
        text = p.read_text(encoding="utf-8")
        klass, tags = _note_meta(_fm(text))
        if cls and klass.lower() != cls:
            continue
        if tag and tag not in tags:
            continue
        if q and q not in text.lower() and q not in p.stem.lower():
            continue
        print(f"\n===== {p.name} =====\n{text.rstrip()}")
        hits += 1
    if not hits:
        scope = " ".join(x for x in (f"class={cls}" if cls else "", f"tag={tag}" if tag else "",
                                     f"query={args.query!r}" if q else "") if x)
        print(f"no notes match {scope}")
    return 0


def cmd_list(_args) -> int:
    if not VAULT.exists():
        print("no vault; run: python memory/mem.py init", file=sys.stderr)
        return 1
    for p in _notes():
        fm = _fm(p.read_text(encoding="utf-8"))
        print(f"{p.stem:32} {fm.get('description', '')}")
    return 0


def cmd_backup(args) -> int:
    dest = _make_backup(args.keep or KEEP_BACKUPS)
    if dest is None:
        print("nothing to back up (no vault/notes)")
        return 0
    print(f"backed up {len(_notes())} notes -> {dest.relative_to(ROOT.parent)}")
    return 0


def cmd_restore(args) -> int:
    snaps = sorted(d for d in BACKUPS.iterdir() if d.is_dir()) if BACKUPS.exists() else []
    if not snaps:
        print("no backups to restore from", file=sys.stderr)
        return 1
    src = (BACKUPS / args.which) if args.which else snaps[-1]
    if not src.is_dir():
        print(f"no such backup: {src.name} (have: {[d.name for d in snaps[-5:]]})", file=sys.stderr)
        return 1
    _make_backup()  # snapshot the current (possibly corrupt) state before overwriting it
    tmp = VAULT.with_name("vault.restoring")
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(src, tmp)
    if VAULT.exists():
        shutil.rmtree(VAULT.with_name("vault.old"), ignore_errors=True)
        os.replace(VAULT, VAULT.with_name("vault.old"))
    os.replace(tmp, VAULT)
    shutil.rmtree(VAULT.with_name("vault.old"), ignore_errors=True)
    print(f"restored vault from backup {src.name}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="DeepThought portable agent memory")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    a = sub.add_parser("add")
    a.add_argument("--type", required=True)
    a.add_argument("--name", required=True)
    a.add_argument("--description", required=True)
    a.add_argument("--class", dest="klass", default="", help="attack class / CWE this lesson is about")
    a.add_argument("--tags", default="", help="comma list: surface/platform/language (e.g. web,python,taint)")
    a.add_argument("--body", default="")
    a.add_argument("--body-file", default="")
    a.add_argument("--date", default="")
    sub.add_parser("index")
    r = sub.add_parser("recall")
    r.add_argument("query", nargs="?", default="")
    r.add_argument("--class", dest="klass", default="", help="only notes of this attack class")
    r.add_argument("--tag", default="", help="only notes carrying this surface/platform/language tag")
    sub.add_parser("list")
    b = sub.add_parser("backup")
    b.add_argument("--keep", type=int, default=0, help=f"snapshots to retain (default {KEEP_BACKUPS})")
    rs = sub.add_parser("restore")
    rs.add_argument("which", nargs="?", default="", help="backup dir name; default = newest")
    args = ap.parse_args()
    return {"init": lambda: cmd_init(), "add": lambda: cmd_add(args),
            "index": lambda: cmd_index(), "recall": lambda: cmd_recall(args),
            "list": lambda: cmd_list(args), "backup": lambda: cmd_backup(args),
            "restore": lambda: cmd_restore(args)}[args.cmd]()


if __name__ == "__main__":
    raise SystemExit(main())
