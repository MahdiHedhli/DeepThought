#!/usr/bin/env python3
"""learn.py — DeepThought's learning switch: a static, local, student-facing explainer.

Point it at a LOCAL source file or directory and learn how DeepThought's detectors think. For each
candidate it shows: what the CWE class is, WHY it matters, a DISPROVE-FIRST triage checklist, and
how to reason about the fix — plus the DeepThought methodology a student should carry away. An
optional ``--ask`` opens a small Q&A over the finding.

    python benchmarks/learn.py path/to/file_or_dir
    python benchmarks/learn.py app.py --ask "why is this exploitable?"

SAFETY (Article III): this reads your source as DATA (it parses an AST) — it NEVER executes it,
fetches anything, or touches a network. A candidate is not a finding until a human confirms it is
reachable from untrusted input.
"""
from __future__ import annotations

import argparse
import importlib
import json as _json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional, TextIO

HERE = Path(__file__).resolve().parent
for _p in (str(HERE), str(HERE / "harness")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import teaching  # noqa: E402

# The public detector modules (the local-only Solidity ones are NOT part of the public build), each
# with the file extensions it actually handles. A detector runs ONLY on files it handles, so a raised
# exception is a REAL detector failure worth surfacing — not an expected wrong-language parse error.
_JS = {".js", ".mjs", ".cjs", ".jsx"}
_DETECTORS_SPEC = [
    ("pp_detector", _JS),
    ("ssrf_detector", {".py"}),
    ("ssti_detector", {".py"}),
    ("crlf_detector", {".py"}),
    ("openredirect_detector", {".py"}),
    ("tarfile_detector", {".py"}),
    ("cmdinj_detector", {".py"} | _JS),
    ("deserial_detector", {".py", ".java"} | _JS),
    ("pathtrav_detector", {".py"} | _JS),
    ("xxe_detector", {".py", ".java"}),
    ("ldapinj_detector", {".py", ".java", ".php"}),
    ("nosql_detector", _JS | {".ts", ".tsx"}),
    ("sqli_detector", {".py", ".php"}),
]
_CODE_EXTS = set().union(*(exts for _m, exts in _DETECTORS_SPEC))
_SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".venv", "site-packages", "__pycache__"}
_MAX_BYTES = 512 * 1024  # skip very large files (a teaching tool works on human-sized source)

Answerer = Callable[[str, dict], str]


def load_detectors() -> tuple[list[tuple[str, Any, set]], list[str]]:
    """Import the public detectors. Returns ``(detectors, skipped)`` where each detector is
    ``(rule_id, module, extensions)``; a module that fails to import is named in ``skipped``."""
    out: list[tuple[str, Any, set]] = []
    skipped: list[str] = []
    for mod, exts in _DETECTORS_SPEC:
        try:
            m = importlib.import_module(mod)
            out.append((getattr(m, "RULE_ID", mod), m, exts))
        except Exception as e:  # a detector whose grammar isn't installed is skipped, not fatal
            skipped.append(f"{mod} ({e})")
    return out, skipped


def _finding_from(result: dict, rule_fallback: str, uri: str) -> Optional[dict]:
    try:
        loc = result["locations"][0]["physicalLocation"]["region"]
        return {
            "rule": result.get("ruleId", rule_fallback),
            "cwe": result.get("properties", {}).get("cwe", ""),
            "file": uri, "line": loc["startLine"], "col": loc.get("startColumn", 1),
            "message": result["message"]["text"],
        }
    except (KeyError, IndexError, TypeError):
        return None


def _iter_source_files(path: Path, on_error: Optional[Callable[[Any], None]] = None):
    """Yield source files under ``path``, pruning excluded directories DURING traversal (never
    descending into node_modules/.git/.venv/… on a large tree).

    Symlink/irregular-file policy is explicit: during directory traversal we yield ONLY regular,
    NON-symlink files — so a symlink is never followed out of the tree, and a FIFO/socket can never
    reach ``read_text`` and hang the scan. A directly-named file is honored as the user's explicit
    choice. Traversal ``OSError``s (e.g. an unreadable subtree) are reported via ``on_error`` rather
    than silently dropped, so an incomplete scan cannot look clean."""
    if path.is_file():  # is_file() follows symlinks: honor an explicitly-named (regular) target
        yield path
        return
    for dirpath, dirnames, filenames in os.walk(path, onerror=on_error, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]  # prune in place → don't descend
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                if p.is_file() and not p.is_symlink():  # regular files only; don't follow symlinks
                    yield p
            except OSError as e:
                if on_error is not None:
                    on_error(e)


def scan_path(path: Path, detectors: list[tuple[str, Any, set]]) -> tuple[list[dict], dict]:
    """Run the detectors over a file or directory (static; reads source as text). Each detector runs
    only on files it handles. Returns ``(findings, coverage)``; coverage records files scanned vs.
    skipped, plus any REAL detector errors (a detector raising on an applicable file) and traversal
    errors (an unreadable subtree) so nothing is silently swallowed — 'not scanned is not clean'."""
    coverage = {"scanned": 0, "skipped": 0, "detector_errors": 0, "walk_errors": 0}
    findings: list[dict] = []
    base = path if path.is_dir() else path.parent

    def _on_walk_error(_err: Any) -> None:
        coverage["walk_errors"] += 1

    for p in _iter_source_files(path, on_error=_on_walk_error):
        ext = p.suffix.lower()
        if ext not in _CODE_EXTS:
            coverage["skipped"] += 1
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                coverage["skipped"] += 1
                continue
            src = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            coverage["skipped"] += 1
            continue
        coverage["scanned"] += 1
        uri = str(p.relative_to(base)) if p != path else p.name
        for rid, m, exts in detectors:
            if ext not in exts:
                continue  # this detector does not handle this language
            try:
                for r in m.scan_source(src, uri):
                    f = _finding_from(r, rid, uri)
                    if f:
                        findings.append(f)
            except Exception:
                coverage["detector_errors"] += 1  # a genuine failure on an applicable file — surfaced
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    return findings, coverage


def render_finding(f: dict, *, index: int, total: int, out: TextIO) -> None:
    """Pedagogical rendering of one candidate: location, then the teaching note (what/why/confirm/
    refute/fix)."""
    loc = f"{f['file']}:{f['line']}:{f.get('col', 1)}"
    print(f"\n[{index}/{total}] {loc}  [{f['rule']} / {f['cwe']}]", file=out)
    print(f"    {f['message']}", file=out)
    t = teaching.teaching_for(f["cwe"], f.get("rule", ""))
    if t is None:
        print(f"    (no teaching note for {f['cwe'] or f['rule']}; treat as an unconfirmed candidate)",
              file=out)
        return
    print(f"    · what it is:  {t['name']} — {t['why']}", file=out)
    print("    · to CONFIRM (disprove-first — rule these out):", file=out)
    for c in t["confirm"]:
        print(f"        - {c}", file=out)
    print("    · likely a FALSE POSITIVE if:", file=out)
    for r in t["refute"]:
        print(f"        - {r}", file=out)
    print(f"    · fix intuition: {t['learn']}", file=out)


def render(findings: list[dict], coverage: dict, *, out: TextIO, skipped_detectors: list[str]) -> None:
    if skipped_detectors:
        print(f"(note: {len(skipped_detectors)} detector(s) unavailable in this environment — "
              "install their grammars to widen coverage)", file=out)
    if not findings:
        print("No candidates surfaced. Remember: a clean scan is not a proof of safety — the "
              "detectors only cover specific classes, and only where the pattern is visible.", file=out)
    else:
        print(f"{len(findings)} teaching candidate(s) — NONE is a confirmed bug. Each is a pattern to "
              "learn from and verify:", file=out)
        for i, f in enumerate(findings, 1):
            render_finding(f, index=i, total=len(findings), out=out)
    errs = coverage.get("detector_errors", 0)
    walk = coverage.get("walk_errors", 0)
    notes = ""
    if errs:
        notes += f"; {errs} detector error(s) — a detector failed on a file it handles"
    if walk:
        notes += f"; {walk} unreadable subtree(s) — the scan is INCOMPLETE"
    print(f"\n[coverage] scanned {coverage['scanned']} source file(s); skipped "
          f"{coverage['skipped']}{notes}. Not scanned is not clean.", file=out)
    print("\nHow DeepThought thinks (carry these away):", file=out)
    for note in teaching.methodology_notes():
        print(f"  • {note}", file=out)


def answer(question: str, finding: dict, *, answerer: Answerer = teaching.local_answer) -> str:
    """Q&A over a finding. Defaults to the offline, deterministic teaching answerer; a real
    subagent (an LLM given the finding + surrounding code) is a drop-in ``answerer`` — the hook that
    makes this a 'subagent for questions' without hard-wiring a model."""
    return answerer(question, finding)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="DeepThought learning switch — static, local, teaches how the detectors think.")
    ap.add_argument("path", help="a source file or directory to explain (read as data, never run)")
    ap.add_argument("--ask", metavar="QUESTION", default="",
                    help="ask a question about the FIRST candidate (offline teaching answerer)")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON (no narration)")
    args = ap.parse_args(argv)

    path = Path(args.path)
    if not path.exists():
        print(f"no such path: {path}", file=sys.stderr)
        return 2

    detectors, skipped = load_detectors()
    findings, coverage = scan_path(path, detectors)

    if args.json:
        print(_json.dumps({"findings": findings, "coverage": coverage}, indent=2))
        return 0

    print(f"== DeepThought · learn == {path}\n   SOURCE ONLY — this reads your code as data and never "
          "runs it. Candidates are teaching examples, not confirmed bugs.")
    render(findings, coverage, out=sys.stdout, skipped_detectors=skipped)

    if args.ask:
        if not findings:
            print("\n(no candidate to ask about)")
        else:
            print(f"\nQ: {args.ask}\nA: {answer(args.ask, findings[0])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
