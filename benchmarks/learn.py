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
import sys
from pathlib import Path
from typing import Any, Callable, Optional, TextIO

HERE = Path(__file__).resolve().parent
for _p in (str(HERE), str(HERE / "harness")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import teaching  # noqa: E402

# The public detector modules (the local-only Solidity ones are NOT part of the public build).
_DETECTOR_MODULES = [
    "pp_detector", "ssrf_detector", "xxe_detector", "cmdinj_detector", "deserial_detector",
    "pathtrav_detector", "tarfile_detector", "crlf_detector", "ldapinj_detector", "nosql_detector",
    "openredirect_detector", "sqli_detector", "ssti_detector",
]
# Source extensions worth feeding to the detectors (wrong-language input safely yields nothing, so
# the mapping need not be exact — a detector self-filters by returning no matches / raising, caught).
_CODE_EXTS = {".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".java", ".php"}
_SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".venv", "site-packages", "__pycache__"}
_MAX_BYTES = 512 * 1024  # skip very large files (a teaching tool works on human-sized source)

Answerer = Callable[[str, dict], str]


def load_detectors() -> tuple[list[tuple[str, Any]], list[str]]:
    """Import the public detectors. Returns ``(detectors, skipped)`` where each detector is
    ``(rule_id, module)``; a module that fails to import is named in ``skipped``."""
    out: list[tuple[str, Any]] = []
    skipped: list[str] = []
    for mod in _DETECTOR_MODULES:
        try:
            m = importlib.import_module(mod)
            out.append((getattr(m, "RULE_ID", mod), m))
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


def scan_path(path: Path, detectors: list[tuple[str, Any]]) -> tuple[list[dict], dict]:
    """Run the detectors over a file or directory (static; reads source as text). Returns
    ``(findings, coverage)``; coverage records files scanned vs. skipped so blind spots are visible."""
    coverage = {"scanned": 0, "skipped": 0}
    files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
    findings: list[dict] = []
    base = path if path.is_dir() else path.parent
    for p in files:
        if any(part in _SKIP_DIRS for part in p.parts) or p.suffix.lower() not in _CODE_EXTS:
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
        for rid, m in detectors:
            try:
                for r in m.scan_source(src, uri):
                    f = _finding_from(r, rid, uri)
                    if f:
                        findings.append(f)
            except Exception:
                continue  # wrong-language input / parse error — this detector simply doesn't apply
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
    print(f"\n[coverage] scanned {coverage['scanned']} source file(s); skipped "
          f"{coverage['skipped']}. Not scanned is not clean.", file=out)
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
