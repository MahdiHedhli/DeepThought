"""Measure a static detector's held-out generalization on REAL code, pinned by SHA.

For each corpus entry the detector runs over the actual target file fetched at the
vulnerable and patched commit SHAs (GitHub raw, cached under ``benchmarks/.cache/``).
Rediscovery is line-precise: the entry's ``sink_probe`` line must be FLAGGED in the
vulnerable file and NOT flagged in the patched file (the fix removed or guarded it).
Raw flag counts are reported separately as precision context; they never decide
rediscovery, so unrelated flags elsewhere in a large file do not inflate the score.

A ``dropped`` entry (no authoritative NVD record, no fetchable fix) is excluded from the
denominator — reported as coverage, never counted as a miss and never hand-faked. This
is the pin-or-drop reproducibility contract from ``rediscovery-corpus.md``.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Callable

from roundrecord import HeldOutResult, Metrics

_CACHE = Path(__file__).resolve().parent.parent / ".cache"
ScanFn = Callable[[str, str], list]  # (source, uri) -> SARIF result dicts


def _raw_url(repo: str, sha: str, path: str) -> str:
    owner_repo = repo.replace("https://github.com/", "").rstrip("/")
    return f"https://raw.githubusercontent.com/{owner_repo}/{sha}/{path}"


def fetch(repo: str, sha: str, path: str, timeout: int = 30) -> str:
    """Fetch a file at a pinned SHA (cached by sha+path). Raises on network failure."""
    key = f"{sha}_{path.replace('/', '_')}"
    cached = _CACHE / key
    if cached.exists():
        return cached.read_text(encoding="utf-8")
    data = urllib.request.urlopen(_raw_url(repo, sha, path), timeout=timeout).read()
    _CACHE.mkdir(parents=True, exist_ok=True)
    text = data.decode("utf-8", "replace")
    cached.write_text(text, encoding="utf-8")
    return text


def _sink_is_flagged(scan: ScanFn, source: str, uri: str, sink_probe: str) -> tuple[bool, int]:
    """Whether the detector flags a sink whose OWN line text contains the probe, plus the
    total flag count. Matching against FLAGGED lines (not a raw text search) means a
    comment or a doc-string that happens to contain the probe text can never be mistaken
    for the sink — the detector only flags real AST subscript sinks, never comments."""
    lines = source.splitlines()
    needle = sink_probe.replace(" ", "")
    hit = False
    count = 0
    for r in scan(source, uri):
        count += 1
        ln = r["locations"][0]["physicalLocation"]["region"]["startLine"]
        if 1 <= ln <= len(lines) and needle in lines[ln - 1].replace(" ", ""):
            hit = True
    return hit, count


def measure_entry(entry: dict, scan: ScanFn) -> dict:
    """Line-precise rediscovery for one pinned entry, over ALL target paths. The sink is
    rediscovered if a FLAGGED line's own text contains the probe in the vulnerable tree
    and NOT in the patched tree. ``patched_flag_count`` (flags on the FIXED code) is the
    honest false-positive context — never assumed zero."""
    probe = entry["sink_probe"]
    vuln_hit = patched_hit = False
    vuln_flags = patched_flags = 0
    for path in entry["target_paths"]:
        vsrc = fetch(entry["repo"], entry["vuln_ref"], path)
        psrc = fetch(entry["repo"], entry["patched_ref"], path)
        vh, vc = _sink_is_flagged(scan, vsrc, path, probe)
        ph, pc = _sink_is_flagged(scan, psrc, path, probe)
        vuln_hit = vuln_hit or vh
        patched_hit = patched_hit or ph
        vuln_flags += vc
        patched_flags += pc
    return {
        "cve": entry["cve"],
        "package": entry["package"],
        "rediscovered": bool(vuln_hit and not patched_hit),
        "vuln_flagged": vuln_hit,
        "patched_flagged": patched_hit,
        "vuln_flag_count": vuln_flags,
        "patched_flag_count": patched_flags,
    }


def measure_heldout(manifest: dict, scan: ScanFn, detector: str) -> HeldOutResult:
    """Run the detector over every PINNED held-out entry and return a typed
    HeldOutResult (rediscovered / missed / missed_cves). Dropped entries are excluded."""
    pinned = [h for h in manifest["heldout"] if h.get("status") == "pinned"]
    rediscovered = 0
    patched_flags = 0
    missed_cves: list[str] = []
    for h in pinned:
        m = measure_entry(h, scan)
        if m["rediscovered"]:
            rediscovered += 1
        else:
            missed_cves.append(h["cve"])
        # Flags on the PATCHED (fixed, safe) file are the honest false positives — never
        # assume zero. This makes the published precision real: a static heuristic that
        # flags other dynamic-write sites on a large fixed file has low file-level
        # precision, even at high sink-level recall. Sink-discrimination precision is
        # reported separately on the minimized fixture (RoundRecord.fixture).
        patched_flags += m["patched_flag_count"]
    return HeldOutResult(
        bug_class=manifest["bug_class"],
        detector=detector,
        heldout_cves=[h["cve"] for h in pinned],
        rediscovered=rediscovered,
        missed=len(missed_cves),
        missed_cves=missed_cves,
        metrics=Metrics(tp=rediscovered, fp=patched_flags, fn=len(missed_cves)),
    )


def load_manifest(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
