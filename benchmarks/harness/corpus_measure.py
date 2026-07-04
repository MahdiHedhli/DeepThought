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
from typing import Callable, Optional

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


def _flagged_lines(scan: ScanFn, source: str, uri: str) -> set[int]:
    out: set[int] = set()
    for r in scan(source, uri):
        out.add(r["locations"][0]["physicalLocation"]["region"]["startLine"])
    return out


def _sink_line(source: str, sink_probe: str) -> Optional[int]:
    """The 1-based line whose whitespace-stripped text contains the sink probe, else
    None (the sink text is absent — e.g. refactored away in the patched file)."""
    needle = sink_probe.replace(" ", "")
    for i, line in enumerate(source.splitlines(), 1):
        if needle in line.replace(" ", ""):
            return i
    return None


def measure_entry(entry: dict, scan: ScanFn) -> dict:
    """Line-precise rediscovery for one pinned entry. Returns a dict with
    ``rediscovered`` plus diagnostics (flag counts as precision context)."""
    path = entry["target_paths"][0]
    probe = entry["sink_probe"]
    vsrc = fetch(entry["repo"], entry["vuln_ref"], path)
    psrc = fetch(entry["repo"], entry["patched_ref"], path)
    vflags = _flagged_lines(scan, vsrc, path)
    pflags = _flagged_lines(scan, psrc, path)
    vsink = _sink_line(vsrc, probe)
    psink = _sink_line(psrc, probe)
    vuln_hit = vsink is not None and vsink in vflags
    patched_hit = psink is not None and psink in pflags
    return {
        "cve": entry["cve"],
        "package": entry["package"],
        "rediscovered": bool(vuln_hit and not patched_hit),
        "vuln_flagged": vuln_hit,
        "patched_flagged": patched_hit,
        "vuln_flag_count": len(vflags),
        "patched_flag_count": len(pflags),
    }


def measure_heldout(manifest: dict, scan: ScanFn, detector: str) -> HeldOutResult:
    """Run the detector over every PINNED held-out entry and return a typed
    HeldOutResult (rediscovered / missed / missed_cves). Dropped entries are excluded."""
    pinned = [h for h in manifest["heldout"] if h.get("status") == "pinned"]
    rediscovered = 0
    missed_cves: list[str] = []
    for h in pinned:
        if measure_entry(h, scan)["rediscovered"]:
            rediscovered += 1
        else:
            missed_cves.append(h["cve"])
    return HeldOutResult(
        bug_class=manifest["bug_class"],
        detector=detector,
        heldout_cves=[h["cve"] for h in pinned],
        rediscovered=rediscovered,
        missed=len(missed_cves),
        missed_cves=missed_cves,
        metrics=Metrics(tp=rediscovered, fp=0, fn=len(missed_cves)),
    )


def load_manifest(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
