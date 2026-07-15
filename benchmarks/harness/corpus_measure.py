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

If a fix deliberately deletes a target, the manifest may list that exact path in
``patched_absent_paths``. Absence is accepted only after the patched commit is verified
and the raw path returns 404; every other fetch failure remains a hard failure.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

from roundrecord import HeldOutResult, Metrics

_CACHE = Path(__file__).resolve().parent.parent / ".cache"
ScanFn = Callable[[str, str], list]  # (source, uri) -> SARIF result dicts
_USER_AGENT = "DeepThought-corpus-measure/1"


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


def _repo_slug(repo: str) -> str:
    prefix = "https://github.com/"
    if not repo.startswith(prefix):
        raise ValueError(f"only public GitHub repositories are supported: {repo!r}")
    slug = repo[len(prefix) :].strip("/")
    if slug.count("/") != 1:
        raise ValueError(f"expected owner/repository GitHub URL: {repo!r}")
    return slug


def _urlopen(url: str, timeout: int):
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    return urllib.request.urlopen(request, timeout=timeout)


def _confirm_ref_exists(repo: str, sha: str, timeout: int = 30) -> None:
    """Fail closed unless *sha* is a real full commit in the declared repository.

    A raw GitHub 404 is ambiguous: it can mean either "this path was deleted" or "the
    ref is invalid".  Verify the ref independently before accepting a declared deletion.
    """
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError(f"patched_ref must be a full lowercase commit SHA: {sha!r}")
    repository_slug = _repo_slug(repo)
    cache_slug = repository_slug.replace("/", "_")
    marker = _CACHE / f"{cache_slug}_{sha}.commit.json"
    expected = {"repo": repo, "sha": sha}
    if marker.exists():
        if json.loads(marker.read_text(encoding="utf-8")) != expected:
            raise ValueError(f"commit cache marker does not match {repo}@{sha}")
        return
    slug = urllib.parse.quote(repository_slug, safe="/")
    url = f"https://api.github.com/repos/{slug}/git/commits/{sha}"
    with _urlopen(url, timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if payload.get("sha") != sha:
        raise ValueError(f"GitHub did not resolve the exact patched_ref {sha}")
    _CACHE.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(expected, sort_keys=True), encoding="utf-8")


def _confirm_patched_absent(repo: str, sha: str, path: str, timeout: int = 30) -> None:
    """Confirm an explicitly declared deleted target.

    Only a 404 for the path at an independently verified commit is accepted.  Auth,
    rate-limit, server, and network failures propagate instead of becoming false fixes.
    """
    _confirm_ref_exists(repo, sha, timeout)
    cache_slug = _repo_slug(repo).replace("/", "_")
    key = f"{cache_slug}_{sha}_{path.replace('/', '_')}.absent.json"
    marker = _CACHE / key
    expected = {"repo": repo, "sha": sha, "path": path, "status": 404}
    if marker.exists():
        if json.loads(marker.read_text(encoding="utf-8")) != expected:
            raise ValueError(f"absence cache marker does not match {repo}@{sha}:{path}")
        return
    try:
        with _urlopen(_raw_url(repo, sha, path), timeout):
            pass
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    else:
        raise ValueError(f"manifest declares patched path absent, but it exists: {path}")
    _CACHE.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(expected, sort_keys=True), encoding="utf-8")


def _sink_is_flagged(scan: ScanFn, source: str, uri: str, sink_probe: str) -> tuple[bool, int]:
    """Whether the detector flags a sink whose OWN line text contains the probe, plus the
    total flag count. Matching against FLAGGED lines (not a raw text search) means a
    comment or a doc-string that happens to contain the probe text can never be mistaken
    for the sink: only a detector-emitted code location is eligible."""
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
    honest false-positive context — never assumed zero. A path declared in
    ``patched_absent_paths`` is treated as empty only after fail-closed deletion proof."""
    probe = entry["sink_probe"]
    declared_absent = entry.get("patched_absent_paths", [])
    if not isinstance(declared_absent, list) or not all(isinstance(path, str) for path in declared_absent):
        raise ValueError("patched_absent_paths must be a list of target-path strings")
    if len(declared_absent) != len(set(declared_absent)):
        raise ValueError("patched_absent_paths must not contain duplicates")
    absent_paths = set(declared_absent)
    target_paths = set(entry["target_paths"])
    if unknown := absent_paths - target_paths:
        raise ValueError(f"patched_absent_paths are not target_paths: {sorted(unknown)}")
    vuln_hit = patched_hit = False
    vuln_flags = patched_flags = 0
    for path in entry["target_paths"]:
        vsrc = fetch(entry["repo"], entry["vuln_ref"], path)
        if path in absent_paths:
            _confirm_patched_absent(entry["repo"], entry["patched_ref"], path)
            psrc = ""
        else:
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
        "patched_absent_paths": sorted(absent_paths),
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
