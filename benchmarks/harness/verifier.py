"""The numerator VERIFIER — re-run the frozen detector on the real pinned SHAs (008, round 5).

An audit proved the irreducible floor a pure validator cannot verify: it cannot
check that the reported numerator (which blind cases were "rediscovered") is TRUE,
because it never sees the detector run on the real code — it only sees a claimed
count. This module closes that gap for the numerator: given the frozen detector and
the pinned corpus SHAs, it RECOMPUTES the rediscovery set from the actual target
files. Round-5 makes the recompute a thing ``contract.validate`` RUNS ITSELF rather
than a caller-supplied set: the strict certify path calls
:func:`recompute_certified_numerator`, which resolves the detector from a COMMITTED,
git-tracked :data:`DETECTOR_REGISTRY` (keyed by the frozen ``detector_id``) and the
fetcher from the COMMITTED :data:`FETCH_FN` — neither is a caller argument the scored
party could forge — and refuses certification (``NUMERATOR_UNVERIFIED``) unless the
reported set MATCHES the recompute. An operator can no longer CLAIM a rediscovery the
detector did not produce on the real code, nor OMIT a real one, nor substitute a
lying detector (the detector is the committed one, keyed by the frozen id).

The rediscovery rule is EXACTLY ``corpus_measure.py``'s line-precise rule (imported,
never reimplemented): a FLAGGED line whose OWN text contains the ``sink_probe`` in the
VULNERABLE tree and NOT in the PATCHED tree. Fetching reuses ``corpus_measure.py``'s
GitHub-raw fetcher (cached under ``benchmarks/.cache``). The registry + fetcher are
module-level and MONKEYPATCHABLE, so unit tests are deterministic and hermetic and
only the one real-re-run integration test touches the network.

SAFETY (Article III): the detector is OUR static analyzer. ``scan_fn`` (a real
detector's ``scan_source``) PARSES the fetched source as DATA — e.g. ``ast.parse`` —
and NEVER executes it. This module must never ``eval`` / ``exec`` fetched content
(the committed detector modules are imported by NAME from the registry, never from
fetched text); no target code is run, so there is no Article III sandbox concern.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Callable, Iterable

import corpus_measure  # reuse the EXACT fetcher + line-precise rule; do not reimplement
from contract import blob_sha256  # the committed per-target content-address primitive (R8-1)

# (repo, ref, path) -> source text. In production this is ``corpus_measure.fetch``;
# tests inject a canned dict-backed fake.
FetchFn = Callable[[str, str, str], str]
# (source, uri) -> SARIF-ish list of finding dicts. This is the frozen detector's
# ``scan_source``; tests inject a canned fake.
ScanFn = Callable[[str, str], list]


class InputBytesUnverified(Exception):
    """R8-1: the fetched pinned bytes do NOT reproduce the committed per-target
    ``vuln_blob_sha256`` / ``patched_blob_sha256`` of the ``CohortEntry`` (or the entry
    committed no hash for a scored target). The recompute then ran — or would have run — the
    detector on bytes an attacker controlling the fetch source/cache could have DOCTORED, so it
    is not the committed pinned input. ``contract.validate`` maps this to
    ``INPUT_BYTES_UNVERIFIED`` (fail closed) rather than trusting the detector's verdict."""


def _require_committed_bytes(entry, path: str, ref: str, source: str, committed: dict) -> None:
    """R8-1: require the fetched ``source`` at (``path``, ``ref``) to reproduce the entry's
    committed per-target blob sha256. A missing commitment for a scored target is itself a
    failure (fail closed) — the seal is not skippable by omitting a hash."""
    want = committed.get(path)
    got = blob_sha256(source)
    if want is None:
        raise InputBytesUnverified(
            f"{entry.repo}@{ref}:{path} has no committed blob sha256 to verify the fetched bytes against"
        )
    if want != got:
        raise InputBytesUnverified(
            f"{entry.repo}@{ref}:{path} fetched bytes sha256 {got} != committed {want} (doctored input)"
        )


def _entry_rediscovered(entry, fetch_fn: FetchFn, scan_fn: ScanFn, *, verify_blobs: bool = True) -> bool:
    """Line-precise rediscovery for one entry over ALL its target paths, using the EXACT
    ``corpus_measure._sink_is_flagged`` rule: the sink is rediscovered iff a FLAGGED
    line's own text contains the probe in the VULN tree and NOT in the PATCHED tree.

    ``entry`` is a ``CohortEntry`` (``.repo`` / ``.vuln_ref`` / ``.patched_ref`` /
    ``.target_paths`` / ``.sink_probe``). The fetched source is read as DATA only.

    R8-1: when ``verify_blobs`` (the default and the ONLY value the certify path uses), each
    fetched source must reproduce the entry's committed per-target blob sha256 BEFORE the
    detector sees it — so a doctored fetch is rejected (``InputBytesUnverified``) rather than
    silently scanned."""
    probe = entry.sink_probe
    vuln_hit = patched_hit = False
    for path in entry.target_paths:
        vuln_source = fetch_fn(entry.repo, entry.vuln_ref, path)
        patched_source = fetch_fn(entry.repo, entry.patched_ref, path)
        if verify_blobs:
            _require_committed_bytes(entry, path, entry.vuln_ref, vuln_source, entry.vuln_blob_sha256)
            _require_committed_bytes(entry, path, entry.patched_ref, patched_source, entry.patched_blob_sha256)
        # corpus_measure._sink_is_flagged(scan, source, uri, probe) -> (hit, flag_count)
        vuln_flagged, _ = corpus_measure._sink_is_flagged(scan_fn, vuln_source, path, probe)
        patched_flagged, _ = corpus_measure._sink_is_flagged(scan_fn, patched_source, path, probe)
        vuln_hit = vuln_hit or vuln_flagged
        patched_hit = patched_hit or patched_flagged
    return bool(vuln_hit and not patched_hit)


def recompute_rediscovered(
    blind_entries: Iterable, *, fetch_fn: FetchFn, scan_fn: ScanFn, verify_blobs: bool = True
) -> set[str]:
    """Recompute the set of rediscovered BLIND entry-identity hashes by re-running the
    frozen detector on the real pinned code.

    Pure function of ``(blind_entries, fetch_fn, scan_fn)`` — deterministic given the
    injected fetch/scan. For each entry, fetch the vuln + patched target files and apply
    the line-precise rule; the entry's ``computed_identity_hash`` joins the returned set
    iff its sink is rediscovered. On the strict certify path ``contract.validate`` RUNS
    this itself via :func:`recompute_certified_numerator`, resolving fetch/scan from
    COMMITTED state rather than trusting a caller-supplied set.

    R8-1: with ``verify_blobs`` (the default), each fetched source must reproduce the entry's
    committed per-target blob sha256, so a doctored fetch raises ``InputBytesUnverified``."""
    rediscovered: set[str] = set()
    for entry in blind_entries:
        if _entry_rediscovered(entry, fetch_fn, scan_fn, verify_blobs=verify_blobs):
            rediscovered.add(entry.computed_identity_hash)
    return rediscovered


# --------------------------------------------------------------------------- #
# Round-5 — the COMMITTED detector registry + committed fetcher (never caller args)
# --------------------------------------------------------------------------- #
#
# R5-1's governing principle: a verification RESULT must never be a caller argument the
# scored party could forge. ``contract.validate`` RUNS the recompute itself, resolving
# the detector from a COMMITTED, git-tracked registry keyed by the frozen
# ``detector_id`` and the fetcher from a COMMITTED module-level fetcher. Both are
# module-level and MONKEYPATCHABLE for hermetic unit tests; production uses the real
# ones (the net-gated integration test exercises the real fetch + a real detector).

# The committed corpus fetcher (GitHub-raw + on-disk cache). Assigned at module level so
# hermetic tests can monkeypatch it with a canned dict-backed fake; the net-gated test
# uses the real one. NOT a caller argument.
FETCH_FN: FetchFn = corpus_measure.fetch

# The committed detector registry: frozen ``detector_id`` -> the git-tracked detector
# module that provides ``scan_source``. Loaders are LAZY (a zero-arg callable returning
# the ``scan_source``) so importing this module never pulls in every detector's heavy
# parser dependencies; the mapping itself is committed, reviewable state.
_DETECTOR_MODULES: dict[str, str] = {
    "DT-SSRF-TAINT": "ssrf_detector",
    "DT-XXE-PARSER": "xxe_detector",
    "DT-PP-MERGE": "pp_detector",
    "DT-OPEN-REDIRECT": "openredirect_detector",
    "DT-SSTI-TEMPLATE": "ssti_detector",
    "DT-PATH-TRAVERSAL": "pathtrav_detector",
    "DT-LDAP-FILTER": "ldapinj_detector",
    "DT-SQLI-QUERY": "sqli_detector",
    "DT-NOSQL-OP": "nosql_detector",
    "DT-CMDI-EXEC": "cmdinj_detector",
    "DT-CRLF-HEADER": "crlf_detector",
    "DT-DESERIAL": "deserial_detector",
}

# The detectors live in ``benchmarks/`` (the parent of this ``harness/`` dir); ensure it
# is importable so a committed ``detector_id`` resolves to its real ``scan_source``.
_BENCHMARKS_DIR = str(Path(__file__).resolve().parent.parent)


def _load_scan_source(module_name: str) -> ScanFn:
    """Import a committed detector module by NAME (never from fetched text) and return its
    ``scan_source``. SAFETY: importing OUR git-tracked analyzer module is not executing a
    target; the fetched corpus source is only ever PARSED as data by ``scan_source``."""
    if _BENCHMARKS_DIR not in sys.path:
        sys.path.insert(0, _BENCHMARKS_DIR)
    module = importlib.import_module(module_name)
    return module.scan_source


def _module_source_hashes(module_name: str) -> dict[str, str]:
    """R10-1 (trust CODE HASHES, not names): recompute the CONTENT HASH of a committed detector's
    SOURCE. For a single-module detector this is ``{basename: sha256(source_bytes)}``. For a PACKAGE
    detector (a directory with ``__init__.py``) it is the hash of EVERY ``.py`` file in the package
    tree, keyed by package-relative POSIX path (sorted) — so a swapped NON-``__init__`` submodule
    cannot slip past the freeze binding: the whole executable bundle is hashed, not just the entry
    file. Every resolved source path is asserted to reside within the benchmarks root, so a symlink
    or crafted origin cannot make the hash read code outside the reviewed tree (no traversal).
    SAFETY (Article III): the analyzer's own source is read as TEXT and hashed — it is NOT
    imported/executed here, and no fetched or target code is run."""
    if _BENCHMARKS_DIR not in sys.path:
        sys.path.insert(0, _BENCHMARKS_DIR)
    spec = importlib.util.find_spec(module_name)
    if spec is None or not spec.origin:
        raise KeyError(f"detector module {module_name!r} has no resolvable source file to hash")
    root = Path(_BENCHMARKS_DIR).resolve()

    def _contained(p: Path) -> Path:
        """Resolve ``p`` and require it to live under the benchmarks root (else fail closed)."""
        rp = p.resolve()
        if rp != root and not rp.is_relative_to(root):
            raise KeyError(f"detector source {rp} escapes the benchmarks root {root}")
        return rp

    # A package exposes submodule search locations; hash its WHOLE .py tree, not just __init__.py.
    if spec.submodule_search_locations:
        pkg_dir = _contained(Path(next(iter(spec.submodule_search_locations))))
        hashes: dict[str, str] = {}
        for py in sorted(pkg_dir.rglob("*.py")):
            cp = _contained(py)
            rel = cp.relative_to(pkg_dir.parent).as_posix()  # package-relative, stable across machines
            hashes[rel] = blob_sha256(cp.read_text(encoding="utf-8"))
        if not hashes:
            raise KeyError(f"detector package {module_name!r} has no .py source to hash")
        return hashes
    origin = _contained(Path(spec.origin))
    return {origin.name: blob_sha256(origin.read_text(encoding="utf-8"))}


DETECTOR_REGISTRY: dict[str, Callable[[], ScanFn]] = {
    detector_id: (lambda module=module_name: _load_scan_source(module))
    for detector_id, module_name in _DETECTOR_MODULES.items()
}

# R10-1: the committed detector MODULE-HASH registry, mirroring DETECTOR_REGISTRY. Keyed by the
# frozen ``detector_id`` -> a zero-arg loader recomputing the module source's content hash(es).
# Module-level and MONKEYPATCHABLE (hermetic tests inject a canned hash without a real module
# file); production hashes the real git-tracked detector source. NOT a caller argument.
DETECTOR_MODULE_HASHES: dict[str, Callable[[], dict[str, str]]] = {
    detector_id: (lambda module=module_name: _module_source_hashes(module))
    for detector_id, module_name in _DETECTOR_MODULES.items()
}


def resolve_module_hashes(detector_id: str) -> dict[str, str]:
    """R10-1: resolve the loaded detector's module content hash(es) from the COMMITTED
    :data:`DETECTOR_MODULE_HASHES`, keyed by the freeze-committed ``detector_id``. NOT a caller
    argument — the scored party cannot swap the detector CODE while keeping the name. Raises
    ``KeyError`` for an unregistered id so the certify path fails closed
    (``DETECTOR_BUNDLE_UNVERIFIED``)."""
    loader = DETECTOR_MODULE_HASHES.get(detector_id)
    if loader is None:
        raise KeyError(f"no committed detector module registered for detector_id {detector_id!r}")
    return loader()


def resolve_scan_fn(detector_id: str) -> ScanFn:
    """Resolve the frozen detector's ``scan_source`` from the COMMITTED
    :data:`DETECTOR_REGISTRY`, keyed by the freeze-committed ``detector_id``. NOT a caller
    argument — the scored party cannot substitute a lying detector. Raises ``KeyError`` for
    an unregistered id so the certify path fails closed on a numerator it cannot recompute."""
    loader = DETECTOR_REGISTRY.get(detector_id)
    if loader is None:
        raise KeyError(f"no committed detector registered for detector_id {detector_id!r}")
    return loader()


def recompute_certified_numerator(blind_entries: Iterable, *, detector_id: str) -> set[str]:
    """RUN the numerator recompute entirely from COMMITTED state (R5-1). Resolve the
    ``scan_fn`` from the committed :data:`DETECTOR_REGISTRY` keyed by ``detector_id`` and the
    ``fetch_fn`` from the committed :data:`FETCH_FN`, then recompute the rediscovered blind
    identity set. Both seams are module-level and monkeypatchable for hermetic tests;
    neither is a caller argument the scored party could forge."""
    scan_fn = resolve_scan_fn(detector_id)
    return recompute_rediscovered(blind_entries, fetch_fn=FETCH_FN, scan_fn=scan_fn)


def recompute_fixed_cohort_recall(regression_entries: Iterable, *, detector_id: str) -> tuple[int, int]:
    """R7-2: RECOMPUTE ``(rediscovered, total)`` over the head cohort's REGRESSION entries by
    re-running the COMMITTED detector — the fixed-cohort mirror of the blind numerator. The
    total is the regression-entry count; the numerator is how many the committed detector
    rediscovers under the EXACT ``corpus_measure`` line-precise rule. RUN from committed state
    (registry + :data:`FETCH_FN`), never a caller-supplied number, so a certified
    ``fixed_cohort_recall`` cannot be a free float (``FIXED_COHORT_UNVERIFIED`` on mismatch)."""
    entries = list(regression_entries)
    scan_fn = resolve_scan_fn(detector_id)
    rediscovered = recompute_rediscovered(entries, fetch_fn=FETCH_FN, scan_fn=scan_fn)
    return len(rediscovered), len(entries)


def recompute_patched_alert_density(entries: Iterable, *, detector_id: str) -> float:
    """R7-2: RECOMPUTE patched-alert density (flags/KLOC on the fixed tree) by re-running the
    COMMITTED detector over each entry's PATCHED target files. The flag count is EXACTLY
    ``corpus_measure._sink_is_flagged``'s emitted-finding count (the same ``patched_flag_count``
    ``corpus_measure`` reports), summed over every patched target line; density is
    ``flags / (lines / 1000)``. RUN from committed state (registry + :data:`FETCH_FN`), never a
    caller-supplied number, so a certified ``patched_alert_density`` cannot be a free float
    (``DENSITY_UNVERIFIED`` on mismatch). SAFETY (Article III): the patched source is PARSED as
    DATA by ``scan_fn``; it is never executed."""
    scan_fn = resolve_scan_fn(detector_id)
    total_flags = 0
    total_lines = 0
    for entry in entries:
        for path in entry.target_paths:
            patched_source = FETCH_FN(entry.repo, entry.patched_ref, path)
            # R8-1: the patched-tree density must be computed on the EXACT committed pinned bytes.
            _require_committed_bytes(entry, path, entry.patched_ref, patched_source, entry.patched_blob_sha256)
            _, flag_count = corpus_measure._sink_is_flagged(scan_fn, patched_source, path, entry.sink_probe)
            total_flags += flag_count
            total_lines += len(patched_source.splitlines())
    if total_lines == 0:
        return 0.0
    return total_flags / (total_lines / 1000.0)
