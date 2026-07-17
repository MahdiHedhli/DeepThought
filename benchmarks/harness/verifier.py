"""The numerator VERIFIER — re-run the frozen detector on the real pinned SHAs (008, round 4).

An audit proved the irreducible floor a pure validator cannot verify: it cannot
check that the reported numerator (which blind cases were "rediscovered") is TRUE,
because it never sees the detector run on the real code — it only sees a claimed
count. This module closes that gap for the numerator: given the frozen detector and
the pinned corpus SHAs, it RECOMPUTES the rediscovery set from the actual target
files and hands it to ``contract.validate(..., recomputed_rediscovered=...)``, which
refuses certification (``NUMERATOR_UNVERIFIED``) unless the reported set MATCHES the
recompute. An operator can no longer CLAIM a rediscovery the detector did not produce
on the real code, nor OMIT a real one.

The rediscovery rule is EXACTLY ``corpus_measure.py``'s line-precise rule (imported,
never reimplemented): a FLAGGED line whose OWN text contains the ``sink_probe`` in the
VULNERABLE tree and NOT in the PATCHED tree. Fetching reuses ``corpus_measure.py``'s
GitHub-raw fetcher (cached under ``benchmarks/.cache``); both are INJECTED
(``fetch_fn`` / ``scan_fn``) so unit tests are deterministic and hermetic and only the
one real-re-run integration test touches the network.

SAFETY (Article III): the detector is OUR static analyzer. ``scan_fn`` (a real
detector's ``scan_source``) PARSES the fetched source as DATA — e.g. ``ast.parse`` —
and NEVER executes it. This module must never ``eval`` / ``exec`` / ``import`` fetched
content; no target code is run, so there is no Article III sandbox concern.
"""

from __future__ import annotations

from typing import Callable, Iterable

import corpus_measure  # reuse the EXACT fetcher + line-precise rule; do not reimplement

# (repo, ref, path) -> source text. In production this is ``corpus_measure.fetch``;
# tests inject a canned dict-backed fake.
FetchFn = Callable[[str, str, str], str]
# (source, uri) -> SARIF-ish list of finding dicts. This is the frozen detector's
# ``scan_source``; tests inject a canned fake.
ScanFn = Callable[[str, str], list]


def _entry_rediscovered(entry, fetch_fn: FetchFn, scan_fn: ScanFn) -> bool:
    """Line-precise rediscovery for one entry over ALL its target paths, using the EXACT
    ``corpus_measure._sink_is_flagged`` rule: the sink is rediscovered iff a FLAGGED
    line's own text contains the probe in the VULN tree and NOT in the PATCHED tree.

    ``entry`` is a ``CohortEntry`` (``.repo`` / ``.vuln_ref`` / ``.patched_ref`` /
    ``.target_paths`` / ``.sink_probe``). The fetched source is read as DATA only."""
    probe = entry.sink_probe
    vuln_hit = patched_hit = False
    for path in entry.target_paths:
        vuln_source = fetch_fn(entry.repo, entry.vuln_ref, path)
        patched_source = fetch_fn(entry.repo, entry.patched_ref, path)
        # corpus_measure._sink_is_flagged(scan, source, uri, probe) -> (hit, flag_count)
        vuln_flagged, _ = corpus_measure._sink_is_flagged(scan_fn, vuln_source, path, probe)
        patched_flagged, _ = corpus_measure._sink_is_flagged(scan_fn, patched_source, path, probe)
        vuln_hit = vuln_hit or vuln_flagged
        patched_hit = patched_hit or patched_flagged
    return bool(vuln_hit and not patched_hit)


def recompute_rediscovered(blind_entries: Iterable, *, fetch_fn: FetchFn, scan_fn: ScanFn) -> set[str]:
    """Recompute the set of rediscovered BLIND entry-identity hashes by re-running the
    frozen detector on the real pinned code.

    Pure function of ``(blind_entries, fetch_fn, scan_fn)`` — deterministic given the
    injected fetch/scan. For each entry, fetch the vuln + patched target files and apply
    the line-precise rule; the entry's ``computed_identity_hash`` joins the returned set
    iff its sink is rediscovered. Feed the result to
    ``contract.validate(..., recomputed_rediscovered=<this set>, strict=True)``."""
    rediscovered: set[str] = set()
    for entry in blind_entries:
        if _entry_rediscovered(entry, fetch_fn, scan_fn):
            rediscovered.add(entry.computed_identity_hash)
    return rediscovered
