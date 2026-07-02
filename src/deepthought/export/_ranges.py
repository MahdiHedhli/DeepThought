"""Shared OSV-range -> human-readable label mapping for the disclosure exporters.

An ``AffectedPackage.ranges`` entry is OSV-shaped (a ``type`` plus ordered
``events`` of ``introduced`` / ``fixed`` / ``last_affected``). CSAF and the
human-readable advisory both render those bounds as a readable string (e.g.
``>=1.0, <2.0``); keeping the mapping here means both agree. The structured CVE
mapping (to ``lessThan`` / ``lessThanOrEqual`` version entries) stays in
``cve.py`` because it is CVE-schema-specific.
"""

from __future__ import annotations


def _tok(value: object, fallback: str) -> str:
    text = str(value).strip() if value is not None else ""
    return text or fallback


def range_labels(ranges: list) -> list[str]:
    """Readable version-range labels from OSV-style ``ranges``, deduped.

    Each range's ``introduced`` / ``fixed`` / ``last_affected`` events become a
    readable bound string, so range-only affected scope is preserved rather than
    dropped. A range with no recognizable events yields no label.
    """
    labels: list[str] = []
    for rng in ranges or []:
        if not isinstance(rng, dict):
            continue
        parts: list[str] = []
        for event in rng.get("events") or []:
            if not isinstance(event, dict):
                continue
            if "introduced" in event:
                parts.append(f">={_tok(event['introduced'], '0')}")
            elif "fixed" in event:
                parts.append(f"<{_tok(event['fixed'], '?')}")
            elif "last_affected" in event:
                parts.append(f"<={_tok(event['last_affected'], '?')}")
        label = ", ".join(parts).strip()
        if label:
            labels.append(label)
    return list(dict.fromkeys(labels))
