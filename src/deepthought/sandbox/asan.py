"""Parse an AddressSanitizer report into a typed, bounded :class:`CrashReport`.

VERIFY turns a sandboxed crash into evidence. This extracts the error class, the
faulting access, and the top symbolized stack frames from otherwise
target-controlled sanitizer text, and computes a stable dedup key from the first
few frames so the same crash is recognized across runs. It parses text only — it
executes nothing.
"""

from __future__ import annotations

import hashlib
import re

from .base import CrashReport

_ERR = re.compile(r"ERROR:\s+(AddressSanitizer):\s+([a-z0-9\-]+)")
_ACCESS = re.compile(r"\b(READ|WRITE) of size (\d+)\b")
# A SYMBOLIZED frame: ``#N 0x… in <function> <file:line[:col]>``. An unsymbolized
# frame (``#N 0x… (/lib/...)``) has no ``in <func> <file:line>`` and is skipped.
_FRAME = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+([^\s(]+:\d+(?::\d+)?)")


def parse_asan(text: str) -> CrashReport | None:
    """Return a :class:`CrashReport` for an ASan report, or ``None`` if the text
    carries no ASan error (a clean run)."""
    err = _ERR.search(text)
    if not err:
        return None

    access = _ACCESS.search(text)
    frames = _FRAME.findall(text)  # list of (function, file:line)
    # Slice to the CrashReport field caps: sanitizer output is target-controlled,
    # and a long C++ symbol (templates) could exceed the bound — truncate rather
    # than raise a ValidationError on an otherwise-valid crash.
    top = [f"{fn} {loc}"[:128] for fn, loc in frames[:8]]
    faulting_fn, faulting_loc = frames[0] if frames else ("", "")

    dedup_source = "|".join(top[:3]) or f"{err.group(2)}:{faulting_loc}"
    dedup_key = hashlib.sha256(dedup_source.encode("utf-8")).hexdigest()[:16]

    return CrashReport(
        sanitizer="AddressSanitizer",
        error_type=err.group(2)[:128],
        access=(access.group(1) if access else "")[:128],
        access_size=int(access.group(2)) if access else None,
        faulting_function=faulting_fn[:128],
        faulting_location=faulting_loc[:512],
        top_frames=top,
        dedup_key=dedup_key,
    )
