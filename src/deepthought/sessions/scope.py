"""Shared, security-critical scope containment for the read-only sessions.

Both MAP and DISCOVER must refuse a scope area that escapes the target root
(an absolute path, a backslash path, or a ``..`` traversal). Keeping the check
in one place means the two sessions cannot drift apart on a security-critical
rule.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath


def _syntactically_safe(area: str) -> bool:
    """Reject escapes that POSIX path resolution would NOT catch.

    A backslash is a valid POSIX filename character, so ``..\\secret`` or
    ``C:\\secret`` would otherwise resolve to an in-tree file rather than being
    refused. Absolute paths and ``..`` traversal are rejected here too, before
    any resolution.
    """
    if not area or area.startswith("/") or "\\" in area:
        return False
    pp = PurePosixPath(area)
    if pp.is_absolute() or ".." in pp.parts:
        return False
    return True


def resolve_within(root: Path, area: str) -> Path | None:
    """Resolve ``area`` under ``root`` iff it stays strictly inside ``root``.

    Returns the resolved path when it is contained, else None. Rejects absolute,
    backslash, and ``..``-traversal areas syntactically first (so a backslash
    entry cannot pass as an in-tree filename), then requires the resolved path to
    stay under the root.
    """
    if not _syntactically_safe(area):
        return None
    resolved_root = root.resolve()
    try:
        area_root = resolved_root.joinpath(area).resolve()
        area_root.relative_to(resolved_root)
    except (ValueError, RuntimeError, OSError):
        return None
    return area_root


def area_in_scope(area: str, root: Path | None) -> bool:
    """Whether a scope area stays inside the target.

    Applies the same syntactic refusals as :func:`resolve_within` (with or
    without a root); when a checkout root resolves, also requires the area to
    resolve strictly inside it.
    """
    if not _syntactically_safe(area):
        return False
    if root is not None:
        return resolve_within(root, area) is not None
    return True
