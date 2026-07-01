"""Shared, security-critical path containment.

Both the SARIF ingest and the read-only sessions (MAP, DISCOVER) must refuse a
path that escapes the target root — an absolute path, a backslash path, a ``..``
traversal, or (against a real checkout) a symlinked component that resolves
outside the root. This lives at the package top level so both ``ingest`` and
``sessions`` can import it without a circular dependency.
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
    backslash, and ``..``-traversal areas syntactically first, then resolves
    (following any symlinks) and requires the result to stay under the root — so
    a symlinked component that escapes the tree is refused.
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
