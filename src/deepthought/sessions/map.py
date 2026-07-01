"""MAP session — record the in-scope attack surface, READ-ONLY (feature 002).

MAP is the first half of the Improbability Drive's reasoning: it walks the
project's in-scope areas on disk and records what surface exists and how deeply
it was looked at, as ``Coverage`` records. It is strictly read-only:

* It executes nothing. It walks the filesystem with :meth:`pathlib.Path.rglob`
  and never runs, imports, or opens target code as anything but a directory
  listing. There is no code execution and no network transmission here
  (feature 002 is READ-ONLY per the constitution's sequencing).
* It never widens scope. It walks only the areas already in
  ``project.scope_allowlist``; a directory outside the allowlist is never
  visited. An empty allowlist is held at the gate, so ``run`` only ever sees a
  project the gate let proceed.

The output is one ``Coverage`` per in-scope area with ``method='read'`` and a
depth of ``explored`` when files were found or ``touched`` when the area exists
but is empty. The next session (DISCOVER) reasons over the mapped areas.

A project with no resolvable root (no ``root`` argument and no ``local_path``,
or a path that does not exist) must not crash the harness: MAP records the gap
in its next steps and closes clean, so the operator can supply a checkout.
"""

from __future__ import annotations

from pathlib import Path

from ..protocol.gate import GateContext
from ..protocol.session import BaseSession, SessionOutcome
from ..schema import (
    Coverage,
    CoverageDepth,
    CoverageMethod,
    Project,
    SessionType,
)
from ..store import NotFoundError, Store

# Directories a source walk should never descend into: version-control, package,
# and tooling caches. They are huge, irrelevant to the attack surface, and skew
# the file count. Pruned in-place during the walk.
_IGNORED_DIRS = frozenset(
    {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
     ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox"}
)


class MapSession(BaseSession):
    type = SessionType.map

    def __init__(self, project_id: str, root: str | None = None):
        self.project_id = project_id
        # An explicit root overrides the project's local_path (e.g. a fresh
        # checkout at a different location). When None, run() falls back to the
        # project's local_path.
        self.root = root

    def _project(self, store: Store) -> Project:
        project = store.get_project(self.project_id)
        if project is None:
            raise NotFoundError(f"project {self.project_id!r} not found")
        return project

    def build_gate_context(self, store: Store) -> GateContext:
        return GateContext.from_project(self._project(store), self.type)

    def _resolve_root(self, project: Project) -> Path | None:
        """The directory to walk, or None when there is nothing resolvable."""
        candidate = self.root or project.local_path
        if not candidate:
            return None
        path = Path(candidate)
        if not path.is_dir():  # the root must be a directory to walk
            return None
        return path

    def run(self, store: Store, session_id: str) -> SessionOutcome:
        project = self._project(store)
        root = self._resolve_root(project)

        # No resolvable checkout: record the gap and close clean. Do not crash.
        if root is None:
            requested = self.root or project.local_path or "(none)"
            return SessionOutcome(
                summary=(
                    f"Project {project.id!r}: no readable root to map "
                    f"(requested {requested!r}). Recorded no coverage."
                ),
                next_steps=(
                    f"Provide a local checkout for {project.id!r} (set the "
                    f"project's local_path or pass a root), then re-run MAP over "
                    f"the in-scope areas: {', '.join(project.scope_allowlist) or '(none)'}."
                ),
            )

        coverage_refs: list[str] = []
        refused: list[str] = []
        explored = 0
        touched = 0
        # Dedupe the allowlist (preserving order) so a repeated entry is not
        # walked twice or written as a duplicate Coverage record.
        # Normalise padding THEN dedupe, so "src" and " src " collapse to one
        # area (otherwise the same tree is walked and recorded twice).
        for area in dict.fromkeys(a.strip() for a in project.scope_allowlist):
            if not area:
                # A blank entry would resolve to the repository root and map the
                # whole checkout — refuse it, don't silently walk everything.
                refused.append("(blank)")
                continue
            contained_path = self._contained_area(root, area)
            if contained_path is None:
                # The area resolves outside the repository root (absolute path or
                # a ../ escape). Refuse it: never walk it, never record it as
                # covered. Least privilege — MAP cannot widen scope beyond root.
                refused.append(area)
                continue
            files_found = self._count_files(contained_path)
            depth = CoverageDepth.explored if files_found else CoverageDepth.touched
            if files_found:
                explored += 1
            else:
                touched += 1
            coverage = Coverage(
                project=project.id,
                area=area,
                method=CoverageMethod.read,
                depth=depth,
                last_session=session_id,
                body=self._area_body(area, files_found),
            )
            store.save_coverage(coverage)
            coverage_refs.append(coverage.ref)

        refused_note = ""
        if refused:
            refused_note = (
                f" Refused {len(refused)} area(s) that resolve outside the root "
                f"(containment): {', '.join(refused)}."
            )
        summary = (
            f"Mapped {len(coverage_refs)} in-scope area(s) of {project.id!r} "
            f"under {str(root)!r}, read-only: {explored} explored, {touched} "
            f"touched. No code executed; scope unchanged.{refused_note}"
        )
        return SessionOutcome(
            summary=summary,
            next_steps=self._suggest_next(project.scope_allowlist, refused),
            coverage_changed=coverage_refs,
        )

    @staticmethod
    def _contained_area(root: Path, area: str) -> Path | None:
        """Resolve ``area`` under ``root`` iff it stays inside ``root``.

        Returns the resolved path when it is strictly within the repository root,
        else None. An absolute ``area`` (``/etc``) or a parent-traversal
        (``../secret``) resolves outside the root and is refused — MAP never
        reads or records a surface beyond the authorized target root.
        """
        resolved_root = root.resolve()
        try:
            area_root = resolved_root.joinpath(area).resolve()
            area_root.relative_to(resolved_root)
        except (ValueError, RuntimeError, OSError):
            return None
        return area_root

    @staticmethod
    def _count_files(area_root: Path) -> int:
        """Count files under a contained area, READ-ONLY. Zero if it is missing.

        Walks with :meth:`pathlib.Path.walk`, pruning VCS/cache directories; it
        lists directory entries only and never opens or executes any target file.
        Robust to the untrusted filesystem: a scope entry that names a single
        file counts as one, and an unreadable directory or a special file
        (``PermissionError``/``OSError``) is skipped rather than crashing.
        """
        try:
            if area_root.is_file():
                return 1  # a scope entry may name a file, not only a directory
            if not area_root.is_dir():
                return 0  # missing, or a special/unreadable entry
        except OSError:
            return 0

        # Walk with in-place pruning (Path.walk, 3.12+) so we never descend into
        # .git/.venv/node_modules/etc. — huge, irrelevant, and count-skewing.
        # on_error=None ignores unreadable directories rather than crashing.
        count = 0
        try:
            for _dirpath, dirnames, filenames in area_root.walk(on_error=None):
                dirnames[:] = [d for d in dirnames if d not in _IGNORED_DIRS]
                count += len(filenames)
        except OSError:
            pass  # unreadable subtree — count what we could reach
        return count

    @staticmethod
    def _area_body(area: str, files_found: int) -> str:
        if files_found:
            return (
                f"Read-only map of `{area}`: {files_found} file(s) present. "
                f"Surface recorded; nothing executed. DISCOVER next."
            )
        return (
            f"Read-only map of `{area}`: no files found (area missing or empty). "
            f"Touched only."
        )

    @staticmethod
    def _suggest_next(scope_allowlist: list[str], refused: list[str]) -> str:
        areas = ", ".join(scope_allowlist) or "(none)"
        step = (
            f"Run a DISCOVER session over the mapped in-scope areas ({areas}) to "
            f"reason over code and any SARIF for candidate findings."
        )
        if refused:
            step += (
                f" Fix {len(refused)} scope entry(ies) that resolve outside the "
                f"root and were refused: {', '.join(refused)}."
            )
        return step
