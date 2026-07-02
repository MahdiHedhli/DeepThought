"""FileStore — the files-in-git implementation of the Store.

Each record is one Markdown file with YAML front-matter. Writes are the model's
``to_markdown()`` output, so diffs are clean text a reviewer can read from the
repository alone. The lifecycle guard is enforced here, at the boundary.
"""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from ..schema import (
    Coverage,
    Finding,
    FindingStatus,
    Methodology,
    Project,
    Session,
)
from ..schema.common import is_record_id, iso_z, utcnow
from ..schema.loop import LoopRun

# A record id is a single safe path segment (findings/<id>.md). Record MODELS
# enforce this on construction, but the ``get_*`` lookups take a RAW string
# argument that is never model-validated — so an id with ``..`` or a separator
# would traverse out of the store on READ. This guard refuses such an argument
# (the lookup returns "not found") — defence in depth at the path boundary. It
# shares ``is_record_id`` with the schema so the guard and the model agree
# exactly (including rejecting a trailing newline).
_safe_id = is_record_id
from ..schema.finding import TransitionLogEntry
from .base import (
    BACKWARD_EDGES,
    FORWARD_EDGES,
    DuplicateProjectError,
    NotFoundError,
    RawRecord,
    Store,
    TransitionResult,
)


# Keep the slug (plus the ".md" suffix) well under the common 255-char filename
# limit. A quoted value longer than this is truncated and disambiguated with a
# hash of the ORIGINAL value, which keeps it injective and filesystem-safe.
_SLUG_MAX = 200


def _slug(value: str) -> str:
    """Injective, filesystem-safe filename for a coverage area.

    Percent-encodes every path separator and unsafe character, so distinct areas
    never collide (``ext/soap`` vs ``ext-soap`` — the old ``/``→``-`` slug mapped
    both to ``ext-soap.md``, silently overwriting one) and no area can escape the
    coverage directory via a ``/`` or ``\\`` in its name. A simple area like
    ``ext-soap`` is unchanged, so existing records keep their filenames. A very
    long (or heavily-encoded) area is bounded to avoid a "File name too long"
    error, staying injective via a hash of the original value.
    """
    quoted = quote(value, safe="") or "_"
    if len(quoted) > _SLUG_MAX:
        # Non-cryptographic use (filename dedup); usedforsecurity=False keeps it
        # available under FIPS, where SHA-1 for security is blocked.
        digest = hashlib.sha1(value.encode("utf-8"), usedforsecurity=False).hexdigest()[:16]
        quoted = f"{quoted[: _SLUG_MAX - len(digest) - 1]}-{digest}"
    return quoted


class FileStore(Store):
    def __init__(self, root: str | Path):
        self.root = Path(root)
        for sub in ("projects", "findings", "sessions", "coverage", "methodology", "loop", "detail"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)

    # --- low-level file IO ----------------------------------------------
    def _write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _read(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    # --- Project ---------------------------------------------------------
    def save_project(self, project: Project) -> Project:
        # Identity resolves on git_url or local_path; never create a duplicate,
        # and never silently overwrite a DIFFERENT project that happens to share an
        # id (two distinct identities can derive/claim the same id — e.g. ``_repo``
        # and ``repo`` both normalise to ``repo``). Same id + same identity is a
        # normal update and is allowed through.
        for existing in self.list_projects():
            if existing.id != project.id and existing.identity == project.identity:
                raise DuplicateProjectError(
                    f"project identity {project.identity!r} already registered as "
                    f"{existing.id!r}"
                )
            if existing.id == project.id and existing.identity != project.identity:
                raise DuplicateProjectError(
                    f"project id {project.id!r} already registered for a different "
                    f"identity {existing.identity!r}"
                )
        self._write(self.root / "projects" / f"{project.id}.md", project.to_markdown())
        return project

    def get_project(self, project_id: str) -> Project | None:
        if not _safe_id(project_id):
            return None
        path = self.root / "projects" / f"{project_id}.md"
        if not path.exists():
            return None
        return Project.from_markdown(self._read(path))

    def list_projects(self) -> list[Project]:
        out = []
        for path in sorted((self.root / "projects").glob("*.md")):
            out.append(Project.from_markdown(self._read(path)))
        return out

    def resolve_project(
        self, *, git_url: str | None = None, local_path: str | None = None
    ) -> Project | None:
        identity = git_url or local_path
        if not identity:
            return None
        for project in self.list_projects():
            if project.identity == identity:
                return project
        return None

    # --- Finding ---------------------------------------------------------
    def save_finding(self, finding: Finding) -> Finding:
        self._write(self.root / "findings" / f"{finding.id}.md", finding.to_markdown())
        return finding

    def get_finding(self, finding_id: str) -> Finding | None:
        if not _safe_id(finding_id):
            return None
        path = self.root / "findings" / f"{finding_id}.md"
        if not path.exists():
            return None
        return Finding.from_markdown(self._read(path))

    def list_findings(self, project: str | None = None) -> list[Finding]:
        out = []
        for path in sorted((self.root / "findings").glob("*.md")):
            finding = Finding.from_markdown(self._read(path))
            if project is None or finding.project == project:
                out.append(finding)
        return out

    def transition_finding(
        self, finding_id: str, new_status: FindingStatus
    ) -> TransitionResult:
        finding = self.get_finding(finding_id)
        if finding is None:
            raise NotFoundError(f"finding {finding_id!r} not found")

        new_status = FindingStatus(new_status)
        old = finding.status
        allowed, reason, backward = self._evaluate_transition(finding, new_status)

        entry = TransitionLogEntry(
            at=iso_z(utcnow()),
            from_status=old.value,
            to_status=new_status.value,
            accepted=allowed,
            reason=reason,
        )
        finding.transition_log.append(entry)

        if allowed:
            finding.status = new_status
            self.save_finding(finding)
            return TransitionResult(ok=True, status=new_status, reason=reason)

        # Rejected: record the blocking reason on the finding, status unchanged.
        self.save_finding(finding)
        return TransitionResult(ok=False, status=old, reason=reason)

    def _evaluate_transition(
        self, finding: Finding, new_status: FindingStatus
    ) -> tuple[bool, str | None, bool]:
        old = finding.status
        if old == new_status:
            return True, "no-op transition", False

        edge = (old, new_status)
        if edge in BACKWARD_EDGES:
            return True, "backward transition: evidence weakened", True
        if edge not in FORWARD_EDGES:
            return (
                False,
                f"illegal transition {old.value} -> {new_status.value}",
                False,
            )

        # Forward edge: enforce the entry guard.
        if edge == (FindingStatus.candidate, FindingStatus.verified):
            if not finding.evidence_ref:
                return False, "candidate -> verified requires a non-empty evidence_ref", False
            if not self.detail_exists(finding.evidence_ref):
                return (
                    False,
                    f"evidence_ref {finding.evidence_ref!r} does not resolve",
                    False,
                )
            return True, None, False

        if edge == (FindingStatus.verified, FindingStatus.disclosed):
            if not finding.cve:
                return False, "verified -> disclosed requires a cve", False
            if not finding.has_reference_type("advisory"):
                return (
                    False,
                    "verified -> disclosed requires an advisory reference",
                    False,
                )
            return True, None, False

        if edge == (FindingStatus.verified, FindingStatus.patched):
            if not finding.cve:
                return False, "verified -> patched requires a cve", False
            if not finding.has_reference_type("fix"):
                return False, "verified -> patched requires a fix reference", False
            return True, None, False

        return False, f"unhandled transition {old.value} -> {new_status.value}", False

    # --- Session ---------------------------------------------------------
    def save_session(self, session: Session) -> Session:
        self._write(self.root / "sessions" / f"{session.id}.md", session.to_markdown())
        return session

    def get_session(self, session_id: str) -> Session | None:
        if not _safe_id(session_id):
            return None
        path = self.root / "sessions" / f"{session_id}.md"
        if not path.exists():
            return None
        return Session.from_markdown(self._read(path))

    def list_sessions(self, project: str | None = None) -> list[Session]:
        out = []
        for path in sorted((self.root / "sessions").glob("*.md")):
            session = Session.from_markdown(self._read(path))
            if project is None or session.project == project:
                out.append(session)
        return out

    # --- Loop run (feature 006) ------------------------------------------
    def save_loop_run(self, run: LoopRun) -> LoopRun:
        self._write(self.root / "loop" / f"{run.id}.md", run.to_markdown())
        return run

    def get_loop_run(self, run_id: str) -> LoopRun | None:
        if not _safe_id(run_id):
            return None
        path = self.root / "loop" / f"{run_id}.md"
        if not path.exists():
            return None
        return LoopRun.from_markdown(self._read(path))

    def list_loop_runs(self, project: str | None = None) -> list[LoopRun]:
        out = []
        for path in sorted((self.root / "loop").glob("*.md")):
            run = LoopRun.from_markdown(self._read(path))
            if project is None or run.project == project:
                out.append(run)
        return out

    # --- Coverage --------------------------------------------------------
    def _coverage_path(self, project: str, area: str) -> Path:
        return self.root / "coverage" / project / f"{_slug(area)}.md"

    def _legacy_coverage_path(self, project: str, area: str) -> Path:
        # The pre-percent-encoding slug (``/``/``\`` -> ``-``). Kept only so a
        # store written by the old code upgrades cleanly instead of duplicating.
        legacy = area.replace("/", "-").replace("\\", "-").strip("-")
        return self.root / "coverage" / project / f"{legacy}.md"

    def save_coverage(self, coverage: Coverage) -> Coverage:
        path = self._coverage_path(coverage.project, coverage.area)
        self._write(path, coverage.to_markdown())
        # Migrate: drop a stale record THIS area wrote under the old slug, so an
        # upgraded store does not keep two files for it. Only remove the legacy
        # file if it genuinely holds this same area — never a different area whose
        # own (new-slug) filename happens to equal this area's legacy filename
        # (e.g. real `ext-soap` vs legacy of `ext/soap`).
        legacy = self._legacy_coverage_path(coverage.project, coverage.area)
        if legacy != path and legacy.exists():
            try:
                existing = Coverage.from_markdown(self._read(legacy))
            except Exception:
                existing = None
            if existing is not None and existing.area == coverage.area:
                try:
                    legacy.unlink()
                except OSError:
                    pass  # cleanup only — a locked/undeletable legacy file must
                    # not fail the primary write that already succeeded.
        return coverage

    def get_coverage(self, project: str, area: str) -> Coverage | None:
        if not _safe_id(project):
            return None
        path = self._coverage_path(project, area)
        if path.exists():
            return Coverage.from_markdown(self._read(path))
        # Fall back to the old slug so a direct lookup still resolves on a
        # not-yet-migrated store — but ONLY if that file genuinely holds THIS
        # area. The old slug is lossy (ext-soap.md could be the record for a
        # different area), so returning it blindly would reintroduce the
        # collision the percent-encoded slug removes.
        legacy = self._legacy_coverage_path(project, area)
        if legacy == path or not legacy.exists():
            return None
        try:
            candidate = Coverage.from_markdown(self._read(legacy))
        except Exception:
            return None  # a corrupt/malformed legacy file is not a valid record
        return candidate if (candidate is not None and candidate.area == area) else None

    def list_coverage(self, project: str | None = None) -> list[Coverage]:
        # A project filter is used verbatim as a path segment (coverage/<project>),
        # so — like get_coverage — refuse a traversal/unsafe value rather than glob
        # (and try to parse) files outside the coverage directory.
        if project is not None and not _safe_id(project):
            return []
        out = []
        base = self.root / "coverage"
        globber = base.glob("*/*.md") if project is None else (base / project).glob("*.md")
        for path in sorted(globber):
            out.append(Coverage.from_markdown(self._read(path)))
        return out

    # --- Methodology -----------------------------------------------------
    def save_methodology(self, methodology: Methodology) -> Methodology:
        self._write(
            self.root / "methodology" / f"{methodology.id}.md",
            methodology.to_markdown(),
        )
        return methodology

    def get_methodology(self, methodology_id: str) -> Methodology | None:
        if not _safe_id(methodology_id):
            return None
        path = self.root / "methodology" / f"{methodology_id}.md"
        if not path.exists():
            return None
        return Methodology.from_markdown(self._read(path))

    def list_methodology(self) -> list[Methodology]:
        out = []
        for path in sorted((self.root / "methodology").glob("*.md")):
            out.append(Methodology.from_markdown(self._read(path)))
        return out

    # --- Detail ----------------------------------------------------------
    def write_detail(self, session_id: str, name: str, content: str) -> str:
        ref = f"detail/{session_id}/{name}"
        self._write(self.root / "detail" / session_id / name, content)
        return ref

    def _detail_path(self, ref: str) -> Path | None:
        """Resolve a ``detail/...`` ref to a path inside the ``detail/`` tree, or
        ``None``.

        Two independent guards, because the ref can be derived from a (possibly
        tampered) session id:

        * LEXICAL — the ref must name the ``detail/`` subtree with no ``..``
          component, so it can neither escape (``detail/../../secret``) nor
          re-enter another store subtree (``detail/../projects/<id>.md``). This
          keeps the candidate -> verified evidence gate pointed at real detail
          artifacts only.
        * PHYSICAL — the RESOLVED target must stay under the CANONICAL detail dir:
          the resolved store root joined with ``detail`` WITHOUT following a
          symlink on that component. This closes the whole symlink class at once —
          a ``detail`` dir symlinked anywhere (outside the store, an in-store
          sibling like ``projects``, or the root via ``.``) resolves the target
          outside the canonical anchor, as does a symlink *inside* detail that
          re-enters a sibling subtree (``detail/x -> ../projects``).
        """
        rel = ref[len("state/") :] if ref.startswith("state/") else ref
        parts = PurePosixPath(rel).parts
        if not parts or parts[0] != "detail" or ".." in parts:
            return None
        detail_base = self.root.resolve() / "detail"
        target = (self.root / rel).resolve()
        if target != detail_base and detail_base not in target.parents:
            return None
        return target

    def detail_exists(self, ref: str) -> bool:
        # ``is_file`` (not ``exists``) so a DIRECTORY ref — the detail base or a
        # session subdir, which exist after any write_detail — is not mistaken for
        # an artifact. This keeps the check consistent with read_detail, so the
        # candidate -> verified evidence gate needs a real file, not a directory.
        path = self._detail_path(ref)
        return path is not None and path.is_file()

    def read_detail(self, ref: str) -> str | None:
        path = self._detail_path(ref)
        if path is None or not path.is_file():
            return None
        return path.read_text(encoding="utf-8")

    # --- Consistency (for check) -----------------------------------------
    def raw_records(self) -> list[RawRecord]:
        out: list[RawRecord] = []
        globs = {
            "project": (self.root / "projects").glob("*.md"),
            "finding": (self.root / "findings").glob("*.md"),
            "session": (self.root / "sessions").glob("*.md"),
            "coverage": (self.root / "coverage").glob("*/*.md"),
            "methodology": (self.root / "methodology").glob("*.md"),
            "loop": (self.root / "loop").glob("*.md"),
        }
        for kind, paths in globs.items():
            for path in sorted(paths):
                out.append(
                    RawRecord(
                        kind=kind,
                        ident=str(path.relative_to(self.root)),
                        text=self._read(path),
                    )
                )
        return out
