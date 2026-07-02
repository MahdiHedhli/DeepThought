"""NEW PROJECT session — register a target under an authorization basis.

The lowest-risk session type. It may run before a project exists. It refuses an
unresolvable git URL, defers authorization and scope refusals to the Gate, and
resolves to the same project on a repeat rather than creating a duplicate.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from pathlib import Path

from ..protocol.gate import GateContext
from ..protocol.session import BaseSession, SessionOutcome
from ..schema import (
    AuthorizationBasis,
    Project,
    ProjectStatus,
    SessionType,
    SourceType,
)
from ..schema.common import is_record_id, safe_record_id
from ..store import DuplicateProjectError, Store


def default_verify_git_url(url: str) -> bool:
    """Whether a git URL resolves. Uses ``git ls-remote`` with a short timeout.

    A ``local_path`` is resolved by existence. Injected in tests so no network
    is required there.
    """
    if not url:
        return False
    # A url starting with ``-`` would be parsed by git as an OPTION, not a
    # repository (argument injection — e.g. ``--upload-pack=<cmd>`` runs a
    # command). Refuse it outright, and pass the url only after a ``--`` options
    # terminator so it is always a positional argument.
    if url.startswith("-"):
        return False
    local = Path(url)
    if local.exists():
        return True
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--exit-code", "--", url, "HEAD"],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def derive_project_id(name: str, git_url: str | None, local_path: str | None) -> str:
    # The derived id becomes ``Project.id`` (a RecordId), so it must be a single
    # safe path segment: ``safe_record_id`` normalises the repo/local tail (trims
    # the leading/trailing punctuation the pattern forbids and bounds the length)
    # so a tail like ``_repo``/``repo.`` or an over-long name can't crash the NEW
    # PROJECT flow with a validation error.
    source = git_url or local_path or name
    tail = source.rstrip("/").split("/")[-1]
    tail = re.sub(r"\.git$", "", tail)
    return safe_record_id(tail.lower(), fallback="project")


class NewProjectSession(BaseSession):
    type = SessionType.new_project
    # A NEW PROJECT session is not tied to an existing project id; the session
    # log links to the project only through its written summary, so a refused
    # registration never leaves an orphan reference.
    project_id = None

    def __init__(
        self,
        *,
        name: str,
        source_type: SourceType | str,
        git_url: str | None = None,
        local_path: str | None = None,
        authorization_basis: AuthorizationBasis | str | None = None,
        authorization_ref: str | None = None,
        scope_allowlist: list[str] | None = None,
        project_id: str | None = None,
        notes: str = "",
        verify_url: Callable[[str], bool] = default_verify_git_url,
    ):
        self.name = name
        self.source_type = SourceType(source_type)
        self.git_url = git_url
        self.local_path = local_path
        self.authorization_basis = (
            AuthorizationBasis(authorization_basis) if authorization_basis else None
        )
        self.authorization_ref = authorization_ref
        self.scope_allowlist = list(scope_allowlist or [])
        self.explicit_id = project_id
        self.notes = notes
        self.verify_url = verify_url

    def build_gate_context(self, store: Store) -> GateContext:
        # Evaluate the proposed registration; the project may not exist yet.
        return GateContext(
            session_type=self.type,
            source_type=self.source_type,
            authorization_basis=self.authorization_basis,
            authorization_ref=self.authorization_ref,
            scope_allowlist=self.scope_allowlist,
        )

    def run(self, store: Store, session_id: str) -> SessionOutcome:
        # An explicit project id (CLI --project-id) is used verbatim as Project.id
        # (a RecordId); reject an unsafe value cleanly rather than let Project(...)
        # raise a bare ValidationError below. A derived id is always normalised
        # (safe_record_id), so only the explicit override needs this guard.
        if self.explicit_id is not None and not is_record_id(self.explicit_id):
            return SessionOutcome(
                summary=f"Refused: invalid project id {self.explicit_id!r}.",
                next_steps="Provide a valid project id — a single safe path segment.",
            )

        # Resolve to one project on a repeat — never create a duplicate.
        existing = store.resolve_project(
            git_url=self.git_url, local_path=self.local_path
        )
        if existing is not None:
            return SessionOutcome(
                summary=(
                    f"Project {existing.id!r} already registered for "
                    f"{existing.identity!r}; resolved to the existing record."
                ),
                next_steps=f"Run a STATUS session on {existing.id!r} to review state.",
            )

        # Refuse an unresolvable git URL before writing anything.
        identity = self.git_url or self.local_path
        if self.git_url and not self.verify_url(self.git_url):
            return SessionOutcome(
                summary=f"Refused: git URL {self.git_url!r} does not resolve.",
                next_steps="Provide a resolvable git_url or a local_path, then retry.",
            )

        project = Project(
            id=self.explicit_id
            or derive_project_id(self.name, self.git_url, self.local_path),
            name=self.name,
            source_type=self.source_type,
            git_url=self.git_url,
            local_path=self.local_path,
            authorization_basis=self.authorization_basis,
            authorization_ref=self.authorization_ref,
            scope_allowlist=self.scope_allowlist,
            status=ProjectStatus.active,
            body=self.notes or f"Registered target {identity!r}.",
        )
        try:
            store.save_project(project)
        except DuplicateProjectError as exc:
            # A different project already holds this (derived) id — refuse rather
            # than clobber it. resolve_project above already handled the same
            # identity, so this is a genuine id collision.
            return SessionOutcome(
                summary=f"Refused: {exc}.",
                next_steps=(
                    "Two distinct targets derive the same project id; pass an "
                    "explicit project_id to disambiguate, then retry."
                ),
            )
        return SessionOutcome(
            summary=(
                f"Registered project {project.id!r} ({self.source_type.value}) with "
                f"basis {self.authorization_basis.value if self.authorization_basis else None} "
                f"and {len(self.scope_allowlist)} scope entr"
                f"{'y' if len(self.scope_allowlist) == 1 else 'ies'}."
            ),
            next_steps=(
                f"Run a STATUS session on {project.id!r}; then map the in-scope "
                f"surface: {', '.join(self.scope_allowlist) or '(none)'}."
            ),
        )
