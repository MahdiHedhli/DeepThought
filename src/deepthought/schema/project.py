"""Project record.

A Project is a target under research. It carries the authorization basis and the
scope allowlist that the Gate reads before any session runs. Identity is the
``git_url`` or ``local_path``; the Store never creates a duplicate for the same
identity.
"""

from __future__ import annotations

from enum import Enum

from pydantic import model_validator

from .common import Record, RecordId


class SourceType(str, Enum):
    open_source = "open_source"
    blackbox = "blackbox"


class AuthorizationBasis(str, Enum):
    own_code = "own_code"
    permissive_oss = "permissive_oss"
    scoped_engagement = "scoped_engagement"


class ProjectStatus(str, Enum):
    active = "active"
    paused = "paused"
    closed = "closed"


class Project(Record):
    id: RecordId
    name: str
    source_type: SourceType
    git_url: str | None = None
    local_path: str | None = None
    # Optional so a project registered without a basis can exist; the Gate is
    # what refuses a session against it. Absence is meaningful, not malformed.
    authorization_basis: AuthorizationBasis | None = None
    # Required when the basis is scoped_engagement (validated below). Also the
    # field the Gate demands for a blackbox target.
    authorization_ref: str | None = None
    # Empty means nothing is in scope, not everything.
    scope_allowlist: list[str] = []
    status: ProjectStatus = ProjectStatus.active

    @model_validator(mode="after")
    def _identity_present(self) -> "Project":
        if not self.git_url and not self.local_path:
            raise ValueError("project requires a git_url or a local_path for identity")
        return self

    @model_validator(mode="after")
    def _scoped_engagement_needs_ref(self) -> "Project":
        if (
            self.authorization_basis is AuthorizationBasis.scoped_engagement
            and not self.authorization_ref
        ):
            raise ValueError(
                "authorization_ref is required when authorization_basis is scoped_engagement"
            )
        return self

    @property
    def identity(self) -> str:
        """The value on which Store resolves duplicate identity."""
        return self.git_url or self.local_path or ""
