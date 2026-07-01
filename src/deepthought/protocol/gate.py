"""Gate — the pre-dispatch authorization and scope check (Constitution I & II).

Every session passes the Gate before any work. There are three outcomes:
``proceed``, ``hold``, ``refuse``. A hold or refuse always carries a reason,
which the session records.

The platform reuses HermesUltraCode as the real gate and observability layer;
the platform adapts to it through this interface rather than rebuilding it.
``HermesUltraCodeGate`` here is the adapter stub: it enforces the authorization
and scope rules locally so 001 is testable, with a single seam where the real
HermesUltraCode call is wired once its interface is confirmed (Phase 0).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..schema import (
    AuthorizationBasis,
    GateOutcome,
    Project,
    SessionType,
    SourceType,
)


@dataclass(frozen=True)
class GateContext:
    """What the Gate evaluates.

    For a NEW PROJECT session this describes the *proposed* registration (a
    project may not exist yet). For every other session it is built from the
    stored Project.
    """

    session_type: SessionType
    source_type: SourceType | None = None
    authorization_basis: AuthorizationBasis | None = None
    authorization_ref: str | None = None
    scope_allowlist: list[str] = field(default_factory=list)
    project_id: str | None = None

    @classmethod
    def from_project(cls, project: Project, session_type: SessionType) -> "GateContext":
        return cls(
            session_type=session_type,
            source_type=project.source_type,
            authorization_basis=project.authorization_basis,
            authorization_ref=project.authorization_ref,
            scope_allowlist=list(project.scope_allowlist),
            project_id=project.id,
        )


@dataclass(frozen=True)
class GateDecision:
    outcome: GateOutcome
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.outcome in (GateOutcome.hold, GateOutcome.refuse) and not self.reason:
            raise ValueError(f"a {self.outcome.value} decision must carry a reason")

    @property
    def proceeds(self) -> bool:
        return self.outcome is GateOutcome.proceed


class Gate(ABC):
    @abstractmethod
    def evaluate(self, context: GateContext) -> GateDecision:
        """Return proceed, hold, or refuse for the given session context."""


class HermesUltraCodeGate(Gate):
    """Adapter stub for the HermesUltraCode pre-dispatch gate.

    Enforces the Constitution's authorization and scope rules. The real adapter
    will delegate to HermesUltraCode; the decision contract (three outcomes,
    reasons logged) is what the rest of the platform depends on and does not
    change when the backing implementation is swapped in.
    """

    def evaluate(self, context: GateContext) -> GateDecision:
        # Article II: a session against a project with no authorization basis is
        # refused at the gate.
        if context.authorization_basis is None:
            return GateDecision(
                GateOutcome.refuse,
                "no authorization basis; refused per Constitution Article II",
            )

        # A blackbox target with no engagement reference is refused.
        if context.source_type is SourceType.blackbox and not context.authorization_ref:
            return GateDecision(
                GateOutcome.refuse,
                "blackbox target requires an authorization_ref",
            )

        # A scoped engagement must name its authorization reference.
        if (
            context.authorization_basis is AuthorizationBasis.scoped_engagement
            and not context.authorization_ref
        ):
            return GateDecision(
                GateOutcome.refuse,
                "scoped_engagement requires an authorization_ref",
            )

        # Empty scope means nothing is in scope, not everything. Hold rather than
        # silently proceed with an undefined surface.
        if not context.scope_allowlist:
            return GateDecision(
                GateOutcome.hold,
                "scope allowlist is empty; nothing is in scope",
            )

        return GateDecision(GateOutcome.proceed)
