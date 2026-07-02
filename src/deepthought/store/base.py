"""Store interface — the repository pattern in front of state.

Nothing reads or writes ``state/`` directly. Everything goes through a Store.
This is what makes the vector-DB swap a single-file change later: one interface,
two future implementations. The lifecycle guard lives here, at the Store
boundary, not in any session.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..schema import (
    Coverage,
    Finding,
    FindingStatus,
    Methodology,
    Project,
    Session,
)
from ..schema.loop import LoopRun


class StoreError(Exception):
    """Base class for Store errors."""


class DuplicateProjectError(StoreError):
    """Raised when a save would create a second project for one identity."""


class NotFoundError(StoreError):
    """Raised when a referenced record does not exist."""


@dataclass(frozen=True)
class RawRecord:
    """An on-disk record before parsing, so ``check`` can report a corrupt file
    rather than crash on it."""

    kind: str
    ident: str
    text: str


@dataclass(frozen=True)
class TransitionResult:
    """The outcome of a finding lifecycle transition.

    On rejection the finding status is unchanged and ``reason`` states why; the
    reason is also recorded on the finding itself.
    """

    ok: bool
    status: FindingStatus
    reason: str | None = None


# Forward lifecycle edges. Backward edges (the reverse of each) are allowed and
# logged when evidence weakens. Anything else is illegal.
FORWARD_EDGES: frozenset[tuple[FindingStatus, FindingStatus]] = frozenset(
    {
        (FindingStatus.candidate, FindingStatus.verified),
        (FindingStatus.verified, FindingStatus.disclosed),
        (FindingStatus.verified, FindingStatus.patched),
    }
)
BACKWARD_EDGES: frozenset[tuple[FindingStatus, FindingStatus]] = frozenset(
    (b, a) for (a, b) in FORWARD_EDGES
)


class Store(ABC):
    # --- Project ---------------------------------------------------------
    @abstractmethod
    def save_project(self, project: Project) -> Project: ...

    @abstractmethod
    def get_project(self, project_id: str) -> Project | None: ...

    @abstractmethod
    def list_projects(self) -> list[Project]: ...

    @abstractmethod
    def resolve_project(
        self, *, git_url: str | None = None, local_path: str | None = None
    ) -> Project | None: ...

    # --- Finding ---------------------------------------------------------
    @abstractmethod
    def save_finding(self, finding: Finding) -> Finding: ...

    @abstractmethod
    def get_finding(self, finding_id: str) -> Finding | None: ...

    @abstractmethod
    def list_findings(self, project: str | None = None) -> list[Finding]: ...

    @abstractmethod
    def transition_finding(
        self, finding_id: str, new_status: FindingStatus
    ) -> TransitionResult: ...

    # --- Session ---------------------------------------------------------
    @abstractmethod
    def save_session(self, session: Session) -> Session: ...

    @abstractmethod
    def get_session(self, session_id: str) -> Session | None: ...

    @abstractmethod
    def list_sessions(self, project: str | None = None) -> list[Session]: ...

    # --- Loop run (feature 006) ------------------------------------------
    @abstractmethod
    def save_loop_run(self, run: LoopRun) -> LoopRun: ...

    @abstractmethod
    def get_loop_run(self, run_id: str) -> LoopRun | None: ...

    @abstractmethod
    def list_loop_runs(self, project: str | None = None) -> list[LoopRun]: ...

    # --- Coverage --------------------------------------------------------
    @abstractmethod
    def save_coverage(self, coverage: Coverage) -> Coverage: ...

    @abstractmethod
    def get_coverage(self, project: str, area: str) -> Coverage | None: ...

    @abstractmethod
    def list_coverage(self, project: str | None = None) -> list[Coverage]: ...

    # --- Methodology -----------------------------------------------------
    @abstractmethod
    def save_methodology(self, methodology: Methodology) -> Methodology: ...

    @abstractmethod
    def get_methodology(self, methodology_id: str) -> Methodology | None: ...

    @abstractmethod
    def list_methodology(self) -> list[Methodology]: ...

    # --- Detail (paged worker output) ------------------------------------
    @abstractmethod
    def write_detail(self, session_id: str, name: str, content: str) -> str:
        """Persist worker detail and return its ``detail/...`` ref."""

    @abstractmethod
    def detail_exists(self, ref: str) -> bool:
        """Whether an evidence/detail ref resolves to stored content."""

    @abstractmethod
    def read_detail(self, ref: str) -> str | None:
        """Return stored detail content for a ``detail/...`` ref, or ``None``."""

    # --- Consistency (for check) -----------------------------------------
    @abstractmethod
    def raw_records(self) -> list[RawRecord]:
        """Every record as raw text, unparsed, for schema validation."""
