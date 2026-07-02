"""The Agent Session Protocol harness.

The engine is the learn-work-teach loop, wrapped by the Gate:

    load state -> gate -> scoped work -> teach back -> validate -> close

Invariants enforced here:

* Every session passes the Gate before any work (Constitution I). A hold or
  refuse still produces a logged session with a reason and next steps.
* A session with no ``## Next steps`` is incomplete and does not close.
* An interrupted session is detectable by the next session, which can resume it.
* Closing writes the findings touched and the coverage changed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from ..schema import (
    CloseState,
    ContextCost,
    GateOutcome,
    Session,
    SessionType,
)
from ..schema.common import is_record_id, iso_z, utcnow
from ..store import Store
from .gate import Gate, GateContext


@dataclass
class SessionOutcome:
    """What a session type teaches back to the platform."""

    summary: str
    next_steps: str
    findings_touched: list[str] = field(default_factory=list)
    coverage_changed: list[str] = field(default_factory=list)
    context_cost: ContextCost = field(default_factory=ContextCost)


class BaseSession(ABC):
    """One typed session. Subclasses implement the gate context and the work."""

    type: SessionType
    project_id: str | None = None
    # The gate the harness is running with, injected by ``run_session`` before
    # ``run``. A session that sub-gates additional targets (e.g. SIBLING HUNT
    # gating each sibling project) MUST use this — the SAME gate the harness
    # applied to the source — so a stricter deployment gate governs every target,
    # never a hardcoded default. ``None`` outside a harness run.
    harness_gate: "Gate | None" = None

    @abstractmethod
    def build_gate_context(self, store: Store) -> GateContext:
        """Return what the Gate should evaluate for this session."""

    @abstractmethod
    def run(self, store: Store, session_id: str) -> SessionOutcome:
        """Do the scoped work and return the teach-back outcome."""


def generate_session_id(store: Store, now: datetime) -> str:
    """A stable, human-readable session id: ``S-YYYY-MM-DD-NNNN``."""
    date = now.strftime("%Y-%m-%d")
    prefix = f"S-{date}-"
    used = [s.id for s in store.list_sessions() if s.id.startswith(prefix)]
    return f"{prefix}{len(used) + 1:04d}"


def _render_body(outcome: SessionOutcome) -> str:
    summary = outcome.summary.strip() or "(no summary)"
    steps = outcome.next_steps.strip()
    body = f"## Summary\n\n{summary}"
    if steps:
        body += f"\n\n## Next steps\n\n{steps}"
    # Return the on-disk normal form (stripped), so an in-memory record equals
    # the same record read back through the Store.
    return body.strip()


def find_resumable(store: Store, project: str | None = None) -> list[Session]:
    """Interrupted sessions the next session can detect and resume."""
    return [
        s
        for s in store.list_sessions(project=project)
        if s.close_state is CloseState.interrupted and s.closed is None
    ]


def run_session(
    store: Store,
    gate: Gate,
    session: BaseSession,
    *,
    session_id: str | None = None,
    clock: Callable[[], datetime] = utcnow,
) -> Session:
    """Run one session end to end and return the persisted Session record."""
    now = clock()
    sid = session_id or generate_session_id(store, now)

    # A raw, user-supplied project id (CLI ``--project``) that is not a safe
    # record id would raise a bare ValidationError when the Session record is
    # built below (``project`` is a RecordId). Refuse it cleanly instead: it can
    # name no real project (get_project would reject it too), so log a refused
    # session rather than crash the CLI with a traceback.
    if session.project_id is not None and not is_record_id(session.project_id):
        record = Session(
            id=sid, type=session.type, project=None,
            started=iso_z(now), close_state=CloseState.interrupted,
        )
        store.save_session(record)
        record.gate_outcome = GateOutcome.refuse
        record.gate_reason = f"invalid project id {session.project_id!r}"
        record.body = _render_body(
            SessionOutcome(
                summary=f"Refused: invalid project id {session.project_id!r}.",
                next_steps="Provide a valid project id — a single safe path segment.",
            )
        )
        record.closed = iso_z(clock())
        record.close_state = CloseState.clean
        store.save_session(record)
        return record

    # A session starts life interrupted, and is persisted immediately, so an
    # interruption before a clean close is detectable and resumable.
    record = Session(
        id=sid,
        type=session.type,
        project=session.project_id,
        started=iso_z(now),
        close_state=CloseState.interrupted,
    )
    store.save_session(record)

    # --- gate ---
    decision = gate.evaluate(session.build_gate_context(store))
    record.gate_outcome = GateOutcome(decision.outcome)
    record.gate_reason = decision.reason

    if not decision.proceeds:
        # Held or refused: logged, with a reason and remediation next steps.
        outcome = SessionOutcome(
            summary=f"Gate {decision.outcome.value}: {decision.reason}",
            next_steps=f"Resolve gate {decision.outcome.value}: {decision.reason}",
        )
    else:
        # Inject the harness gate so a session that sub-gates further targets
        # (SIBLING HUNT) applies the SAME gate this harness used on the source.
        session.harness_gate = gate
        # --- scoped work --- (an exception here leaves the session interrupted)
        try:
            outcome = session.run(store, sid)
        except Exception as exc:
            record.body = f"## Summary\n\nInterrupted before completion: {exc}"
            record.close_state = CloseState.interrupted
            store.save_session(record)
            raise

    # --- teach back ---
    record.body = _render_body(outcome)
    record.findings_touched = list(outcome.findings_touched)
    record.coverage_changed = list(outcome.coverage_changed)
    record.context_cost = outcome.context_cost

    # --- validate --- a session with no next steps does not close.
    if not record.has_next_steps():
        record.close_state = CloseState.interrupted
        store.save_session(record)
        return record

    # --- close ---
    record.closed = iso_z(clock())
    record.close_state = CloseState.clean
    store.save_session(record)
    return record
