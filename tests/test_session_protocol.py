"""T011 — the Agent Session Protocol harness.

A session with no next steps does not close; an interrupted session is
detectable and resumable; closing writes findings touched and coverage changed.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from deepthought.protocol import (
    BaseSession,
    Gate,
    GateContext,
    GateDecision,
    SessionOutcome,
    find_resumable,
    run_session,
)
from deepthought.schema import CloseState, GateOutcome, SessionType
from deepthought.store import FileStore

FIXED = datetime(2026, 6, 30, 12, 0, 0, tzinfo=timezone.utc)


class ProceedGate(Gate):
    def evaluate(self, context: GateContext) -> GateDecision:
        return GateDecision(GateOutcome.proceed)


class RefuseGate(Gate):
    def evaluate(self, context: GateContext) -> GateDecision:
        return GateDecision(GateOutcome.refuse, "not authorized for this test")


class FakeSession(BaseSession):
    type = SessionType.status
    project_id = None

    def __init__(self, outcome=None, raise_exc=None):
        self._outcome = outcome
        self._raise = raise_exc

    def build_gate_context(self, store) -> GateContext:
        return GateContext(session_type=self.type)

    def run(self, store, session_id) -> SessionOutcome:
        if self._raise is not None:
            raise self._raise
        return self._outcome


def test_session_without_next_steps_does_not_close(state_dir):
    store = FileStore(state_dir)
    session = FakeSession(SessionOutcome(summary="did work", next_steps=""))
    record = run_session(store, ProceedGate(), session, clock=lambda: FIXED)
    assert record.close_state is CloseState.interrupted
    assert record.closed is None


def test_clean_close_writes_touched_and_coverage(state_dir):
    store = FileStore(state_dir)
    session = FakeSession(
        SessionOutcome(
            summary="did work",
            next_steps="do the next thing",
            findings_touched=["F-0001", "F-0002"],
            coverage_changed=["php-src/ext-soap"],
        )
    )
    record = run_session(store, ProceedGate(), session, clock=lambda: FIXED)
    assert record.close_state is CloseState.clean
    assert record.closed is not None
    assert record.findings_touched == ["F-0001", "F-0002"]
    assert record.coverage_changed == ["php-src/ext-soap"]
    # Persisted identically.
    assert store.get_session(record.id) == record


def test_interrupted_session_is_detectable_and_resumable(state_dir):
    store = FileStore(state_dir)
    session = FakeSession(raise_exc=RuntimeError("worker died"))
    with pytest.raises(RuntimeError):
        run_session(store, ProceedGate(), session, clock=lambda: FIXED)

    resumable = find_resumable(store)
    assert len(resumable) == 1
    assert resumable[0].close_state is CloseState.interrupted
    assert "Interrupted" in resumable[0].body


def test_clean_session_is_not_resumable(state_dir):
    store = FileStore(state_dir)
    session = FakeSession(SessionOutcome(summary="s", next_steps="n"))
    run_session(store, ProceedGate(), session, clock=lambda: FIXED)
    assert find_resumable(store) == []


def test_gate_refuse_is_logged_with_reason_and_still_closes(state_dir):
    store = FileStore(state_dir)
    session = FakeSession(SessionOutcome(summary="unused", next_steps="unused"))
    record = run_session(store, RefuseGate(), session, clock=lambda: FIXED)
    assert record.gate_outcome is GateOutcome.refuse
    assert record.gate_reason == "not authorized for this test"
    assert record.close_state is CloseState.clean  # closes with remediation steps
    assert "not authorized" in record.body


def test_session_ids_increment_per_day(state_dir):
    store = FileStore(state_dir)
    first = run_session(
        store, ProceedGate(), FakeSession(SessionOutcome("a", "b")), clock=lambda: FIXED
    )
    second = run_session(
        store, ProceedGate(), FakeSession(SessionOutcome("a", "b")), clock=lambda: FIXED
    )
    assert first.id == "S-2026-06-30-0001"
    assert second.id == "S-2026-06-30-0002"
