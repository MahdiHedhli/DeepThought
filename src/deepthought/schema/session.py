"""Session record — one run of the Agent Session Protocol.

A session learns current state, gates, works, teaches back, validates, and
closes. A session with no ``## Next steps`` in its body is incomplete and does
not close. An interrupted session is detectable by the next session.
"""

from __future__ import annotations

import re
from enum import Enum

from .common import ContextCost, Record, RecordId


class SessionType(str, Enum):
    new_project = "new_project"
    status = "status"
    # Later features add these; the enum is fixed here so records validate.
    discover = "discover"
    map = "map"
    verify = "verify"
    sibling_hunt = "sibling_hunt"
    disclosure = "disclosure"


class GateOutcome(str, Enum):
    proceed = "proceed"
    hold = "hold"
    refuse = "refuse"


class CloseState(str, Enum):
    clean = "clean"
    interrupted = "interrupted"


_NEXT_STEPS = re.compile(r"^##\s+Next steps\s*$(.*?)(?=^##\s|\Z)", re.MULTILINE | re.DOTALL)


class Session(Record):
    id: RecordId
    type: SessionType
    project: RecordId | None = None
    started: str
    closed: str | None = None
    gate_outcome: GateOutcome | None = None
    gate_reason: str | None = None
    close_state: CloseState = CloseState.interrupted
    findings_touched: list[str] = []
    coverage_changed: list[str] = []
    context_cost: ContextCost = ContextCost()

    def next_steps(self) -> str:
        """The text under the ``## Next steps`` heading, or empty."""
        match = _NEXT_STEPS.search(self.body)
        return match.group(1).strip() if match else ""

    def has_next_steps(self) -> bool:
        return bool(self.next_steps())
