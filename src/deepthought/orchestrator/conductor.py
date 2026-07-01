"""Conductor — the orchestrator's envelope ingest boundary (the firewall).

The orchestrator consumes a worker envelope, validates it, updates the primitive
ledger and exploit graph, and pages detail to the Store. It never reads worker
free-text, and a hint never acts on its own.

This is the injection firewall in code:

* A malformed or instruction-laden envelope fails schema validation, is treated
  as ``outcome: error``, is logged, and does not touch the ledger.
* ``detail_ref`` is a pointer only. Its content is never loaded into the
  orchestrator's state.
* ``next_step_hints`` are recorded inert. Ingest dispatches nothing and mutates
  no finding on its own; the orchestrator decides separately.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import ValidationError

from ..schema import Envelope
from .ledger import Ledger


@dataclass(frozen=True)
class IngestResult:
    ok: bool
    outcome: str
    primitives_added: int = 0
    hints: tuple[str, ...] = ()
    detail_ref: str | None = None
    reason: str | None = None
    # The validated Envelope on success, None on rejection. The orchestrator
    # reads teach-back fields from THIS, never from the raw payload it handed in
    # — so a worker that returns an untyped dict is only ever seen through the
    # Conductor's validated view.
    envelope: Envelope | None = None


@dataclass
class Conductor:
    """Holds the compact state and the single ingest channel from workers."""

    ledger: Ledger = field(default_factory=Ledger)
    errors: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    # Dispatch is a deliberate, separate act. Ingest never appends here; the
    # emptiness of this list after ingest is the "a hint does not dispatch"
    # property made observable.
    dispatched: list[str] = field(default_factory=list)

    def ingest(self, raw: Envelope | dict) -> IngestResult:
        envelope = self._validate(raw)
        if envelope is None:
            # Rejected envelope: logged, ledger untouched, treated as error.
            return IngestResult(ok=False, outcome="error", reason=self.errors[-1])

        added = 0
        for primitive in envelope.primitives:
            self.ledger.add_primitive(primitive)
            added += 1

        # Hints are suggestions the orchestrator MAY act on. Recorded, never
        # executed here. No dispatch, no state mutation.
        self.hints.extend(envelope.next_step_hints)

        # detail_ref is carried as a pointer only. Its content is never read
        # into orchestrator state.
        return IngestResult(
            ok=True,
            outcome=envelope.outcome.value,
            primitives_added=added,
            hints=tuple(envelope.next_step_hints),
            detail_ref=envelope.detail_ref,
            envelope=envelope,
        )

    def _validate(self, raw: Envelope | dict) -> Envelope | None:
        if isinstance(raw, Envelope):
            return raw
        try:
            return Envelope.model_validate(raw)
        except ValidationError as exc:
            self.errors.append(f"rejected envelope: {exc.error_count()} validation error(s)")
            return None

    def state_summary(self) -> dict:
        """The orchestrator's compact working set, for observability."""
        return {
            "primitives": len(self.ledger),
            "compositions": len(self.ledger.compositions()),
            "hints": len(self.hints),
            "errors": len(self.errors),
            "dispatched": len(self.dispatched),
        }
