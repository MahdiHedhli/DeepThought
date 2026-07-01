"""Worker envelope contract — the single channel from a Marvin to the core.

A worker runs one narrow task in isolated context and returns exactly one
envelope. The orchestrator reads the envelope and nothing else from the worker.
Two properties make this the firewall:

1. Context economy. Worker detail pages to the Store, not the orchestrator. The
   envelope carries only a ``detail_ref`` pointer.
2. Injection resistance. A prompt-injected worker can only return this typed,
   length-capped structure. There is no free-text field the orchestrator
   interprets as instruction. The schema is the firewall.

Every string field is length-capped so a worker cannot smuggle a large
free-text payload through a structured field.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

# Capability taxonomy, starter set. Extensible in features 002 and 003; the
# shape is fixed in 001, the vocabulary grows. An unknown kind or grant fails
# validation.
CAPABILITY_TAXONOMY: frozenset[str] = frozenset(
    {
        "read:arbitrary-file",
        "read:memory",
        "write:arbitrary-file",
        "write:logfile",
        "exec:command",
        "exec:code",
        "leak:info",
        "leak:secret",
        "control:flow",
        "auth:bypass",
        "escalate:privilege",
        "ssrf:request",
        "inject:sql",
        "inject:template",
        "deserialize:untrusted",
    }
)

# Length caps. Oversized fields fail validation.
Short = Annotated[str, StringConstraints(max_length=128)]
Ref = Annotated[str, StringConstraints(max_length=256)]
Locus = Annotated[str, StringConstraints(max_length=256)]
TaskText = Annotated[str, StringConstraints(max_length=512)]
Hint = Annotated[str, StringConstraints(max_length=280)]
Precondition = Annotated[str, StringConstraints(max_length=256)]


class Outcome(str, Enum):
    resolved = "resolved"
    partial = "partial"
    empty = "empty"
    blocked = "blocked"
    error = "error"


class Confidence(str, Enum):
    suspected = "suspected"
    demonstrated = "demonstrated"
    verified = "verified"


class Primitive(BaseModel):
    """A capability a finding grants. Primitives are the nodes the orchestrator
    composes into chains."""

    model_config = ConfigDict(extra="forbid")

    kind: Short
    target_locus: Locus
    preconditions: list[Precondition] = []
    grants: list[Short] = []
    confidence: Confidence
    evidence_ref: Ref | None = None
    finding_ref: Short

    @model_validator(mode="after")
    def _known_capabilities(self) -> "Primitive":
        if self.kind not in CAPABILITY_TAXONOMY:
            raise ValueError(f"unknown primitive kind: {self.kind!r}")
        unknown = [g for g in self.grants if g not in CAPABILITY_TAXONOMY]
        if unknown:
            raise ValueError(f"unknown grants: {unknown!r}")
        return self

    @model_validator(mode="after")
    def _evidence_when_shown(self) -> "Primitive":
        # A demonstrated or verified primitive must point at repro evidence.
        if self.confidence in (Confidence.demonstrated, Confidence.verified) and not self.evidence_ref:
            raise ValueError(
                f"evidence_ref is required when confidence is {self.confidence.value}"
            )
        return self


class CoverageDelta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    area: Short
    method: Short
    depth: Short


class GateAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope_ok: bool
    authorization_ref: Ref


class ContextCost(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tokens: int = 0
    wall_seconds: float = 0.0


class Envelope(BaseModel):
    """The Marvin-to-core envelope. Validated before ingest; a failing envelope
    is treated as ``outcome: error``, logged, and does not update the ledger."""

    model_config = ConfigDict(extra="forbid")

    envelope_version: Short
    session_ref: Short
    worker_id: Short
    task_ref: TaskText
    outcome: Outcome
    primitives: list[Primitive] = []
    findings_written: list[Short] = []
    coverage_delta: list[CoverageDelta] = []
    # Hints, not commands. Each is length-capped and the list is bounded so a
    # worker cannot flood the orchestrator through this field.
    next_step_hints: list[Hint] = Field(default=[], max_length=32)
    context_cost: ContextCost = ContextCost()
    detail_ref: Ref | None = None
    gate_attestation: GateAttestation
