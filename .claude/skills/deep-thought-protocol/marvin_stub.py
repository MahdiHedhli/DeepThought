"""Marvin worker harness stub — produces a conforming envelope.

A Marvin runs one narrow task in isolated context (on Codex in the real runtime)
and returns exactly one envelope. This stub stands in for that worker: it builds
a schema-valid :class:`Envelope` so the orchestrator's ingest boundary can be
exercised end to end, and it is the reference for what a real Marvin must emit.

Run it:

    python .claude/skills/deep-thought-protocol/marvin_stub.py

It prints a valid envelope as JSON and asserts the orchestrator ingests it.
"""

from __future__ import annotations

import json

from deepthought.orchestrator import Conductor
from deepthought.schema import Envelope


def build_envelope(
    *,
    session_ref: str = "S-2026-06-30-0007",
    worker_id: str = "marvin-04",
    detail_ref: str = "detail/S-2026-06-30-0007/",
) -> Envelope:
    """Return a conforming envelope for a memory-safety analysis task."""
    return Envelope.model_validate(
        {
            "envelope_version": "1.0",
            "session_ref": session_ref,
            "worker_id": worker_id,
            "task_ref": "analyze module streambucket for memory-safety primitives",
            "outcome": "partial",
            "primitives": [
                {
                    "kind": "write:arbitrary-file",
                    "target_locus": "ext/soap/php_streams.c:412",
                    "preconditions": ["attacker controls stream filter chain"],
                    "grants": ["write:arbitrary-file"],
                    "confidence": "demonstrated",
                    "evidence_ref": f"{detail_ref}repro-01.txt",
                    "finding_ref": "F-0019",
                }
            ],
            "findings_written": ["F-0019"],
            "coverage_delta": [
                {"area": "ext/soap", "method": "static", "depth": "explored"}
            ],
            "next_step_hints": [
                "F-0019 write primitive may compose with F-0014 include path to reach exec:code"
            ],
            "context_cost": {"tokens": 38120, "wall_seconds": 41},
            "detail_ref": detail_ref,
            "gate_attestation": {"scope_ok": True, "authorization_ref": "permissive_oss"},
        }
    )


def main() -> None:
    envelope = build_envelope()
    print(json.dumps(envelope.model_dump(mode="json"), indent=2))

    # The orchestrator reads only this envelope — never the worker's free-text.
    conductor = Conductor()
    result = conductor.ingest(envelope)
    assert result.ok, "a conforming envelope must ingest"
    assert result.primitives_added == 1
    print(f"\ningested: {conductor.state_summary()}")


if __name__ == "__main__":
    main()
