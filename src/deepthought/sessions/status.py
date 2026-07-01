"""STATUS session — summarize current state without changing it.

The second-lowest-risk session type. It loads and summarizes findings and
coverage, writes a session log with next steps, and changes no finding status.
"""

from __future__ import annotations

from collections import Counter

from ..protocol.gate import GateContext
from ..protocol.session import BaseSession, SessionOutcome
from ..schema import Project, SessionType
from ..store import NotFoundError, Store


class StatusSession(BaseSession):
    type = SessionType.status

    def __init__(self, project_id: str):
        self.project_id = project_id

    def _project(self, store: Store) -> Project:
        project = store.get_project(self.project_id)
        if project is None:
            raise NotFoundError(f"project {self.project_id!r} not found")
        return project

    def build_gate_context(self, store: Store) -> GateContext:
        return GateContext.from_project(self._project(store), self.type)

    def run(self, store: Store, session_id: str) -> SessionOutcome:
        project = self._project(store)
        findings = store.list_findings(project=project.id)
        coverage = store.list_coverage(project=project.id)

        by_status = Counter(f.status.value for f in findings)
        by_depth = Counter(c.depth.value for c in coverage)

        status_line = (
            ", ".join(f"{n} {status}" for status, n in sorted(by_status.items()))
            or "no findings yet"
        )
        coverage_line = (
            ", ".join(f"{n} {depth}" for depth, n in sorted(by_depth.items()))
            or "no coverage recorded"
        )

        summary = (
            f"Project {project.id!r}: {len(findings)} finding(s) [{status_line}]; "
            f"{len(coverage)} coverage area(s) [{coverage_line}]. "
            f"Scope: {', '.join(project.scope_allowlist) or '(none)'}. "
            f"No finding status was changed."
        )

        next_steps = self._suggest_next(by_status, coverage)
        # STATUS reads only. findings_touched and coverage_changed stay empty.
        return SessionOutcome(summary=summary, next_steps=next_steps)

    @staticmethod
    def _suggest_next(by_status: Counter, coverage: list) -> str:
        if not coverage:
            return "Run a MAP session to record attack-surface coverage (feature 002)."
        candidates = by_status.get("candidate", 0)
        if candidates:
            return (
                f"{candidates} candidate finding(s) await evidence. Queue a VERIFY "
                f"session once the sandbox lands (feature 003)."
            )
        return "Extend coverage to the untouched in-scope areas."
