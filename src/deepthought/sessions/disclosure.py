"""DISCLOSURE session — draft-only advisory & VEX (feature 005).

From a *verified* finding, draft four LOCAL artifacts — a human-readable advisory
(Markdown), a CVE JSON 5.1 draft, a CSAF 2.0 advisory, and an OpenVEX statement —
persist them as session detail, and stop.

This session is DRAFT-ONLY (Constitution Article V: "Disclosure leaves the
machine only past a human. Drafting may be done by an agent; sending is done by a
person."). It structurally refuses two failure modes:

* **No transmission.** Nothing is sent, submitted, or published. There is no
  network code here; the session only writes local detail through the Store.
* **No fabricated authority, no lifecycle change.** It never advances the finding
  to ``disclosed`` (that requires a real, human-assigned CVE *and* an advisory
  reference), never sets ``finding.cve``, never adds an ``advisory`` reference,
  and never touches ``finding.disclosure``. The finding is left exactly as it
  was — still ``verified``.

Crossing any of those is a hard stop that requires a human, not an autonomous
step.
"""

from __future__ import annotations

import json

from ..export.advisory import finding_to_advisory
from ..export.csaf import finding_to_csaf
from ..export.cve import finding_to_cve_draft
from ..export.openvex import finding_to_openvex
from ..protocol.gate import GateContext
from ..protocol.session import BaseSession, SessionOutcome
from ..schema import FindingStatus, Project, SessionType
from ..store import NotFoundError, Store

# The four draft artifacts, in the order they are drafted and reported. Each is a
# durable Store detail written under the running session id.
_ADVISORY_NAME = "disclosure-advisory.md"
_CSAF_NAME = "disclosure-csaf.json"
_OPENVEX_NAME = "disclosure-openvex.json"
_CVE_NAME = "disclosure-cve-draft.json"


def _json(doc: dict) -> str:
    """Stable, human-diffable JSON for a draft artifact."""
    return json.dumps(doc, indent=2, sort_keys=True)


class DisclosureSession(BaseSession):
    """Draft disclosure artifacts for one verified finding. Transmits nothing."""

    type = SessionType.disclosure

    def __init__(self, project_id: str, finding_id: str) -> None:
        self.project_id = project_id
        self.finding_id = finding_id
        # Exposed after run() for inspection: the teach-back outcome and the four
        # detail refs the drafts were written to.
        self.outcome: SessionOutcome | None = None
        self.artifact_refs: dict[str, str] = {}

    # --- gate context ------------------------------------------------------

    def _project(self, store: Store) -> Project:
        project = store.get_project(self.project_id)
        if project is None:
            raise NotFoundError(f"project {self.project_id!r} not found")
        return project

    def build_gate_context(self, store: Store) -> GateContext:
        # Built from the stored project, like every non-registration session, so
        # the unchanged gate governs: no basis -> refuse, empty scope -> hold.
        return GateContext.from_project(self._project(store), self.type)

    # --- scoped work -------------------------------------------------------

    def run(self, store: Store, session_id: str) -> SessionOutcome:
        finding = store.get_finding(self.finding_id)
        if finding is None:
            # A mistyped finding id is an INPUT refusal, not a crash. Return a
            # clean refusal (like wrong-project / non-verified) so the session log
            # closes cleanly rather than leaving a resumable interrupted session
            # for a typo. Nothing is drafted.
            return self._record(
                SessionOutcome(
                    summary=(
                        f"DISCLOSURE on {self.project_id!r}: finding "
                        f"{self.finding_id!r} was not found — refusing. Nothing was "
                        f"drafted."
                    ),
                    next_steps=(
                        f"Check the finding id and re-run DISCLOSURE with a "
                        f"verified finding that exists in {self.project_id!r}."
                    ),
                )
            )

        # Refuse a finding that belongs to a DIFFERENT project. The gate was
        # evaluated for self.project_id only; drafting another project's finding
        # under this project's gate would cross an authority boundary.
        if finding.project != self.project_id:
            return self._record(
                SessionOutcome(
                    summary=(
                        f"DISCLOSURE on {self.project_id!r}: finding {finding.id!r} "
                        f"belongs to project {finding.project!r}, not "
                        f"{self.project_id!r} — refusing. Nothing was drafted."
                    ),
                    next_steps=(
                        f"Run DISCLOSURE under the finding's own project "
                        f"({finding.project!r}), or pass a finding that belongs to "
                        f"{self.project_id!r}."
                    ),
                )
            )

        # Refuse anything that is not verified. A disclosure is drafted only from
        # a confirmed bug with evidence; a candidate is not disclosure-ready.
        if finding.status is not FindingStatus.verified:
            return self._record(
                SessionOutcome(
                    summary=(
                        f"DISCLOSURE on {self.project_id!r}: finding {finding.id!r} "
                        f"is {finding.status.value!r}, not verified — refusing. "
                        f"Nothing was drafted; status unchanged."
                    ),
                    next_steps=(
                        f"Verify {finding.id!r} first (VERIFY promotes a candidate "
                        f"to verified on resolving evidence), then re-run "
                        f"DISCLOSURE to draft its advisory and VEX."
                    ),
                    # A refusal drafts nothing, so it touches no finding — an empty
                    # findings_touched is the record-level signal that no drafts
                    # exist (only a successful draft sets findings_touched).
                )
            )

        # --- draft, read-only over the finding's typed fields ---
        # The exporters never interpret the finding body as instruction; free-text
        # is carried only as inert string values inside the artifacts.
        advisory = finding_to_advisory(finding)
        csaf = finding_to_csaf(finding)
        openvex = finding_to_openvex(finding)
        cve_draft = finding_to_cve_draft(finding)

        # --- persist as durable, human-diffable Store detail ---
        # DRAFT-ONLY: write_detail is the ONLY mutation. The finding itself is
        # never saved, transitioned, or annotated (no cve, no advisory reference,
        # no disclosure sub-object).
        self.artifact_refs = {
            _ADVISORY_NAME: store.write_detail(session_id, _ADVISORY_NAME, advisory),
            _CSAF_NAME: store.write_detail(session_id, _CSAF_NAME, _json(csaf)),
            _OPENVEX_NAME: store.write_detail(session_id, _OPENVEX_NAME, _json(openvex)),
            _CVE_NAME: store.write_detail(session_id, _CVE_NAME, _json(cve_draft)),
        }
        refs = ", ".join(self.artifact_refs[n] for n in (
            _ADVISORY_NAME, _CSAF_NAME, _OPENVEX_NAME, _CVE_NAME
        ))

        return self._record(
            SessionOutcome(
                summary=(
                    f"DISCLOSURE on {self.project_id!r}: drafted four artifacts for "
                    f"{finding.id!r} ({refs}). Nothing was transmitted; no CVE was "
                    f"assigned; no advisory reference was added; the finding is "
                    f"unchanged (still verified)."
                ),
                next_steps=(
                    f"HUMAN GATE (Constitution Article V): review the drafts, obtain "
                    f"and assign a real CVE, publish the advisory and add a "
                    f"Reference(type='advisory', url=...) to {finding.id!r}, then "
                    f"run the verified -> disclosed transition through the Store "
                    f"lifecycle guard. Sending is a human action; Deep Thought "
                    f"drafts only."
                ),
                findings_touched=[finding.id],
                coverage_changed=[],
            )
        )

    def _record(self, outcome: SessionOutcome) -> SessionOutcome:
        """Store the teach-back outcome for inspection, then return it."""
        self.outcome = outcome
        return outcome
