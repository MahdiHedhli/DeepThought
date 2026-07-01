"""Finding record — the record that exports to OSV.

Front-matter mirrors OSV field names where it can, so export is a mapping, not a
translation. The Finding-to-OSV field map lives in ``export/osv.py``. Lifecycle
legality is enforced at the Store boundary, not here; this model is the shape.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict

from .common import Record


class FindingStatus(str, Enum):
    candidate = "candidate"
    verified = "verified"
    disclosed = "disclosed"
    patched = "patched"


class Severity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cvss_vector: str
    cvss_score: float


class AffectedPackage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem: str
    package: str
    ranges: list[dict] = []
    versions: list[str] = []


class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Free-form here; normalised to the OSV reference-type enum on export.
    type: str
    url: str


class TimelineEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    date: str
    event: str


class Disclosure(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reported: str | None = None
    vendor_contact: str | None = None
    embargo_until: str | None = None
    timeline: list[TimelineEntry] = []


class TransitionLogEntry(BaseModel):
    """A lifecycle transition attempt, recorded on the finding.

    The data model requires that a rejected transition records its blocking
    reason on the finding, and that backward transitions are logged. This is
    where both land.
    """

    model_config = ConfigDict(extra="forbid")

    at: str
    from_status: str
    to_status: str
    accepted: bool
    reason: str | None = None


class Finding(Record):
    id: str
    project: str
    summary: str
    status: FindingStatus = FindingStatus.candidate
    severity: Severity | None = None
    affected: list[AffectedPackage] = []
    references: list[Reference] = []
    aliases: list[str] = []
    cve: str | None = None
    disclosure: Disclosure | None = None
    evidence_ref: str | None = None
    downstream_impact: str | None = None
    published: str | None = None
    modified: str | None = None
    # Implementation field: the audit trail the data model requires the Store to
    # keep on the finding for rejected and backward transitions.
    transition_log: list[TransitionLogEntry] = []

    def has_reference_type(self, ref_type: str) -> bool:
        wanted = ref_type.lower()
        return any(r.type.lower() == wanted for r in self.references)
