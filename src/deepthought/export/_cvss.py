"""Shared CVSS 3.x helpers for the disclosure exporters.

CSAF and the CVE draft both need the same three things from a stored CVSS vector:
the declared minor version, the qualitative base-severity band, and a faithful,
HERMETIC (no-network) FIRST.org CVSS 3.x JSON schema to validate against. Keeping
them here means one source of truth — the CSAF ``cvss_v3`` branch and the CVE
``cvssV3_x`` metric validate against the identical schema.
"""

from __future__ import annotations

import re

# The official FIRST.org CVSS 3.x vectorString shape: the EIGHT base metrics are
# mandatory and ORDERED (AV/AC/PR/UI/S/C/I/A), then the optional temporal +
# environmental metrics. A permissive "(token/)*token" would wrongly accept a
# partial vector like "CVSS:3.1/AV:N".
_BASE = "AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
_OPT = (
    "(/E:[XUPFH])?(/RL:[XOTWU])?(/RC:[XURC])?(/CR:[XLMH])?(/IR:[XLMH])?"
    "(/AR:[XLMH])?(/MAV:[XNALP])?(/MAC:[XLH])?(/MPR:[XNLH])?(/MUI:[XNR])?"
    "(/MS:[XUC])?(/MC:[XNLH])?(/MI:[XNLH])?(/MA:[XNLH])?"
)


def _vector_pattern(minor: str) -> str:
    return rf"^CVSS:3[.]{minor}/{_BASE}{_OPT}$"


def cvss3_version(vector: str) -> str | None:
    """The CVSS 3.x minor version a vector declares ("3.0"/"3.1"), or ``None``.

    Only v3.0/v3.1 have bundled schemas here; a non-v3 vector (2.0, 4.0, …)
    returns ``None`` so callers omit the score rather than emit an unvalidatable
    one.
    """
    v = (vector or "").strip()
    if v.startswith("CVSS:3.0/"):
        return "3.0"
    if v.startswith("CVSS:3.1/"):
        return "3.1"
    return None


def base_severity(score: float) -> str:
    """CVSS 3.x qualitative severity band for a base score."""
    if score <= 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def cvss3_schema(minor: str) -> dict:
    """Build the FIRST.org CVSS v3.<minor> JSON schema (draft-07)."""
    cia = {"type": "string", "enum": ["NONE", "LOW", "HIGH"]}
    cia_req = {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "NOT_DEFINED"]}
    score = {"type": "number", "minimum": 0, "maximum": 10}
    severity = {"type": "string", "enum": ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]}
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "version": {"type": "string", "enum": [f"3.{minor}"]},
            "vectorString": {"type": "string", "pattern": _vector_pattern(minor)},
            "attackVector": {
                "type": "string",
                "enum": ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"],
            },
            "attackComplexity": {"type": "string", "enum": ["HIGH", "LOW"]},
            "privilegesRequired": {"type": "string", "enum": ["HIGH", "LOW", "NONE"]},
            "userInteraction": {"type": "string", "enum": ["NONE", "REQUIRED"]},
            "scope": {"type": "string", "enum": ["UNCHANGED", "CHANGED"]},
            "confidentialityImpact": cia,
            "integrityImpact": cia,
            "availabilityImpact": cia,
            "baseScore": score,
            "baseSeverity": severity,
            "exploitCodeMaturity": {
                "type": "string",
                "enum": ["UNPROVEN", "PROOF_OF_CONCEPT", "FUNCTIONAL", "HIGH", "NOT_DEFINED"],
            },
            "remediationLevel": {
                "type": "string",
                "enum": ["OFFICIAL_FIX", "TEMPORARY_FIX", "WORKAROUND", "UNAVAILABLE", "NOT_DEFINED"],
            },
            "reportConfidence": {
                "type": "string",
                "enum": ["UNKNOWN", "REASONABLE", "CONFIRMED", "NOT_DEFINED"],
            },
            "temporalScore": score,
            "temporalSeverity": severity,
            "confidentialityRequirement": cia_req,
            "integrityRequirement": cia_req,
            "availabilityRequirement": cia_req,
            "environmentalScore": score,
            "environmentalSeverity": severity,
        },
        "required": ["version", "vectorString", "baseScore", "baseSeverity"],
    }


def cvss3_metric(vector: str, score: float) -> dict | None:
    """A validated CVSS 3.x metric object for a stored vector, or ``None``.

    Returns ``None`` unless the vector is a well-formed v3.0/v3.1 vector, so a
    caller never emits a metric an honest validator would reject. The ``version``
    and ``baseSeverity`` are derived from the vector/score.
    """
    version = cvss3_version(vector)  # "3.0" / "3.1" / None
    if version is None:
        return None
    minor = version.split(".")[1]  # the pattern/schema key is the MINOR ("0"/"1")
    if not re.match(_vector_pattern(minor), vector or ""):
        return None
    return {
        "version": version,
        "vectorString": vector,
        "baseScore": score,
        "baseSeverity": base_severity(score),
    }
