"""Finding -> OASIS CSAF 2.0 mapping and CSAF schema validation (DRAFT-ONLY).

CSAF (Common Security Advisory Framework) 2.0 is a machine-readable advisory
format. A Deep Thought Finding maps to a ``csaf_security_advisory`` document that
validates against the bundled CSAF 2.0 JSON schema (draft 2020-12).

This exporter is DRAFT-ONLY and must never fabricate authority:

* No fabricated CVE. A ``cve`` member is emitted ONLY when ``finding.cve`` is set
  AND matches the official pattern ``^CVE-[0-9]{4}-[0-9]{4,}$``. Otherwise the
  vulnerability carries an internal ``ids[]`` tracking entry and NO ``cve``. The
  sentinel ``CVE-XXXX-XXXXX`` therefore never becomes a ``cve`` member.
* Placeholder publisher identity only — never a real CNA/vendor. The publisher is
  a ``vendor`` named ``PLACEHOLDER`` under a ``.local`` placeholder namespace.
* Optional blocks are omitted, never faked. If ``finding.severity`` is ``None``
  the ``scores`` block is omitted entirely.
* Injection inertness. Finding free-text (summary/body/downstream_impact) is
  carried ONLY as inert string VALUES in text leaves (title / note text). It is
  never used as a document key, structure, or ``$ref``.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources
from typing import TYPE_CHECKING

import jsonschema
from referencing import Registry, Resource

from ..schema.common import iso_z, utcnow
from .osv import _details, osv_id_for

if TYPE_CHECKING:  # pragma: no cover
    from ..schema.finding import Finding

# Pinned CSAF specification version. The bundled csaf_schema.json is the validator.
CSAF_VERSION = "2.0"

# Placeholder product id. Draft advisories reference a single synthetic product.
_PLACEHOLDER_PID = "CSAFPID-0001"

# Placeholder publisher identity — deliberately not a real CNA/vendor.
_PLACEHOLDER_NAMESPACE = "https://deepthought.local/placeholder"

# The official CVE id pattern. The sentinel "CVE-XXXX-XXXXX" fails this on
# purpose so a draft can never be mistaken for a real, submittable CVE.
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


@lru_cache(maxsize=1)
def _csaf_schema() -> dict:
    text = resources.files("deepthought.export").joinpath("csaf_schema.json").read_text()
    return json.loads(text)


# The CSAF schema references the FIRST.org CVSS schemas by remote URL. We supply
# faithful local copies so validation is hermetic (no network, deterministic) —
# mirroring the offline OSV validator. These reproduce the official FIRST.org
# CVSS 3.x property/enum/pattern set for the fields any CSAF producer may emit.
def _cvss3_schema(minor: str) -> dict:
    """Build the FIRST.org CVSS v3.<minor> JSON schema (draft-07)."""
    cia = {"type": "string", "enum": ["NONE", "LOW", "HIGH"]}
    mod_cia = {"type": "string", "enum": ["NONE", "LOW", "HIGH", "NOT_DEFINED"]}
    cia_req = {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "NOT_DEFINED"]}
    score = {"type": "number", "minimum": 0, "maximum": 10}
    severity = {"type": "string", "enum": ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]}
    metric = (
        r"(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|"
        r"RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|"
        r"MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])"
    )
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "version": {"type": "string", "enum": [f"3.{minor}"]},
            "vectorString": {
                "type": "string",
                "pattern": rf"^CVSS:3[.]{minor}/({metric}/)*{metric}$",
            },
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
                "enum": [
                    "UNPROVEN",
                    "PROOF_OF_CONCEPT",
                    "FUNCTIONAL",
                    "HIGH",
                    "NOT_DEFINED",
                ],
            },
            "remediationLevel": {
                "type": "string",
                "enum": [
                    "OFFICIAL_FIX",
                    "TEMPORARY_FIX",
                    "WORKAROUND",
                    "UNAVAILABLE",
                    "NOT_DEFINED",
                ],
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


@lru_cache(maxsize=1)
def _cvss_registry() -> Registry:
    """A referencing Registry that resolves the CSAF CVSS refs locally."""
    resources_by_uri = {
        "https://www.first.org/cvss/cvss-v3.0.json": _cvss3_schema("0"),
        "https://www.first.org/cvss/cvss-v3.1.json": _cvss3_schema("1"),
    }
    return Registry().with_resources(
        (uri, Resource.from_contents(schema)) for uri, schema in resources_by_uri.items()
    )


def _base_severity(score: float) -> str:
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


def _cvss3_version(vector: str) -> str | None:
    """The CVSS 3.x minor version a vector declares, or ``None``.

    CSAF's ``cvss_v3`` is ``oneOf: [v3.0, v3.1]``, and each branch pins both the
    ``version`` enum and the ``vectorString`` prefix. Emitting the wrong version
    (e.g. ``3.1`` for a ``CVSS:3.0/...`` vector) fails BOTH branches, which would
    turn ``check`` red. Only v3.0/v3.1 have bundled schemas; any other version
    (2.0, 4.0, …) returns ``None`` so the caller omits the score rather than emit
    an unvalidatable one.
    """
    v = (vector or "").strip()
    if v.startswith("CVSS:3.0/"):
        return "3.0"
    if v.startswith("CVSS:3.1/"):
        return "3.1"
    return None


def _product_tree(finding: "Finding") -> dict:
    """Build a vendor -> product_name -> product_version branch for the finding.

    Each CSAF branch object must have exactly three properties, so leaf branches
    carry ``product`` and inner branches carry ``branches``.
    """
    pkg = finding.affected[0]
    version = pkg.versions[0] if pkg.versions else "unspecified"
    product_name = pkg.package

    version_branch = {
        "category": "product_version",
        "name": version,
        "product": {
            "name": f"{product_name} {version}",
            "product_id": _PLACEHOLDER_PID,
        },
    }
    product_branch = {
        "category": "product_name",
        "name": product_name,
        "branches": [version_branch],
    }
    vendor_branch = {
        "category": "vendor",
        "name": pkg.ecosystem,
        "branches": [product_branch],
    }
    return {"branches": [vendor_branch]}


def _notes(finding: "Finding") -> list[dict]:
    """A single inert summary note carrying the human details prose.

    ``notes[].text`` requires a non-empty string, so fall back to the finding
    summary when the body yields no root-cause/impact prose.
    """
    text = _details(finding) or finding.summary
    return [{"category": "summary", "text": text}]


def _scores(finding: "Finding") -> list[dict] | None:
    """CVSS v3 score block, or ``None`` when there is no v3 severity to report.

    The ``version`` is derived from the stored vector so a ``CVSS:3.0/...``
    finding is emitted as v3.0 (and validates against the v3.0 oneOf branch). A
    non-v3 vector (2.0/4.0) yields no score block rather than a mislabelled one.
    """
    severity = finding.severity
    if severity is None:
        return None
    version = _cvss3_version(severity.cvss_vector)
    if version is None:
        return None
    return [
        {
            "cvss_v3": {
                "version": version,
                "vectorString": severity.cvss_vector,
                "baseScore": severity.cvss_score,
                "baseSeverity": _base_severity(severity.cvss_score),
            },
            "products": [_PLACEHOLDER_PID],
        }
    ]


def _vulnerability(finding: "Finding") -> dict:
    vuln: dict = {
        "title": finding.summary,
        "notes": _notes(finding),
        "product_status": {"known_affected": [_PLACEHOLDER_PID]},
    }

    # DRAFT-ONLY: emit a real CVE member only for a real CVE; otherwise carry an
    # inert internal tracking id and never a fabricated "cve".
    if finding.cve and _CVE_RE.match(finding.cve):
        vuln["cve"] = finding.cve
    else:
        vuln["ids"] = [{"system_name": "DeepThought", "text": osv_id_for(finding.id)}]

    scores = _scores(finding)
    if scores is not None:
        vuln["scores"] = scores

    if finding.references:
        vuln["references"] = [
            {"category": "self", "summary": "Source location", "url": finding.references[0].url}
        ]

    return vuln


def finding_to_csaf(finding: "Finding") -> dict:
    """Map a Finding to a CSAF 2.0 security-advisory document (a plain dict)."""
    now = iso_z(utcnow())
    tracking_id = osv_id_for(finding.id)

    doc: dict = {
        "document": {
            "category": "csaf_security_advisory",
            "csaf_version": CSAF_VERSION,
            "publisher": {
                "category": "vendor",
                "name": "PLACEHOLDER",
                "namespace": _PLACEHOLDER_NAMESPACE,
            },
            "title": finding.summary,
            "tracking": {
                "current_release_date": now,
                "id": tracking_id,
                "initial_release_date": now,
                "revision_history": [
                    {
                        "date": now,
                        "number": "1",
                        "summary": "Initial draft generated from code finding.",
                    }
                ],
                "status": "draft",
                "version": "1",
            },
        },
        "vulnerabilities": [_vulnerability(finding)],
    }

    if finding.affected:
        doc["product_tree"] = _product_tree(finding)

    return doc


def validate_csaf(doc: dict) -> list[str]:
    """Return a list of CSAF schema violations. Empty means conformant."""
    schema = _csaf_schema()
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema, registry=_cvss_registry())
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]
