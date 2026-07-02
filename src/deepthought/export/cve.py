"""Finding -> CVE Record Format 5.1 DRAFT mapping and validation.

This is a *draft* exporter. Deep Thought is not a CNA and never fabricates a CVE
identifier or a publisher identity, so every draft is deliberately marked with
inert placeholders that a downstream human must replace before submission:

* the ``cveId`` is the sentinel ``CVE-XXXX-XXXXX``, which is *designed to fail*
  the official pattern ``^CVE-[0-9]{4}-[0-9]{4,19}$`` so it can never be
  accidentally submitted as a real record;
* the assigner and provider identities are the all-zero placeholder UUID and an
  obvious ``PLACEHOLDER_CNA`` short name.

Everything else is a faithful mapping of a :class:`Finding` onto the published
CNA container so the structural shape can be validated. Optional blocks are
*omitted* rather than faked: no severity means no ``metrics`` block, and because
a Finding has no CWE field there is never a ``problemTypes`` block.

Free-text scraped from the finding body is carried only as inert string
*values* inside ``descriptions[].value`` — never as a document key, structure,
or ``$ref`` — so adversarial finding prose cannot alter the record shape.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import TYPE_CHECKING

import jsonschema
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from ..schema.common import iso_z, utcnow  # noqa: F401  (re-exported timestamp helper)
from .osv import _details, osv_id_for  # reuse body-prose scraping + id mapping

if TYPE_CHECKING:  # pragma: no cover
    from ..schema.finding import Finding

# Pinned CVE Record Format version. The bundled cve_schema.json is the validator.
CVE_SCHEMA_DATAVERSION = "5.1"

# Never fabricate identity. These are inert, obviously-placeholder values that a
# human must replace before anything could ever be submitted.
_SENTINEL_CVE_ID = "CVE-XXXX-XXXXX"
_ZEROED_ORG_UUID = "00000000-0000-4000-8000-000000000000"
_PLACEHOLDER_CNA_SHORTNAME = "PLACEHOLDER_CNA"
_PLACEHOLDER_VENDOR = "PLACEHOLDER"

# CVE description value has minLength 1 / maxLength 4096.
_DESCRIPTION_MAX = 4096

# The official schema pulls CVSS and reference-tag definitions from sibling
# files via ``file:`` refs that are not bundled. They are resolved to permissive
# stubs so validation can run; the parts we author are still validated strictly.
_EXTERNAL_FILE_REFS = (
    "file:imports/cvss/cvss-v2.0.json",
    "file:imports/cvss/cvss-v3.0.json",
    "file:imports/cvss/cvss-v3.1.json",
    "file:imports/cvss/cvss-v4.0.json",
    "file:tags/adp-tags.json",
    "file:tags/cna-tags.json",
    "file:tags/reference-tags.json",
)


@lru_cache(maxsize=1)
def _cve_schema() -> dict:
    text = resources.files("deepthought.export").joinpath("cve_schema.json").read_text()
    return json.loads(text)


@lru_cache(maxsize=1)
def _published_schema() -> dict:
    """The ``PUBLISHED`` branch of the official ``oneOf``, with definitions.

    A draft is always a published-shaped record, so validating against this
    branch directly (rather than the whole ``oneOf``) yields precise per-field
    errors instead of a single opaque ``oneOf`` failure at the document root.
    """
    full = _cve_schema()
    published = dict(full["oneOf"][0])
    published["definitions"] = full["definitions"]
    published["$schema"] = full.get(
        "$schema", "http://json-schema.org/draft-07/schema#"
    )
    return published


@lru_cache(maxsize=1)
def _registry() -> Registry:
    resources_list = [
        (uri, Resource.from_contents({}, default_specification=DRAFT7))
        for uri in _EXTERNAL_FILE_REFS
    ]
    return Registry().with_resources(resources_list)


def _base_severity(score: float) -> str:
    """CVSS v3.1 qualitative severity band for a base score."""
    if score <= 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _description_value(finding: "Finding") -> str:
    """Build the human-readable description from summary + scraped body prose.

    Carries finding free-text as an inert string value only. Guaranteed to be at
    least a few characters (schema minLength) and trimmed to the schema maximum.
    """
    parts = [finding.summary.strip()] if finding.summary else []
    details = _details(finding)
    if details:
        parts.append(details)
    value = "\n\n".join(p for p in parts if p).strip()
    if not value:
        # Never emit an empty description; fall back to the stable id.
        value = f"Draft disclosure for finding {osv_id_for(finding.id)}."
    return value[:_DESCRIPTION_MAX]


def finding_to_cve_draft(finding: "Finding") -> dict:
    """Map a Finding to a CVE Record Format 5.1 *draft* (a plain dict).

    The draft is deliberately non-submittable: sentinel ``cveId`` and zeroed
    placeholder identities. Optional blocks are omitted rather than faked.
    """
    first_pkg = finding.affected[0] if finding.affected else None
    product = first_pkg.package if first_pkg else _PLACEHOLDER_VENDOR
    versions = list(first_pkg.versions) if first_pkg and first_pkg.versions else []
    first_version = versions[0] if versions else "0"

    cna: dict = {
        "providerMetadata": {
            "orgId": _ZEROED_ORG_UUID,
            "shortName": _PLACEHOLDER_CNA_SHORTNAME,
        },
        "descriptions": [{"lang": "en", "value": _description_value(finding)}],
        "affected": [
            {
                "vendor": _PLACEHOLDER_VENDOR,
                "product": product,
                "versions": [
                    {
                        "version": first_version,
                        "status": "affected",
                        "versionType": "semver",
                    }
                ],
                "defaultStatus": "unaffected",
            }
        ],
    }

    # Omit the metrics block entirely when there is no severity to report.
    if finding.severity is not None:
        cna["metrics"] = [
            {
                "cvssV3_1": {
                    "version": "3.1",
                    "vectorString": finding.severity.cvss_vector,
                    "baseScore": finding.severity.cvss_score,
                    "baseSeverity": _base_severity(finding.severity.cvss_score),
                }
            }
        ]

    # references is required (minItems 1). Use the first finding reference; fall
    # back to a stable placeholder URL if the finding has none.
    if finding.references:
        ref_url = finding.references[0].url
    else:
        ref_url = f"https://deepthought.invalid/finding/{osv_id_for(finding.id)}"
    cna["references"] = [{"url": ref_url, "tags": ["vdb-entry"]}]

    return {
        "dataType": "CVE_RECORD",
        "dataVersion": CVE_SCHEMA_DATAVERSION,
        "cveMetadata": {
            "cveId": _SENTINEL_CVE_ID,
            "assignerOrgId": _ZEROED_ORG_UUID,
            "state": "PUBLISHED",
        },
        "containers": {"cna": cna},
    }


def _passes_cveid(error) -> bool:
    """True if a validation error is attributable to the sentinel ``cveId``."""
    if any(str(p) == "cveId" for p in error.absolute_path):
        return True
    return any(str(p) == "cveId" for p in error.absolute_schema_path)


def validate_cve_draft(doc: dict) -> list[str]:
    """Return CVE-schema violations, dropping the intentional cveId deviation.

    A structurally-complete draft returns ``[]`` even though its ``cveId`` is the
    non-submittable sentinel: any error whose path passes through ``cveId`` is
    the deliberate placeholder deviation and is dropped. Every other violation is
    reported as a sorted ``"path: message"`` string.
    """
    schema = _published_schema()
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema, registry=_registry())
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in errors
        if not _passes_cveid(e)
    ]
