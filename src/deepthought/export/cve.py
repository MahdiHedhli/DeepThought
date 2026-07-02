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
    """CVSS v3.x qualitative severity band for a base score."""
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

    The CVE metric object keys the score by version (``cvssV3_0`` vs
    ``cvssV3_1``), so the key and ``version`` are derived from the stored vector.
    A non-v3 vector (2.0/4.0) returns ``None`` and the caller omits the metric
    rather than mislabel it.
    """
    v = (vector or "").strip()
    if v.startswith("CVSS:3.0/"):
        return "3.0"
    if v.startswith("CVSS:3.1/"):
        return "3.1"
    return None


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


def _affected(finding: "Finding") -> list[dict]:
    """One CNA ``affected`` entry per affected package, with ALL its versions.

    Collapsing to the first package/version would under-report the disclosure's
    scope, so every ``AffectedPackage`` and every recorded version is preserved. A
    package with no recorded versions gets a single ``0`` placeholder (the CNA
    ``versions`` array requires at least one entry); a finding with no affected
    packages at all falls back to a single PLACEHOLDER entry so the required
    ``affected`` array is non-empty.
    """
    entries: list[dict] = []
    for pkg in finding.affected or []:
        versions = [
            {"version": v, "status": "affected", "versionType": "semver"}
            for v in (pkg.versions or [])
        ]
        if not versions:
            versions = [{"version": "0", "status": "affected", "versionType": "semver"}]
        entries.append(
            {
                "vendor": _PLACEHOLDER_VENDOR,
                "product": pkg.package,
                "versions": versions,
                "defaultStatus": "unaffected",
            }
        )
    if not entries:
        entries.append(
            {
                "vendor": _PLACEHOLDER_VENDOR,
                "product": _PLACEHOLDER_VENDOR,
                "versions": [
                    {"version": "0", "status": "affected", "versionType": "semver"}
                ],
                "defaultStatus": "unaffected",
            }
        )
    return entries


def finding_to_cve_draft(finding: "Finding") -> dict:
    """Map a Finding to a CVE Record Format 5.1 *draft* (a plain dict).

    The draft is deliberately non-submittable: sentinel ``cveId`` and zeroed
    placeholder identities. Optional blocks are omitted rather than faked.
    """
    cna: dict = {
        "providerMetadata": {
            "orgId": _ZEROED_ORG_UUID,
            "shortName": _PLACEHOLDER_CNA_SHORTNAME,
        },
        "descriptions": [{"lang": "en", "value": _description_value(finding)}],
        "affected": _affected(finding),
    }

    # Omit the metrics block entirely when there is no severity — or when the
    # vector is not CVSS v3 (the metric is keyed by version: cvssV3_0/cvssV3_1).
    if finding.severity is not None:
        version = _cvss3_version(finding.severity.cvss_vector)
        if version is not None:
            key = "cvssV3_1" if version == "3.1" else "cvssV3_0"
            cna["metrics"] = [
                {
                    key: {
                        "version": version,
                        "vectorString": finding.severity.cvss_vector,
                        "baseScore": finding.severity.cvss_score,
                        "baseSeverity": _base_severity(finding.severity.cvss_score),
                    }
                }
            ]

    # references is required (minItems 1) and each url must be non-empty. Carry
    # EVERY non-empty finding reference url (so a later advisory/fix link is not
    # dropped and an empty first url does not emit an invalid ""), falling back to
    # a stable placeholder only when the finding has no usable url at all.
    ref_urls = [r.url for r in finding.references if r.url and r.url.strip()]
    if not ref_urls:
        ref_urls = [f"https://deepthought.invalid/finding/{osv_id_for(finding.id)}"]
    cna["references"] = [{"url": url, "tags": ["vdb-entry"]} for url in ref_urls]

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


def _is_sentinel_cveid_error(error) -> bool:
    """True only for the INTENDED sentinel deviation: a ``pattern`` failure at
    ``cveId``.

    Suppressing every ``cveId`` error would mask a genuinely malformed id (an
    integer, ``null``, an empty string — which fail with ``type``/``minLength``).
    Only the sentinel's ``pattern`` failure is the deliberate, tolerated
    deviation; the caller further gates this on the value actually being the
    sentinel, so a non-sentinel pattern miss is still reported.
    """
    if error.validator != "pattern":
        return False
    return any(str(p) == "cveId" for p in error.absolute_path) or any(
        str(p) == "cveId" for p in error.absolute_schema_path
    )


def validate_cve_draft(doc: dict) -> list[str]:
    """Return CVE-schema violations, dropping ONLY the intentional cveId sentinel.

    A structurally-complete draft returns ``[]`` even though its ``cveId`` is the
    non-submittable sentinel ``CVE-XXXX-XXXXX``: the sentinel's ``pattern`` failure
    is the deliberate placeholder deviation and is dropped — but ONLY when the
    ``cveId`` really is the sentinel. A malformed ``cveId`` (wrong type, empty, or
    any other non-sentinel value) is still reported, as is every other violation,
    each as a sorted ``"path: message"`` string.
    """
    schema = _published_schema()
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema, registry=_registry())
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))

    metadata = doc.get("cveMetadata")
    cveid = metadata.get("cveId") if isinstance(metadata, dict) else None
    tolerate_sentinel = cveid == _SENTINEL_CVE_ID

    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in errors
        if not (tolerate_sentinel and _is_sentinel_cveid_error(e))
    ]
