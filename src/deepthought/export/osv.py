"""Finding -> OSV mapping and OSV schema validation.

OSV is the canonical finding record. Front-matter mirrors OSV field names where
it can, so this is a mapping rather than a translation. ``check`` validates
every finding's OSV against the pinned schema bundled in this package.

The OSV ``id`` must carry a known home-database prefix. Deep Thought is the home
database, so internal ids (``F-0007``) are exported under the reserved ``x_``
local prefix (``x_F-0007``). The CVE, when present, is mirrored into ``aliases``.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources
from typing import TYPE_CHECKING

import jsonschema

from ..schema.common import iso_z, utcnow

if TYPE_CHECKING:  # pragma: no cover
    from ..schema.finding import Finding

# Pinned OSV schema version. The bundled schema.json is the validator.
OSV_SCHEMA_VERSION = "1.7.0"

_OSV_ID_LOCAL_PREFIX = "x_"

# OSV reference-type enum. Anything unrecognised maps to WEB.
_OSV_REF_TYPES = {
    "ADVISORY",
    "ARTICLE",
    "DETECTION",
    "DISCUSSION",
    "REPORT",
    "FIX",
    "INTRODUCED",
    "GIT",
    "PACKAGE",
    "EVIDENCE",
    "WEB",
}


@lru_cache(maxsize=1)
def _osv_schema() -> dict:
    text = resources.files("deepthought.export").joinpath("osv_schema.json").read_text()
    return json.loads(text)


def osv_id_for(internal_id: str) -> str:
    """Map an internal finding id to a schema-valid OSV id."""
    if internal_id.startswith(_OSV_ID_LOCAL_PREFIX):
        return internal_id
    return f"{_OSV_ID_LOCAL_PREFIX}{internal_id}"


def internal_id_for(osv_id: str) -> str:
    """Reverse of :func:`osv_id_for`, for round-tripping."""
    if osv_id.startswith(_OSV_ID_LOCAL_PREFIX):
        return osv_id[len(_OSV_ID_LOCAL_PREFIX) :]
    return osv_id


def _severity_type(vector: str) -> str:
    if vector.startswith("CVSS:4"):
        return "CVSS_V4"
    if vector.startswith("CVSS:3"):
        return "CVSS_V3"
    return "CVSS_V2"


def _ref_type(raw: str) -> str:
    upper = raw.strip().upper()
    return upper if upper in _OSV_REF_TYPES else "WEB"


def _section(body: str, heading: str) -> str:
    pattern = re.compile(
        rf"^##\s+{re.escape(heading)}\s*$(.*?)(?=^##\s|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(body or "")
    return match.group(1).strip() if match else ""


def _details(finding: "Finding") -> str:
    """Assemble OSV ``details`` from the body root cause and impact narrative."""
    parts: list[str] = []
    root_cause = _section(finding.body, "Root cause")
    if root_cause:
        parts.append(f"## Root cause\n\n{root_cause}")
    impact = _section(finding.body, "Impact") or (finding.downstream_impact or "")
    if impact:
        parts.append(f"## Impact\n\n{impact}")
    return "\n\n".join(parts)


def _aliases(finding: "Finding") -> list[str]:
    aliases = list(finding.aliases)
    if finding.cve and finding.cve not in aliases:
        aliases.append(finding.cve)
    return aliases


def finding_to_osv(finding: "Finding") -> dict:
    """Map a Finding to an OSV record (a plain dict, JSON-serializable)."""
    modified = finding.modified or iso_z(utcnow())
    osv: dict = {
        "schema_version": OSV_SCHEMA_VERSION,
        "id": osv_id_for(finding.id),
        "modified": modified,
        "summary": finding.summary,
    }

    aliases = _aliases(finding)
    if aliases:
        osv["aliases"] = aliases
    if finding.published:
        osv["published"] = finding.published

    details = _details(finding)
    if details:
        osv["details"] = details

    if finding.severity:
        osv["severity"] = [
            {
                "type": _severity_type(finding.severity.cvss_vector),
                "score": finding.severity.cvss_vector,
            }
        ]

    affected: list[dict] = []
    for pkg in finding.affected:
        entry: dict = {"package": {"ecosystem": pkg.ecosystem, "name": pkg.package}}
        if pkg.ranges:
            entry["ranges"] = pkg.ranges
        if pkg.versions:
            entry["versions"] = pkg.versions
        affected.append(entry)
    if affected:
        osv["affected"] = affected

    if finding.references:
        osv["references"] = [
            {"type": _ref_type(ref.type), "url": ref.url} for ref in finding.references
        ]

    return osv


def validate_osv(osv: dict) -> list[str]:
    """Return a list of OSV schema violations. Empty means conformant."""
    schema = _osv_schema()
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)
    errors = sorted(validator.iter_errors(osv), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]
