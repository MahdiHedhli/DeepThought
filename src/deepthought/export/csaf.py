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
* Optional blocks are omitted, never faked. If ``finding.severity`` has no
  well-formed CVSS v3 vector the ``scores`` block is omitted entirely.
* Full scope. EVERY affected package/version becomes its own product in the
  product tree and ``product_status.known_affected`` — the draft never
  under-reports the affected scope.
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
from ._cvss import cvss3_metric, cvss3_schema
from .osv import _details, osv_id_for

if TYPE_CHECKING:  # pragma: no cover
    from ..schema.finding import Finding

# Pinned CSAF specification version. The bundled csaf_schema.json is the validator.
CSAF_VERSION = "2.0"

# Placeholder publisher identity — deliberately not a real CNA/vendor.
_PLACEHOLDER_NAMESPACE = "https://deepthought.local/placeholder"

# The OFFICIAL CVE id pattern (CVE 5.1 schema: 4..19 digit sequence). Only a value
# matching this is treated as a real, assigned CVE; anything else (the sentinel,
# or a malformed/over-long value) falls back to an internal id and is never
# presented as an assigned CVE.
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")

# Finding reference types that name the finding's OWN source/detection location
# (CSAF category "self"); everything else (advisory, fix, report, web, …) is an
# "external" reference — including the published advisory/fix links a disclosed or
# patched finding carries.
_SELF_REF_TYPES = frozenset({"self", "source", "detection", "location"})


def _nonempty(text: object, fallback: str) -> str:
    """A non-empty (stripped) string, or ``fallback``.

    CSAF requires minLength 1 on title / notes text / product & branch names. A
    finding's summary/package can be empty (the model does not forbid it), so
    every such field is coerced non-empty here rather than emit an invalid draft.
    """
    value = str(text).strip() if text is not None else ""
    return value if value else fallback


@lru_cache(maxsize=1)
def _csaf_schema() -> dict:
    text = resources.files("deepthought.export").joinpath("csaf_schema.json").read_text()
    return json.loads(text)


# A permissive draft-07 stub. Used for the CVSS v2 branch: this exporter never
# emits a cvss_v2 score, but ``validate_csaf`` is public and may be handed an
# externally-built CSAF that does — resolving the ref to a permissive stub keeps
# the validator hermetic and returning a ``list[str]`` instead of raising an
# unresolved-reference error.
_PERMISSIVE_STUB = {"$schema": "http://json-schema.org/draft-07/schema#"}


@lru_cache(maxsize=1)
def _cvss_registry() -> Registry:
    """A referencing Registry that resolves every CSAF CVSS ref locally.

    The bundled CSAF schema references FIRST.org CVSS v2.0/v3.0/v3.1 by URL.
    v3.0/v3.1 get the faithful shared in-code schemas (the versions this exporter
    emits); v2.0 gets a permissive stub so an external CSAF with a v2 score
    validates (its other fields strictly) rather than raising.
    """
    resources_by_uri = {
        "https://www.first.org/cvss/cvss-v2.0.json": _PERMISSIVE_STUB,
        "https://www.first.org/cvss/cvss-v3.0.json": cvss3_schema("0"),
        "https://www.first.org/cvss/cvss-v3.1.json": cvss3_schema("1"),
    }
    return Registry().with_resources(
        (uri, Resource.from_contents(schema)) for uri, schema in resources_by_uri.items()
    )


def _products(finding: "Finding") -> tuple[dict, list[str]]:
    """Build the product tree and the list of ALL product ids it defines.

    One product id per (affected package, recorded version), so the vulnerability
    can mark every affected product — the draft never collapses multi-package or
    multi-version scope to the first entry. A finding with no affected package
    still defines a single ``CSAFPID-0001`` placeholder so ``product_status``
    never references an undefined id.
    """
    if not finding.affected:
        pid = "CSAFPID-0001"
        tree = {
            "branches": [
                {
                    "category": "vendor",
                    "name": "PLACEHOLDER",
                    "branches": [
                        {
                            "category": "product_name",
                            "name": "PLACEHOLDER",
                            "branches": [
                                {
                                    "category": "product_version",
                                    "name": "unspecified",
                                    "product": {
                                        "name": "PLACEHOLDER unspecified",
                                        "product_id": pid,
                                    },
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        return tree, [pid]

    vendor_branches: list[dict] = []
    pids: list[str] = []
    counter = 1
    for pkg in finding.affected:
        # Only non-blank versions (stripped), deduped; fall back to "unspecified"
        # when none remain — a blank product_version name is non-conformant.
        versions = list(
            dict.fromkeys(v.strip() for v in (pkg.versions or []) if v and v.strip())
        ) or ["unspecified"]
        product_name = _nonempty(pkg.package, "PLACEHOLDER")  # minLength 1
        version_branches = []
        for version in versions:
            pid = f"CSAFPID-{counter:04d}"
            counter += 1
            pids.append(pid)
            version_branches.append(
                {
                    "category": "product_version",
                    "name": version,
                    "product": {
                        "name": f"{product_name} {version}",
                        "product_id": pid,
                    },
                }
            )
        vendor_branches.append(
            {
                "category": "vendor",
                "name": _nonempty(pkg.ecosystem, "PLACEHOLDER"),
                "branches": [
                    {
                        "category": "product_name",
                        "name": product_name,
                        "branches": version_branches,
                    }
                ],
            }
        )
    return {"branches": vendor_branches}, pids


def _notes(finding: "Finding") -> list[dict]:
    """A single inert summary note carrying the human details prose.

    ``notes[].text`` requires a non-empty string, so fall back to the finding
    summary when the body yields no root-cause/impact prose.
    """
    text = _nonempty(_details(finding) or finding.summary, "No details recorded.")
    return [{"category": "summary", "text": text}]


def _scores(finding: "Finding", product_ids: list[str]) -> list[dict] | None:
    """CVSS v3 score block over ALL affected products, or ``None``.

    ``None`` when there is no severity or the vector is not a well-formed v3
    vector (so a malformed vector never yields a mislabelled/invalid score).
    """
    severity = finding.severity
    if severity is None:
        return None
    metric = cvss3_metric(severity.cvss_vector, severity.cvss_score)
    if metric is None:
        return None
    return [{"cvss_v3": metric, "products": list(product_ids)}]


def _references(finding: "Finding") -> list[dict]:
    """Map EVERY non-empty finding reference into CSAF, categorized.

    Emitting only the first reference would drop a published advisory or fix URL
    later in the list (e.g. on a disclosed/patched finding). Each is carried as an
    inert url value; an empty url is skipped (it carries no link and would be
    non-conformant), and a blank type gets a non-empty default summary.
    """
    refs: list[dict] = []
    for ref in finding.references:
        if not (ref.url and ref.url.strip()):
            continue
        rtype = ref.type.strip()
        category = "self" if rtype in _SELF_REF_TYPES else "external"
        refs.append({"category": category, "summary": rtype or "reference", "url": ref.url})
    return refs


def _vulnerability(finding: "Finding", product_ids: list[str]) -> dict:
    vuln: dict = {
        "title": _nonempty(finding.summary, osv_id_for(finding.id)),
        "notes": _notes(finding),
        "product_status": {"known_affected": list(product_ids)},
    }

    # DRAFT-ONLY: emit a real CVE member only for a real CVE; otherwise carry an
    # inert internal tracking id and never a fabricated "cve".
    if finding.cve and _CVE_RE.match(finding.cve):
        vuln["cve"] = finding.cve
    else:
        vuln["ids"] = [{"system_name": "DeepThought", "text": osv_id_for(finding.id)}]

    scores = _scores(finding, product_ids)
    if scores is not None:
        vuln["scores"] = scores

    references = _references(finding)
    if references:
        vuln["references"] = references

    return vuln


def finding_to_csaf(finding: "Finding") -> dict:
    """Map a Finding to a CSAF 2.0 security-advisory document (a plain dict)."""
    now = iso_z(utcnow())
    tracking_id = osv_id_for(finding.id)
    product_tree, product_ids = _products(finding)

    return {
        "document": {
            "category": "csaf_security_advisory",
            "csaf_version": CSAF_VERSION,
            "publisher": {
                "category": "vendor",
                "name": "PLACEHOLDER",
                "namespace": _PLACEHOLDER_NAMESPACE,
            },
            "title": _nonempty(finding.summary, tracking_id),
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
        "vulnerabilities": [_vulnerability(finding, product_ids)],
        # ALWAYS define the product tree (a placeholder product for a finding with
        # no affected package), so product_status never points at an undefined id.
        "product_tree": product_tree,
    }


def validate_csaf(doc: dict) -> list[str]:
    """Return a list of CSAF schema violations. Empty means conformant."""
    schema = _csaf_schema()
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema, registry=_cvss_registry())
    # Stringify path elements before sorting: a JSON path mixes str keys and int
    # array indices, and comparing str vs int across two errors raises TypeError.
    errors = sorted(validator.iter_errors(doc), key=lambda e: [str(p) for p in e.path])
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]
