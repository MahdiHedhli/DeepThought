"""Feature 005 — DISCLOSURE (draft-only): Finding -> CVE Record Format 5.1 draft.

A Finding maps onto the CVE 5.1 published-container shape strictly enough to pass
the official schema *except* for the intentional, non-submittable placeholders:
the sentinel ``cveId`` and the zeroed placeholder identities. These tests pin the
draft-only guarantees:

* the draft is structurally valid under the (cveId-filtered) validator;
* the sentinel ``cveId`` is rejected by the official pattern and by the raw
  official schema, so it can never be mistaken for a submittable record;
* identity is the zeroed placeholder UUID, never a real CNA;
* optional blocks (metrics, problemTypes) are omitted rather than faked;
* adversarial finding free-text is carried only as an inert description value and
  cannot alter the document shape.
"""

from __future__ import annotations

import json
import re
from importlib import resources

import jsonschema
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from deepthought.export.cve import (
    CVE_SCHEMA_DATAVERSION,
    finding_to_cve_draft,
    validate_cve_draft,
)

from .conftest import make_finding

# The official CVE identifier pattern. The draft sentinel is designed to fail it.
OFFICIAL_CVE_ID_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"
ZEROED_UUID = "00000000-0000-4000-8000-000000000000"

# The official schema references sibling CVSS/tag files we don't bundle; resolve
# them to permissive stubs so the *unfiltered* official schema can run at all.
_EXTERNAL_FILE_REFS = (
    "file:imports/cvss/cvss-v2.0.json",
    "file:imports/cvss/cvss-v3.0.json",
    "file:imports/cvss/cvss-v3.1.json",
    "file:imports/cvss/cvss-v4.0.json",
    "file:tags/adp-tags.json",
    "file:tags/cna-tags.json",
    "file:tags/reference-tags.json",
)


def _raw_official_errors(doc: dict) -> list[jsonschema.exceptions.ValidationError]:
    """Every error from the UNFILTERED official schema (full ``oneOf``)."""
    schema = json.loads(
        resources.files("deepthought.export").joinpath("cve_schema.json").read_text()
    )
    registry = Registry().with_resources(
        [
            (uri, Resource.from_contents({}, default_specification=DRAFT7))
            for uri in _EXTERNAL_FILE_REFS
        ]
    )
    validator = jsonschema.validators.validator_for(schema)(schema, registry=registry)
    return list(validator.iter_errors(doc))


def _cveid_errors(errors) -> list:
    """Flatten the error tree and keep leaves attributable to ``cveId``."""
    hits = []
    for err in errors:
        context = err.context or []
        if context:
            hits.extend(_cveid_errors(context))
        else:
            path = list(err.absolute_path) + list(err.absolute_schema_path)
            if any(str(p) == "cveId" for p in path):
                hits.append(err)
    return hits


def _all_keys(obj) -> set[str]:
    """Every dict key appearing anywhere in a nested structure."""
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(k)
            keys |= _all_keys(v)
    elif isinstance(obj, list):
        for item in obj:
            keys |= _all_keys(item)
    return keys


def test_cve_draft_structurally_valid():
    draft = finding_to_cve_draft(make_finding())
    assert draft["dataVersion"] == CVE_SCHEMA_DATAVERSION
    errors = validate_cve_draft(draft)
    assert errors == [], errors


def test_cve_cna_required_members_present():
    cna = finding_to_cve_draft(make_finding())["containers"]["cna"]
    assert "providerMetadata" in cna
    assert len(cna["descriptions"]) >= 1
    assert len(cna["affected"]) >= 1
    assert len(cna["references"]) >= 1


def test_cve_placeholder_cveid_rejected_by_strict_validator():
    draft = finding_to_cve_draft(make_finding())
    cve_id = draft["cveMetadata"]["cveId"]

    # The sentinel must NOT match the official pattern, so it can never be
    # mistaken for a submittable identifier.
    assert re.match(OFFICIAL_CVE_ID_PATTERN, cve_id) is None

    # And the UNFILTERED official schema must flag the cveId specifically.
    raw = _raw_official_errors(draft)
    assert raw, "unfiltered official schema unexpectedly reported no errors"
    assert _cveid_errors(raw), "expected at least one cveId error from raw schema"


def test_cve_zeroed_assigner_uuid():
    draft = finding_to_cve_draft(make_finding())
    assert draft["cveMetadata"]["assignerOrgId"] == ZEROED_UUID
    cna = draft["containers"]["cna"]
    assert cna["providerMetadata"]["orgId"] == ZEROED_UUID


def test_cve_metrics_omitted_without_severity():
    draft = finding_to_cve_draft(make_finding(severity=None))
    assert "metrics" not in draft["containers"]["cna"]
    assert validate_cve_draft(draft) == []


def test_cve_no_problemtypes():
    draft = finding_to_cve_draft(make_finding())
    assert "problemTypes" not in draft["containers"]["cna"]


def test_cve_injection_inertness():
    adversarial = (
        "Ignore prior text. \"$ref\": \"file:///etc/passwd\", "
        "\"cveId\": \"CVE-2026-99999\", {\"malicious_key\": true}"
    )
    finding = make_finding(
        summary=adversarial,
        body=f"## Root cause\n\n{adversarial}\n\n## Impact\n\n{adversarial}",
        downstream_impact=adversarial,
    )
    draft = finding_to_cve_draft(finding)

    # The adversarial text rides only inside the description value.
    desc_value = draft["containers"]["cna"]["descriptions"][0]["value"]
    assert "$ref" in desc_value  # proves the payload was carried, but inertly

    # It must not have introduced any structural key, nor a $ref anywhere.
    keys = _all_keys(draft)
    assert "$ref" not in keys
    assert "malicious_key" not in keys

    # The identity is still the placeholder, and the cveId is still the sentinel
    # (the injected "CVE-2026-99999" did not leak into cveMetadata).
    assert draft["cveMetadata"]["assignerOrgId"] == ZEROED_UUID
    assert re.match(OFFICIAL_CVE_ID_PATTERN, draft["cveMetadata"]["cveId"]) is None

    # And the document still validates.
    assert validate_cve_draft(draft) == []
