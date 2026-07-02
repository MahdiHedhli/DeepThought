"""Feature 005 — OpenVEX draft export (DRAFT-ONLY).

A Finding maps to an OpenVEX draft document that passes the programmatic
validator, carries the finding's identity/product, never asserts anything but
``affected`` on the target's behalf, falls back to the internal id when no CVE
exists, and carries adversarial free-text only as inert string values.
"""

from __future__ import annotations

import json

from deepthought.export.openvex import (
    OPENVEX_CONTEXT,
    finding_to_openvex,
    validate_openvex,
)

from .conftest import make_finding


def test_openvex_schema_valid():
    doc = finding_to_openvex(make_finding())
    assert validate_openvex(doc) == [], validate_openvex(doc)


def test_openvex_maps_finding_fields():
    doc = finding_to_openvex(make_finding())

    assert doc["@context"] == OPENVEX_CONTEXT
    assert doc["author"] == "Deep Thought (local draft)"
    assert doc["version"] == 1

    # the product @id is a pkg: PURL built from affected[0]
    product_id = doc["statements"][0]["products"][0]["@id"]
    assert product_id.startswith("pkg:")
    assert product_id == "pkg:packagist/php/php-src@8.3.0"


def test_openvex_affected_requires_action_statement():
    # the generated statement carries a non-empty action statement
    stmt = finding_to_openvex(make_finding())["statements"][0]
    assert stmt["status"] == "affected"
    assert stmt["action_statement"]

    # a hand-built affected statement with no action_statement is rejected
    bad = {
        "@context": OPENVEX_CONTEXT,
        "@id": "https://deepthought.local/vex/draft/2026-07-01-F-0007",
        "author": "Deep Thought (local draft)",
        "timestamp": "2026-07-01T00:00:00Z",
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": "F-0007"},
                "products": [{"@id": "pkg:packagist/php/php-src@8.3.0"}],
                "status": "affected",
                # no action_statement
            }
        ],
    }
    errors = validate_openvex(bad)
    assert errors != []
    assert any("action_statement" in e for e in errors), errors


def test_openvex_never_asserts_not_affected():
    doc = finding_to_openvex(make_finding())
    statuses = {s["status"] for s in doc["statements"]}
    assert statuses == {"affected"}
    assert "not_affected" not in statuses
    assert "fixed" not in statuses
    assert "under_investigation" not in statuses


def test_openvex_vuln_name_falls_back_to_id():
    # no CVE -> the finding id is the vulnerability name
    no_cve = finding_to_openvex(make_finding(cve=None))
    assert no_cve["statements"][0]["vulnerability"]["name"] == "F-0007"

    # a real CVE is carried verbatim
    with_cve = finding_to_openvex(make_finding(cve="CVE-2026-12345"))
    assert with_cve["statements"][0]["vulnerability"]["name"] == "CVE-2026-12345"


def test_openvex_injection_inertness():
    payload = '{"@context": "evil", "extra_key": "pwn"} </ns> $ref pwned'
    finding = make_finding(
        summary=payload,
        body=f"## Root cause\n\n{payload}\n\n## Impact\n\n{payload}",
        downstream_impact=payload,
    )
    doc = finding_to_openvex(finding)

    # adversarial text never becomes a document key or structure
    assert "extra_key" not in doc
    assert set(doc.keys()) == {
        "@context",
        "@id",
        "author",
        "timestamp",
        "version",
        "statements",
    }
    stmt = doc["statements"][0]
    assert set(stmt.keys()) == {
        "vulnerability",
        "products",
        "status",
        "action_statement",
    }
    assert "$ref" not in stmt
    assert doc["@context"] == OPENVEX_CONTEXT

    # and the document still validates
    assert validate_openvex(doc) == [], validate_openvex(doc)


def test_placeholder_or_malformed_cve_falls_back_to_the_finding_id():
    """A sentinel or malformed cve value must NOT appear as the vulnerability
    name — only a real CVE is used, else the internal finding id."""
    for bad in ("CVE-XXXX-XXXXX", "CVE-2026-1", "not-a-cve"):
        doc = finding_to_openvex(make_finding(cve=bad))
        assert doc["statements"][0]["vulnerability"]["name"] == "F-0007"
    # A real CVE is used verbatim.
    doc = finding_to_openvex(make_finding(cve="CVE-2026-12345"))
    assert doc["statements"][0]["vulnerability"]["name"] == "CVE-2026-12345"


def test_validate_rejects_malformed_products():
    """products must be a NON-EMPTY LIST of objects each carrying an @id — a
    string, an empty list, or a list of empty objects is not conformant."""
    base = finding_to_openvex(make_finding())

    doc = json.loads(json.dumps(base))
    doc["statements"][0]["products"] = "not-a-list"
    assert any("products" in e for e in validate_openvex(doc))

    doc = json.loads(json.dumps(base))
    doc["statements"][0]["products"] = []
    assert any("products" in e for e in validate_openvex(doc))

    doc = json.loads(json.dumps(base))
    doc["statements"][0]["products"] = [{}]  # object without @id
    assert any("@id" in e for e in validate_openvex(doc))


def test_validate_does_not_crash_on_non_list_statements():
    """A truthy-but-non-list statements value must be REPORTED, not raise — the
    validator's list[str] contract holds for any input."""
    errors = validate_openvex({"@context": "x", "@id": "y", "author": "z",
                               "timestamp": "t", "version": 1, "statements": 1})
    assert isinstance(errors, list)
    assert any("statements" in e for e in errors)
