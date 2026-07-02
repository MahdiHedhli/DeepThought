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
    # no CVE -> the osv_id_for-prefixed internal id is the vulnerability name
    no_cve = finding_to_openvex(make_finding(cve=None))
    assert no_cve["statements"][0]["vulnerability"]["name"] == "x_F-0007"

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
    for bad in ("CVE-XXXX-XXXXX", "CVE-2026-1", "not-a-cve", "CVE-2026-" + "1" * 20):
        doc = finding_to_openvex(make_finding(cve=bad))
        assert doc["statements"][0]["vulnerability"]["name"] == "x_F-0007"
    # A real CVE is used verbatim.
    doc = finding_to_openvex(make_finding(cve="CVE-2026-12345"))
    assert doc["statements"][0]["vulnerability"]["name"] == "CVE-2026-12345"


def test_openvex_cve_shaped_id_without_cve_is_not_presented_as_a_cve():
    """A CVE-SHAPED finding id (with no recorded cve) must NOT become the
    vulnerability name verbatim — it is prefixed so it can't look assigned."""
    doc = finding_to_openvex(make_finding(id="CVE-2026-99999", cve=None))
    name = doc["statements"][0]["vulnerability"]["name"]
    assert name == "x_CVE-2026-99999"


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


def test_product_id_is_a_well_formed_uri_for_ecosystems_with_spaces():
    """An OSV ecosystem containing spaces (e.g. 'GitHub Actions') must still yield
    a well-formed, space-free @id — the PURL components are percent-encoded."""
    from deepthought.schema import AffectedPackage

    doc = finding_to_openvex(
        make_finding(affected=[AffectedPackage(ecosystem="GitHub Actions", package="org/pkg", versions=["1.0"])])
    )
    pid = doc["statements"][0]["products"][0]["@id"]
    assert " " not in pid
    assert pid.startswith("pkg:github%20actions/")
    assert validate_openvex(doc) == []


def test_emits_a_product_for_every_affected_package_and_version():
    """The OpenVEX statement carries one product per (package, version) — the full
    affected scope, not just the first."""
    from deepthought.schema import AffectedPackage

    doc = finding_to_openvex(
        make_finding(
            affected=[
                AffectedPackage(ecosystem="Packagist", package="php/php-src", versions=["8.3.0", "8.3.1"]),
                AffectedPackage(ecosystem="PyPI", package="foo", versions=["1.0"]),
            ]
        )
    )
    ids = [p["@id"] for p in doc["statements"][0]["products"]]
    assert len(ids) == 3
    assert any("8.3.0" in i for i in ids)
    assert any("8.3.1" in i for i in ids)
    assert any("foo" in i for i in ids)
    assert validate_openvex(doc) == []


def test_validate_requires_non_empty_strings_not_truthy_values():
    """A corrupted persisted draft with a non-string vulnerability.name / @id /
    action_statement (e.g. a number) is REPORTED — a truthiness check would wrongly
    accept it."""
    doc = finding_to_openvex(make_finding())
    doc["statements"][0]["vulnerability"]["name"] = 123
    assert any("vulnerability/name" in e for e in validate_openvex(doc))

    doc2 = finding_to_openvex(make_finding())
    doc2["statements"][0]["products"][0]["@id"] = 123
    assert any("@id" in e for e in validate_openvex(doc2))

    doc3 = finding_to_openvex(make_finding())
    doc3["@id"] = 42
    assert any("@id" in e for e in validate_openvex(doc3))


def test_products_are_deduplicated_and_uniqueness_is_validated():
    """Duplicate affected versions must not yield duplicate product @ids (OpenVEX
    products must be unique); the validator also reports a hand-built duplicate."""
    from deepthought.schema import AffectedPackage

    doc = finding_to_openvex(
        make_finding(affected=[AffectedPackage(ecosystem="PyPI", package="p", versions=["1.0", "1.0"])])
    )
    ids = [p["@id"] for p in doc["statements"][0]["products"]]
    assert len(ids) == len(set(ids)) == 1
    assert validate_openvex(doc) == []
    # A hand-built duplicate is reported.
    doc["statements"][0]["products"] = [{"@id": "pkg:x/y"}, {"@id": "pkg:x/y"}]
    assert any("unique" in e for e in validate_openvex(doc))


def test_whitespace_finding_id_yields_a_valid_document_id():
    """A model-valid finding id with whitespace must not produce an invalid @id /
    product IRI — the id is percent-encoded."""
    doc = finding_to_openvex(make_finding(id="F 0007", affected=[]))
    assert " " not in doc["@id"]
    assert " " not in doc["statements"][0]["products"][0]["@id"]
    assert validate_openvex(doc) == []


def test_validate_enforces_timestamp_date_time_format():
    """A non-date timestamp is reported (not merely required non-empty)."""
    doc = finding_to_openvex(make_finding())
    doc["timestamp"] = "not-a-date"
    assert any("timestamp" in e for e in validate_openvex(doc))


def test_validate_enforces_context_and_version_values():
    """@context must be the pinned OpenVEX context and version a positive integer —
    a corrupted draft with a wrong context or a non-integer version is reported."""
    doc = finding_to_openvex(make_finding())
    assert validate_openvex(doc) == []  # our draft is conformant

    bad_ctx = finding_to_openvex(make_finding())
    bad_ctx["@context"] = "https://example.test/not-openvex"
    assert any("@context" in e for e in validate_openvex(bad_ctx))

    for bad_version in ("1", 1.5, True, 0):
        bad = finding_to_openvex(make_finding())
        bad["version"] = bad_version
        assert any("version" in e for e in validate_openvex(bad)), bad_version


def test_validate_does_not_crash_on_non_string_status():
    """A non-string status (JSON object/array — unhashable) is REPORTED, not a
    crash — the set-membership test is guarded by an isinstance check."""
    doc = finding_to_openvex(make_finding())
    doc["statements"][0]["status"] = {"weird": True}
    errors = validate_openvex(doc)
    assert isinstance(errors, list)
    assert any("status" in e for e in errors)


def test_range_affected_package_keeps_a_versionless_product():
    """A package with exact versions AND OSV ranges emits a versionless product
    PURL for the range scope, so the range is not dropped."""
    from deepthought.schema import AffectedPackage

    doc = finding_to_openvex(
        make_finding(affected=[AffectedPackage(
            ecosystem="PyPI", package="foo", versions=["1.0"],
            ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "3.0"}]}],
        )])
    )
    ids = {p["@id"] for p in doc["statements"][0]["products"]}
    assert "pkg:pypi/foo@1.0" in ids       # the exact version
    assert "pkg:pypi/foo" in ids            # the versionless (range) product
    assert validate_openvex(doc) == []


def test_validate_does_not_crash_on_non_list_statements():
    """A truthy-but-non-list statements value must be REPORTED, not raise — the
    validator's list[str] contract holds for any input."""
    errors = validate_openvex({"@context": "x", "@id": "y", "author": "z",
                               "timestamp": "t", "version": 1, "statements": 1})
    assert isinstance(errors, list)
    assert any("statements" in e for e in errors)
