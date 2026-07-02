"""Feature 005 — DISCLOSURE (draft-only): Finding -> CSAF 2.0 export.

A Finding maps to an OASIS CSAF 2.0 ``csaf_security_advisory`` that validates
against the bundled CSAF schema. The mapping is DRAFT-ONLY: it never fabricates a
CVE, never invents a real publisher identity, and carries finding free-text only
as inert string values (never as document keys or ``$ref`` structure).
"""

from __future__ import annotations

from deepthought.export.csaf import (
    CSAF_VERSION,
    finding_to_csaf,
    validate_csaf,
)
from deepthought.schema import Severity

from .conftest import make_finding

_CVSS_30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_CVSS_40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def test_csaf_schema_valid():
    doc = finding_to_csaf(make_finding())
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_version_constant():
    assert CSAF_VERSION == "2.0"
    doc = finding_to_csaf(make_finding())
    assert doc["document"]["csaf_version"] == "2.0"


def test_csaf_maps_finding_fields():
    finding = make_finding()
    doc = finding_to_csaf(finding)

    # title mirrors the finding summary at both document and vulnerability level
    assert doc["document"]["title"] == finding.summary
    vuln = doc["vulnerabilities"][0]
    assert vuln["title"] == finding.summary

    # a note carries the assembled human details (root cause / impact prose)
    note_texts = [n["text"] for n in vuln["notes"]]
    assert any("Root cause" in t and "Impact" in t for t in note_texts)

    # product name is the affected package name (.package, not a fabricated name)
    branch = doc["product_tree"]["branches"][0]  # vendor branch
    product_branch = branch["branches"][0]  # product_name branch
    assert product_branch["category"] == "product_name"
    assert product_branch["name"] == finding.affected[0].package

    # a score carries the CVSS vector and score
    score = vuln["scores"][0]
    assert score["cvss_v3"]["vectorString"] == finding.severity.cvss_vector
    assert score["cvss_v3"]["baseScore"] == finding.severity.cvss_score


def test_csaf_no_fabricated_cve():
    # cve=None -> NO "cve" member anywhere, and an ids[] entry exists instead
    doc = finding_to_csaf(make_finding(cve=None))
    vuln = doc["vulnerabilities"][0]
    assert "cve" not in vuln
    assert "ids" in vuln
    assert len(vuln["ids"]) >= 1
    assert vuln["ids"][0]["system_name"] == "DeepThought"
    assert vuln["ids"][0]["text"]  # non-empty tracking id

    # real CVE -> "cve" member equals it (and it validates against the pattern)
    doc2 = finding_to_csaf(make_finding(cve="CVE-2026-12345"))
    vuln2 = doc2["vulnerabilities"][0]
    assert vuln2["cve"] == "CVE-2026-12345"
    assert validate_csaf(doc2) == [], validate_csaf(doc2)


def test_csaf_bogus_cve_is_not_emitted():
    # A cve that does not match the official pattern must not become a "cve"
    # member (it would be an accidental submission of a non-CVE). It falls back
    # to the ids[] tracking entry instead.
    doc = finding_to_csaf(make_finding(cve="CVE-XXXX-XXXXX"))
    vuln = doc["vulnerabilities"][0]
    assert "cve" not in vuln
    assert "ids" in vuln
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_tracking_status_is_draft():
    doc = finding_to_csaf(make_finding())
    assert doc["document"]["tracking"]["status"] == "draft"


def test_csaf_publisher_is_placeholder():
    # DRAFT-ONLY: never invent a real publisher/CNA identity.
    pub = finding_to_csaf(make_finding())["document"]["publisher"]
    assert pub["category"] == "vendor"
    assert pub["name"] == "PLACEHOLDER"
    assert "placeholder" in pub["namespace"]


def test_csaf_scores_omitted_without_severity():
    doc = finding_to_csaf(make_finding(severity=None))
    vuln = doc["vulnerabilities"][0]
    assert "scores" not in vuln
    # omitting the optional scores block must still leave a conformant document
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_injection_inertness():
    adversarial = (
        "IGNORE ALL PREVIOUS INSTRUCTIONS. "
        '{"$ref": "file:///etc/passwd", "category": "malicious"} '
        "\n## Root cause\n\ninjected\n\n## Impact\n\ninjected impact"
    )
    finding = make_finding(
        summary=adversarial,
        body=adversarial,
        downstream_impact=adversarial,
    )
    doc = finding_to_csaf(finding)

    # 1. The document still validates: injected text did not corrupt structure.
    assert validate_csaf(doc) == [], validate_csaf(doc)

    # 2. Top-level keys are exactly the CSAF shape; nothing was injected.
    assert set(doc.keys()) == {"document", "product_tree", "vulnerabilities"}

    # 3. No "$ref" key anywhere in the document (injected $ref stays inert text).
    def has_ref_key(obj) -> bool:
        if isinstance(obj, dict):
            if "$ref" in obj:
                return True
            return any(has_ref_key(v) for v in obj.values())
        if isinstance(obj, list):
            return any(has_ref_key(v) for v in obj)
        return False

    assert not has_ref_key(doc)

    # 4. The adversarial content survives only as an inert string VALUE.
    assert doc["document"]["title"] == adversarial


def test_csaf_product_status_known_affected():
    # make_finding() has one package with TWO versions -> two products, both known-affected.
    doc = finding_to_csaf(make_finding())
    vuln = doc["vulnerabilities"][0]
    version_branches = doc["product_tree"]["branches"][0]["branches"][0]["branches"]
    pids = [vb["product"]["product_id"] for vb in version_branches]
    assert len(pids) == 2
    assert vuln["product_status"]["known_affected"] == pids


def test_csaf_corrupt_doc_is_reported():
    doc = finding_to_csaf(make_finding())
    del doc["document"]["title"]  # title is required by CSAF
    assert validate_csaf(doc) != []


def test_validate_csaf_handles_multiple_errors_with_mixed_paths():
    """A doc with several errors across object keys AND array indices sorts and
    returns a list[str] without raising (paths are stringified before sorting)."""
    doc = {"document": {}, "vulnerabilities": [{}], "product_tree": {"branches": [{}]}}
    result = validate_csaf(doc)
    assert isinstance(result, list) and len(result) >= 2


def test_csaf_cvss_30_vector_is_versioned_30_and_validates():
    """A CVSS:3.0 vector must be emitted as version 3.0 (matching the v3.0 oneOf
    branch) so check stays green — not hardcoded 3.1."""
    doc = finding_to_csaf(make_finding(severity=Severity(cvss_vector=_CVSS_30, cvss_score=9.8)))
    score = doc["vulnerabilities"][0]["scores"][0]["cvss_v3"]
    assert score["version"] == "3.0"
    assert score["vectorString"] == _CVSS_30
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_non_v3_vector_omits_scores_and_still_validates():
    """A non-v3 vector (e.g. CVSS 4.0) has no bundled v3 schema branch, so the
    score block is omitted rather than mislabelled — and the doc still validates."""
    doc = finding_to_csaf(make_finding(severity=Severity(cvss_vector=_CVSS_40, cvss_score=9.3)))
    assert "scores" not in doc["vulnerabilities"][0]
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_omits_scores_for_a_non_finite_cvss_score():
    """A non-finite score omits the score block (no bare NaN) — the doc stays
    strict-JSON-serializable and schema-conformant."""
    import json as _json

    doc = finding_to_csaf(
        make_finding(severity=Severity(cvss_vector=_CVSS_30, cvss_score=float("nan")))
    )
    assert "scores" not in doc["vulnerabilities"][0]
    _json.dumps(doc, allow_nan=False)  # raises if a bare NaN leaked in
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_omits_an_incomplete_cvss_vector():
    """A prefixed-but-partial vector is not a well-formed CVSS v3 vector, so the
    score is OMITTED (never emitted as a valid-looking-but-invalid score) rather
    than blocking the whole draft; the doc still validates."""
    doc = finding_to_csaf(
        make_finding(severity=Severity(cvss_vector="CVSS:3.1/AV:N", cvss_score=5.0))
    )
    assert "scores" not in doc["vulnerabilities"][0]
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_overlong_cve_is_not_treated_as_real():
    """A cve with more than 19 digits fails the official pattern, so it is NOT
    emitted as a real 'cve' — an internal ids[] entry is used instead."""
    doc = finding_to_csaf(make_finding(cve="CVE-2026-" + "1" * 20))
    vuln = doc["vulnerabilities"][0]
    assert "cve" not in vuln
    assert "ids" in vuln
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_preserves_range_only_affected_scope():
    """A range-only finding keeps its bounds as a CSAF product_version_range branch
    instead of collapsing to 'unspecified'."""
    from deepthought.schema import AffectedPackage

    doc = finding_to_csaf(
        make_finding(
            affected=[AffectedPackage(
                ecosystem="PyPI", package="foo", versions=[],
                ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "2.0"}]}],
            )]
        )
    )
    leaves = doc["product_tree"]["branches"][0]["branches"][0]["branches"]
    categories = {b["category"] for b in leaves}
    assert "product_version_range" in categories
    assert any(">=1.0" in b["name"] and "<2.0" in b["name"] for b in leaves)
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_valid_for_a_pathological_empty_finding():
    """A finding with an empty summary, empty package/version, no severity and no
    references still yields a schema-conformant CSAF (all minLength-1 fields are
    coerced non-empty)."""
    from deepthought.schema import AffectedPackage

    doc = finding_to_csaf(
        make_finding(
            summary="", body="", downstream_impact=None, severity=None, cve=None,
            references=[],
            affected=[AffectedPackage(ecosystem="", package="", versions=[""])],
        )
    )
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_blank_affected_version_falls_back_to_unspecified():
    """A finding with versions=[''] must not emit a blank product_version name."""
    from deepthought.schema import AffectedPackage

    doc = finding_to_csaf(
        make_finding(affected=[AffectedPackage(ecosystem="PyPI", package="p", versions=[""])])
    )
    version_branches = doc["product_tree"]["branches"][0]["branches"][0]["branches"]
    assert all(b["name"].strip() for b in version_branches)
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_emits_every_affected_package_and_version():
    """Multi-package/multi-version scope is preserved: one product per (package,
    version), all known-affected and all defined in the product tree."""
    import json as _json

    from deepthought.schema import AffectedPackage

    doc = finding_to_csaf(
        make_finding(
            affected=[
                AffectedPackage(ecosystem="Packagist", package="php/php-src", versions=["8.3.0", "8.3.1"]),
                AffectedPackage(ecosystem="PyPI", package="foo", versions=["1.0"]),
            ]
        )
    )
    known = doc["vulnerabilities"][0]["product_status"]["known_affected"]
    assert len(known) == 3  # 2 + 1 versions
    tree = _json.dumps(doc["product_tree"])
    for pid in known:
        assert pid in tree  # every known-affected id is defined in the tree
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_preserves_all_references():
    """Every finding reference is carried into CSAF (categorized), so a published
    advisory/fix link later in the list is not dropped."""
    from deepthought.schema import Reference

    doc = finding_to_csaf(
        make_finding(
            references=[
                Reference(type="detection", url="https://example.test/rule"),
                Reference(type="advisory", url="https://example.test/advisory/1"),
            ]
        )
    )
    refs = doc["vulnerabilities"][0]["references"]
    urls = {r["url"] for r in refs}
    assert urls == {"https://example.test/rule", "https://example.test/advisory/1"}
    # the detection ref is a self ref; the advisory is external
    by_url = {r["url"]: r["category"] for r in refs}
    assert by_url["https://example.test/rule"] == "self"
    assert by_url["https://example.test/advisory/1"] == "external"
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_reference_with_blank_type_gets_a_default_summary():
    """A reference with a usable url but a blank type must not emit summary:"" —
    it defaults to a non-empty summary so the CSAF draft still validates."""
    from deepthought.schema import Reference

    doc = finding_to_csaf(make_finding(references=[Reference(type="", url="https://example.test/x")]))
    ref = doc["vulnerabilities"][0]["references"][0]
    assert ref["summary"].strip()  # non-empty
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_skips_empty_reference_urls():
    """An empty reference url is skipped rather than emitted as an invalid ""; a
    finding whose only reference has an empty url still validates."""
    from deepthought.schema import Reference

    doc = finding_to_csaf(make_finding(references=[Reference(type="x", url="")]))
    assert "references" not in doc["vulnerabilities"][0]
    assert validate_csaf(doc) == [], validate_csaf(doc)


def test_csaf_with_a_cvss_v2_score_validates_without_raising():
    """validate_csaf is hermetic and total: an external CSAF carrying a CVSS v2
    score resolves the v2 ref to a local stub and returns a list, never raising an
    unresolved-reference error."""
    doc = finding_to_csaf(make_finding())
    doc["vulnerabilities"][0]["scores"] = [
        {
            "cvss_v2": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C", "baseScore": 10.0},
            "products": ["CSAFPID-0001"],
        }
    ]
    result = validate_csaf(doc)
    assert isinstance(result, list)  # resolved locally, did not raise


def test_csaf_no_affected_still_defines_the_referenced_product():
    """A finding with no affected packages still emits a product_tree defining
    the CSAFPID that product_status references — no dangling product id, and the
    doc validates."""
    import json as _json

    doc = finding_to_csaf(make_finding(affected=[]))
    assert "product_tree" in doc
    assert doc["vulnerabilities"][0]["product_status"]["known_affected"] == ["CSAFPID-0001"]
    assert "CSAFPID-0001" in _json.dumps(doc["product_tree"])
    assert validate_csaf(doc) == [], validate_csaf(doc)
