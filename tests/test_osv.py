"""T003 — Finding model and OSV export.

A Finding serializes to OSV that validates against the pinned OSV schema, the
field map round-trips, and ``cve`` mirrors into ``aliases``.
"""

from __future__ import annotations

from deepthought.export.osv import (
    finding_to_osv,
    internal_id_for,
    osv_id_for,
    validate_osv,
)

from .conftest import VALID_CVSS, make_finding


def test_osv_validates_against_pinned_schema():
    osv = finding_to_osv(make_finding())
    errors = validate_osv(osv)
    assert errors == [], errors


def test_field_map_round_trips():
    finding = make_finding(
        aliases=["GHSA-xxxx-yyyy-zzzz"], published="2026-06-30T00:00:00Z"
    )
    osv = finding_to_osv(finding)

    assert internal_id_for(osv["id"]) == finding.id
    assert osv_id_for(finding.id) == osv["id"]
    assert osv["summary"] == finding.summary
    assert osv["published"] == finding.published
    assert set(finding.aliases).issubset(set(osv["aliases"]))

    # severity maps to the matching CVSS type with the vector as score
    assert osv["severity"][0]["type"] == "CVSS_V3"
    assert osv["severity"][0]["score"] == VALID_CVSS

    # affected maps package + versions
    pkg = osv["affected"][0]
    assert pkg["package"]["ecosystem"] == "Packagist"
    assert pkg["package"]["name"] == "php/php-src"
    assert pkg["versions"] == ["8.3.0", "8.3.1"]

    # references map to the OSV enum (advisory -> ADVISORY)
    assert osv["references"][0]["type"] == "ADVISORY"


def test_cve_mirrors_into_aliases():
    finding = make_finding(cve="CVE-2026-12345")
    osv = finding_to_osv(finding)
    assert "CVE-2026-12345" in osv["aliases"]


def test_details_assembled_from_body():
    osv = finding_to_osv(make_finding())
    assert "Root cause" in osv["details"]
    assert "Impact" in osv["details"]


def test_unknown_reference_type_maps_to_web_and_still_validates():
    finding = make_finding(
        references=[{"type": "blog-post", "url": "https://example.test/x"}]
    )
    osv = finding_to_osv(finding)
    assert osv["references"][0]["type"] == "WEB"
    assert validate_osv(osv) == []


def test_cvss_v4_type_detected():
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    finding = make_finding(severity={"cvss_vector": v4, "cvss_score": 9.3})
    osv = finding_to_osv(finding)
    assert osv["severity"][0]["type"] == "CVSS_V4"
    assert validate_osv(osv) == []


def test_corrupt_osv_is_reported():
    osv = finding_to_osv(make_finding())
    del osv["id"]  # id is required by OSV
    assert validate_osv(osv) != []
