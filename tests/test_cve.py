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

from deepthought.schema import AffectedPackage, Severity

from .conftest import make_finding

# The official CVE identifier pattern. The draft sentinel is designed to fail it.
OFFICIAL_CVE_ID_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"
ZEROED_UUID = "00000000-0000-4000-8000-000000000000"
_CVSS_30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_CVSS_40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

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


def test_cve_bounds_overlong_product_and_url():
    """An over-long affected product name or reference url would make the draft
    non-conformant; product is bounded to the schema limit and an over-long url is
    dropped, so the persisted draft still validates."""
    from deepthought.schema import AffectedPackage, Reference

    draft = finding_to_cve_draft(
        make_finding(
            affected=[AffectedPackage(ecosystem="PyPI", package="p" * 5000, versions=["1.0"])],
            references=[
                Reference(type="web", url="https://example.test/" + "a" * 5000),
                Reference(type="advisory", url="https://example.test/ok"),
            ],
        )
    )
    assert len(draft["containers"]["cna"]["affected"][0]["product"]) <= 2048
    urls = {r["url"] for r in draft["containers"]["cna"]["references"]}
    assert "https://example.test/ok" in urls
    assert all(len(u) <= 2048 for u in urls)
    assert validate_cve_draft(draft) == []


def test_cve_maps_ranges_and_never_fabricates_version_zero():
    """A range-only finding maps its OSV bounds to a CVE version-range entry
    (introduced->version, fixed->lessThan) instead of fabricating version 0; a
    finding with neither versions nor ranges uses an honest 'unspecified'."""
    from deepthought.schema import AffectedPackage

    draft = finding_to_cve_draft(
        make_finding(
            affected=[AffectedPackage(
                ecosystem="PyPI", package="foo", versions=[],
                ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "2.0"}]}],
            )]
        )
    )
    versions = draft["containers"]["cna"]["affected"][0]["versions"]
    assert {"version": "1.0", "lessThan": "2.0", "status": "affected", "versionType": "custom"} in versions
    assert all(v["version"] != "0" for v in versions)  # no fabricated version 0
    assert validate_cve_draft(draft) == []

    empty = finding_to_cve_draft(
        make_finding(affected=[AffectedPackage(ecosystem="", package="", versions=[])])
    )
    empty_versions = [v["version"] for v in empty["containers"]["cna"]["affected"][0]["versions"]]
    assert empty_versions == ["unspecified"]  # honest, not a fabricated 0


def test_cve_valid_for_a_pathological_empty_finding():
    """A finding with an empty summary/package/version, no severity and no
    references still yields a structurally-conformant CVE draft."""
    from deepthought.schema import AffectedPackage

    draft = finding_to_cve_draft(
        make_finding(
            summary="", body="", severity=None, cve=None, references=[],
            affected=[AffectedPackage(ecosystem="", package="", versions=[""])],
        )
    )
    assert validate_cve_draft(draft) == []

    # A finding with NO affected package at all (e.g. a SARIF-created finding) must
    # not fabricate an affected version 0 — it uses the honest 'unspecified' marker.
    no_pkg = finding_to_cve_draft(make_finding(affected=[]))
    versions = [v["version"] for v in no_pkg["containers"]["cna"]["affected"][0]["versions"]]
    assert versions == ["unspecified"]
    assert validate_cve_draft(no_pkg) == []


def test_cve_bounds_and_skips_empty_versions():
    """An empty version is skipped and an over-long one is bounded to 1024, so the
    persisted draft stays schema-conformant."""
    from deepthought.schema import AffectedPackage

    draft = finding_to_cve_draft(
        make_finding(affected=[AffectedPackage(ecosystem="PyPI", package="p", versions=["", "9" * 5000])])
    )
    versions = [v["version"] for v in draft["containers"]["cna"]["affected"][0]["versions"]]
    assert "" not in versions
    assert all(1 <= len(v) <= 1024 for v in versions)
    assert validate_cve_draft(draft) == []


def test_cve_omits_metric_for_a_non_finite_cvss_score():
    """A non-finite score (NaN) would serialize as bare NaN (invalid JSON); the
    metric is omitted so the draft is strict-JSON-valid and schema-conformant."""
    draft = finding_to_cve_draft(
        make_finding(severity=Severity(cvss_vector=_CVSS_30, cvss_score=float("nan")))
    )
    assert "metrics" not in draft["containers"]["cna"]
    json.dumps(draft, allow_nan=False)  # raises if a bare NaN leaked in
    assert validate_cve_draft(draft) == []


def test_cve_dedupes_versions_and_references():
    """affected[].versions and references are uniqueItems: duplicate stored
    versions/urls are collapsed so the persisted draft stays conformant."""
    from deepthought.schema import AffectedPackage, Reference

    draft = finding_to_cve_draft(
        make_finding(
            affected=[AffectedPackage(ecosystem="PyPI", package="p", versions=["1.0", "1.0", "2.0"])],
            references=[
                Reference(type="web", url="https://example.test/dup"),
                Reference(type="advisory", url="https://example.test/dup"),
            ],
        )
    )
    versions = [v["version"] for v in draft["containers"]["cna"]["affected"][0]["versions"]]
    assert versions == ["1.0", "2.0"]
    urls = [r["url"] for r in draft["containers"]["cna"]["references"]]
    assert urls == ["https://example.test/dup"]
    assert validate_cve_draft(draft) == []


def test_validate_cve_draft_handles_multiple_errors_with_mixed_paths():
    """A structurally-broken draft with errors across object keys AND array
    indices sorts and returns a list[str] without raising (paths stringified)."""
    draft = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {},
        "containers": {"cna": {"affected": [{}], "descriptions": [{}]}},
    }
    result = validate_cve_draft(draft)
    assert isinstance(result, list) and len(result) >= 2


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


def test_cve_fallback_url_encodes_a_whitespace_finding_id():
    """A finding with no usable reference url and a whitespace id yields a VALID
    placeholder URI (the id segment is percent-encoded)."""
    draft = finding_to_cve_draft(make_finding(id="F 0007", references=[]))
    urls = [r["url"] for r in draft["containers"]["cna"]["references"]]
    assert all(" " not in u for u in urls)
    assert validate_cve_draft(draft) == []


def test_cve_enforces_uri_format_on_references():
    """A corrupted persisted CVE draft with a non-URI reference url is reported —
    the validator supplies a FormatChecker."""
    draft = finding_to_cve_draft(make_finding())
    draft["containers"]["cna"]["references"][0]["url"] = "not a uri"
    assert validate_cve_draft(draft) != []


def test_validate_reports_a_malformed_cveid_not_just_the_sentinel():
    """validate_cve_draft tolerates ONLY the exact sentinel's pattern miss. A
    genuinely malformed cveId (wrong type, or a different bad string) must still
    be reported — not masked by a blanket cveId suppression."""
    for bad in (123, "", "not-a-cve"):
        draft = finding_to_cve_draft(make_finding())
        draft["cveMetadata"]["cveId"] = bad
        errors = validate_cve_draft(draft)
        assert any("cveId" in e for e in errors), f"{bad!r} should be reported: {errors}"


def test_cve_cvss_30_vector_uses_cvssV3_0_key():
    """A CVSS:3.0 vector is keyed as cvssV3_0 with version 3.0 (not mislabelled
    as cvssV3_1)."""
    draft = finding_to_cve_draft(make_finding(severity=Severity(cvss_vector=_CVSS_30, cvss_score=9.8)))
    metric = draft["containers"]["cna"]["metrics"][0]
    assert "cvssV3_0" in metric and "cvssV3_1" not in metric
    assert metric["cvssV3_0"]["version"] == "3.0"
    assert validate_cve_draft(draft) == []


def test_cve_omits_metric_for_a_malformed_v3_vector():
    """A prefixed-but-partial v3 vector is not well-formed, so no metric is
    emitted (rather than an invalid one), and the draft still validates."""
    draft = finding_to_cve_draft(
        make_finding(severity=Severity(cvss_vector="CVSS:3.1/AV:N", cvss_score=5.0))
    )
    assert "metrics" not in draft["containers"]["cna"]
    assert validate_cve_draft(draft) == []


def test_cve_validate_reports_a_malformed_cvss_metric():
    """validate_cve_draft now validates the CVSS metric against the real schema:
    an externally-corrupted metric (bad vectorString) is REPORTED, not accepted."""
    draft = finding_to_cve_draft(make_finding())  # valid cvssV3_1 metric
    draft["containers"]["cna"]["metrics"][0]["cvssV3_1"]["vectorString"] = "CVSS:3.1/AV:N"
    assert validate_cve_draft(draft) != []


def test_cve_non_v3_vector_omits_metrics():
    """A non-v3 vector (CVSS 4.0) yields no metrics block rather than a
    mislabelled one; the draft still validates structurally."""
    draft = finding_to_cve_draft(make_finding(severity=Severity(cvss_vector=_CVSS_40, cvss_score=9.3)))
    assert "metrics" not in draft["containers"]["cna"]
    assert validate_cve_draft(draft) == []


def test_validate_does_not_crash_on_non_object_input():
    """validate_cve_draft returns a list[str] for a decoded non-object draft
    (null / list), reporting the type error rather than raising."""
    for bad in (None, [], "x", 5):
        errors = validate_cve_draft(bad)
        assert isinstance(errors, list) and errors


def test_cve_drops_dangerous_scheme_references():
    """A javascript:/file: reference is dropped from the CVE draft; a safe http(s)
    reference is kept and the draft validates."""
    from deepthought.schema import Reference

    draft = finding_to_cve_draft(
        make_finding(references=[
            Reference(type="web", url="file:///etc/passwd"),
            Reference(type="advisory", url="https://ok.test/a"),
        ])
    )
    urls = {r["url"] for r in draft["containers"]["cna"]["references"]}
    assert urls == {"https://ok.test/a"}
    assert validate_cve_draft(draft) == []


def test_cve_references_skip_empty_urls_and_never_emit_blank():
    """An empty reference url must not become an invalid "" in the draft, and
    valid later urls are preserved; with no usable url a placeholder is used."""
    from deepthought.schema import Reference

    # An empty first url + a real advisory url later: the empty is skipped.
    draft = finding_to_cve_draft(
        make_finding(
            references=[Reference(type="detection", url=""),
                        Reference(type="advisory", url="https://example.test/a")]
        )
    )
    urls = {r["url"] for r in draft["containers"]["cna"]["references"]}
    assert "" not in urls
    assert "https://example.test/a" in urls
    assert validate_cve_draft(draft) == []

    # No usable url at all -> a single non-empty placeholder, still valid.
    draft2 = finding_to_cve_draft(make_finding(references=[Reference(type="x", url="")]))
    refs2 = draft2["containers"]["cna"]["references"]
    assert refs2 and all(r["url"].strip() for r in refs2)
    assert validate_cve_draft(draft2) == []


def test_cve_preserves_all_affected_packages_and_versions():
    """Every affected package AND every recorded version is preserved — the draft
    must not collapse the disclosure's scope to the first package/version."""
    draft = finding_to_cve_draft(
        make_finding(
            affected=[
                AffectedPackage(ecosystem="Packagist", package="php/php-src", versions=["8.3.0", "8.3.1"]),
                AffectedPackage(ecosystem="PyPI", package="foo", versions=["1.0"]),
            ]
        )
    )
    aff = draft["containers"]["cna"]["affected"]
    assert {e["product"] for e in aff} == {"php/php-src", "foo"}
    php = next(e for e in aff if e["product"] == "php/php-src")
    assert {v["version"] for v in php["versions"]} == {"8.3.0", "8.3.1"}
    assert validate_cve_draft(draft) == []
