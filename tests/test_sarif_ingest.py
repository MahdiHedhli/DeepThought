"""002 slice 1 — SARIF ingest.

SARIF is an untrusted, read-only input. Ingest maps each result into a candidate
Finding (OSV-valid by construction) and, via a closed ruleId/tag -> capability
lookup, a suspected Primitive. SARIF text is only ever copied into data fields;
it never becomes instruction and a rule string never mints an arbitrary
capability.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from deepthought.export.osv import finding_to_osv, validate_osv
from deepthought.ingest.sarif import (
    load_sarif,
    sarif_to_findings,
    sarif_to_primitives,
)
from deepthought.schema import CAPABILITY_TAXONOMY
from deepthought.schema.finding import Finding, FindingStatus

FIXTURE = Path(__file__).parent / "fixtures" / "sample.sarif"


# --- fixtures / helpers -----------------------------------------------------


@pytest.fixture
def sample_sarif() -> dict:
    return load_sarif(str(FIXTURE))


def minimal_sarif(**result_overrides) -> dict:
    """A minimal, well-formed SARIF 2.1.0 doc with a single result."""
    result = {
        "ruleId": "py/sql-injection",
        "level": "error",
        "message": {"text": "SQL query built from untrusted input."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app/db.py"},
                    "region": {"startLine": 42},
                }
            }
        ],
    }
    result.update(result_overrides)
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "T",
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "properties": {"tags": ["external/cwe/cwe-89"]},
                                "helpUri": "https://example.test/rules/sqli",
                            }
                        ],
                    }
                },
                "results": [result],
            }
        ],
    }


# --- load_sarif -------------------------------------------------------------


def test_load_sarif_reads_a_valid_document(sample_sarif):
    assert sample_sarif["version"] == "2.1.0"
    assert isinstance(sample_sarif["runs"], list)


def test_load_sarif_rejects_non_json(tmp_path):
    bad = tmp_path / "bad.sarif"
    bad.write_text("this is not json")
    with pytest.raises(Exception):
        load_sarif(str(bad))


def test_load_sarif_rejects_wrong_version(tmp_path):
    doc = tmp_path / "v1.sarif"
    doc.write_text(json.dumps({"version": "1.0.0", "runs": []}))
    with pytest.raises(Exception):
        load_sarif(str(doc))


# --- sarif_to_findings ------------------------------------------------------


def test_findings_are_candidate_and_ided_from_start(sample_sarif):
    findings = sarif_to_findings(sample_sarif, project="demo", id_start=1)
    # three results in the fixture, all with message text
    assert [f.id for f in findings] == ["F-0001", "F-0002", "F-0003"]
    assert all(isinstance(f, Finding) for f in findings)
    assert all(f.status == FindingStatus.candidate for f in findings)
    assert all(f.project == "demo" for f in findings)


def test_findings_id_start_offsets(sample_sarif):
    findings = sarif_to_findings(sample_sarif, project="demo", id_start=7)
    assert findings[0].id == "F-0007"
    assert findings[1].id == "F-0008"


def test_finding_summary_carries_rule_and_message(sample_sarif):
    findings = sarif_to_findings(sample_sarif, project="demo")
    first = findings[0]
    assert "py/sql-injection" in first.summary
    assert "SQL query" in first.summary


def test_finding_body_has_root_cause(sample_sarif):
    findings = sarif_to_findings(sample_sarif, project="demo")
    assert findings[0].body.startswith("## Root cause")
    assert "user-provided value" in findings[0].body


def test_finding_references_from_help_uri(sample_sarif):
    findings = sarif_to_findings(sample_sarif, project="demo")
    urls = [r.url for r in findings[0].references]
    assert "https://example.test/rules/sql-injection" in urls


def test_findings_are_osv_valid_by_construction(sample_sarif):
    findings = sarif_to_findings(sample_sarif, project="demo")
    assert findings  # non-empty
    for f in findings:
        osv = finding_to_osv(f)
        assert validate_osv(osv) == [], (f.id, validate_osv(osv))


def test_finding_affected_empty_and_no_evidence(sample_sarif):
    findings = sarif_to_findings(sample_sarif, project="demo")
    for f in findings:
        assert f.affected == []
        assert f.evidence_ref is None


def test_result_without_message_text_is_skipped():
    doc = minimal_sarif()
    # add a second result with no message text -> should be skipped
    doc["runs"][0]["results"].append(
        {"ruleId": "py/sql-injection", "locations": []}
    )
    findings = sarif_to_findings(doc, project="demo")
    assert len(findings) == 1


def test_finding_body_is_length_bounded():
    """Contract property 1 / data-model: SARIF text is length-bounded into the
    length-capped finding fields. A hostile, oversized message.text must not
    flow verbatim into an unbounded body (and then into OSV details on export).
    """
    from deepthought.ingest.sarif import _BODY_MAX

    hostile = "A" * 5000
    doc = minimal_sarif(message={"text": hostile})
    findings = sarif_to_findings(doc, project="demo")

    assert len(findings) == 1
    body = findings[0].body
    # The whole body is bounded, so the copied SARIF text cannot exceed the cap.
    assert len(body) <= _BODY_MAX
    # The finding still exports to valid OSV with the bounded body.
    osv = finding_to_osv(findings[0])
    assert validate_osv(osv) == [], validate_osv(osv)
    assert len(osv.get("details", "")) <= _BODY_MAX


# --- sarif_to_primitives ----------------------------------------------------


def test_sql_rule_yields_inject_sql_suspected(sample_sarif):
    findings = sarif_to_findings(sample_sarif, project="demo")
    prims = sarif_to_primitives(sample_sarif, finding_ids=[f.id for f in findings])
    sql = [p for p in prims if p.kind == "inject:sql"]
    assert len(sql) == 1
    p = sql[0]
    assert p.confidence.value == "suspected"
    assert p.evidence_ref is None
    assert p.finding_ref == "F-0001"
    assert p.target_locus == "app/db.py:42"


def test_path_rule_yields_write_arbitrary_file(sample_sarif):
    findings = sarif_to_findings(sample_sarif, project="demo")
    prims = sarif_to_primitives(sample_sarif, finding_ids=[f.id for f in findings])
    kinds = {p.kind for p in prims}
    assert "write:arbitrary-file" in kinds


def test_unmatched_rule_yields_no_primitive(sample_sarif):
    findings = sarif_to_findings(sample_sarif, project="demo")
    prims = sarif_to_primitives(sample_sarif, finding_ids=[f.id for f in findings])
    # the style-only result (F-0003) must not produce a primitive
    assert all(p.finding_ref != "F-0003" for p in prims)


def test_primitive_kinds_are_all_in_taxonomy(sample_sarif):
    findings = sarif_to_findings(sample_sarif, project="demo")
    prims = sarif_to_primitives(sample_sarif, finding_ids=[f.id for f in findings])
    for p in prims:
        assert p.kind in CAPABILITY_TAXONOMY
        for g in p.grants:
            assert g in CAPABILITY_TAXONOMY


# --- empty / edge -----------------------------------------------------------


def test_empty_sarif_yields_no_findings():
    doc = {"version": "2.1.0", "runs": []}
    assert sarif_to_findings(doc, project="demo") == []
    assert sarif_to_primitives(doc, finding_ids=[]) == []


def test_run_with_no_results_yields_nothing():
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "T"}}}]}
    assert sarif_to_findings(doc, project="demo") == []
    assert sarif_to_primitives(doc, finding_ids=[]) == []


# --- CVE / CWE metadata carried from SARIF properties -----------------------
# A SARIF result (or its rule) can carry a `cve` and `cwe` in its properties for a
# known-vulnerability rediscovery. The ingest copies a VALIDATED cve onto the
# finding (mirrored into OSV aliases on export) and a validated cwe into the body.
# Untrusted SARIF: a malformed value is dropped, never persisted or injected.


def test_finding_carries_validated_cve_and_cwe_from_result_properties():
    doc = minimal_sarif(
        ruleId="DT-TARFILE-EXTRACTALL",
        message={"text": "unsanitized tar member path passed to extractall"},
        properties={"cve": "CVE-2007-4559", "cwe": "CWE-22"},
    )
    finding = sarif_to_findings(doc, project="demo")[0]
    assert finding.cve == "CVE-2007-4559"
    assert "CWE-22" in finding.body
    osv = finding_to_osv(finding)
    assert validate_osv(osv) == []
    assert "CVE-2007-4559" in osv.get("aliases", [])


def test_cve_and_cwe_are_read_from_rule_properties_as_a_fallback():
    doc = minimal_sarif(message={"text": "known weakness"})
    # put cve/cwe on the RULE, not the result
    doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"].update(
        {"cve": "CVE-2007-4559", "cwe": "CWE-22"}
    )
    finding = sarif_to_findings(doc, project="demo")[0]
    assert finding.cve == "CVE-2007-4559"
    assert "CWE-22" in finding.body


def test_malformed_cve_or_cwe_in_properties_is_ignored():
    doc = minimal_sarif(
        properties={"cve": "CVE-XXXX-XXXXX", "cwe": "javascript:alert(1)"}
    )
    finding = sarif_to_findings(doc, project="demo")[0]
    assert finding.cve is None                      # sentinel/invalid cve dropped
    assert "javascript" not in finding.body         # unvalidated cwe never injected
    assert "alert" not in finding.body
    assert validate_osv(finding_to_osv(finding)) == []


def test_absent_cve_cwe_properties_leave_the_finding_unchanged():
    finding = sarif_to_findings(minimal_sarif(), project="demo")[0]
    assert finding.cve is None
    assert finding.aliases == []
