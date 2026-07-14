"""Class 3 of the vuln-rediscovery skill: XXE (CWE-611), multi-language (Java + Python).

Offline unit tests pin DT-XXE-PARSER's discrimination on both backends; a real-pipeline
test rediscovers the Java seed shape through the shipped DISCOVER; a network-gated test
measures held-out generalization on the real pinned trees.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_java")

from xxe_detector import GROUND_TRUTH_CWE, RULE_ID, scan_file, scan_source  # noqa: E402

FIX_JAVA = Path(__file__).parent / "fixtures" / "xxe_fixture.java"
FIX_PY = Path(__file__).parent / "fixtures" / "xxe_fixture.py"
MANIFEST = Path(__file__).parent / "corpus" / "xxe" / "manifest.json"
SEED_CVE = "CVE-2025-66516"


def test_fixtures_discriminate_vulnerable_from_hardened():
    assert len(scan_file(FIX_JAVA, uri="xxe_fixture.java")["runs"][0]["results"]) == 1
    assert len(scan_file(FIX_PY, uri="xxe_fixture.py")["runs"][0]["results"]) == 1


@pytest.mark.parametrize(
    "uri,src,expected",
    [
        # --- Java: unhardened factories (flagged) ---
        ("a.java", "class A{ void m(){ var f = XMLInputFactory.newFactory(); f.setProperty(X.IS_VALIDATING,false); } }", 1),
        ("a.java", "class A{ void m(){ var f = DocumentBuilderFactory.newInstance(); parse(f); } }", 1),
        ("a.java", "class A{ void m(){ var r = new SAXReader(); r.read(in); } }", 1),
        # --- Java: hardened (skipped) ---
        ("a.java", "class A{ void m(){ var f = XMLInputFactory.newFactory(); f.setProperty(XMLInputFactory.SUPPORT_DTD,false); } }", 0),
        ("a.java", "class A{ void m(){ var f = DocumentBuilderFactory.newInstance(); f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true); } }", 0),
        ("a.java", "class A{ void m(){ var f = SAXParserFactory.newInstance(); f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true); } }", 0),
        # --- Python: unhardened / hardened / defusedxml ---
        ("a.py", "from lxml import etree\np = etree.XMLParser(remove_blank_text=True)", 1),
        ("a.py", "from lxml import etree\np = etree.XMLParser(resolve_entities=False)", 0),
        ("a.py", "from lxml import etree\np = etree.XMLParser(no_network=True)", 0),
        ("a.py", "import defusedxml.lxml\np = defusedxml.lxml.parse(f)", 0),
        # --- precision: a non-XML factory is not flagged ---
        ("a.java", "class A{ void m(){ var x = SomeOtherThing.newInstance(); } }", 0),
    ],
)
def test_rule_variants(uri, src, expected):
    assert len(scan_source(src, uri)) == expected


def test_full_pipeline_rediscovers_the_seed_shape(tmp_path):
    from deepthought.check import run_check
    from deepthought.export.osv import finding_to_osv, validate_osv
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.schema.finding import FindingStatus
    from deepthought.sessions import DiscoverSession, MapSession, NewProjectSession
    from deepthought.store import FileStore

    gate = HermesUltraCodeGate()
    store = FileStore(str(tmp_path / "state"))
    pid = "tika-cve-2025-66516"
    root = tmp_path / "checkout"
    root.mkdir()
    uri = "XxeFixture.java"
    (root / uri).write_text(FIX_JAVA.read_text())

    reg = NewProjectSession(
        name="tika XXE", source_type="open_source", local_path=str(root),
        authorization_basis="permissive_oss", scope_allowlist=[uri],
        project_id=pid, verify_url=lambda _u: True,
    )
    assert run_session(store, gate, reg).gate_outcome.value == "proceed"
    run_session(store, gate, MapSession(pid, root=str(root)))
    sarif = tmp_path / "xxe.sarif"
    sarif.write_text(json.dumps(scan_file(root / uri, uri=uri, cve=SEED_CVE)))
    run_session(store, gate, DiscoverSession(pid, sarif_path=str(sarif), root=str(root)))

    findings = store.list_findings(project=pid)
    assert len(findings) == 1
    f = findings[0]
    assert f.status is FindingStatus.candidate
    assert f.cve is None
    assert SEED_CVE in f.aliases
    assert GROUND_TRUTH_CWE in f.body
    assert validate_osv(finding_to_osv(f)) == []
    assert run_check(store).ok, run_check(store).errors


def _net() -> bool:
    if os.environ.get("DEEPTHOUGHT_BENCHMARK_NET") != "1":
        return False
    try:
        socket.create_connection(("raw.githubusercontent.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _net(), reason="held-out fetch needs DEEPTHOUGHT_BENCHMARK_NET=1")
def test_heldout_generalization_on_real_pinned_trees():
    import sys

    sys.path.insert(0, str(Path(__file__).parent / "harness"))
    from corpus_measure import load_manifest, measure_entry, measure_heldout

    man = load_manifest(MANIFEST)
    assert measure_entry(man["seed"], scan_source)["rediscovered"], "seed not rediscovered"
    result = measure_heldout(man, scan_source, RULE_ID)
    # python-docx generalizes; dom4j (fix adds a safe alternative in another file) and
    # JDOM2 (fix reorders existing features) are documented hard misses.
    assert result.rediscovered == 1
    assert set(result.missed_cves) == {"CVE-2020-10683", "CVE-2021-33813"}
