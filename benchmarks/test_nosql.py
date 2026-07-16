"""NoSQL operator-injection class (CWE-943), deterministic JS/TS tree-sitter."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from nosql_detector import GROUND_TRUTH_CWE, RULE_ID, scan_file, scan_source

FIXTURE = Path(__file__).parent / "fixtures" / "nosql.js"
MANIFEST = Path(__file__).parent / "corpus" / "nosql" / "manifest.json"
SEED_CVE = "CVE-2026-48121"


def test_fixture_flags_unguarded_configurable_destructure():
    results = scan_file(FIXTURE, uri=FIXTURE.name)["runs"][0]["results"]
    assert len(results) >= 1
    text = FIXTURE.read_text()
    lines = text.splitlines()
    flagged = [
        lines[r["locations"][0]["physicalLocation"]["region"]["startLine"] - 1]
        for r in results
    ]
    assert any("configurable" in ln or "req.body" in ln or "find(" in ln for ln in flagged)


@pytest.mark.parametrize(
    "source,expected_min",
    [
        (
            "async function f(config, col) {\n"
            " const { thread_id, checkpoint_ns } = config.configurable ?? {};\n"
            " return col.find({ thread_id, checkpoint_ns });\n}\n",
            1,
        ),
        (
            "async function f(config, col) {\n"
            " function getStringConfigValue(n,v){ if(typeof v!=='string') throw 0; return v;}\n"
            " const thread_id = getStringConfigValue('thread_id', config.configurable?.thread_id);\n"
            " return col.find({ thread_id });\n}\n",
            0,
        ),
        (
            "async function f(req, db) {\n"
            " const token = req.body?.token;\n"
            " return db.findOne({ token });\n}\n",
            1,
        ),
        (
            "async function f(req, db) {\n"
            " const token = req.body?.token;\n"
            " if (token && typeof token !== 'string') throw new Error('bad');\n"
            " return db.findOne({ token });\n}\n",
            0,
        ),
    ],
)
def test_shapes(source, expected_min):
    n = len(scan_source(source, "t.js"))
    if expected_min == 0:
        assert n == 0
    else:
        assert n >= expected_min


def test_full_pipeline_rediscovers_the_seed_shape(tmp_path):
    from deepthought.check import run_check
    from deepthought.export.osv import finding_to_osv, validate_osv
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.schema.finding import FindingStatus
    from deepthought.sessions import DiscoverSession, MapSession, NewProjectSession
    from deepthought.store import FileStore

    root = tmp_path / "checkout"
    root.mkdir()
    uri = "seed.js"
    seed_src = (
        "async function getTuple(config, collection) {\n"
        "  const {\n"
        "    thread_id,\n"
        "    checkpoint_ns = '',\n"
        "  } = config.configurable ?? {};\n"
        "  return collection.find({ thread_id, checkpoint_ns });\n"
        "}\n"
    )
    (root / uri).write_text(seed_src)
    store = FileStore(str(tmp_path / "state"))
    gate = HermesUltraCodeGate()
    project = "langgraph-cve-2026-48121"

    registration = NewProjectSession(
        name="langgraph NoSQL",
        source_type="open_source",
        local_path=str(root),
        authorization_basis="permissive_oss",
        scope_allowlist=[uri],
        project_id=project,
        verify_url=lambda _url: True,
    )
    assert run_session(store, gate, registration).gate_outcome.value == "proceed"
    run_session(store, gate, MapSession(project, root=str(root)))
    sarif_path = tmp_path / "nosql.sarif"
    sarif_path.write_text(json.dumps(scan_file(root / uri, uri=uri, cve=SEED_CVE)))
    run_session(store, gate, DiscoverSession(project, sarif_path=str(sarif_path), root=str(root)))

    findings = store.list_findings(project=project)
    assert len(findings) >= 1
    finding = findings[0]
    assert finding.status is FindingStatus.candidate
    assert finding.cve is None
    assert SEED_CVE in finding.aliases
    assert GROUND_TRUTH_CWE in finding.body
    assert validate_osv(finding_to_osv(finding)) == []
    assert run_check(store).ok, run_check(store).errors


def _network_enabled() -> bool:
    if os.environ.get("DEEPTHOUGHT_BENCHMARK_NET") != "1":
        return False
    try:
        socket.create_connection(("raw.githubusercontent.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _network_enabled(), reason="real-tree measurement needs explicit network opt-in")
def test_heldout_generalization_on_real_pinned_trees():
    import sys

    sys.path.insert(0, str(Path(__file__).parent / "harness"))
    from corpus_measure import load_manifest, measure_entry, measure_heldout

    manifest = load_manifest(MANIFEST)
    assert measure_entry(manifest["seed"], scan_source)["rediscovered"]
    result = measure_heldout(manifest, scan_source, RULE_ID)
    assert result.rediscovered == 2
    assert result.missed_cves == ["CVE-2026-29793"]
    assert result.generalization == round(2 / 3, 3)
