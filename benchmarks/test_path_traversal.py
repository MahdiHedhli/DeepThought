"""Round 3 path-traversal class (CWE-22), JS + Python, static-only."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_javascript")

from pathtrav_detector import GROUND_TRUTH_CWE, RULE_ID, scan_file, scan_source  # noqa: E402

FIX_JS = Path(__file__).parent / "fixtures" / "path_traversal.js"
FIX_PY = Path(__file__).parent / "fixtures" / "path_traversal.py"
MANIFEST = Path(__file__).parent / "corpus" / "path_traversal" / "manifest.json"
SEED_CVE = "CVE-2020-12265"


def test_fixtures_discriminate_vulnerable_from_contained_paths():
    assert len(scan_file(FIX_JS, uri=FIX_JS.name)["runs"][0]["results"]) == 1
    assert len(scan_file(FIX_PY, uri=FIX_PY.name)["runs"][0]["results"]) == 1


@pytest.mark.parametrize(
    "uri,source,expected",
    [
        ("a.js", "function f(root,e){return path.join(root,e.name)}", 1),
        ("a.js", "function f(root,e){const p=path.resolve(root,e.name);if(!p.startsWith(path.resolve(root)))throw Error();return p}", 0),
        ("a.js", "function f(root,e,url){if(!url.startsWith('/'))throw Error();return path.join(root,e.name)}", 1),
        ("a.js", "function f(root,e){function helper(x){return realpath(x)}return path.join(root,e.name)}", 1),
        ("a.js", "function f(root){return path.join(root,'fixed.txt')}", 0),
        ("a.js", "function f(root){return path.join(root,`fixed.txt`)}", 0),
        ("a.py", "import os\ndef f(root,name): return os.path.join(root,name)", 1),
        ("a.py", "from pathlib import Path\ndef f(root,name):\n p=Path(root).joinpath(name)\n p.relative_to(Path(root))\n return p", 0),
        ("a.py", "import os\ndef outer(root,name):\n def inner():\n  return relative_to\n return os.path.join(root,name)", 1),
        ("a.py", "import os\ndef f(root): return os.path.join(root,'fixed.txt')", 0),
    ],
)
def test_rule_variants(uri, source, expected):
    assert len(scan_source(source, uri)) == expected


def test_full_pipeline_rediscovers_the_seed_shape(tmp_path):
    from deepthought.check import run_check
    from deepthought.export.osv import finding_to_osv, validate_osv
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.schema.finding import FindingStatus
    from deepthought.sessions import DiscoverSession, MapSession, NewProjectSession
    from deepthought.store import FileStore

    store = FileStore(str(tmp_path / "state"))
    gate = HermesUltraCodeGate()
    root = tmp_path / "checkout"
    root.mkdir()
    uri = FIX_JS.name
    (root / uri).write_text(FIX_JS.read_text())
    pid = "decompress-cve-2020-12265"

    registration = NewProjectSession(
        name="decompress path traversal",
        source_type="open_source",
        local_path=str(root),
        authorization_basis="permissive_oss",
        scope_allowlist=[uri],
        project_id=pid,
        verify_url=lambda _url: True,
    )
    assert run_session(store, gate, registration).gate_outcome.value == "proceed"
    run_session(store, gate, MapSession(pid, root=str(root)))
    sarif = tmp_path / "path-traversal.sarif"
    sarif.write_text(json.dumps(scan_file(root / uri, uri=uri, cve=SEED_CVE)))
    run_session(store, gate, DiscoverSession(pid, sarif_path=str(sarif), root=str(root)))

    findings = store.list_findings(project=pid)
    assert len(findings) == 1
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
    assert result.missed_cves == ["CVE-2024-23334"]
    assert result.generalization == round(2 / 3, 3)
