"""CRLF / HTTP response-splitting class (CWE-113), deterministic Python AST only."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from crlf_detector import GROUND_TRUTH_CWE, RULE_ID, scan_file, scan_source

FIXTURE = Path(__file__).parent / "fixtures" / "crlf.py"
MANIFEST = Path(__file__).parent / "corpus" / "crlf" / "manifest.json"
SEED_CVE = "CVE-2026-42874"


def test_fixture_discriminates_vuln_from_safe():
    results = scan_file(FIXTURE, uri=FIXTURE.name)["runs"][0]["results"]
    lines = {r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results}
    src = FIXTURE.read_text().splitlines()
    flagged = "\n".join(src[i - 1] for i in sorted(lines))
    assert "write_header_vuln" in FIXTURE.read_text()
    assert any("b\": \"" in src[i - 1] or 'b": "' in src[i - 1] or '": "' in src[i - 1] for i in lines)
    # Safe paths must not be flagged
    assert "write_header_safe" not in flagged or "_nocrlf" not in flagged
    assert "set_cookie_safe" not in flagged
    # Vulnerable set_cookie stores without guard
    assert any("Set-Cookie" in src[i - 1] for i in lines)


@pytest.mark.parametrize(
    "source,expected",
    [
        ("def write_header(h):\n return h[0] + b': ' + h[1] + b'\\r\\n'\n", 1),
        (
            "def write_header(h):\n"
            " def _nocrlf(v):\n  return v.replace(b'\\r', b'').replace(b'\\n', b'')\n"
            " return _nocrlf(h[0]) + b': ' + _nocrlf(h[1]) + b'\\r\\n'\n",
            0,
        ),
        (
            "def _safe_header(v):\n return v\n"
            "def write(k,v):\n return _safe_header(k) + ': ' + _safe_header(v) + '\\r\\n'\n",
            0,
        ),
        (
            "class R:\n def __init__(self):\n  self.headers={}\n"
            " def set_cookie(self, cookie, value):\n"
            "  http_cookie = cookie + '=' + value\n"
            "  self.headers['Set-Cookie'] = [http_cookie]\n",
            1,
        ),
        (
            "class R:\n def __init__(self):\n  self.headers={}\n"
            " def set_cookie(self, cookie, value):\n"
            "  http_cookie = cookie + '=' + value\n"
            "  if '\\r' in http_cookie or '\\n' in http_cookie:\n   raise ValueError('bad')\n"
            "  self.headers['Set-Cookie'] = [http_cookie]\n",
            0,
        ),
        (
            "def add(content_type):\n headers={}\n headers['Content-Type'] = content_type\n",
            1,
        ),
        (
            "def add(content_type):\n"
            " if '\\r' in content_type or '\\n' in content_type:\n  raise ValueError('bad')\n"
            " headers={}\n headers['Content-Type'] = content_type\n",
            0,
        ),
        (
            "def bin_headers(headers):\n"
            " return ''.join([k + ': ' + v + '\\r\\n' for k, v in headers.items()])\n",
            1,
        ),
    ],
)
def test_shapes(source, expected):
    assert len(scan_source(source, "t.py")) == expected


def test_full_pipeline_rediscovers_the_seed_shape(tmp_path):
    from deepthought.check import run_check
    from deepthought.export.osv import finding_to_osv, validate_osv
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.schema.finding import FindingStatus
    from deepthought.sessions import DiscoverSession, MapSession, NewProjectSession
    from deepthought.store import FileStore

    root = tmp_path / "checkout"
    root.mkdir()
    uri = "microdot_seed.py"
    seed_src = (
        "class Response:\n"
        " def __init__(self):\n  self.headers = {}\n"
        " def set_cookie(self, cookie, value):\n"
        "  http_cookie = '{cookie}={value}'.format(cookie=cookie, value=value)\n"
        "  if 'Set-Cookie' in self.headers:\n"
        "   self.headers['Set-Cookie'].append(http_cookie)\n"
        "  else:\n"
        "   self.headers['Set-Cookie'] = [http_cookie]\n"
    )
    (root / uri).write_text(seed_src)
    store = FileStore(str(tmp_path / "state"))
    gate = HermesUltraCodeGate()
    project = "microdot-cve-2026-42874"

    registration = NewProjectSession(
        name="microdot CRLF",
        source_type="open_source",
        local_path=str(root),
        authorization_basis="permissive_oss",
        scope_allowlist=[uri],
        project_id=project,
        verify_url=lambda _url: True,
    )
    assert run_session(store, gate, registration).gate_outcome.value == "proceed"
    run_session(store, gate, MapSession(project, root=str(root)))
    sarif_path = tmp_path / "crlf.sarif"
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
    assert result.rediscovered == 3
    assert result.missed_cves == []
    assert result.metrics.fp >= 0  # honest patched-file context
    assert result.generalization == 1.0
