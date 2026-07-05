"""Class 2 of the vuln-rediscovery skill: SSRF (CWE-918).

Three layers:
  * OFFLINE unit tests pin the DT-SSRF-TAINT rule — it flags an outbound-request sink
    (requests/httpx/aiohttp/urllib) with a non-literal URL when the enclosing scope has
    no SSRF guard, and skips the guarded / sink-substituted shape.
  * A REAL-PIPELINE test rediscovers the seed shape through the shipped
    ``sarif_to_findings`` + ``DiscoverSession``, filing one CWE-918 candidate that
    carries the seed CVE as an informational alias only.
  * A NETWORK-gated test measures held-out generalization on the REAL package files at
    their pinned vulnerable/patched SHAs (gradio, pydantic-ai, langchain, lmdeploy).
    Opt-in (``DEEPTHOUGHT_BENCHMARK_NET=1``) so a default run never touches the network.

The seed is dify CVE-2025-0184 — the corpus's urllib3 seed was authoritatively CWE-601
(redirect), not CWE-918 SSRF, so it was swapped (see the manifest). Nothing here executes
target code; the detector only parses source into a Python AST.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from ssrf_detector import GROUND_TRUTH_CWE, RULE_ID, scan_file, scan_source  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "ssrf.py"
FIXTURE_URI = "ssrf.py"
MANIFEST = Path(__file__).parent / "corpus" / "ssrf" / "manifest.json"
SEED_CVE = "CVE-2025-0184"


# --------------------------------------------------------------------------- #
# offline: the rule discriminates vulnerable from patched
# --------------------------------------------------------------------------- #


def test_fixture_flags_the_vulnerable_sink_and_skips_both_patched():
    src = FIXTURE.read_text()
    results = scan_source(src, FIXTURE_URI)
    assert len(results) == 1, [r["message"]["text"] for r in results]
    flagged = results[0]["locations"][0]["physicalLocation"]["region"]["startLine"]
    vuln_def = next(i for i, l in enumerate(src.splitlines(), 1) if "def fetch_vulnerable" in l)
    proxy_def = next(i for i, l in enumerate(src.splitlines(), 1) if "def fetch_patched_proxy" in l)
    assert vuln_def < flagged < proxy_def          # the flag is inside fetch_vulnerable
    assert results[0]["properties"]["cwe"] == GROUND_TRUTH_CWE


@pytest.mark.parametrize(
    "src,expected",
    [
        # --- vulnerable shapes (flagged) ---
        ("import requests\ndef f(url):\n    return requests.get(url, stream=True)", 1),
        ("def f(sync_client,url):\n    return sync_client.stream('GET', url)", 1),         # httpx stream
        ("async def f(client,url):\n    return await client.get(url, follow_redirects=True)", 1),
        ("def f(session,url):\n    return session.get(url)", 1),                            # aiohttp
        ("import urllib.request\ndef f(url):\n    return urllib.request.urlopen(url)", 1),
        # --- guarded / substituted shapes (skipped) ---
        ("from h import ssrf_proxy\ndef f(url):\n    return ssrf_proxy.get(url, stream=True)", 0),  # safe wrapper
        ("import httpx\ndef f(url):\n    check_public_url(url)\n    return httpx.get(url)", 0),      # validation call
        ("import requests, ipaddress\nfrom urllib.parse import urlparse\ndef f(url):\n    host=urlparse(url).hostname\n    if not ipaddress.ip_address(host).is_global: raise ValueError()\n    return requests.get(url)", 0),  # IP guard on the URL's own host
        ("import requests\nfrom urllib.parse import urlparse\ndef f(url):\n    if urlparse(url).hostname not in ALLOW: raise ValueError()\n    return requests.get(url)", 0),  # allowlist
        # --- precision: not SSRF (skipped) ---
        ("import requests\ndef f():\n    return requests.get('http://fixed.example/api')", 0),      # literal URL
        ("def f(d,key):\n    return d.get(key)", 0),                                                # dict.get
        ("def f(cache,key):\n    return cache.get(key)", 0),                                        # non-client .get
        # scope isolation: a guard in a SIBLING helper must not cover this sink
        ("import requests\ndef helper(u):\n    check_url(u)\n\ndef f(url):\n    return requests.get(url)", 1),
        # --- review regressions (agy + codex adversarial PoCs) ---
        # requests.request('GET', url): the URL is the 2nd positional, not the method
        ("import requests\ndef f(url):\n    return requests.request('GET', url)", 1),
        # a directly-imported request function (bare-name call) is still a sink
        ("from requests import get\ndef f(url):\n    return get(url)", 1),
        ("from urllib.request import urlopen as fetch\ndef f(url):\n    return fetch(url)", 1),
        # parsing/logging the hostname is NOT a guard
        ("import requests\nfrom urllib.parse import urlparse\ndef f(url):\n    print(urlparse(url).hostname)\n    return requests.get(url)", 1),
        # instantiating an IP without a range check is NOT a guard
        ("import requests, ipaddress\ndef f(url,ip):\n    addr=ipaddress.ip_address(ip)\n    return requests.get(url)", 1),
        # a validation of a DIFFERENT url must not suppress this sink
        ("import requests\ndef f(callback_url,user_url):\n    check_public_url(callback_url)\n    return requests.get(user_url)", 1),
        # ...but a guard on an assignment-LINKED alias of the sink url IS a guard
        ("import requests\ndef f(url_spec):\n    url = url_spec.geturl()\n    is_safe = check_url(url)\n    return requests.get(url_spec.geturl())", 0),
        # --- review regressions (agy round 2) ---
        # an ALIASED direct import of `request` still reads the URL as the 2nd arg
        ("from requests import request as req\ndef f(url):\n    return req('GET', url)", 1),
        # `.is_global` on a NON-IP object (a config flag) is not an IP range check
        ("import requests\ndef f(url,user):\n    if user.is_global: pass\n    return requests.get(url)", 1),
        # a real IP range check (with ipaddress context) on the URL's own IP IS a guard
        ("import requests, ipaddress\nfrom urllib.parse import urlparse\ndef f(url):\n    ip = ipaddress.ip_address(urlparse(url).hostname)\n    if not ip.is_global: raise ValueError()\n    return requests.get(url)", 0),
        # --- review regressions (codex round 2) ---
        # a guard AFTER the sink does not protect it
        ("import requests\ndef f(url):\n    r = requests.get(url)\n    check_public_url(url)\n    return r", 1),
        # a range check on an UNRELATED ip does not guard the fetched url
        ("import requests, ipaddress\ndef f(url,ip):\n    if not ipaddress.ip_address(ip).is_global: raise ValueError()\n    return requests.get(url)", 1),
        # a real client whose name merely CONTAINS 'safe' (unsafe_client) is still a sink
        ("def f(unsafe_client,url):\n    return unsafe_client.get(url)", 1),
        # --- review regressions (agy + codex round 3) ---
        # a module-aliased import (import requests as req) is resolved to a sink
        ("import requests as req\ndef f(url):\n    return req.get(url)", 1),
        ("import httpx as hx\ndef f(url):\n    return hx.get(url)", 1),
        # a confirmed client VARIABLE named safe_client is still a sink
        ("import requests\ndef f(url):\n    safe_client = requests.Session()\n    return safe_client.get(url)", 1),
        # urlopen aliased as `request` keeps the URL 1st (not the request() 2-arg shape)
        ("from urllib.request import urlopen as request\ndef f(url):\n    return request(url, 'postdata')", 1),
        # IPv4Address(...).is_global is recognised as IP context (a real guard)
        ("from ipaddress import IPv4Address\nimport requests\ndef f(url):\n    if IPv4Address(url).is_global:\n        return requests.get(url)", 0),
    ],
)
def test_rule_variants(src, expected):
    assert len(scan_source(src, "t.py")) == expected


# --------------------------------------------------------------------------- #
# the REAL pipeline: rediscover through the shipped DISCOVER, filing a candidate
# --------------------------------------------------------------------------- #


def test_full_pipeline_rediscovers_the_seed_shape(tmp_path):
    from deepthought.check import run_check
    from deepthought.export.osv import finding_to_osv, validate_osv
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.schema.finding import FindingStatus
    from deepthought.sessions import DiscoverSession, MapSession, NewProjectSession
    from deepthought.store import FileStore

    gate = HermesUltraCodeGate()
    store = FileStore(str(tmp_path / "state"))
    pid = "dify-cve-2025-0184"
    root = tmp_path / "checkout"
    root.mkdir()
    (root / FIXTURE_URI).write_text(FIXTURE.read_text())

    reg = NewProjectSession(
        name="dify SSRF", source_type="open_source", local_path=str(root),
        authorization_basis="permissive_oss", scope_allowlist=[FIXTURE_URI],
        project_id=pid, verify_url=lambda _u: True,
    )
    assert run_session(store, gate, reg).gate_outcome.value == "proceed"
    run_session(store, gate, MapSession(pid, root=str(root)))

    sarif_path = tmp_path / "ssrf.sarif"
    sarif_path.write_text(json.dumps(scan_file(root / FIXTURE_URI, uri=FIXTURE_URI, cve=SEED_CVE)))
    run_session(store, gate, DiscoverSession(pid, sarif_path=str(sarif_path), root=str(root)))

    findings = store.list_findings(project=pid)
    assert len(findings) == 1
    f = findings[0]
    assert f.status is FindingStatus.candidate
    assert f.cve is None                     # never authoritatively assigned by the analyzer
    assert SEED_CVE in f.aliases             # informational cross-reference only
    assert GROUND_TRUTH_CWE in f.body
    assert validate_osv(finding_to_osv(f)) == []
    assert run_check(store).ok, run_check(store).errors


# --------------------------------------------------------------------------- #
# held-out generalization on REAL pinned trees (opt-in; never on a default run)
# --------------------------------------------------------------------------- #


def _net() -> bool:
    if os.environ.get("DEEPTHOUGHT_BENCHMARK_NET") != "1":
        return False
    try:
        socket.create_connection(("raw.githubusercontent.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


requires_net = pytest.mark.skipif(
    not _net(), reason="held-out fetch needs DEEPTHOUGHT_BENCHMARK_NET=1 and network"
)


@requires_net
def test_heldout_generalization_on_real_pinned_trees():
    import sys

    sys.path.insert(0, str(Path(__file__).parent / "harness"))
    from corpus_measure import load_manifest, measure_entry, measure_heldout

    man = load_manifest(MANIFEST)
    assert measure_entry(man["seed"], scan_source)["rediscovered"], "seed not rediscovered"

    result = measure_heldout(man, scan_source, RULE_ID)
    # gradio + pydantic-ai + lmdeploy generalize; langchain is the documented miss (its
    # same-domain prevent_outside bool flag is not a validation call the rule detects).
    assert result.rediscovered == 3
    assert result.missed_cves == ["CVE-2023-46229"]  # langchain
    assert result.generalization == round(3 / 4, 3)
