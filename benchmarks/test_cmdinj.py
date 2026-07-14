"""Class 7 of the vuln-rediscovery skill: OS command injection (CWE-78), JS + Python."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_javascript")

from cmdinj_detector import GROUND_TRUTH_CWE, RULE_ID, scan_file, scan_source  # noqa: E402

FIX_JS = Path(__file__).parent / "fixtures" / "cmdinj_fixture.js"
FIX_PY = Path(__file__).parent / "fixtures" / "cmdinj_fixture.py"
MANIFEST = Path(__file__).parent / "corpus" / "command_injection" / "manifest.json"
SEED_CVE = "CVE-2025-64756"


def test_fixtures_discriminate():
    assert len(scan_file(FIX_JS, uri="cmdinj_fixture.js")["runs"][0]["results"]) == 1
    assert len(scan_file(FIX_PY, uri="cmdinj_fixture.py")["runs"][0]["results"]) == 1


@pytest.mark.parametrize(
    "uri,src,expected",
    [
        # --- flagged ---
        ("a.js", "const {execSync}=require('cp'); function f(x){return execSync('npm '+x);}", 1),           # execSync string concat
        ("a.js", "const {foregroundChild}=require('fc'); foregroundChild(cmd, m, {shell:true});", 1),        # shell:true (seed)
        ("a.js", "const {exec}=require('cp'); exec('bash', ['-c', localCommand]);", 1),                      # bash -c dynamic (aws-cdk)
        ("a.py", "import subprocess\ndef f(a): return subprocess.Popen(a, shell=True)", 1),                  # Popen shell=True
        ("a.py", "import subprocess,os\ndef f(a): return subprocess.Popen(a, shell=os.name!='nt')", 1),      # ansys shape
        ("a.py", "import os\ndef f(x): return os.system('rm '+x)", 1),                                       # os.system dynamic
        # --- not flagged ---
        ("a.js", "const {execFileSync}=require('cp'); execFileSync('npm', [x]);", 0),                        # argv, no shell
        ("a.js", "const {exec}=require('cp'); exec('ls -la');", 0),                                          # constant command
        ("a.py", "import subprocess\nsubprocess.run(['ls', x])", 0),                                         # argv, no shell
        ("a.py", "import subprocess\nsubprocess.run(cmd, shell=False)", 0),                                  # shell=False
        # --- guard: shlex.quote in scope (dulwich shape) ---
        ("a.py", "import subprocess, shlex\ndef f(p): cmd='cat '+shlex.quote(p); return subprocess.run(cmd, shell=True)", 0),
        ("a.js", "const {execSync}=require('cp'); const q=require('shell-quote'); function f(x){return execSync(q.quote(['npm',x]));}", 0),
        # --- review round-1 findings ---
        # P1 FP: a `-c` flag on a NON-shell program is not a shell invocation
        ("a.js", "const {execFile}=require('cp'); execFile('git',['-c','user.name='+name,'commit']);", 0),
        # P1 FP: bash -c with a CONSTANT command and only a dynamic option value (cwd)
        ("a.js", "const {spawn}=require('cp'); spawn('bash',['-c','ls'],{cwd:dir});", 0),
        # ...but bash -c with a DYNAMIC command is still flagged
        ("a.js", "const {exec}=require('cp'); exec('bash',['-c',localCommand]);", 1),
        # P2 FN: a string-valued shell option is as dangerous as shell:true
        ("a.js", "const {spawn}=require('cp'); function f(u){return spawn(u,[],{shell:'/bin/bash'});}", 1),
        # minor: a bare `system` imported from os
        ("a.py", "from os import system\ndef f(x): return system('rm '+x)", 1),
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
    pid = "glob-cve-2025-64756"
    root = tmp_path / "checkout"
    root.mkdir()
    uri = "bin.js"
    (root / uri).write_text(FIX_JS.read_text())

    reg = NewProjectSession(
        name="glob cmd injection", source_type="open_source", local_path=str(root),
        authorization_basis="permissive_oss", scope_allowlist=[uri],
        project_id=pid, verify_url=lambda _u: True,
    )
    assert run_session(store, gate, reg).gate_outcome.value == "proceed"
    run_session(store, gate, MapSession(pid, root=str(root)))
    sarif = tmp_path / "ci.sarif"
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
    assert measure_entry(man["seed"], scan_source)["rediscovered"]
    result = measure_heldout(man, scan_source, RULE_ID)
    # cyclonedx (execSync->execFile), dulwich (shlex.quote guard), ansys (Popen shell=)
    # rediscovered; aws-cdk missed (patched keeps a bash -c for command hooks).
    assert result.rediscovered == 3
    assert result.missed_cves == ["CVE-2026-11417"]
