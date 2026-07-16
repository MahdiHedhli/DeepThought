"""SSTI class (CWE-1336), deterministic Python AST only."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from ssti_detector import GROUND_TRUTH_CWE, RULE_ID, scan_file, scan_source

FIXTURE = Path(__file__).parent / "fixtures" / "ssti.py"
MANIFEST = Path(__file__).parent / "corpus" / "ssti" / "manifest.json"
SEED_CVE = "CVE-2026-44209"


def test_fixture_flags_unsandboxed_constructors_only():
    results = scan_file(FIXTURE, uri=FIXTURE.name)["runs"][0]["results"]
    lines = {r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results}
    src = FIXTURE.read_text().splitlines()
    flagged = [src[i - 1].strip() for i in sorted(lines)]
    # three vulnerable sinks: Environment(), Template(), render_template_string
    assert len(results) == 3, flagged
    assert any("Environment(" in line and "Sandboxed" not in line for line in flagged)
    assert any("Template(" in line for line in flagged)
    assert any("render_template_string" in line for line in flagged)


@pytest.mark.parametrize(
    "source,expected",
    [
        ("from jinja2 import Environment\nenv = Environment()\n", 1),
        ("from jinja2 import Template\nTemplate('{{ x }}')\n", 1),
        ("from jinja2.sandbox import SandboxedEnvironment\nSandboxedEnvironment()\n", 0),
        (
            "from jinja2.sandbox import SandboxedEnvironment as Environment\nEnvironment()\n",
            0,
        ),
        (
            "from jinja2.sandbox import ImmutableSandboxedEnvironment\n"
            "ImmutableSandboxedEnvironment()\n",
            0,
        ),
        ("from flask import render_template_string\nrender_template_string(user)\n", 1),
        ("import jinja2\njinja2.Environment()\n", 1),
        ("import jinja2\njinja2.sandbox.SandboxedEnvironment()\n", 0),
        (
            "from jinja2 import Environment\n"
            "def outer():\n from jinja2.sandbox import SandboxedEnvironment as Environment\n"
            " return Environment()\n"
            "def sibling():\n return Environment()\n",
            1,
        ),
        # Local helper named Environment is not Jinja — no import binding.
        ("def Environment(x): return x\nEnvironment('{{x}}')\n", 0),
        (
            "from jinja2.nativetypes import NativeEnvironment\nNativeEnvironment()\n",
            1,
        ),
        # Safe alias assignment
        (
            "from jinja2.sandbox import SandboxedEnvironment\nEnv = SandboxedEnvironment\nEnv()\n",
            0,
        ),
        # Review P1: defining-module import path
        ("from jinja2.environment import Environment\nenv = Environment()\n", 1),
        ("from jinja2.environment import Template\nTemplate(user)\n", 1),
        ("import jinja2.environment as environment\nenvironment.Environment()\n", 1),
        # Review P1: local rebinding shadows module import
        (
            "from jinja2 import Environment\n"
            "def render():\n Environment = lambda **kwargs: None\n return Environment()\n",
            0,
        ),
        (
            "from jinja2 import Environment\ndef f():\n Environment = str\n return Environment('x')\n",
            0,
        ),
        # Review P2: non-Flask attribute with the same name is not a sink
        (
            "class Helper:\n def render_template_string(self, s): return s\n"
            "Helper().render_template_string(user)\n",
            0,
        ),
        # Review P2: nativetypes module alias + AnnAssign
        ("import jinja2.nativetypes as nt\nnt.NativeEnvironment()\n", 1),
        (
            "from jinja2 import Environment\nEnv: type = Environment\nEnv()\n",
            1,
        ),
    ],
)
def test_binding_and_sandbox_discrimination(source, expected):
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
    uri = FIXTURE.name
    # Scope the pipeline to a single vulnerable shape so DISCOVER yields one candidate.
    seed_src = (
        "from jinja2 import Environment, select_autoescape\n\n"
        "env = Environment(autoescape=select_autoescape(default=False))\n"
    )
    (root / uri).write_text(seed_src)
    store = FileStore(str(tmp_path / "state"))
    gate = HermesUltraCodeGate()
    project = "banks-cve-2026-44209"

    registration = NewProjectSession(
        name="banks SSTI",
        source_type="open_source",
        local_path=str(root),
        authorization_basis="permissive_oss",
        scope_allowlist=[uri],
        project_id=project,
        verify_url=lambda _url: True,
    )
    assert run_session(store, gate, registration).gate_outcome.value == "proceed"
    run_session(store, gate, MapSession(project, root=str(root)))
    sarif_path = tmp_path / "ssti.sarif"
    sarif_path.write_text(json.dumps(scan_file(root / uri, uri=uri, cve=SEED_CVE)))
    run_session(store, gate, DiscoverSession(project, sarif_path=str(sarif_path), root=str(root)))

    findings = store.list_findings(project=project)
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
    assert result.rediscovered == 4
    assert result.missed_cves == []
    assert result.metrics.fp == 0
    assert result.generalization == 1.0
