"""Tier 2 rediscovery: cJSON heap over-read (issue #800), through the REAL pipeline
WITH real sandboxed execution — crossing the Article III hard stop behind a
sign-off.

Ground truth is public and patched (fixed in cJSON 1.7.18), so this is a
deterministic rediscovery with no disclosure risk: ``cJSON_ParseWithLength`` on
``{"1":1,`` (7 bytes, no trailing NUL) over-reads in ``parse_string`` (CWE-125).

Discipline enforced here:
- **Execution only in the sandbox.** VERIFY reproduces the crash ONLY inside the
  hardened ``DockerSandbox`` (no network, read-only rootfs, all caps dropped,
  non-root, memory/pid limits), and ONLY with a valid ``Signoff`` scoped to
  ``cjson`` AND ``execution_enabled=True``. No target code runs outside it.
- **verified is earned by evidence.** The candidate is promoted only because the
  ASan report resolves as ``evidence_ref``; remove it and the transition is refused.
- **Disclosure authority stays human.** The analyzer/crash add only informational
  data — CWE in the body, no authoritative ``cve``, no ``advisory``/``fix``
  reference (the sibling of the Tier-1 CVE-fabrication line).

The whole module SKIPS (never fails) where docker or the ASan image is absent —
the sandbox correctly fails closed rather than falling back to unisolated
execution.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from deepthought.check import run_check
from deepthought.export.csaf import validate_csaf
from deepthought.export.cve import validate_cve_draft
from deepthought.export.openvex import validate_openvex
from deepthought.export.osv import finding_to_osv, validate_osv
from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.schema.finding import FindingStatus
from deepthought.sandbox import DockerSandbox, SandboxPolicy, SandboxSpec, Signoff
from deepthought.sessions import (
    DiscoverSession,
    DisclosureSession,
    MapSession,
    NewProjectSession,
)
from deepthought.store import FileStore

GATE = HermesUltraCodeGate()
PROJECT = "cjson"
IMAGE = "deepthought/cjson-asan:tier2"
SINK_URI = "cJSON.c"
ISSUE_URL = "https://github.com/DaveGamble/cJSON/issues/800"


def _image_present() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        out = subprocess.run(
            ["docker", "images", "-q", IMAGE], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and bool(out.stdout.strip())


requires_sandbox = pytest.mark.skipif(
    not _image_present(),
    reason="docker + the deepthought/cjson-asan:tier2 image are required for the "
    "signed-off Tier 2 run (build: docker build -t deepthought/cjson-asan:tier2 benchmarks/tier2/)",
)


def _signoff() -> Signoff:
    """The human sign-off that unlocks execution (Article III).

    Mahdi's real grant for the initial run was scoped to 2026-07-04. This
    regression test needs a sign-off that stays *valid* whenever CI runs it, so —
    like the reference sandbox tests — it uses a far-future expiry. The mechanism
    under test is "a VALID sign-off unlocks the sandbox"; the expiry/wrong-project
    REFUSALS are covered separately in tests/test_sandbox_signoff.py.
    """
    return Signoff(approver="Mahdi Hedhli", project=PROJECT,
                   expires_at="2099-01-01T00:00:00Z", reason="tier 2 benchmark")


def _sink_sarif() -> dict:
    """An analyzer flagging the parsing sink (``parse_string`` via
    ``cJSON_ParseWithLength``) — informational only: CWE-125 + a report reference
    to the public issue, and NO cve (there is none for this bug)."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deepthought-cjson-sink",
                        "rules": [
                            {
                                "id": "DT-CJSON-PARSE-OOB",
                                "helpUri": ISSUE_URL,
                                "properties": {
                                    "cwe": "CWE-125",
                                    "tags": ["security", "CWE-125", "out-of-bounds-read"],
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "DT-CJSON-PARSE-OOB",
                        "level": "error",
                        "message": {
                            "text": "parse_string reached via cJSON_ParseWithLength "
                            "over-reads a length-bounded buffer (heap out-of-bounds read)"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": SINK_URI},
                                    "region": {"startLine": 786},
                                }
                            }
                        ],
                        "properties": {"cwe": "CWE-125"},
                    }
                ],
            }
        ],
    }


def _register_and_discover(store, tmp_path):
    root = tmp_path / "cjson"
    root.mkdir()
    (root / SINK_URI).write_text("/* cJSON v1.7.17 parser (sink at parse_string) */\n")
    reg = run_session(store, GATE, NewProjectSession(
        name="cJSON", source_type="open_source", local_path=str(root),
        authorization_basis="permissive_oss", scope_allowlist=[SINK_URI],
        project_id=PROJECT, verify_url=lambda _u: True,
    ))
    assert reg.gate_outcome.value == "proceed", reg.gate_reason
    # MAP the in-scope surface (read-only), then DISCOVER over the analyzer SARIF.
    run_session(store, GATE, MapSession(PROJECT, root=str(root)))
    sarif_path = tmp_path / "cjson.sarif"
    sarif_path.write_text(json.dumps(_sink_sarif()))
    run_session(store, GATE, DiscoverSession(PROJECT, sarif_path=str(sarif_path), root=str(root)))
    findings = store.list_findings(project=PROJECT)
    assert len(findings) == 1
    return findings[0]


def _verify_spec() -> SandboxSpec:
    return SandboxSpec(
        image=IMAGE,
        command=["/harness", "/seeds/trigger"],  # the baked libFuzzer replay input
        repro_ref="detail/seed/trigger",
        workdir="/",
        policy=SandboxPolicy(),  # default-deny hardening
    )


# --------------------------------------------------------------------------- #
# DISCOVER: the parsing sink -> candidate, informational only
# --------------------------------------------------------------------------- #


def test_discover_files_an_informational_candidate(state_dir, tmp_path):
    store = FileStore(state_dir)
    finding = _register_and_discover(store, tmp_path)
    assert finding.status is FindingStatus.candidate
    assert "CWE-125" in finding.body                       # weakness travels
    assert finding.cve is None                             # NO authoritative cve
    assert finding.aliases == []                           # nothing to cross-reference
    # The analyzer contributes an INFORMATIONAL reference to the public issue,
    # never one that gates disclosure. (The sibling of the Tier-1 CVE line.)
    assert finding.has_reference_type("detection")         # informational pointer
    assert not finding.has_reference_type("advisory")      # analyzer authorizes nothing
    assert not finding.has_reference_type("fix")
    assert any(ISSUE_URL == r.url for r in finding.references)
    assert validate_osv(finding_to_osv(finding)) == []


# --------------------------------------------------------------------------- #
# VERIFY: reproduce ONLY in the signed-off sandbox; verified is earned
# --------------------------------------------------------------------------- #


@requires_sandbox
def test_verify_reproduces_in_the_sandbox_and_promotes_on_evidence(state_dir, tmp_path):
    from deepthought.sessions import VerifySession

    store = FileStore(state_dir)
    finding = _register_and_discover(store, tmp_path)

    # The ONLY door to execution: a signed-off, explicitly-enabled hardened backend.
    box = DockerSandbox(project=PROJECT, signoff=_signoff(), execution_enabled=True,
                        store=store, runtime="docker")
    record = run_session(store, GATE, VerifySession(PROJECT, finding.id, _verify_spec(), box))
    assert record.gate_outcome.value == "proceed", record.gate_reason

    verified = store.get_finding(finding.id)
    assert verified.status is FindingStatus.verified          # promoted on the crash
    assert verified.evidence_ref and store.detail_exists(verified.evidence_ref)
    evidence = store.read_detail(verified.evidence_ref)
    assert "heap-buffer-overflow" in evidence
    assert "parse_string" in evidence
    assert "READ" in evidence
    # Disclosure authority stays human even after a real reproduction.
    assert verified.cve is None
    assert not verified.has_reference_type("advisory")
    assert not verified.has_reference_type("fix")
    assert run_check(store).ok, run_check(store).errors


def test_verified_is_refused_without_resolving_evidence(state_dir, tmp_path):
    """verified is reached ONLY because the evidence resolves — a candidate whose
    evidence_ref does not resolve is refused by the lifecycle guard (no sandbox,
    no execution needed to prove this)."""
    store = FileStore(state_dir)
    finding = _register_and_discover(store, tmp_path)
    finding.evidence_ref = "detail/nope/missing.txt"  # does not resolve
    store.save_finding(finding)
    result = store.transition_finding(finding.id, FindingStatus.verified)
    assert result.ok is False
    assert store.get_finding(finding.id).status is FindingStatus.candidate


# --------------------------------------------------------------------------- #
# Megadodo: draft-only disclosure; authority stays human; nothing transmitted
# --------------------------------------------------------------------------- #


@requires_sandbox
def test_megadodo_drafts_validate_and_assert_the_human_gate(state_dir, tmp_path):
    from deepthought.sessions import VerifySession

    store = FileStore(state_dir)
    finding = _register_and_discover(store, tmp_path)
    box = DockerSandbox(project=PROJECT, signoff=_signoff(), execution_enabled=True,
                        store=store, runtime="docker")
    run_session(store, GATE, VerifySession(PROJECT, finding.id, _verify_spec(), box))
    assert store.get_finding(finding.id).status is FindingStatus.verified

    session = DisclosureSession(PROJECT, finding.id)
    record = run_session(store, GATE, session)
    assert record.close_state.value == "clean"
    refs = session.artifact_refs
    assert set(refs) == {
        "disclosure-advisory.md", "disclosure-csaf.json",
        "disclosure-openvex.json", "disclosure-cve-draft.json",
    }
    assert validate_csaf(json.loads(store.read_detail(refs["disclosure-csaf.json"]))) == []
    assert validate_openvex(json.loads(store.read_detail(refs["disclosure-openvex.json"]))) == []
    assert validate_cve_draft(json.loads(store.read_detail(refs["disclosure-cve-draft.json"]))) == []

    # DRAFT-ONLY: the finding is unchanged — still verified, no cve, no advisory ref,
    # not advanced to disclosed. A human sends.
    after = store.get_finding(finding.id)
    assert after.status is FindingStatus.verified
    assert after.cve is None
    assert not after.has_reference_type("advisory")
    assert not after.has_reference_type("fix")
