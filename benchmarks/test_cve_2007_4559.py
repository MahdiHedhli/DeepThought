"""Tier 1 benchmark: rediscover CVE-2007-4559 through the REAL platform pipeline.

CVE-2007-4559 is the Python ``tarfile`` path traversal in ``extract`` /
``extractall``. Ground truth is public and the bug is patched, so this is a
deterministic rediscovery with no disclosure risk. The static rule emits SARIF;
the SAME ingest DISCOVER uses (``deepthought.ingest.sarif``) files a candidate
Finding carrying the CVE and CWE; the finding exports to valid OSV and passes
``check``; a benign traversal repro is staged. The vulnerable extraction sink is
NEVER executed — that is the Article III execution hard stop, asserted directly:
every test runs with ``TarFile.extractall``/``extract`` monkeypatched to raise.

No fork: the finding is produced by the real ``sarif_to_findings`` and the real
``DiscoverSession``, not a benchmark-local finding builder.
"""

from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

import pytest

from deepthought.check import run_check
from deepthought.export.osv import finding_to_osv, validate_osv
from deepthought.ingest.sarif import sarif_to_findings
from deepthought.loop import LoopBudget, run_loop
from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.schema.finding import FindingStatus
from deepthought.schema.loop import ActionKind
from deepthought.sessions import DiscoverSession, MapSession, NewProjectSession
from deepthought.store import FileStore
from tarfile_detector import GROUND_TRUTH_CVE, GROUND_TRUTH_CWE, RULE_ID, scan_file

FIXTURES = Path(__file__).parent / "fixtures"
VULN_FIXTURE = FIXTURES / "vulnerable_extract.py"
FIXTURE_URI = VULN_FIXTURE.name  # relative to the fixture checkout root
GATE = HermesUltraCodeGate()


@pytest.fixture(autouse=True)
def _no_extraction(monkeypatch):
    """EXECUTION HARD STOP (Article III): the vulnerable sink must never run in
    Tier 1. Every test in this module runs with extraction monkeypatched to raise,
    so any accidental call — by the pipeline or a test — fails loudly."""

    def _boom(*_a, **_k):
        raise AssertionError(
            "execution hard stop crossed: tar extraction must not run in Tier 1"
        )

    monkeypatch.setattr(tarfile.TarFile, "extractall", _boom)
    monkeypatch.setattr(tarfile.TarFile, "extract", _boom)


def _build_traversal_tar() -> io.BytesIO:
    """A crafted tar whose only member escapes the destination. Benign marker, no
    payload — it exists to be staged and inspected, never extracted."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        data = b"deep thought benchmark marker\n"
        info = tarfile.TarInfo(name="../deep_thought_poc_marker")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


# --------------------------------------------------------------------------- #
# the static rule
# --------------------------------------------------------------------------- #


def test_detector_flags_vulnerable_and_skips_patched():
    # The fixture holds one vulnerable extractall and one patched extractall
    # (filter='data'). The rule must flag exactly the vulnerable one.
    sarif = scan_file(VULN_FIXTURE)
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    result = results[0]
    assert result["ruleId"] == RULE_ID
    assert result["properties"]["cwe"] == GROUND_TRUTH_CWE
    assert result["properties"]["cve"] == GROUND_TRUTH_CVE


def test_detector_flags_unsafe_filter_values():
    """An UNSAFE filter is still CVE-2007-4559: only a known-safe filter is the fix,
    so `filter=None`, `filter='fully_trusted'`, a dynamic filter, and a bare
    `extract`/`extractall` must all be flagged."""
    from tarfile_detector import scan_source

    vulnerable = [
        "tar.extractall(dest)",
        "tar.extractall(dest, filter=None)",
        'tar.extractall(dest, filter="fully_trusted")',
        "tar.extractall(dest, filter=chosen_at_runtime)",
        # a `.data_filter` on something we cannot prove is the tarfile module — not
        # accepted as safe (it could be any object's attribute).
        "tar.extractall(dest, filter=untrusted.data_filter)",
        "tar.extractall(dest, filter=data_filter)",
        "tar.extract(member, dest)",
    ]
    for snippet in vulnerable:
        assert len(scan_source(snippet, uri="x.py")) == 1, snippet


def test_detector_suppresses_only_known_safe_filters():
    from tarfile_detector import scan_source

    for snippet in (
        'tar.extractall(dest, filter="data")',
        'tar.extractall(dest, filter="tar")',
        "tar.extractall(dest, filter=tarfile.data_filter)",
    ):
        assert scan_source(snippet, uri="x.py") == [], snippet


# --------------------------------------------------------------------------- #
# the REAL ingest: SARIF -> candidate Finding (what DISCOVER does)
# --------------------------------------------------------------------------- #


def test_real_ingest_files_candidate_with_ground_truth():
    sarif = scan_file(VULN_FIXTURE)
    findings = sarif_to_findings(sarif, project="tarfile-cve-2007-4559")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.status is FindingStatus.candidate
    assert finding.cve is None                        # untrusted SARIF cannot ASSIGN a cve
    assert GROUND_TRUTH_CVE in finding.aliases        # only an informational alias
    assert GROUND_TRUTH_CWE in finding.body           # tagged with the CWE
    assert RULE_ID in finding.summary


def test_finding_exports_to_valid_osv():
    finding = sarif_to_findings(scan_file(VULN_FIXTURE), project="tarfile-cve-2007-4559")[0]
    osv = finding_to_osv(finding)
    assert validate_osv(osv) == []
    assert GROUND_TRUTH_CVE in osv.get("aliases", [])


# --------------------------------------------------------------------------- #
# the crafted repro is STAGED, the sink is NEVER executed
# --------------------------------------------------------------------------- #


def test_repro_is_staged_not_executed():
    buf = _build_traversal_tar()
    dest = "/tmp/dt_hypothetical_dest"  # never created, never written

    # Inspecting the crafted input is not executing the sink (extractall/extract
    # are monkeypatched to raise by the autouse fixture; opening + reading members
    # does not call them).
    with tarfile.open(fileobj=buf) as tar:
        members = tar.getmembers()

    traversing = [m.name for m in members if os.path.isabs(m.name) or ".." in m.name.split("/")]
    assert traversing == ["../deep_thought_poc_marker"]

    resolved = os.path.normpath(os.path.join(dest, members[0].name))
    would_escape = not resolved.startswith(os.path.abspath(dest) + os.sep)
    assert would_escape  # the repro genuinely traverses, and we never extracted it


# --------------------------------------------------------------------------- #
# the full integration path — the REAL verbs
# --------------------------------------------------------------------------- #


def _register(store, tmp_path):
    """NEW PROJECT over the fixture, basis permissive_oss, scoped to the fixture."""
    root = tmp_path / "checkout"
    root.mkdir()
    (root / FIXTURE_URI).write_text(VULN_FIXTURE.read_text())
    session = NewProjectSession(
        name="tarfile CVE-2007-4559",
        source_type="open_source",
        local_path=str(root),
        authorization_basis="permissive_oss",
        scope_allowlist=[FIXTURE_URI],
        project_id="tarfile-cve-2007-4559",
        verify_url=lambda _u: True,
    )
    record = run_session(store, GATE, session)
    assert record.gate_outcome.value == "proceed", record.gate_reason
    return root


def test_full_pipeline_rediscovers_and_stops_at_the_verify_escalation(state_dir, tmp_path):
    store = FileStore(state_dir)
    pid = "tarfile-cve-2007-4559"
    root = _register(store, tmp_path)

    # MAP the in-scope surface (read-only).
    run_session(store, GATE, MapSession(pid, root=str(root)))

    # DISCOVER over the detector's SARIF, through the SHIPPED DiscoverSession.
    sarif_path = tmp_path / "tarfile.sarif"
    import json
    sarif_path.write_text(json.dumps(scan_file(root / FIXTURE_URI, uri=FIXTURE_URI)))
    run_session(store, GATE, DiscoverSession(pid, sarif_path=str(sarif_path), root=str(root)))

    # Exactly one candidate, rediscovered with the ground-truth CVE + CWE.
    findings = store.list_findings(project=pid)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.status is FindingStatus.candidate
    assert finding.id.startswith("F-")            # id from the session, not hardcoded
    assert finding.cve is None                        # not authoritatively assigned
    assert GROUND_TRUTH_CVE in finding.aliases        # informational cross-reference
    assert GROUND_TRUTH_CWE in finding.body
    assert validate_osv(finding_to_osv(finding)) == []

    # check is green on the rediscovered state.
    assert run_check(store).ok, run_check(store).errors

    # VERIFY boundary: the autonomous loop reaches the candidate and records a
    # verify_escalation — real reproduction (extraction) is a human-signed hard
    # stop (Article III). The candidate is NEVER promoted; nothing is executed.
    run = run_loop(store, GATE, pid, LoopBudget(max_sessions=20))
    escalations = [s for s in run.trace if s.kind is ActionKind.verify_escalation]
    assert escalations and escalations[0].finding == finding.id
    assert any(finding.id in action and "sign-off" in action.lower()
               for action in run.outstanding_actions)
    assert store.get_finding(finding.id).status is FindingStatus.candidate  # unpromoted
    assert store.get_finding(finding.id).evidence_ref is None               # no evidence


def test_cli_discover_produces_the_candidate_through_the_shipped_session(state_dir, tmp_path):
    import json

    from typer.testing import CliRunner

    from deepthought.cli import app

    runner = CliRunner()
    store = FileStore(state_dir)
    pid = "tarfile-cve-2007-4559"
    root = _register(store, tmp_path)
    sarif_path = tmp_path / "tarfile.sarif"
    sarif_path.write_text(json.dumps(scan_file(root / FIXTURE_URI, uri=FIXTURE_URI)))

    result = runner.invoke(app, [
        "playbook", "discover", "--project", pid,
        "--sarif", str(sarif_path), "--root", str(root), "--state", str(state_dir),
    ])
    assert result.exit_code == 0, result.output
    findings = FileStore(state_dir).list_findings(project=pid)
    assert len(findings) == 1
    assert GROUND_TRUTH_CVE in findings[0].aliases
    assert findings[0].cve is None
    assert findings[0].status is FindingStatus.candidate
