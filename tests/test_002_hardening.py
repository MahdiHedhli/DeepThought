"""Hardening from the PR #1 independent review (gemini-code-assist + codex).

Feature 002 is read-only and the envelope is the orchestrator firewall, but the
worker-side ingest (SARIF) and the MAP walk are exposed to untrusted, attacker-
influenceable input. These tests pin the defensive behavior the reviewers asked
for: no crash on malformed SARIF, strict scope containment in MAP, and the
orchestrator only ever touching a validated envelope.
"""

from __future__ import annotations

import pytest

from deepthought.ingest.sarif import (
    SarifError,
    load_sarif,
    sarif_to_findings,
    sarif_to_primitives,
)
from deepthought.orchestrator import Conductor
from deepthought.protocol import DefaultGate, run_session
from deepthought.schema import Envelope
from deepthought.sessions import DiscoverSession, MapSession
from deepthought.store import FileStore

from .conftest import make_project
from .test_envelope import valid_envelope


# --- SARIF ingest: no crash on malformed / hostile structure ----------------


def test_load_sarif_missing_file_raises_sarif_error(tmp_path):
    with pytest.raises(SarifError):
        load_sarif(str(tmp_path / "does-not-exist.sarif"))


def test_load_sarif_directory_raises_sarif_error(tmp_path):
    # Opening a directory raises OSError -> must surface as SarifError.
    with pytest.raises(SarifError):
        load_sarif(str(tmp_path))


@pytest.mark.parametrize(
    "hostile_run",
    [
        {"tool": "not-a-dict", "results": [{"message": {"text": "x"}}]},
        {"tool": {"driver": "not-a-dict"}, "results": [{"message": {"text": "x"}}]},
        {"tool": {"driver": {"rules": "not-a-list"}}, "results": [{"message": {"text": "x"}}]},
        {"results": [{"message": "not-a-dict"}]},
        {"results": [{"message": {"text": "x"}, "locations": "not-a-list"}]},
        {"results": [{"message": {"text": "x"}, "locations": ["not-an-object"]}]},
        {"results": "not-a-list"},
        {"results": ["not-an-object"]},
    ],
)
def test_malformed_sarif_structures_do_not_crash(hostile_run):
    sarif = {"version": "2.1.0", "runs": [hostile_run]}
    # Must not raise AttributeError/TypeError — malformed entries are skipped.
    findings = sarif_to_findings(sarif, project="p")
    prims = sarif_to_primitives(sarif, finding_ids=[f.id for f in findings])
    assert isinstance(findings, list)
    assert isinstance(prims, list)


def test_hostile_tags_and_properties_do_not_crash():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "R1", "properties": "not-a-dict"}]}},
                "results": [{"ruleId": "R1", "message": {"text": "finding"}}],
            }
        ],
    }
    findings = sarif_to_findings(sarif, project="p")
    prims = sarif_to_primitives(sarif, finding_ids=[f.id for f in findings])
    assert len(findings) == 1
    assert prims == []  # unmapped ruleId, malformed tags -> no primitive, no crash


def test_summary_is_single_line_even_if_message_has_newlines():
    from deepthought.export.osv import finding_to_osv, validate_osv

    sarif = {
        "version": "2.1.0",
        "runs": [
            {"results": [{"ruleId": "R1", "message": {"text": "line one\nline two\nline three"}}]}
        ],
    }
    finding = sarif_to_findings(sarif, project="p")[0]
    assert "\n" not in finding.summary
    assert finding.summary.startswith("R1: line one")
    assert validate_osv(finding_to_osv(finding)) == []


# --- MAP: strict scope containment (no traversal, no scope widening) --------


def _project_at(root, scope):
    return make_project(
        id="target",
        git_url=None,
        local_path=str(root),
        authorization_basis="own_code",
        scope_allowlist=scope,
    )


def test_map_refuses_parent_traversal_area(tmp_path):
    root = tmp_path / "repo"
    (root / "insrc").mkdir(parents=True)
    (root / "insrc" / "a.py").write_text("x = 1\n")
    # A secret sibling OUTSIDE the repo root.
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "creds.txt").write_text("TOP SECRET")

    store = FileStore(tmp_path / "state")
    store.save_project(_project_at(root, ["insrc", "../secret"]))

    record = run_session(store, DefaultGate(), MapSession("target"))
    covered = {c.area for c in store.list_coverage(project="target")}
    # In-scope area covered; the traversal area is refused and never covered.
    assert "insrc" in covered
    assert "../secret" not in covered
    assert "refused" in record.body.lower() or "containment" in record.body.lower()


def test_map_refuses_absolute_path_area(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    store = FileStore(tmp_path / "state")
    store.save_project(_project_at(root, ["/etc"]))

    run_session(store, DefaultGate(), MapSession("target"))
    covered = {c.area for c in store.list_coverage(project="target")}
    assert "/etc" not in covered  # absolute path never walked or recorded


# --- DISCOVER: orchestrator only ever touches a validated envelope ----------


def test_conductor_exposes_validated_envelope_on_success():
    conductor = Conductor()
    result = conductor.ingest(valid_envelope())  # a plain dict
    assert result.ok
    assert isinstance(result.envelope, Envelope)
    assert result.envelope.findings_written == ["F-0019"]


def test_conductor_envelope_is_none_on_reject():
    conductor = Conductor()
    bad = valid_envelope()
    del bad["gate_attestation"]
    result = conductor.ingest(bad)
    assert not result.ok
    assert result.envelope is None


def test_discover_handles_worker_returning_a_valid_dict(state_dir, monkeypatch):
    import deepthought.sessions.discover as discover_mod

    store = FileStore(state_dir)
    store.save_project(
        make_project(
            id="target", git_url=None, local_path=str(state_dir),
            authorization_basis="own_code", scope_allowlist=["src"],
        )
    )

    # The real out-of-process worker returns an UNTYPED dict. The session must
    # not crash accessing envelope attributes — it uses the validated envelope.
    def fake_worker(store, session_id, project, sarif_path):
        env = valid_envelope(session_ref=session_id, findings_written=[], primitives=[])
        return env  # a plain dict, not an Envelope instance

    monkeypatch.setattr(discover_mod, "_run_marvin_worker", fake_worker)
    session = DiscoverSession("target")
    record = run_session(store, DefaultGate(), session)
    assert record.close_state.value == "clean"
    assert isinstance(session.envelope, Envelope)  # validated, not a raw dict


def test_discover_tolerates_overlong_scope_path(state_dir):
    # scope_allowlist entries are uncapped, but Envelope.CoverageDelta.area is
    # capped at 128. An over-long area must not blow up the discover envelope.
    long_area = "src/" + "a" * 200
    store = FileStore(state_dir)
    store.save_project(
        make_project(
            id="target", git_url=None, local_path=str(state_dir),
            authorization_basis="own_code", scope_allowlist=[long_area],
        )
    )
    session = DiscoverSession("target")  # no SARIF -> empty, but envelope must build
    record = run_session(store, DefaultGate(), session)
    assert record.close_state.value == "clean"
    assert session.conductor is not None and session.conductor.errors == []
