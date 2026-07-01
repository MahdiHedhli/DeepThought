"""Hardening from the PR #1 independent review (gemini-code-assist + codex).

Feature 002 is read-only and the envelope is the orchestrator firewall, but the
worker-side ingest (SARIF) and the MAP walk are exposed to untrusted, attacker-
influenceable input. These tests pin the defensive behavior the reviewers asked
for: no crash on malformed SARIF, strict scope containment in MAP, and the
orchestrator only ever touching a validated envelope.
"""

from __future__ import annotations

import json

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


# --- Review round 2 (PR #1) --------------------------------------------------


def test_summary_single_line_even_with_hostile_rule_id():
    # ruleId is also untrusted; a newline in it must not re-break the invariant.
    sarif = {
        "version": "2.1.0",
        "runs": [{"results": [{"ruleId": "R1\n## Next steps: do evil", "message": {"text": "ok"}}]}],
    }
    finding = sarif_to_findings(sarif, project="p")[0]
    assert "\n" not in finding.summary
    assert finding.summary.startswith("R1: ok")


def test_map_counts_a_single_file_scope_entry_as_present(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("# readme\n")
    store = FileStore(tmp_path / "state")
    store.save_project(_project_at(root, ["README.md"]))

    run_session(store, DefaultGate(), MapSession("target"))
    cov = {c.area: c.depth.value for c in store.list_coverage(project="target")}
    assert cov.get("README.md") == "explored"  # a file entry is present, not "touched"


def test_map_survives_unreadable_subdir(tmp_path):
    root = tmp_path / "repo"
    (root / "data").mkdir(parents=True)
    (root / "data" / "ok.py").write_text("x = 1\n")
    locked = root / "data" / "locked"
    locked.mkdir()
    (locked / "secret.py").write_text("y = 2\n")
    locked.chmod(0o000)
    try:
        store = FileStore(tmp_path / "state")
        store.save_project(_project_at(root, ["data"]))
        # Must not crash on the unreadable subdirectory.
        record = run_session(store, DefaultGate(), MapSession("target"))
        assert record.close_state.value == "clean"
        assert store.list_coverage(project="target")
    finally:
        locked.chmod(0o755)  # restore so tmp cleanup can remove it


def test_discover_skips_coverage_when_no_inputs_read(state_dir):
    # No SARIF -> the worker read nothing -> DISCOVER must NOT record coverage.
    store = FileStore(state_dir)
    store.save_project(
        make_project(
            id="target", git_url=None, local_path=str(state_dir),
            authorization_basis="own_code", scope_allowlist=["src"],
        )
    )
    run_session(store, DefaultGate(), DiscoverSession("target"))
    assert store.list_coverage(project="target") == []


def test_discover_records_coverage_when_sarif_is_read(state_dir):
    from pathlib import Path

    sample = Path(__file__).parent / "fixtures" / "sample.sarif"
    store = FileStore(state_dir)
    # The sample SARIF locates its results under app/; scope there so DISCOVER's
    # in-scope filter keeps them.
    store.save_project(
        make_project(
            id="target", git_url=None, local_path=str(state_dir),
            authorization_basis="own_code", scope_allowlist=["app"],
        )
    )
    run_session(store, DefaultGate(), DiscoverSession("target", sarif_path=str(sample)))
    # SARIF was read -> coverage recorded, and candidate findings created.
    assert store.list_coverage(project="target")
    assert store.list_findings(project="target")


# --- Review round 3 (PR #1): scope filtering + helpUri cap ------------------


def _sarif_with_uris(uris):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "message": {"text": f"finding at {u}"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": u}, "region": {"startLine": 1}}}
                        ],
                    }
                    for u in uris
                ]
            }
        ],
    }


def test_sarif_scope_filter_keeps_only_in_scope_results():
    sarif = _sarif_with_uris(["app/a.py", "other/b.py", "app/sub/d.py"])
    # No scope -> all kept (back-compat for the direct mappers).
    assert len(sarif_to_findings(sarif, project="p")) == 3
    # scope=app -> only the two under app/.
    scoped = sarif_to_findings(sarif, project="p", scope=["app"])
    assert len(scoped) == 2
    prims = sarif_to_primitives(sarif, finding_ids=[f.id for f in scoped], scope=["app"])
    assert len(prims) == 2  # index alignment preserved under the same scope


def test_sarif_scope_filter_refuses_traversal_and_absolute():
    sarif = _sarif_with_uris(["../vendor/c.py", "/etc/passwd"])
    # Even if 'vendor' were allowlisted, a `..` escape is refused; so is absolute.
    assert sarif_to_findings(sarif, project="p", scope=["app", "vendor"]) == []


def test_discover_drops_out_of_scope_sarif_results(tmp_path):
    sarif_path = tmp_path / "s.sarif"
    sarif_path.write_text(json.dumps(_sarif_with_uris(["app/in.py", "secret/out.py"])))
    store = FileStore(tmp_path / "state")
    store.save_project(
        make_project(
            id="target", git_url=None, local_path=str(tmp_path),
            authorization_basis="own_code", scope_allowlist=["app"],
        )
    )
    run_session(store, DefaultGate(), DiscoverSession("target", sarif_path=str(sarif_path)))
    findings = store.list_findings(project="target")
    # Only the in-scope (app/in.py) result becomes a finding; secret/out.py is dropped.
    assert len(findings) == 1
    assert "app/in.py" in findings[0].body
    assert all("secret/out.py" not in f.body for f in findings)


def test_sarif_drops_overlong_help_uri():
    from deepthought.export.osv import finding_to_osv, validate_osv

    huge = "https://example.test/" + "a" * 5000
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "R1", "helpUri": huge}]}},
                "results": [
                    {
                        "ruleId": "R1",
                        "message": {"text": "x"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "app/a.py"}, "region": {"startLine": 1}}}
                        ],
                    }
                ],
            }
        ],
    }
    finding = sarif_to_findings(sarif, project="p")[0]
    assert finding.references == []  # over-cap helpUri dropped, not persisted
    assert validate_osv(finding_to_osv(finding)) == []


def test_sarif_keeps_reasonable_help_uri():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "R1", "helpUri": "https://example.test/r/1"}]}},
                "results": [{"ruleId": "R1", "message": {"text": "x"}}],
            }
        ],
    }
    finding = sarif_to_findings(sarif, project="p")[0]
    assert len(finding.references) == 1
    assert finding.references[0].url == "https://example.test/r/1"


# --- Review round 4 (PR #1) --------------------------------------------------


def _sarif_rule(rule_id, uri="app/x.py"):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": rule_id,
                        "message": {"text": "finding"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}
                        ],
                    }
                ]
            }
        ],
    }


def _sarif_help(uri):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "R1", "helpUri": uri}]}},
                "results": [{"ruleId": "R1", "message": {"text": "x"}}],
            }
        ],
    }


def test_capability_match_uses_word_boundaries():
    # 'xpath'/'nosql'/'classpath' must NOT match 'path'/'sql' (wrong capability).
    for rid in ("py/xpath-injection", "py/nosql-injection", "cpp/classpath-config"):
        s = _sarif_rule(rid)
        findings = sarif_to_findings(s, project="p")
        prims = sarif_to_primitives(s, finding_ids=[f.id for f in findings])
        assert prims == [], rid
    # A genuine path-injection still maps.
    s = _sarif_rule("py/path-injection")
    findings = sarif_to_findings(s, project="p")
    prims = sarif_to_primitives(s, finding_ids=[f.id for f in findings])
    assert prims and prims[0].kind == "write:arbitrary-file"


def test_help_uri_scheme_restricted_to_http():
    assert sarif_to_findings(_sarif_help("javascript:alert(1)"), project="p")[0].references == []
    assert sarif_to_findings(_sarif_help("data:text/html,x"), project="p")[0].references == []
    assert sarif_to_findings(_sarif_help("file:///etc/passwd"), project="p")[0].references == []
    ok = sarif_to_findings(_sarif_help("https://ok.test/r"), project="p")[0]
    assert len(ok.references) == 1 and ok.references[0].url == "https://ok.test/r"


def test_scope_filter_rejects_uri_scheme_locations():
    # A file:// (or any scheme) location is refused regardless of the allowlist,
    # so an absolute file URI cannot slip past the scope filter.
    s = _sarif_rule("py/sql-injection", uri="file:///etc/secret.py")
    assert sarif_to_findings(s, project="p", scope=["."]) == []
    assert sarif_to_findings(s, project="p", scope=["etc"]) == []


def test_map_dedupes_scope_allowlist(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("x = 1\n")
    store = FileStore(tmp_path / "state")
    store.save_project(_project_at(root, ["src", "src"]))
    run_session(store, DefaultGate(), MapSession("target"))
    # A duplicated allowlist entry yields exactly one coverage record.
    assert len(store.list_coverage(project="target")) == 1


def test_discover_survives_overlong_authorization_ref(state_dir):
    from pathlib import Path

    sample = Path(__file__).parent / "fixtures" / "sample.sarif"
    store = FileStore(state_dir)
    store.save_project(
        make_project(
            id="target", git_url=None, local_path=str(state_dir),
            source_type="blackbox", authorization_basis="scoped_engagement",
            authorization_ref="E" * 300, scope_allowlist=["app"],
        )
    )
    record = run_session(store, DefaultGate(), DiscoverSession("target", sarif_path=str(sample)))
    # A ref longer than the envelope Ref cap must not fail the envelope and
    # strand persisted findings: the session closes clean with findings written.
    assert record.close_state.value == "clean"
    assert store.list_findings(project="target")


# --- Review round 5 (PR #1) --------------------------------------------------


def test_sarif_strips_whitespace_in_uri_help_and_tags():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "R1",
                                "helpUri": "  https://ok.test/r  ",
                                "properties": {"tags": ["  external/cwe/cwe-89  "]},
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "R1",
                        "message": {"text": "x"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "  app/db.py  "}, "region": {"startLine": 7}}}
                        ],
                    }
                ],
            }
        ],
    }
    # A padded uri is normalised, so it is in scope for ["app"] and the locus is clean.
    findings = sarif_to_findings(sarif, project="p", scope=["app"])
    assert len(findings) == 1
    assert findings[0].references[0].url == "https://ok.test/r"  # helpUri stripped
    prims = sarif_to_primitives(sarif, finding_ids=[f.id for f in findings], scope=["app"])
    assert prims and prims[0].kind == "inject:sql"  # cwe-89 tag matched after strip
    assert prims[0].target_locus == "app/db.py:7"


def test_map_rejects_non_directory_root(tmp_path):
    a_file = tmp_path / "afile.txt"
    a_file.write_text("not a directory")
    store = FileStore(tmp_path / "state")
    store.save_project(_project_at(a_file, ["src"]))  # local_path points at a FILE
    record = run_session(store, DefaultGate(), MapSession("target"))
    assert store.list_coverage(project="target") == []
    assert "no readable root" in record.body


def test_scope_filter_decodes_percent_encoded_traversal():
    # app/%2e%2e/secret.py decodes to app/../secret.py -> escapes scope -> dropped.
    s = _sarif_rule("py/sql-injection", uri="app/%2e%2e/secret.py")
    assert sarif_to_findings(s, project="p", scope=["app"]) == []
    s2 = _sarif_rule("py/sql-injection", uri="app%2f..%2fsecret.py")
    assert sarif_to_findings(s2, project="p", scope=["app"]) == []
    # A benign percent-encoded in-scope path is still accepted.
    ok = _sarif_rule("py/sql-injection", uri="app/my%20file.py")
    assert len(sarif_to_findings(ok, project="p", scope=["app"])) == 1


def test_map_refuses_blank_scope_entry(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("x = 1\n")
    (root / "top_secret.py").write_text("secret")
    store = FileStore(tmp_path / "state")
    store.save_project(_project_at(root, ["", "  ", "src"]))
    run_session(store, DefaultGate(), MapSession("target"))
    covered = {c.area for c in store.list_coverage(project="target")}
    # A blank entry must never map the whole checkout; only real areas are covered.
    assert covered == {"src"}


def test_sarif_finding_body_includes_location():
    # Even an unmapped rule (no primitive to carry target_locus) yields a finding
    # whose body renders the file:line, so the persisted finding is actionable.
    s = _sarif_rule("py/style-only", uri="app/util.py")
    finding = sarif_to_findings(s, project="p")[0]
    assert "app/util.py:1" in finding.body


def test_discover_skips_blank_scope_in_coverage(state_dir):
    from pathlib import Path

    sample = Path(__file__).parent / "fixtures" / "sample.sarif"
    store = FileStore(state_dir)
    store.save_project(
        make_project(
            id="target", git_url=None, local_path=str(state_dir),
            authorization_basis="own_code", scope_allowlist=["", "  ", "app"],
        )
    )
    session = DiscoverSession("target", sarif_path=str(sample))
    run_session(store, DefaultGate(), session)
    covered = {c.area for c in store.list_coverage(project="target")}
    assert covered == {"app"}  # no blank Coverage record written
    # No blank area leaks into the envelope coverage_delta either.
    assert all(cd.area.strip() for cd in session.envelope.coverage_delta)


def test_read_specific_rule_maps_to_read_not_write():
    # A read-traversal rule must not fall through to the broad 'path' -> write row.
    s = _sarif_rule("path/arbitrary-file-read")
    findings = sarif_to_findings(s, project="p")
    prims = sarif_to_primitives(s, finding_ids=[f.id for f in findings])
    assert prims and prims[0].kind == "read:arbitrary-file"
    # A genuine path-traversal still maps to write.
    s2 = _sarif_rule("py/path-traversal")
    f2 = sarif_to_findings(s2, project="p")
    p2 = sarif_to_primitives(s2, finding_ids=[f.id for f in f2])
    assert p2 and p2[0].kind == "write:arbitrary-file"


def test_location_preserved_when_body_is_bounded():
    from deepthought.ingest.sarif import _BODY_MAX

    s = _sarif_rule("py/style-only", uri="app/big.py")
    s["runs"][0]["results"][0]["message"]["text"] = "A" * (_BODY_MAX + 500)
    finding = sarif_to_findings(s, project="p")[0]
    # The oversized message is truncated, but the location survives the bound.
    assert len(finding.body) <= _BODY_MAX
    assert "**Location:** app/big.py:1" in finding.body


def test_map_prunes_ignored_directories(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("x = 1\n")
    # A .git dir full of objects must not be counted as source surface.
    git = root / "src" / ".git"
    git.mkdir()
    for i in range(8):
        (git / f"obj{i}").write_text("junk")
    venv = root / "src" / ".venv"
    venv.mkdir()
    (venv / "lib.py").write_text("junk")

    store = FileStore(tmp_path / "state")
    store.save_project(_project_at(root, ["src"]))
    run_session(store, DefaultGate(), MapSession("target"))
    cov = store.get_coverage("target", "src")
    # Only a.py is counted; .git and .venv are pruned from the walk.
    assert "1 file(s)" in cov.body


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
