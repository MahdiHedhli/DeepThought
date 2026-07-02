"""005 — CLI wiring for DISCLOSURE (draft-only).

``playbook disclose`` runs the session and asserts the human gate; ``publish
--format`` emits the finding record (osv) plus the DRAFT-only disclosure formats
(csaf/openvex/cve-draft/advisory) as LOCAL artifacts, status-filtered, under the
same human gate. Nothing transmits, and publish stays hard-gated on ``check``.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from deepthought.cli import app
from deepthought.export.csaf import validate_csaf
from deepthought.store import FileStore

from .conftest import make_finding, make_project

runner = CliRunner()


def _seed_verified(state, *, extra_findings=()):
    store = FileStore(state)
    store.save_project(make_project())
    ev = store.write_detail("S-seed", "evidence.txt", "resolving evidence")
    store.save_finding(make_finding(status="verified", evidence_ref=ev))
    for f in extra_findings:
        store.save_finding(f)
    return store


def test_disclose_drafts_and_asserts_human_gate(tmp_path):
    state = tmp_path / "state"
    _seed_verified(state)

    result = runner.invoke(
        app,
        ["playbook", "disclose", "--state", str(state),
         "--project", "php-src", "--finding", "F-0007"],
    )
    assert result.exit_code == 0, result.output
    assert "HUMAN GATE" in result.output
    assert "nothing was transmitted" in result.output
    # The finding is unchanged — still verified.
    assert FileStore(state).get_finding("F-0007").status.value == "verified"


def test_disclose_refuses_a_non_verified_finding(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())
    store.save_finding(make_finding(status="candidate"))  # not verified

    result = runner.invoke(
        app,
        ["playbook", "disclose", "--state", str(state),
         "--project", "php-src", "--finding", "F-0007"],
    )
    assert result.exit_code == 0, result.output
    assert "not verified" in result.output
    # The success banner must NOT appear on a refusal — it would misstate state.
    assert "unchanged (still verified)" not in result.output
    assert "review the drafts and send" not in result.output


def test_disclose_missing_finding_is_a_clean_refusal(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())

    result = runner.invoke(
        app,
        ["playbook", "disclose", "--state", str(state),
         "--project", "php-src", "--finding", "F-9999"],
    )
    assert result.exit_code == 0, result.output   # clean refusal, not a crash
    assert "not found" in result.output
    assert "unchanged (still verified)" not in result.output


def test_disclose_unknown_project_refused_without_dirtying_state(tmp_path):
    """A mistyped --project must NOT persist an orphan interrupted session that
    would then break `check`."""
    state = tmp_path / "state"
    FileStore(state).save_project(make_project())  # a real, different project exists

    result = runner.invoke(
        app,
        ["playbook", "disclose", "--state", str(state),
         "--project", "does-not-exist", "--finding", "F-0007"],
    )
    assert result.exit_code == 2
    assert "not found" in result.output
    # No session was persisted, so `check` is unaffected.
    assert FileStore(state).list_sessions() == []


def test_publish_format_csaf_is_namespaced_and_validates(tmp_path):
    state = tmp_path / "state"
    out = tmp_path / "out"
    _seed_verified(state)

    result = runner.invoke(
        app, ["publish", "--state", str(state), "--out", str(out), "--format", "csaf"]
    )
    assert result.exit_code == 0, result.output
    artifact = out / "csaf" / "x_F-0007.json"
    assert artifact.exists()
    assert validate_csaf(json.loads(artifact.read_text())) == []
    assert "HUMAN GATE" in result.output


def test_publish_format_all_writes_every_format(tmp_path):
    state = tmp_path / "state"
    out = tmp_path / "out"
    _seed_verified(state)

    result = runner.invoke(
        app, ["publish", "--state", str(state), "--out", str(out), "--format", "all"]
    )
    assert result.exit_code == 0, result.output
    assert (out / "x_F-0007.json").exists()               # osv at root (back-compat)
    assert (out / "csaf" / "x_F-0007.json").exists()
    assert (out / "openvex" / "x_F-0007.json").exists()
    assert (out / "cve-draft" / "x_F-0007.json").exists()
    assert (out / "advisory" / "x_F-0007.md").exists()


def test_publish_disclosure_formats_are_status_filtered(tmp_path):
    state = tmp_path / "state"
    out = tmp_path / "out"
    # A verified finding AND a candidate; only the verified one gets a CSAF draft.
    _seed_verified(state, extra_findings=[make_finding(id="F-0008", status="candidate")])

    result = runner.invoke(
        app, ["publish", "--state", str(state), "--out", str(out), "--format", "csaf"]
    )
    assert result.exit_code == 0, result.output
    assert (out / "csaf" / "x_F-0007.json").exists()       # verified -> drafted
    assert not (out / "csaf" / "x_F-0008.json").exists()   # candidate -> filtered out


def test_publish_stem_is_filesystem_safe():
    """A finding id with path separators / '..' must not produce an artifact path
    that escapes the format directory."""
    from deepthought.cli import _safe_stem

    for bad in ("F/../../etc/passwd", "F\\..\\x", "a/b/c", "..", "F-0007"):
        stem = _safe_stem(bad)
        assert "/" not in stem and "\\" not in stem
        assert stem not in ("", ".", "..")
        assert not stem.startswith("..")
    # normal ids are unchanged (aside from the x_ prefix)
    assert _safe_stem("F-0007") == "x_F-0007"


def test_publish_unknown_format_is_refused(tmp_path):
    state = tmp_path / "state"
    _seed_verified(state)
    result = runner.invoke(
        app, ["publish", "--state", str(state), "--format", "bogus"]
    )
    assert result.exit_code == 2
    assert "unknown --format" in result.output


def test_publish_all_formats_still_gated_on_check(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    # Orphan finding (no project) → check red → publish refused for every format.
    store.save_finding(make_finding(project="ghost"))
    result = runner.invoke(
        app, ["publish", "--state", str(state), "--format", "all"]
    )
    assert result.exit_code == 1
    assert "refused" in result.output
