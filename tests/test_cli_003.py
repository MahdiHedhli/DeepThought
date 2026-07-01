"""Feature 003 slice 3 — CLI wiring for ``playbook verify`` (the dry-run path).

Test-first, and HERMETIC: every test here passes with **no Docker daemon and no
network**, and NOTHING executes untrusted target code. The command reaches
execution only through the ``Sandbox`` seam, and by default that seam is a
``NoopSandbox`` that records the requested run and returns a canned
``SandboxResult`` without running anything.

The 003 hard stop is a CLI invariant, asserted here:

- **Default is a dry-run with NO execution.** Without ``--i-have-sandbox-signoff``
  the command constructs a ``VerifySession`` backed by a ``NoopSandbox`` whose
  canned result is *non-reproducing*, prints ``no execution — sandbox sign-off
  pending``, leaves the candidate a candidate, and exits 0. It never enables
  ``DockerSandbox`` execution and never calls ``DockerSandbox.run()``.
- **``--i-have-sandbox-signoff`` still does not execute in this slice.** No real
  executing backend is wired in 003, so the flag exits non-zero with a clear
  message and runs nothing. (Enabling execution is a distinct, later, signed-off
  change.)
- **A Noop *reproducing* result promotes through the guard.** The dev/test flag
  ``--noop-reproduced`` feeds a reproducing canned result through the *same*
  ``NoopSandbox`` seam (still zero execution), so the candidate reaches
  ``verified`` via ``store.transition_finding`` — the path the 003 smoke drives.
- Unknown project / unknown finding exit non-zero with a message, matching the
  existing ``status``/``map``/``discover`` handling.

No test enables ``execution_enabled``, calls ``DockerSandbox.run()``, or spawns a
subprocess.
"""

from __future__ import annotations

import subprocess

from typer.testing import CliRunner

from deepthought.cli import app
from deepthought.schema import FindingStatus
from deepthought.store import FileStore

from .conftest import make_finding, make_project

runner = CliRunner()


def _seeded_state(tmp_path, **finding_overrides):
    """A store with a proceed-able project and one candidate finding."""
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())
    store.save_finding(
        make_finding(status="candidate", evidence_ref=None, **finding_overrides)
    )
    return state, store


# --- default dry-run: NoopSandbox, no execution, candidate untouched ---------


def test_verify_dry_run_says_no_execution_and_exits_zero(tmp_path):
    state, _ = _seeded_state(tmp_path)

    result = runner.invoke(
        app,
        ["playbook", "verify", "--state", str(state),
         "--project", "php-src", "--finding", "F-0007"],
    )

    assert result.exit_code == 0, result.output
    # Follows the _echo_session shape (gate/close lines).
    assert "gate    : proceed" in result.output
    assert "close   : clean" in result.output
    # And the dry-run states plainly that nothing executed.
    assert "no execution" in result.output.lower()
    assert "sign-off pending" in result.output.lower()


def test_verify_dry_run_leaves_candidate_a_candidate(tmp_path):
    state, store = _seeded_state(tmp_path)

    result = runner.invoke(
        app,
        ["playbook", "verify", "--state", str(state),
         "--project", "php-src", "--finding", "F-0007"],
    )

    assert result.exit_code == 0, result.output
    # A dry-run NoopSandbox returns a NON-reproducing result, so the finding is
    # NOT promoted — it stays a candidate.
    assert store.get_finding("F-0007").status is FindingStatus.candidate


def test_verify_dry_run_never_spawns_a_subprocess(tmp_path, monkeypatch):
    def _boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("playbook verify must not spawn a subprocess")

    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)

    state, _ = _seeded_state(tmp_path)
    result = runner.invoke(
        app,
        ["playbook", "verify", "--state", str(state),
         "--project", "php-src", "--finding", "F-0007"],
    )
    assert result.exit_code == 0, result.output


def test_verify_dry_run_never_calls_docker_run(tmp_path, monkeypatch):
    from deepthought.sandbox import docker as docker_mod

    def _boom(self, spec):  # pragma: no cover - must never run
        raise AssertionError("playbook verify must not call DockerSandbox.run()")

    monkeypatch.setattr(docker_mod.DockerSandbox, "run", _boom)

    state, _ = _seeded_state(tmp_path)
    result = runner.invoke(
        app,
        ["playbook", "verify", "--state", str(state),
         "--project", "php-src", "--finding", "F-0007"],
    )
    assert result.exit_code == 0, result.output


# --- Noop reproducing result: promotion through the Store guard --------------


def test_verify_noop_reproduced_promotes_candidate_to_verified(tmp_path):
    state, store = _seeded_state(tmp_path)

    result = runner.invoke(
        app,
        ["playbook", "verify", "--state", str(state),
         "--project", "php-src", "--finding", "F-0007", "--noop-reproduced"],
    )

    assert result.exit_code == 0, result.output
    finding = store.get_finding("F-0007")
    # Promoted THROUGH the guard: a resolving evidence_ref and status verified.
    assert finding.status is FindingStatus.verified
    assert finding.evidence_ref
    assert store.detail_exists(finding.evidence_ref)


def test_verify_noop_reproduced_leaves_check_green(tmp_path):
    state, _ = _seeded_state(tmp_path)

    verified = runner.invoke(
        app,
        ["playbook", "verify", "--state", str(state),
         "--project", "php-src", "--finding", "F-0007", "--noop-reproduced"],
    )
    assert verified.exit_code == 0, verified.output

    checked = runner.invoke(app, ["check", "--state", str(state)])
    assert checked.exit_code == 0, checked.output
    assert "OK" in checked.output


def test_verify_noop_reproduced_still_no_execution(tmp_path, monkeypatch):
    """Even the reproducing path runs nothing: it is the NoopSandbox seam, never a
    subprocess and never DockerSandbox.run()."""
    from deepthought.sandbox import docker as docker_mod

    def _boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("no execution is permitted in this slice")

    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(docker_mod.DockerSandbox, "run", _boom)

    state, store = _seeded_state(tmp_path)
    result = runner.invoke(
        app,
        ["playbook", "verify", "--state", str(state),
         "--project", "php-src", "--finding", "F-0007", "--noop-reproduced"],
    )
    assert result.exit_code == 0, result.output
    assert store.get_finding("F-0007").status is FindingStatus.verified


# --- the hard stop: --i-have-sandbox-signoff does not execute in this slice ---


def test_verify_signoff_flag_refuses_and_runs_nothing(tmp_path, monkeypatch):
    """The sign-off flag is the 003 hard stop's escape hatch — but no real
    executing backend is wired in this slice, so it exits non-zero with a clear
    message and executes nothing. It must never call DockerSandbox.run() or spawn
    a subprocess."""
    from deepthought.sandbox import docker as docker_mod

    def _boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("the hard stop forbids execution in this slice")

    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(docker_mod.DockerSandbox, "run", _boom)

    state, store = _seeded_state(tmp_path)
    result = runner.invoke(
        app,
        ["playbook", "verify", "--state", str(state),
         "--project", "php-src", "--finding", "F-0007",
         "--i-have-sandbox-signoff"],
    )

    assert result.exit_code != 0
    # A clear message about the missing executing backend / hard stop.
    combined = (result.output + str(result.exception or "")).lower()
    assert "sign-off" in combined or "sandbox" in combined or "execution" in combined
    # The candidate is untouched — nothing ran, nothing was promoted.
    assert store.get_finding("F-0007").status is FindingStatus.candidate


# --- error handling parity with status/map/discover -------------------------


def test_verify_unknown_project_errors(tmp_path):
    state = tmp_path / "state"
    FileStore(state)  # empty store
    result = runner.invoke(
        app,
        ["playbook", "verify", "--state", str(state),
         "--project", "ghost", "--finding", "F-0007"],
    )
    assert result.exit_code != 0


def test_verify_unknown_finding_errors(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())
    # No finding saved.
    result = runner.invoke(
        app,
        ["playbook", "verify", "--state", str(state),
         "--project", "php-src", "--finding", "F-9999"],
    )
    assert result.exit_code != 0


# --- gate still governs ------------------------------------------------------


def test_verify_refused_when_project_has_no_authorization_basis(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project(authorization_basis=None))
    store.save_finding(make_finding(status="candidate", evidence_ref=None))

    result = runner.invoke(
        app,
        ["playbook", "verify", "--state", str(state),
         "--project", "php-src", "--finding", "F-0007"],
    )
    # The harness closes the session; the gate refuses (echoed in the record).
    assert "refuse" in result.output.lower()
    assert store.get_finding("F-0007").status is FindingStatus.candidate
