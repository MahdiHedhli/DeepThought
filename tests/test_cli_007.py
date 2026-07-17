"""Feature 007 — the ``mostly_harmless`` low-friction profile.

Test-first coverage of the 18 acceptance criteria in
``specs/007-mostly-harmless/spec.md``. Every load-bearing stop (authorization &
scope, sandboxed execution, no self-directed scope expansion, draft-only
disclosure) is asserted to behave identically with the profile on and off. The
profile is DATA: it fills unset CLI defaults and trims informational display; it
changes no gate decision, writes no scope, defaults no basis, carries no output
path, and cannot extend the loop repertoire.
"""

from __future__ import annotations

import ast
import socket
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from deepthought import cli as cli_mod
from deepthought import profile as profile_mod
from deepthought.cli import app
from deepthought.profile import (
    Profile,
    UnknownProfileError,
    available_profiles,
    resolve_profile,
)
from deepthought.schema import (
    AuthorizationBasis,
    CloseState,
    FindingStatus,
    GateOutcome,
    SessionType,
)
from deepthought.schema.loop import ActionKind, LoopAction, LoopBudget
from deepthought.store import FileStore

from .conftest import make_coverage, make_finding, make_project

runner = CliRunner()

# The canned default the (removed) auto_next_steps streamline used to substitute.
# It must NEVER appear now — the profile does not suppress a session's own next
# steps. Tests key off this phrase as the string that must be ABSENT.
AUTO_NEXT_SENTINEL = "No human action is required"


# --- fixtures / builders ----------------------------------------------------


def _repo(tmp_path, name="repo", scope_dirs=("src",)):
    repo = tmp_path / name
    for d in scope_dirs:
        (repo / d).mkdir(parents=True, exist_ok=True)
        (repo / d / "a.py").write_text("x = 1\n", encoding="utf-8")
    return repo


def _register_own_code(state, repo, scope=("src",), extra=()):
    args = [
        "playbook", "new-project", "--state", str(state),
        "--name", "Local target", "--source-type", "open_source",
        "--local-path", str(repo), "--basis", "own_code",
    ]
    for s in scope:
        args += ["--scope", s]
    args += list(extra)
    return runner.invoke(app, args)


def _seed_project(state, **overrides):
    store = FileStore(state)
    store.save_project(make_project(**overrides))
    return store


# ===========================================================================
# AC-1 (FR-13) — default mode is byte-for-byte unchanged.
# ===========================================================================


def test_ac1_default_mode_read_only_output_unchanged(tmp_path):
    """With no --profile and no env var, the read-only verbs render the full,
    un-collapsed _echo_session header and no profile hint — exactly as 001-006."""
    state = tmp_path / "state"
    repo = _repo(tmp_path)
    _seed_project(state, local_path=str(repo), git_url=None, scope_allowlist=["src"])

    result = runner.invoke(
        app, ["playbook", "map", "--state", str(state), "--project", "php-src"]
    )
    assert result.exit_code == 0, result.output
    # The full four-field header (not the terse one-liner) is present.
    assert "gate    : proceed" in result.output
    assert "close   : clean" in result.output
    # No profile artefacts leak into default mode.
    assert AUTO_NEXT_SENTINEL not in result.output
    assert "profile" not in result.output.lower()


def test_ac1_env_unset_is_default(tmp_path, monkeypatch):
    """An empty DEEPTHOUGHT_PROFILE resolves to default (no profile)."""
    monkeypatch.setenv("DEEPTHOUGHT_PROFILE", "")
    assert resolve_profile("") is None
    assert resolve_profile(None) is None


# ===========================================================================
# AC-2 (FR-5, RT) — scope is never auto-filled; empty stays a HOLD.
# ===========================================================================


def test_ac2_new_project_empty_scope_writes_no_scope_under_profile(tmp_path):
    state = tmp_path / "state"
    repo = _repo(tmp_path)
    result = _register_own_code(
        state, repo, scope=(), extra=["--profile", "mostly_harmless"]
    )
    # No project is durably registered with a manufactured scope. Whether the
    # gate HOLD persists a project or not, NOTHING ever carries '.'/root scope.
    for p in FileStore(state).list_projects():
        assert p.scope_allowlist == [], p.scope_allowlist
        assert "." not in p.scope_allowlist
    # The registration itself HOLDs (empty scope) under the profile.
    assert "hold" in result.output.lower()


def test_ac2_empty_scope_holds_identically_on_and_off_profile(tmp_path):
    """Same project, empty scope: the gate decision is identical with the profile
    ON and OFF — no durable widening (RT F1.1)."""
    state = tmp_path / "state"
    _seed_project(state, scope_allowlist=[])  # empty scope, own basis

    off = runner.invoke(
        app, ["playbook", "status", "--state", str(state), "--project", "php-src"]
    )
    on = runner.invoke(
        app, ["playbook", "status", "--state", str(state), "--project", "php-src",
              "--profile", "mostly_harmless"]
    )
    assert "hold" in off.output.lower()
    assert "hold" in on.output.lower()
    # The gate reason is identical — the profile did not change the decision.
    reason = "scope allowlist is empty"
    assert reason in off.output
    assert reason in on.output
    # And a helpful pointer is emitted under the profile (never a default scope).
    assert "--scope" in on.output


# ===========================================================================
# AC-3 (FR-5, RT) — the profile never emits a root-equivalent area as scope.
# ===========================================================================


def test_ac3_profile_carries_no_scope_field():
    prof = resolve_profile("mostly_harmless")
    for banned in ("scope", "default_scope", "default_scope_for_local",
                   "scope_allowlist"):
        assert not hasattr(prof, banned), banned
    field_names = {f.name for f in _dataclass_fields(prof)}
    assert not any("scope" in n for n in field_names), field_names


def test_ac3_no_root_equivalent_persisted(tmp_path):
    state = tmp_path / "state"
    repo = _repo(tmp_path)
    _register_own_code(state, repo, scope=(), extra=["--profile", "mostly_harmless"])
    for p in FileStore(state).list_projects():
        for token in (".", "./", "", "/"):
            assert token not in p.scope_allowlist


# ===========================================================================
# AC-4 (FR-4, RT) — containment is still enforced under the profile.
# ===========================================================================


def test_ac4_map_refuses_escapes_under_profile(tmp_path):
    state = tmp_path / "state"
    repo = _repo(tmp_path, scope_dirs=("src",))
    # A sibling secret OUTSIDE the checkout the escapes would reach.
    (tmp_path / "secret").mkdir()
    (tmp_path / "secret" / "leak.txt").write_text("secret\n")
    store = _seed_project(
        state, local_path=str(repo), git_url=None,
        scope_allowlist=["src", "../secret", "/etc", "..\\secret"],
    )
    result = runner.invoke(
        app, ["playbook", "map", "--state", str(state), "--project", "php-src",
              "--profile", "mostly_harmless"]
    )
    assert result.exit_code == 0, result.output
    # Only the contained area is mapped; every escape is refused by scope.py.
    covered = {c.area for c in store.list_coverage(project="php-src")}
    assert covered == {"src"}, covered
    assert "../secret" not in covered and "/etc" not in covered
    assert "containment" in result.output.lower() or "refused" in result.output.lower()


# ===========================================================================
# AC-5 (FR-6, RT) — basis is never defaulted; a basis-less project REFUSES.
# ===========================================================================


def test_ac5_basis_never_defaulted(tmp_path):
    state = tmp_path / "state"
    # A project registered with NO basis (created directly to bypass the gate).
    _seed_project(state, authorization_basis=None, scope_allowlist=["src"])

    on = runner.invoke(
        app, ["playbook", "status", "--state", str(state), "--project", "php-src",
              "--profile", "mostly_harmless"]
    )
    off = runner.invoke(
        app, ["playbook", "status", "--state", str(state), "--project", "php-src"]
    )
    assert "refuse" in on.output.lower()
    assert "refuse" in off.output.lower()
    assert "no authorization basis" in on.output
    assert "no authorization basis" in off.output
    # The stored project's basis was NOT filled in by the profile.
    assert FileStore(state).get_project("php-src").authorization_basis is None


def test_ac5_new_project_no_basis_does_not_inject_basis(tmp_path):
    state = tmp_path / "state"
    repo = _repo(tmp_path)
    runner.invoke(
        app,
        ["playbook", "new-project", "--state", str(state), "--name", "x",
         "--source-type", "open_source", "--local-path", str(repo),
         "--scope", "src", "--profile", "mostly_harmless"],
    )
    for p in FileStore(state).list_projects():
        assert p.authorization_basis is None


# ===========================================================================
# AC-6 (FR-6) — a blackbox target still needs an authorization_ref.
# ===========================================================================


def test_ac6_blackbox_still_needs_ref_under_profile(tmp_path):
    state = tmp_path / "state"
    _seed_project(
        state, source_type="blackbox", authorization_basis="permissive_oss",
        authorization_ref=None, git_url="https://example.test/x", local_path=None,
        scope_allowlist=["src"],
    )
    result = runner.invoke(
        app, ["playbook", "status", "--state", str(state), "--project", "php-src",
              "--profile", "mostly_harmless"]
    )
    assert "refuse" in result.output.lower()
    assert "blackbox target requires an authorization_ref" in result.output


# ===========================================================================
# AC-7 (FR-8, RT) — verify --i-have-sandbox-signoff refuses and runs nothing,
# for profile in {unset, mostly_harmless, arbitrary} and via env.
# ===========================================================================


@pytest.mark.parametrize("profile_arg", [None, "mostly_harmless", "totally-bogus"])
@pytest.mark.parametrize("via_env", [False, True])
def test_ac7_verify_signoff_refuses_under_every_profile(
    tmp_path, monkeypatch, profile_arg, via_env
):
    from deepthought.sandbox import docker as docker_mod

    def _boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("the hard stop forbids execution under any profile")

    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(docker_mod.DockerSandbox, "run", _boom)

    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())
    store.save_finding(make_finding(status="candidate", evidence_ref=None))

    args = ["playbook", "verify", "--state", str(state), "--project", "php-src",
            "--finding", "F-0007", "--i-have-sandbox-signoff"]
    if profile_arg is not None:
        if via_env:
            monkeypatch.setenv("DEEPTHOUGHT_PROFILE", profile_arg)
        else:
            args += ["--profile", profile_arg]
    elif via_env:
        pytest.skip("no profile to set via env")

    result = runner.invoke(app, args)
    # The refusal is the LITERAL FIRST action — it fires BEFORE profile
    # resolution, so even an unknown profile still exits 2 (a hard-stop refusal,
    # never a profile-parse error).
    assert result.exit_code == 2, result.output
    combined = (result.output + str(result.exception or "")).lower()
    assert "nothing was executed" in combined or "hard stop" in combined \
        or "does not wire" in combined
    # The candidate is untouched — nothing ran, nothing was promoted.
    assert store.get_finding("F-0007").status is FindingStatus.candidate


# ===========================================================================
# AC-8 (FR-8) — verify is a Noop dry-run under the profile: no promotion.
# ===========================================================================


def test_ac8_verify_noop_dry_run_under_profile_does_not_promote(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())
    store.save_finding(make_finding(status="candidate", evidence_ref=None))

    result = runner.invoke(
        app, ["playbook", "verify", "--state", str(state), "--project", "php-src",
              "--finding", "F-0007", "--noop-reproduced",
              "--profile", "mostly_harmless"]
    )
    assert result.exit_code == 0, result.output
    finding = store.get_finding("F-0007")
    assert finding.status is FindingStatus.candidate       # NOT promoted
    assert not finding.evidence_ref
    assert finding.transition_log == []                    # no transition written
    assert "no execution" in result.output.lower()


# ===========================================================================
# AC-9 (FR-8, RT) — no executing backend imported by cli.py or profile.py.
# ===========================================================================


def _imports_and_names(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported, referenced, modules = set(), set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                modules.add(node.module)
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.Name):
            referenced.add(node.id)
        elif isinstance(node, ast.Attribute):
            referenced.add(node.attr)
    return imported, referenced, modules


def test_ac9_no_executing_backend_referenced():
    from pathlib import Path

    for mod in (cli_mod, profile_mod):
        path = Path(mod.__file__).with_suffix(".py")
        imported, referenced, modules = _imports_and_names(path)
        # Never IMPORT the executing backend or its module.
        assert "DockerSandbox" not in imported, mod.__name__
        assert not any(m.split(".")[-1] == "docker" for m in modules), modules
        # Never REFERENCE the executing backend by name (docstrings — which do
        # mention it — are string constants, not Name/Attribute nodes).
        assert "DockerSandbox" not in referenced, mod.__name__


def test_ac9_docker_backend_still_exported_by_sandbox_package():
    """The executing backend IS exported — the CLI deliberately never uses it."""
    from deepthought import sandbox

    assert "DockerSandbox" in sandbox.__all__


def test_ac9_cli_import_closure_excludes_executing_backend():
    """codex review (PR #37): the AST name-check is necessary but NOT sufficient.
    cli.py does `from .sandbox import ...`, which runs the sandbox package __init__;
    if that eagerly imported `.docker`, the executing backend would be in the
    process import closure even though cli.py never names it. Verify in a CLEAN
    subprocess that importing deepthought.cli leaves deepthought.sandbox.docker
    unloaded (DockerSandbox is exported lazily)."""
    import os
    import subprocess
    import sys

    code = (
        "import sys, deepthought.cli; "
        "print('LOADED' if 'deepthought.sandbox.docker' in sys.modules else 'CLEAN')"
    )
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env
    )
    assert result.returncode == 0, result.stderr
    assert "CLEAN" in result.stdout, (
        "importing deepthought.cli loaded the executing backend "
        f"(stdout={result.stdout!r} stderr={result.stderr!r})"
    )


def test_ac9_docker_backend_lazily_importable():
    """DockerSandbox stays available (lazily) for the signed-off Tier-2 harness."""
    from deepthought import sandbox

    assert sandbox.DockerSandbox.__name__ == "DockerSandbox"


def test_ac9_profile_module_has_no_sandbox_field():
    prof = resolve_profile("mostly_harmless")
    field_names = {f.name for f in _dataclass_fields(prof)}
    assert not any(
        k in n for n in field_names for k in ("sandbox", "exec", "docker", "run_")
    ), field_names


# ===========================================================================
# AC-10 (FR-7, RT) — execution-stop messaging is not trimmed under terse.
# ===========================================================================


def test_ac10_verify_banner_full_under_terse_profile(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())
    store.save_finding(make_finding(status="candidate", evidence_ref=None))

    dry = runner.invoke(
        app, ["playbook", "verify", "--state", str(state), "--project", "php-src",
              "--finding", "F-0007", "--profile", "mostly_harmless"]
    )
    assert dry.exit_code == 0, dry.output
    # The full dry-run banner renders — terse never touches verify.
    assert "no execution — sandbox sign-off pending" in dry.output
    # verify keeps the FULL _echo_session header (not the terse one-liner).
    assert "gate    : proceed" in dry.output

    refuse = runner.invoke(
        app, ["playbook", "verify", "--state", str(state), "--project", "php-src",
              "--finding", "F-0007", "--i-have-sandbox-signoff",
              "--profile", "mostly_harmless"]
    )
    assert refuse.exit_code == 2
    assert "Nothing was executed" in refuse.output


# ===========================================================================
# AC-11 (FR-3, RT) — the profile loop budget is finite, frozen, echoed.
# ===========================================================================


def test_ac11_profile_budget_is_finite_frozen_valid():
    budget = resolve_profile("mostly_harmless").default_loop_budget
    assert isinstance(budget, LoopBudget)
    limits = (budget.max_sessions, budget.max_wall_seconds, budget.max_context_tokens)
    assert not all(x is None for x in limits)           # never all-None
    assert any(x is not None and x > 0 for x in limits)  # >=1 positive finite
    # Frozen — the loop cannot grow its own budget.
    with pytest.raises((TypeError, ValueError, AttributeError)):
        budget.max_sessions = 9999


def test_ac11_flag_free_loop_uses_and_echoes_profile_budget(tmp_path):
    state = tmp_path / "state"
    repo = _repo(tmp_path)
    _seed_project(state, local_path=str(repo), git_url=None, scope_allowlist=["src"])

    result = runner.invoke(
        app, ["loop", "--project", "php-src", "--state", str(state),
              "--profile", "mostly_harmless"]
    )
    assert result.exit_code == 0, result.output
    # It did NOT hit the "requires at least one budget limit" refusal.
    assert "requires at least one budget" not in result.output
    # The effective budget is echoed.
    budget = resolve_profile("mostly_harmless").default_loop_budget
    assert str(budget.max_sessions) in result.output
    # The persisted LoopRun carries the profile's finite budget.
    run = FileStore(state).list_loop_runs(project="php-src")[-1]
    assert run.budget.max_sessions == budget.max_sessions
    assert run.budget == budget


def test_ac11_flag_free_loop_off_profile_still_exits_2(tmp_path):
    state = tmp_path / "state"
    repo = _repo(tmp_path)
    _seed_project(state, local_path=str(repo), git_url=None, scope_allowlist=["src"])
    result = runner.invoke(app, ["loop", "--project", "php-src", "--state", str(state)])
    assert result.exit_code == 2
    assert "budget" in result.output.lower()


# ===========================================================================
# AC-12 (FR-11, RT) — the loop repertoire is frozen under any profile.
# ===========================================================================


def test_ac12_build_session_raises_for_non_runnable_kinds():
    from deepthought.loop.driver import _build_session

    for kind in (ActionKind.verify_escalation, ActionKind.disclosure_send):
        action = LoopAction(
            kind=kind, project="php-src", finding="F-0007",
            human_action="human must act",
        )
        with pytest.raises(ValueError):
            _build_session(action)


def test_ac12_profile_has_no_field_that_registers_a_session_kind():
    prof = resolve_profile("mostly_harmless")
    field_names = {f.name for f in _dataclass_fields(prof)}
    # The exact, fixed field set — none of which names or registers a session kind.
    assert field_names == {
        "name", "low_ceremony_bases", "default_loop_budget",
        "terse_output", "default_root_from_local_path",
    }, field_names


# ===========================================================================
# AC-13 (FR-11, RT) — the flag-free profile loop escalates, never executes.
# ===========================================================================


def test_ac13_flag_free_profile_loop_escalates_candidate(tmp_path):
    state = tmp_path / "state"
    repo = _repo(tmp_path)
    store = _seed_project(
        state, local_path=str(repo), git_url=None, scope_allowlist=["src"]
    )
    store.save_finding(make_finding(status="candidate", evidence_ref=None))

    result = runner.invoke(
        app, ["loop", "--project", "php-src", "--state", str(state),
              "--profile", "mostly_harmless"]
    )
    assert result.exit_code == 0, result.output
    run = store.list_loop_runs(project="php-src")[-1]
    assert run.stop_reason.value == "hard_stop"
    # The candidate is routed to a verify_escalation whose trace row has NO
    # session_id (it was NEVER run).
    esc = [s for s in run.trace if s.kind is ActionKind.verify_escalation]
    assert esc, run.trace
    assert all(s.session_id is None for s in esc)
    # The candidate was never promoted — no execution happened.
    assert store.get_finding("F-0007").status is FindingStatus.candidate


def test_ac13_verify_session_out_of_loop_import_closure():
    import os
    from pathlib import Path

    import deepthought

    src_dir = str(Path(deepthought.__file__).resolve().parent.parent)
    env = dict(os.environ, PYTHONPATH=src_dir)
    code = (
        "import sys; import deepthought.loop; "
        "assert 'deepthought.sessions.verify' not in sys.modules, "
        "'VerifySession leaked into the loop import closure'; print('ok')"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env
    )
    assert proc.returncode == 0, proc.stderr
    assert "ok" in proc.stdout


# ===========================================================================
# AC-14 (FR-9, RT) — auto-next-steps never touches disclosure / findings /
# the loop teach-back.
# ===========================================================================


def test_ac14_disclose_keeps_full_human_gate_under_profile(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())
    store.save_finding(make_finding(status="verified"))

    result = runner.invoke(
        app, ["playbook", "disclose", "--state", str(state), "--project", "php-src",
              "--finding", "F-0007", "--profile", "mostly_harmless"]
    )
    assert result.exit_code == 0, result.output
    # The full disclosure human-gate text is intact — never auto-substituted.
    assert "Sending is a human action" in result.output
    assert "nothing was transmitted" in result.output.lower()
    assert AUTO_NEXT_SENTINEL not in result.output


def test_ac14_session_with_findings_touched_not_auto_substituted(tmp_path):
    """DISCOVER that produced candidates has non-empty findings_touched, so the
    truthful 'no action' default must NOT paper over its real guidance."""
    from pathlib import Path

    state = tmp_path / "state"
    repo = _repo(tmp_path, scope_dirs=("app",))
    fixture = str(Path(__file__).parent / "fixtures" / "sample.sarif")
    _seed_project(state, local_path=str(repo), git_url=None, scope_allowlist=["app"])

    result = runner.invoke(
        app, ["playbook", "discover", "--state", str(state), "--project", "php-src",
              "--sarif", fixture, "--profile", "mostly_harmless"]
    )
    assert result.exit_code == 0, result.output
    assert FileStore(state).list_findings(project="php-src")  # candidates created
    assert AUTO_NEXT_SENTINEL not in result.output


def test_ac14_loop_teach_back_lists_disclosure_send(tmp_path):
    state = tmp_path / "state"
    repo = _repo(tmp_path)
    store = _seed_project(
        state, local_path=str(repo), git_url=None, scope_allowlist=["src"]
    )
    store.save_finding(make_finding(status="verified"))
    # Draft the disclosure so the loop surfaces a SEND escalation (Article V).
    drafted = runner.invoke(
        app, ["playbook", "disclose", "--state", str(state), "--project", "php-src",
              "--finding", "F-0007"]
    )
    assert drafted.exit_code == 0, drafted.output

    result = runner.invoke(
        app, ["loop", "--project", "php-src", "--state", str(state),
              "--profile", "mostly_harmless"]
    )
    assert result.exit_code == 0, result.output
    out = result.output.lower()
    assert "send" in out and "review" in out          # the send hard stop persists
    run = store.list_loop_runs(project="php-src")[-1]
    assert any("send" in a.lower() for a in run.outstanding_actions)


# ===========================================================================
# AC-15 (FR-7, RT) — terse preserves the transmission notice on publish/disclose.
# ===========================================================================


def test_ac15_publish_preserves_transmission_notice_under_profile(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())
    # A candidate finding keeps `check` green (a `verified` finding would need a
    # resolving evidence_ref); publish emits the OSV record for every finding and
    # asserts the human gate regardless of status.
    store.save_finding(make_finding(status="candidate"))

    result = runner.invoke(
        app, ["publish", "--state", str(state), "--out", str(tmp_path / "out"),
              "--profile", "mostly_harmless"]
    )
    assert result.exit_code == 0, result.output
    out = result.output.lower()
    assert "nothing was transmitted" in out
    assert "human" in out and "review" in out and "send" in out


def test_ac15_disclose_preserves_transmission_notice_under_profile(tmp_path):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())
    store.save_finding(make_finding(status="verified"))

    result = runner.invoke(
        app, ["playbook", "disclose", "--state", str(state), "--project", "php-src",
              "--finding", "F-0007", "--profile", "mostly_harmless"]
    )
    assert result.exit_code == 0, result.output
    out = result.output.lower()
    assert "nothing was transmitted" in out
    assert "human" in out and "review" in out and "send" in out


# ===========================================================================
# AC-16 (FR-10, RT) — no profile output path; disclose stays local & inert.
# ===========================================================================


def test_ac16_profile_has_no_output_path_field():
    prof = resolve_profile("mostly_harmless")
    for banned in ("state_path", "out", "output_dir", "state", "out_dir", "path"):
        assert not hasattr(prof, banned), banned


def test_ac16_disclose_under_profile_is_local_and_inert(tmp_path, monkeypatch):
    state = tmp_path / "state"
    store = FileStore(state)
    store.save_project(make_project())
    store.save_finding(make_finding(status="verified"))

    def _no_socket(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("disclose must open no socket")

    monkeypatch.setattr(socket, "socket", _no_socket)

    result = runner.invoke(
        app, ["playbook", "disclose", "--state", str(state), "--project", "php-src",
              "--finding", "F-0007", "--profile", "mostly_harmless"]
    )
    assert result.exit_code == 0, result.output
    finding = store.get_finding("F-0007")
    assert finding.status is FindingStatus.verified   # lifecycle NOT advanced
    assert finding.cve is None                         # no CVE fabricated


# ===========================================================================
# AC-17 (FR-3, FR-4) — explicit flags override profile defaults.
# ===========================================================================


def test_ac17_explicit_max_sessions_overrides_profile_budget(tmp_path):
    state = tmp_path / "state"
    repo = _repo(tmp_path)
    store = _seed_project(
        state, local_path=str(repo), git_url=None, scope_allowlist=["src"]
    )
    result = runner.invoke(
        app, ["loop", "--project", "php-src", "--state", str(state),
              "--profile", "mostly_harmless", "--max-sessions", "3"]
    )
    assert result.exit_code == 0, result.output
    run = store.list_loop_runs(project="php-src")[-1]
    assert run.budget.max_sessions == 3            # explicit wins
    assert run.budget.max_wall_seconds is None     # profile budget NOT used
    assert run.budget.max_context_tokens is None


def test_ac17_explicit_root_overrides_profile_root_default(tmp_path):
    state = tmp_path / "state"
    # local_path points at an EMPTY dir; the real checkout is elsewhere.
    empty = tmp_path / "empty"
    empty.mkdir()
    real = _repo(tmp_path, name="real", scope_dirs=("src",))
    store = _seed_project(
        state, local_path=str(empty), git_url=None, scope_allowlist=["src"]
    )
    result = runner.invoke(
        app, ["playbook", "map", "--state", str(state), "--project", "php-src",
              "--profile", "mostly_harmless", "--root", str(real)]
    )
    assert result.exit_code == 0, result.output
    # Coverage came from the EXPLICIT --root (which has files), not local_path.
    cov = {c.area: c for c in store.list_coverage(project="php-src")}
    assert "src" in cov
    assert cov["src"].depth.value == "explored"   # files were found under --root


# ===========================================================================
# AC-18 (FR-12) — `deepthought profiles` is auditable and read-only.
# ===========================================================================


def test_ac18_profiles_command_lists_exact_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["profiles"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "mostly_harmless" in out
    budget = resolve_profile("mostly_harmless").default_loop_budget
    assert str(budget.max_sessions) in out
    assert "1800" in out and "200000" in out
    assert "terse" in out.lower()
    assert "root" in out.lower()
    # It documents the refusals it does NOT streamline.
    low = out.lower()
    assert "scope" in low and "basis" in low
    # It changed no state — no store directory was created in cwd.
    assert not (tmp_path / "state").exists()
    assert list(tmp_path.iterdir()) == []


def test_ac18_resolve_unknown_profile_raises():
    with pytest.raises(UnknownProfileError):
        resolve_profile("does-not-exist")
    # The registry exposes exactly the shipped profile(s).
    names = {p.name for p in available_profiles()}
    assert "mostly_harmless" in names


# --- shared helpers ---------------------------------------------------------


def _dataclass_fields(obj):
    import dataclasses

    assert dataclasses.is_dataclass(obj), "Profile must be a (frozen) dataclass"
    return dataclasses.fields(obj)


def test_terse_applied_to_clean_read_only(tmp_path):
    """A clean read-only session under the profile gets the compact one-line header
    (terse_output). The body — including the session's own next steps — renders in
    full; the profile never substitutes a canned default."""
    state = tmp_path / "state"
    repo = _repo(tmp_path)
    _seed_project(
        state, local_path=str(repo), git_url=None, scope_allowlist=["src"]
    )

    on = runner.invoke(
        app, ["playbook", "status", "--state", str(state), "--project", "php-src",
              "--profile", "mostly_harmless"]
    )
    assert on.exit_code == 0, on.output
    # Terse: the compact one-liner header, NOT the four-field block.
    assert "gate=proceed" in on.output
    assert "gate    : proceed" not in on.output
    # The profile NEVER substitutes a canned "no action required" default.
    assert AUTO_NEXT_SENTINEL not in on.output


def test_profile_status_preserves_verify_escalation(tmp_path):
    """Regression (PR #37, codex review): a status run on a project that already has
    a candidate finding is read-only (touches nothing this session), but its real
    next step is to queue a VERIFY. The profile must NOT replace that guidance with
    a canned default — a pending human escalation is never suppressed."""
    state = tmp_path / "state"
    repo = _repo(tmp_path)
    store = _seed_project(
        state, local_path=str(repo), git_url=None, scope_allowlist=["src"]
    )
    # Coverage present + a candidate → status suggests a VERIFY escalation (not MAP).
    store.save_coverage(make_coverage())
    store.save_finding(
        make_finding(id="F-0001", project="php-src", status="candidate")
    )

    out = runner.invoke(
        app, ["playbook", "status", "--state", str(state), "--project", "php-src",
              "--profile", "mostly_harmless"]
    )
    assert out.exit_code == 0, out.output
    # The real remediation guidance survives in full ...
    assert "VERIFY" in out.output
    # ... and the removed canned default never appears.
    assert AUTO_NEXT_SENTINEL not in out.output


def test_root_default_survives_store_error(tmp_path, monkeypatch):
    """gemini review (cli.py:151): under the profile, a StoreError while resolving
    the default --root must NOT escape as a traceback — the command's own
    StoreError handler produces a clean exit 2."""
    from deepthought.store import FileStore, StoreError

    state = tmp_path / "state"
    repo = _repo(tmp_path)
    _seed_project(state, local_path=str(repo), git_url=None, scope_allowlist=["src"])

    def boom(self, project_id):
        raise StoreError("corrupt state")

    monkeypatch.setattr(FileStore, "get_project", boom)

    out = runner.invoke(
        app, ["playbook", "map", "--state", str(state), "--project", "php-src",
              "--profile", "mostly_harmless"]
    )
    # A clean exit 2 (handled), never an unhandled traceback (exit 1 + exception).
    assert out.exit_code == 2, (out.exit_code, out.output, out.exception)


@pytest.mark.parametrize("argv", [["profiles"], ["check"], ["playbook", "findings"]])
def test_unknown_env_profile_rejected_by_all_commands(argv, tmp_path, monkeypatch):
    """codex review (cli.py:76): an unknown DEEPTHOUGHT_PROFILE is rejected
    uniformly — including by commands without profile behavior (profiles/check/
    findings) — so a misspelled global profile never appears accepted depending on
    which command is run."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DEEPTHOUGHT_PROFILE", "does-not-exist")
    result = runner.invoke(app, argv)
    assert result.exit_code == 2, (argv, result.exit_code, result.output)
    assert "does-not-exist" in result.output or "unknown profile" in result.output.lower()


def test_explicit_valid_profile_flag_overrides_bad_env(tmp_path, monkeypatch):
    """A stale invalid DEEPTHOUGHT_PROFILE must NOT block an explicit valid
    --profile flag (flag-over-env precedence — why validation is per-command, not a
    blanket env-only callback)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DEEPTHOUGHT_PROFILE", "does-not-exist")
    result = runner.invoke(app, ["profiles", "--profile", "mostly_harmless"])
    assert result.exit_code == 0, result.output
    assert "mostly_harmless" in result.output


def test_profile_is_frozen():
    prof = resolve_profile("mostly_harmless")
    import dataclasses

    assert dataclasses.is_dataclass(prof)
    with pytest.raises(dataclasses.FrozenInstanceError):
        prof.name = "mutated"
