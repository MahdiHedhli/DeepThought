"""003 slice 1 — the sandbox module.

Test-first, and HERMETIC: every test here passes with **no Docker daemon and no
network**. No test enables ``execution_enabled``, calls ``DockerSandbox.run()``,
or executes untrusted target code. ``subprocess`` is never called with untrusted
input anywhere in this slice, and the tests prove it: the isolation contract is
asserted by *inspecting the built argv*, never by running a container.

Coverage:

- ``SandboxPolicy`` default-constructed is fully hardened (locked-down defaults),
  and ``extra='forbid'`` rejects unknown keys.
- ``SandboxSpec`` requires a ``policy`` and an argv-list ``command`` (a shell
  string fails); ``SandboxResult`` carries the typed firewall fields and forbids
  extras.
- ``Sandbox`` is an ABC whose ``run`` is abstract (cannot be instantiated).
- ``NoopSandbox`` records the spec it was handed and returns the caller-supplied
  canned result, executing nothing.
- ``DockerSandbox.build_command`` renders the fully-hardened ``docker run`` argv
  (every isolation flag present, no ``-v`` host mount, non-root user), as data.
- ``DockerSandbox.run`` raises the sign-off ``SandboxError`` by default and spawns
  no subprocess.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from deepthought.sandbox import (
    DockerSandbox,
    NoopSandbox,
    Sandbox,
    SandboxError,
    SandboxExecutionDisabled,
    SandboxPolicy,
    SandboxResult,
    SandboxSpec,
)


# --- builders --------------------------------------------------------------


def make_spec(**overrides) -> SandboxSpec:
    data = dict(
        image="ghcr.io/deepthought/repro-runner@sha256:" + "0" * 64,
        command=["/repro/run", "--input", "/work/case"],
        repro_ref="detail/S-2026-07-01-0001/repro-01.bin",
        workdir="/work",
        env={},
        policy=SandboxPolicy(),
    )
    data.update(overrides)
    return SandboxSpec.model_validate(data)


def make_result(**overrides) -> SandboxResult:
    data = dict(
        exit_code=134,
        timed_out=False,
        wall_seconds=0.42,
        stdout_ref="detail/S-2026-07-01-0001/verify-stdout.txt",
        stderr_ref="detail/S-2026-07-01-0001/verify-stderr.txt",
        reproduced=True,
    )
    data.update(overrides)
    return SandboxResult.model_validate(data)


# --- SandboxPolicy: locked-down defaults ----------------------------------


def test_policy_defaults_are_fully_hardened():
    """The whole safety story is here: a default policy is locked down."""
    p = SandboxPolicy()
    assert p.network == "none"           # default-deny egress
    assert p.read_only_rootfs is True
    assert p.allow_host_mounts is False
    assert p.drop_all_caps is True
    assert p.no_new_privileges is True
    assert p.run_as_non_root is True
    # Positive, present resource + wall-time bounds.
    assert isinstance(p.pids_limit, int) and p.pids_limit > 0
    assert isinstance(p.memory_mib, int) and p.memory_mib > 0
    assert p.cpus > 0
    assert isinstance(p.wall_timeout_seconds, int) and p.wall_timeout_seconds > 0


def test_policy_forbids_unknown_fields():
    with pytest.raises(ValidationError):
        SandboxPolicy(allow_everything=True)


def test_policy_rejects_nonpositive_limits():
    with pytest.raises(ValidationError):
        SandboxPolicy(pids_limit=0)
    with pytest.raises(ValidationError):
        SandboxPolicy(memory_mib=0)
    with pytest.raises(ValidationError):
        SandboxPolicy(cpus=0)
    with pytest.raises(ValidationError):
        SandboxPolicy(wall_timeout_seconds=0)


# --- SandboxSpec -----------------------------------------------------------


def test_spec_requires_policy():
    with pytest.raises(ValidationError):
        SandboxSpec.model_validate(
            dict(image="img", command=["/run"], repro_ref="detail/x/r.bin")
        )


def test_spec_command_must_be_argv_list_not_shell_string():
    # A shell string is not an argv list; it must fail validation. No shell=True
    # semantics anywhere in the sandbox.
    with pytest.raises(ValidationError):
        make_spec(command="/repro/run --input /work/case && curl evil.example")


def test_spec_requires_a_non_empty_command():
    # An empty command would run the image's default entrypoint, not the repro.
    with pytest.raises(ValidationError):
        make_spec(command=[])


def test_spec_forbids_unknown_fields():
    with pytest.raises(ValidationError):
        make_spec(shell=True)


def test_spec_defaults_empty_env_and_workdir():
    s = SandboxSpec.model_validate(
        dict(
            image="img",
            command=["/run"],
            repro_ref="detail/x/r.bin",
            policy=SandboxPolicy(),
        )
    )
    assert s.env == {}
    assert s.workdir  # a non-empty default working dir


# --- SandboxResult (the firewall type) ------------------------------------


def test_result_carries_typed_firewall_fields():
    r = make_result()
    assert r.exit_code == 134
    assert r.timed_out is False
    assert r.wall_seconds == pytest.approx(0.42)
    # stdout/stderr are POINTERS to paged Store output, never inlined content.
    assert r.stdout_ref.startswith("detail/")
    assert r.stderr_ref.startswith("detail/")
    assert r.reproduced is True


def test_result_forbids_unknown_fields():
    with pytest.raises(ValidationError):
        make_result(stdout="the entire raw target output inlined here")


def test_result_reproduced_defaults_false():
    r = SandboxResult.model_validate(
        dict(exit_code=0, timed_out=False, wall_seconds=0.0)
    )
    assert r.reproduced is False


# --- Sandbox ABC -----------------------------------------------------------


def test_sandbox_is_abstract():
    with pytest.raises(TypeError):
        Sandbox()  # abstract run() -> cannot instantiate


# --- NoopSandbox: records, returns canned, executes nothing ---------------


def test_noop_records_spec_and_returns_canned_result():
    canned = make_result(reproduced=True)
    box = NoopSandbox(canned)
    spec = make_spec()

    out = box.run(spec)

    assert out is canned                     # the exact canned result, unmodified
    assert box.recorded == [spec]            # it RECORDED the requested run
    assert box.recorded[0].command == spec.command


def test_noop_records_each_run_in_order():
    box = NoopSandbox(make_result())
    s1 = make_spec(repro_ref="detail/x/r1.bin")
    s2 = make_spec(repro_ref="detail/x/r2.bin")
    box.run(s1)
    box.run(s2)
    assert box.recorded == [s1, s2]


def test_noop_never_spawns_a_subprocess(monkeypatch):
    called = {"n": 0}

    def _boom(*a, **k):  # pragma: no cover - must never run
        called["n"] += 1
        raise AssertionError("NoopSandbox must not spawn a subprocess")

    import subprocess

    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)

    NoopSandbox(make_result()).run(make_spec())
    assert called["n"] == 0


def test_noop_is_a_sandbox():
    assert isinstance(NoopSandbox(make_result()), Sandbox)


# --- DockerSandbox.build_command: the prove-isolation gate -----------------


def test_build_command_renders_every_hardening_flag():
    spec = make_spec()
    argv = DockerSandbox().build_command(spec)

    assert isinstance(argv, list)
    assert all(isinstance(tok, str) for tok in argv)

    joined = " ".join(argv)
    assert argv[:2] == ["docker", "run"]
    assert "--rm" in argv                                   # ephemeral, torn down
    assert "--network=none" in joined                       # default-deny egress
    assert "--read-only" in argv                            # read-only rootfs
    assert "--cap-drop=ALL" in joined                       # drop all caps
    assert "--security-opt=no-new-privileges" in joined     # no-new-privileges
    assert "--pids-limit" in argv                           # pids cap
    assert "--memory" in argv                               # memory cap
    assert "--cpus" in argv                                 # cpu cap


def test_build_command_uses_a_non_root_user():
    argv = DockerSandbox().build_command(make_spec())
    assert "--user" in argv
    user = argv[argv.index("--user") + 1]
    # never root / uid 0
    assert user not in ("root", "0", "0:0")
    assert not user.startswith("0:")


def test_build_command_refuses_root_user_spellings():
    """The non-root gate must not be bypassable by a root SPELLING. Any user whose
    uid/name part resolves to root/0 — including root:root, root:0, 0:1, padded, or
    upper-case — is refused, never rendered as a privileged run."""
    for bad in ("root", "0", "0:0", "0:1", "root:root", "root:0", " root ", "ROOT", "Root:0"):
        with pytest.raises(SandboxError):
            DockerSandbox().build_command(make_spec(policy=SandboxPolicy(user=bad)))


def test_build_command_refuses_image_starting_with_dash():
    """An image ref that starts with '-' would be parsed by docker as another
    OPTION (argument injection, e.g. --privileged). It is refused, not rendered."""
    for bad in ("--privileged", "-v", "-", "   "):
        with pytest.raises(SandboxError):
            DockerSandbox().build_command(make_spec(image=bad))


def test_build_command_strips_image_whitespace():
    padded = "  ghcr.io/x/y@sha256:" + "0" * 64 + "  "
    argv = DockerSandbox().build_command(make_spec(image=padded))
    assert padded.strip() in argv      # the trimmed image is what is rendered
    assert padded not in argv          # the padded form never is


def test_build_command_refuses_empty_user():
    """An empty / whitespace / ':gid' user has no uid part; it would render an
    empty --user and let docker fall back to the image user (maybe root). Refused."""
    for bad in ("", "   ", ":100", " :100"):
        with pytest.raises(SandboxError):
            DockerSandbox().build_command(make_spec(policy=SandboxPolicy(user=bad)))


def test_build_command_refuses_invalid_env_key():
    """A malformed env key ('=', whitespace, dash, leading digit) is refused —
    it would produce a broken --env token."""
    for bad in ("BAD-KEY", "1BAD", "FOO=X", "FOO BAR", ""):
        with pytest.raises(SandboxError):
            DockerSandbox().build_command(make_spec(env={bad: "x"}))


def test_build_command_accepts_valid_env_keys():
    argv = DockerSandbox().build_command(make_spec(env={"LANG": "C", "_X9": "y"}))
    assert "LANG=C" in argv
    assert "_X9=y" in argv


def test_build_command_stop_timeout_is_a_short_fixed_grace():
    """--stop-timeout is a small FIXED teardown grace, decoupled from
    wall_timeout_seconds (a large wall timeout must not block teardown for
    minutes). The wall-clock execution limit is enforced externally by the runner."""
    argv = DockerSandbox().build_command(
        make_spec(policy=SandboxPolicy(wall_timeout_seconds=300))
    )
    assert "--stop-timeout" in argv
    grace = int(argv[argv.index("--stop-timeout") + 1])
    assert 0 < grace <= 10                 # short and fixed
    assert grace != 300                    # NOT the wall timeout


def test_build_command_renders_no_host_mount():
    # No -v / --mount host bind is EVER rendered: host_mounts are enforced off.
    argv = DockerSandbox().build_command(make_spec())
    assert "-v" not in argv
    assert "--volume" not in argv
    assert "--mount" not in argv


def test_build_command_leaks_no_host_env():
    # Only spec.env (explicit, bounded) may be rendered. With an empty env, no
    # --env / -e appears at all.
    argv = DockerSandbox().build_command(make_spec(env={}))
    assert "--env" not in argv
    assert "-e" not in argv


def test_build_command_renders_bounded_spec_env_only():
    argv = DockerSandbox().build_command(make_spec(env={"LANG": "C"}))
    assert "--env" in argv
    assert "LANG=C" in argv


def test_build_command_ends_with_image_then_argv():
    spec = make_spec(command=["/repro/run", "--input", "/work/case"])
    argv = DockerSandbox().build_command(spec)
    # image immediately precedes the untrusted argv; the argv is passed as tokens,
    # never joined into a shell string.
    idx = argv.index(spec.image)
    assert argv[idx + 1 :] == spec.command


def test_build_command_renders_workdir():
    argv = DockerSandbox().build_command(make_spec(workdir="/work"))
    assert "--workdir" in argv
    assert argv[argv.index("--workdir") + 1] == "/work"


def test_build_command_is_pure_and_spawns_nothing(monkeypatch):
    import subprocess

    def _boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("build_command must not spawn a subprocess")

    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)

    argv1 = DockerSandbox().build_command(make_spec())
    argv2 = DockerSandbox().build_command(make_spec())
    assert argv1 == argv2  # pure: same input, same output


# --- DockerSandbox.run: the HARD STOP -------------------------------------


def test_docker_execution_disabled_by_default():
    assert DockerSandbox().execution_enabled is False


def test_docker_run_raises_signoff_error_by_default(monkeypatch):
    import subprocess

    def _boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("run() must not spawn a subprocess when disabled")

    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)

    box = DockerSandbox()
    # The hard stop raises the dedicated SandboxExecutionDisabled (a SandboxError
    # subclass), so callers can catch the sign-off gate precisely.
    with pytest.raises(SandboxExecutionDisabled) as exc:
        box.run(make_spec())
    assert issubclass(SandboxExecutionDisabled, SandboxError)
    msg = str(exc.value).lower()
    assert "sign-off" in msg
    assert "003" in msg or "hard stop" in msg


def test_docker_is_a_sandbox():
    assert isinstance(DockerSandbox(), Sandbox)
