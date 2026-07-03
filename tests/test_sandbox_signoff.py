"""Sandbox execution enablement — the Article III sign-off gate + ASan evidence.

These tests EXECUTE NOTHING: they exercise the double gate (a run is refused
without an explicit ``execution_enabled`` and a valid ``Signoff``, and fails
CLOSED when the runtime is absent), and they parse a real cJSON AddressSanitizer
report into a typed, bounded ``CrashReport``. No container, no daemon, no
subprocess is ever spawned here (a monkeypatch asserts it).
"""

from __future__ import annotations

import os
import subprocess

import pytest
from pydantic import ValidationError

from deepthought.sandbox import (
    CrashReport,
    DockerSandbox,
    IsolationUnavailable,
    SandboxError,
    SandboxExecutionDisabled,
    SandboxPolicy,
    SandboxSpec,
    Signoff,
    SignoffRequired,
    parse_asan,
)

# A real cJSON heap over-read report (issue #800), symbolized — the shape a run
# under the ASan toolchain emits.
CJSON_ASAN = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xffff8bc00797 at pc 0xaaaae2c4f748 bp 0xffffea12f330 sp 0xffffea12f328
READ of size 1 at 0xffff8bc00797 thread T0
    #0 0xaaaae2c4f744 in parse_string /src/cJSON/cJSON.c:786:9
    #1 0xaaaae2c41840 in parse_object /src/cJSON/cJSON.c:1665:14
    #2 0xaaaae2c41840 in parse_value /src/cJSON/cJSON.c:1365:16
    #3 0xaaaae2c40144 in cJSON_ParseWithLengthOpts /src/cJSON/cJSON.c:1125:10
0xffff8bc00797 is located 0 bytes to the right of 7-byte region [0xffff8bc00790,0xffff8bc00797)
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/cJSON/cJSON.c:786:9 in parse_string
"""


def _spec() -> SandboxSpec:
    return SandboxSpec(
        image="deepthought/cjson-asan:tier2",
        command=["/harness", "/seeds/trigger"],
        repro_ref="detail/seed/trigger",
        workdir="/",
        policy=SandboxPolicy(),
    )


def _signoff(project="cjson", expires="2099-01-01T00:00:00Z") -> Signoff:
    return Signoff(approver="Mahdi Hedhli", project=project, expires_at=expires,
                   reason="tier 2 benchmark")


# --- the Signoff itself -----------------------------------------------------


def test_signoff_valid_window_and_project():
    s = _signoff()
    assert s.valid_for("cjson") is True
    assert s.valid_for("other-project") is False           # wrong project
    assert Signoff(approver="m", project="cjson",
                   expires_at="2000-01-01T00:00:00Z").valid_for("cjson") is False  # expired


def test_signoff_orders_a_fractional_now_correctly():
    # A whole-second expiry vs a fractional `now` in the SAME second: a lexical
    # string compare (the former bug) kept the EXPIRED sign-off valid because "."
    # sorts before "Z"; parsing the timestamps orders them correctly.
    s = Signoff(approver="m", project="cjson",
                granted_at="2026-07-02T11:00:00Z", expires_at="2026-07-02T12:00:00Z")
    assert s.valid_for("cjson", now="2026-07-02T11:59:59.999999Z") is True
    assert s.valid_for("cjson", now="2026-07-02T12:00:00.500000Z") is False  # expired


def test_signoff_unparseable_timestamp_fails_closed():
    s = Signoff(approver="m", project="cjson", granted_at="2026-07-02T11:00:00Z",
                expires_at="not-a-timestamp")
    assert s.valid_for("cjson", now="2026-07-02T11:30:00Z") is False


# --- the double gate (Article III), executing NOTHING -----------------------


@pytest.fixture(autouse=True)
def _no_subprocess(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("the sandbox must not spawn a process on a refused run")

    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(subprocess, "Popen", _boom)


def test_disabled_is_the_hard_stop():
    with pytest.raises(SandboxExecutionDisabled) as exc:
        DockerSandbox().run(_spec())
    assert "sign-off" in str(exc.value).lower()


def test_enabled_without_a_signoff_is_refused():
    box = DockerSandbox(project="cjson", signoff=None, execution_enabled=True)
    with pytest.raises(SignoffRequired):
        box.run(_spec())


def test_enabled_with_a_signoff_for_another_project_is_refused():
    box = DockerSandbox(project="cjson", signoff=_signoff(project="something-else"),
                        execution_enabled=True)
    with pytest.raises(SignoffRequired):
        box.run(_spec())


def test_enabled_with_an_expired_signoff_is_refused():
    box = DockerSandbox(project="cjson",
                        signoff=_signoff(expires="2000-01-01T00:00:00Z"),
                        execution_enabled=True)
    with pytest.raises(SignoffRequired):
        box.run(_spec())


def test_missing_runtime_fails_closed(monkeypatch):
    # Signed off + enabled, but the runtime is absent -> IsolationUnavailable,
    # never a weaker unisolated fallback (and still no subprocess).
    import deepthought.sandbox.docker as docker_mod

    monkeypatch.setattr(docker_mod.shutil, "which", lambda _name: None)
    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True)
    with pytest.raises(IsolationUnavailable):
        box.run(_spec())


def _enabled_box(monkeypatch, **kw) -> DockerSandbox:
    """A signed-off, enabled sandbox with the runtime present and the daemon
    assumed up — the decision logic in run() can then be exercised by stubbing
    _stream_capture, without a real docker. Hermetic."""
    import deepthought.sandbox.docker as docker_mod

    monkeypatch.setattr(docker_mod.shutil, "which", lambda _name: "/usr/bin/docker")
    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker", **kw)
    monkeypatch.setattr(box, "_preflight_runtime", lambda: None)  # daemon reachable
    return box


def test_build_argv_uses_the_configured_runtime():
    # argv[0] must be the CONFIGURED runtime, not a hardcoded "docker": otherwise a
    # podman sandbox would launch under docker while being checked/cleaned under
    # podman (a fail-closed + cleanup escape).
    assert DockerSandbox(runtime="podman").build_argv(_spec(), _spec().policy)[:2] \
        == ["podman", "run"]
    assert DockerSandbox().build_argv(_spec(), _spec().policy)[0] == "docker"  # default


def test_run_returns_a_typed_timeout_result(monkeypatch):
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (None, "partial", "", True, False))
    result = box.run(_spec())
    assert result.timed_out is True and result.reproduced is False and result.exit_code == -1


def test_run_aborts_when_output_overflows(monkeypatch):
    # A flooding target is killed at the cap; its truncated output is not evidence.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (137, "flood", "", False, True))
    with pytest.raises(SandboxError):
        box.run(_spec())


def test_run_raises_on_a_container_launch_failure(monkeypatch):
    # docker exit 125/126/127 = the container never ran -> isolation failure, NOT a
    # negative verification result.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture",
                        lambda *_a: (125, "", "docker: No such image (pull=never)", False, False))
    with pytest.raises(IsolationUnavailable):
        box.run(_spec())


def test_run_raises_when_the_exit_code_is_unavailable(monkeypatch):
    # The client could not be reaped (returncode None) -> an anomaly, not a result:
    # never construct a SandboxResult with a None exit_code (a ValidationError).
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (None, "", "", False, False))
    with pytest.raises(SandboxError):
        box.run(_spec())


def test_run_rejects_spoofed_asan_on_a_clean_exit(monkeypatch):
    # ASan-shaped text but a CLEAN (exit 0) run is target-controlled spoofing, never
    # a crash — a finding must not be promoted on it.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (0, CJSON_ASAN, "", False, False))
    result = box.run(_spec())
    assert result.reproduced is False and result.crash is None


def test_run_rejects_spoofed_asan_on_a_plain_nonzero_exit(monkeypatch):
    # A non-zero exit is NOT enough: a target can print fake ASan and exit(1). Only a
    # DEADLY-SIGNAL termination (docker exit >=128, a real abort_on_error crash) is
    # credited — exit 1 with ASan-shaped text must NOT reproduce.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (1, CJSON_ASAN, "", False, False))
    result = box.run(_spec())
    assert result.reproduced is False and result.crash is None


def test_run_reproduces_only_on_a_deadly_signal_exit(monkeypatch):
    # 134 = 128 + SIGABRT: a real sanitizer abort. Crash credited.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (134, CJSON_ASAN, "", False, False))
    result = box.run(_spec())
    assert result.reproduced is True
    assert result.crash is not None and result.crash.faulting_function == "parse_string"


def test_preflight_fails_closed_when_the_daemon_is_unreachable(monkeypatch):
    # The binary exists but `docker version` fails (daemon down) -> IsolationUnavailable
    # BEFORE any container is launched, never a false-negative verification.
    import deepthought.sandbox.docker as docker_mod

    monkeypatch.setattr(docker_mod.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(docker_mod.subprocess, "run",
                        lambda *_a, **_k: subprocess.CompletedProcess([], 1, b"", b"cannot connect"))
    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker")
    with pytest.raises(IsolationUnavailable):
        box.run(_spec())


def test_teardown_force_removes_an_active_container(monkeypatch):
    # The context-manager teardown (VerifySession's `with`) force-removes a
    # container left in flight by an interrupt/error between launch and cleanup.
    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker")
    removed: list[str] = []
    monkeypatch.setattr(box, "_force_remove", removed.append)
    box._active_container = "sandbox-abc"
    box.teardown()
    assert removed == ["sandbox-abc"] and box._active_container is None
    box.teardown()  # idempotent: nothing in flight, no-op
    assert removed == ["sandbox-abc"]


def _fake_popen(monkeypatch, stdout_bytes: bytes, wait_code: int):
    """Install a fake Popen whose stdout emits ``stdout_bytes`` (then EOF) and whose
    stderr is empty. Returns the list that records _force_remove calls."""
    import deepthought.sandbox.docker as docker_mod

    r_out, w_out = os.pipe()
    r_err, w_err = os.pipe()
    if stdout_bytes:
        os.write(w_out, stdout_bytes)
    os.close(w_out)   # EOF on stdout after the (optional) bytes
    os.close(w_err)   # stderr immediately EOF

    class _Proc:
        returncode = None

        def __init__(self, *_a, **_k):
            self.stdout = os.fdopen(r_out, "rb", buffering=0)
            self.stderr = os.fdopen(r_err, "rb", buffering=0)

        def wait(self, timeout=None):
            self.returncode = wait_code
            return wait_code

    monkeypatch.setattr(docker_mod.subprocess, "Popen", _Proc)


def test_stream_capture_caps_flooded_output_and_kills(monkeypatch):
    # An over-cap flood is truncated at the byte cap AND the container is killed —
    # bounded in memory (no unbounded buffer) and on disk (no temp file). Non-UTF-8
    # bytes decode with replacement, never raise.
    import deepthought.sandbox.docker as docker_mod

    monkeypatch.setattr(docker_mod, "_CAPTURE_MAX", 16)
    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker")
    removed: list[str] = []
    monkeypatch.setattr(box, "_force_remove", removed.append)
    _fake_popen(monkeypatch, b"\xff" * 100, wait_code=0)

    rc, out, err, timed_out, overflowed = box._stream_capture(["docker", "run"], "sandbox-flood", 5.0)
    assert overflowed is True and timed_out is False
    assert removed == ["sandbox-flood"]
    assert len(out) == 16  # capped read; replacement chars, no decode error


def test_stream_capture_stops_a_hung_container_at_the_deadline(monkeypatch):
    import deepthought.sandbox.docker as docker_mod

    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker")
    removed: list[str] = []
    monkeypatch.setattr(box, "_force_remove", removed.append)
    # stdout/stderr that never produce data or EOF -> select hits the wall deadline.
    r_out, w_out = os.pipe()
    r_err, w_err = os.pipe()

    class _Hang:
        returncode = None

        def __init__(self, *_a, **_k):
            self.stdout = os.fdopen(r_out, "rb", buffering=0)
            self.stderr = os.fdopen(r_err, "rb", buffering=0)

        def wait(self, timeout=None):
            self.returncode = -9
            return -9

    monkeypatch.setattr(docker_mod.subprocess, "Popen", _Hang)
    try:
        _rc, _o, _e, timed_out, overflowed = box._stream_capture(["docker", "run"], "sandbox-hang", 0.2)
        assert timed_out is True and overflowed is False
        assert removed == ["sandbox-hang"]
    finally:
        os.close(w_out)
        os.close(w_err)


def test_stream_capture_reaps_the_client_and_stops_the_container_on_interrupt(monkeypatch):
    # An interrupt mid-capture must stop the daemon-side container AND reap the local
    # client (no orphan), then propagate — not leak either.
    import deepthought.sandbox.docker as docker_mod

    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker")
    removed: list[str] = []
    waited: list[bool] = []
    monkeypatch.setattr(box, "_force_remove", removed.append)
    r_out, w_out = os.pipe()
    r_err, w_err = os.pipe()

    class _Proc:
        returncode = None

        def __init__(self, *_a, **_k):
            self.stdout = os.fdopen(r_out, "rb", buffering=0)
            self.stderr = os.fdopen(r_err, "rb", buffering=0)

        def wait(self, timeout=None):
            waited.append(True)
            self.returncode = -9
            return -9

    monkeypatch.setattr(docker_mod.subprocess, "Popen", _Proc)
    monkeypatch.setattr(docker_mod.select, "select",
                        lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        with pytest.raises(KeyboardInterrupt):
            box._stream_capture(["docker", "run"], "sandbox-int", 5.0)
        assert removed == ["sandbox-int"]   # container stopped
        assert waited                        # client reaped, not orphaned
    finally:
        os.close(w_out)
        os.close(w_err)


# --- ASan report -> typed CrashReport ---------------------------------------


def test_parse_asan_extracts_the_cjson_crash():
    crash = parse_asan(CJSON_ASAN)
    assert crash is not None
    assert crash.error_type == "heap-buffer-overflow"
    assert crash.access == "READ" and crash.access_size == 1
    assert crash.faulting_function == "parse_string"
    assert crash.faulting_location == "/src/cJSON/cJSON.c:786:9"
    assert crash.top_frames[0].startswith("parse_string")
    assert len(crash.dedup_key) == 16


def test_parse_asan_is_stable_and_clean_output_is_none():
    assert parse_asan(CJSON_ASAN).dedup_key == parse_asan(CJSON_ASAN).dedup_key
    assert parse_asan("harness: 100000 runs, 0 crashes, all good\n") is None


def test_parse_asan_survives_an_adversarial_access_size():
    # A hostile "of size <5000 digits>" must not crash int() (Python 3.11+ rejects
    # conversion of >4300-digit strings). The size is dropped; the crash still parses.
    report = CJSON_ASAN.replace("READ of size 1", "READ of size " + "9" * 5000)
    crash = parse_asan(report)
    assert crash is not None
    assert crash.access == "READ"
    assert crash.access_size is None       # oversized -> dropped, never a crash
    assert crash.faulting_function == "parse_string"


def test_crash_report_fields_are_bounded():
    # An adversarial sanitizer report with a huge symbol truncates rather than
    # raising — the typed evidence stays bounded.
    huge = "A" * 5000
    report = CJSON_ASAN.replace("parse_string", huge)
    crash = parse_asan(report)
    assert crash is not None
    assert len(crash.faulting_function) <= 128
    assert all(len(frame) <= 128 for frame in crash.top_frames)
    # the CrashReport model itself rejects an over-long field (defence in depth)
    with pytest.raises(ValidationError):
        CrashReport(faulting_function=huge)
