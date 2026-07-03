"""Sandbox execution enablement — the Article III sign-off gate + ASan evidence.

These tests EXECUTE NOTHING: they exercise the double gate (a run is refused
without an explicit ``execution_enabled`` and a valid ``Signoff``, and fails
CLOSED when the runtime is absent), and they parse a real cJSON AddressSanitizer
report into a typed, bounded ``CrashReport``. No container, no daemon, no
subprocess is ever spawned here (a monkeypatch asserts it).
"""

from __future__ import annotations

import subprocess

import pytest
from pydantic import ValidationError

from deepthought.sandbox import (
    CrashReport,
    DockerSandbox,
    IsolationUnavailable,
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
