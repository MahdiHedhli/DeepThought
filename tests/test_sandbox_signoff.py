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


_IMAGE_DIGEST = "sha256:deadbeefcafe"


def _spec() -> SandboxSpec:
    return SandboxSpec(
        image="deepthought/cjson-asan:tier2",
        image_digest=_IMAGE_DIGEST,
        command=["/runner", "/harness", "/seeds/trigger"],  # trusted wrapper + harness
        repro_ref="detail/seed/trigger",
        input_path="/seeds/trigger",
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


def test_signoff_timezone_less_timestamp_fails_closed():
    # A timestamp with no Z/offset is ambiguous — the execution gate must refuse it
    # rather than silently assume UTC.
    s = Signoff(approver="m", project="cjson", granted_at="2026-07-02T11:00:00Z",
                expires_at="2099-01-01T00:00:00")  # no Z
    assert s.valid_for("cjson", now="2026-07-02T11:30:00Z") is False
    assert s.valid_for("cjson", now="2026-07-02T11:30:00") is False  # naive now too


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


class _FakeStore:
    """Minimal store for hermetic run() decision tests: the repro_ref resolves
    (provenance passes), read_detail returns the 7-byte trigger, and paged output is
    discarded."""

    def detail_exists(self, ref: str) -> bool:
        return True

    def read_detail(self, ref: str) -> str:
        return '{"1":1,'

    def write_detail(self, session_id: str, name: str, content: str) -> str:
        return f"detail/{session_id}/{name}"


def _rm_ok(sink: list) -> "callable":
    """A _force_remove stand-in that records the name and reports CONFIRMED removal."""
    def _rm(name: str) -> bool:
        sink.append(name)
        return True
    return _rm


def _enabled_box(monkeypatch, **kw) -> DockerSandbox:
    """A signed-off, enabled sandbox with the runtime present, the daemon assumed
    up, and a store whose repro_ref resolves — the decision logic in run() can then
    be exercised by stubbing _stream_capture, without a real docker. Hermetic."""
    import deepthought.sandbox.docker as docker_mod

    monkeypatch.setattr(docker_mod.shutil, "which", lambda _name: "/usr/bin/docker")
    kw.setdefault("store", _FakeStore())
    kw.setdefault("runtime", "docker")
    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True, **kw)
    monkeypatch.setattr(box, "_preflight_runtime", lambda: None)     # daemon reachable
    monkeypatch.setattr(box, "_image_id", lambda _img: _IMAGE_DIGEST)  # image attests
    monkeypatch.setattr(box, "_verify_baked_input", lambda _spec: None)  # input bound
    return box


def test_build_argv_uses_the_configured_runtime():
    # argv[0] must be the CONFIGURED runtime, not a hardcoded "docker": otherwise a
    # podman sandbox would launch under docker while being checked/cleaned under
    # podman (a fail-closed + cleanup escape).
    assert DockerSandbox(runtime="podman").build_argv(_spec(), _spec().policy)[:2] \
        == ["podman", "run"]
    assert DockerSandbox().build_argv(_spec(), _spec().policy)[0] == "docker"  # default


def test_runtime_pins_the_local_daemon():
    # docker runs are forced onto the LOCAL socket (--context default) so a remote
    # default context cannot redirect a signed-off repro off-host.
    assert DockerSandbox(runtime="docker")._runtime() == ["docker", "--context", "default"]
    # an absolute-path runtime still gets the context pin (basename match)
    assert DockerSandbox(runtime="/usr/bin/docker")._runtime() == \
        ["/usr/bin/docker", "--context", "default"]
    assert DockerSandbox(runtime="podman")._runtime() == ["podman"]


def test_runtime_env_strips_remote_endpoint_vars(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://evil.example:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "remote")
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "1")
    monkeypatch.setenv("PATH", "/usr/bin")  # a benign var survives
    env = DockerSandbox(runtime="docker")._runtime_env()
    assert "DOCKER_HOST" not in env and "DOCKER_CONTEXT" not in env
    assert "DOCKER_TLS_VERIFY" not in env
    assert env.get("PATH") == "/usr/bin"


def test_run_refuses_a_dynamic_pseudo_file_input(monkeypatch):
    # A dynamic pseudo-file (/proc/version) reads differently in the preflight than in
    # the harness — require the input under the immutable seed dir.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (99, CJSON_ASAN, "", False, False, True))
    pseudo = SandboxSpec(image="deepthought/cjson-asan:tier2",
                         command=["/runner", "/harness", "/proc/version"],
                         repro_ref="detail/seed/trigger", input_path="/proc/version",
                         policy=SandboxPolicy())
    with pytest.raises(SandboxError):
        box.run(pseudo)


def test_hardening_disables_swap():
    # --memory-swap == --memory disables swap, so total memory (RAM + swap) is capped
    # at the memory limit, not RAM + docker's default extra swap.
    argv = DockerSandbox().build_argv(_spec(), _spec().policy)
    mem = argv[argv.index("--memory") + 1]
    assert argv[argv.index("--memory-swap") + 1] == mem


def test_run_requires_an_attested_image_digest(monkeypatch):
    # No image_digest -> refuse (a tag alone cannot attest the runtime image).
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (99, CJSON_ASAN, "", False, False, True))
    no_digest = SandboxSpec(image="deepthought/cjson-asan:tier2", image_digest="",
                            command=["/runner", "/harness", "/seeds/trigger"],
                            repro_ref="detail/seed/trigger", input_path="/seeds/trigger",
                            policy=SandboxPolicy())
    with pytest.raises(SandboxError):
        box.run(no_digest)


def test_run_refuses_an_unattested_image(monkeypatch):
    # The image's actual content ID differs from the attested digest (a re-tagged or
    # fake image) -> refuse before crediting anything it produces.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_image_id", lambda _img: "sha256:0000different")
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (99, CJSON_ASAN, "", False, False, True))
    with pytest.raises(SandboxError):
        box.run(_spec())


def test_run_launches_the_attested_content_id_not_the_mutable_tag(monkeypatch):
    # TOCTOU guard: after attesting the tag's digest, the launch AND the baked-input
    # read must target the RESOLVED content ID (immutable), so a tag repointed between
    # the inspect and the run cannot swap the executed image. _image_id resolves the tag
    # to _IMAGE_DIGEST; both the launched argv and the spec handed to _verify_baked_input
    # must carry THAT, never the "deepthought/..." tag.
    box = _enabled_box(monkeypatch)
    seen = {}
    monkeypatch.setattr(box, "_verify_baked_input",
                        lambda spec: seen.__setitem__("verify_image", spec.image))
    captured = {}
    monkeypatch.setattr(box, "_stream_capture",
                        lambda argv, *_a: (captured.__setitem__("argv", argv)
                                           or (99, CJSON_ASAN, "", False, False, True)))
    box.run(_spec())
    argv = captured["argv"]
    assert _IMAGE_DIGEST in argv                             # ran the ATTESTED bytes
    assert "deepthought/cjson-asan:tier2" not in argv        # NOT the mutable tag
    assert seen["verify_image"] == _IMAGE_DIGEST             # baked-input read pinned too


def test_run_refuses_an_unpinnable_non_docker_runtime(monkeypatch):
    # Only docker is pinned to the local daemon (--context default + env strip). A
    # non-docker client can select a REMOTE endpoint via its own config, which env
    # sanitization cannot reach — so an executing run must fail CLOSED rather than run
    # unpinned and risk streaming the repro off-host (the Tier 2 local-only boundary).
    box = _enabled_box(monkeypatch, runtime="podman")
    monkeypatch.setattr(box, "_stream_capture",
                        lambda *_a: (99, CJSON_ASAN, "", False, False, True))
    with pytest.raises(IsolationUnavailable):
        box.run(_spec())


def test_run_returns_a_typed_timeout_result(monkeypatch):
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (None, "partial", "", True, False, True))
    result = box.run(_spec())
    assert result.timed_out is True and result.reproduced is False and result.exit_code == -1


def test_run_aborts_when_output_overflows(monkeypatch):
    # A flooding target is killed at the cap; its truncated output is not evidence.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (137, "flood", "", False, True, True))
    with pytest.raises(SandboxError):
        box.run(_spec())


def test_run_raises_on_a_container_launch_failure(monkeypatch):
    # 125/126/127 come ONLY from the runtime now (the wrapper remaps a harness exit of
    # these to 98), so each is unambiguously a launch failure -> IsolationUnavailable,
    # decided by the EXIT CODE, not any target-controlled output text.
    for code in (125, 126, 127):
        box = _enabled_box(monkeypatch)
        monkeypatch.setattr(box, "_stream_capture",
                            # even target-echoed text does not change the classification
                            lambda *_a, rc=code: (rc, "target said: crun: whatever", "", False, False, True))
        with pytest.raises(IsolationUnavailable):
            box.run(_spec())


def test_run_requires_input_path_to_bind_the_repro(monkeypatch):
    # An executing run with no spec.input_path cannot bind the executed input to the
    # stored repro -> refused BEFORE the container runs.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (99, CJSON_ASAN, "", False, False, True))
    unbound = SandboxSpec(image="deepthought/cjson-asan:tier2",
                          command=["/runner", "/harness", "/seeds/trigger"],
                          repro_ref="detail/seed/trigger", input_path="",
                          policy=SandboxPolicy())
    with pytest.raises(SandboxError):
        box.run(unbound)


def test_verify_baked_input_binds_bytes_and_refuses_a_mismatch(monkeypatch):
    # The read now goes through the bounded, named _stream_capture (same cleanup as
    # the real run); stub it to return the cat output as the 6-tuple.
    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker", store=_FakeStore())  # read_detail -> '{"1":1,'

    def _cap(out, rc=0, timed_out=False, overflowed=False, gone=True):
        return lambda *_a: (rc, out, "", timed_out, overflowed, gone)

    monkeypatch.setattr(box, "_stream_capture", _cap("DIFFERENT BYTES"))
    with pytest.raises(SandboxError):                 # baked != stored -> refuse
        box._verify_baked_input(_spec())
    monkeypatch.setattr(box, "_stream_capture", _cap('{"1":1,'))
    box._verify_baked_input(_spec())                  # byte-identical -> OK, no raise
    monkeypatch.setattr(box, "_stream_capture", _cap("", rc=1))
    with pytest.raises(SandboxError):                 # could not read baked input -> refuse
        box._verify_baked_input(_spec())
    monkeypatch.setattr(box, "_stream_capture", _cap("", rc=None, timed_out=True))
    with pytest.raises(SandboxError):                 # read exceeded limits -> refuse
        box._verify_baked_input(_spec())
    # match, but the read container's removal is UNCONFIRMED -> fail closed AND leave
    # the container queued for teardown (never overwritten by the real run).
    monkeypatch.setattr(box, "_stream_capture", _cap('{"1":1,', gone=False))
    with pytest.raises(SandboxError):
        box._verify_baked_input(_spec())
    assert box._active_container is not None


def test_run_validates_image_before_verifying_input(monkeypatch):
    # An executing run with a malformed image name must fail validation in run()
    # BEFORE running the verify container. The guard now fires at ATTESTATION: run()
    # pins the launch to the resolved content ID, and _image_id renders the image
    # through _safe_image (which rejects an injection-prone ref like a leading '-')
    # while building its inspect argv — before any container or input read.
    import deepthought.sandbox.docker as docker_mod
    box = _enabled_box(monkeypatch)
    # Un-stub _image_id so the REAL _safe_image guard inside it runs (it raises during
    # argv construction, before any subprocess) instead of the hermetic digest stub.
    monkeypatch.setattr(box, "_image_id",
                        lambda img: docker_mod._safe_image(img) and _IMAGE_DIGEST)
    def _boom(*_a, **_k):
        raise AssertionError("_verify_baked_input should not be called for invalid image")
    monkeypatch.setattr(box, "_verify_baked_input", _boom)

    unbound = SandboxSpec(image=" --privileged", image_digest=_IMAGE_DIGEST,
                          command=["/runner", "/harness", "/seeds/trigger"],
                          repro_ref="detail/seed/trigger", input_path="/seeds/trigger",
                          policy=SandboxPolicy())
    with pytest.raises(SandboxError) as exc:
        box.run(unbound)
    assert "image ref" in str(exc.value)


def test_run_refuses_when_command_does_not_run_the_bound_input(monkeypatch):
    # input_path is verified, but the command reads a DIFFERENT baked file -> the
    # executed input is not bound to the provenance; refuse before running.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (99, CJSON_ASAN, "", False, False, True))
    diverged = SandboxSpec(image="deepthought/cjson-asan:tier2",
                           command=["/runner", "/harness", "/seeds/OTHER"],
                           repro_ref="detail/seed/trigger", input_path="/seeds/trigger",
                           policy=SandboxPolicy())
    with pytest.raises(SandboxError):
        box.run(diverged)
    # input_path present but NOT the final arg (another input follows) -> refused:
    # it must be the SOLE, final input the harness runs.
    not_last = SandboxSpec(image="deepthought/cjson-asan:tier2",
                           command=["/runner", "/harness", "/seeds/trigger", "/seeds/other"],
                           repro_ref="detail/seed/trigger", input_path="/seeds/trigger",
                           policy=SandboxPolicy())
    with pytest.raises(SandboxError):
        box.run(not_last)
    # input_path IS the final arg, but an EXTRA positional input precedes it -> the
    # harness could read/crash on /seeds/other; the exactly-3-token contract refuses it.
    extra_input = SandboxSpec(image="deepthought/cjson-asan:tier2",
                              command=["/runner", "/harness", "/seeds/other", "/seeds/trigger"],
                              repro_ref="detail/seed/trigger", input_path="/seeds/trigger",
                              policy=SandboxPolicy())
    with pytest.raises(SandboxError):
        box.run(extra_input)


def test_run_requires_the_trusted_wrapper_as_entrypoint(monkeypatch):
    # Exit 99 is only authentic when the trusted /runner is command[0]. A non-runner
    # entrypoint (e.g. /bin/sh) could print a forged report and exit(99) itself, so it
    # is refused even though it satisfies the input binding.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (99, CJSON_ASAN, "", False, False, True))
    forged = SandboxSpec(image="deepthought/cjson-asan:tier2",
                         command=["/bin/sh", "-c", "print-forged-report", "/seeds/trigger"],
                         repro_ref="detail/seed/trigger", input_path="/seeds/trigger",
                         policy=SandboxPolicy())
    with pytest.raises(SandboxError):
        box.run(forged)


def test_run_refuses_to_execute_the_input_as_the_harness(monkeypatch):
    # ["/runner", input_path] passes the sole-final-input + runner-entrypoint checks,
    # but the wrapper would execv the INPUT FILE as code. A distinct harness token is
    # required before the input.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (99, CJSON_ASAN, "", False, False, True))
    input_as_child = SandboxSpec(image="deepthought/cjson-asan:tier2",
                                 command=["/runner", "/seeds/trigger"],
                                 repro_ref="detail/seed/trigger", input_path="/seeds/trigger",
                                 policy=SandboxPolicy())
    with pytest.raises(SandboxError):
        box.run(input_as_child)
    # A RELATIVE harness that resolves (against workdir) to the input file would make
    # the wrapper execv the input as code — the workdir-resolved compare refuses it.
    aliased = SandboxSpec(image="deepthought/cjson-asan:tier2",
                          command=["/runner", "trigger", "/seeds/trigger"],
                          repro_ref="detail/seed/trigger", input_path="/seeds/trigger",
                          workdir="/seeds", policy=SandboxPolicy())
    with pytest.raises(SandboxError):
        box.run(aliased)
    # A RELATIVE workdir resolves differently on the host vs the container, defeating
    # the alias check -> require an absolute workdir.
    rel_workdir = SandboxSpec(image="deepthought/cjson-asan:tier2",
                              command=["/runner", "/harness", "trigger"],
                              repro_ref="detail/seed/trigger", input_path="trigger",
                              workdir="seeds", policy=SandboxPolicy())
    with pytest.raises(SandboxError):
        box.run(rel_workdir)


def test_run_fails_closed_on_a_wrapper_infrastructure_exit(monkeypatch):
    # runner.c's own RESERVED failures (usage/pipe/fork/execv/waitpid = 100..104) mean
    # the target never ran -> an error, NOT a recorded negative verification result.
    box = _enabled_box(monkeypatch)
    for code in (100, 101, 102, 103, 104):
        monkeypatch.setattr(box, "_stream_capture", lambda *_a, rc=code: (rc, "", "", False, False, True))
        with pytest.raises(SandboxError):
            box.run(_spec())


def test_run_treats_a_sysexits_harness_exit_as_a_negative_result(monkeypatch):
    # A harness exiting a sysexits value (70/71/72) is NO LONGER misclassified as a
    # wrapper infra failure — the wrapper's own codes are the reserved 100..104, so a
    # real harness exit is an ordinary non-reproducing result.
    box = _enabled_box(monkeypatch)
    for code in (70, 71, 72):
        monkeypatch.setattr(box, "_stream_capture",
                            lambda *_a, rc=code: (rc, CJSON_ASAN, "", False, False, True))
        result = box.run(_spec())
        assert result.reproduced is False and result.exit_code == code


def test_verify_baked_input_uses_a_named_container_double_dash_and_stripped_image(monkeypatch):
    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker", store=_FakeStore())

    captured = {}
    def _cap(argv, run_id, timeout):
        captured["argv"] = argv
        return (0, '{"1":1,', "", False, False, True)

    monkeypatch.setattr(box, "_stream_capture", _cap)
    spec = SandboxSpec(
        image="  my-image:latest  ",
        command=["/runner", "/harness", "/seeds/trigger"],
        repro_ref="detail/seed/trigger",
        input_path="/seeds/trigger",
        policy=SandboxPolicy(),
    )
    box._verify_baked_input(spec)
    argv = captured["argv"]
    assert "my-image:latest" in argv          # stripped image
    assert "--name" in argv                    # named -> cleanup path
    assert "--" in argv
    idx = argv.index("--")
    assert argv[idx + 1] == "/seeds/trigger"   # input_path is a filename, not a flag
    assert argv[idx - 1] == "my-image:latest"
    # the read mirrors the SAME policy hardening as the real run
    joined = " ".join(argv)
    assert "--network=none" in joined and "--read-only" in joined
    assert "--cap-drop=ALL" in joined and "--security-opt=no-new-privileges" in joined
    assert "--user" in argv and "--workdir" in argv


def test_verify_baked_input_read_mirrors_a_non_default_policy_user(monkeypatch):
    # A non-default policy user must be applied to the READ too (not a hardcoded
    # 65534), so the seed check runs under the same permissions as the harness.
    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker", store=_FakeStore())
    captured = {}

    def _cap(argv, run_id, timeout):
        captured["argv"] = argv
        return (0, '{"1":1,', "", False, False, True)

    monkeypatch.setattr(box, "_stream_capture", _cap)
    spec = SandboxSpec(image="deepthought/cjson-asan:tier2",
                       command=["/runner", "/harness", "/seeds/trigger"],
                       repro_ref="detail/seed/trigger", input_path="/seeds/trigger",
                       policy=SandboxPolicy(user="1000:2000"))
    box._verify_baked_input(spec)
    argv = captured["argv"]
    assert "1000:2000" in argv                 # the policy user, not a hardcoded 65534
    assert "65534:65534" not in argv


def test_run_raises_when_the_exit_code_is_unavailable(monkeypatch):
    # The client could not be reaped (returncode None) -> an anomaly, not a result:
    # never construct a SandboxResult with a None exit_code (a ValidationError).
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (None, "", "", False, False, True))
    with pytest.raises(SandboxError):
        box.run(_spec())


def test_run_rejects_spoofed_asan_on_a_clean_exit(monkeypatch):
    # ASan-shaped text but a CLEAN (exit 0) run is target-controlled spoofing, never
    # a crash — a finding must not be promoted on it.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (0, CJSON_ASAN, "", False, False, True))
    result = box.run(_spec())
    assert result.reproduced is False and result.crash is None


def test_run_rejects_spoofed_asan_on_any_forgeable_exit(monkeypatch):
    # A crash is credited ONLY on the trusted wrapper's code (99). ASan-shaped text
    # with ANY self-chosen exit — a clean 0, a plain 1, or even 134 (which docker
    # cannot tell from a real SIGABRT death) — must NOT reproduce: the wrapper only
    # emits 99 when the OS observed a real signal death.
    for forged in (0, 1, 134, 139):
        box = _enabled_box(monkeypatch)
        monkeypatch.setattr(box, "_stream_capture",
                            lambda *_a, rc=forged: (rc, CJSON_ASAN, "", False, False, True))
        result = box.run(_spec())
        assert result.reproduced is False and result.crash is None, f"exit {forged} wrongly credited"


def test_run_pages_the_report_from_its_asan_header(monkeypatch):
    # A crash whose report appears after a lot of pre-crash output must still page the
    # ACTUAL report (from the ASan header) as evidence, not a truncated head that
    # omits the report that justified promotion.
    class _RecordingStore(_FakeStore):
        def __init__(self):
            self.details = {}

        def write_detail(self, sid, name, content):
            self.details[name] = content
            return f"detail/{sid}/{name}"

    store = _RecordingStore()
    box = _enabled_box(monkeypatch, store=store)
    noise = "x" * 200_000  # > _OUTPUT_MAX of pre-crash output
    monkeypatch.setattr(box, "_stream_capture",
                        lambda *_a: (99, noise + "\n" + CJSON_ASAN, "", False, False, True))
    result = box.run(_spec())
    assert result.reproduced is True
    report = store.details["asan-report.txt"]
    assert report.startswith("ERROR: AddressSanitizer")  # the report, not the noise head
    assert "parse_string" in report


def test_run_reproduces_only_on_the_trusted_sanitizer_exit(monkeypatch):
    # Exit 99 = the in-image wrapper observed the child die by a deadly signal. Crash
    # credited (with the ASan report present).
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (99, CJSON_ASAN, "", False, False, True))
    result = box.run(_spec())
    assert result.reproduced is True
    assert result.crash is not None and result.crash.faulting_function == "parse_string"


def test_run_does_not_reproduce_on_exit_99_without_a_sanitizer_report(monkeypatch):
    # Exit 99 but no parseable ASan report -> no crash object, not reproduced.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture",
                        lambda *_a: (99, "runner: child signaled, but no report\n", "", False, False, True))
    result = box.run(_spec())
    assert result.reproduced is False and result.crash is None


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


def test_run_fails_closed_without_store_backed_provenance(monkeypatch):
    # An executing run must be tied to a resolving, stored repro. No store, or a
    # ref that does not resolve, refuses BEFORE the container runs — even though the
    # (stubbed) capture would otherwise report a crash.
    import deepthought.sandbox.docker as docker_mod

    monkeypatch.setattr(docker_mod.shutil, "which", lambda _name: "/usr/bin/docker")

    no_store = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                             runtime="docker")  # store defaults None
    monkeypatch.setattr(no_store, "_preflight_runtime", lambda: None)
    monkeypatch.setattr(no_store, "_image_id", lambda _img: _IMAGE_DIGEST)
    monkeypatch.setattr(no_store, "_stream_capture", lambda *_a: (134, CJSON_ASAN, "", False, False, True))
    with pytest.raises(SandboxError):
        no_store.run(_spec())

    class _NoResolve(_FakeStore):
        def detail_exists(self, ref):  # ref present but dangling
            return False

    dangling = _enabled_box(monkeypatch, store=_NoResolve())
    monkeypatch.setattr(dangling, "_stream_capture", lambda *_a: (134, CJSON_ASAN, "", False, False, True))
    with pytest.raises(SandboxError):
        dangling.run(_spec())


def test_run_ids_are_unique_per_invocation():
    # A per-invocation nonce prevents same-second, same-spec runs from colliding on
    # the container --name (docker exit 125) or overwriting each other's output.
    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker")
    argv = box.build_argv(_spec(), _spec().policy)
    ids = {box._run_id(argv) for _ in range(200)}
    assert len(ids) == 200
    assert all(i.startswith("sandbox-") for i in ids)


def test_force_remove_reports_confirmed_removal_only(monkeypatch):
    import deepthought.sandbox.docker as docker_mod

    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker")

    def _result(rc, stderr=b""):
        return lambda *_a, **_k: subprocess.CompletedProcess([], rc, b"", stderr)

    monkeypatch.setattr(docker_mod.subprocess, "run", _result(0))
    assert box._force_remove("x") is True                       # removed
    monkeypatch.setattr(docker_mod.subprocess, "run", _result(1, b"Error: No such container: x"))
    assert box._force_remove("x") is True                       # already gone
    monkeypatch.setattr(docker_mod.subprocess, "run", _result(1, b"Cannot connect to the Docker daemon"))
    assert box._force_remove("x") is False                      # UNCONFIRMED -> keep queued


def test_unconfirmed_removal_keeps_the_container_queued_for_teardown(monkeypatch):
    # A timeout whose `rm -f` could not be confirmed must NOT clear _active_container
    # — teardown gets to retry rather than assume the untrusted container stopped.
    box = _enabled_box(monkeypatch)
    monkeypatch.setattr(box, "_stream_capture", lambda *_a: (None, "", "", True, False, False))
    result = box.run(_spec())
    assert result.timed_out is True
    assert box._active_container is not None      # left queued
    later: list[str] = []
    monkeypatch.setattr(box, "_force_remove", _rm_ok(later))
    box.teardown()                                # retry succeeds
    assert later and box._active_container is None


def test_teardown_force_removes_an_active_container(monkeypatch):
    # The context-manager teardown (VerifySession's `with`) force-removes a
    # container left in flight by an interrupt/error between launch and cleanup.
    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker")
    removed: list[str] = []
    monkeypatch.setattr(box, "_force_remove", _rm_ok(removed))
    box._active_container = "sandbox-abc"
    box.teardown()
    assert removed == ["sandbox-abc"] and box._active_container is None
    box.teardown()  # idempotent: nothing in flight, no-op
    assert removed == ["sandbox-abc"]


def test_teardown_fails_closed_when_removal_cannot_be_confirmed(monkeypatch):
    # A container that STILL cannot be confirmed removed must surface (raise), not
    # pass as a clean teardown — a leaked, still-running container fails the session.
    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker")
    monkeypatch.setattr(box, "_force_remove", lambda _name: False)  # never confirms
    box._active_container = "sandbox-stuck"
    with pytest.raises(SandboxError):
        box.teardown()
    assert box._active_container == "sandbox-stuck"  # still flagged, not silently dropped


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
    monkeypatch.setattr(box, "_force_remove", _rm_ok(removed))
    _fake_popen(monkeypatch, b"\xff" * 100, wait_code=0)

    rc, out, err, timed_out, overflowed, gone = box._stream_capture(["docker", "run"], "sandbox-flood", 5.0)
    assert overflowed is True and timed_out is False
    assert removed == ["sandbox-flood"]
    assert len(out) == 16  # capped read; replacement chars, no decode error


def test_stream_capture_catches_a_client_that_survives_eof(monkeypatch):
    # A target can close stdout/stderr but keep running: the read loop ends on EOF,
    # yet the client has not exited. That must be caught as a TIMEOUT and the
    # container force-removed — never treated as a clean exit that leaks it.
    import deepthought.sandbox.docker as docker_mod

    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker")
    removed: list[str] = []
    monkeypatch.setattr(box, "_force_remove", _rm_ok(removed))
    r_out, w_out = os.pipe()
    r_err, w_err = os.pipe()
    os.close(w_out)   # both EOF immediately -> loop exits without a timeout...
    os.close(w_err)

    class _AliveAfterEof:
        returncode = None

        def __init__(self, *_a, **_k):
            self.stdout = os.fdopen(r_out, "rb", buffering=0)
            self.stderr = os.fdopen(r_err, "rb", buffering=0)

        def wait(self, timeout=None):   # ...but the client never exits
            raise subprocess.TimeoutExpired(["docker"], timeout)

        def kill(self):
            pass

    monkeypatch.setattr(docker_mod.subprocess, "Popen", _AliveAfterEof)
    _rc, _o, _e, timed_out, overflowed, _gone = box._stream_capture(
        ["docker", "run"], "sandbox-alive", 0.1)
    assert timed_out is True and overflowed is False
    assert removed == ["sandbox-alive"]   # container force-removed, not leaked


def test_stream_capture_stops_a_hung_container_at_the_deadline(monkeypatch):
    import deepthought.sandbox.docker as docker_mod

    box = DockerSandbox(project="cjson", signoff=_signoff(), execution_enabled=True,
                        runtime="docker")
    removed: list[str] = []
    monkeypatch.setattr(box, "_force_remove", _rm_ok(removed))
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
        _rc, _o, _e, timed_out, overflowed, _gone = box._stream_capture(["docker", "run"], "sandbox-hang", 0.2)
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
    monkeypatch.setattr(box, "_force_remove", _rm_ok(removed))
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


def test_parse_asan_refuses_a_header_only_report():
    # Structural evidence required: exit 99 proves a real signal, but a bare ASan
    # header with NO access line and NO frame is not credible (truncated/spoofed) —
    # refuse it so an executing VERIFY never promotes on header-only text.
    header_only = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0\n"
    assert parse_asan(header_only) is None
    # An access line ALONE (real crash, symbols stripped) is enough to credit it.
    with_access = header_only + "READ of size 1 at 0x0 thread T0\n"
    assert parse_asan(with_access) is not None


def test_parse_asan_uses_the_last_report_not_an_echoed_fake():
    # An input-echoed FAKE "ERROR: AddressSanitizer" block before the real crash must
    # not populate the evidence — the real report is the LAST (dying) output.
    fake = ("==0==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0\n"
            "WRITE of size 9 at 0x0 thread T0\n"
            "    #0 0x0 in fake_func /evil/fake.c:1:1\n\n")
    crash = parse_asan(fake + CJSON_ASAN)
    assert crash is not None
    assert crash.faulting_function == "parse_string"   # from the REAL (last) report
    assert crash.access == "READ" and crash.access_size == 1


def test_parse_asan_accepts_an_uppercase_error_class():
    # An uppercase/mixed error class (e.g. SEGV) must still parse — a real crash must
    # never be misread as a clean run because of case.
    crash = parse_asan(CJSON_ASAN.replace("heap-buffer-overflow", "SEGV"))
    assert crash is not None and crash.error_type == "SEGV"


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
