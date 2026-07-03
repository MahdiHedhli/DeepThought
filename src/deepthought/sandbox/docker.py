"""``DockerSandbox`` — the hardened container backend.

Two surfaces:

- ``build_command(spec)`` is a **pure function** that renders the hardened
  ``docker run`` argv a real run *would* use, as a ``list[str]`` for
  **inspection**. It executes nothing. The isolation tests assert every hardening
  clause over this argv, with no Docker daemon and no network.

- ``run(spec)`` is the **Article III door**. It is the one method that shells out
  to execute untrusted code, and it is behind a **double gate**: a default-OFF
  ``execution_enabled`` flag AND a valid ``Signoff`` scoped to the project. With
  the flag off — the state that ships by default and the one every non-benchmark
  test/smoke/CLI path exercises — it raises ``SandboxExecutionDisabled`` and
  executes nothing. Enabled but unsigned raises ``SignoffRequired``; a missing
  runtime raises ``IsolationUnavailable`` (fail closed, never a weaker fallback).
  Only the Tier-2 rediscovery benchmark constructs it enabled, and only with the
  human sign-off Mahdi granted (Constitution Article III).

When it does run, it shells out with **exactly** the isolation ``build_argv``
renders (no shell string is ever built), captures the output, distils any
sanitizer crash into a bounded typed ``CrashReport``, and pages the raw report to
the Store behind a pointer — the orchestrator reads the typed result, never the
raw target output.
"""

from __future__ import annotations

import hashlib
import os
import re
import select
import shutil
import subprocess
import time
from typing import Callable, Optional

from ..schema.common import utcnow
from .asan import parse_asan
from .base import (
    IsolationUnavailable,
    Sandbox,
    SandboxError,
    SandboxExecutionDisabled,
    SandboxPolicy,
    SandboxResult,
    SandboxSpec,
    Signoff,
    SignoffRequired,
)

# A short, FIXED grace period (seconds) for --stop-timeout: the window docker
# waits after SIGTERM before SIGKILL when tearing a container down. It is
# deliberately NOT policy.wall_timeout_seconds — coupling the teardown grace to a
# large wall timeout would block the runner for minutes when killing a hung
# container. The wall-clock EXECUTION limit is enforced externally by the runner.
_STOP_GRACE_SECONDS = 2

# POSIX-style environment variable name: an ASCII letter/underscore then letters,
# digits, underscores. Rejects names with '=', whitespace, dashes, a leading
# digit, unicode, or empties — which would malform the rendered --env token.
_ENV_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# A strictly numeric token (used to validate the --user uid[:gid]). We require a
# NUMERIC uid so a named user cannot alias to UID 0 in the image's /etc/passwd
# (e.g. "toor"), which we cannot inspect at argv-build time.
_NUMERIC_RE = re.compile(r"[0-9]+")

# Bound the raw target output paged to the Store, so an adversarial target cannot
# smuggle an unbounded blob into state. The distilled CrashReport is the typed,
# bounded evidence the orchestrator reads; this is the raw pointer content.
_OUTPUT_MAX = 65536

# Hard cap on bytes READ from the container's stdout+stderr, enforced DURING
# capture (not just on read-back): a target that floods stdio is killed the moment
# it crosses this, so it can exhaust neither controller memory (buffers never grow
# past it) nor host disk (nothing is spooled to a file). Generous over _OUTPUT_MAX
# so a real, multi-frame sanitizer report is captured whole before we page a
# bounded slice of it. A memory-safety repro never emits this much.
_CAPTURE_MAX = 1024 * 1024

# docker/podman reserve these exit codes for "could not run the container" — a bad
# flag or missing image under --pull=never (125), an un-executable entrypoint
# (126), or an entrypoint not found (127). But docker also PROPAGATES a target's own
# exit of those codes, so a code alone is ambiguous: we treat it as an isolation
# failure only when the captured output also carries a runtime-error signature.
_RUNTIME_ERROR_EXITS = frozenset({125, 126, 127})

# Signatures a container CLIENT (docker OR podman/other OCI runtimes) writes when it
# cannot run the container, used to tell a genuine launch failure from a target that
# merely exited 125/126/127. These are RUNTIME-ATTRIBUTABLE phrases the engine emits,
# NOT generic ones a target could print to itself (e.g. "no such file or directory",
# "exec: ") — so a target cannot forge an IsolationUnavailable classification and
# drop its own negative result. A 125/126/127 without one of these is treated as an
# ordinary (non-reproducing) target exit.
_RUNTIME_ERROR_MARKERS = (
    # docker
    "error response from daemon",
    "cannot connect to the docker daemon",
    # podman
    "cannot connect to podman",
    "error preparing container",
    "unable to start container process",
    "image not known",
    "unable to find image",
    "short-name resolution",
    # OCI runtimes name themselves in their error diagnostics
    "oci runtime",
    "runc create failed",
    "crun: ",
)

# The trusted authenticity code: the in-image wrapper (benchmarks/tier2/runner.c)
# forks the harness and returns this ONLY when the OS reports the child died by a
# deadly signal (WIFSIGNALED) — a real sanitizer abort. A crash is credited on this
# code alone, so target-printed ASan text with any self-chosen exit cannot forge a
# reproduction (the child cannot make the wrapper observe a signal it did not raise).
_SANITIZER_CRASH_EXIT = 99

# The trusted wrapper's in-image path. Exit 99 is only authentic when the wrapper
# ITSELF is the container entrypoint (command[0]); with any other entrypoint the
# target could simply exit(99) after printing a forged report. An executing run
# requires this entrypoint.
_TRUSTED_RUNNER = "/runner"

# Wall budget for the baked-input read preflight — small; it only cats one file.
_PREFLIGHT_READ_TIMEOUT = 30.0


class DockerSandbox(Sandbox):
    """Builds a fully-hardened ``docker run`` argv, and — only behind a valid
    sign-off AND an explicit ``execution_enabled`` — actually runs it.

    The double gate is the Article III hard stop in code:
    - ``execution_enabled`` defaults **False**; with it off, ``run`` raises
      ``SandboxExecutionDisabled`` and never spawns a process (the shipped state).
    - Even enabled, ``run`` requires a ``Signoff`` whose ``project`` matches and
      whose window contains now, else ``SignoffRequired``.
    - The runtime must exist, else ``IsolationUnavailable`` — a run fails CLOSED,
      never falling back to a weaker, unisolated execution.

    ``build_command`` stays a pure, execution-free argv renderer, so construction
    and isolation inspection need no sign-off.

    **Trust model.** The sandbox runs a platform-built IMAGE (pinned tag,
    ``--pull=never``, behind the sign-off) whose entrypoint is a trusted wrapper
    that forks the harness and reports ``_SANITIZER_CRASH_EXIT`` (99) ONLY when the
    OS observes the child die by a deadly signal. A crash is credited on that code
    alone, never on target-printed ASan text or a self-chosen exit (docker cannot
    tell a SIGABRT death from ``exit(134)`` by code, so the wrapper's OS-level
    ``WIFSIGNALED`` check is what the target cannot forge), and the executed input is
    bound byte-for-byte to the stored repro before the run.

    The threat model is **untrusted INPUT to trusted, sanitizer-instrumented
    code-under-test** — the fuzzing/reproduction model. The wrapper authenticates
    "the process died by a signal", which distinguishes a real sanitizer abort from
    a clean exit for code (like cJSON) that never self-signals. It does NOT — and
    cannot, for ANY in-process signal — distinguish a sanitizer-raised signal from
    one a fully-adversarial *target binary* raised itself after printing a forged
    report; running attacker-controlled CODE (not input) is out of scope, since
    arbitrary code execution dwarfs report authenticity. Forging ``reproduced`` thus
    requires substituting a malicious IMAGE, which the pinned / no-pull / signed-off
    controls exclude — evidence is only ever as trustworthy as the image, exactly
    the property those controls protect.
    """

    def __init__(
        self,
        *,
        project: Optional[str] = None,
        signoff: Optional[Signoff] = None,
        execution_enabled: bool = False,
        store=None,
        runtime: str = "docker",
        clock: Callable[[], object] = utcnow,
    ) -> None:
        # Default OFF. This is the hard stop.
        self.execution_enabled = execution_enabled
        self.project = project
        self.signoff = signoff
        self.store = store          # paged raw output goes here (optional)
        self.runtime = runtime
        self._clock = clock
        # The name of a container currently believed to be running. Set while a run
        # is in flight and cleared once the container is gone; teardown() force-
        # removes it, so an interrupt (KeyboardInterrupt/SystemExit) between launch
        # and normal cleanup cannot leak a running container past the `with` block.
        self._active_container: Optional[str] = None

    # --- pure config builder (inspection only) -----------------------------

    def _hardening_flags(self, policy: SandboxPolicy, workdir: str) -> list[str]:
        """The default-deny isolation flags rendered from ``policy`` (network,
        read-only rootfs, dropped caps, no-new-privileges, non-root user, pid/memory/
        cpu bounds, stop grace, workdir). Shared by ``build_argv`` and the input-read
        preflight so a read is NEVER less isolated than the real run."""
        flags: list[str] = []
        if policy.ephemeral:
            flags.append("--rm")  # ephemeral: built fresh, torn down after
        # Default-deny egress (the only network value in this slice is "none").
        flags.append(f"--network={policy.network}")
        # Never pull from a registry: a missing image would trigger a host-side fetch
        # (network egress) BEFORE --network=none takes effect.
        flags.append("--pull=never")
        if policy.read_only_rootfs:
            flags.append("--read-only")
        if policy.drop_all_caps:
            flags.append("--cap-drop=ALL")
        if policy.no_new_privileges:
            flags.append("--security-opt=no-new-privileges")
        # Non-root user. Require a STRICTLY NUMERIC, non-zero UID — never a name, which
        # could alias to UID 0 in the image's /etc/passwd (uninspectable here). int()
        # == 0 rejects "0"/"00"/…; the regex rejects "+0"/"-0"/""/":gid". A gid, if
        # present, must also be numeric.
        if policy.run_as_non_root:
            user = policy.user
            uid_raw, sep, gid_raw = user.partition(":")
            uid = uid_raw.strip()
            gid = gid_raw.strip()
            if not _NUMERIC_RE.fullmatch(uid) or int(uid) == 0:
                raise SandboxError(
                    f"run_as_non_root requires a numeric non-zero UID; user "
                    f"{user!r} is refused (a named or zero UID can run as root)"
                )
            if sep and not _NUMERIC_RE.fullmatch(gid):
                raise SandboxError(
                    f"run_as_non_root requires a numeric gid; user {user!r} has a"
                    " non-numeric gid"
                )
            # Render the NORMALIZED (stripped) numeric value, not the raw string.
            flags += ["--user", f"{uid}:{gid}" if sep else uid]
        # Resource bounds. Presence is fixed and tested.
        flags += ["--pids-limit", str(policy.pids_limit)]
        # --memory-swap == --memory DISABLES swap, so total memory (RAM + swap) is
        # capped at memory_mib. Without it docker grants swap on top of --memory, and
        # an aggressively-allocating repro could exceed the budget and hammer host
        # swap/disk.
        flags += ["--memory", f"{policy.memory_mib}m"]
        flags += ["--memory-swap", f"{policy.memory_mib}m"]
        flags += ["--cpus", _format_cpus(policy.cpus)]
        # --stop-timeout is a short, FIXED teardown grace (SIGKILL delay), NOT the
        # wall-clock execution limit (which the reader enforces via the deadline).
        flags += ["--stop-timeout", str(_STOP_GRACE_SECONDS)]
        flags += ["--workdir", workdir]
        return flags

    def build_command(self, spec: SandboxSpec) -> list[str]:
        """Render the hardened ``docker run`` argv for ``spec`` and its policy.

        Pure: same input, same output, no side effects, no execution. Returns a
        ``list[str]`` of argv tokens for inspection — never a shell string.
        """
        return self.build_argv(spec, spec.policy)

    def build_argv(self, spec: SandboxSpec, policy: SandboxPolicy) -> list[str]:
        """The argv mapping (contract name). ``build_command`` delegates here."""
        # argv[0] is the CONFIGURED runtime, not a hardcoded "docker": the same
        # value drives the preflight which-check AND the timeout cleanup, so a
        # non-docker runtime (e.g. "podman") cannot launch under one binary while
        # being checked/cleaned under another (which would defeat fail-closed and
        # leak the container). self.runtime is trusted operator config.
        # The default-deny isolation flags, rendered from the policy. Shared with the
        # input-read preflight so both enforce the SAME hardening (never a weaker read).
        argv: list[str] = [self.runtime, "run"]
        argv += self._hardening_flags(policy, spec.workdir)

        # Force EXACTLY spec.command to run, independent of the image's
        # ENTRYPOINT/CMD. `docker run IMAGE cmd...` appends the trailing tokens as
        # ARGS to any image ENTRYPOINT, so command[0] would NOT be the executable —
        # the image's entrypoint would run instead of the minimized repro. Setting
        # --entrypoint to command[0] (a docker OPTION, before the image) and passing
        # command[1:] after the image makes the repro argv deterministic and stops
        # any baked-in entrypoint from running. command is non-empty (min_length=1).
        argv += ["--entrypoint", spec.command[0]]

        # NO host bind mounts are EVER rendered in this slice: host_mounts are
        # enforced off. The repro input reaches the sandbox as a controlled
        # artifact (spec.repro_ref), never a host-path bind.
        # (Deliberately: no -v / --volume / --mount is appended.)

        # Only spec.env — explicit and bounded. No host env leaks in. With an
        # empty env nothing is rendered. Each key must be a valid POSIX env name:
        # a malformed key ('=', whitespace, dash, leading digit) would produce a
        # broken --env token and could fail or confuse the container startup.
        for key in sorted(spec.env):
            if not _ENV_KEY_RE.fullmatch(key):
                raise SandboxError(
                    f"invalid environment variable name {key!r}: must match"
                    " [A-Za-z_][A-Za-z0-9_]*"
                )
            argv += ["--env", f"{key}={spec.env[key]}"]

        # The image, then the untrusted argv as separate tokens (never joined into a
        # shell string). Validate the image token first (see _safe_image): a ref
        # beginning with '-' would be consumed as a docker OPTION — argument
        # injection that could enable a privileged run.
        argv.append(_safe_image(spec.image))
        # Only the ARGS (command[1:]) follow the image; command[0] is the
        # --entrypoint rendered above, so exactly spec.command executes.
        argv += list(spec.command[1:])
        return argv

    # --- the double-gated real execution -----------------------------------

    def run(self, spec: SandboxSpec) -> SandboxResult:
        """Run the hardened container — behind the Article III double gate.

        Off by default: ``execution_enabled`` False raises
        ``SandboxExecutionDisabled`` (the sign-off hard stop) and never spawns a
        process. Enabled but unsigned raises ``SignoffRequired``. Only with both,
        and a present runtime, does it shell out — with EXACTLY the isolation
        ``build_argv`` renders — capture the output, distil any sanitizer crash,
        and page the raw output to the Store.
        """
        if not self.execution_enabled:
            raise SandboxExecutionDisabled(
                "execution requires Mahdi's sign-off — the 003 hard stop "
                "(Article III); provide a valid Signoff and set execution_enabled"
            )
        if (
            self.signoff is None
            or self.project is None
            or not self.signoff.valid_for(self.project)
        ):
            raise SignoffRequired(
                f"execution is enabled but there is no valid sign-off for project "
                f"{self.project!r} (Article III)"
            )
        if shutil.which(self.runtime) is None:
            # Fail CLOSED: never fall back to a weaker, unisolated execution.
            raise IsolationUnavailable(f"container runtime not found: {self.runtime}")
        # The binary exists, but is its DAEMON reachable? A down daemon makes the
        # run exit non-zero without the target ever executing; probe first so that
        # reads as IsolationUnavailable, not a negative verification result.
        self._preflight_runtime()
        # Provenance, FAIL CLOSED. The repro input is delivered to the container BY
        # THE IMAGE (baked in at the path in spec.command) — the hardening forbids
        # host bind mounts, so no host file crosses the boundary. Every executing run
        # must still be tied to a real, stored repro artifact: require a configured
        # store AND a repro_ref that RESOLVES. No store, an empty ref, or a dangling
        # ref refuses the run — a signed-off execution never runs without provenance.
        if (
            self.store is None
            or not spec.repro_ref
            or not self.store.detail_exists(spec.repro_ref)
        ):
            raise SandboxError(
                f"executing run requires a store-backed repro: repro_ref "
                f"{spec.repro_ref!r} must resolve in a configured store (provenance)"
            )
        # BIND provenance to the executed input: read the baked input back and refuse
        # unless it is byte-identical to the stored repro. spec.input_path is required
        # for an executing run, so a stale or unrelated repro_ref cannot authorize a
        # run that verifies a DIFFERENT baked input.
        if not spec.input_path:
            raise SandboxError(
                "executing run requires spec.input_path (the in-image repro path) so "
                "the executed input can be bound to the stored repro"
            )
        # The executed command must RUN the bound input as its SOLE input. We require
        # input_path to be the FINAL command token and to appear EXACTLY ONCE — the
        # single-input-file convention a repro harness follows ("harness FILE"). This
        # rejects a command that reads a different baked file, so a crash cannot be
        # promoted under a repro_ref that names a different input.
        #
        # HARNESS CONTRACT: the caller's harness must read exactly this final argument
        # as its input and no other baked file. The sandbox verifies input_path's
        # bytes (see _verify_baked_input) and pins its argv position; it cannot parse
        # arbitrary harness argument semantics, so airtight binding for a harness that
        # takes multiple inputs would require the sandbox to STAGE the input itself
        # (a documented follow-up beyond this benchmark's single-input harness).
        if spec.command[-1] != spec.input_path or spec.command.count(spec.input_path) != 1:
            raise SandboxError(
                f"spec.command {spec.command!r} must run the bound input "
                f"{spec.input_path!r} as its sole, final argument; the executed argv "
                f"must run exactly the verified input"
            )
        # Exit 99 is only authentic when the TRUSTED WRAPPER is the entrypoint — it is
        # what turns the OS-observed WIFSIGNALED into 99. With any other entrypoint
        # (e.g. /bin/sh) the target could print a forged report and exit(99) itself,
        # so refuse to run — and thus to ever credit _SANITIZER_CRASH_EXIT — unless
        # command[0] is the bundled runner.
        if spec.command[0] != _TRUSTED_RUNNER:
            raise SandboxError(
                f"executing run requires the trusted wrapper as entrypoint "
                f"(command[0] must be {_TRUSTED_RUNNER!r}); exit "
                f"{_SANITIZER_CRASH_EXIT} is only authentic when the wrapper reports it"
            )
        base_argv = self.build_argv(spec, spec.policy)  # the hardened, isolation-tested argv
        self._verify_baked_input(spec)

        run_id = self._run_id(base_argv)
        # Name the container deterministically so a timed-out / hung container can
        # be force-removed. subprocess's timeout only SIGKILLs the local docker
        # CLIENT; the daemon-side container keeps running unless we stop it by name
        # (--stop-timeout is a teardown grace, not a wall-clock kill). Inserted in
        # run() — not build_argv — so the isolation-tested argv stays pure, and so
        # run_id (a digest of that argv) is stable.
        argv = [*base_argv[:2], "--name", run_id, *base_argv[2:]]
        # Mark the container in-flight BEFORE launch. If an interrupt or error
        # unwinds run() before the container is cleaned, teardown() (via the `with`
        # in VerifySession) force-removes it. Cleared once the container is gone.
        self._active_container = run_id
        # MONOTONIC duration: a backward system-clock shift on a calendar-clock delta
        # could yield a NEGATIVE wall_seconds and crash SandboxResult's ge=0.0 bound.
        started = time.monotonic()
        returncode, stdout, stderr, timed_out, overflowed, container_gone = self._stream_capture(
            argv, run_id, spec.policy.wall_timeout_seconds
        )
        # Clear the active-container state ONLY when removal is confirmed. If a
        # timeout cleanup could not confirm the container is gone, LEAVE it set so
        # the context-manager teardown retries — never assume a failed `rm -f` means
        # the untrusted container stopped.
        if container_gone:
            self._active_container = None
        wall = time.monotonic() - started

        if timed_out:
            return SandboxResult(
                exit_code=returncode if returncode is not None else -1,
                timed_out=True,
                wall_seconds=wall,
                stdout_ref=self._page(run_id, "stdout.txt", stdout),
                stderr_ref=self._page(run_id, "stderr.txt", stderr),
                reproduced=False,
            )
        if overflowed:
            # A memory-safety repro does not emit a megabyte of output. A target
            # that floods stdio past the cap was killed; refuse to mine its
            # truncated output for evidence — an anomalous run is not a result.
            raise SandboxError(
                f"target exceeded the {_CAPTURE_MAX}-byte output cap; run aborted"
            )
        if returncode is None:
            # The client could not be reaped (both waits timed out). We cannot
            # attribute an exit, so this is an anomalous run, not a result — never
            # let it construct a SandboxResult with a None exit_code.
            raise SandboxError(
                "container exit code could not be determined; run aborted"
            )

        combined = f"{stdout}\n{stderr}"
        if returncode in _RUNTIME_ERROR_EXITS and _looks_like_runtime_error(combined):
            # The container could not be started/exec'd (the runtime, not the
            # target, wrote the error) — an isolation failure, not a target run.
            # Never let it read as "did not reproduce". A target that merely EXITED
            # 125/126/127 (no runtime-error signature) falls through to a normal,
            # non-reproducing result rather than a false IsolationUnavailable.
            raise IsolationUnavailable(
                f"{self.runtime} could not run the container (exit {returncode}); "
                f"the target did not execute"
            )

        # TRUST MODEL. A crash is credited ONLY on the trusted wrapper's
        # _SANITIZER_CRASH_EXIT (99): the in-image wrapper forks the harness and
        # returns 99 solely when the OS reports the child died by a deadly SIGNAL
        # (WIFSIGNALED) — a real sanitizer abort. This does not trust the target's
        # stdout or its self-chosen exit code (docker collapses a SIGABRT death and
        # a plain exit(134) to the same 134, so an exit code alone is forgeable);
        # the child cannot make the wrapper observe a signal it never raised. The
        # wrapper, harness, and sanitizer are one platform-built image (pinned tag +
        # --pull=never + sign-off), so the evidence is as trustworthy as the image —
        # exactly what those controls protect.
        crash = parse_asan(combined) if returncode == _SANITIZER_CRASH_EXIT else None
        if crash is not None:
            # Page the full raw sanitizer report; the typed CrashReport carries
            # only bounded fields into orchestrator state.
            crash.raw_ref = self._page(run_id, "asan-report.txt", combined)
        return SandboxResult(
            exit_code=returncode,
            timed_out=False,
            wall_seconds=wall,
            stdout_ref=self._page(run_id, "stdout.txt", stdout),
            stderr_ref=self._page(run_id, "stderr.txt", stderr),
            # A sanitizer crash on an abnormal exit IS the reproduction.
            reproduced=crash is not None,
            crash=crash,
        )

    def _stream_capture(
        self, argv: list[str], run_id: str, wall_timeout: float
    ) -> tuple[Optional[int], str, str, bool, bool, bool]:
        """Launch the container and read stdout/stderr under a hard byte cap and a
        wall deadline, killing the container if either is exceeded.

        Returns ``(returncode, stdout, stderr, timed_out, overflowed, container_gone)``.
        Bounds BOTH memory (buffers never exceed ``_CAPTURE_MAX``) and disk (nothing
        is spooled to a file): a flooding target is stopped AT the cap, not at the
        timeout, and a hung one is stopped at the deadline. ``stdin`` is closed to
        the target. Undecodable bytes are replaced, never raised. ``container_gone``
        is True only when removal is CONFIRMED, so the caller keeps an unconfirmed
        container queued for a teardown retry.

        Not thread-safe: a single instance must not be ``run`` concurrently (each run
        mutates ``_active_container``); the driver constructs one per session.
        """
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        fd_out, fd_err = proc.stdout.fileno(), proc.stderr.fileno()
        bufs: dict[int, bytearray] = {fd_out: bytearray(), fd_err: bytearray()}
        open_fds = {fd_out, fd_err}
        total = 0
        timed_out = False
        overflowed = False
        # MONOTONIC deadline: this is the wall-limit ENFORCEMENT point, so it must
        # not move with the system clock. A backward NTP/manual adjustment on a
        # utcnow() deadline would grow ``remaining`` and let the untrusted container
        # run past wall_timeout; a forward jump would fire a false timeout.
        deadline = time.monotonic() + wall_timeout
        try:
            try:
                while open_fds and not overflowed:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    ready, _, _ = select.select(list(open_fds), [], [], remaining)
                    if not ready:
                        timed_out = True
                        break
                    for fd in ready:
                        chunk = os.read(fd, 65536)
                        if not chunk:  # EOF on this stream
                            open_fds.discard(fd)
                            continue
                        room = _CAPTURE_MAX - total
                        if room > 0:
                            take = chunk[:room]
                            bufs[fd].extend(take)
                            total += len(take)
                        if total >= _CAPTURE_MAX:
                            overflowed = True
                            break
            finally:
                proc.stdout.close()
                proc.stderr.close()
        except BaseException:
            # An interrupt (KeyboardInterrupt) or error mid-capture: stop the
            # daemon-side container AND reap the local client so NEITHER is left
            # orphaned, then propagate. teardown() is a backstop; this handles it at
            # the point of failure.
            self._force_remove(run_id)
            self._reap(proc)
            raise

        # The read loop ended. EOF on both pipes does NOT prove the container
        # exited — a target can close its stdout/stderr and keep running — so wait
        # for the CLIENT to actually exit within the remaining wall budget. If it
        # does not, the container is still alive past the deadline: treat it as a
        # timeout so it is force-removed rather than leaked past wall_timeout.
        if not (timed_out or overflowed):
            remaining = deadline - time.monotonic()
            if not self._wait_client(proc, remaining):
                timed_out = True

        # Force-remove by name on EVERY path — never trust --rm blindly. It is
        # idempotent: after a clean exit + --rm, ``rm -f`` reports "No such
        # container" (counted as gone); if --rm silently failed, this removes the
        # leak; if removal cannot be confirmed, container_gone is False and run()
        # keeps it queued for a teardown retry. (On a timeout/overflow the container
        # is still alive, so this is also the stop.)
        container_gone = self._force_remove(run_id)
        self._reap(proc)  # reap the local client, killing it if it will not exit
        stdout = bytes(bufs[fd_out]).decode("utf-8", "replace")
        stderr = bytes(bufs[fd_err]).decode("utf-8", "replace")
        return proc.returncode, stdout, stderr, timed_out, overflowed, container_gone

    # --- output paging (Store pointers, bounded) ---------------------------

    def _run_id(self, argv: list[str]) -> str:
        # A per-INVOCATION id: timestamp + argv digest + a random nonce. The nonce
        # makes it unique even for identical specs launched in the same second, so
        # concurrent runs never collide on the container --name (a docker exit 125)
        # or overwrite each other's paged output under the same detail dir.
        stamp = self._clock().strftime("%Y%m%d-%H%M%S")
        digest = hashlib.sha256("\x00".join(argv).encode("utf-8")).hexdigest()[:8]
        nonce = os.urandom(4).hex()
        return f"sandbox-{stamp}-{digest}-{nonce}"

    def _force_remove(self, name: str) -> bool:
        """Force-remove the named container. Returns True only when the container is
        CONFIRMED gone (removed, or already absent), False when removal could not be
        confirmed — so the caller keeps it queued for a teardown retry instead of
        assuming success and leaking a still-running container.
        """
        try:
            proc = subprocess.run(
                [self.runtime, "rm", "-f", name],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if proc.returncode == 0:
            return True
        # `rm -f` on a container that does not exist reports "No such container" — it
        # is not running, so that is also "gone". Any other non-zero (e.g. the daemon
        # is unreachable) is UNCONFIRMED: report failure so teardown retries.
        err = proc.stderr or b""
        text = err.decode("utf-8", "replace") if isinstance(err, bytes) else str(err)
        return "no such container" in text.lower()

    def _wait_client(self, proc: "subprocess.Popen", timeout: float) -> bool:
        """Wait up to ``timeout`` seconds for the client to exit. Returns True if it
        exited (the container is gone), False if it is still running — so a target
        that closes its output but keeps running is caught as a timeout, not treated
        as a clean exit."""
        try:
            proc.wait(timeout=max(0.0, timeout))
            return True
        except subprocess.TimeoutExpired:
            return False

    def _reap(self, proc: "subprocess.Popen") -> None:
        """Reap the local client process, KILLING it if it will not exit.

        The daemon-side container is stopped separately by name; this guarantees the
        ``docker run`` CLIENT is never left as an orphaned/zombie process — on the
        normal path, on timeout/overflow, and on an interrupt mid-capture.
        """
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def _verify_baked_input(self, spec: SandboxSpec) -> None:
        """Read the baked input at ``spec.input_path`` and refuse unless it is
        byte-identical to the stored ``repro_ref`` — binding the EXECUTED input to
        the provenance that authorized the run. The read runs in a hardened,
        network-denied, read-only, non-root container (no host mount), and any read
        failure or mismatch fails CLOSED."""
        stored = self.store.read_detail(spec.repro_ref)
        if stored is None:
            raise SandboxError(
                f"repro_ref {spec.repro_ref!r} does not resolve; refusing to run"
            )
        # The read mirrors the run's policy exactly (_hardening_flags: same user,
        # workdir, caps, limits) so it can neither pass nor fail under different
        # permissions than the harness, and reads a RELATIVE input_path against the
        # same workdir. Validate the image here too (not only in build_argv), so a
        # direct call is safe regardless of ordering; "--" ends option parsing so an
        # input_path beginning with '-' is a filename to cat, never a flag. The read
        # goes through the SAME bounded, NAMED, cleanup-guaranteed path as the real
        # run (_stream_capture): output is capped (_CAPTURE_MAX) and a hung/oversized
        # read is killed and force-removed by name.
        base = [
            self.runtime, "run",
            *self._hardening_flags(spec.policy, spec.workdir),
            "--entrypoint", "/bin/cat",
            _safe_image(spec.image), "--", spec.input_path,
        ]
        run_id = self._run_id(base)
        argv = [*base[:2], "--name", run_id, *base[2:]]
        self._active_container = run_id  # teardown backstop while the read is in flight
        rc, stdout, _stderr, timed_out, overflowed, gone = self._stream_capture(
            argv, run_id, _PREFLIGHT_READ_TIMEOUT
        )
        if gone:
            self._active_container = None
        if timed_out or overflowed:
            raise SandboxError(
                f"reading baked input {spec.input_path!r} exceeded the read limits; "
                f"refusing to verify"
            )
        if rc != 0:
            raise SandboxError(
                f"could not read baked input {spec.input_path!r} from the image "
                f"(exit {rc})"
            )
        if stdout != stored:
            raise SandboxError(
                f"baked input {spec.input_path!r} does not match the stored repro "
                f"{spec.repro_ref!r}; refusing to verify an unbound input"
            )
        if not gone:
            # The read matched, but the read container's removal is UNCONFIRMED. Fail
            # closed rather than return and let run() overwrite _active_container with
            # the real run id — that would lose the only teardown handle for the
            # leaked read container. Leaving it set here queues it for the teardown
            # retry (which raises if it still cannot confirm removal).
            raise SandboxError(
                f"could not confirm removal of the input-read container {run_id!r}; "
                f"refusing to continue (teardown will retry the cleanup)"
            )

    def _preflight_runtime(self) -> None:
        """Confirm the runtime DAEMON is reachable, not merely that the client binary
        exists. A down daemon makes ``run`` exit non-zero without the target ever
        executing; detecting it here raises ``IsolationUnavailable`` (fail closed) so
        an infrastructure failure never reads as a negative verification result."""
        try:
            probe = subprocess.run(
                [self.runtime, "version"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise IsolationUnavailable(
                f"{self.runtime} runtime probe failed: {exc}"
            ) from exc
        if probe.returncode != 0:
            raise IsolationUnavailable(
                f"{self.runtime} daemon is not reachable (probe exit "
                f"{probe.returncode}); refusing to run"
            )

    def teardown(self) -> None:
        """Context-manager cleanup (the ``with`` in VerifySession always runs it).

        A normal or timed-out run clears ``_active_container`` once removal is
        CONFIRMED, so this is a no-op then. Its job is the ABNORMAL exit — an
        interrupt/error between launch and cleanup, or a run whose ``rm -f`` could
        not be confirmed — where it (re)removes a container that would otherwise
        keep running past the ``with`` block.

        FAILS CLOSED: if removal STILL cannot be confirmed, raise rather than
        silently discard the sandbox — a leaked, still-running untrusted container
        must surface (and fail the session), never pass as a clean teardown.
        """
        leaked = self._active_container
        if leaked is None:
            return
        if self._force_remove(leaked):
            self._active_container = None
            return
        raise SandboxError(
            f"container {leaked!r} could not be confirmed removed; it may still be "
            f"running — manual cleanup required ({self.runtime} rm -f {leaked})"
        )

    def _page(self, run_id: str, name: str, content: Optional[str]) -> Optional[str]:
        """Page bounded raw output to the Store and return its ref, or None."""
        if self.store is None or not content:
            return None
        return self.store.write_detail(run_id, name, content[:_OUTPUT_MAX])


def _safe_image(image: str) -> str:
    """Return the stripped image ref, or raise on an injection-prone one. docker/
    podman parse options until the IMAGE positional, so a ref beginning with '-'
    (e.g. ``--privileged``) is consumed as another OPTION — argument injection that
    could enable a privileged run. Refuse it wherever an image is rendered into an
    argv, not only in build_argv."""
    ref = image.strip()
    if not ref or ref.startswith("-"):
        raise SandboxError(
            f"invalid image ref {image!r}: must be non-empty and must not start "
            f"with '-' (argument-injection guard)"
        )
    return ref


def _looks_like_runtime_error(text: str) -> bool:
    """Whether captured output carries a docker/OCI runtime-error signature — used
    to tell a genuine container-launch failure from a target that merely exited a
    125/126/127 status the daemon happens to reserve."""
    low = text.lower()
    return any(marker in low for marker in _RUNTIME_ERROR_MARKERS)


def _format_cpus(cpus: float) -> str:
    """Render a fractional CPU cap without a trailing ``.0`` for whole numbers."""
    if cpus == int(cpus):
        return str(int(cpus))
    return str(cpus)
