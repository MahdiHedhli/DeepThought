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
from datetime import timedelta
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
# (126), or an entrypoint not found (127). The target never ran, so these are
# ISOLATION failures, never a negative verification result.
_RUNTIME_ERROR_EXITS = frozenset({125, 126, 127})


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
        argv: list[str] = [self.runtime, "run"]

        if policy.ephemeral:
            argv.append("--rm")  # ephemeral: built fresh, torn down after

        # Default-deny egress. The only network value in this slice is "none".
        argv.append(f"--network={policy.network}")

        # Never pull from a registry. A missing image would otherwise trigger a
        # host-side registry fetch (network egress) BEFORE --network=none takes
        # effect, breaking default-deny / no-transmission. The image must be
        # preloaded; a real signed-off backend fails closed if it is absent.
        argv.append("--pull=never")

        if policy.read_only_rootfs:
            argv.append("--read-only")

        if policy.drop_all_caps:
            argv.append("--cap-drop=ALL")

        if policy.no_new_privileges:
            argv.append("--security-opt=no-new-privileges")

        # Non-root user. Require a STRICTLY NUMERIC, non-zero UID — never a name.
        # A named user ("root", "toor", "nobody", ...) can alias to UID 0 in the
        # image's /etc/passwd, which we cannot inspect at argv-build time, so any
        # non-numeric uid is refused. int() == 0 additionally rejects every numeric
        # zero spelling ("0", "00", "000"); the regex rejects "+0"/"-0"/""/":gid".
        # A gid, if present, must also be numeric.
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
            # Render the NORMALIZED (stripped) numeric value — NOT the raw string.
            # Validating the stripped parts but rendering the raw " 1000 : 2000 "
            # would let docker fail numeric parsing and fall back to a passwd lookup.
            argv += ["--user", f"{uid}:{gid}" if sep else uid]

        # Resource bounds. Presence is fixed and tested.
        argv += ["--pids-limit", str(policy.pids_limit)]
        argv += ["--memory", f"{policy.memory_mib}m"]
        argv += ["--cpus", _format_cpus(policy.cpus)]
        # --stop-timeout is a short, FIXED teardown grace (SIGKILL delay after a
        # stop signal) — NOT policy.wall_timeout_seconds, which would block the
        # runner for minutes when killing a hung container. The wall-clock
        # EXECUTION limit (wall_timeout_seconds) is enforced externally by the
        # runner when a real backend is wired (a distinct, signed-off change); it
        # is not a docker run flag.
        argv += ["--stop-timeout", str(_STOP_GRACE_SECONDS)]

        argv += ["--workdir", spec.workdir]

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

        # The image, then the untrusted argv as separate tokens (never joined
        # into a shell string). Validate the image token first: docker parses
        # options until the IMAGE positional, so a ref beginning with '-' (e.g.
        # "--privileged") would be consumed as another OPTION — argument injection
        # that could enable a privileged run. Strip and refuse it; never render it.
        image = spec.image.strip()
        if not image or image.startswith("-"):
            raise SandboxError(
                f"invalid image ref {spec.image!r}: must be non-empty and must not"
                " start with '-' (argument-injection guard)"
            )
        argv.append(image)
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
        # Provenance: the repro input is delivered to the container BY THE IMAGE
        # (baked in at the path in spec.command) — the hardening forbids host bind
        # mounts, so no host file crosses the boundary. spec.repro_ref is the Store
        # pointer to that same input; require it to RESOLVE so a run is always tied
        # to a real, stored repro artifact and never to a dangling reference.
        if (
            self.store is not None
            and spec.repro_ref
            and not self.store.detail_exists(spec.repro_ref)
        ):
            raise SandboxError(
                f"repro_ref {spec.repro_ref!r} does not resolve in the store; "
                f"refusing to run a repro with no provenance"
            )

        base_argv = self.build_argv(spec, spec.policy)  # the hardened, isolation-tested argv
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
        started = self._clock()
        returncode, stdout, stderr, timed_out, overflowed = self._stream_capture(
            argv, run_id, spec.policy.wall_timeout_seconds
        )
        # The container has been reaped (and, on any abnormal exit, force-removed by
        # name inside _stream_capture); nothing is left to tear down.
        self._active_container = None
        wall = (self._clock() - started).total_seconds()

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
        if returncode in _RUNTIME_ERROR_EXITS:
            # The container could not be started/exec'd — an isolation failure, not
            # a target run. Never let it read as "did not reproduce".
            raise IsolationUnavailable(
                f"{self.runtime} could not run the container (exit {returncode}); "
                f"the target did not execute"
            )

        combined = f"{stdout}\n{stderr}"
        # A crash is credited ONLY on a deadly-signal termination — docker reports a
        # container killed by signal N as exit 128+N. Under ASAN_OPTIONS=abort_on_
        # error=1 a real sanitizer error aborts the process (a signal death), so a
        # genuine crash lands at >=128. Target-PRINTED ASan text with a normal exit
        # (0, or a plain exit(1)) is spoofable and must NEVER become evidence: a
        # spoof would have to actually raise a crash signal, i.e. genuinely abort.
        crash = parse_asan(combined) if returncode >= 128 else None
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
    ) -> tuple[Optional[int], str, str, bool, bool]:
        """Launch the container and read stdout/stderr under a hard byte cap and a
        wall deadline, killing the container if either is exceeded.

        Returns ``(returncode, stdout, stderr, timed_out, overflowed)``. Bounds BOTH
        memory (buffers never exceed ``_CAPTURE_MAX``) and disk (nothing is spooled
        to a file): a flooding target is stopped AT the cap, not at the timeout, and
        a hung one is stopped at the deadline. ``stdin`` is closed to the target.
        Undecodable bytes are replaced, never raised.
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
        deadline = self._clock() + timedelta(seconds=wall_timeout)
        try:
            try:
                while open_fds and not overflowed:
                    remaining = (deadline - self._clock()).total_seconds()
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

        if timed_out or overflowed:
            # subprocess-level kill reaches only the local client; stop the
            # daemon-side container by name so it cannot keep running.
            self._force_remove(run_id)
        self._reap(proc)  # always reap the local client, killing it if it will not exit
        stdout = bytes(bufs[fd_out]).decode("utf-8", "replace")
        stderr = bytes(bufs[fd_err]).decode("utf-8", "replace")
        return proc.returncode, stdout, stderr, timed_out, overflowed

    # --- output paging (Store pointers, bounded) ---------------------------

    def _run_id(self, argv: list[str]) -> str:
        stamp = self._clock().strftime("%Y%m%d-%H%M%S")
        digest = hashlib.sha256("\x00".join(argv).encode("utf-8")).hexdigest()[:8]
        return f"sandbox-{stamp}-{digest}"

    def _force_remove(self, name: str) -> None:
        """Best-effort stop+remove of the named container (timeout cleanup).

        Never masks the original timeout: a runtime that is gone or a name that no
        longer exists is swallowed — the caller has already decided the run timed
        out.
        """
        try:
            subprocess.run(
                [self.runtime, "rm", "-f", name],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass

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

        A normal or timed-out run clears ``_active_container`` once the container is
        gone, so this is a no-op then. Its job is the ABNORMAL exit — an interrupt
        or error between launch and cleanup — where it force-removes a container
        that would otherwise keep running untrusted code past the ``with`` block.
        """
        if self._active_container is not None:
            self._force_remove(self._active_container)
            self._active_container = None

    def _page(self, run_id: str, name: str, content: Optional[str]) -> Optional[str]:
        """Page bounded raw output to the Store and return its ref, or None."""
        if self.store is None or not content:
            return None
        return self.store.write_detail(run_id, name, content[:_OUTPUT_MAX])


def _format_cpus(cpus: float) -> str:
    """Render a fractional CPU cap without a trailing ``.0`` for whole numbers."""
    if cpus == int(cpus):
        return str(int(cpus))
    return str(cpus)
