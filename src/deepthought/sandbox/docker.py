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
import shutil
import subprocess
import tempfile
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

    # --- pure config builder (inspection only) -----------------------------

    def build_command(self, spec: SandboxSpec) -> list[str]:
        """Render the hardened ``docker run`` argv for ``spec`` and its policy.

        Pure: same input, same output, no side effects, no execution. Returns a
        ``list[str]`` of argv tokens for inspection — never a shell string.
        """
        return self.build_argv(spec, spec.policy)

    def build_argv(self, spec: SandboxSpec, policy: SandboxPolicy) -> list[str]:
        """The argv mapping (contract name). ``build_command`` delegates here."""
        argv: list[str] = ["docker", "run"]

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

        base_argv = self.build_argv(spec, spec.policy)  # the hardened, isolation-tested argv
        run_id = self._run_id(base_argv)
        # Name the container deterministically so a timed-out / hung container can
        # be force-removed. subprocess's timeout only SIGKILLs the local docker
        # CLIENT; the daemon-side container keeps running unless we stop it by name
        # (--stop-timeout is a teardown grace, not a wall-clock kill). Inserted in
        # run() — not build_argv — so the isolation-tested argv stays pure, and so
        # run_id (a digest of that argv) is stable.
        argv = [*base_argv[:2], "--name", run_id, *base_argv[2:]]
        started = self._clock()
        # Capture to on-disk files, NEVER an in-RAM PIPE: an adversarial target
        # that floods stdout cannot exhaust controller memory, because we read back
        # only a bounded prefix (_read_capped reads at most _OUTPUT_MAX bytes). The
        # files also hold the PARTIAL output on a timeout, so we don't depend on
        # TimeoutExpired.stdout (which is bytes even under text=True — a decode
        # hazard). stdin is closed so the target cannot read the host's stdin.
        with tempfile.TemporaryDirectory(prefix="dt-sandbox-") as td:
            out_path = os.path.join(td, "stdout")
            err_path = os.path.join(td, "stderr")
            try:
                with open(out_path, "wb") as fo, open(err_path, "wb") as fe:
                    proc = subprocess.run(
                        argv,
                        stdin=subprocess.DEVNULL,
                        stdout=fo,
                        stderr=fe,
                        timeout=spec.policy.wall_timeout_seconds,
                        check=False,
                    )
            except subprocess.TimeoutExpired:
                # Stop the daemon-side container before returning; leaving it
                # running would keep executing untrusted code past the wall limit.
                self._force_remove(run_id)
                wall = (self._clock() - started).total_seconds()
                return SandboxResult(
                    exit_code=-1,
                    timed_out=True,
                    wall_seconds=wall,
                    stdout_ref=self._page(run_id, "stdout.txt", _read_capped(out_path)),
                    stderr_ref=self._page(run_id, "stderr.txt", _read_capped(err_path)),
                    reproduced=False,
                )
            wall = (self._clock() - started).total_seconds()
            stdout = _read_capped(out_path)
            stderr = _read_capped(err_path)

        combined = f"{stdout}\n{stderr}"
        crash = parse_asan(combined)
        if crash is not None:
            # Page the full raw sanitizer report; the typed CrashReport carries
            # only bounded fields into orchestrator state.
            crash.raw_ref = self._page(run_id, "asan-report.txt", combined)
        return SandboxResult(
            exit_code=proc.returncode,
            timed_out=False,
            wall_seconds=wall,
            stdout_ref=self._page(run_id, "stdout.txt", stdout),
            stderr_ref=self._page(run_id, "stderr.txt", stderr),
            # A sanitizer crash IS the reproduction of a memory-safety bug.
            reproduced=crash is not None,
            crash=crash,
        )

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

    def _page(self, run_id: str, name: str, content: Optional[str]) -> Optional[str]:
        """Page bounded raw output to the Store and return its ref, or None."""
        if self.store is None or not content:
            return None
        return self.store.write_detail(run_id, name, content[:_OUTPUT_MAX])


def _read_capped(path: str) -> str:
    """Read at most ``_OUTPUT_MAX`` bytes from a file and decode leniently.

    ``f.read(_OUTPUT_MAX)`` bounds the READ itself — a flooded output file is never
    loaded wholesale into memory, only its bounded prefix. Undecodable bytes from
    untrusted target output are replaced, never raised.
    """
    try:
        with open(path, "rb") as f:
            return f.read(_OUTPUT_MAX).decode("utf-8", "replace")
    except OSError:
        return ""


def _format_cpus(cpus: float) -> str:
    """Render a fractional CPU cap without a trailing ``.0`` for whole numbers."""
    if cpus == int(cpus):
        return str(int(cpus))
    return str(cpus)
