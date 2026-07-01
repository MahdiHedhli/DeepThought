"""``DockerSandbox`` — the hardened container backend, **config only** in 003.

Two surfaces:

- ``build_command(spec)`` is a **pure function** that renders the hardened
  ``docker run`` argv a real run *would* use, as a ``list[str]`` for
  **inspection**. It executes nothing. The isolation tests assert every hardening
  clause over this argv, with no Docker daemon and no network.

- ``run(spec)`` is the **HARD STOP**. It is the one method that would shell out to
  execute untrusted code. It is guarded by a default-OFF ``execution_enabled``
  flag; with the flag off — the only state that ships — it raises ``SandboxError``
  and executes nothing. No test, smoke, or CLI path enables the flag or calls
  ``run()``. Enabling it, and adding a real backend run (an ephemeral microVM per
  Phase 0 §0.3, or this container fallback), is a distinct, later change behind
  **Mahdi's sign-off** (Constitution Article III).

``subprocess`` is never called with untrusted input anywhere in this slice: the
``build_command`` output is data for inspection, not a command that is run.
"""

from __future__ import annotations

import re

from .base import (
    Sandbox,
    SandboxError,
    SandboxExecutionDisabled,
    SandboxPolicy,
    SandboxResult,
    SandboxSpec,
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


class DockerSandbox(Sandbox):
    """Builds a fully-hardened ``docker run`` argv. Execution is guarded OFF."""

    def __init__(self, *, execution_enabled: bool = False) -> None:
        # Default OFF. This is the hard stop. Do NOT enable it in this slice.
        self.execution_enabled = execution_enabled

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
            uid, _, gid = user.partition(":")
            uid = uid.strip()
            if not _NUMERIC_RE.fullmatch(uid) or int(uid) == 0:
                raise SandboxError(
                    f"run_as_non_root requires a numeric non-zero UID; user "
                    f"{user!r} is refused (a named or zero UID can run as root)"
                )
            if gid and not _NUMERIC_RE.fullmatch(gid.strip()):
                raise SandboxError(
                    f"run_as_non_root requires a numeric gid; user {user!r} has a"
                    " non-numeric gid"
                )
            argv += ["--user", user]

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
        argv += list(spec.command)
        return argv

    # --- the HARD STOP -----------------------------------------------------

    def run(self, spec: SandboxSpec) -> SandboxResult:
        """HARD STOP. Guarded by ``execution_enabled`` (default False).

        With the flag off — the only shipped state — this raises
        ``SandboxExecutionDisabled`` and executes nothing. It never reaches a
        ``subprocess`` call. Enabling it and adding a real backend run requires
        Mahdi's sign-off.
        """
        if not self.execution_enabled:
            raise SandboxExecutionDisabled(
                "execution requires sign-off — 003 hard stop"
            )
        # Unreachable in this slice: execution_enabled is never turned on. A real
        # backend run lands in a distinct, later, Mahdi-signed-off change.
        raise SandboxExecutionDisabled(  # pragma: no cover
            "no execution backend is wired in 003; enabling execution is a"
            " separate, signed-off change"
        )


def _format_cpus(cpus: float) -> str:
    """Render a fractional CPU cap without a trailing ``.0`` for whole numbers."""
    if cpus == int(cpus):
        return str(int(cpus))
    return str(cpus)
