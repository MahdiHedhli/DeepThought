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

from .base import (
    Sandbox,
    SandboxError,
    SandboxExecutionDisabled,
    SandboxPolicy,
    SandboxResult,
    SandboxSpec,
)

_ROOT_USERS = frozenset({"root", "0", "0:0"})


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

        if policy.read_only_rootfs:
            argv.append("--read-only")

        if policy.drop_all_caps:
            argv.append("--cap-drop=ALL")

        if policy.no_new_privileges:
            argv.append("--security-opt=no-new-privileges")

        # Non-root user, never root/0. Refuse to render a root run.
        if policy.run_as_non_root:
            user = policy.user
            if user in _ROOT_USERS or user.startswith("0:"):
                raise SandboxError(
                    f"run_as_non_root is set but user {user!r} is root; refusing"
                    " to render a privileged run configuration"
                )
            argv += ["--user", user]

        # Resource + wall-time bounds. Presence is fixed and tested.
        argv += ["--pids-limit", str(policy.pids_limit)]
        argv += ["--memory", f"{policy.memory_mib}m"]
        argv += ["--cpus", _format_cpus(policy.cpus)]
        # The wall-time bound is enforced by the runner (a --stop-timeout on the
        # ephemeral container, torn down after); it is not a host mount.
        argv += ["--stop-timeout", str(policy.wall_timeout_seconds)]

        argv += ["--workdir", spec.workdir]

        # NO host bind mounts are EVER rendered in this slice: host_mounts are
        # enforced off. The repro input reaches the sandbox as a controlled
        # artifact (spec.repro_ref), never a host-path bind.
        # (Deliberately: no -v / --volume / --mount is appended.)

        # Only spec.env — explicit and bounded. No host env leaks in. With an
        # empty env nothing is rendered.
        for key in sorted(spec.env):
            argv += ["--env", f"{key}={spec.env[key]}"]

        # The image, then the untrusted argv as separate tokens (never joined
        # into a shell string).
        argv.append(spec.image)
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
