"""The sandbox interface and its firewall types.

Running untrusted target code is the highest-risk act in the platform, so it
happens only behind this one interface, under a hardened, default-deny policy,
and — for a real executing backend — only after Mahdi's sign-off (Constitution
Article III; Phase 0 §0.3).

This module defines four things and executes nothing:

- ``SandboxPolicy`` — the hardened, **default-deny** run configuration. A
  default-constructed policy is fully locked down; an operator opts into *less*
  isolation explicitly, never into *more* by omission.
- ``SandboxSpec`` — the typed request: what to run (an argv ``command``, never a
  shell string), the repro input as a Store pointer, and the policy it runs
  under. Data only.
- ``SandboxResult`` — the typed outcome and the **only** thing the orchestrator
  reads back from a run. Raw target output is paged to the Store; this carries
  ``stdout_ref``/``stderr_ref`` pointers, never inlined content. It mirrors the
  worker ``Envelope`` firewall.
- ``Sandbox`` — the one-method ABC (``run(spec) -> SandboxResult``) mirroring the
  ``Store``/``Gate`` seams, plus a context-manager lifecycle that guarantees an
  ephemeral, torn-down environment. The backing technology (Phase 0 §0.3: an
  ephemeral microVM primary, a hardened container fallback) is a single-adapter
  swap.

``SandboxError`` is the module's error type.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

# Length caps, mirroring the envelope discipline: a bounded string field cannot
# smuggle a large free-text payload past the typed boundary.
Ref = Annotated[str, StringConstraints(max_length=256)]
Short = Annotated[str, StringConstraints(max_length=128)]
PathStr = Annotated[str, StringConstraints(max_length=512)]


class SandboxError(RuntimeError):
    """Base error for the sandbox module."""


class SandboxExecutionDisabled(SandboxError):
    """The feature-003 HARD STOP.

    A real executing backend raises this rather than execute untrusted target
    code while execution is disabled (the only shipped state). Enabling
    execution requires Mahdi's explicit sandbox sign-off (Constitution III;
    phase-0-decisions.md §0.3).
    """


class SandboxPolicy(BaseModel):
    """The hardened, default-deny run configuration.

    Every default here is the safe one. The isolation contract is proven by
    inspecting how ``DockerSandbox.build_command`` renders this policy — not by
    running a container. A test asserts these defaults are locked down.
    """

    model_config = ConfigDict(extra="forbid")

    # Egress is default-DENY. No allowlist in this slice; the only value is
    # ``"none"`` (rendered as ``--network=none``).
    network: Literal["none"] = "none"
    # Read-only root filesystem (rendered ``--read-only``).
    read_only_rootfs: bool = True
    # No host bind mounts, ever, in this slice (enforced off; no ``-v`` rendered).
    allow_host_mounts: bool = False
    # Drop every Linux capability (rendered ``--cap-drop=ALL``).
    drop_all_caps: bool = True
    # Forbid privilege escalation (rendered ``--security-opt=no-new-privileges``).
    no_new_privileges: bool = True
    # Run as a non-root user (rendered ``--user <uid>:<gid>``; never root/0).
    run_as_non_root: bool = True

    # Positive, present resource + wall-time bounds. Conservative starters; their
    # presence is fixed and tested, the concrete numbers are tuned once execution
    # is enabled (spec Open questions).
    pids_limit: int = Field(default=128, gt=0)
    memory_mib: int = Field(default=512, gt=0)
    cpus: float = Field(default=1.0, gt=0)
    wall_timeout_seconds: int = Field(default=30, gt=0)

    # Ephemeral: built fresh per run and torn down after (rendered ``--rm``).
    ephemeral: bool = True

    # The non-root uid:gid rendered into ``--user``. Never root/0.
    user: Short = "65534:65534"


class SandboxSpec(BaseModel):
    """What to run: the minimized repro plus the policy it runs under. Data only.

    ``command`` is an argv ``list[str]``, never a shell string — there is no
    ``shell=True`` semantics anywhere in the sandbox. ``repro_ref`` is a Store
    pointer, not inlined content. ``policy`` is required: there is no unpoliced
    run.
    """

    model_config = ConfigDict(extra="forbid")

    image: Ref
    command: list[Short]
    repro_ref: Ref
    workdir: PathStr = "/work"
    env: dict[Short, Short] = Field(default_factory=dict)
    policy: SandboxPolicy


class SandboxResult(BaseModel):
    """The typed outcome — and the ONLY thing the orchestrator reads back.

    Mirrors the worker ``Envelope`` firewall: raw target stdout/stderr is paged
    to the Store and referenced by pointer here; the orchestrator never loads
    that content into its context. ``reproduced`` is the verdict the caller sets
    and the evidence gate for promotion.
    """

    model_config = ConfigDict(extra="forbid")

    exit_code: int
    timed_out: bool
    wall_seconds: float = Field(ge=0.0)
    # Pointers to paged output in the Store, NOT inlined content.
    stdout_ref: Ref | None = None
    stderr_ref: Ref | None = None
    # The caller's verdict: did the minimized repro reproduce the vulnerable
    # behavior? The lifecycle guard promotes a candidate only on resolving
    # evidence; this is what a VERIFY session keys promotion off.
    reproduced: bool = False


class Sandbox(ABC):
    """The isolated, egress-controlled execution boundary.

    One method, ``run(spec) -> SandboxResult``, mirroring the ``Store``/``Gate``
    seams so the backing technology is a single-adapter swap. The context-manager
    lifecycle (``setup``/``teardown``) guarantees an ephemeral environment that is
    always torn down, even on error.
    """

    @abstractmethod
    def run(self, spec: SandboxSpec) -> SandboxResult:
        """Run the repro under ``spec.policy`` and return a typed result.

        Implementations must NOT return raw target output inline — they page it
        to the Store and return ``stdout_ref``/``stderr_ref`` pointers.
        """

    # --- ephemeral lifecycle ------------------------------------------------

    def setup(self) -> None:
        """Build the ephemeral environment. Default: nothing to build."""

    def teardown(self) -> None:
        """Tear the ephemeral environment down. Default: nothing to tear down."""

    def __enter__(self) -> "Sandbox":
        self.setup()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Teardown always runs, so the environment is never left standing.
        self.teardown()
