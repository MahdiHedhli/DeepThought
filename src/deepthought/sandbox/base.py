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
from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from ..schema.common import RecordId, iso_z, utcnow

# Length caps, mirroring the envelope discipline: a bounded string field cannot
# smuggle a large free-text payload past the typed boundary.
Ref = Annotated[str, StringConstraints(max_length=256)]
Short = Annotated[str, StringConstraints(max_length=128)]
PathStr = Annotated[str, StringConstraints(max_length=512)]


def _now_z() -> str:
    """Current time in the RFC3339 ``…Z`` form used across records."""
    return iso_z(utcnow())


class SandboxError(RuntimeError):
    """Base error for the sandbox module."""


class SignoffRequired(SandboxError):
    """Execution was attempted without a valid, in-window human sign-off scoped to
    the project (Constitution Article III). Also raised when a signed-off backend
    is not explicitly ``execution_enabled``."""


class IsolationUnavailable(SandboxError):
    """The backend cannot guarantee isolation on this host (e.g. the container
    runtime is absent). A run fails CLOSED — it never falls back to a weaker,
    unisolated execution."""


class SandboxExecutionDisabled(SandboxError):
    """The feature-003 HARD STOP.

    A real executing backend raises this rather than execute untrusted target
    code while execution is disabled (the only shipped state). Enabling
    execution requires Mahdi's explicit sandbox sign-off (Constitution III;
    phase-0-decisions.md §0.3).
    """


class Signoff(BaseModel):
    """A human sign-off authorizing target-code execution for ONE project — the
    Article III hard stop, enforced in code. An executing backend refuses to run
    without a sign-off whose ``project`` matches and whose window contains now.

    Timestamps are the RFC3339 ``…Z`` form, so a lexical string compare is a
    correct time compare.
    """

    model_config = ConfigDict(extra="forbid")

    approver: Short
    project: RecordId  # scoped to exactly one project id
    granted_at: str = Field(default_factory=_now_z)
    expires_at: str
    reason: Short = ""

    def valid_for(self, project: str, now: Optional[str] = None) -> bool:
        now = now or _now_z()
        return self.project == project and self.granted_at <= now < self.expires_at


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
    # The core isolation invariants are LOCKED to their hardened value with
    # ``Literal[True]``: they are security guarantees for running untrusted code,
    # not operator-tunable knobs. A config, finding, or future caller must not be
    # able to weaken them by omission or override (e.g. ``read_only_rootfs=False``);
    # relaxing any of them would be a distinct, explicit, signed-off change.
    read_only_rootfs: Literal[True] = True      # rendered ``--read-only``
    drop_all_caps: Literal[True] = True          # rendered ``--cap-drop=ALL``
    no_new_privileges: Literal[True] = True      # ``--security-opt=no-new-privileges``
    run_as_non_root: Literal[True] = True        # ``--user <uid>:<gid>``; never root/0
    # No host bind mounts, ever, in this slice (enforced off; no ``-v`` rendered).
    allow_host_mounts: Literal[False] = False

    # Positive, present resource + wall-time bounds. Conservative starters; their
    # presence is fixed and tested, the concrete numbers are tuned once execution
    # is enabled (spec Open questions). ``cpus`` forbids inf/nan — an infinite cap
    # both defeats the bound and crashes the argv renderer (int(inf) overflows).
    pids_limit: int = Field(default=128, gt=0)
    memory_mib: int = Field(default=512, gt=0)
    cpus: float = Field(default=1.0, gt=0, allow_inf_nan=False)
    wall_timeout_seconds: int = Field(default=30, gt=0)

    # Ephemeral: built fresh per run and torn down after (rendered ``--rm``).
    ephemeral: Literal[True] = True

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
    # At least one argv token: an empty command would run the image's default
    # entrypoint/cmd — not the minimized repro. A repro must be explicit.
    command: list[Short] = Field(min_length=1)
    repro_ref: Ref

    @field_validator("command")
    @classmethod
    def _executable_token_is_non_empty(cls, value: list[str]) -> list[str]:
        # command[0] becomes ``--entrypoint``. An EMPTY executable token would
        # render ``--entrypoint ""``, which docker treats as CLEARING the
        # entrypoint — falling back to the image's own ENTRYPOINT/CMD and breaking
        # the "exactly spec.command runs" invariant. Require a real executable.
        if not value or not value[0].strip():
            raise ValueError("command[0] (the executable) must be a non-empty token")
        return value
    workdir: PathStr = "/work"
    env: dict[Short, Short] = Field(default_factory=dict)
    policy: SandboxPolicy


class CrashReport(BaseModel):
    """A sanitizer crash, distilled to typed, BOUNDED fields — the firewall for
    untrusted sanitizer output. Raw ASan/UBSan text is target-controlled, so only
    these length-capped, structured fields cross into orchestrator state; the full
    report is paged to the Store and pointed at by ``raw_ref``.

    ``dedup_key`` is a stable hash of the top frames, so the same crash is
    recognized across runs.
    """

    model_config = ConfigDict(extra="forbid")

    sanitizer: Short = "AddressSanitizer"
    error_type: Short = ""              # heap-buffer-overflow, use-after-free, …
    access: Short = ""                  # READ or WRITE
    access_size: int | None = None
    faulting_function: Short = ""
    faulting_location: PathStr = ""     # file:line[:col]
    top_frames: list[Short] = Field(default_factory=list, max_length=16)
    dedup_key: Short = ""
    raw_ref: Ref | None = None          # pointer to the full report in the Store


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
    # The distilled sanitizer crash, when the run crashed. Structured + bounded —
    # a memory-safety reproduction IS a crash, so an executing backend sets
    # ``reproduced`` from its presence.
    crash: CrashReport | None = None


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
        try:
            self.setup()
        except BaseException:
            # setup() may have allocated resources before raising. Because the
            # context was never entered, __exit__ will NOT run — so tear down here
            # before propagating, or a partial VM/container could be left standing.
            self.teardown()
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Teardown always runs, so the environment is never left standing.
        self.teardown()
