"""The execution sandbox — VERIFY's isolated, egress-controlled boundary.

Running untrusted target code is the highest-risk act in the platform, so it
happens only behind the ``Sandbox`` interface, under a hardened, default-deny
``SandboxPolicy``. This slice (003) delivers the sandbox as a typed, tested
interface: isolation is proven by *inspecting* the hardened run configuration
(``DockerSandbox.build_command``), not by running containers. ``NoopSandbox`` lets
VERIFY be exercised with no execution. The real executing backend's ``run()`` is
the hard stop — guarded off by default (Constitution Article III; Phase 0 §0.3).
"""

from .asan import parse_asan
from .base import (
    CrashReport,
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
from .noop import NoopSandbox

__all__ = [
    "Sandbox",
    "SandboxError",
    "SandboxExecutionDisabled",
    "SignoffRequired",
    "IsolationUnavailable",
    "SandboxPolicy",
    "SandboxSpec",
    "SandboxResult",
    "Signoff",
    "CrashReport",
    "parse_asan",
    "NoopSandbox",
    "DockerSandbox",
]


def __getattr__(name: str):
    # ``DockerSandbox`` is the executing backend. It stays exported for the callers
    # that explicitly need it (the signed-off Tier-2 harness), but it is imported
    # LAZILY (PEP 562): merely importing this package — e.g. via the CLI, which only
    # needs ``NoopSandbox`` — must never pull the executing backend into the process
    # import closure. This keeps the CLI's "no executing backend imported" invariant
    # real, not just true of its source (Constitution Article III; codex review #37).
    if name == "DockerSandbox":
        from .docker import DockerSandbox

        return DockerSandbox
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
