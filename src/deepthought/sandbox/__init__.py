"""The execution sandbox — VERIFY's isolated, egress-controlled boundary.

Running untrusted target code is the highest-risk act in the platform, so it
happens only behind the ``Sandbox`` interface, under a hardened, default-deny
``SandboxPolicy``. This slice (003) delivers the sandbox as a typed, tested
interface: isolation is proven by *inspecting* the hardened run configuration
(``DockerSandbox.build_command``), not by running containers. ``NoopSandbox`` lets
VERIFY be exercised with no execution. The real executing backend's ``run()`` is
the hard stop — guarded off by default (Constitution Article III; Phase 0 §0.3).
"""

from .base import (
    Sandbox,
    SandboxError,
    SandboxExecutionDisabled,
    SandboxPolicy,
    SandboxResult,
    SandboxSpec,
)
from .docker import DockerSandbox
from .noop import NoopSandbox

__all__ = [
    "Sandbox",
    "SandboxError",
    "SandboxExecutionDisabled",
    "SandboxPolicy",
    "SandboxSpec",
    "SandboxResult",
    "NoopSandbox",
    "DockerSandbox",
]
