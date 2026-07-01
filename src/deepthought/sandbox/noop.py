"""``NoopSandbox`` — the test double VERIFY uses in this slice.

It **records** the ``SandboxSpec`` it was handed (so a test can assert VERIFY
built a hardened, in-scope spec) and returns a caller-supplied canned
``SandboxResult``. It **executes nothing** — no container, no subprocess, no
daemon. This is what makes the VERIFY session tests hermetic: they pass with no
Docker daemon and no network.
"""

from __future__ import annotations

from .base import Sandbox, SandboxResult, SandboxSpec


class NoopSandbox(Sandbox):
    """Records the requested run and returns a canned result. Runs nothing."""

    def __init__(self, result: SandboxResult) -> None:
        self._result = result
        # The specs it was handed, in order — for test inspection.
        self.recorded: list[SandboxSpec] = []

    def run(self, spec: SandboxSpec) -> SandboxResult:
        self.recorded.append(spec)  # RECORD the requested run
        return self._result         # return the CANNED result; execute nothing
