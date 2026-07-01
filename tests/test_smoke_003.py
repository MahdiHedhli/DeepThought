"""The 003 VERIFY smoke, run programmatically and HERMETICALLY.

Mirrors ``test_smoke.py`` for feature 003: it drives the full VERIFY lifecycle —
NEW PROJECT -> seed a candidate -> a Noop dry-run leaves it a candidate -> a Noop
reproducing result promotes it to ``verified`` through the Store lifecycle guard
-> ``check`` stays green -> a verified finding whose evidence stops resolving is
caught by ``check``.

NOTHING executes untrusted target code: VERIFY reaches execution only through the
injected ``Sandbox`` seam, and the seam here is a ``NoopSandbox`` that records the
requested run and returns a canned result without running anything. No Docker
daemon, no network, no subprocess, and ``DockerSandbox.run()`` is never called.
"""

from __future__ import annotations

import subprocess

from deepthought.check import run_check
from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.sandbox import NoopSandbox, SandboxPolicy, SandboxResult, SandboxSpec
from deepthought.schema import CloseState, FindingStatus, GateOutcome
from deepthought.sessions import NewProjectSession, VerifySession
from deepthought.store import FileStore

from .conftest import make_finding

GATE = HermesUltraCodeGate()


def _spec() -> SandboxSpec:
    return SandboxSpec(
        image="deepthought/verify-dry-run:noop",
        command=["/repro/run"],
        repro_ref="detail/pending/repro.bin",
        policy=SandboxPolicy(),
    )


def _result(reproduced: bool) -> SandboxResult:
    return SandboxResult(
        exit_code=0, timed_out=False, wall_seconds=0.0, reproduced=reproduced
    )


def test_003_smoke(tmp_path, monkeypatch):
    # The hard stop, enforced for the whole test: any subprocess or a
    # DockerSandbox.run() would fail the run outright.
    from deepthought.sandbox import docker as docker_mod

    def _boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("003 executes nothing: no subprocess, no docker run")

    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(docker_mod.DockerSandbox, "run", _boom)

    state = tmp_path / "state"
    store = FileStore(state)
    target = tmp_path / "php-src"
    target.mkdir()

    # 1. NEW PROJECT with a basis and scope -> a Project file exists.
    new_project = run_session(
        store,
        GATE,
        NewProjectSession(
            name="PHP src",
            source_type="open_source",
            local_path=str(target),
            project_id="php-src",
            authorization_basis="permissive_oss",
            scope_allowlist=["ext/soap"],
        ),
    )
    assert new_project.gate_outcome is GateOutcome.proceed
    assert new_project.close_state is CloseState.clean

    # 2. Seed a candidate finding (what DISCOVER would produce).
    store.save_finding(
        make_finding(id="F-0001", project="php-src", status="candidate", evidence_ref=None)
    )

    # 3. A Noop DRY-RUN (non-reproducing) leaves the candidate a candidate.
    dry = run_session(
        store, GATE,
        VerifySession("php-src", "F-0001", spec=_spec(), sandbox=NoopSandbox(_result(False))),
    )
    assert dry.close_state is CloseState.clean
    assert store.get_finding("F-0001").status is FindingStatus.candidate
    assert not store.get_finding("F-0001").evidence_ref

    # 4. A Noop REPRODUCING result promotes candidate -> verified THROUGH the guard.
    verified = run_session(
        store, GATE,
        VerifySession("php-src", "F-0001", spec=_spec(), sandbox=NoopSandbox(_result(True))),
    )
    assert verified.close_state is CloseState.clean
    finding = store.get_finding("F-0001")
    assert finding.status is FindingStatus.verified
    assert finding.evidence_ref
    assert store.detail_exists(finding.evidence_ref)

    # 5. check is green on the produced state...
    assert run_check(store).ok

    # ...and RED if the verified finding's evidence stops resolving (lifecycle-at-
    # rest guard holds for VERIFY output, unchanged from 001).
    finding.evidence_ref = "detail/does-not/exist.txt"
    store.save_finding(finding)
    assert not run_check(store).ok
