"""The 004 SIBLING HUNT smoke, run programmatically and HERMETICALLY.

Mirrors ``test_smoke_003.py`` for feature 004. It drives the read-only variant
loop end to end:

  NEW PROJECT (source) + NEW PROJECT (authorized sibling) + NEW PROJECT (a third
  sibling with NO basis) -> DISCOVER a candidate on the source over the bundled
  SARIF -> VERIFY it to ``verified`` (Noop-backed reproducing) -> SIBLING HUNT
  from the verified finding (derives the signature, writes same-class variant
  candidates in the source AND the authorized sibling, REFUSED at the gate for
  the unauthorized sibling, SKIPS an unregistered named sibling) -> ``check``
  green -> corrupt a variant -> ``check`` fails.

NOTHING executes untrusted target code. SIBLING HUNT is read-only: no subprocess,
no Docker, no ``DockerSandbox.run()``, nothing transmitted. It also NEVER calls
``save_project`` during the hunt and NEVER widens a scope or sets a basis.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from deepthought.check import run_check
from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.sandbox import NoopSandbox, SandboxPolicy, SandboxResult, SandboxSpec
from deepthought.schema import CloseState, FindingStatus, GateOutcome
from deepthought.sessions import (
    DiscoverSession,
    NewProjectSession,
    SiblingHuntSession,
    VerifySession,
)
from deepthought.store import FileStore

GATE = HermesUltraCodeGate()
SIBLINGS = str(Path(__file__).parent / "fixtures" / "siblings.sarif")
SAMPLE = str(Path(__file__).parent / "fixtures" / "sample.sarif")


def _spec() -> SandboxSpec:
    return SandboxSpec(
        image="deepthought/verify-dry-run:noop",
        command=["/repro/run"],
        repro_ref="detail/pending/repro.bin",
        policy=SandboxPolicy(),
    )


def test_004_smoke(tmp_path, monkeypatch):
    # The read-only hard stop, enforced for the whole test: any subprocess or a
    # DockerSandbox.run() fails the run outright.
    from deepthought.sandbox import docker as docker_mod

    def _boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("004 executes nothing: no subprocess, no docker run")

    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(docker_mod.DockerSandbox, "run", _boom)

    state = tmp_path / "state"
    store = FileStore(state)

    # 1. NEW PROJECT: source, authorized sibling, and an unauthorized (no basis)
    #    sibling. All scoped to app/ (where the SARIF fixtures locate results).
    src = tmp_path / "src-proj"
    src.mkdir()
    sib = tmp_path / "sib-proj"
    sib.mkdir()
    for pid, path, basis in [
        ("src-proj", src, "permissive_oss"),
        ("sib-proj", sib, "permissive_oss"),
    ]:
        rec = run_session(
            store, GATE,
            NewProjectSession(
                name=pid, source_type="open_source", local_path=str(path),
                project_id=pid, authorization_basis=basis, scope_allowlist=["app"],
            ),
        )
        assert rec.gate_outcome is GateOutcome.proceed

    # The unauthorized sibling: registered but with NO authorization basis. NEW
    # PROJECT itself refuses at the gate, but the project record is written so the
    # hunt later re-gates it and REFUSES it. Save it directly (no basis).
    from .conftest import make_project

    store.save_project(
        make_project(
            id="noauth-proj", name="No auth", git_url="https://example.test/noauth",
            authorization_basis=None, scope_allowlist=["app"],
        )
    )

    projects_after_setup = {p.id for p in store.list_projects()}
    assert projects_after_setup == {"src-proj", "sib-proj", "noauth-proj"}

    # 2. DISCOVER on the source over the sample SARIF -> candidate findings.
    run_session(store, GATE, DiscoverSession("src-proj", sarif_path=SAMPLE))
    cands = [f for f in store.list_findings(project="src-proj")
             if f.status is FindingStatus.candidate]
    # Pick the SQL-injection candidate so its verified signature is inject:sql.
    sql_cand = next(f for f in cands if "sql" in f.summary.lower())

    # 3. VERIFY it to verified (Noop-backed reproducing result promotes it).
    verified = run_session(
        store, GATE,
        VerifySession(
            "src-proj", sql_cand.id, spec=_spec(),
            sandbox=NoopSandbox(
                SandboxResult(exit_code=0, timed_out=False, wall_seconds=0.0, reproduced=True)
            ),
        ),
    )
    assert verified.close_state is CloseState.clean
    assert store.get_finding(sql_cand.id).status is FindingStatus.verified

    # --- authority spy: save_project must NEVER be called during the hunt ---
    calls = {"save_project": 0}
    real_save = store.save_project

    def spy_save(project):
        calls["save_project"] += 1
        return real_save(project)

    monkeypatch.setattr(store, "save_project", spy_save)
    scopes_before = {
        p.id: (tuple(p.scope_allowlist), p.authorization_basis)
        for p in store.list_projects()
    }

    # 4. SIBLING HUNT from the verified finding: source + authorized sibling +
    #    unauthorized sibling + an unregistered named sibling.
    session = SiblingHuntSession(
        project_id="src-proj",
        finding_id=sql_cand.id,
        sibling_project_ids=["sib-proj", "noauth-proj", "ghost-proj"],
        sarif_path=SIBLINGS,
    )
    hunt = run_session(store, GATE, session)
    assert hunt.close_state is CloseState.clean
    assert session.signature is not None
    assert session.signature.capability == "inject:sql"

    # Variants in the source AND the authorized sibling; NONE for the unauthorized
    # sibling; the unregistered sibling was never created.
    src_variants = [f for f in store.list_findings(project="src-proj")
                    if f.status is FindingStatus.candidate and f.id != sql_cand.id]
    sib_variants = [f for f in store.list_findings(project="sib-proj")
                    if f.status is FindingStatus.candidate]
    assert src_variants, "expected same-class variants in the source"
    assert sib_variants, "expected same-class variants in the authorized sibling"
    assert store.list_findings(project="noauth-proj") == []
    assert store.get_project("ghost-proj") is None

    noauth = next(t for t in session.target_outcomes if t.project_id == "noauth-proj")
    assert noauth.gate_outcome == "refuse" and not noauth.proceeded
    ghost = next(t for t in session.target_outcomes if t.project_id == "ghost-proj")
    assert ghost.gate_outcome == "skipped" and not ghost.proceeded

    # --- authority invariants: no project created, no scope/basis mutated ---
    assert calls["save_project"] == 0
    scopes_after = {
        p.id: (tuple(p.scope_allowlist), p.authorization_basis)
        for p in store.list_projects()
    }
    assert scopes_after == scopes_before
    assert {p.id for p in store.list_projects()} == projects_after_setup

    # 5. check is green on the produced state.
    assert run_check(store).ok

    # 6. corrupt a variant -> check fails (the gate holds over hunt output).
    bad = src_variants[0]
    bad.status = FindingStatus.verified
    bad.evidence_ref = None
    store.save_finding(bad)
    assert not run_check(store).ok
