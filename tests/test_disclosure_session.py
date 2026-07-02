"""005 — the DISCLOSURE session (draft-only).

Hermetic: no network, no lifecycle change, nothing transmitted. DISCLOSURE reads
a VERIFIED finding and drafts four LOCAL artifacts (advisory, CSAF, OpenVEX, CVE
draft) as Store detail. It never advances the finding to ``disclosed``, never
sets ``cve``, never adds an ``advisory`` reference, and never touches
``finding.disclosure`` — the finding is left exactly as it was.
"""

from __future__ import annotations

import json

from deepthought.export.csaf import validate_csaf
from deepthought.export.cve import validate_cve_draft
from deepthought.export.openvex import validate_openvex
from deepthought.protocol import HermesUltraCodeGate, run_session
from deepthought.schema import CloseState, FindingStatus, Reference
from deepthought.sessions import DisclosureSession
from deepthought.store import FileStore

from .conftest import make_finding, make_project

GATE = HermesUltraCodeGate()

_ARTIFACTS = (
    "disclosure-advisory.md",
    "disclosure-csaf.json",
    "disclosure-openvex.json",
    "disclosure-cve-draft.json",
)


def _seed(store, *, status="verified", cve=None, references=None, project="php-src"):
    store.save_project(make_project(id=project))
    ev = store.write_detail("S-seed", "evidence.txt", "resolving evidence")
    kwargs = dict(status=status, evidence_ref=ev, project=project, cve=cve)
    if references is not None:
        kwargs["references"] = references
    store.save_finding(make_finding(**kwargs))


def _read(store, ref):
    return (store.root / ref).read_text()


def test_drafts_all_four_artifacts_and_they_validate(state_dir):
    store = FileStore(state_dir)
    _seed(store)

    session = DisclosureSession(project_id="php-src", finding_id="F-0007")
    record = run_session(store, GATE, session)

    assert record.close_state is CloseState.clean
    assert set(session.artifact_refs) == set(_ARTIFACTS)
    for name in _ARTIFACTS:
        assert store.detail_exists(session.artifact_refs[name])

    # Each JSON draft is conformant to its own validator.
    assert validate_csaf(json.loads(_read(store, session.artifact_refs["disclosure-csaf.json"]))) == []
    assert validate_openvex(json.loads(_read(store, session.artifact_refs["disclosure-openvex.json"]))) == []
    assert validate_cve_draft(json.loads(_read(store, session.artifact_refs["disclosure-cve-draft.json"]))) == []
    # The advisory is Markdown with the DRAFT footer.
    advisory = _read(store, session.artifact_refs["disclosure-advisory.md"])
    assert advisory.startswith("# Advisory:")
    assert "DRAFT" in advisory and "nothing transmitted" in advisory


def test_refuses_a_finding_from_another_project(state_dir):
    store = FileStore(state_dir)
    _seed(store, project="php-src")  # finding belongs to php-src
    store.save_project(
        make_project(id="other-proj", git_url="https://github.com/other/other-proj")
    )

    session = DisclosureSession(project_id="other-proj", finding_id="F-0007")
    record = run_session(store, GATE, session)

    assert record.close_state is CloseState.clean
    assert "refusing" in session.outcome.summary
    assert session.artifact_refs == {}  # nothing drafted


def test_refuses_a_non_verified_finding(state_dir):
    for status in ("candidate", "disclosed", "patched"):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            store = FileStore(Path(d) / "state")
            # disclosed/patched need cve; seed accordingly so save_finding's guard passes.
            cve = "CVE-2026-99999" if status in ("disclosed", "patched") else None
            refs = None
            if status == "disclosed":
                refs = [Reference(type="advisory", url="https://example.test/a")]
            elif status == "patched":
                refs = [Reference(type="fix", url="https://example.test/fix")]
            _seed(store, status=status, cve=cve, references=refs)

            session = DisclosureSession(project_id="php-src", finding_id="F-0007")
            record = run_session(store, GATE, session)

            assert record.close_state is CloseState.clean
            assert "not verified" in session.outcome.summary
            assert session.artifact_refs == {}
            assert session.outcome.findings_touched == ["F-0007"]


def test_does_not_transition_the_finding_or_mutate_it(state_dir, monkeypatch):
    store = FileStore(state_dir)
    _seed(store, cve=None, references=[Reference(type="web", url="https://example.test/w")])
    before = store.get_finding("F-0007").model_dump()

    # transition_finding and save_finding must NEVER be called during a draft.
    def _forbidden(*a, **k):
        raise AssertionError("DISCLOSURE must not mutate the finding")

    monkeypatch.setattr(store, "transition_finding", _forbidden)
    monkeypatch.setattr(store, "save_finding", _forbidden)

    session = DisclosureSession(project_id="php-src", finding_id="F-0007")
    run_session(store, GATE, session)

    after = store.get_finding("F-0007")
    assert after.status is FindingStatus.verified          # unchanged
    assert after.cve is None                               # no fabricated CVE
    assert not after.has_reference_type("advisory")        # no fabricated advisory ref
    assert after.model_dump() == before                    # byte-for-byte unchanged


def test_transmits_nothing_no_network_imports():
    import deepthought.sessions.disclosure as mod

    source = (mod.__file__)
    text = open(source, encoding="utf-8").read()
    for banned in ("import socket", "import urllib", "http.client", "import requests",
                   "urlopen", "smtplib", "httpx"):
        assert banned not in text, f"disclosure session must not use {banned!r}"


def test_next_steps_names_the_human_gate(state_dir):
    store = FileStore(state_dir)
    _seed(store)

    session = DisclosureSession(project_id="php-src", finding_id="F-0007")
    run_session(store, GATE, session)

    steps = session.outcome.next_steps
    assert steps.strip()
    low = steps.lower()
    assert "human gate" in low and "cve" in low and "advisory" in low
