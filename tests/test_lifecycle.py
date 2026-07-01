"""T006 — Lifecycle guard at the Store boundary.

One test per transition. Illegal transitions are rejected with the reason
recorded on the finding; backward transitions are logged.
"""

from __future__ import annotations

from deepthought.schema import FindingStatus, Reference
from deepthought.store import FileStore

from .conftest import make_finding


def _store_with(finding, state_dir) -> FileStore:
    store = FileStore(state_dir)
    store.save_finding(finding)
    return store


def test_candidate_to_verified_requires_resolving_evidence(state_dir):
    store = _store_with(make_finding(status="candidate", evidence_ref=None), state_dir)

    # No evidence_ref → rejected, status unchanged, reason recorded.
    result = store.transition_finding("F-0007", FindingStatus.verified)
    assert not result.ok
    assert "evidence_ref" in result.reason
    assert store.get_finding("F-0007").status == FindingStatus.candidate
    assert store.get_finding("F-0007").transition_log[-1].accepted is False

    # A non-resolving evidence_ref is still rejected.
    finding = store.get_finding("F-0007")
    finding.evidence_ref = "detail/S-x/missing.txt"
    store.save_finding(finding)
    result = store.transition_finding("F-0007", FindingStatus.verified)
    assert not result.ok and "does not resolve" in result.reason

    # Once the evidence resolves, the transition is accepted.
    ref = store.write_detail("S-x", "repro.txt", "trace")
    finding = store.get_finding("F-0007")
    finding.evidence_ref = ref
    store.save_finding(finding)
    result = store.transition_finding("F-0007", FindingStatus.verified)
    assert result.ok
    assert store.get_finding("F-0007").status == FindingStatus.verified


def _verified_finding(state_dir, **overrides) -> FileStore:
    store = FileStore(state_dir)
    ref = store.write_detail("S-x", "repro.txt", "trace")
    finding = make_finding(status="verified", evidence_ref=ref, **overrides)
    store.save_finding(finding)
    return store


def test_verified_to_disclosed_requires_cve_and_advisory(state_dir):
    # cve missing → rejected
    store = _verified_finding(state_dir, cve=None)
    result = store.transition_finding("F-0007", FindingStatus.disclosed)
    assert not result.ok and "cve" in result.reason

    # cve present but no advisory reference → rejected
    store = _verified_finding(state_dir, cve="CVE-2026-1", references=[])
    result = store.transition_finding("F-0007", FindingStatus.disclosed)
    assert not result.ok and "advisory" in result.reason

    # cve + advisory reference → accepted
    store = _verified_finding(
        state_dir,
        cve="CVE-2026-1",
        references=[Reference(type="advisory", url="https://example.test/a")],
    )
    result = store.transition_finding("F-0007", FindingStatus.disclosed)
    assert result.ok
    assert store.get_finding("F-0007").status == FindingStatus.disclosed


def test_verified_to_patched_requires_cve_and_fix(state_dir):
    store = _verified_finding(state_dir, cve="CVE-2026-1", references=[])
    result = store.transition_finding("F-0007", FindingStatus.patched)
    assert not result.ok and "fix" in result.reason

    store = _verified_finding(
        state_dir,
        cve="CVE-2026-1",
        references=[Reference(type="fix", url="https://example.test/commit/abc")],
    )
    result = store.transition_finding("F-0007", FindingStatus.patched)
    assert result.ok
    assert store.get_finding("F-0007").status == FindingStatus.patched


def test_illegal_transition_is_rejected_with_reason(state_dir):
    # candidate -> disclosed is not a legal edge at all.
    store = _store_with(make_finding(status="candidate"), state_dir)
    result = store.transition_finding("F-0007", FindingStatus.disclosed)
    assert not result.ok
    assert "illegal transition" in result.reason
    finding = store.get_finding("F-0007")
    assert finding.status == FindingStatus.candidate
    assert finding.transition_log[-1].reason == result.reason


def test_backward_transition_is_allowed_and_logged(state_dir):
    store = _verified_finding(
        state_dir,
        cve="CVE-2026-1",
        references=[Reference(type="advisory", url="https://example.test/a")],
    )
    # verified -> candidate is a backward edge: allowed, and logged.
    result = store.transition_finding("F-0007", FindingStatus.candidate)
    assert result.ok
    finding = store.get_finding("F-0007")
    assert finding.status == FindingStatus.candidate
    last = finding.transition_log[-1]
    assert last.accepted is True
    assert "backward" in last.reason
