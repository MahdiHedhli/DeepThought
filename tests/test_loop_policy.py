"""T604 — select_next_action: the deterministic, monotonic selection policy.

The ladder is STATUS -> MAP -> DISCOVER (per project) -> SIBLING HUNT -> DISCLOSURE
(per verified finding) -> VERIFY escalation (per candidate) -> fixed point. Each
rung fires only while it makes NEW progress; the driver's ``done`` set plus
store-visible signals keep it from re-proposing completed work.
"""

from __future__ import annotations

from deepthought.loop.policy import select_next_action
from deepthought.schema import Session
from deepthought.schema.loop import ActionKind
from deepthought.store import FileStore

from .conftest import make_coverage, make_finding, make_project


def _proj(store):
    p = make_project()  # basis permissive_oss + scope -> gate proceeds
    store.save_project(p)
    return p


def _add_session(store, stype, sid, gate_outcome="proceed", **kw):
    # Default to a gate-PROCEEDED session — only a session that proceeded counts as
    # completed work in the policy (a refused attempt must not mark its rung done).
    store.save_session(Session(id=sid, type=stype, project="php-src",
                               started="2026-07-02T00:00:00Z",
                               gate_outcome=gate_outcome, **kw))


def _past_recon(store):
    """Advance the store past the recon rungs: a status baseline, real MAP
    progress (Coverage exists), and a completed DISCOVER."""
    _add_session(store, "status", "S-1")
    store.save_coverage(make_coverage())     # MAP made progress
    _add_session(store, "discover", "S-3")   # DISCOVER done


def test_fresh_project_starts_with_status(state_dir):
    store = FileStore(state_dir)
    p = _proj(store)
    action = select_next_action(store, p)
    assert action is not None and action.kind is ActionKind.status
    assert action.project == "php-src" and action.is_escalation is False


def test_ladder_advances_status_then_map_then_discover(state_dir):
    store = FileStore(state_dir)
    p = _proj(store)
    _add_session(store, "status", "S-1")
    assert select_next_action(store, p).kind is ActionKind.map
    # MAP is "done" only once it records Coverage — not by the session alone.
    store.save_coverage(make_coverage())
    assert select_next_action(store, p).kind is ActionKind.discover
    _add_session(store, "discover", "S-3")
    # nothing found -> fixed point
    assert select_next_action(store, p) is None


def test_map_reruns_when_it_produced_no_coverage(state_dir):
    """A MAP that recorded no Coverage (e.g. a project with no checkout yet) is not
    'done' — the loop re-proposes it so it can recover once the operator adds the
    checkout its own next-steps ask for."""
    store = FileStore(state_dir)
    p = _proj(store)
    _add_session(store, "status", "S-1")
    _add_session(store, "map", "S-2")  # a MAP session that recorded NO coverage
    assert select_next_action(store, p).kind is ActionKind.map  # re-proposed
    store.save_coverage(make_coverage())                        # now MAP made progress
    assert select_next_action(store, p).kind is ActionKind.discover


def test_refused_discover_attempt_is_not_counted_as_done(state_dir):
    """A gate-refused DISCOVER (e.g. authorization was temporarily removed) is not
    progress — after the gate is fixed the loop re-proposes DISCOVER instead of
    reporting a fixed point without ever discovering."""
    store = FileStore(state_dir)
    p = _proj(store)
    _add_session(store, "status", "S-1")
    store.save_coverage(make_coverage())
    _add_session(store, "discover", "S-3", gate_outcome="refuse")  # a REFUSED attempt
    assert select_next_action(store, p).kind is ActionKind.discover  # re-proposed
    _add_session(store, "discover", "S-4", gate_outcome="proceed")   # now it succeeds
    assert select_next_action(store, p) is None


def test_refused_sibling_hunt_in_prior_trace_is_not_counted(state_dir):
    """A gate-refused sibling-hunt step in a prior loop trace is not 'hunted' —
    after the gate is fixed the next run resumes variant analysis."""
    from deepthought.loop import LoopBudget
    from deepthought.schema.loop import LoopRun, LoopStep

    store = FileStore(state_dir)
    p = _proj(store)
    _past_recon(store)
    store.save_finding(make_finding(id="F-1", project="php-src", status="verified"))
    store.save_loop_run(LoopRun(
        id="L-1", project="php-src", started="t", stop_reason="gate_refused",
        budget=LoopBudget(max_sessions=5),
        trace=[LoopStep(kind="sibling_hunt", session_id="S-9", finding="F-1",
                        gate_outcome="refuse")],
        body="## Summary\n\nx\n\n## Next steps\n\ny",
    ))
    assert select_next_action(store, p).kind is ActionKind.sibling_hunt  # resumed


def test_verified_finding_yields_sibling_hunt_then_disclosure(state_dir):
    store = FileStore(state_dir)
    p = _proj(store)
    _past_recon(store)
    store.save_finding(make_finding(id="F-1", project="php-src", status="verified"))

    a = select_next_action(store, p)
    assert a.kind is ActionKind.sibling_hunt and a.finding == "F-1"
    # once the hunt is dispatched (driver marks it done), disclosure is next
    done = {("sibling_hunt", "F-1")}
    a = select_next_action(store, p, done=done)
    assert a.kind is ActionKind.disclosure and a.finding == "F-1"
    # a disclosure session that drafted F-1 (findings_touched) is the cross-run signal
    _add_session(store, "disclosure", "S-4", findings_touched=["F-1"])
    assert select_next_action(store, p, done=done) is None


def test_candidate_yields_a_verify_escalation(state_dir):
    store = FileStore(state_dir)
    p = _proj(store)
    _past_recon(store)
    store.save_finding(make_finding(id="F-9", project="php-src", status="candidate"))
    a = select_next_action(store, p)
    assert a.kind is ActionKind.verify_escalation
    assert a.is_escalation is True and a.finding == "F-9"
    assert "sign-off" in a.human_action.lower()


def test_disclosure_precedes_verify_escalation(state_dir):
    """All safe work (draft disclosure for verified) comes before the hard-stop
    escalation for candidates."""
    store = FileStore(state_dir)
    p = _proj(store)
    _past_recon(store)
    store.save_finding(make_finding(id="F-1", project="php-src", status="verified"))
    store.save_finding(make_finding(id="F-9", project="php-src", status="candidate"))
    done = {("sibling_hunt", "F-1")}
    a = select_next_action(store, p, done=done)
    assert a.kind is ActionKind.disclosure and a.finding == "F-1"  # not the escalation yet


def test_monotonic_done_set_prevents_reproposal(state_dir):
    """Re-invoking after marking an action done never re-proposes it — the loop
    cannot spin on the same work."""
    store = FileStore(state_dir)
    p = _proj(store)
    # status is the first rung; once marked done it is not re-proposed even before
    # a status session is persisted.
    a1 = select_next_action(store, p)
    assert a1.kind is ActionKind.status
    a2 = select_next_action(store, p, done={("status", "php-src")})
    assert a2.kind is ActionKind.map


def test_missing_project_signals_are_read_only(state_dir):
    """select_next_action writes nothing to the store."""
    store = FileStore(state_dir)
    p = _proj(store)
    before = sorted(state_dir.rglob("*.md"))
    select_next_action(store, p)
    assert sorted(state_dir.rglob("*.md")) == before
