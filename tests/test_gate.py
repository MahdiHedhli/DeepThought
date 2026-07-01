"""T007 — Gate interface and the HermesUltraCode adapter stub.

Refuse on missing authorization_basis, refuse on blackbox without
authorization_ref, proceed on a clean in-scope project; every hold and refuse
writes a reason.
"""

from __future__ import annotations

import pytest

from deepthought.protocol import (
    DefaultGate,
    GateContext,
    GateDecision,
    HermesUltraCodeGate,
)
from deepthought.protocol.gate import Gate
from deepthought.schema import (
    AuthorizationBasis,
    GateOutcome,
    SessionType,
    SourceType,
)

from .conftest import make_project

GATE = HermesUltraCodeGate()


def test_refuse_on_missing_authorization_basis():
    ctx = GateContext.from_project(
        make_project(authorization_basis=None), SessionType.status
    )
    decision = GATE.evaluate(ctx)
    assert decision.outcome is GateOutcome.refuse
    assert decision.reason


def test_refuse_on_blackbox_without_authorization_ref():
    ctx = GateContext(
        session_type=SessionType.status,
        source_type=SourceType.blackbox,
        authorization_basis=AuthorizationBasis.scoped_engagement,
        authorization_ref=None,
        scope_allowlist=["api.example.test"],
    )
    decision = GATE.evaluate(ctx)
    assert decision.outcome is GateOutcome.refuse
    assert "blackbox" in decision.reason or "authorization_ref" in decision.reason


def test_proceed_on_clean_in_scope_project():
    ctx = GateContext.from_project(make_project(), SessionType.status)
    decision = GATE.evaluate(ctx)
    assert decision.outcome is GateOutcome.proceed
    assert decision.proceeds


def test_hold_on_empty_scope_allowlist():
    ctx = GateContext.from_project(
        make_project(scope_allowlist=[]), SessionType.status
    )
    decision = GATE.evaluate(ctx)
    assert decision.outcome is GateOutcome.hold
    assert decision.reason


def test_scoped_engagement_without_ref_is_refused():
    ctx = GateContext(
        session_type=SessionType.status,
        source_type=SourceType.open_source,
        authorization_basis=AuthorizationBasis.scoped_engagement,
        authorization_ref=None,
        scope_allowlist=["x"],
    )
    decision = GATE.evaluate(ctx)
    assert decision.outcome is GateOutcome.refuse


def test_every_hold_and_refuse_carries_a_reason():
    # A hold or refuse decision cannot be constructed without a reason.
    with pytest.raises(ValueError):
        GateDecision(GateOutcome.refuse)
    with pytest.raises(ValueError):
        GateDecision(GateOutcome.hold)
    # proceed needs none.
    assert GateDecision(GateOutcome.proceed).reason is None


# --- Slice 4: DefaultGate honesty (phase-0 decision 0.1) --------------------


def test_default_gate_holds_the_authorization_and_scope_rules():
    """DefaultGate is a concrete Gate carrying the local rules directly."""
    assert issubclass(DefaultGate, Gate)
    gate = DefaultGate()
    ctx = GateContext.from_project(make_project(), SessionType.status)
    assert gate.evaluate(ctx).outcome is GateOutcome.proceed


def test_hermes_ultra_code_gate_subclasses_default_gate():
    """The named HermesUltraCode seam delegates to DefaultGate until the real
    interface is confirmed (phase-0 decision 0.1). It is a thin subclass."""
    assert issubclass(HermesUltraCodeGate, DefaultGate)


def test_default_and_hermes_gates_agree_on_every_outcome():
    """The seam changes nothing observable: both gates return the same decision
    for proceed, hold, and refuse cases."""
    default = DefaultGate()
    hermes = HermesUltraCodeGate()
    cases = [
        GateContext.from_project(make_project(), SessionType.status),
        GateContext.from_project(
            make_project(authorization_basis=None), SessionType.status
        ),
        GateContext.from_project(
            make_project(scope_allowlist=[]), SessionType.status
        ),
        GateContext(
            session_type=SessionType.status,
            source_type=SourceType.blackbox,
            authorization_basis=AuthorizationBasis.scoped_engagement,
            authorization_ref=None,
            scope_allowlist=["x"],
        ),
    ]
    for ctx in cases:
        d, h = default.evaluate(ctx), hermes.evaluate(ctx)
        assert d.outcome is h.outcome
        assert d.reason == h.reason


def test_default_gate_refuses_missing_basis_like_hermes():
    ctx = GateContext.from_project(
        make_project(authorization_basis=None), SessionType.status
    )
    assert DefaultGate().evaluate(ctx).outcome is GateOutcome.refuse
