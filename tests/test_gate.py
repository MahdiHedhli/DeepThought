"""T007 — Gate interface and the HermesUltraCode adapter stub.

Refuse on missing authorization_basis, refuse on blackbox without
authorization_ref, proceed on a clean in-scope project; every hold and refuse
writes a reason.
"""

from __future__ import annotations

import pytest

from deepthought.protocol import GateContext, GateDecision, HermesUltraCodeGate
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
