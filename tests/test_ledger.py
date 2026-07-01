"""T010 — Primitive ledger and exploit graph.

Add a primitive from an envelope; detect a composition where one primitive's
grants meet another's preconditions; the working set stays within a configured
bound.
"""

from __future__ import annotations

from deepthought.orchestrator import Ledger
from deepthought.schema import Primitive


def prim(**overrides) -> Primitive:
    data = dict(
        kind="write:logfile",
        target_locus="src/log.c:10",
        preconditions=[],
        grants=["write:logfile"],
        confidence="suspected",
        finding_ref="F-0001",
    )
    data.update(overrides)
    return Primitive.model_validate(data)


def test_add_primitive_from_envelope():
    ledger = Ledger()
    key = ledger.add_primitive(prim())
    assert len(ledger) == 1
    assert ledger.get(key).kind == "write:logfile"


def test_readding_same_primitive_does_not_grow_ledger():
    ledger = Ledger()
    ledger.add_primitive(prim())
    ledger.add_primitive(prim())
    assert len(ledger) == 1


def test_detects_composition_where_grant_meets_precondition():
    ledger = Ledger()
    # write:logfile grants write:logfile; the second primitive requires it.
    ledger.add_primitive(
        prim(kind="write:logfile", grants=["write:logfile"], finding_ref="F-0001")
    )
    ledger.add_primitive(
        prim(
            kind="exec:code",
            target_locus="src/include.c:88",
            preconditions=["log inclusion of write:logfile output"],
            grants=["exec:command"],
            finding_ref="F-0002",
        )
    )
    comps = ledger.compositions()
    assert len(comps) == 1
    edge = comps[0]
    assert edge.via == "write:logfile"
    assert edge.frm.startswith("F-0001")
    assert edge.to.startswith("F-0002")


def test_no_spurious_compositions():
    ledger = Ledger()
    ledger.add_primitive(prim(kind="leak:info", grants=["leak:info"], finding_ref="F-1"))
    ledger.add_primitive(
        prim(
            kind="ssrf:request",
            grants=["ssrf:request"],
            preconditions=["network egress allowed"],
            finding_ref="F-2",
        )
    )
    assert ledger.compositions() == []


def test_working_set_stays_within_bound():
    ledger = Ledger(max_primitives=5)
    for i in range(20):
        ledger.add_primitive(
            prim(target_locus=f"src/f.c:{i}", finding_ref=f"F-{i:04d}")
        )
    assert len(ledger) == 5
    # The most recent survive; the oldest were evicted (they page in the Store).
    surviving = {n.finding_ref for n in ledger.nodes()}
    assert "F-0019" in surviving
    assert "F-0000" not in surviving
