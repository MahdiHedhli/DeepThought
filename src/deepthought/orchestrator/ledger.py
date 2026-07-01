"""Primitive ledger and exploit graph — the orchestrator's compact state.

The orchestrator holds a small working set: what capability each finding grants
(the ledger) and how those primitives compose (the exploit graph). Full worker
detail pages to the Store; only these distilled nodes live here. The working set
is bounded so the orchestrator can hold the exploit chain in mind without
drowning in context.

A composition is an edge A -> B where a token in A's ``grants`` satisfies one of
B's ``preconditions``. Example: ``write:logfile`` plus ``exec:code`` via log
inclusion composes to ``exec:command``. Workers supply the nodes; the
orchestrator holds the graph.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from ..schema import Primitive

DEFAULT_MAX_PRIMITIVES = 256


@dataclass(frozen=True)
class PrimitiveNode:
    key: str
    finding_ref: str
    kind: str
    target_locus: str
    grants: tuple[str, ...]
    preconditions: tuple[str, ...]
    confidence: str


@dataclass(frozen=True)
class Composition:
    """An edge in the exploit graph: ``frm`` grants what ``to`` requires."""

    frm: str
    to: str
    via: str


@dataclass
class Ledger:
    """A bounded primitive ledger plus the exploit-graph derivation."""

    max_primitives: int = DEFAULT_MAX_PRIMITIVES
    _nodes: "OrderedDict[str, PrimitiveNode]" = field(default_factory=OrderedDict)

    def __len__(self) -> int:
        return len(self._nodes)

    @staticmethod
    def _node_key(primitive: Primitive) -> str:
        return f"{primitive.finding_ref}:{primitive.kind}@{primitive.target_locus}"

    def add_primitive(self, primitive: Primitive) -> str:
        """Add a primitive node from an envelope; return its node key.

        The working set stays within ``max_primitives``; the oldest node is
        evicted first when the bound is exceeded (it remains paged in the Store).
        """
        key = self._node_key(primitive)
        node = PrimitiveNode(
            key=key,
            finding_ref=primitive.finding_ref,
            kind=primitive.kind,
            target_locus=primitive.target_locus,
            grants=tuple(primitive.grants),
            preconditions=tuple(primitive.preconditions),
            confidence=primitive.confidence.value,
        )
        # Re-adding a node refreshes its recency.
        if key in self._nodes:
            del self._nodes[key]
        self._nodes[key] = node
        while len(self._nodes) > self.max_primitives:
            self._nodes.popitem(last=False)
        return key

    def nodes(self) -> list[PrimitiveNode]:
        return list(self._nodes.values())

    def get(self, key: str) -> PrimitiveNode | None:
        return self._nodes.get(key)

    def compositions(self) -> list[Composition]:
        """Every edge where one node's grant meets another's precondition."""
        edges: list[Composition] = []
        nodes = self.nodes()
        for src in nodes:
            for grant in src.grants:
                token = grant.lower()
                for dst in nodes:
                    if dst.key == src.key:
                        continue
                    if any(token in pre.lower() for pre in dst.preconditions):
                        edges.append(Composition(frm=src.key, to=dst.key, via=grant))
        return edges
