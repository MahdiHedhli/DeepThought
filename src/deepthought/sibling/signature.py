"""The variant ``Signature`` and its derivation — the input firewall (feature 004).

SIBLING HUNT starts from a VERIFIED finding (a confirmed bug class) and derives a
runtime :class:`Signature` describing that class: its *capability* (the source
``Primitive.kind``), a normalized *locus pattern*, and the closed-lookup *match
terms* that the same-class hunt keys on. The hunt then looks for SIBLING
instances that grant the same capability.

This module is the input-side injection boundary (Constitution Article VIII).
The signature is **derived from typed fields only**:

* ``capability`` comes from the bound :class:`Primitive.kind` — a member of
  ``CAPABILITY_TAXONOMY``. It can never introduce a capability, only reuse one.
* ``locus_pattern`` comes from the finding's *typed* location reference (the
  ``**Location:**`` line the SARIF ingest rendered, or a ``references[]`` url) —
  a normalized, length-bounded match hint, never a path that is opened or run.
* ``match_terms`` are the closed-lookup keys (ruleId/tag/CWE needles) that map to
  ``capability`` — the exact vocabulary ``ingest.sarif`` uses. Unknown terms are
  dropped.

The finding's free-text ``body`` is **never** read as instruction. A hostile
finding can, at worst, fail to yield a signature (:func:`signature_from_finding`
returns ``None``); it can never mint a capability or smuggle a command. The
:class:`Signature` is *not* a persisted :class:`Record` — it is a transient
runtime value the session holds for the duration of one hunt.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from ..ingest.sarif import _HEURISTIC, _match_capability
from ..schema.envelope import CAPABILITY_TAXONOMY, Primitive
from ..schema.finding import Finding

# Length caps, mirroring the envelope's discipline: every string field is bounded
# so a signature can never carry an oversized (or hostile) free-text payload.
_Short = Annotated[str, StringConstraints(max_length=128)]
_Ref = Annotated[str, StringConstraints(max_length=256)]
_LocusPattern = Annotated[str, StringConstraints(max_length=256)]
_MatchTerm = Annotated[str, StringConstraints(max_length=64)]

# A match_terms list is bounded in count so a derivation (or a caller) cannot
# flood the signature with terms. The closed lookup has far fewer needles than
# this per capability, so the bound is generous but real.
_MATCH_TERMS_MAX = 32

# The closed set of every needle the SARIF heuristic table keys on. A match term
# outside this set is not a known lookup key and is refused — the signature keys
# only on the same fixed vocabulary the ingest maps to capabilities.
_KNOWN_MATCH_TERMS: frozenset[str] = frozenset(needle for needle, _ in _HEURISTIC)

# The reverse of the heuristic table: for a capability, the needles that map to
# it. Built once at import so derivation is a pure lookup, never a scan of
# free-text. Preserves table order (most-specific-first) for determinism.
_TERMS_BY_CAPABILITY: dict[str, list[str]] = {}
for _needle, _capability in _HEURISTIC:
    _TERMS_BY_CAPABILITY.setdefault(_capability, []).append(_needle)

# The "**Location:** `<locus>`" line the SARIF ingest renders into a finding
# body. The locus is the ONLY part of the body the derivation reads, and only as
# a typed location reference (matched by this fixed pattern), never as free-text
# instruction. The backtick-wrapped group is the normalized location shape.
_LOCATION_RE = re.compile(r"\*\*Location:\*\*\s+`([^`]+)`")


class Signature(BaseModel):
    """A runtime variant signature derived from a verified finding.

    Not a persisted :class:`Record`: a transient value the SIBLING HUNT session
    holds while it hunts. ``extra='forbid'`` and the per-field length caps make
    it as tamper-resistant as the envelope — there is no free-text field a caller
    (or a hostile source finding) can smuggle an instruction through, and
    ``capability`` must be a taxonomy member.
    """

    model_config = ConfigDict(extra="forbid")

    source_finding: _Short
    source_project: _Short
    capability: _Short
    locus_pattern: _LocusPattern | None = None
    match_terms: Annotated[list[_MatchTerm], Field(max_length=_MATCH_TERMS_MAX)] = []

    @model_validator(mode="after")
    def _known_capability(self) -> "Signature":
        # The signature reuses a capability, never introduces one — the same
        # invariant Primitive.kind enforces. A non-taxonomy capability fails.
        if self.capability not in CAPABILITY_TAXONOMY:
            raise ValueError(f"unknown signature capability: {self.capability!r}")
        return self

    @model_validator(mode="after")
    def _terms_are_known_keys(self) -> "Signature":
        # Every match term must be a known closed-lookup key. An unknown term
        # (e.g. one injected from a finding body) never reaches a constructed
        # signature — the derivation drops unknowns, and this refuses any that
        # slip through a direct construction.
        unknown = [t for t in self.match_terms if t not in _KNOWN_MATCH_TERMS]
        if unknown:
            raise ValueError(f"unknown match_terms (not closed-lookup keys): {unknown!r}")
        return self

    @staticmethod
    def known_match_terms() -> frozenset[str]:
        """The closed set of every legal match term (the heuristic needles)."""
        return _KNOWN_MATCH_TERMS


def _bound_capability(finding: Finding, primitives: list[Primitive]) -> str | None:
    """The capability from the primitive bound to this finding, or ``None``.

    Reads ``Primitive.kind`` ONLY from a primitive whose ``finding_ref`` equals
    the source finding id — a primitive bound to another finding never drives the
    signature. When several match, the one whose kind sorts first in taxonomy
    order wins, so derivation is deterministic. ``kind`` is already a taxonomy
    member by the Primitive model's own validator.
    """
    kinds = sorted(
        {
            p.kind
            for p in primitives
            if p.finding_ref == finding.id and p.kind in CAPABILITY_TAXONOMY
        }
    )
    return kinds[0] if kinds else None


def _locus_pattern(finding: Finding) -> str | None:
    """The normalized location shape from the finding's TYPED location reference.

    Reads the ``**Location:** `<locus>` `` line the SARIF ingest rendered (the
    only structured location the body carries) or, failing that, a
    ``references[]`` url stem. This is a match hint — never a path that is
    resolved, opened, or executed. The rest of the body is never read.
    """
    match = _LOCATION_RE.search(finding.body or "")
    if match:
        locus = match.group(1).strip()
        if locus:
            return locus[:256]
    for ref in finding.references or []:
        url = (ref.url or "").strip()
        if url:
            return url[:256]
    return None


def _match_terms(capability: str) -> list[str]:
    """The closed-lookup keys that map to ``capability`` (deduped, bounded).

    A pure reverse lookup of the SARIF heuristic table. Every returned term is a
    known closed-lookup key by construction, so the signature keys only on the
    same fixed vocabulary the ingest maps to capabilities.
    """
    terms = _TERMS_BY_CAPABILITY.get(capability, [])
    return list(dict.fromkeys(terms))[:_MATCH_TERMS_MAX]


def signature_from_finding(
    finding: Finding, primitives: list[Primitive] | None = None
) -> Signature | None:
    """Derive a variant :class:`Signature` from a verified finding, or ``None``.

    Typed-fields-only derivation (the input firewall):

    1. ``capability`` is derived from the finding's TYPED ``summary`` via the SAME
       closed lookup DISCOVER uses (and known-key ruleId tokens) — never free-text
       interpretation. If a caller passes ``primitives`` bound to ``finding`` (by
       ``finding_ref``), the bound ``Primitive.kind`` takes precedence; this
       bound-primitive path stays supported for direct callers and tests. But
       primitives are NOT persisted in the Store across sessions, so the SIBLING
       HUNT session calls this with no ``primitives`` (``None``, treated as ``[]``)
       and derives capability from the summary alone. If neither the bound
       primitive nor the summary lookup yields a taxonomy capability, return
       ``None``: the hunt has no class to look for and never invents one.
    2. ``locus_pattern`` is the finding's typed location reference, normalized.
    3. ``match_terms`` are the closed-lookup keys that map to ``capability``.

    The finding's free-text ``body`` is never parsed for instructions. A source
    finding whose body carries an injected instruction derives the identical
    signature as one without.

    This is a PURE derivation over typed fields; it does not itself check the
    finding's lifecycle status. The contract's "derive from a VERIFIED finding"
    rule is enforced by the CALLER: :meth:`SiblingHuntSession.run` refuses a
    non-verified source finding before it ever calls this. Keeping the check at
    the session boundary (a real refusal, not a strippable ``assert``) lets the
    function stay usable in unit tests over any finding shape.
    """
    capability = _bound_capability(finding, primitives or [])
    if capability is None:
        # Closed-lookup fallback over the TYPED summary only (the same
        # _match_capability path the SARIF ingest uses). The summary is a
        # length-capped, SARIF-derived field; it is used only as a table key,
        # never interpreted. The body is never consulted.
        capability = _match_capability(finding.summary, [])
    if capability is None or capability not in CAPABILITY_TAXONOMY:
        return None

    return Signature(
        source_finding=finding.id[:128],
        source_project=finding.project[:128],
        capability=capability,
        locus_pattern=_locus_pattern(finding),
        match_terms=_match_terms(capability),
    )
