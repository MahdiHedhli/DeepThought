"""Variant analysis (SIBLING HUNT, feature 004).

This package holds the variant :class:`Signature` and its derivation. A
:class:`~deepthought.sessions.sibling_hunt.SiblingHuntSession` takes a VERIFIED
finding, derives a runtime variant signature from that finding's *typed* fields
only (never its untrusted free-text body), and hunts read-only for sibling
instances of the same bug class across the source project and any pre-authorized
sibling project — mirroring DISCOVER's shape while adding a same-class filter.

"""

from __future__ import annotations

from .signature import Signature, signature_from_finding

__all__ = ["Signature", "signature_from_finding"]
