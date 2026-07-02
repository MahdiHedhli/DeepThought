"""Finding -> OpenVEX draft mapping and programmatic validation.

OpenVEX is a vulnerability-exploitability exchange document. Feature 005 is
DRAFT-ONLY: exports are never authoritative and must never be mistaken for a
publishable, human-reviewed attestation. Two rules keep drafts inert:

* A verified finding is, by definition, *affected*. We only ever emit the
  ``affected`` status; we never assert ``not_affected``, ``fixed`` or
  ``under_investigation`` on the target's behalf. ``affected`` obliges an
  ``action_statement`` -- we emit an explicit PLACEHOLDER demanding human
  remediation guidance before disclosure.
* The vulnerability name falls back to the internal finding id when no CVE is
  assigned. We never fabricate a CVE.

``validate_openvex`` is a small programmatic validator (OpenVEX has no bundled
JSON schema here). It mirrors the ``validate_osv`` contract: it returns a sorted
list of ``"path: message"`` strings, and an empty list means the document is
conformant.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..schema.common import iso_z, utcnow
from .osv import osv_id_for

if TYPE_CHECKING:  # pragma: no cover
    from ..schema.finding import Finding

# The official CVE id pattern. Only a value matching this is treated as a real,
# assigned CVE; the sentinel "CVE-XXXX-XXXXX" and any malformed value fail it and
# fall back to the internal finding id.
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")

# Pinned OpenVEX context (spec version). Carried as the ``@context`` member.
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# The author identity is an obvious local-draft placeholder; never a real CNA or
# publisher identity.
_DRAFT_AUTHOR = "Deep Thought (local draft)"

# ``affected`` requires human remediation guidance before disclosure. We refuse
# to invent one, so the action statement is a loud placeholder.
_ACTION_STATEMENT_PLACEHOLDER = (
    "PLACEHOLDER — human remediation guidance required before disclosure."
)

# The valid OpenVEX statement status labels.
_VALID_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}


def _vuln_name(finding: "Finding") -> str:
    """The statement's vulnerability name: the real CVE, or the internal id.

    A stored ``cve`` is used only when it matches the official CVE pattern. The
    sentinel ``CVE-XXXX-XXXXX`` or any malformed value falls back to the finding
    id, so a local draft never appears to reference a non-existent assigned CVE.
    """
    if finding.cve and _CVE_RE.match(finding.cve):
        return finding.cve
    return finding.id


def _purl(finding: "Finding") -> str:
    """Build a Package-URL product id from the first affected package.

    Falls back to a deepthought.local product id when the finding has no
    affected package, so the product list is never empty.
    """
    if not finding.affected:
        return f"https://deepthought.local/product/{osv_id_for(finding.id)}"
    pkg = finding.affected[0]
    ecosystem = pkg.ecosystem.lower()
    purl = f"pkg:{ecosystem}/{pkg.package}"
    if pkg.versions:
        purl = f"{purl}@{pkg.versions[0]}"
    return purl


def finding_to_openvex(finding: "Finding") -> dict:
    """Map a Finding to an OpenVEX draft document (a JSON-serializable dict)."""
    utcdate = iso_z(utcnow())[:10]
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"https://deepthought.local/vex/draft/{utcdate}-{finding.id}",
        "author": _DRAFT_AUTHOR,
        "timestamp": iso_z(utcnow()),
        "version": 1,
        "statements": [
            {
                # Never fabricate OR echo a placeholder/malformed CVE: only a value
                # matching the real CVE pattern is used; otherwise fall back to the
                # internal finding id so the draft never appears to name a
                # non-existent assigned CVE.
                "vulnerability": {"name": _vuln_name(finding)},
                "products": [{"@id": _purl(finding)}],
                # A verified finding is affected; we never assert otherwise.
                "status": "affected",
                # affected obliges an action statement; refuse to invent one.
                "action_statement": _ACTION_STATEMENT_PLACEHOLDER,
            }
        ],
    }


def validate_openvex(doc: dict) -> list[str]:
    """Return a sorted list of OpenVEX violations. Empty means conformant.

    Programmatic checks (no bundled schema):

    * required document members: ``@context``, ``@id``, ``author``,
      ``timestamp``, ``version``;
    * ``statements`` must be present and non-empty;
    * per statement: ``vulnerability.name`` present, ``products`` non-empty,
      ``status`` in the valid enum, and the conditional rule that
      ``status == "affected"`` requires a non-empty ``action_statement``.
    """
    errors: list[str] = []

    if not isinstance(doc, dict):
        return ["<root>: document must be an object"]

    for field in ("@context", "@id", "author", "timestamp", "version"):
        if not doc.get(field):
            errors.append(f"{field}: is a required document field")

    statements = doc.get("statements")
    if not statements:
        errors.append("statements: must contain at least one statement")
    else:
        for i, stmt in enumerate(statements):
            base = f"statements/{i}"
            if not isinstance(stmt, dict):
                errors.append(f"{base}: statement must be an object")
                continue

            vuln = stmt.get("vulnerability")
            if not isinstance(vuln, dict) or not vuln.get("name"):
                errors.append(f"{base}/vulnerability/name: is required")

            if not stmt.get("products"):
                errors.append(f"{base}/products: must be non-empty")

            status = stmt.get("status")
            if status not in _VALID_STATUSES:
                errors.append(
                    f"{base}/status: {status!r} is not one of "
                    f"{sorted(_VALID_STATUSES)}"
                )

            if status == "affected" and not stmt.get("action_statement"):
                errors.append(
                    f"{base}/action_statement: is required when status is 'affected'"
                )

    return sorted(errors)
