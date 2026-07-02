"""Finding -> human-readable Markdown advisory (DRAFT-only).

The advisory is a draft artifact for human review. It renders each finding
section as inert Markdown prose and never leaves the machine. Two properties are
load-bearing:

* **Draft-only.** No CVE is ever fabricated and no publisher identity is
  invented. A fixed footer states plainly that nothing has been transmitted, so
  the document can never be mistaken for a real disclosure.
* **Injection inertness.** Finding free-text (summary, body prose, downstream
  impact, reference urls) is carried only as inert string values inside text
  leaves. It never becomes a Markdown heading of its own or otherwise alters the
  fixed section structure — the seven fixed headings are always where they
  belong regardless of what the free-text contains.

Prose scraping (``_details``) is reused from the OSV exporter so the human
narrative stays consistent with the canonical record.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .osv import _details

if TYPE_CHECKING:  # pragma: no cover
    from ..schema.finding import Finding

# Fixed footer. This is the guarantee, verbatim, that the document is a draft.
_DRAFT_STATUS = (
    "DRAFT — no CVE assigned, nothing transmitted, finding remains verified."
)


def finding_to_advisory(finding: "Finding") -> str:
    """Render a Finding as a human-readable, draft-only Markdown advisory.

    All finding free-text is emitted as inert prose values; the fixed section
    headings are always present (except Severity, which is omitted when the
    finding carries no severity) and never displaced by adversarial content.
    """
    # summary is a text value on the title line; even if it contains "##" or
    # "</script>" or a JSON $ref it stays on this single line and the fixed
    # headings below are unaffected.
    parts: list[str] = [f"# Advisory: {finding.summary}"]

    parts.append("## Summary")
    parts.append(finding.summary)

    # Omit the whole CVSS block when there is no severity — never fake scores.
    if finding.severity is not None:
        parts.append("## Severity")
        parts.append(f"- CVSS vector: {finding.severity.cvss_vector}")
        parts.append(f"- CVSS score: {finding.severity.cvss_score}")

    parts.append("## Affected")
    if finding.affected:
        for pkg in finding.affected:
            versions = ", ".join(pkg.versions) if pkg.versions else "(unspecified)"
            parts.append(f"- {pkg.ecosystem}: {pkg.package} — versions {versions}")
    else:
        parts.append("- (no affected packages recorded)")

    parts.append("## Details")
    details = _details(finding)
    # ``_details`` scrapes body prose that may itself contain "##" sub-headings
    # (Root cause / Impact). Render it as a blockquote so those are carried as
    # inert quoted prose and can never masquerade as a top-level document
    # section — the document's own section grammar stays fixed.
    if details:
        parts.append("\n".join(f"> {line}" for line in details.splitlines()))
    else:
        parts.append("(no details recorded)")

    impact = (finding.downstream_impact or "").strip()
    if impact:
        parts.append("## Impact")
        parts.append(impact)

    parts.append("## References")
    if finding.references:
        for ref in finding.references:
            parts.append(f"- {ref.type}: {ref.url}")
    else:
        parts.append("- (no references recorded)")

    disclosure = finding.disclosure
    if disclosure is not None and disclosure.timeline:
        parts.append("## Disclosure timeline")
        for entry in disclosure.timeline:
            parts.append(f"- {entry.date}: {entry.event}")

    parts.append("## Status")
    parts.append(_DRAFT_STATUS)

    return "\n\n".join(parts) + "\n"
