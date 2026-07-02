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

def _status_footer(finding: "Finding") -> str:
    """A DRAFT footer that reflects the finding's ACTUAL status and CVE.

    ``publish`` renders advisories for verified/disclosed/patched findings, so a
    hardcoded "no CVE assigned, remains verified" line would misstate a disclosed
    or patched finding. The footer derives its CVE and status from the finding,
    and always asserts the load-bearing invariant: Deep Thought transmitted
    nothing (any real disclosure is a human act).
    """
    cve = f"CVE {finding.cve}" if finding.cve else "no CVE assigned"
    return (
        f"DRAFT rendering — {cve}; finding status: {finding.status.value}; "
        f"nothing transmitted (Deep Thought emits local artifacts only)."
    )


def _escape(text: object) -> str:
    """Make free-text inert in an HTML-enabled Markdown renderer.

    HTML-escapes ``&``/``<``/``>`` (so ``<script>`` or other raw HTML from a
    hostile finding renders as literal text, never markup) and backslash-escapes
    the Markdown link/image brackets (so ``[x](javascript:…)`` cannot become a
    clickable/executable link). Combined with :func:`_inline` /
    :func:`_blockquote`, finding free-text can neither forge document structure
    nor smuggle active HTML into the human-review draft.
    """
    s = (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return s.replace("[", "\\[").replace("]", "\\]")


def _inline(text: object) -> str:
    """Collapse free-text to a single, escaped, inert line.

    Any embedded newline could otherwise let a value start a new Markdown line
    (e.g. ``"foo\\n## Injected"``), which — placed on a heading or list line —
    would forge a top-level section. Whitespace is collapsed to single spaces and
    the result is escaped, so the value stays an inert data leaf on its own line.
    """
    return _escape(" ".join(str(text).split()))


def _blockquote(text: str) -> str:
    """Render a multi-line block as an inert, escaped Markdown blockquote.

    Every line is prefixed with ``> `` and escaped, so an embedded ``## Heading``
    becomes quoted prose (``> ## Heading``), raw HTML becomes literal text, and
    the document's own section grammar stays fixed.
    """
    lines = str(text).splitlines() or [""]
    return "\n".join(f"> {_escape(line)}" for line in lines)


def finding_to_advisory(finding: "Finding") -> str:
    """Render a Finding as a human-readable, draft-only Markdown advisory.

    All finding free-text is emitted as inert prose values; the fixed section
    headings are always present (except Severity, which is omitted when the
    finding carries no severity) and never displaced by adversarial content.
    """
    # summary is a text value; collapse it to a single inert line for the title
    # (so an embedded newline + "##" cannot forge a heading) and render the
    # Summary body as a blockquote for the same reason.
    parts: list[str] = [f"# Advisory: {_inline(finding.summary)}"]

    parts.append("## Summary")
    parts.append(_blockquote(finding.summary))

    # Omit the whole CVSS block when there is no severity — never fake scores.
    if finding.severity is not None:
        parts.append("## Severity")
        parts.append(f"- CVSS vector: {_inline(finding.severity.cvss_vector)}")
        parts.append(f"- CVSS score: {finding.severity.cvss_score}")

    parts.append("## Affected")
    if finding.affected:
        for pkg in finding.affected:
            versions = (
                ", ".join(_inline(v) for v in pkg.versions)
                if pkg.versions
                else "(unspecified)"
            )
            parts.append(
                f"- {_inline(pkg.ecosystem)}: {_inline(pkg.package)} — versions {versions}"
            )
    else:
        parts.append("- (no affected packages recorded)")

    parts.append("## Details")
    details = _details(finding)
    # ``_details`` scrapes body prose that may itself contain "##" sub-headings
    # (Root cause / Impact) or raw HTML/links. Render it through ``_blockquote``,
    # which escapes each line, so those are carried as inert quoted prose and can
    # never masquerade as a top-level section or active markup.
    if details:
        parts.append(_blockquote(details))
    else:
        parts.append("(no details recorded)")

    impact = (finding.downstream_impact or "").strip()
    if impact:
        parts.append("## Impact")
        parts.append(_blockquote(impact))

    parts.append("## References")
    if finding.references:
        for ref in finding.references:
            parts.append(f"- {_inline(ref.type)}: {_inline(ref.url)}")
    else:
        parts.append("- (no references recorded)")

    disclosure = finding.disclosure
    if disclosure is not None and disclosure.timeline:
        parts.append("## Disclosure timeline")
        for entry in disclosure.timeline:
            parts.append(f"- {_inline(entry.date)}: {_inline(entry.event)}")

    parts.append("## Status")
    parts.append(_status_footer(finding))

    return "\n\n".join(parts) + "\n"
