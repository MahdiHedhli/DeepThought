"""Finding -> human-readable Markdown advisory (DRAFT-only).

The advisory is a draft artifact: it renders every finding section as inert
Markdown prose, never fabricates a CVE, and carries a fixed DRAFT footer so it
can never be mistaken for a transmitted disclosure. Adversarial free-text is
carried only as literal string values and must not break section structure.
"""

from __future__ import annotations

from deepthought.export.advisory import finding_to_advisory

from .conftest import make_finding

# The load-bearing, status-agnostic part of the DRAFT footer.
DRAFT_FOOTER = "nothing transmitted (Deep Thought emits local artifacts only)."


def test_renders_all_expected_sections():
    md = finding_to_advisory(make_finding())
    finding = make_finding()

    assert md.startswith(f"# Advisory: {finding.summary}")
    assert "## Summary" in md
    assert finding.summary in md
    assert "## Severity" in md
    assert finding.severity.cvss_vector in md
    assert str(finding.severity.cvss_score) in md
    assert "## Affected" in md
    assert "Packagist" in md
    assert "php/php-src" in md
    assert "8.3.0" in md
    assert "8.3.1" in md
    assert "## Details" in md
    assert "Root cause" in md
    assert "## References" in md
    assert "advisory" in md
    assert "https://example.test/advisory/1" in md
    assert "## Status" in md


def test_omits_severity_section_when_severity_none():
    md = finding_to_advisory(make_finding(severity=None))
    assert "## Severity" not in md
    # the rest of the document is still rendered
    assert "## Summary" in md
    assert "## Affected" in md
    assert "## Status" in md


def test_includes_draft_status_footer_verbatim():
    md = finding_to_advisory(make_finding())
    assert "## Status" in md
    assert DRAFT_FOOTER in md


def _top_level_headings(md: str) -> list[str]:
    """The document's own section headings (lines that are exactly a heading).

    ``_details`` re-emits body sub-headings like ``## Impact`` as inert prose
    inside the Details block, so a bare substring check would confuse those with
    the document's own top-level Impact section. Restrict to standalone lines.
    """
    return [line for line in md.splitlines() if line.startswith("## ")]


def test_impact_section_rendered_and_omitted():
    with_impact = finding_to_advisory(
        make_finding(downstream_impact="Fleet-wide RCE across managed hosts.")
    )
    assert "## Impact" in _top_level_headings(with_impact)
    assert "Fleet-wide RCE across managed hosts." in with_impact

    without_impact = finding_to_advisory(make_finding(downstream_impact=None))
    assert "## Impact" not in _top_level_headings(without_impact)


def test_disclosure_timeline_rendered_when_present():
    md = finding_to_advisory(
        make_finding(
            disclosure={
                "timeline": [
                    {"date": "2026-06-01", "event": "Reported to vendor"},
                    {"date": "2026-06-15", "event": "Vendor acknowledged"},
                ]
            }
        )
    )
    assert "## Disclosure timeline" in md
    assert "2026-06-01" in md
    assert "Reported to vendor" in md
    assert "Vendor acknowledged" in md


def test_disclosure_timeline_omitted_when_absent():
    md = finding_to_advisory(make_finding(disclosure=None))
    assert "## Disclosure timeline" not in md


def test_injection_inertness():
    adversarial_summary = 'X </script> {"$ref":"y"}'
    md = finding_to_advisory(
        make_finding(
            summary=adversarial_summary,
            body="## Root cause\n../../etc/passwd\n",
        )
    )

    # Raw HTML is neutralized (escaped), never emitted as active markup.
    assert "</script>" not in md
    assert "&lt;/script&gt;" in md
    # Non-HTML prose is still carried literally.
    assert "../../etc/passwd" in md

    # the fixed section structure survives — all headings still present
    for heading in (
        "## Summary",
        "## Severity",
        "## Affected",
        "## Details",
        "## References",
        "## Status",
    ):
        assert heading in md, heading
    # the escaped summary is on the title line
    assert md.startswith('# Advisory: X &lt;/script&gt; {"$ref":"y"}')

    # the DRAFT footer marker is intact
    assert DRAFT_FOOTER in md


def test_advisory_defuses_markdown_links_in_free_text():
    """A finding summary carrying a Markdown link with a javascript: target must
    NOT render as a clickable link — the brackets are escaped."""
    md = finding_to_advisory(make_finding(summary="click [here](javascript:alert(1))"))
    assert "[here](javascript:" not in md
    assert "\\[here\\]" in md


def test_advisory_body_details_are_escaped_too():
    """The Details block (scraped body prose) is escaped like every other free
    text — raw HTML in the body must not become active markup."""
    md = finding_to_advisory(
        make_finding(body="## Root cause\n<img src=x onerror=alert(1)>\n")
    )
    assert "<img" not in md
    assert "&lt;img" in md


def test_summary_with_embedded_heading_cannot_forge_a_section():
    """A summary carrying a newline + Markdown heading must NOT become a real
    top-level section: it is collapsed onto the title line and quoted in the
    Summary body, so no forged heading appears."""
    md = finding_to_advisory(make_finding(summary="benign\n## INJECTED SECTION\n- x"))
    assert not any(
        line.lstrip().startswith("## INJECTED") for line in md.splitlines()
    )
    assert "INJECTED SECTION" in md  # still carried, inertly
    assert md.startswith("# Advisory: benign ## INJECTED SECTION - x")
    assert "## Summary" in md and "## Status" in md


def test_status_footer_reflects_the_finding_status_and_cve():
    """The footer is not hardcoded to verified/no-CVE: for a disclosed finding it
    names the real CVE and status (so a rendered disclosed/patched advisory does
    not misstate its state), while always asserting nothing was transmitted."""
    md = finding_to_advisory(make_finding(status="disclosed", cve="CVE-2026-12345"))
    assert "CVE CVE-2026-12345" in md
    assert "finding status: disclosed" in md
    assert "nothing transmitted" in md
    # And the verified/no-CVE case reads accordingly.
    md2 = finding_to_advisory(make_finding(status="verified", cve=None))
    assert "no CVE assigned" in md2 and "finding status: verified" in md2
