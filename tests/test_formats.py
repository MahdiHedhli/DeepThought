"""005 — the hermetic date-time / uri format checkers used by the draft gate."""

from __future__ import annotations

from deepthought.export._formats import _is_date_time, _is_uri


def test_is_date_time_requires_full_rfc3339():
    assert _is_date_time("2026-07-02T00:00:00Z")
    assert _is_date_time("2026-07-02T00:00:00+00:00")
    assert _is_date_time("2026-07-02T00:00:00.123456Z")
    # Not RFC3339 date-time:
    assert not _is_date_time("2026-07-01")             # date only
    assert not _is_date_time("2026-07-01T12:00:00")    # no timezone
    assert not _is_date_time("not-a-date")
    assert not _is_date_time("2026-13-01T00:00:00Z")   # impossible month


def test_is_uri_rejects_whitespace_and_requires_a_scheme():
    assert _is_uri("https://example.test/a")
    assert _is_uri("http://example.test/a")
    assert not _is_uri("https://exa mple.com")  # embedded space
    assert not _is_uri("not a uri")
    assert not _is_uri("")
    assert not _is_uri("/relative/only")         # no scheme
    assert not _is_uri("https://x.test/\tpath")  # control char


def test_is_uri_rejects_rfc3986_invalid_characters():
    """Characters not valid unescaped in a URI ('"', '<', '>', backtick, etc.) are
    rejected even with an http(s) scheme; valid query/fragment/percent URLs pass."""
    assert _is_uri("https://example.test/a?b=c#d")
    assert _is_uri("https://example.test/a%20b")
    for bad in ('https://example.test/a"bad', "https://example.test/<x>",
                "https://example.test/`x`", "https://example.test/a|b",
                "https://example.test/a{b}"):
        assert not _is_uri(bad), bad


def test_is_uri_accepts_valid_non_http_schemes_incl_purl():
    """The uri format accepts ANY well-formed URI (CSAF's purl uses pkg:), not just
    http(s) — otherwise valid package URLs would fail schema validation."""
    assert _is_uri("pkg:packagist/php/php-src@8.3.0")
    assert _is_uri("pkg:pypi/foo@1.0")
    assert _is_uri("ftp://x.test/a")   # a valid (non-dangerous) URI
    assert _is_uri("urn:uuid:12345")


def test_is_uri_rejects_dangerous_schemes():
    """Active/dangerous schemes are refused even though they are syntactically
    URI-shaped, so a draft never carries an executable link into a review."""
    for bad in ("javascript:alert(1)", "file:///etc/passwd", "data:text/html,x",
                "vbscript:msgbox(1)"):
        assert not _is_uri(bad), bad
