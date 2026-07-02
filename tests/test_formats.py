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


def test_is_uri_rejects_active_and_foreign_schemes():
    """Only http(s) is a safe disclosure link — active/foreign schemes are refused
    so a draft never carries a dangerous URL into a human-reviewed artifact."""
    for bad in ("javascript:alert(1)", "file:///etc/passwd", "data:text/html,x",
                "ftp://x.test/a", "vbscript:msgbox(1)"):
        assert not _is_uri(bad), bad
