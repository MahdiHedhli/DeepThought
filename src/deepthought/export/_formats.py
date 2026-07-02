"""A hermetic jsonschema ``FormatChecker`` for the disclosure validators.

``jsonschema`` treats ``format`` as an annotation and only enforces it when a
``FormatChecker`` is supplied — and its built-in checker does NOT cover
``date-time`` or ``uri`` (those need optional third-party packages). The
disclosure ``check`` gate claims schema conformance for persisted CSAF/CVE
drafts, so a corrupted draft with a non-date timestamp or a non-URI namespace
must be caught. This module registers dependency-free ``date-time`` and ``uri``
checkers so validation stays offline and total.
"""

from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlparse

import jsonschema

# RFC3339 date-time: full date + 'T' + time + a timezone (Z or +/-hh:mm). This is
# stricter than datetime.fromisoformat, which also accepts a bare date or a
# timezone-less time — neither of which satisfies JSON Schema's date-time format.
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)


def _is_date_time(value: object) -> bool:
    # Only a string can be a date-time; a non-string is a type error handled by
    # the schema's own "type" keyword, so treat it as conformant here.
    if not isinstance(value, str):
        return True
    if not _RFC3339_RE.match(value):
        return False
    try:
        # Confirm the component VALUES are real (e.g. month <= 12), not just shaped.
        datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
        return True
    except ValueError:
        return False


# A disclosure URI must be a clean http(s) URL with an authority, built ONLY from
# RFC3986-valid characters (unreserved + reserved gen-/sub-delims + percent). This
# refuses active/foreign schemes (javascript:, file:, data:, …) AND stray
# characters that are not valid unescaped in a URI ('"', '<', '>', space, '{', '}',
# '\\', '^', '`', '|'), so a draft never carries a broken or dangerous link into a
# human-reviewed artifact.
_SAFE_HTTP_URL_RE = re.compile(
    r"^https?://(?![/?#])[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$", re.IGNORECASE
)


def is_safe_http_url(value: object) -> bool:
    """Whether ``value`` is a clean http(s) URL (no whitespace, safe scheme)."""
    return isinstance(value, str) and bool(_SAFE_HTTP_URL_RE.match(value))


# The ``uri`` FORMAT applies to every uri field in the schemas — including CSAF's
# ``purl`` (a ``pkg:`` Package-URL), not just http(s) links — so this checker must
# accept ANY well-formed RFC3986 URI, rejecting only malformed ones (whitespace /
# stray characters / no scheme) and a denylist of active/dangerous schemes. The
# http(s)-only restriction for *reference* links lives in the exporters
# (``is_safe_http_url``), which is where a dangerous link would be emitted.
_DANGEROUS_URI_SCHEMES = frozenset({"javascript", "data", "vbscript", "file"})
_URI_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.\-]*:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$"
)


def _is_uri(value: object) -> bool:
    # Only a string is a uri; a non-string is a type error handled by the schema's
    # own "type" keyword.
    if not isinstance(value, str):
        return True
    if not _URI_RE.match(value):
        return False
    scheme = value.split(":", 1)[0].lower()
    return scheme not in _DANGEROUS_URI_SCHEMES


def format_checker() -> jsonschema.FormatChecker:
    """A FormatChecker enforcing ``date-time`` and ``uri`` with no extra deps."""
    checker = jsonschema.FormatChecker()
    checker.checks("date-time")(_is_date_time)
    checker.checks("uri")(_is_uri)
    return checker
