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


# A disclosure URI must be a clean, whitespace/control-free http(s) URL with an
# authority — matching the SARIF ingest's posture. This refuses active/foreign
# schemes (javascript:, file:, data:, …) so a draft never carries a dangerous link
# into a human-reviewed artifact.
_SAFE_HTTP_URL_RE = re.compile(r"^https?://(?![/?#])[!-~]+$", re.IGNORECASE)


def is_safe_http_url(value: object) -> bool:
    """Whether ``value`` is a clean http(s) URL (no whitespace, safe scheme)."""
    return isinstance(value, str) and bool(_SAFE_HTTP_URL_RE.match(value))


def _is_uri(value: object) -> bool:
    # Only a string is a uri; a non-string is a type error handled by the schema's
    # own "type" keyword. Disclosure uri fields (publisher namespace, references)
    # are web links, so restrict them to safe http(s) — an active scheme like
    # javascript:/file: is refused rather than emitted into a draft.
    if not isinstance(value, str):
        return True
    return is_safe_http_url(value)


def format_checker() -> jsonschema.FormatChecker:
    """A FormatChecker enforcing ``date-time`` and ``uri`` with no extra deps."""
    checker = jsonschema.FormatChecker()
    checker.checks("date-time")(_is_date_time)
    checker.checks("uri")(_is_uri)
    return checker
