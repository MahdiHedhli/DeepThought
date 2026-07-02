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


def _is_uri(value: object) -> bool:
    if not isinstance(value, str):
        return True
    # A URI cannot contain whitespace or control characters (urlparse would still
    # accept "https://exa mple.com"); reject those before the structural check.
    if not value or any(c.isspace() or ord(c) < 0x20 for c in value):
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    # A URI needs a scheme and some hierarchical/opaque part.
    return bool(parsed.scheme) and bool(parsed.netloc or parsed.path)


def format_checker() -> jsonschema.FormatChecker:
    """A FormatChecker enforcing ``date-time`` and ``uri`` with no extra deps."""
    checker = jsonschema.FormatChecker()
    checker.checks("date-time")(_is_date_time)
    checker.checks("uri")(_is_uri)
    return checker
