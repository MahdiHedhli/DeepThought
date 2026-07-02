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

from datetime import datetime
from urllib.parse import urlparse

import jsonschema


def _is_date_time(value: object) -> bool:
    # Only a string can be a date-time; a non-string is a type error handled by
    # the schema's own "type" keyword, so treat it as conformant here.
    if not isinstance(value, str):
        return True
    try:
        # Accept RFC3339/ISO-8601, including a trailing 'Z'.
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _is_uri(value: object) -> bool:
    if not isinstance(value, str):
        return True
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
