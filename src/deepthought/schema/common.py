"""Shared primitives for the canonical schema.

Every state record is Markdown with YAML front-matter: structured fields in the
front-matter, human narrative in the body. ``Record`` is the base that both
serializes a model to that on-disk form and validates front-matter back into a
model on every read. Front-matter is validated against these Pydantic models on
read; a malformed record fails ``check``.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Annotated

import yaml
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

# A record file is exactly: a YAML front-matter block delimited by --- lines,
# then a Markdown body. The body may itself be empty.
_FRONT_MATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z", re.DOTALL)

# A record id is used VERBATIM as a filename (e.g. ``findings/<id>.md``), so it
# must be a single safe path segment: it starts and ends with an alphanumeric and
# in between allows only ``._-``. This forbids path separators, ``..``/``.``,
# whitespace, control characters, and leading/trailing punctuation — so a crafted
# id can never traverse out of the store or collide with a special name. Bounded
# to 128 chars to stay a valid filename. (Existing ids — ``F-0007``, ``php-src``,
# ``S-2026-07-02-0001`` — all conform.)
_SAFE_ID_PATTERN = r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$"
RecordId = Annotated[str, StringConstraints(pattern=_SAFE_ID_PATTERN)]

# The longest string _SAFE_ID_PATTERN accepts (1 + 126 + 1). A derived id is
# bounded to this so it stays a valid filename and a valid RecordId.
_SAFE_ID_MAXLEN = 128
_UNSAFE_ID_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def safe_record_id(raw: str, *, fallback: str) -> str:
    """Coerce an arbitrary string into a value that matches ``_SAFE_ID_PATTERN``.

    Any id we *derive* (e.g. a project id from a repo tail) feeds straight into a
    ``RecordId`` field, so it must be a single safe path segment or the model
    refuses to construct. This replaces every unsafe run with ``-``, trims the
    leading/trailing punctuation the pattern forbids, and bounds the length —
    returning ``fallback`` (which must itself be a valid id) when nothing safe
    remains. The output is guaranteed to satisfy ``_SAFE_ID_PATTERN``.
    """
    slug = _UNSAFE_ID_CHARS.sub("-", raw).strip("._-")[:_SAFE_ID_MAXLEN].strip("._-")
    return slug or fallback


class RecordError(ValueError):
    """Raised when a record cannot be parsed from its on-disk form."""


def utcnow() -> datetime:
    """Timezone-aware current time in UTC."""
    return datetime.now(timezone.utc)


def iso_z(value: datetime) -> str:
    """Format a datetime as the OSV / RFC3339 ``...Z`` form.

    OSV pins timestamps to ``YYYY-MM-DDTHH:MM:SS(.ffffff)?Z``. We normalise any
    aware datetime to UTC and render the ``Z`` suffix rather than ``+00:00``.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    if value.microsecond:
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def split_front_matter(text: str) -> tuple[str, str]:
    """Split a record file into (front-matter YAML, body Markdown)."""
    match = _FRONT_MATTER.match(text)
    if not match:
        raise RecordError("record is missing a YAML front-matter block")
    return match.group(1), match.group(2).strip()


class Record(BaseModel):
    """Base for every persisted record.

    Front-matter is the model fields minus ``body``. ``extra='forbid'`` means an
    unknown front-matter key is a validation error, so a corrupted record is
    caught on read rather than silently ignored.
    """

    model_config = ConfigDict(extra="forbid")

    body: str = Field(default="", description="Human narrative Markdown body.")

    def front_matter(self) -> dict:
        return self.model_dump(mode="json", exclude={"body"}, exclude_none=True)

    def to_markdown(self) -> str:
        dumped = yaml.safe_dump(
            self.front_matter(),
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
        ).rstrip("\n")
        body = self.body.strip()
        if body:
            return f"---\n{dumped}\n---\n\n{body}\n"
        return f"---\n{dumped}\n---\n"

    @classmethod
    def from_markdown(cls, text: str):
        fm_text, body = split_front_matter(text)
        try:
            data = yaml.safe_load(fm_text)
        except yaml.YAMLError as exc:  # pragma: no cover - passthrough
            raise RecordError(f"front-matter is not valid YAML: {exc}") from exc
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise RecordError("front-matter must be a mapping")
        data = dict(data)
        data["body"] = body
        return cls.model_validate(data)


class ContextCost(BaseModel):
    """Cost accounting shared by sessions and worker envelopes."""

    model_config = ConfigDict(extra="forbid")

    tokens: int = 0
    wall_seconds: float = 0.0
