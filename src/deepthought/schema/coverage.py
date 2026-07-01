"""Coverage record — what surface was looked at, how, and how deeply."""

from __future__ import annotations

from enum import Enum

from .common import Record


class CoverageMethod(str, Enum):
    read = "read"
    static = "static"
    fuzz = "fuzz"
    manual = "manual"


class CoverageDepth(str, Enum):
    touched = "touched"
    explored = "explored"
    exhausted = "exhausted"


class Coverage(Record):
    project: str
    area: str
    method: CoverageMethod
    depth: CoverageDepth
    last_session: str

    @property
    def ref(self) -> str:
        """The ``<project-id>/<area-id>`` path this record lives at."""
        return f"{self.project}/{self.area}"
