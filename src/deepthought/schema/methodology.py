"""Methodology record — versioned reference data, not code.

Sessions cite a methodology by id and version so scoring is reproducible.
Examples: the severity rubric, the impact-statement template.
"""

from __future__ import annotations

from .common import Record, RecordId


class Methodology(Record):
    id: RecordId
    purpose: str
    version: str
