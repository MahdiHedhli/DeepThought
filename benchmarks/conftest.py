"""Fixtures for the benchmark suite (kept separate from the unit-test conftest)."""

from __future__ import annotations

import pytest


@pytest.fixture
def state_dir(tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    return root
