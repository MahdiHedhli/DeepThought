"""LoopBudget & LoopSpend — the autonomous loop's limit awareness (feature 006).

The definitions live in ``schema.loop`` (they are field types of the ``LoopRun``
record) so the schema layer never depends on the loop package — the loop depends
on schema, not the reverse, which keeps the import graph acyclic. This module is
the loop-package home the contract names; it simply re-exports them.
"""

from __future__ import annotations

from ..schema.loop import LoopBudget, LoopSpend

__all__ = ["LoopBudget", "LoopSpend"]
