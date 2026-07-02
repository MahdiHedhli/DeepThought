"""Autonomous loop — a deterministic, bounded, gated driver over the sessions.

The loop cannot expand its own scope, execute target code, or transmit disclosure
(Constitution Articles IX, III, V); it advances the safe, read-only, draft-only
work up to those hard-stop boundaries and escalates them to a human. See
``specs/006-autonomous-loop``.
"""

from __future__ import annotations

from .budget import LoopBudget, LoopSpend
from .driver import generate_loop_run_id, run_loop
from .policy import select_next_action

__all__ = [
    "LoopBudget",
    "LoopSpend",
    "run_loop",
    "generate_loop_run_id",
    "select_next_action",
]
