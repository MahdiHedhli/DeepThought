"""Typed session implementations. Each does one job."""

from .disclosure import DisclosureSession
from .discover import DiscoverSession
from .map import MapSession
from .new_project import NewProjectSession, derive_project_id
from .sibling_hunt import SiblingHuntSession
from .status import StatusSession

__all__ = [
    "NewProjectSession",
    "StatusSession",
    "MapSession",
    "DiscoverSession",
    "VerifySession",
    "SiblingHuntSession",
    "DisclosureSession",
    "derive_project_id",
]


def __getattr__(name: str):
    # VerifySession is the ONLY session that imports the execution sandbox. Load it
    # lazily so importing this package — e.g. from the autonomous loop, which never
    # verifies — does NOT pull the execution backend into the loop's import closure.
    # The loop's structural hard stop (no target-code execution) then holds at the
    # dependency level, not just at construction. ``from ...sessions import
    # VerifySession`` still works (this resolves it on demand).
    if name == "VerifySession":
        from .verify import VerifySession

        return VerifySession
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
