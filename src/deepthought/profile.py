"""Profiles — opt-in, purely-ergonomic CLI configuration (feature 007).

A :class:`Profile` is **frozen data**. It fills UNSET CLI defaults and trims
purely-informational display; it is fed to the *same* unchanged gate as ordinary
input and changes no authorization decision, no scope, no execution posture, and
no transmission boundary. It is resolved per invocation from ``--profile`` /
``DEEPTHOUGHT_PROFILE`` (mirroring the ``DEEPTHOUGHT_STATE`` precedent) and is
**never written to a Project record** — no project silently carries low-ceremony
defaults (Constitution VI, IX).

Defined by what it refuses to carry as much as by what it streamlines (see
``specs/007-mostly-harmless/threat-model.md``):

* **No scope field.** The profile never writes, defaults, or widens a
  ``scope_allowlist``; an empty scope stays a gate HOLD (FR-5, RT F1.1).
* **No authorization basis.** The profile adds no ``AuthorizationBasis`` member
  and never supplies, guesses, or defaults a basis (FR-6, RT F1.2/F1.3).
* **No output/state path.** The profile carries no ``state_path`` or output
  directory; the physical location of drafts is the Article V machine boundary,
  not a convenience knob (FR-10, RT F3.1).
* **No sandbox / execution field.** The profile confers zero execution privilege
  and this module imports no executing backend (FR-8, RT F2.2).
"""

from __future__ import annotations

from dataclasses import dataclass, fields

from .schema import AuthorizationBasis
from .schema.loop import LoopBudget

#: The name of the shipped low-friction profile.
MOSTLY_HARMLESS = "mostly_harmless"

#: The env var that activates a profile, mirroring ``DEEPTHOUGHT_STATE``.
PROFILE_ENV_VAR = "DEEPTHOUGHT_PROFILE"

# The low-ceremony bases are exactly the no-reference bases. ``scoped_engagement``
# is NEVER low-ceremony — it always needs an ``authorization_ref``. This frozenset
# is DESCRIPTIVE data used only by introspection; the profile NEVER supplies,
# guesses, or defaults a basis (FR-6). The unchanged gate remains the sole
# authority on the authorization basis.
_LOW_CEREMONY_BASES = frozenset(
    {AuthorizationBasis.own_code, AuthorizationBasis.permissive_oss}
)


class UnknownProfileError(ValueError):
    """Raised when a requested profile name is not in the registry."""


@dataclass(frozen=True)
class Profile:
    """A frozen, opt-in bundle of purely-ergonomic CLI defaults.

    Every field either fills an UNSET CLI default (``default_loop_budget``,
    ``default_root_from_local_path``) or trims purely-informational display
    (``terse_output``). No field can change a gate decision,
    write scope, default a basis, choose an output path, or register a session
    kind. ``low_ceremony_bases`` is descriptive-only (used by ``profiles``).
    """

    name: str
    low_ceremony_bases: frozenset[AuthorizationBasis]
    default_loop_budget: LoopBudget
    terse_output: bool = False
    default_root_from_local_path: bool = False

    def __post_init__(self) -> None:
        # Defense in depth: scoped_engagement can never be a low-ceremony basis
        # (it always requires an authorization_ref). Even the descriptive field
        # may not imply otherwise.
        if AuthorizationBasis.scoped_engagement in self.low_ceremony_bases:
            raise ValueError("scoped_engagement is never a low-ceremony basis")


# The shipped profile. Its loop budget is finite on every limit (never all-None),
# so the loop stays bounded and frozen even when run flag-free (FR-3). Magnitudes
# are the spec's conservative starting point (spec Open question 2).
_MOSTLY_HARMLESS = Profile(
    name=MOSTLY_HARMLESS,
    low_ceremony_bases=_LOW_CEREMONY_BASES,
    default_loop_budget=LoopBudget(
        max_sessions=25,
        max_wall_seconds=1800.0,
        max_context_tokens=200000,
    ),
    terse_output=True,
    default_root_from_local_path=True,
)

# The registry. Resolution is per-invocation; a profile is never persisted.
_REGISTRY: dict[str, Profile] = {_MOSTLY_HARMLESS.name: _MOSTLY_HARMLESS}


def available_profiles() -> tuple[Profile, ...]:
    """Every registered profile, in a stable order (for introspection)."""
    return tuple(_REGISTRY[name] for name in sorted(_REGISTRY))


def profile_fields(profile: Profile) -> tuple[str, ...]:
    """The Profile's declared field names — used by the audit introspection."""
    return tuple(f.name for f in fields(profile))


def resolve_profile(name: str | None) -> Profile | None:
    """Resolve a profile name to a frozen :class:`Profile`, or ``None``.

    ``None`` (or an empty/whitespace name — e.g. ``DEEPTHOUGHT_PROFILE=``) means
    default mode: today's behavior, byte-for-byte (FR-1, FR-13). An unrecognised
    name raises :class:`UnknownProfileError`.
    """
    if name is None:
        return None
    name = name.strip()
    if not name:
        return None
    try:
        return _REGISTRY[name]
    except KeyError:
        available = ", ".join(sorted(_REGISTRY)) or "(none)"
        raise UnknownProfileError(
            f"unknown profile {name!r}; available: {available}"
        ) from None
