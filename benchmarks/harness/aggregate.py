"""Feature 009 — the aggregate class-manifest.

008 (``contract.py``) makes each PER-CLASS rediscovery number tamper-evident. But the headline
DeepThought figure is an AGGREGATE mean across classes, and 008 does not bind the SET of classes
feeding that mean — so an operator could drop a weak class and report a higher mean with every
surviving per-class attestation still perfectly honest. 009 closes that last code-closable
inflation surface: a committed, monotonic ``ClassManifest`` so the aggregate is a total function of
a git-anchored set, and omitting a class fails closed.

Reuses 008's machinery (``merkle_root`` / ``chain_root`` / ``leaf_hash`` / ed25519 ``verify`` /
``CommittedGenesisState`` / ``advance_committed_root``). Design principles carried from 008's audit
rounds:

* **Run verifications FROM committed state, never from caller arguments (008 R5).** ``certify_aggregate``
  loads ``load_committed_genesis_state()`` INTERNALLY; the scored party cannot substitute their own
  evaluator key / manifest root and self-sign. Tests monkeypatch the loader.
* **Every authorization is COMMITTED, not caller-supplied.** A class may leave the mean only via a
  ``ClassExit`` EMBEDDED in the manifest version that performs the departure — folded into the
  version ``content_hash`` and thus into the git-committed, reproduced manifest root. An unsigned,
  uncommitted caller event log would let an operator fabricate a retirement to drop any class.
* **Bind by an INDEPENDENT committed anchor, not a circular operator-controlled field.** Each class's
  ``head_history_root`` is pinned by the committed per-class registry ``committed.class_registry``;
  every in-mean class MUST be pinned (a class absent from the registry is rejected, not waved
  through). The manifest entry the operator presents cannot re-point a class to a stronger class's
  attestation.
* **Recompute the headline UNCONDITIONALLY** (a guard whose only firing path is the non-empty branch
  fails open on an empty in-mean set).

Article III unchanged: nothing fetched or target-side is executed here.
"""

from __future__ import annotations

from collections import Counter
from enum import Enum
from fractions import Fraction
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from contract import (  # noqa: E402  (008 machinery, reused)
    _CHAIN_GENESIS,
    _EMPTY_ROOT,
    _sha256,
    Attestation,
    ContractReport,
    Report,
    ViolationReason,
    chain_root,
    leaf_hash,
    load_committed_genesis_state,
    merkle_root,
    verify,
)


class ClassStatus(str, Enum):
    """A class's standing in the aggregate. Only ``ACTIVE`` classes feed the mean; every other
    status is a committed, versioned exit from the mean that a ``ClassExit`` must authorize."""

    ACTIVE = "active"
    RETIRED = "retired"
    MERGED = "merged"
    RECLASSED = "reclassed"
    NA = "na"  # scored not-applicable (e.g. a genuine no-detector class): logged, out of the mean


_IN_MEAN: frozenset[ClassStatus] = frozenset({ClassStatus.ACTIVE})


class ClassCorrectionReason(str, Enum):
    """The committed reasons a class may leave the aggregate mean — the class-dimension analogue of a
    008 cohort-correction. A departure with no matching committed ``ClassExit`` is
    ``CLASS_SILENTLY_DROPPED``."""

    RETIRED = "retired"
    MERGED = "merged"
    RECLASSED = "reclassed"
    NA = "na"


class ClassExit(BaseModel):
    """A COMMITTED authorization for one class to leave the aggregate mean at the manifest version it
    is embedded in (the transition parent_version -> this version). Because it is folded into the
    version ``content_hash`` (and thus the git-committed, reproduced manifest root), it cannot be
    fabricated at certify time: a reviewer sees every retirement in git, and the validator only
    accepts a departure that a committed exit authorizes."""

    model_config = ConfigDict(extra="forbid")

    class_id: str
    reason: ClassCorrectionReason


class ClassManifestEntry(BaseModel):
    """One class in scope for the aggregate. ``head_history_root`` is the class's committed 008
    history root; it is PINNED to ``committed.class_registry`` so a per-class attestation is bound to
    its class independently of this operator-presented field."""

    model_config = ConfigDict(extra="forbid")

    class_id: str
    cwe: str
    detector_id: str
    head_history_root: str
    status: ClassStatus = ClassStatus.ACTIVE

    @property
    def leaf(self) -> str:
        return leaf_hash(self.model_dump(mode="json"))


class ClassManifest(BaseModel):
    """One version of the class set. ``exits`` are the COMMITTED departures authorized at this
    version (transition from ``parent_version``). ``manifest_root`` is a domain-separated Merkle root
    over the sorted entry leaves; ``content_hash`` folds version + lineage + leaves + exits, so a
    post-seal edit to any of them (including a fabricated/removed exit) changes it."""

    model_config = ConfigDict(extra="forbid")

    version: str
    entries: list[ClassManifestEntry]
    exits: list[ClassExit] = Field(default_factory=list)
    parent_version: Optional[str] = None
    reason: str = ""

    @model_validator(mode="after")
    def _unique_ids(self) -> "ClassManifest":
        ids = [e.class_id for e in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError("class_id values must be unique within a manifest version")
        exit_ids = [x.class_id for x in self.exits]
        if len(exit_ids) != len(set(exit_ids)):
            raise ValueError("a class may have at most one exit per manifest version")
        return self

    def class_ids(self) -> set[str]:
        return {e.class_id for e in self.entries}

    def active_ids(self) -> set[str]:
        return {e.class_id for e in self.entries if e.status in _IN_MEAN}

    def by_id(self) -> dict[str, ClassManifestEntry]:
        return {e.class_id: e for e in self.entries}

    def exit_ids(self) -> set[str]:
        return {x.class_id for x in self.exits}

    @property
    def manifest_root(self) -> str:
        return merkle_root(sorted(e.leaf for e in self.entries))

    @property
    def content_hash(self) -> str:
        return leaf_hash(
            {
                "version": self.version,
                "parent_version": self.parent_version,
                "reason": self.reason,
                "leaves": sorted(e.leaf for e in self.entries),
                "exits": sorted(leaf_hash(x.model_dump(mode="json")) for x in self.exits),
            }
        )


class ClassManifestHistory(BaseModel):
    """The append-only chain of manifest versions. ``root`` is the prefix fold (``chain_root``) over
    version content hashes — the value bound as ``committed.latest_class_manifest_root``."""

    model_config = ConfigDict(extra="forbid")

    versions: list[ClassManifest] = Field(default_factory=list)

    def latest(self) -> Optional[ClassManifest]:
        return self.versions[-1] if self.versions else None

    @property
    def root(self) -> str:
        return chain_root([v.content_hash for v in self.versions])


class CertifiedClassResult(BaseModel):
    """A per-class certified result feeding the aggregate: the class's 008 ``Attestation`` and the
    ``Report`` it committed (``attestation.report_hash == leaf_hash(report)``)."""

    model_config = ConfigDict(extra="forbid")

    class_id: str
    attestation: Attestation
    report: Report


class AggregateReport(BaseModel):
    """The reported headline: the mean rediscovery rate across the in-mean classes and the class
    count. Both are RECOMPUTED and compared on certify — never trusted. ``mean`` is a bounded finite
    rate (no inf/nan)."""

    model_config = ConfigDict(extra="forbid")

    mean: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    n_classes: int = Field(ge=0)


def _manifest_reproduces_committed(history: ClassManifestHistory, committed_root: str) -> bool:
    """009 (parity with 008's ledger-reproduction): True iff some prefix of the presented manifest
    chain reproduces the committed ``latest_class_manifest_root`` — i.e. the presented history is
    exactly the committed prior manifest plus zero-or-more appended versions. So an operator cannot
    present a fresh, shorter manifest that silently omits a committed class. Bootstrap: an EMPTY
    committed root is reproduced by the empty prefix; truncation protection engages once a real
    committed baseline exists."""
    running = _CHAIN_GENESIS
    if running == committed_root:
        return True
    for version in history.versions:
        running = _sha256(running + version.content_hash)
        if running == committed_root:
            return True
    return False


def _check_manifest_preservation(history: ClassManifestHistory, report: ContractReport) -> None:
    """A class may leave the aggregate mean two ways — REMOVED from the manifest, or its status
    changed OUT of the in-mean set while kept. BOTH must be authorized by a COMMITTED ``ClassExit``
    embedded in the version that performs the departure. Adjacent-pair check (the exit lives on the
    successor version) + a TERMINAL-HEAD resurrection guard: a class ever in the mean that is not in
    the head mean must have at least one committed exit for it somewhere in the manifest, so a split
    remove-then-readd cannot launder a drop."""
    for prev, curr in zip(history.versions, history.versions[1:]):
        removed = prev.class_ids() - curr.class_ids()
        left_mean = prev.active_ids() - curr.active_ids()
        authorized = curr.exit_ids()  # committed exits recorded on the successor version
        for class_id in sorted(removed | left_mean):
            if class_id not in authorized:
                report.add(
                    ViolationReason.CLASS_SILENTLY_DROPPED,
                    f"{prev.version}->{curr.version}: class {class_id!r} left the aggregate mean "
                    "(removed or status-downgraded) with no committed ClassExit on the successor version",
                )
    head = history.latest()
    if head is not None:
        ever_in_mean: set[str] = set()
        exits_anywhere: set[str] = set()
        for v in history.versions:
            ever_in_mean |= v.active_ids()
            exits_anywhere |= v.exit_ids()
        head_active = head.active_ids()
        head_present = head.class_ids()
        for class_id in sorted(ever_in_mean):
            if class_id not in head_active and class_id not in exits_anywhere:
                report.add(
                    ViolationReason.CLASS_SILENTLY_DROPPED,
                    f"class {class_id!r} was in the aggregate mean earlier and is not in the head mean "
                    f"(present={class_id in head_present}) with no committed ClassExit anywhere in the manifest",
                )


def certify_aggregate(
    *,
    manifest: ClassManifestHistory,
    results: list[CertifiedClassResult],
    aggregate: AggregateReport,
) -> ContractReport:
    """Certify an aggregate mean over the committed class set. The committed trust anchor is loaded
    INTERNALLY (never a caller argument — 008 R5): the scored party cannot substitute the evaluator
    key or the manifest/registry. Fails closed (a typed ``ContractReport``) unless:

    * the presented manifest reproduces + append-only-extends the committed manifest root
      (``CLASS_MANIFEST_TRUNCATED``);
    * every class that left the mean did so via a committed ``ClassExit`` (``CLASS_SILENTLY_DROPPED``);
    * every in-mean head class has a present per-class result (``CLASS_ATTESTATION_MISSING``);
    * every in-mean class is PINNED in the committed registry and its manifest entry matches the pin;
      each result carries a signature verifying against the committed evaluator key, the committed
      evaluator id, and a ``report_hash`` reproducing its report (``CLASS_ATTESTATION_INVALID``);
    * the reported mean + class count RECOMPUTE exactly over the in-mean head classes
      (``AGGREGATE_UNVERIFIED``).

    Pure: no file writes. On a clean report the harness advances the committed root via
    ``advance_committed_root(class_manifest_root=manifest.root)``."""
    report = ContractReport()
    committed = load_committed_genesis_state()  # 008 R5: committed state, never a caller arg
    registry = committed.class_registry

    # 1. committed-monotonic reproduction.
    if not _manifest_reproduces_committed(manifest, committed.latest_class_manifest_root):
        report.add(
            ViolationReason.CLASS_MANIFEST_TRUNCATED,
            "presented class-manifest does not reproduce + append-only-extend the committed "
            f"class_manifest_root {committed.latest_class_manifest_root[:12]}",
        )

    # 2. no class leaves the mean without a committed exit.
    _check_manifest_preservation(manifest, report)

    head = manifest.latest()
    if head is None:
        report.add(ViolationReason.CLASS_MANIFEST_TRUNCATED, "no manifest version presented")
        return report

    head_entries = head.by_id()
    head_active = head.active_ids()

    # 3 + 4. every in-mean head class has exactly one valid, registry-pinned, bound result.
    results_by_class: dict[str, CertifiedClassResult] = {}
    for r in results:
        if r.class_id in results_by_class:
            report.add(ViolationReason.CLASS_ATTESTATION_INVALID, f"class {r.class_id!r} has more than one presented result")
            continue
        results_by_class[r.class_id] = r
        if r.class_id not in head_active:
            report.add(ViolationReason.CLASS_ATTESTATION_INVALID, f"result for class {r.class_id!r} not an in-mean head class")

    # REAUDIT-009: the pin is MANDATORY once a real committed manifest baseline exists — NOT merely
    # when the registry is non-empty. advance_committed_root advances latest_class_manifest_root to
    # non-empty on a successful certify while never writing the registry, so gating the pin on
    # ``if registry`` left a reachable state (real committed manifest, empty registry) where the
    # re-point swap silently worked. Once the committed manifest root is non-empty the baseline claims
    # to be binding, so every in-mean class MUST be pinned; the ONLY pin-free window is the true
    # bootstrap (committed manifest root still empty AND no registry) — the genesis-completeness floor.
    baseline_committed = committed.latest_class_manifest_root != _EMPTY_ROOT
    require_pin = baseline_committed or bool(registry)
    for class_id in sorted(head_active):
        entry = head_entries[class_id]
        if require_pin:
            pinned = registry.get(class_id)
            if pinned is None:
                report.add(
                    ViolationReason.CLASS_ATTESTATION_INVALID,
                    f"in-mean class {class_id!r} is not pinned in the committed class registry "
                    "(a registry pin is mandatory once a committed manifest baseline exists)",
                )
            elif entry.head_history_root != pinned:
                report.add(
                    ViolationReason.CLASS_ATTESTATION_INVALID,
                    f"class {class_id!r}: manifest head_history_root is not the committed class-registry value",
                )
        r = results_by_class.get(class_id)
        if r is None:
            report.add(ViolationReason.CLASS_ATTESTATION_MISSING, f"in-mean head class {class_id!r} has no present per-class attestation")
            continue
        att = r.attestation
        if att.history_root != entry.head_history_root:
            report.add(ViolationReason.CLASS_ATTESTATION_INVALID, f"class {class_id!r}: attestation history_root is not this class's head_history_root")
        if att.report_hash != leaf_hash(r.report.model_dump(mode="json")):
            report.add(ViolationReason.CLASS_ATTESTATION_INVALID, f"class {class_id!r}: presented report does not reproduce the attested report_hash")
        if att.evaluator_id != committed.evaluator_id:
            report.add(ViolationReason.CLASS_ATTESTATION_INVALID, f"class {class_id!r}: attestation evaluator_id {att.evaluator_id!r} != committed evaluator")
        if not verify(att.attestation_root, att.signature, committed.verify_key):
            report.add(ViolationReason.CLASS_ATTESTATION_INVALID, f"class {class_id!r}: attestation signature does not verify against the committed evaluator key")

    # 5. RECOMPUTE the headline UNCONDITIONALLY; never trust it.
    if aggregate.n_classes != len(head_active):
        report.add(
            ViolationReason.AGGREGATE_UNVERIFIED,
            f"reported n_classes {aggregate.n_classes} != in-mean head class count {len(head_active)}",
        )
    if not head_active:
        if abs(aggregate.mean - 0.0) > 1e-9:
            report.add(
                ViolationReason.AGGREGATE_UNVERIFIED,
                f"reported mean {aggregate.mean} over ZERO in-mean classes must be 0.0 (no rates to average)",
            )
    elif all(c in results_by_class for c in head_active):
        rates = [
            Fraction(results_by_class[c].report.blind_recall.rediscovered, results_by_class[c].report.blind_recall.total)
            if results_by_class[c].report.blind_recall.total > 0
            else Fraction(0)
            for c in sorted(head_active)
        ]
        mean_frac = sum(rates, Fraction(0)) / len(rates)
        if abs(float(mean_frac) - aggregate.mean) > 1e-9:
            report.add(
                ViolationReason.AGGREGATE_UNVERIFIED,
                f"reported mean {aggregate.mean} != recomputed mean {float(mean_frac):.12f} over {len(head_active)} in-mean classes",
            )
    # else: an in-mean class is missing its result (CLASS_ATTESTATION_MISSING already fired).

    return report
