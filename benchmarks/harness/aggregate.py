"""Feature 009 — the aggregate class-manifest.

008 (``contract.py``) makes each PER-CLASS rediscovery number tamper-evident. But the headline
DeepThought figure is an AGGREGATE mean across classes, and 008 does not bind the SET of classes
feeding that mean — so an operator could drop a weak class and report a higher mean with every
surviving per-class attestation still perfectly honest. 009 closes that last code-closable
inflation surface: a committed, monotonic ``ClassManifest`` so the aggregate is a total function of
a git-anchored set, and omitting a class fails closed.

Reuses 008's machinery (``merkle_root`` / ``chain_root`` / ``leaf_hash`` / ed25519 ``verify`` /
``CommittedGenesisState`` / ``advance_committed_root``) rather than re-implementing it. The manifest
root is COMMITTED monotonic state (parity with history/evaluation/exposure): the presented manifest
must reproduce + append-only-extend ``committed.latest_class_manifest_root``.

Lessons carried from 008's audit rounds: a class can leave the aggregate two ways — removed from the
manifest, OR its status changed out of the in-mean set — and BOTH must be authorized by a matched,
logged, versioned ``ClassManifestEvent`` (bind to the STRUCTURAL transition, not a label); the
guard holds against the TERMINAL head, not just the adjacent successor, so a split
remove-then-readd cannot launder a drop; every per-class result is bound to its manifest entry by
the class's committed 008 history root (so a high-scoring class's attestation cannot be swapped onto
a weak class's slot); and the reported mean is RECOMPUTED (never trusted) as an exact fraction.

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
    CommittedGenesisState,
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
    status is a LOGGED, versioned exit from the mean that a ``ClassManifestEvent`` must authorize."""

    ACTIVE = "active"
    RETIRED = "retired"
    MERGED = "merged"
    RECLASSED = "reclassed"
    NA = "na"  # scored not-applicable (e.g. a genuine no-detector class): logged, out of the mean


_IN_MEAN: frozenset[ClassStatus] = frozenset({ClassStatus.ACTIVE})


class ClassManifestEntry(BaseModel):
    """One class in scope for the aggregate. ``head_history_root`` is the class's committed 008
    history root — the binding that ties a per-class attestation to THIS class's slot, so a
    high-scoring class's signed attestation cannot be presented for a weak class."""

    model_config = ConfigDict(extra="forbid")

    class_id: str
    cwe: str
    detector_id: str
    head_history_root: str  # the class's committed 008 CohortHistory.root (binds its attestation)
    status: ClassStatus = ClassStatus.ACTIVE

    @property
    def leaf(self) -> str:
        return leaf_hash(self.model_dump(mode="json"))


class ClassManifest(BaseModel):
    """One version of the class set. ``manifest_root`` is a domain-separated Merkle root over the
    sorted entry leaves (008 R10-7 scheme via ``merkle_root``); ``content_hash`` folds version +
    lineage + leaves for the append-only chain, so a post-seal lineage edit changes it."""

    model_config = ConfigDict(extra="forbid")

    version: str
    entries: list[ClassManifestEntry]
    parent_version: Optional[str] = None
    reason: str = ""

    @model_validator(mode="after")
    def _unique_class_ids(self) -> "ClassManifest":
        ids = [e.class_id for e in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError("class_id values must be unique within a manifest version")
        return self

    def class_ids(self) -> set[str]:
        return {e.class_id for e in self.entries}

    def active_ids(self) -> set[str]:
        return {e.class_id for e in self.entries if e.status in _IN_MEAN}

    def by_id(self) -> dict[str, ClassManifestEntry]:
        return {e.class_id: e for e in self.entries}

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


class ClassCorrectionReason(str, Enum):
    """The logged reasons a class may leave the aggregate mean — the class-dimension analogue of a
    008 cohort-correction. A silent departure (no event) is a ``CLASS_SILENTLY_DROPPED``."""

    RETIRED = "retired"
    MERGED = "merged"
    RECLASSED = "reclassed"
    NA = "na"


class ClassManifestEvent(BaseModel):
    """Authorizes ONE class leaving the aggregate at ONE exact ``(class_id, from, to)`` transition.
    Consumed per transition, so a stale event cannot launder a later departure."""

    model_config = ConfigDict(extra="forbid")

    class_id: str
    reason: ClassCorrectionReason
    from_version: str
    to_version: str


class ClassManifestLog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[ClassManifestEvent] = Field(default_factory=list)

    def transitions(self) -> "Counter[tuple[str, str, str]]":
        return Counter((e.class_id, e.from_version, e.to_version) for e in self.events)


class CertifiedClassResult(BaseModel):
    """A per-class certified result feeding the aggregate: the class's 008 ``Attestation`` and the
    ``Report`` it commits (``attestation.report_hash == leaf_hash(report)``)."""

    model_config = ConfigDict(extra="forbid")

    class_id: str
    attestation: Attestation
    report: Report


class AggregateReport(BaseModel):
    """The reported headline: the mean rediscovery rate across the in-mean classes and the class
    count. Both are RECOMPUTED and compared on certify — never trusted."""

    model_config = ConfigDict(extra="forbid")

    mean: float
    n_classes: int


def _manifest_reproduces_committed(history: ClassManifestHistory, committed_root: str) -> bool:
    """009 (parity with ``_exposure_reproduces_committed``): True iff some prefix of the presented
    manifest chain reproduces the committed ``latest_class_manifest_root`` — i.e. the presented
    history is exactly the committed prior manifest plus zero-or-more appended versions. So an
    operator cannot present a fresh, shorter manifest that silently omits a committed class: the
    committed prefix must fold in, and every departure from it onward needs a logged event.

    Bootstrap: an EMPTY committed root (no committed manifest baseline yet) is reproduced by the
    empty prefix, which any presented history extends; truncation protection engages once a real
    (non-empty) committed manifest baseline exists."""
    running = _CHAIN_GENESIS
    if running == committed_root:
        return True
    for version in history.versions:
        running = _sha256(running + version.content_hash)
        if running == committed_root:
            return True
    return False


def _check_manifest_preservation(history: ClassManifestHistory, events: ClassManifestLog, report: ContractReport) -> None:
    """A class may leave the aggregate mean two ways — REMOVED from the manifest, or its status
    changed OUT of the in-mean set (active -> retired/merged/reclassed/na) while kept. BOTH must be
    authorized by a matched ``ClassManifestEvent`` for the exact ``(class_id, from, to)`` transition,
    consumed one-per-transition (a stale event cannot launder a later drop).

    Adjacent-pair check + a TERMINAL-HEAD resurrection guard (008 R11-1b lesson): a class that was
    in the mean in any earlier version and is NOT in the head mean while still PRESENT in the head
    (a split remove-then-readd-as-retired) must be covered by at least one event, so the departure
    cannot be laundered across versions."""
    available = events.transitions()
    for prev, curr in zip(history.versions, history.versions[1:]):
        removed = prev.class_ids() - curr.class_ids()
        left_mean = prev.active_ids() - curr.active_ids()  # was in the mean, now removed or downgraded
        for class_id in sorted(removed | left_mean):
            key = (class_id, prev.version, curr.version)
            if available.get(key, 0) > 0:
                available[key] -= 1
            else:
                report.add(
                    ViolationReason.CLASS_SILENTLY_DROPPED,
                    f"{prev.version}->{curr.version}: class {class_id!r} left the aggregate mean "
                    "(removed or status-downgraded) with no matching class-manifest event",
                )
    # TERMINAL-HEAD resurrection guard: a class ever in the mean that survives in the head as a
    # non-mean status must have at least one logged event for it (else a split departure passed the
    # per-pair check by being consumed at the wrong transition, or the history was presented with a
    # gap). Events for the class are counted across the whole log.
    head = history.latest()
    if head is not None:
        ever_in_mean: set[str] = set()
        for v in history.versions:
            ever_in_mean |= v.active_ids()
        head_active = head.active_ids()
        head_present = head.class_ids()
        events_per_class: "Counter[str]" = Counter(e.class_id for e in events.events)
        for class_id in sorted(ever_in_mean):
            if class_id not in head_active and events_per_class.get(class_id, 0) == 0:
                report.add(
                    ViolationReason.CLASS_SILENTLY_DROPPED,
                    f"class {class_id!r} was in the aggregate mean earlier and is not in the head mean "
                    f"(present={class_id in head_present}) with no class-manifest event anywhere in the log",
                )


def certify_aggregate(
    *,
    manifest: ClassManifestHistory,
    results: list[CertifiedClassResult],
    aggregate: AggregateReport,
    events: Optional[ClassManifestLog] = None,
    committed: Optional[CommittedGenesisState] = None,
) -> ContractReport:
    """Certify an aggregate mean over the committed class set. Fails closed (a typed
    ``ContractReport``) unless:

    * the presented manifest reproduces + append-only-extends the committed manifest root
      (``CLASS_MANIFEST_TRUNCATED``);
    * every class that left the mean did so via a matched, logged event
      (``CLASS_SILENTLY_DROPPED``);
    * every in-mean head class has a present per-class result (``CLASS_ATTESTATION_MISSING``);
    * every presented result is bound to its head manifest entry by the class's committed 008
      history root, carries a signature that verifies against the committed evaluator key, the
      committed evaluator id, and a ``report_hash`` reproducing its report (``CLASS_ATTESTATION_INVALID``);
    * the reported mean + class count RECOMPUTE exactly over the in-mean head classes
      (``AGGREGATE_UNVERIFIED``).

    Pure: no file writes. On a clean report the harness advances the committed root via
    ``advance_committed_root(class_manifest_root=manifest.root)``."""
    report = ContractReport()
    events = events or ClassManifestLog()
    committed = committed or load_committed_genesis_state()

    # 1. committed-monotonic reproduction (parity with history/eval/exposure).
    if not _manifest_reproduces_committed(manifest, committed.latest_class_manifest_root):
        report.add(
            ViolationReason.CLASS_MANIFEST_TRUNCATED,
            "presented class-manifest does not reproduce + append-only-extend the committed "
            f"class_manifest_root {committed.latest_class_manifest_root[:12]}",
        )

    # 2. no class leaves the mean without a logged event.
    _check_manifest_preservation(manifest, events, report)

    head = manifest.latest()
    if head is None:
        report.add(ViolationReason.CLASS_MANIFEST_TRUNCATED, "no manifest version presented")
        return report

    head_entries = head.by_id()
    head_active = head.active_ids()

    # 3 + 4. every in-mean head class has exactly one valid, bound result.
    results_by_class: dict[str, CertifiedClassResult] = {}
    for r in results:
        if r.class_id in results_by_class:
            report.add(
                ViolationReason.CLASS_ATTESTATION_INVALID,
                f"class {r.class_id!r} has more than one presented result",
            )
            continue
        results_by_class[r.class_id] = r
        if r.class_id not in head_active:
            report.add(
                ViolationReason.CLASS_ATTESTATION_INVALID,
                f"result for class {r.class_id!r} that is not an in-mean class of the head manifest",
            )

    for class_id in sorted(head_active):
        r = results_by_class.get(class_id)
        if r is None:
            report.add(
                ViolationReason.CLASS_ATTESTATION_MISSING,
                f"in-mean head class {class_id!r} has no present per-class attestation",
            )
            continue
        entry = head_entries[class_id]
        att = r.attestation
        # AUDIT-009-2: pin the class -> head_history_root binding to COMMITTED state, not the
        # operator-supplied manifest entry. Binding only ``att.history_root == entry.head_history_root``
        # is CIRCULAR — the operator controls both sides (set the weak class's entry.head_history_root
        # to the strong class's root, then attach the strong class's genuine signed attestation), so a
        # high-scoring attestation lands in a weak class's slot. The committed per-class registry
        # ``committed.class_registry`` fixes each class's head_history_root in git-reviewable state;
        # when it is populated (production posture) the manifest entry MUST match it. (Post-bootstrap
        # the committed manifest root also pins it via reproduction; the registry closes the bootstrap
        # window too. An empty registry is the genesis-completeness org floor.)
        committed_root_for_class = committed.class_registry.get(class_id)
        if committed_root_for_class is not None and entry.head_history_root != committed_root_for_class:
            report.add(
                ViolationReason.CLASS_ATTESTATION_INVALID,
                f"class {class_id!r}: manifest head_history_root is not the committed class-registry value",
            )
        # bind the attestation to THIS class's head (no cross-class swap within the presented set).
        if att.history_root != entry.head_history_root:
            report.add(
                ViolationReason.CLASS_ATTESTATION_INVALID,
                f"class {class_id!r}: attestation history_root is not this class's committed head_history_root",
            )
        # the report we read for the mean must be the one the attestation committed.
        if att.report_hash != leaf_hash(r.report.model_dump(mode="json")):
            report.add(
                ViolationReason.CLASS_ATTESTATION_INVALID,
                f"class {class_id!r}: presented report does not reproduce the attested report_hash",
            )
        # the certification must be by the committed evaluator, and the signature must verify.
        if att.evaluator_id != committed.evaluator_id:
            report.add(
                ViolationReason.CLASS_ATTESTATION_INVALID,
                f"class {class_id!r}: attestation evaluator_id {att.evaluator_id!r} != committed evaluator",
            )
        if not verify(att.attestation_root, att.signature, committed.verify_key):
            report.add(
                ViolationReason.CLASS_ATTESTATION_INVALID,
                f"class {class_id!r}: attestation signature does not verify against the committed evaluator key",
            )

    # 5. RECOMPUTE the headline UNCONDITIONALLY; never trust it. AUDIT-009-1: the n_classes and mean
    # checks must fire even when the in-mean set is EMPTY — an integrity guard whose only firing path
    # is the non-empty branch fails OPEN on an all-retired / all-na / empty head, letting a fabricated
    # mean + n_classes certify clean.
    if aggregate.n_classes != len(head_active):
        report.add(
            ViolationReason.AGGREGATE_UNVERIFIED,
            f"reported n_classes {aggregate.n_classes} != in-mean head class count {len(head_active)}",
        )
    if not head_active:
        # An aggregate over zero in-mean classes has no headline: the vacuous mean is 0.0. Any other
        # value is a fabrication (there are no rates to average).
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
                f"reported mean {aggregate.mean} != recomputed mean {float(mean_frac):.12f} "
                f"over {len(head_active)} in-mean classes",
            )
    # else: an in-mean class is missing its result (CLASS_ATTESTATION_MISSING already fired); the
    # mean cannot be recomputed and the report is already not ok.

    return report
