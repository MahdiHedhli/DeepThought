"""The typed EvaluationContract — the honest-measurement spine (feature 008).

``roundrecord.py`` protects a class's *rate* and *presence*; it does not protect
**cohort identity** or the **denominator**. A detector can "improve" a class by
dropping the hard case, re-pinning to an easier commit, or narrowing
``target_paths`` — and no guard trips. This module is the missing spine: typed,
content-addressed, deterministic Pydantic models plus a ``validate`` gate that
turn the locked cross-model honesty consensus
(``memory/vault/measurement-honesty-contract.md``) into enforced invariants.

The single principle behind all of it: **every exclusion is a logged, reviewable,
versioned event — never a silent reclassification.**

Everything here is DETERMINISTIC. No ``datetime.now``, no wall-clock, no
randomness in the models: timestamps and sample seeds are passed in, so a hash
computed on one machine at one time equals the hash computed anywhere else.

Enforcement lives here (a benchmarks-harness ``validate``) rather than in the
shipped ``deepthought check``: the product package operates over the disclosure
Store (projects / findings / sessions) and does not carry cohorts, runs, or
ledgers, so wiring this in would couple the CLI to the benchmarks harness. Tests
and CI (and ``scripts/smoke_008.sh``) invoke ``validate`` directly.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from roundrecord import ClassRate, _pct, _safe_div  # reuse the existing yardstick style

# --------------------------------------------------------------------------- #
# Canonical hashing — the content-addressing primitives
# --------------------------------------------------------------------------- #


def _canonical_json(obj: Any) -> str:
    """Canonical JSON: sorted keys, tight separators, UTF-8 preserved. Two objects
    that are semantically equal serialize byte-for-byte identically, so their
    sha256 matches on any machine."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _content_hash(obj: Any) -> str:
    return _sha256(_canonical_json(obj))


# --------------------------------------------------------------------------- #
# Typed vocabularies (closed taxonomies)
# --------------------------------------------------------------------------- #


class Role(str, Enum):
    """The disjoint role of a cohort entry (FR-4)."""

    CALIBRATION = "calibration"  # a tuned-on seed
    REGRESSION = "regression"  # a former miss, now a fixture
    BLIND = "blind"  # never tuned on; the authoritative denominator


class ExclusionReason(str, Enum):
    """The CLOSED exclusion taxonomy (FR-8). An unknown reason is rejected at the
    type boundary — an exclusion can never be an untyped free-text escape hatch."""

    UNSUPPORTED_LANGUAGE = "unsupported-language"
    CRASH = "crash"
    TIMEOUT = "timeout"
    MALFORMED_SARIF = "malformed-SARIF"
    BUDGET_TRUNCATION = "budget-truncation"
    FETCH_FAILURE = "fetch-failure"
    REPO_GONE = "repo-gone"
    PATH_DRIFT = "path-drift"
    UNVERIFIED_PATCHED_DELETION = "unverified-patched-deletion"
    CWE_RECLASS = "cwe-reclass"
    ALIAS_DUPE = "alias-dupe"
    SEED_SWAP = "seed-swap"
    DROP_REASON_CHANGE = "drop_reason-change"
    TARGET_PATHS_NARROWING = "target_paths-narrowing"
    SINK_PROBE_EDIT = "sink_probe-edit"
    TRIAGE_DEDUP_SUPPRESSION = "triage/dedup-suppression"
    POLICY_REFUSAL = "policy_refusal"
    NO_ARTIFACT = "no-artifact"


class ExclusionClass(str, Enum):
    """How an exclusion scores.

    The AC-tested binary is INFRASTRUCTURE (invalidates the run) vs
    ANALYSIS_LIMITATION (counts as a miss, stays in the denominator). Two further
    classes are modelled honestly rather than forced into that binary:
    COHORT_CORRECTION is a versioned structural fix that legitimises a
    cross-version denominator change (it does not itself score), and
    POLICY_REFUSAL scores **N/A** — never 0, which would falsely imply a detector
    was measured (per the locked vault consensus)."""

    INFRASTRUCTURE = "infrastructure"  # invalidates the run
    ANALYSIS_LIMITATION = "analysis-limitation"  # counts as a miss, in denominator
    COHORT_CORRECTION = "cohort-correction"  # versioned correction; permits removal
    POLICY_REFUSAL = "policy-refusal"  # task-completion failure; score N/A


_EXCLUSION_CLASS: dict[ExclusionReason, ExclusionClass] = {
    # Infrastructure — a failed measurement, not a detector verdict: invalidate.
    ExclusionReason.CRASH: ExclusionClass.INFRASTRUCTURE,
    ExclusionReason.TIMEOUT: ExclusionClass.INFRASTRUCTURE,
    ExclusionReason.MALFORMED_SARIF: ExclusionClass.INFRASTRUCTURE,
    ExclusionReason.BUDGET_TRUNCATION: ExclusionClass.INFRASTRUCTURE,
    ExclusionReason.FETCH_FAILURE: ExclusionClass.INFRASTRUCTURE,
    ExclusionReason.REPO_GONE: ExclusionClass.INFRASTRUCTURE,
    ExclusionReason.UNVERIFIED_PATCHED_DELETION: ExclusionClass.INFRASTRUCTURE,
    ExclusionReason.NO_ARTIFACT: ExclusionClass.INFRASTRUCTURE,
    # Analysis limitation — "we can't parse this" is a capability gap: a MISS.
    ExclusionReason.UNSUPPORTED_LANGUAGE: ExclusionClass.ANALYSIS_LIMITATION,
    # Cohort correction — a logged structural change that creates a new version.
    ExclusionReason.PATH_DRIFT: ExclusionClass.COHORT_CORRECTION,
    ExclusionReason.CWE_RECLASS: ExclusionClass.COHORT_CORRECTION,
    ExclusionReason.ALIAS_DUPE: ExclusionClass.COHORT_CORRECTION,
    ExclusionReason.SEED_SWAP: ExclusionClass.COHORT_CORRECTION,
    ExclusionReason.DROP_REASON_CHANGE: ExclusionClass.COHORT_CORRECTION,
    ExclusionReason.TARGET_PATHS_NARROWING: ExclusionClass.COHORT_CORRECTION,
    ExclusionReason.SINK_PROBE_EDIT: ExclusionClass.COHORT_CORRECTION,
    ExclusionReason.TRIAGE_DEDUP_SUPPRESSION: ExclusionClass.COHORT_CORRECTION,
    # Policy refusal — N/A, distinct from a 0 miss.
    ExclusionReason.POLICY_REFUSAL: ExclusionClass.POLICY_REFUSAL,
}


class ViolationReason(str, Enum):
    """Every ``check`` failure carries a typed reason (FR-14) — never a bare bool."""

    BAD_ENTRY_HASH = "bad-entry-hash"
    IN_PLACE_EDIT = "in-place-edit-without-version-bump"
    NON_MONOTONE_VERSION = "non-monotone-version"
    DUPLICATE_VERSION = "duplicate-version-tag"
    DENOMINATOR_SHRINK = "silent-denominator-shrink"
    BLIND_REUSED_AFTER_FIX = "blind-reused-after-guiding-a-fix"
    CURATOR_IS_SUBJECT = "curator-equals-subject"
    MISSING_FREEZE = "missing-freeze-before-evaluation"
    BLIND_ACCESS_PRE_FREEZE = "blind-access-pre-freeze"
    BLIND_ACCESS_EXCEEDED = "blind-access-exceeded"
    INFRA_RETRY_REQUIRES_UNCHANGED = "infra-retry-requires-unchanged-hashes"
    ACHIEVABILITY_NOT_PRE_FREEZE = "achievability-not-pre-freeze"
    SYNTHETIC_IN_REAL_AGGREGATE = "synthetic-in-real-cve-aggregate"


class ContractViolation(Exception):
    """A typed contract failure. Raised by guard methods that must refuse an
    action outright (a bad evaluation attempt), and collected — never raised — by
    ``validate`` into a ``ContractReport``."""

    def __init__(self, reason: ViolationReason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)


class ContractReport(BaseModel):
    """The result of ``validate`` — ok plus the list of typed violations."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    violations: list[ContractViolation] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations

    def add(self, reason: ViolationReason, detail: str = "") -> None:
        self.violations.append(ContractViolation(reason, detail))

    def reasons(self) -> set[ViolationReason]:
        return {v.reason for v in self.violations}

    def summary(self) -> str:
        if self.ok:
            return "contract OK"
        return "contract FAILED: " + "; ".join(f"{v.reason.value} ({v.detail})" for v in self.violations)


# --------------------------------------------------------------------------- #
# FR-1 / FR-4 — CohortEntry: canonical identity + disjoint role
# --------------------------------------------------------------------------- #


class CohortEntry(BaseModel):
    """One pinned ground-truth case. Identity is a sha256 over its canonical
    fields (FR-1): ``repo``, ``vuln_ref``, ``patched_ref``, **sorted**
    ``target_paths``, ``sink_probe``, and ``status``/``drop_reason``. ``role`` and
    ``guided_fix`` are deliberately NOT part of identity, so moving an entry
    blind -> regression (FR-4) is a role change that preserves its identity and
    thus the denominator."""

    model_config = ConfigDict(extra="forbid")

    repo: str
    vuln_ref: str
    patched_ref: str
    target_paths: list[str]
    sink_probe: str
    status: str = "pinned"
    drop_reason: Optional[str] = None

    role: Role
    guided_fix: bool = False  # has this entry ever guided a fix? (FR-4)

    # The identity hash SEALED when the entry was created. Left None it is simply
    # computed; set, ``validate`` recomputes and rejects a mismatch — that is how a
    # canonical-field edit without a fresh hash is caught (AC-1).
    declared_identity_hash: Optional[str] = None

    @property
    def computed_identity_hash(self) -> str:
        return _content_hash(
            {
                "repo": self.repo,
                "vuln_ref": self.vuln_ref,
                "patched_ref": self.patched_ref,
                "target_paths": sorted(self.target_paths),
                "sink_probe": self.sink_probe,
                "status": self.status,
                "drop_reason": self.drop_reason or "",
            }
        )

    @property
    def identity_hash(self) -> str:
        return self.declared_identity_hash or self.computed_identity_hash

    def sealed(self) -> "CohortEntry":
        """A copy with ``declared_identity_hash`` pinned to the current computed
        hash — the entry's content address at creation time."""
        return self.model_copy(update={"declared_identity_hash": self.computed_identity_hash})


# --------------------------------------------------------------------------- #
# FR-2 — Cohort + CohortHistory: content-addressed, versioned, immutable
# --------------------------------------------------------------------------- #


class Cohort(BaseModel):
    """A role-tagged set of entries, content-addressed by its sorted entry-identity
    hashes plus a version tag (FR-2). A correction creates a NEW version; history
    is never edited."""

    model_config = ConfigDict(extra="forbid")

    version: str
    entries: list[CohortEntry]
    reason: str = ""  # why this version exists (empty for the first)
    parent_version: Optional[str] = None

    # The content hash SEALED at creation. Set, ``validate`` recomputes and rejects
    # a mismatch — catching an in-place entry edit that kept the same version (AC-2).
    declared_content_hash: Optional[str] = None

    @model_validator(mode="after")
    def _entries_are_unique_by_identity(self) -> "Cohort":
        # A single entry identity may hold exactly one role in a version. Duplicate
        # identities would let the same case sit in two role buckets at once,
        # defeating the calibration/regression/blind partition (FR-4).
        ids = [e.computed_identity_hash for e in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate entry identity within a cohort version")
        return self

    @property
    def computed_content_hash(self) -> str:
        return _content_hash(
            {"version": self.version, "entries": sorted(e.computed_identity_hash for e in self.entries)}
        )

    @property
    def content_hash(self) -> str:
        return self.declared_content_hash or self.computed_content_hash

    def identities(self) -> set[str]:
        return {e.computed_identity_hash for e in self.entries}

    def by_role(self, role: Role) -> list[CohortEntry]:
        return [e for e in self.entries if e.role == role]

    def sealed(self) -> "Cohort":
        return self.model_copy(update={"declared_content_hash": self.computed_content_hash})


class CohortHistory(BaseModel):
    """Ordered cohort versions, oldest first. Append-only: a new version is added,
    prior versions are never mutated."""

    model_config = ConfigDict(extra="forbid")

    versions: list[Cohort] = Field(default_factory=list)

    def append(self, cohort: Cohort) -> None:
        # Re-defining an existing version tag with different content would rewrite
        # history — refuse it. A correction must use a NEW version tag (FR-2).
        for existing in self.versions:
            if existing.version == cohort.version and existing.content_hash != cohort.content_hash:
                raise ContractViolation(
                    ViolationReason.IN_PLACE_EDIT, f"version {cohort.version} redefined with new content"
                )
        self.versions.append(cohort)

    def latest(self) -> Optional[Cohort]:
        return self.versions[-1] if self.versions else None

    def get(self, version: str) -> Optional[Cohort]:
        for c in self.versions:
            if c.version == version:
                return c
        return None


def _version_num(tag: str) -> int:
    """Parse the ordering integer from a version tag like ``v3`` -> 3. A tag with
    no digits sorts as 0 (and will therefore trip the monotonicity check against a
    numbered predecessor)."""
    m = re.search(r"\d+", tag)
    return int(m.group()) if m else 0


# --------------------------------------------------------------------------- #
# FR-5 — Freeze: a content hash of the whole executable bundle
# --------------------------------------------------------------------------- #


class DetectorBundle(BaseModel):
    """Everything that determines what the detector *does*. The freeze hash is a
    content hash over exactly these components (FR-5), so changing any one — a
    parser version, the lockfile, an invocation param — changes the freeze."""

    model_config = ConfigDict(extra="forbid")

    detector_id: str
    module_hashes: dict[str, str] = Field(default_factory=dict)  # detector + transitive modules
    rules_config_hash: str = ""
    lockfile_hash: str = ""
    interpreter_version: str = ""
    parser_versions: dict[str, str] = Field(default_factory=dict)
    entrypoint: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    calibration_seed_ids: list[str] = Field(default_factory=list)  # entry-identity hashes

    @property
    def bundle_hash(self) -> str:
        payload = self.model_dump()
        payload["calibration_seed_ids"] = sorted(payload["calibration_seed_ids"])
        return _content_hash(payload)


class FreezeManifest(BaseModel):
    """The committed, timestamped freeze. The timestamp is metadata passed in (never
    ``datetime.now``); it is deliberately OUTSIDE the content hash so re-recording
    the same bundle later yields the same freeze hash, while any bundle change moves
    it (AC-5)."""

    model_config = ConfigDict(extra="forbid")

    bundle: DetectorBundle
    timestamp: str  # ISO-8601, supplied by the caller

    @property
    def freeze_hash(self) -> str:
        return self.bundle.bundle_hash


# --------------------------------------------------------------------------- #
# FR-6 — ExposureLedger: curator != subject
# --------------------------------------------------------------------------- #


class ExposureRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cohort_content_hash: str
    actor: str  # model / harness id
    activity: str = Field(pattern="^(curated|inspected)$")


class ExposureLedger(BaseModel):
    """Records which model/harness curated or inspected each cohort. A subject that
    appears here for a cohort can never be that cohort's scored subject (FR-6)."""

    model_config = ConfigDict(extra="forbid")

    records: list[ExposureRecord] = Field(default_factory=list)

    def record(self, *, cohort_content_hash: str, actor: str, activity: str) -> None:
        self.records.append(
            ExposureRecord(cohort_content_hash=cohort_content_hash, actor=actor, activity=activity)
        )

    def curators_inspectors_of(self, cohort_content_hash: str) -> set[str]:
        return {r.actor for r in self.records if r.cohort_content_hash == cohort_content_hash}

    def can_score(self, cohort_content_hash: str, subject: str) -> bool:
        return subject not in self.curators_inspectors_of(cohort_content_hash)

    def rotate_subject(self, candidates: list[str], cohort_content_hash: str) -> Optional[str]:
        """Pick a subject that never touched this cohort — ownership rotation so no
        model's pool grades itself (FR-6)."""
        for c in candidates:
            if self.can_score(cohort_content_hash, c):
                return c
        return None


# --------------------------------------------------------------------------- #
# FR-8 — ExclusionEvent + append-only ExclusionLog
# --------------------------------------------------------------------------- #


class ExclusionEvent(BaseModel):
    """A typed, append-only exclusion (FR-8). No exclusion edits history."""

    model_config = ConfigDict(extra="forbid")

    reason: ExclusionReason
    entry_identity: str = ""  # the affected entry's identity hash (for a removal)
    from_version: str = ""
    to_version: str = ""
    detail: str = ""

    @property
    def classification(self) -> ExclusionClass:
        return _EXCLUSION_CLASS[self.reason]

    @property
    def invalidates_run(self) -> bool:
        return self.classification is ExclusionClass.INFRASTRUCTURE

    @property
    def is_miss(self) -> bool:
        return self.classification is ExclusionClass.ANALYSIS_LIMITATION

    @property
    def scored_outcome(self) -> str:
        return {
            ExclusionClass.INFRASTRUCTURE: "run_invalid",
            ExclusionClass.ANALYSIS_LIMITATION: "miss",
            ExclusionClass.COHORT_CORRECTION: "correction",
            ExclusionClass.POLICY_REFUSAL: "n/a",
        }[self.classification]


class ExclusionLog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[ExclusionEvent] = Field(default_factory=list)

    def append(self, event: ExclusionEvent) -> None:
        self.events.append(event)

    def is_extension_of(self, prior: "ExclusionLog") -> bool:
        """True iff ``prior`` is a prefix of this log — the append-only invariant.
        A log that dropped or reordered a prior event is NOT an extension."""
        return self.events[: len(prior.events)] == prior.events

    def removed_identities(self) -> set[str]:
        return {e.entry_identity for e in self.events if e.entry_identity}


# --------------------------------------------------------------------------- #
# FR-7 — EvaluationRun: blind-access discipline
# --------------------------------------------------------------------------- #


class EvalAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phase: str = Field(pattern="^(pre_freeze|post_freeze)$")
    produced_results: bool
    artifact_hash: str = ""
    env_hash: str = ""
    logs_intact: bool = True


class EvaluationRun(BaseModel):
    """One evaluation of one subject against one frozen cohort. Enforces: zero
    pre-freeze attempts, exactly one post-freeze semantic evaluation, and an infra
    retry only when no results were produced and artifact/env hashes are unchanged
    (FR-7)."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    subject: str  # the model/harness being scored
    cohort_content_hash: str
    freeze_hash: Optional[str] = None
    attempts: list[EvalAttempt] = Field(default_factory=list)

    @property
    def pre_freeze_attempts(self) -> list[EvalAttempt]:
        return [a for a in self.attempts if a.phase == "pre_freeze"]

    @property
    def post_freeze_attempts(self) -> list[EvalAttempt]:
        return [a for a in self.attempts if a.phase == "post_freeze"]

    @property
    def semantic_evaluation_count(self) -> int:
        # A semantic evaluation is a post-freeze attempt that actually produced
        # detector results. Attempts that produced nothing (a crash) are not
        # semantic evaluations — that is why an infra retry is allowed.
        return sum(1 for a in self.post_freeze_attempts if a.produced_results)

    def attempt_evaluation(
        self,
        *,
        phase: str,
        produced_results: bool,
        artifact_hash: str = "",
        env_hash: str = "",
        logs_intact: bool = True,
    ) -> EvalAttempt:
        """Record one evaluation attempt, refusing anything the contract forbids.
        Raises ``ContractViolation`` (nothing is recorded on refusal)."""
        if phase == "pre_freeze":
            # Zero blind-cohort attempts before freeze — even attempting is a leak.
            raise ContractViolation(
                ViolationReason.BLIND_ACCESS_PRE_FREEZE, "no blind access is permitted before freeze"
            )
        if phase != "post_freeze":
            raise ValueError(f"unknown phase: {phase!r}")
        if self.freeze_hash is None:
            raise ContractViolation(
                ViolationReason.MISSING_FREEZE, "cannot evaluate before a freeze manifest exists"
            )

        prior = self.post_freeze_attempts
        if prior:
            if any(a.produced_results for a in prior):
                # A semantic evaluation already happened: exactly one is allowed.
                raise ContractViolation(
                    ViolationReason.BLIND_ACCESS_EXCEEDED,
                    "a post-freeze semantic evaluation already produced results",
                )
            # All prior attempts produced no results: an infra retry is allowed
            # ONLY if logs are intact and artifact/env hashes are unchanged.
            last = prior[-1]
            if not (logs_intact and artifact_hash == last.artifact_hash and env_hash == last.env_hash):
                raise ContractViolation(
                    ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED,
                    "an infra retry requires intact logs and unchanged artifact/env hashes",
                )

        attempt = EvalAttempt(
            phase="post_freeze",
            produced_results=produced_results,
            artifact_hash=artifact_hash,
            env_hash=env_hash,
            logs_intact=logs_intact,
        )
        self.attempts.append(attempt)
        return attempt


# --------------------------------------------------------------------------- #
# FR-9 — recall vs precision, kept separate
# --------------------------------------------------------------------------- #


class RecallReport(BaseModel):
    """Rediscovery (recall) by the line-precise sink-probe rule. Patched-alert
    density is carried as operational context and NEVER decides recall (FR-9)."""

    model_config = ConfigDict(extra="forbid")

    rediscovered: int = Field(ge=0)
    total: int = Field(ge=0)
    patched_alert_density: float = Field(default=0.0, ge=0.0)  # flags/KLOC, context only

    @model_validator(mode="after")
    def _rediscovered_within_total(self) -> "RecallReport":
        if self.rediscovered > self.total:
            raise ValueError(f"rediscovered ({self.rediscovered}) cannot exceed total ({self.total})")
        return self

    @property
    def recall(self) -> float:
        return _safe_div(self.rediscovered, self.total)  # independent of density


def precision_sample_seed(cohort_hash: str, freeze_hash: str, run_id: str) -> int:
    """The deterministic seed for the blind confusion-pair sample:
    ``hash(cohort_hash, freeze_hash, run_id)`` (FR-9). Fixed inputs -> fixed seed,
    so the sample cannot be re-rolled until it flatters the detector."""
    return int(_sha256("\x1f".join([cohort_hash, freeze_hash, run_id])), 16)


def sample_confusion_pairs(pairs: list[str], k: int, seed: int) -> list[str]:
    """A deterministic, seed-reproducible sample of confusion pairs."""
    rng = random.Random(seed)
    return rng.sample(list(pairs), min(k, len(pairs)))


class AdjudicatorVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adjudicator: str
    is_builder: bool
    is_curator: bool
    decision: str = Field(pattern="^(true-positive|false-positive|real-other-finding|ambiguous)$")


class Adjudication(BaseModel):
    """One confusion pair, judged by the panel. Consensus is a unanimous verdict;
    any disagreement needs human resolution and, like an explicit ``ambiguous``,
    counts AGAINST precision (FR-9)."""

    model_config = ConfigDict(extra="forbid")

    pair_id: str
    verdicts: list[AdjudicatorVerdict]

    @property
    def resolved_decision(self) -> str:
        decisions = {v.decision for v in self.verdicts}
        if len(decisions) == 1:
            return next(iter(decisions))
        return "disagreement"

    @property
    def counts_as_true_positive(self) -> bool:
        return self.resolved_decision == "true-positive"

    @property
    def is_ambiguous(self) -> bool:
        # Ambiguous OR unresolved disagreement — either way, not a clean TP.
        return self.resolved_decision in ("ambiguous", "disagreement")


class AdjudicatedPrecision(BaseModel):
    """Precision from a blind confusion-pair sample. The panel must be two
    non-builder adjudicators with at least one non-curator; ambiguous counts
    against precision (FR-9)."""

    model_config = ConfigDict(extra="forbid")

    seed: int
    sampled_pairs: list[str]
    adjudications: list[Adjudication]

    @model_validator(mode="after")
    def _panel_and_sample_are_valid(self) -> "AdjudicatedPrecision":
        if not self.sampled_pairs:
            raise ValueError("precision requires a non-empty blind confusion-pair sample")
        sampled = set(self.sampled_pairs)
        for adj in self.adjudications:
            if adj.pair_id not in sampled:
                raise ValueError(f"adjudicated pair {adj.pair_id!r} is not in the seeded sample")
            if len(adj.verdicts) < 2:
                raise ValueError("each pair needs at least two adjudicators")
            if any(v.is_builder for v in adj.verdicts):
                raise ValueError("adjudicators must be non-builders")
            if not any(not v.is_curator for v in adj.verdicts):
                raise ValueError("at least one adjudicator must be a non-curator")
        return self

    @property
    def precision(self) -> float:
        adjudicated = len(self.adjudications)
        tp = sum(1 for a in self.adjudications if a.counts_as_true_positive)
        return _safe_div(tp, adjudicated)

    @property
    def needs_human_resolution(self) -> list[str]:
        return [a.pair_id for a in self.adjudications if a.resolved_decision == "disagreement"]


# --------------------------------------------------------------------------- #
# FR-10 — real-other-finding becomes a gated candidate
# --------------------------------------------------------------------------- #


class LocalCandidate(BaseModel):
    """A patched-tree flag adjudicated ``real-other-finding``: a LOCAL candidate
    that must re-enter a fresh authorization gate; never auto-investigated or
    disclosed (FR-10). It is modelled as data only — no investigation is wired."""

    model_config = ConfigDict(extra="forbid")

    origin_pair_id: str
    cohort_content_hash: str
    description: str = ""
    requires_authorization: bool = True
    auto_investigated: bool = False

    @model_validator(mode="after")
    def _never_auto_investigated(self) -> "LocalCandidate":
        if self.auto_investigated:
            raise ValueError("a real-other-finding must re-enter a fresh authorization gate; never auto-investigated")
        if not self.requires_authorization:
            raise ValueError("a real-other-finding candidate always requires a fresh authorization gate")
        return self


def candidates_from_adjudications(
    adjudications: list[Adjudication], *, cohort_content_hash: str
) -> list[LocalCandidate]:
    return [
        LocalCandidate(origin_pair_id=a.pair_id, cohort_content_hash=cohort_content_hash)
        for a in adjudications
        if a.resolved_decision == "real-other-finding"
    ]


# --------------------------------------------------------------------------- #
# FR-11 — synthetic separation
# --------------------------------------------------------------------------- #


class SyntheticVariant(BaseModel):
    """A synthetic patch-shape variant. It NEVER aggregates into a real-CVE number
    (FR-11); each carries class-appropriate proof it removes the vulnerability, and
    execution-based proof stays behind the Article III sandbox."""

    model_config = ConfigDict(extra="forbid")

    variant_id: str
    base_cve: str
    removal_proof: str  # required, non-empty
    proof_kind: str = Field(pattern="^(static|execution)$")
    sandbox_attested: bool = False

    @model_validator(mode="after")
    def _proof_is_present_and_gated(self) -> "SyntheticVariant":
        if not self.removal_proof.strip():
            raise ValueError("a synthetic variant needs class-appropriate proof it removes the vulnerability")
        if self.proof_kind == "execution" and not self.sandbox_attested:
            raise ValueError("execution-based removal proof stays behind the Article III sandbox")
        return self


class SyntheticSuite(BaseModel):
    """The loudly-labelled robustness suite. Kept entirely separate from real-CVE
    aggregates."""

    model_config = ConfigDict(extra="forbid")

    label: str
    variants: list[SyntheticVariant] = Field(default_factory=list)


class RealCVEAggregate(BaseModel):
    """A real-CVE number. It only ever holds ``ClassRate`` rows; a synthetic variant
    offered to it is refused with a typed reason (FR-11)."""

    model_config = ConfigDict(extra="forbid")

    label: str
    class_rates: list[ClassRate] = Field(default_factory=list)

    def add(self, item: Any) -> None:
        if isinstance(item, SyntheticVariant):
            raise ContractViolation(
                ViolationReason.SYNTHETIC_IN_REAL_AGGREGATE,
                "synthetic variants never aggregate into a real-CVE number",
            )
        if not isinstance(item, ClassRate):
            raise TypeError(f"a real-CVE aggregate holds ClassRate rows, not {type(item).__name__}")
        self.class_rates.append(item)


# --------------------------------------------------------------------------- #
# FR-12 — achievability: append-only, pre-freeze, falsifiable
# --------------------------------------------------------------------------- #


class AchievabilityPrediction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry_identity: str
    predicted_achievable: bool
    registered_at: str  # ISO-8601, supplied by the caller
    note: str = ""


class AchievabilityLog(BaseModel):
    """Optional per-entry achievability predictions: pre-registered, frozen before
    unseal, APPEND-ONLY (FR-12). A later rediscovery falsifies a prediction without
    rewriting it; the authoritative rate stays blind/all-pinned."""

    model_config = ConfigDict(extra="forbid")

    freeze_timestamp: str  # the unseal boundary
    predictions: list[AchievabilityPrediction] = Field(default_factory=list)

    def append(self, prediction: AchievabilityPrediction) -> None:
        # Pre-registered means BEFORE unseal: a prediction registered at/after the
        # freeze timestamp is not a prediction, it is hindsight — refuse it.
        if prediction.registered_at >= self.freeze_timestamp:
            raise ContractViolation(
                ViolationReason.ACHIEVABILITY_NOT_PRE_FREEZE,
                "achievability predictions must be pre-registered before freeze",
            )
        self.predictions.append(prediction)

    def falsifications(self, rediscovered_ids: set[str]) -> list[AchievabilityPrediction]:
        """Predictions that said 'not achievable' for an entry later rediscovered.
        The records themselves are returned UNCHANGED — falsification never rewrites
        history."""
        return [
            p for p in self.predictions if not p.predicted_achievable and p.entry_identity in rediscovered_ids
        ]


# --------------------------------------------------------------------------- #
# FR-13 — blind-led, multi-number reporting
# --------------------------------------------------------------------------- #


class Report(BaseModel):
    """The blind-led report. Blind recall is the HEADLINE; fixed-cohort recall,
    coverage, patched-alert density, and adjudicated precision are distinct,
    labelled secondaries (FR-13). No single figure is presented as "the" score."""

    model_config = ConfigDict(extra="forbid")

    blind_recall: RecallReport
    fixed_cohort_recall: RecallReport
    coverage: float = Field(ge=0.0, le=1.0)  # pinned / all
    patched_alert_density: float = Field(ge=0.0)  # flags/KLOC on the fixed tree
    adjudicated_precision: float = Field(ge=0.0, le=1.0)
    achievable_recall: Optional[float] = None  # labelled diagnostic secondary only

    @property
    def authoritative_recall(self) -> RecallReport:
        # Authoritative = blind-rediscovered / all-pinned. Achievable-recall is a
        # diagnostic, never the authoritative number (FR-12/FR-13).
        return self.blind_recall

    def headline(self) -> str:
        return f"blind recall (HEADLINE): {_pct(self.blind_recall.recall)} ({self.blind_recall.rediscovered}/{self.blind_recall.total})"

    def secondaries(self) -> dict[str, str]:
        out = {
            "fixed-cohort recall": f"{_pct(self.fixed_cohort_recall.recall)} ({self.fixed_cohort_recall.rediscovered}/{self.fixed_cohort_recall.total})",
            "coverage": _pct(self.coverage),
            "patched-alert density": f"{self.patched_alert_density:.2f} flags/KLOC",
            "adjudicated precision": _pct(self.adjudicated_precision),
        }
        if self.achievable_recall is not None:
            out["achievable-recall (diagnostic)"] = _pct(self.achievable_recall)
        return out

    def lines(self) -> list[str]:
        return [self.headline(), *[f"{label}: {value}" for label, value in self.secondaries().items()]]

    def render(self) -> str:
        return "\n".join(self.lines())


# --------------------------------------------------------------------------- #
# FR-14 — validate: the contract's `check`
# --------------------------------------------------------------------------- #


def validate(
    *,
    history: Optional[CohortHistory] = None,
    exclusions: Optional[ExclusionLog] = None,
    ledger: Optional[ExposureLedger] = None,
    run: Optional[EvaluationRun] = None,
) -> ContractReport:
    """Validate the Evaluation Contract (FR-14). Checks entry-hash integrity,
    version monotonicity, denominator preservation, blind-reuse, the exposure
    ledger (curator != subject), freeze-before-evaluation, and the blind-access
    counter. Every violation is collected with a typed reason; ``report.ok`` is
    True only when there are none. A ``check`` that raises is itself a failed check
    (Constitution VII), so unexpected errors are captured, not propagated."""
    report = ContractReport()

    try:
        if history is not None:
            _check_entry_hash_integrity(history, report)
            _check_content_seals(history, report)
            _check_version_monotonicity(history, report)
            _check_denominator_preservation(history, exclusions, report)
            _check_blind_reuse(history, report)

        if run is not None:
            _check_freeze_before_evaluation(run, report)
            _check_blind_access(run, report)
            if ledger is not None:
                _check_exposure(run, ledger, report)
    except ContractViolation as exc:  # a guard that raised mid-check is a failure
        report.violations.append(exc)
    except Exception as exc:  # noqa: BLE001 - any crash in check IS a failed check
        report.add(ViolationReason.IN_PLACE_EDIT, f"unexpected check error: {exc}")

    return report


def _check_entry_hash_integrity(history: CohortHistory, report: ContractReport) -> None:
    for cohort in history.versions:
        for entry in cohort.entries:
            if entry.declared_identity_hash is not None and entry.declared_identity_hash != entry.computed_identity_hash:
                report.add(
                    ViolationReason.BAD_ENTRY_HASH,
                    f"{cohort.version}: entry hash {entry.declared_identity_hash[:12]} != recomputed {entry.computed_identity_hash[:12]}",
                )


def _check_content_seals(history: CohortHistory, report: ContractReport) -> None:
    for cohort in history.versions:
        if cohort.declared_content_hash is not None and cohort.declared_content_hash != cohort.computed_content_hash:
            report.add(
                ViolationReason.IN_PLACE_EDIT,
                f"{cohort.version}: content changed in place without a version bump",
            )


def _check_version_monotonicity(history: CohortHistory, report: ContractReport) -> None:
    seen: set[str] = set()
    prev: Optional[int] = None
    for cohort in history.versions:
        if cohort.version in seen:
            report.add(ViolationReason.DUPLICATE_VERSION, f"version {cohort.version} appears twice")
        seen.add(cohort.version)
        num = _version_num(cohort.version)
        if prev is not None and num <= prev:
            report.add(
                ViolationReason.NON_MONOTONE_VERSION,
                f"version {cohort.version} ({num}) does not increase past {prev}",
            )
        prev = num


def _check_denominator_preservation(
    history: CohortHistory, exclusions: Optional[ExclusionLog], report: ContractReport
) -> None:
    logged = exclusions.removed_identities() if exclusions is not None else set()
    for prev, curr in zip(history.versions, history.versions[1:]):
        removed = prev.identities() - curr.identities()
        for identity in sorted(removed):
            if identity not in logged:
                report.add(
                    ViolationReason.DENOMINATOR_SHRINK,
                    f"{prev.version}->{curr.version}: entry {identity[:12]} left the denominator with no exclusion event",
                )


def _check_blind_reuse(history: CohortHistory, report: ContractReport) -> None:
    latest = history.latest()
    if latest is None:
        return
    for entry in latest.entries:
        if entry.role == Role.BLIND and entry.guided_fix:
            report.add(
                ViolationReason.BLIND_REUSED_AFTER_FIX,
                f"{latest.version}: entry {entry.identity_hash[:12]} guided a fix but is still blind; move it to regression in a new version",
            )


def _check_freeze_before_evaluation(run: EvaluationRun, report: ContractReport) -> None:
    if run.post_freeze_attempts and run.freeze_hash is None:
        report.add(ViolationReason.MISSING_FREEZE, f"run {run.run_id}: evaluation recorded without a freeze manifest")


def _check_blind_access(run: EvaluationRun, report: ContractReport) -> None:
    if run.pre_freeze_attempts:
        report.add(
            ViolationReason.BLIND_ACCESS_PRE_FREEZE,
            f"run {run.run_id}: {len(run.pre_freeze_attempts)} blind attempt(s) before freeze",
        )
    if run.semantic_evaluation_count > 1:
        report.add(
            ViolationReason.BLIND_ACCESS_EXCEEDED,
            f"run {run.run_id}: {run.semantic_evaluation_count} post-freeze semantic evaluations (>1)",
        )


def _check_exposure(run: EvaluationRun, ledger: ExposureLedger, report: ContractReport) -> None:
    if not ledger.can_score(run.cohort_content_hash, run.subject):
        report.add(
            ViolationReason.CURATOR_IS_SUBJECT,
            f"run {run.run_id}: subject {run.subject!r} curated/inspected this cohort",
        )


# A convenience alias: the contract's `check` (FR-14) reads as `check(...)` too.
check = validate
