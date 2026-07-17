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
from collections import Counter
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
    ROLE_DOWNGRADE = "role-downgrade"  # a blind entry legitimately moved out of the blind set (FR-4)
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
    ExclusionReason.ROLE_DOWNGRADE: ExclusionClass.COHORT_CORRECTION,
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
    # Adversarial-audit seals (H1..H9): validate() enforces these, not only the
    # constructor helpers a from-storage rebuild bypasses.
    RUN_INVALID = "infrastructure-exclusion-invalidates-run"
    BAD_FREEZE_BINDING = "freeze-hash-not-bound-to-frozen-bundle"
    SEED_IN_BLIND = "calibration-seed-is-a-blind-entry"
    REPORT_DENOMINATOR_MISMATCH = "report-recall-not-bound-to-frozen-cohort"
    PRECISION_SAMPLE_UNBOUND = "precision-sample-not-bound-to-seed"
    # Round-2 adversarial-audit seals (R1..R8): validate() enforces these too.
    HISTORY_TRUNCATED = "history-truncated-or-reordered-vs-prior-baseline"
    REPORT_UNBOUND = "report-not-bound-to-any-resolvable-cohort"
    NON_CANONICAL_RUN_ID = "run-id-not-the-canonical-cohort-freeze-subject-hash"
    EVALUATED_MORE_THAN_ONCE = "cohort-freeze-subject-evaluated-more-than-once"


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
        # R1: role and guided_fix are SEALED into the content hash (not just the
        # identity set). An in-place role flip or guided_fix edit on a sealed cohort
        # therefore breaks the seal (IN_PLACE_EDIT) instead of silently shrinking the
        # blind-role denominator with no version bump. They remain OUTSIDE entry
        # *identity*, so a role move across a new version still preserves the identity.
        return _content_hash(
            {
                "version": self.version,
                "entries": sorted(
                    # role may be a Role member or a raw str (model_copy(update=...)
                    # skips validation); normalise to the enum value either way.
                    [
                        e.computed_identity_hash,
                        e.role.value if isinstance(e.role, Role) else str(e.role),
                        e.guided_fix,
                    ]
                    for e in self.entries
                ),
            }
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

    @model_validator(mode="after")
    def _run_level_reasons_carry_no_entry(self) -> "ExclusionEvent":
        # POLICY_REFUSAL and INFRASTRUCTURE are RUN-level outcomes, never per-entry
        # deletions (H3). An event carrying an entry_identity for one of them would
        # masquerade as a denominator removal — refuse it at the type boundary.
        if _EXCLUSION_CLASS[self.reason] in (ExclusionClass.POLICY_REFUSAL, ExclusionClass.INFRASTRUCTURE):
            if self.entry_identity:
                raise ValueError(
                    f"{self.reason.value} is a run-level exclusion and must not carry an entry_identity"
                )
        return self

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

    def correction_removed_identities(self) -> set[str]:
        """Identities whose removal is legitimized by a COHORT_CORRECTION-class
        event (H1). A miss (ANALYSIS_LIMITATION) or a run-level outcome
        (INFRASTRUCTURE / POLICY_REFUSAL) can never authorize a denominator
        removal — only a logged, versioned structural correction may."""
        return {
            e.entry_identity
            for e in self.events
            if e.entry_identity and _EXCLUSION_CLASS[e.reason] is ExclusionClass.COHORT_CORRECTION
        }

    def correction_transitions(self) -> "Counter[tuple[str, str, str]]":
        """A multiset of the exact (entry_identity, from_version, to_version)
        transitions authorized by COHORT_CORRECTION events (H4). One event
        authorizes exactly its named removal at its named transition — a stale
        v1->v2 event cannot launder a later v3->v4 removal of the same identity."""
        return Counter(
            (e.entry_identity, e.from_version, e.to_version)
            for e in self.events
            if e.entry_identity and _EXCLUSION_CLASS[e.reason] is ExclusionClass.COHORT_CORRECTION
        )


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


def _canonical_run_id(cohort_content_hash: str, freeze_hash: str, subject: str) -> str:
    """The ONE canonical run_id for a (cohort, freeze, subject) triple (R5):
    ``sha256(cohort_content_hash | freeze_hash | subject)``. Because the run_id is a
    pure function of those three sealed inputs, an operator cannot mint a fresh
    run_id to re-roll the precision sample or to launder a second evaluation as a new
    run — there is exactly one valid run_id per (cohort, freeze, subject)."""
    return _sha256("\x1f".join([cohort_content_hash, freeze_hash, subject]))


class EvaluationRecord(BaseModel):
    """One completed evaluation, keyed by the sealed (cohort, freeze, subject)."""

    model_config = ConfigDict(extra="forbid")

    cohort_content_hash: str
    freeze_hash: str
    subject: str


class EvaluationLedger(BaseModel):
    """Append-only record of which (cohort, freeze, subject) triples have already
    been evaluated (R5). Mirrors ``ExposureLedger``. Supplied to ``validate`` as the
    ``prior_evaluations`` baseline so a SECOND evaluation of the same triple — the
    blind re-roll ("freeze once, evaluate N times, keep the best") — is flagged
    ``EVALUATED_MORE_THAN_ONCE`` instead of passing as a fresh run."""

    model_config = ConfigDict(extra="forbid")

    records: list[EvaluationRecord] = Field(default_factory=list)

    def record(self, *, cohort_content_hash: str, freeze_hash: str, subject: str) -> None:
        self.records.append(
            EvaluationRecord(
                cohort_content_hash=cohort_content_hash, freeze_hash=freeze_hash, subject=subject
            )
        )

    def count(self, cohort_content_hash: str, freeze_hash: str, subject: str) -> int:
        return sum(
            1
            for r in self.records
            if r.cohort_content_hash == cohort_content_hash
            and r.freeze_hash == freeze_hash
            and r.subject == subject
        )


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

    # R8: pool and k are MANDATORY. The sample is ALWAYS verified to be the exact
    # deterministic draw ``sample_confusion_pairs(pool, k, seed)`` — so a hand-picked
    # favorable subset can no longer hide behind an omitted pool/k (P1: no binding is
    # skippable by leaving a sibling field None).
    pool: list[str]  # the full confusion-pair pool the sample is drawn from
    k: int  # the sample size
    # Optional binding context. When the full (cohort, freeze, run) is supplied, the
    # seed must be exactly precision_sample_seed(cohort, freeze, run).
    cohort_hash: Optional[str] = None
    freeze_hash: Optional[str] = None
    run_id: Optional[str] = None

    @model_validator(mode="after")
    def _panel_and_sample_are_valid(self) -> "AdjudicatedPrecision":
        if not self.sampled_pairs:
            raise ValueError("precision requires a non-empty blind confusion-pair sample")
        sampled = set(self.sampled_pairs)
        # COVERAGE (H8): every seeded pair must be adjudicated. A subset lets the
        # unfavorable pairs be silently dropped to inflate precision.
        adjudicated = {a.pair_id for a in self.adjudications}
        if adjudicated != sampled:
            raise ValueError(
                f"every seeded pair must be adjudicated: sampled={sorted(sampled)} adjudicated={sorted(adjudicated)}"
            )
        for adj in self.adjudications:
            if adj.pair_id not in sampled:
                raise ValueError(f"adjudicated pair {adj.pair_id!r} is not in the seeded sample")
            if len(adj.verdicts) < 2:
                raise ValueError("each pair needs at least two adjudicators")
            if any(v.is_builder for v in adj.verdicts):
                raise ValueError("adjudicators must be non-builders")
            if not any(not v.is_curator for v in adj.verdicts):
                raise ValueError("at least one adjudicator must be a non-curator")
        # SAMPLE BINDING (R8): pool/k are mandatory, so the draw is ALWAYS verified —
        # the sample must be exactly sample_confusion_pairs(pool, k, seed).
        expected_sample = sample_confusion_pairs(self.pool, self.k, self.seed)
        if list(self.sampled_pairs) != list(expected_sample):
            raise ValueError("sampled_pairs is not the deterministic sample_confusion_pairs(pool, k, seed) draw")
        # If the full seed context is declared, the seed must be exactly
        # precision_sample_seed(cohort, freeze, run).
        if self.cohort_hash is not None and self.freeze_hash is not None and self.run_id is not None:
            expected_seed = precision_sample_seed(self.cohort_hash, self.freeze_hash, self.run_id)
            if self.seed != expected_seed:
                raise ValueError("seed is not bound to precision_sample_seed(cohort_hash, freeze_hash, run_id)")
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

    # The content hash SEALED at creation (H9). Set, ``validate`` recomputes and
    # rejects a mismatch — catching an in-place rewrite of the predictions that
    # ``append`` (with its pre-freeze guard) never saw.
    declared_content_hash: Optional[str] = None

    @property
    def computed_content_hash(self) -> str:
        return _content_hash(
            {
                "freeze_timestamp": self.freeze_timestamp,
                "predictions": [
                    {
                        "entry_identity": p.entry_identity,
                        "predicted_achievable": p.predicted_achievable,
                        "registered_at": p.registered_at,
                        "note": p.note,
                    }
                    for p in self.predictions
                ],
            }
        )

    @property
    def content_hash(self) -> str:
        return self.declared_content_hash or self.computed_content_hash

    def sealed(self) -> "AchievabilityLog":
        return self.model_copy(update={"declared_content_hash": self.computed_content_hash})

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

    # Optional cohort/freeze binding (H7). When supplied and validate() is given the
    # history, the blind denominator is recomputed from the frozen cohort's BLIND
    # entries — a free-int total can no longer under-report the true denominator, and
    # the rediscovered set must be a subset of the actual blind identities.
    cohort_content_hash: Optional[str] = None
    freeze_hash: Optional[str] = None
    rediscovered_blind_ids: Optional[list[str]] = None  # blind entry-identity hashes rediscovered

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
    freeze: Optional[FreezeManifest] = None,
    report: Optional["Report"] = None,
    precision: Optional[AdjudicatedPrecision] = None,
    achievability: Optional[AchievabilityLog] = None,
    prior_exclusions: Optional[ExclusionLog] = None,
    prior_achievability: Optional[AchievabilityLog] = None,
    prior_history: Optional[CohortHistory] = None,
    prior_evaluations: Optional[EvaluationLedger] = None,
) -> ContractReport:
    """Validate the Evaluation Contract (FR-14). Checks entry-hash integrity,
    version monotonicity, denominator preservation, blind-reuse, the exposure
    ledger (curator != subject), freeze-before-evaluation, and the blind-access
    counter. Every violation is collected with a typed reason; ``result.ok`` is
    True only when there are none. A ``check`` that raises is itself a failed check
    (Constitution VII), so unexpected errors are captured, not propagated.

    The optional parameters (``freeze``, ``report``, ``precision``,
    ``achievability``, and the ``prior_*`` baselines) let ``validate`` enforce the
    adversarial-audit seals (H1..H9) that previously lived only in constructor
    helpers — bypassed whenever a model is rebuilt from storage. They are
    keyword-only and default to ``None`` so every existing call site keeps working
    unchanged."""
    result = ContractReport()

    try:
        if history is not None:
            _check_entry_hash_integrity(history, result)
            _check_content_seals(history, result)
            _check_version_monotonicity(history, result)
            _check_denominator_preservation(history, exclusions, result)
            _check_blind_reuse(history, result)
            if prior_history is not None:
                _check_history_extension(history, prior_history, result)  # R3

        if exclusions is not None:
            _check_exclusion_run_validity(exclusions, result)
            if prior_exclusions is not None and not exclusions.is_extension_of(prior_exclusions):
                result.add(
                    ViolationReason.IN_PLACE_EDIT,
                    "exclusion log is not an append-only extension of its prior baseline",
                )

        if run is not None:
            _check_freeze_before_evaluation(run, result)
            _check_blind_access(run, result)
            _check_run_id_canonical(run, result)  # R5
            _check_evaluation_ledger(run, prior_evaluations, result)  # R5
            # R6: a run that recorded post-freeze attempts MUST be validated against
            # its FreezeManifest — a fabricated run.freeze_hash cannot stand in for it.
            if run.post_freeze_attempts and freeze is None:
                result.add(
                    ViolationReason.MISSING_FREEZE,
                    "a run with post-freeze attempts must be validated against its FreezeManifest",
                )
            if ledger is not None:
                _check_exposure(run, ledger, history, result)  # R7

        if freeze is not None:
            _check_freeze_binding(freeze, run, history, result)

        if report is not None:
            _check_report(report, history, run, freeze, result)

        if precision is not None:
            _check_precision_binding(precision, run, freeze, result)

        if achievability is not None:
            _check_achievability(achievability, prior_achievability, result)
    except ContractViolation as exc:  # a guard that raised mid-check is a failure
        result.violations.append(exc)
    except Exception as exc:  # noqa: BLE001 - any crash in check IS a failed check
        result.add(ViolationReason.IN_PLACE_EDIT, f"unexpected check error: {exc}")

    return result


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
    # A removal is legitimate ONLY when a COHORT_CORRECTION-class event names the
    # EXACT (identity, from_version, to_version) transition (H1 + H4). A class-blind
    # or flat-identity check let a miss/infra/policy event — or a stale v1->v2 event
    # — launder a later removal. Events are consumed per transition: one event
    # authorizes exactly its named removal.
    #
    # R2: preservation is BLIND-SET preserving, not merely identity-set preserving.
    # An identity can leave the authoritative blind denominator two ways — by being
    # removed from the cohort entirely, OR by a role-downgrade (BLIND -> regression/
    # calibration) that keeps its identity. BOTH must be authorized by a matched
    # COHORT_CORRECTION event. The union is deduped, so an identity that both leaves
    # the blind set and is removed needs exactly one event.
    available: "Counter[tuple[str, str, str]]" = (
        exclusions.correction_transitions() if exclusions is not None else Counter()
    )
    for prev, curr in zip(history.versions, history.versions[1:]):
        removed = prev.identities() - curr.identities()
        prev_blind = {e.computed_identity_hash for e in prev.by_role(Role.BLIND)}
        curr_blind = {e.computed_identity_hash for e in curr.by_role(Role.BLIND)}
        left_blind = prev_blind - curr_blind
        must_authorize = removed | left_blind
        for identity in sorted(must_authorize):
            key = (identity, prev.version, curr.version)
            if available.get(key, 0) > 0:
                available[key] -= 1  # consume the one event that authorizes this transition
            else:
                report.add(
                    ViolationReason.DENOMINATOR_SHRINK,
                    f"{prev.version}->{curr.version}: entry {identity[:12]} left the blind denominator "
                    "(removed or role-downgraded) with no matching cohort-correction event",
                )


def _check_history_extension(
    history: CohortHistory, prior: CohortHistory, report: ContractReport
) -> None:
    """R3: the presented ``history`` must be an APPEND-ONLY extension of the
    ``prior_history`` baseline. Every version in the baseline must appear at the same
    index with an identical content_hash. A from-storage rebuild that drops an earlier
    version (e.g. collapses to a single easier version, dodging the consecutive-pair
    denominator check) or rewrites a prior version is rejected — HISTORY_TRUNCATED for
    a dropped/reordered version, IN_PLACE_EDIT for a same-tag content rewrite."""
    for i, prior_cohort in enumerate(prior.versions):
        if i >= len(history.versions):
            report.add(
                ViolationReason.HISTORY_TRUNCATED,
                f"baseline version {prior_cohort.version} (index {i}) is missing from the presented history",
            )
            continue
        curr = history.versions[i]
        if curr.version != prior_cohort.version:
            report.add(
                ViolationReason.HISTORY_TRUNCATED,
                f"baseline version {prior_cohort.version} at index {i} was dropped/reordered "
                f"(presented {curr.version} instead)",
            )
        elif curr.content_hash != prior_cohort.content_hash:
            report.add(
                ViolationReason.IN_PLACE_EDIT,
                f"baseline version {prior_cohort.version} content changed vs the prior_history baseline",
            )


def _check_exclusion_run_validity(exclusions: ExclusionLog, report: ContractReport) -> None:
    # An INFRASTRUCTURE-class exclusion is a failed measurement, not a detector
    # verdict: it INVALIDATES the run rather than quietly shrinking the denominator
    # (H2; threat-model L-vectors "infrastructure failure INVALIDATES the run").
    for event in exclusions.events:
        if event.invalidates_run:
            report.add(
                ViolationReason.RUN_INVALID,
                f"infrastructure exclusion {event.reason.value!r} invalidates the run",
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
    # Mirror the infra-retry invariant that ``attempt_evaluation`` enforces at
    # record-time, so a run REBUILT FROM STORAGE cannot launder several blind
    # evaluations as "retries" (H5). Across the post-freeze attempts: every
    # non-producing attempt must have intact logs and the SAME artifact/env hashes
    # as the first post-freeze attempt; any post-freeze attempt with broken logs is
    # itself a violation.
    post = run.post_freeze_attempts
    if post:
        first = post[0]
        for attempt in post:
            if not attempt.logs_intact:
                report.add(
                    ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED,
                    f"run {run.run_id}: a post-freeze attempt has logs_intact=False",
                )
                break
        for attempt in post[1:]:
            if attempt.artifact_hash != first.artifact_hash or attempt.env_hash != first.env_hash:
                report.add(
                    ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED,
                    f"run {run.run_id}: post-freeze artifact/env hashes changed across attempts",
                )
                break


def _check_exposure(
    run: EvaluationRun,
    ledger: ExposureLedger,
    history: Optional[CohortHistory],
    report: ContractReport,
) -> None:
    """R7: resolve exposure by ENTRY IDENTITY across versions, not by the
    version-scoped cohort content hash. A version bump (same entries, new hash) must
    not launder a curator into a subject: if the subject curated/inspected ANY cohort
    version that shares an entry identity with the scored cohort, it is barred."""
    # Direct content-hash exposure always bars (works even with no history to resolve).
    if not ledger.can_score(run.cohort_content_hash, run.subject):
        report.add(
            ViolationReason.CURATOR_IS_SUBJECT,
            f"run {run.run_id}: subject {run.subject!r} curated/inspected this cohort",
        )
        return
    # Entry-identity resolution across versions (needs history to resolve hashes).
    scored = _cohort_by_content_hash(history, run.cohort_content_hash)
    if scored is None:
        return
    scored_ids = scored.identities()
    for record in ledger.records:
        if record.actor != run.subject:
            continue
        record_cohort = _cohort_by_content_hash(history, record.cohort_content_hash)
        if record_cohort is None:
            continue
        if scored_ids & record_cohort.identities():
            report.add(
                ViolationReason.CURATOR_IS_SUBJECT,
                f"run {run.run_id}: subject {run.subject!r} curated/inspected a cohort version "
                "sharing an entry identity with the scored cohort",
            )
            return


def _check_run_id_canonical(run: EvaluationRun, report: ContractReport) -> None:
    """R5: the run_id must be the ONE canonical hash of (cohort, freeze, subject).
    A free-string run_id is re-rollable — it lets an operator freeze once and mint a
    fresh run_id per attempt to re-roll the precision sample or launder a repeat
    evaluation. Enforced whenever the run carries a freeze_hash (the run has frozen)."""
    if run.freeze_hash is None:
        return
    expected = _canonical_run_id(run.cohort_content_hash, run.freeze_hash, run.subject)
    if run.run_id != expected:
        report.add(
            ViolationReason.NON_CANONICAL_RUN_ID,
            f"run_id {run.run_id!r} != canonical(cohort, freeze, subject) {expected[:12]}",
        )


def _check_evaluation_ledger(
    run: EvaluationRun, prior_evaluations: Optional[EvaluationLedger], report: ContractReport
) -> None:
    """R5: evaluate-once. If a prior EvaluationLedger already contains this
    (cohort, freeze, subject) triple, this is a second evaluation of the same blind
    cohort — the "keep the best of N" re-roll — and is flagged."""
    if run.freeze_hash is None or prior_evaluations is None:
        return
    if prior_evaluations.count(run.cohort_content_hash, run.freeze_hash, run.subject) > 0:
        report.add(
            ViolationReason.EVALUATED_MORE_THAN_ONCE,
            f"run {run.run_id}: (cohort, freeze, subject={run.subject!r}) was already evaluated",
        )


def _cohort_by_content_hash(history: Optional[CohortHistory], content_hash: Optional[str]) -> Optional[Cohort]:
    if history is None:
        return None
    if content_hash is not None:
        for cohort in history.versions:
            if cohort.content_hash == content_hash:
                return cohort
    return None


def _blind_identities(cohort: Cohort) -> set[str]:
    return {e.computed_identity_hash for e in cohort.by_role(Role.BLIND)}


def _check_freeze_binding(
    freeze: FreezeManifest,
    run: Optional[EvaluationRun],
    history: Optional[CohortHistory],
    report: ContractReport,
) -> None:
    """A freeze must bind a real bundle (H6). The run's ``freeze_hash`` must equal
    the freeze's content hash — a free string can no longer stand in for a frozen
    bundle — and the calibration seeds must be disjoint from the scored cohort's
    BLIND entries (a seed sitting in the blind set would tune on the denominator)."""
    if run is not None and run.freeze_hash is not None and run.freeze_hash != freeze.freeze_hash:
        report.add(
            ViolationReason.BAD_FREEZE_BINDING,
            f"run freeze_hash {run.freeze_hash!r} does not equal the frozen bundle hash {freeze.freeze_hash[:12]}",
        )

    cohort = None
    if run is not None:
        cohort = _cohort_by_content_hash(history, run.cohort_content_hash)
    if cohort is None and history is not None:
        cohort = history.latest()
    if cohort is not None:
        blind = _blind_identities(cohort)
        overlap = blind & set(freeze.bundle.calibration_seed_ids)
        for identity in sorted(overlap):
            report.add(
                ViolationReason.SEED_IN_BLIND,
                f"calibration seed {identity[:12]} is also a BLIND entry in the scored cohort",
            )


def _check_report(
    report_view: "Report",
    history: Optional[CohortHistory],
    run: Optional[EvaluationRun],
    freeze: Optional[FreezeManifest],
    report: ContractReport,
) -> None:
    """Bind the Report's blind recall to the frozen cohort (H7). ``blind_recall.total``
    is recomputed from the cohort's BLIND entries, so a free int can no longer
    under-report the true denominator; the rediscovered set (when supplied) must be a
    subset of the actual blind identities and its size must equal the reported count."""
    cohort = _cohort_by_content_hash(history, report_view.cohort_content_hash)
    if cohort is None and run is not None:
        cohort = _cohort_by_content_hash(history, run.cohort_content_hash)
    if cohort is None and history is not None:
        cohort = history.latest()
    if cohort is None:
        # R4 (P1): a Report presented with nothing to bind against is NOT a silent
        # pass — an unbound headline number is unverifiable and therefore rejected.
        report.add(
            ViolationReason.REPORT_UNBOUND,
            "a Report must bind to a resolvable cohort/history; none resolved",
        )
        return

    blind = _blind_identities(cohort)
    if report_view.blind_recall.total != len(blind):
        report.add(
            ViolationReason.REPORT_DENOMINATOR_MISMATCH,
            f"reported blind total {report_view.blind_recall.total} != frozen cohort blind count {len(blind)}",
        )

    if freeze is not None and report_view.freeze_hash is not None and report_view.freeze_hash != freeze.freeze_hash:
        report.add(
            ViolationReason.REPORT_DENOMINATOR_MISMATCH,
            "report freeze_hash does not equal the frozen bundle hash",
        )

    # R4 (P1): the numerator binding is MANDATORY once a cohort resolves. Without the
    # per-entry rediscovered set, a headline "4/4" is an unverifiable free integer.
    if report_view.rediscovered_blind_ids is None:
        report.add(
            ViolationReason.REPORT_DENOMINATOR_MISMATCH,
            "rediscovered_blind_ids is required to bind the numerator to the frozen cohort's blind entries",
        )
    else:
        rediscovered = set(report_view.rediscovered_blind_ids)
        extraneous = rediscovered - blind
        if extraneous:
            report.add(
                ViolationReason.REPORT_DENOMINATOR_MISMATCH,
                f"rediscovered set contains {len(extraneous)} identity(ies) that are not BLIND entries",
            )
        if report_view.blind_recall.rediscovered != len(rediscovered & blind):
            report.add(
                ViolationReason.REPORT_DENOMINATOR_MISMATCH,
                f"reported rediscovered {report_view.blind_recall.rediscovered} != "
                f"|rediscovered ∩ blind| {len(rediscovered & blind)}",
            )


def _check_precision_binding(
    precision: AdjudicatedPrecision,
    run: Optional[EvaluationRun],
    freeze: Optional[FreezeManifest],
    report: ContractReport,
) -> None:
    """Route precision through validate (H8/R8). The seed must be the deterministic
    ``precision_sample_seed`` over THIS run's (cohort, freeze, run_id); a precision
    computed over some other context — a re-rolled sample — is rejected. R8 (P1): a
    precision object presented with no run/freeze to bind to is itself unbound — it is
    not silently accepted."""
    if run is None or freeze is None:
        report.add(
            ViolationReason.PRECISION_SAMPLE_UNBOUND,
            "precision presented without a run/freeze to bind the sample to",
        )
        return
    if precision.cohort_hash is not None and precision.cohort_hash != run.cohort_content_hash:
        report.add(
            ViolationReason.PRECISION_SAMPLE_UNBOUND,
            "precision cohort_hash does not match the run's cohort",
        )
    if precision.run_id is not None and precision.run_id != run.run_id:
        report.add(
            ViolationReason.PRECISION_SAMPLE_UNBOUND,
            f"precision run_id {precision.run_id!r} does not match run {run.run_id!r}",
        )
    if precision.freeze_hash is not None and precision.freeze_hash != freeze.freeze_hash:
        report.add(
            ViolationReason.PRECISION_SAMPLE_UNBOUND,
            "precision freeze_hash does not equal the frozen bundle hash",
        )
    expected_seed = precision_sample_seed(run.cohort_content_hash, freeze.freeze_hash, run.run_id)
    if precision.seed != expected_seed:
        report.add(
            ViolationReason.PRECISION_SAMPLE_UNBOUND,
            "precision seed is not precision_sample_seed(cohort, freeze, run_id) for this run",
        )


def _check_achievability(
    achievability: AchievabilityLog,
    prior: Optional[AchievabilityLog],
    report: ContractReport,
) -> None:
    """Enforce the achievability seals in validate (H9). Every prediction must be
    pre-registered before the freeze timestamp (a direct construction bypasses
    ``append``'s guard); the declared seal must match a recompute (an in-place
    rewrite trips it); and, when a baseline is supplied, the log must be an
    append-only extension of it."""
    for prediction in achievability.predictions:
        if prediction.registered_at >= achievability.freeze_timestamp:
            report.add(
                ViolationReason.ACHIEVABILITY_NOT_PRE_FREEZE,
                f"prediction for {prediction.entry_identity!r} registered at/after the freeze timestamp",
            )
    if achievability.declared_content_hash is not None and achievability.declared_content_hash != achievability.computed_content_hash:
        report.add(
            ViolationReason.IN_PLACE_EDIT,
            "achievability log content changed in place after its seal",
        )
    if prior is not None and achievability.predictions[: len(prior.predictions)] != prior.predictions:
        report.add(
            ViolationReason.IN_PLACE_EDIT,
            "achievability log is not an append-only extension of its prior baseline",
        )


# A convenience alias: the contract's `check` (FR-14) reads as `check(...)` too.
check = validate


def check_report(
    report: "Report",
    history: Optional[CohortHistory],
    *,
    run: Optional[EvaluationRun] = None,
    freeze: Optional[FreezeManifest] = None,
) -> ContractReport:
    """Standalone Report/recall binding check (H7), also reachable through
    ``validate(report=...)``. Recomputes the blind denominator from the frozen
    cohort's BLIND entries and returns a typed ``ContractReport``."""
    result = ContractReport()
    _check_report(report, history, run, freeze, result)
    return result
