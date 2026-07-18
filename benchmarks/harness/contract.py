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
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
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


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _content_hash(obj: Any) -> str:
    return _sha256(_canonical_json(obj))


def blob_sha256(source: str) -> str:
    """R8-1: the sha256 of a fetched target file's UTF-8 bytes — the per-target CONTENT hash a
    ``CohortEntry`` commits (``vuln_blob_sha256`` / ``patched_blob_sha256``) and folds into its
    identity. The numerator recompute (``verifier``) requires each fetched source to reproduce
    this committed hash, so an attacker controlling the fetch source/cache cannot feed the
    detector DOCTORED bytes and have it "confirm" a false rediscovery. The fetcher returns text
    decoded UTF-8, so hashing ``source.encode('utf-8')`` is the machine-independent content
    address of exactly the bytes the detector parses."""
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Cryptographic anchoring primitives (Part B) — stdlib-only, DETERMINISTIC
# --------------------------------------------------------------------------- #
#
# These turn "omit / truncate / rewrite / reorder any component" from a
# fail-closed hole into an *impossible* one: a certified score is bound to a
# single committed, signed root, and ``validate(strict=...)`` refuses unless the
# presented state REPRODUCES that root and the signature verifies.
#
# The anti-omission property does NOT depend on the signature — it comes from
# "the presented state must reproduce the committed root". The signature adds
# non-repudiation and tamper-evidence. Signing is ASYMMETRIC ed25519 (round-6):
# ``genesis_root.json`` commits ONLY the ed25519 PUBLIC key, so any repo reader can
# VERIFY but none can FORGE a signature — the private signing key is held externally
# by a party that is NOT the scored subject (curator != subject). ed25519 is
# deterministic (no per-signature randomness), so a signature computed on one machine
# equals the signature computed anywhere else; the hashing (``hashlib``) uses no wall
# clock and no randomness, so every root is machine-independent too.

# A fixed, domain-separated genesis for the append-only chain fold. Baking a
# constant in means an empty chain has a well-defined, reproducible root.
_CHAIN_GENESIS = _sha256("deepthought/evaluation-contract/chain-genesis/v1")


def leaf_hash(obj: Any) -> str:
    """A leaf hash = sha256 of the object's canonical JSON. Two semantically
    equal objects hash identically on any machine."""
    return _content_hash(obj)


# R10-7: domain-separation prefixes (CVE-2012-2459). A leaf is hashed under 0x00 and an
# internal node under 0x01, so a leaf digest can never be mistaken for an internal-node
# digest — the precondition for the classic duplicate-leaf second-preimage collision.
_MERKLE_LEAF_PREFIX = b"\x00"
_MERKLE_NODE_PREFIX = b"\x01"


def _merkle_tree_hash(leaves: list[str]) -> str:
    """R10-7 (RFC 6962-style, domain-separated) tree hash over an ORDERED leaf list.
    Leaves are hashed under the 0x00 prefix and internal nodes under 0x01; an odd level is
    split at the largest power of two BELOW the count (never duplicate-last), so no leaf set
    can collide with a different one carrying a duplicated tail (CVE-2012-2459)."""
    n = len(leaves)
    if n == 1:
        return _sha256_bytes(_MERKLE_LEAF_PREFIX + leaves[0].encode("utf-8"))
    k = 1
    while k * 2 < n:
        k *= 2  # the largest power of two strictly less than n
    left = _merkle_tree_hash(leaves[:k])
    right = _merkle_tree_hash(leaves[k:])
    return _sha256_bytes(_MERKLE_NODE_PREFIX + left.encode("utf-8") + right.encode("utf-8"))


def merkle_root(hashes: list[str]) -> str:
    """A deterministic, DOMAIN-SEPARATED sha256 Merkle root over ``sorted(hashes)`` (R10-7).
    Order-independent by construction: the same *set* of leaves always yields the same root,
    so callers need not agree on an order. An empty list yields the domain-separated genesis
    (a well-defined "nothing" root).

    R10-7 (CVE-2012-2459): leaves are hashed under a 0x00 prefix and internal nodes under a
    0x01 prefix, and an odd level is split at the largest power of two below the count rather
    than by duplicating the last node — so ``merkle_root([...,x]) != merkle_root([...,x,x])``:
    a duplicate-leaf second preimage can no longer collide with a shorter honest set."""
    nodes = sorted(hashes)
    if not nodes:
        return _CHAIN_GENESIS
    return _merkle_tree_hash(nodes)


def chain_root(entries: list[str]) -> str:
    """An APPEND-ONLY root: fold ``h = sha256(h || entry)`` from the fixed
    genesis. Because each step mixes the running hash with the next entry in
    order, dropping, reordering, OR rewriting ANY entry changes the final root —
    that is the anti-truncation / anti-rewrite property the ledgers rely on. An
    empty entry list yields the genesis."""
    h = _CHAIN_GENESIS
    for entry in entries:
        h = _sha256(h + entry)
    return h


# The reproducible "nothing" root shared by an empty history / ledger / log.
_EMPTY_ROOT = chain_root([])


# --------------------------------------------------------------------------- #
# PART 3 / Round-5 — the git-anchored, MONOTONIC committed genesis state
# --------------------------------------------------------------------------- #
#
# A pure validator cannot verify GENESIS COMPLETENESS — that the committed
# baseline was not itself a truncated, self-serving starting point — nor can it hold a
# caller-supplied ``prior_history`` honest, because the scored party supplies it. Both
# move OUT of the validator and into GIT: ``benchmarks/harness/genesis_root.json`` is a
# committed, reviewable file whose git history supplies the external timestamp and
# review the validator cannot. Round-5 makes it a REAL, non-empty, MONOTONIC chain:
# it holds the initial cohort's ``genesis_history_root`` PLUS the ``latest`` certified
# ``{history_root, attestation_root}``, and the evaluator's committed ``{id,
# verify_key}``. The strict certify path loads the prior baseline FROM this committed
# state (never from the caller): the presented history must append-only-EXTEND the
# committed prior history root (else ``ATTESTATION_NOT_EXTENDING``) and the attestation
# must chain from the committed latest attestation root (else ``GENESIS_UNANCHORED``),
# so post-genesis truncation is impossible and no operator can re-anchor to a fresh,
# private genesis. On a successful certify the harness calls
# :func:`advance_committed_root` to persist the new roots — the chain advances only
# through committed, git-reviewable state.

_GENESIS_ROOT_PATH = Path(__file__).resolve().parent / "genesis_root.json"

# The domain-separated attestation-chain base: the ``prior_attestation_root`` the FIRST
# certification chains from before any real attestation exists. Committing it (as the
# initial ``latest.attestation_root``) means the chain base is well-defined and
# reproducible, distinct from the history genesis so the two anchors never alias.
_ATTESTATION_CHAIN_GENESIS = _sha256("deepthought/evaluation-contract/attestation-chain-genesis/v1")


class CommittedGenesisState(BaseModel):
    """The committed, git-reviewable anchor state loaded from ``genesis_root.json``: the
    immutable initial ``genesis_history_root`` plus the advancing ``latest`` certified
    ``{history_root, attestation_root, evaluation_root}`` and the committed evaluator
    ``{id, verify_key}``. The strict certify path binds to THIS, never to a caller-supplied
    baseline.

    ``verify_key`` is the committed ed25519 PUBLIC key (round-6); the matching private
    signing key is held EXTERNALLY by the curator (curator != subject) and is NEVER in the
    committed file. ``latest_evaluation_root`` (F2) is the committed root of the append-only
    EvaluationLedger: the presented ``prior_evaluations`` must reproduce + append-only-extend
    it, so evaluate-once is COMMITTED monotonic state, not a caller-suppliable empty ledger."""

    model_config = ConfigDict(extra="ignore")

    genesis_history_root: str
    latest_history_root: str
    latest_attestation_root: str
    latest_evaluation_root: str = _EMPTY_ROOT
    # R10-2: the committed root of the append-only ExposureLedger. The presented ledger must
    # reproduce + append-only-extend it, so a truncated exposure ledger (drop the incriminating
    # curator record and re-sign) cannot certify — parity with history/evaluation. Its bootstrap
    # value is the reproducible empty-ledger root (no committed exposure baseline yet).
    latest_exposure_root: str = _EMPTY_ROOT
    # Feature 009: the committed root of the append-only ClassManifest history — the SET of classes
    # that feed the aggregate mean. Given the SAME committed-monotonic treatment as history/eval/
    # exposure: a presented manifest must reproduce + append-only-extend it (else
    # CLASS_MANIFEST_TRUNCATED), so a whole class cannot be silently dropped from the headline. Its
    # bootstrap value is the reproducible empty-ledger root (no committed manifest baseline yet).
    latest_class_manifest_root: str = _EMPTY_ROOT
    evaluator_id: str
    verify_key: bytes
    # R10-6: the committed adjudicator roster — ``{adjudicator_id: {is_builder, is_curator}}``. The
    # certify path validates each verdict's self-asserted ``is_builder`` / ``is_curator`` against
    # THIS (trust the committed roster, not the self-assertion) and requires the adjudicator to be
    # independent of the scored subject. That the rostered adjudicators are genuinely independent
    # people is the irreducible organizational remainder (documented, alongside key custody).
    adjudicator_roster: dict[str, dict[str, bool]] = Field(default_factory=dict)
    # Feature 009 (AUDIT-009-2): the committed per-class registry ``{class_id: head_history_root}``.
    # It fixes each aggregated class's 008 head history root in git-reviewable state so the aggregate
    # certify binds a per-class attestation to its class INDEPENDENTLY of the operator-supplied
    # manifest entry (which the operator controls). Empty by default (the genesis-completeness floor
    # at bootstrap); a production deployment commits the real per-class roots.
    class_registry: dict[str, str] = Field(default_factory=dict)


def _read_committed_config(path: Optional[Path] = None) -> dict:
    p = path or _GENESIS_ROOT_PATH
    return json.loads(p.read_text(encoding="utf-8"))


def load_committed_genesis_state(path: Optional[Path] = None) -> CommittedGenesisState:
    """Load the full committed anchor state. Tests monkeypatch THIS loader with a hermetic
    fixture consistent with their presented history, so they never depend on the real
    committed file's value; production reads the reviewable, version-controlled
    ``genesis_root.json``. Every root must be a non-empty string (an inert/empty root
    would let a truncated cohort 'anchor' — R5-2 fails closed)."""
    data = _read_committed_config(path)
    genesis = data.get("genesis_history_root")
    if not isinstance(genesis, str) or not genesis:
        raise ValueError(f"{path or _GENESIS_ROOT_PATH}: genesis_history_root must be a non-empty string")
    latest = data.get("latest") or {}
    latest_history = latest.get("history_root") or genesis
    latest_attestation = latest.get("attestation_root") or _ATTESTATION_CHAIN_GENESIS
    # F2: the committed EvaluationLedger root. An absent value means "no eval has certified
    # yet", i.e. the empty-ledger root — a well-defined, reproducible baseline.
    latest_evaluation = latest.get("evaluation_root") or _EMPTY_ROOT
    # R10-2: the committed ExposureLedger root. An absent value means "no committed exposure
    # baseline yet", i.e. the empty-ledger root (the same reproducible bootstrap sentinel).
    latest_exposure = latest.get("exposure_root") or _EMPTY_ROOT
    # Feature 009: the committed ClassManifest root. Absent -> the empty-ledger bootstrap sentinel
    # ("no committed manifest baseline yet"), which any presented manifest extends; truncation
    # protection engages once a real (non-empty) committed manifest baseline exists.
    latest_class_manifest = latest.get("class_manifest_root") or _EMPTY_ROOT
    # R8-6: fail closed on an INERT committed HISTORY root. ``_history_reproduces_committed``
    # anchors any prefix that reproduces the committed prior history root, so an inert root
    # (the empty ``chain_root([])`` genesis) would let a TRUNCATED cohort "anchor" against the
    # empty prefix — exactly what the docstring promises to reject. The immutable
    # ``genesis_history_root`` and the advancing ``latest.history_root`` must therefore be REAL,
    # non-inert commitments. (The attestation/evaluation chain BASES are legitimately their inert
    # bootstrap sentinels until the first certify, so they are not rejected here.)
    _inert_history_roots = {_CHAIN_GENESIS, _EMPTY_ROOT}
    if genesis in _inert_history_roots:
        raise ValueError(
            f"{path or _GENESIS_ROOT_PATH}: genesis_history_root is the inert empty-chain root; a "
            "truncated cohort would anchor against it (fail closed)"
        )
    if not isinstance(latest_history, str) or not latest_history:
        raise ValueError("latest.history_root must be a non-empty string")
    if latest_history in _inert_history_roots:
        raise ValueError(
            "latest.history_root is the inert empty-chain root; a truncated cohort would anchor "
            "against it (fail closed)"
        )
    if not isinstance(latest_attestation, str) or not latest_attestation:
        raise ValueError("latest.attestation_root must be a non-empty string")
    if not isinstance(latest_evaluation, str) or not latest_evaluation:
        raise ValueError("latest.evaluation_root must be a non-empty string")
    if not isinstance(latest_exposure, str) or not latest_exposure:
        raise ValueError("latest.exposure_root must be a non-empty string")
    if not isinstance(latest_class_manifest, str) or not latest_class_manifest:
        raise ValueError("latest.class_manifest_root must be a non-empty string")
    evaluator = data.get("evaluator") or {}
    evaluator_id = evaluator.get("id")
    # F4: the committed value is the ed25519 PUBLIC key (verify_key_pub_hex). The private
    # signing key is held externally by the curator and is NEVER committed.
    verify_key_pub_hex = evaluator.get("verify_key_pub_hex")
    if not isinstance(evaluator_id, str) or not evaluator_id:
        raise ValueError("evaluator.id must be a non-empty string")
    if not isinstance(verify_key_pub_hex, str) or not verify_key_pub_hex:
        raise ValueError("evaluator.verify_key_pub_hex must be a non-empty hex string (the ed25519 PUBLIC key)")
    # R10-6: normalise the committed adjudicator roster to ``{id: {is_builder, is_curator}}``.
    raw_roster = data.get("adjudicators") or {}
    roster: dict[str, dict[str, bool]] = {}
    for name, flags in raw_roster.items():
        flags = flags or {}
        roster[name] = {
            "is_builder": bool(flags.get("is_builder", False)),
            "is_curator": bool(flags.get("is_curator", False)),
        }
    # Feature 009: normalise the committed per-class registry to ``{class_id: head_history_root}``.
    raw_registry = data.get("classes") or {}
    class_registry: dict[str, str] = {}
    for class_id, entry in raw_registry.items():
        # accept either a bare root string or a {"head_history_root": ...} object for forward-compat.
        root = entry.get("head_history_root") if isinstance(entry, dict) else entry
        if isinstance(root, str) and root:
            class_registry[class_id] = root
    return CommittedGenesisState(
        genesis_history_root=genesis,
        latest_history_root=latest_history,
        latest_attestation_root=latest_attestation,
        latest_evaluation_root=latest_evaluation,
        latest_exposure_root=latest_exposure,
        latest_class_manifest_root=latest_class_manifest,
        evaluator_id=evaluator_id,
        verify_key=bytes.fromhex(verify_key_pub_hex),
        adjudicator_roster=roster,
        class_registry=class_registry,
    )


def load_committed_genesis_root(path: Optional[Path] = None) -> str:
    """The committed root the NEXT attestation must chain FROM — the ``latest`` certified
    attestation root (the attestation-chain genesis when nothing has certified yet).
    Kept as the honest default for :func:`build_attestation`'s ``prior_attestation_root``."""
    return load_committed_genesis_state(path).latest_attestation_root


def load_committed_verify_key(path: Optional[Path] = None) -> bytes:
    """The committed evaluator ed25519 PUBLIC key (F4). ``validate`` verifies attestations
    against THIS, never a caller-supplied key — a subject-minted key or an old HMAC secret
    fails ``ATTESTATION_INVALID``. Because only the PUBLIC key is committed, a repo reader can
    verify but cannot forge; the matching private signing key is held externally by a party
    that is NOT the scored subject (curator != subject) — the organizational custody floor."""
    return load_committed_genesis_state(path).verify_key


def load_committed_evaluation_root(path: Optional[Path] = None) -> str:
    """The committed EvaluationLedger root (F2) the presented ``prior_evaluations`` must
    reproduce + append-only-extend. Evaluate-once is thereby COMMITTED monotonic state: a
    caller cannot present an empty ledger to dodge the blind-set re-roll check."""
    return load_committed_genesis_state(path).latest_evaluation_root


def load_committed_evaluator_id(path: Optional[Path] = None) -> str:
    """The committed evaluator identity (R5-4). A certified attestation's ``evaluator_id``
    must equal this committed id (and differ from the scored subject)."""
    return load_committed_genesis_state(path).evaluator_id


def load_committed_class_manifest_root(path: Optional[Path] = None) -> str:
    """Feature 009: the committed ClassManifest root the presented manifest must reproduce +
    append-only-extend. The SET of classes feeding the aggregate mean is thereby COMMITTED
    monotonic state: an operator cannot present a smaller manifest to drop a weak class."""
    return load_committed_genesis_state(path).latest_class_manifest_root


def advance_committed_root(
    *,
    history_root: Optional[str] = None,
    attestation_root: Optional[str] = None,
    evaluation_root: Optional[str] = None,
    exposure_root: Optional[str] = None,
    class_manifest_root: Optional[str] = None,
    path: Optional[Path] = None,
) -> None:
    """Persist the new certified roots to the committed file (R5-2 + F2 + R10-2/R10-4), advancing
    the chain. The immutable ``genesis_history_root`` is preserved; only ``latest`` moves —
    including ``evaluation_root`` (F2, evaluate-once) AND ``exposure_root`` (R10-2, curator-set) —
    so BOTH ledgers are COMMITTED monotonic state that advances only through this git-reviewable
    file, with no inert short-circuit left to dodge them. Called by the harness AFTER a successful
    strict certify. Written atomically (temp + replace).

    Every root is PRESERVED when omitted (``None``), so a per-class 008 certify advances the four
    008 roots while a feature-009 aggregate certify advances ``class_manifest_root`` alone — neither
    disturbs the other's committed state. 008 callers that pass all four roots explicitly are
    unaffected."""
    p = path or _GENESIS_ROOT_PATH
    data = _read_committed_config(p)
    prior_latest = data.get("latest") or {}
    data["latest"] = {
        "history_root": history_root if history_root is not None else prior_latest.get("history_root"),
        "attestation_root": attestation_root if attestation_root is not None else prior_latest.get("attestation_root"),
        "evaluation_root": evaluation_root if evaluation_root is not None else prior_latest.get("evaluation_root"),
        "exposure_root": exposure_root if exposure_root is not None else prior_latest.get("exposure_root"),
        "class_manifest_root": class_manifest_root if class_manifest_root is not None else prior_latest.get("class_manifest_root", _EMPTY_ROOT),
    }
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)


def _history_reproduces_committed(history: "CohortHistory", committed_prior_root: str) -> bool:
    """R5-2: True iff some prefix of the presented history's append-only version chain
    reproduces the committed prior ``history_root`` — i.e. the presented history is exactly
    the committed prior history plus zero-or-more appended versions. ``history_root`` is a
    prefix fold (:func:`chain_root`), so a prefix reproducing the committed root proves
    every committed prior version is present, unchanged, and in order (omitting, rewriting,
    or reordering any changes the fold). The committed prior root is REAL and non-empty, so
    the reproducing prefix is non-trivial — a truncated cohort cannot anchor."""
    running = _CHAIN_GENESIS
    if running == committed_prior_root:
        return True
    for version in history.versions:
        running = _sha256(running + version.content_hash)
        if running == committed_prior_root:
            return True
    return False


def _evaluation_reproduces_committed(ledger: "EvaluationLedger", committed_root: str) -> bool:
    """F2 + R10-4: True iff some prefix of the presented ``prior_evaluations`` append-only chain
    reproduces the committed ``latest_evaluation_root`` — i.e. the presented ledger is exactly
    the committed prior ledger plus zero-or-more appended records. The ledger ``root`` is a
    prefix fold (:func:`chain_root`) over ``leaf_hash(record)``, so a prefix reproducing the
    committed root proves every committed prior evaluation is present, unchanged, and in order
    (omitting, rewriting, or reordering any changes the fold). An operator can therefore NOT
    present an empty ledger to dodge the blind-set re-roll check: the empty-ledger root only
    reproduces a committed root that is itself empty (a genuine first evaluation).

    R10-4 (fail closed on the inert short-circuit, matching R8-6 for history): the inert
    empty-chain committed root is a legitimate baseline ONLY at bootstrap — an EMPTY presented
    ledger. A NON-EMPTY ledger that "reproduces" the inert root via the empty prefix means the
    committed chain never advanced to record those prior evals, so the genesis short-circuit is
    honored only when there is genuinely nothing to reproduce (``not ledger.records``)."""
    running = _CHAIN_GENESIS
    if running == committed_root:
        return not ledger.records
    for record in ledger.records:
        running = _sha256(running + leaf_hash(record.model_dump(mode="json")))
        if running == committed_root:
            return True
    return False


def _exposure_reproduces_committed(ledger: "ExposureLedger", committed_root: str) -> bool:
    """R10-2: True iff some prefix of the presented ``ledger`` append-only chain reproduces the
    committed ``latest_exposure_root`` — i.e. the presented exposure ledger is exactly the
    committed prior ledger plus zero-or-more appended records. The ledger ``root`` is a prefix
    fold (:func:`chain_root`) over ``leaf_hash(record)``, so a prefix reproducing the committed
    root proves every committed prior curation/inspection record is present, unchanged, and in
    order — dropping the incriminating curator record and re-signing changes the fold and no
    longer reproduces the committed baseline (``EXPOSURE_LEDGER_TRUNCATED``).

    Unlike evaluate-once, an exposure ledger is legitimately NON-EMPTY at its first certify
    (curators curate before a cohort is scored), so the committed-empty baseline is a genuine
    "no committed exposure baseline yet" bootstrap that any presented ledger extends — the
    truncation protection engages once a real (non-empty) committed exposure baseline exists."""
    running = _CHAIN_GENESIS
    if running == committed_root:
        return True
    for record in ledger.records:
        running = _sha256(running + leaf_hash(record.model_dump(mode="json")))
        if running == committed_root:
            return True
    return False


def sign(root: str, private_key: bytes) -> str:
    """Sign a root with ed25519 (round-6). ``private_key`` is the 32-byte ed25519 seed
    held EXTERNALLY by the curator (never committed). Returns the hex signature. ed25519
    signing is deterministic, so the signature is machine-independent."""
    sk = Ed25519PrivateKey.from_private_bytes(private_key)
    return sk.sign(root.encode("utf-8")).hex()


def verify(root: str, signature: str, public_key: bytes) -> bool:
    """Verify an ed25519 signature over ``root`` against the committed 32-byte PUBLIC key.
    A signature made with any other private key (a subject-minted key, an old HMAC secret,
    a truncated/garbage signature) fails — only the holder of the private key matching this
    committed public key can produce a verifying signature."""
    try:
        pk = Ed25519PublicKey.from_public_bytes(public_key)
        pk.verify(bytes.fromhex(signature), root.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


def ed25519_public_key(private_key: bytes) -> bytes:
    """Derive the 32-byte ed25519 PUBLIC key from a 32-byte private seed. A pure crypto
    utility (no key material is embedded here): the test/build helpers use it to commit a
    public key into ``genesis_root.json`` from a private seed they hold, and to verify that
    the committed public key is the one their signing seed corresponds to."""
    return Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()


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
    # Round-3 Class-1 silent-bug seals (A1..A6).
    POLICY_REFUSAL_ON_PRODUCED_RUN = "policy-refusal-on-a-run-that-produced-results"
    BLIND_REEVALUATED = "blind-set-re-evaluated-across-a-re-freeze"
    # Round-3 cryptographic-anchoring seals (B5): a certified score is bound to a
    # single committed, signed attestation root — validate() fails closed unless
    # the presented state reproduces every root and the signature verifies.
    ATTESTATION_MISMATCH = "presented-state-does-not-reproduce-the-attested-root"
    ATTESTATION_INVALID = "attestation-signature-does-not-verify"
    ATTESTATION_INCOMPLETE = "attestation-references-a-component-that-was-not-presented"
    ATTESTATION_UNSIGNED = "certification-requires-a-verify-key"
    UNANCHORED = "certification-requires-a-signed-attestation"
    # Round-4 out-of-contract verification seals (P1a..P1e, PART 2, PART 3): the
    # certify path now attacks the irreducible floor a pure validator could not reach —
    # genesis completeness, numerator input-truthfulness, and key custody.
    ATTESTATION_NOT_EXTENDING = "certification-history-does-not-append-only-extend-the-prior-committed-root"
    CERTIFY_WITHOUT_EVALUATION = "certification-without-exactly-one-producing-evaluation"
    PRECISION_UNBOUND = "certified-precision-not-bound-to-a-real-adjudication"
    NUMERATOR_UNVERIFIED = "reported-rediscoveries-do-not-match-the-recomputed-detector-run"
    GENESIS_UNANCHORED = "attestation-chain-base-not-rooted-in-the-committed-genesis"
    # Round-5 fail-closed certify seals (R5-3, R5-6): every completeness input a strict
    # certify needs is MANDATORY and resolved from committed state; omission fails closed.
    MISSING_LEDGER = "certification-requires-a-committed-ledger-that-was-not-presented"
    ACHIEVABLE_UNBOUND = "certified-report-carries-an-unbound-achievable-recall-diagnostic"
    # Round-7 structural-report seals (R7-2): every certified numeric is RECOMPUTED from the
    # committed detector+cohort or FORBIDDEN — no free secondary floats in a certified report.
    FIXED_COHORT_UNVERIFIED = "certified-fixed-cohort-recall-does-not-match-the-recomputed-regression-run"
    DENSITY_UNVERIFIED = "certified-patched-alert-density-does-not-match-the-recomputed-patched-tree-flags"
    COVERAGE_UNBOUND = "certified-report-carries-a-free-secondary-numeric-not-recomputable-from-committed-state"
    # Round-8 input-truthfulness + sample-commitment seals (R8-1, R8-2): the numerator recompute
    # runs on the EXACT committed pinned bytes, and the precision sample is committed at freeze
    # time rather than derived from the grindable freeze_hash.
    INPUT_BYTES_UNVERIFIED = "recomputed-input-bytes-do-not-match-the-committed-per-target-blob-sha256"
    # Round-10 comprehensive final seals (R10-1..R10-7): re-enforce every constructor invariant on
    # the certify path, bind each ledger to a committed-monotonic root, and trust CODE HASHES not
    # names.
    DETECTOR_BUNDLE_UNVERIFIED = "loaded-detector-module-hash-does-not-match-the-frozen-bundle"
    EXPOSURE_LEDGER_TRUNCATED = "presented-exposure-ledger-does-not-reproduce-the-committed-monotonic-root"
    EVALUATION_RECORD_UNBOUND = "evaluation-record-blind-ids-not-bound-to-its-resolved-cohort"
    PRECISION_PANEL_INVALID = "from-storage-precision-panel-or-coverage-invariant-violated"
    ADJUDICATOR_INVALID = "adjudicator-not-independent-or-not-on-the-committed-roster"
    # Feature 009 — aggregate class-manifest seals: the SET of classes feeding the aggregate mean is
    # a committed, monotonic manifest, so no whole class can be silently dropped from the headline.
    CLASS_SILENTLY_DROPPED = "class-left-the-aggregate-manifest-with-no-matching-class-manifest-event"
    CLASS_ATTESTATION_MISSING = "committed-manifest-class-has-no-present-per-class-attestation"
    CLASS_ATTESTATION_INVALID = "per-class-attestation-signature-report-hash-or-evaluator-does-not-verify"
    AGGREGATE_UNVERIFIED = "reported-aggregate-mean-does-not-match-the-recompute-over-the-committed-manifest"
    CLASS_MANIFEST_TRUNCATED = "presented-class-manifest-does-not-reproduce-the-committed-monotonic-root"


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

    # R8-1: the per-target CONTENT hash of the pinned bytes — ``{path: sha256(bytes)}`` at
    # ``vuln_ref`` / ``patched_ref``. Committed here and FOLDED INTO the identity hash (so the
    # committed bytes ride inside history_root + the signed attestation), the numerator recompute
    # requires each fetched source to reproduce these, closing the doctored-fetch hole. Left empty
    # they are omitted from the identity (backwards-compatible for cases with no committed bytes),
    # but the strict certify recompute REQUIRES them for every scored blind target.
    vuln_blob_sha256: dict[str, str] = Field(default_factory=dict)
    patched_blob_sha256: dict[str, str] = Field(default_factory=dict)

    role: Role
    guided_fix: bool = False  # has this entry ever guided a fix? (FR-4)

    # The identity hash SEALED when the entry was created. Left None it is simply
    # computed; set, ``validate`` recomputes and rejects a mismatch — that is how a
    # canonical-field edit without a fresh hash is caught (AC-1).
    declared_identity_hash: Optional[str] = None

    @property
    def computed_identity_hash(self) -> str:
        payload = {
            "repo": self.repo,
            "vuln_ref": self.vuln_ref,
            "patched_ref": self.patched_ref,
            "target_paths": sorted(self.target_paths),
            "sink_probe": self.sink_probe,
            "status": self.status,
            "drop_reason": self.drop_reason or "",
        }
        # R8-1: fold the committed per-target content hashes into identity when present. Included
        # only when non-empty so a case with no committed bytes keeps its historical identity;
        # once bytes are committed, editing them (or the pin they were taken at) breaks the seal.
        if self.vuln_blob_sha256:
            payload["vuln_blob_sha256"] = dict(sorted(self.vuln_blob_sha256.items()))
        if self.patched_blob_sha256:
            payload["patched_blob_sha256"] = dict(sorted(self.patched_blob_sha256.items()))
        return _content_hash(payload)

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

    @property
    def history_root(self) -> str:
        """B1: an append-only :func:`chain_root` over the version content hashes.
        Omitting, reordering, or truncating any version changes the root, so a
        from-storage rebuild that drops an earlier (harder) baseline cannot
        reproduce the committed ``history_root``."""
        return chain_root([v.content_hash for v in self.versions])


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
    # B4: the confusion-pair pool membership, committed at freeze time BEFORE the
    # precision seed is derivable. ``pool_root = merkle_root([leaf_hash(p) for p
    # in sorted(set(pool))])`` (see :func:`pool_root_of`). Because it rides inside
    # the bundle it is part of ``bundle_hash``/``freeze_hash``, so it is frozen
    # alongside everything else. Combined with A6's canonical draw, the precision
    # sample becomes a pure function of committed membership.
    pool_root: str = ""
    # P1d: the precision sample size ``k``, committed at freeze time BEFORE the seed is
    # derivable. Because it rides inside the bundle it is part of ``bundle_hash`` /
    # ``freeze_hash``. Combined with B4's committed ``pool_root`` and A6's canonical
    # draw, the ENTIRE precision sample (membership + size + draw) is fixed before the
    # seed exists — closing k-choice inflation ("pick the k that flatters the sample").
    # Left 0 the check is inert (backwards-compatible); set, precision binding requires
    # ``precision.k == committed_k``.
    committed_k: int = 0
    # R8-2: the committed PRECISION SAMPLE root — ``merkle_root`` over the sorted sampled pairs
    # (see :func:`sample_root_of`). The precision sample was previously derived from
    # ``precision_sample_seed(cohort, freeze_hash, run_id)`` and ``freeze_hash`` is GRINDABLE
    # (tweak an inert bundle param until the seed-derived sample is favorable, then certify once
    # with no re-eval). Committing the sample explicitly INSIDE the frozen bundle — BEFORE any
    # adjudication — pins it: it rides inside ``bundle_hash`` / ``freeze_hash`` and the signed
    # attestation, and ``_check_precision_binding`` requires the presented sample to REPRODUCE
    # it, so grinding the hash can no longer re-roll the sample. Left empty the check is inert
    # (legacy freeze-derived path); set, it is the authoritative sample commitment and the
    # strict certify path REQUIRES it (``PRECISION_SAMPLE_UNBOUND`` otherwise).
    committed_sample_root: str = ""

    @property
    def bundle_hash(self) -> str:
        payload = self.model_dump()
        payload["calibration_seed_ids"] = sorted(payload["calibration_seed_ids"])
        return _content_hash(payload)


def pool_root_of(pool: list[str]) -> str:
    """B4: the committed pool root — ``merkle_root`` over the canonical
    (sorted, unique) confusion-pair pool. The freeze commits this; the precision
    check later requires the presented pool to reproduce it."""
    return merkle_root([leaf_hash(p) for p in sorted(set(pool))])


def sample_root_of(sampled_pairs: list[str]) -> str:
    """R8-2: the committed precision-sample root — ``merkle_root`` over the sorted sampled
    pairs. The freeze commits this at freeze time; :func:`_check_precision_binding` later
    requires the presented ``sampled_pairs`` to reproduce it, so the sample is fixed BEFORE
    adjudication and cannot be re-derived by grinding the freeze hash."""
    return merkle_root([leaf_hash(p) for p in sorted(sampled_pairs)])


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

    @property
    def pool_root(self) -> str:
        """B4: the confusion-pair pool root committed inside the frozen bundle."""
        return self.bundle.pool_root

    @property
    def committed_k(self) -> int:
        """P1d: the precision sample size ``k`` committed inside the frozen bundle."""
        return self.bundle.committed_k

    @property
    def sample_root(self) -> str:
        """R8-2: the precision-sample root committed inside the frozen bundle."""
        return self.bundle.committed_sample_root


# --------------------------------------------------------------------------- #
# FR-6 — ExposureLedger: curator != subject
# --------------------------------------------------------------------------- #


class ExposureRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cohort_content_hash: str
    actor: str  # model / harness id
    activity: str = Field(pattern="^(curated|inspected)$")
    # B3: the entry identities this actor curated/inspected, recorded by IDENTITY
    # so exposure resolves WITHOUT re-supplying the old cohort version. A subject
    # whose scored blind identities intersect any record's ``curated_entry_ids`` is
    # barred, no matter how the cohort was later re-versioned.
    curated_entry_ids: list[str] = Field(default_factory=list)


class ExposureLedger(BaseModel):
    """Records which model/harness curated or inspected each cohort. A subject that
    appears here for a cohort can never be that cohort's scored subject (FR-6)."""

    model_config = ConfigDict(extra="forbid")

    records: list[ExposureRecord] = Field(default_factory=list)

    def record(
        self,
        *,
        cohort_content_hash: str,
        actor: str,
        activity: str,
        curated_entry_ids: Optional[list[str]] = None,
    ) -> None:
        self.records.append(
            ExposureRecord(
                cohort_content_hash=cohort_content_hash,
                actor=actor,
                activity=activity,
                curated_entry_ids=list(curated_entry_ids or []),
            )
        )

    @property
    def root(self) -> str:
        """B2: an append-only :func:`chain_root` over the records. Rewriting or
        dropping any record changes the root."""
        return chain_root([leaf_hash(r.model_dump(mode="json")) for r in self.records])

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

    @property
    def root(self) -> str:
        """B2: an append-only :func:`chain_root` over the events. Rewriting or
        dropping any event changes the root."""
        return chain_root([leaf_hash(e.model_dump(mode="json")) for e in self.events])

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
    # A4: the freeze hash this attempt ran under. ``validate`` requires the first
    # post-freeze attempt's ``freeze_hash`` to equal the FreezeManifest's hash, so
    # you cannot freeze bundle B and then evaluate an unrelated bundle B'.
    freeze_hash: str = ""
    # R8-5: a content hash BINDING ``produced_results``. A real evaluation produces detector
    # results and therefore a non-empty ``results_hash``; a non-producing "infra retry" produces
    # nothing and MUST carry an empty one. So N-1 real post-freeze evals can no longer hide as
    # ``produced_results=False`` "retries": a non-producing attempt carrying a results_hash is a
    # concealed real run (``INFRA_RETRY_REQUIRES_UNCHANGED``), and a producing attempt with an
    # empty results_hash is unbound. Enforced at record time (``attempt_evaluation``) AND in
    # ``validate`` (``_check_blind_access``) so a from-storage rebuild cannot dodge it.
    results_hash: str = ""


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
        results_hash: str = "",
    ) -> EvalAttempt:
        """Record one evaluation attempt, refusing anything the contract forbids.
        Raises ``ContractViolation`` (nothing is recorded on refusal)."""
        # R8-5: a non-producing "infra retry" produced no detector results, so it MUST carry an
        # empty results_hash — a retry carrying one is a concealed real evaluation.
        if not produced_results and results_hash:
            raise ContractViolation(
                ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED,
                "a non-producing infra retry must carry an empty results_hash",
            )
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
            # A4: bind the attempt to the freeze it ran under.
            freeze_hash=self.freeze_hash or "",
            results_hash=results_hash,
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
    """One completed evaluation, keyed by the sealed (cohort, freeze, subject).

    A3: it also records the scored cohort's BLIND entry-identity set, so
    evaluate-once is enforced at BLIND-SET granularity — a re-freeze (a trivial
    param change that mints a new ``freeze_hash``) cannot re-roll the same blind
    cohort behind a fresh ledger key."""

    model_config = ConfigDict(extra="forbid")

    cohort_content_hash: str
    freeze_hash: str
    subject: str
    blind_ids: list[str] = Field(default_factory=list)  # scored cohort's blind entry identities


class EvaluationLedger(BaseModel):
    """Append-only record of which (cohort, freeze, subject) triples have already
    been evaluated (R5). Mirrors ``ExposureLedger``. Supplied to ``validate`` as the
    ``prior_evaluations`` baseline so a SECOND evaluation of the same triple — the
    blind re-roll ("freeze once, evaluate N times, keep the best") — is flagged
    ``EVALUATED_MORE_THAN_ONCE`` instead of passing as a fresh run."""

    model_config = ConfigDict(extra="forbid")

    records: list[EvaluationRecord] = Field(default_factory=list)

    def record(
        self,
        *,
        cohort_content_hash: str,
        freeze_hash: str,
        subject: str,
        blind_ids: Optional[list[str]] = None,
    ) -> None:
        self.records.append(
            EvaluationRecord(
                cohort_content_hash=cohort_content_hash,
                freeze_hash=freeze_hash,
                subject=subject,
                blind_ids=sorted(blind_ids or []),
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

    @property
    def root(self) -> str:
        """B2: an append-only :func:`chain_root` over the records. Rewriting or
        dropping any record changes the root."""
        return chain_root([leaf_hash(r.model_dump(mode="json")) for r in self.records])


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


# A6: the minimum sample size relative to the pool. A single-pair "precision" is
# not a measurement; the floor is min'd against the pool size so a pool smaller
# than the floor is still sampleable.
_MIN_PRECISION_SAMPLE_K = 2


def sample_confusion_pairs(pairs: list[str], k: int, seed: int) -> list[str]:
    """A deterministic, seed-reproducible sample of confusion pairs. A6: the draw
    is always taken from the CANONICAL pool ``sorted(set(pairs))`` — never the
    operator-supplied order — so a public deterministic seed cannot be gamed by
    permuting the pool to land favorable pairs at the sampled indices."""
    canonical = sorted(set(pairs))
    rng = random.Random(seed)
    return rng.sample(canonical, min(k, len(canonical)))


def canonical_sample_seed(cohort_content_hash: str, pool_root: str, k: int) -> int:
    """R9-1: the seed for the CANONICAL precision draw — a pure function of COMMITTED,
    non-grindable state: the cohort identity, the committed confusion-pair ``pool_root``, and the
    committed sample size ``k``. Unlike :func:`precision_sample_seed` (whose ``freeze_hash`` input
    is GRINDABLE — tweak an inert bundle param until the seed-derived sample flatters the
    detector), NONE of these inputs carries an operator degree of freedom: the cohort is
    genesis-anchored, the pool is committed at freeze time (B4), and ``k`` is committed at freeze
    time (P1d). So once ``(cohort, pool, k)`` are committed the sample is FIXED, with no operator
    choice left."""
    return int(_sha256("\x1f".join([cohort_content_hash, pool_root, str(k)])), 16)


def canonical_sampled_pairs(cohort_content_hash: str, pool: list[str], k: int) -> list[str]:
    """R9-1: the CANONICAL precision draw — ``sample_confusion_pairs(sorted(pool), k, seed)`` with
    ``seed = canonical_sample_seed(cohort_content_hash, pool_root_of(pool), k)``. The operator
    cannot cherry-pick which pairs to commit: the draw is a total function of committed state
    ``(cohort_content_hash, pool_root, k)``."""
    seed = canonical_sample_seed(cohort_content_hash, pool_root_of(pool), k)
    return sample_confusion_pairs(pool, k, seed)


def canonical_sample_root(cohort_content_hash: str, pool: list[str], k: int) -> str:
    """R9-1: the CANONICAL committed precision-sample root — ``sample_root_of`` the canonical draw.
    The strict certify path RECOMPUTES this from committed state (the HEAD cohort_content_hash +
    the committed ``pool_root`` + the committed ``k``) and requires the committed freeze
    ``sample_root`` to EQUAL it; an operator-chosen (cherry-picked) sample is thereby
    ``PRECISION_SAMPLE_UNBOUND``. R8-2 committed the sample into the bundle but the operator still
    CHOSE which pairs to commit (the seed was a free operator input); R9-1 removes that last degree
    of freedom by deriving the sample from committed, non-grindable state."""
    return sample_root_of(canonical_sampled_pairs(cohort_content_hash, pool, k))


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
        # A6: the pool MUST be canonical — sorted and unique. Any permutation or
        # duplicate is rejected, so the sample is a pure function of committed
        # membership (B4) rather than of an operator-chosen order.
        if list(self.pool) != sorted(set(self.pool)):
            raise ValueError("pool must be canonical: exactly sorted(set(pool)) (unique, sorted)")
        # A6: enforce a minimum sample size relative to the pool.
        if self.k < min(len(self.pool), _MIN_PRECISION_SAMPLE_K):
            raise ValueError(
                f"k ({self.k}) is below the minimum min(|pool|, {_MIN_PRECISION_SAMPLE_K})"
            )
        sampled = set(self.sampled_pairs)
        # COVERAGE (H8): every seeded pair must be adjudicated. A subset lets the
        # unfavorable pairs be silently dropped to inflate precision.
        adjudicated = {a.pair_id for a in self.adjudications}
        if adjudicated != sampled:
            raise ValueError(
                f"every seeded pair must be adjudicated: sampled={sorted(sampled)} adjudicated={sorted(adjudicated)}"
            )
        # R11-2 (CARDINALITY): exactly ONE adjudication per sampled pair. The coverage check above is
        # SET-based, but ``precision`` divides tp by len(adjudications) — so appending duplicate
        # favorable (true-positive) adjudications for already-covered pairs inflates tp/len toward 1.0
        # while the SET of pair_ids is unchanged. Require the MULTISET of adjudicated pair_ids to equal
        # the sampled draw exactly (no duplicates), pinning the precision denominator to |sample|.
        adjudicated_ids = [a.pair_id for a in self.adjudications]
        if sorted(adjudicated_ids) != sorted(self.sampled_pairs):
            raise ValueError(
                "exactly one adjudication per sampled pair is required (no duplicate/inflating "
                f"adjudications): sampled={sorted(self.sampled_pairs)} adjudicated={sorted(adjudicated_ids)}"
            )
        for adj in self.adjudications:
            if adj.pair_id not in sampled:
                raise ValueError(f"adjudicated pair {adj.pair_id!r} is not in the seeded sample")
            if len(adj.verdicts) < 2:
                raise ValueError("each pair needs at least two adjudicators")
            # CR-1: two verdicts from the SAME adjudicator are one person double-voting, not an
            # independent panel. Require at least two DISTINCT adjudicator identities per pair.
            if len({v.adjudicator for v in adj.verdicts}) < 2:
                raise ValueError("each pair needs at least two DISTINCT adjudicators (one identity cannot double-vote)")
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

    @property
    def root(self) -> str:
        """B2: an append-only :func:`chain_root` over the predictions. Rewriting
        or dropping any prediction changes the root."""
        return chain_root(
            [
                leaf_hash(
                    {
                        "entry_identity": p.entry_identity,
                        "predicted_achievable": p.predicted_achievable,
                        "registered_at": p.registered_at,
                        "note": p.note,
                    }
                )
                for p in self.predictions
            ]
        )

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
    # R7-2: coverage (pinned / all) is NOT recomputable from committed state — the denominator
    # "all" includes dropped, uncommitted entries. It is a labelled DIAGNOSTIC for non-certified
    # reports only; a certified report must leave it None (a free float would be an unbound
    # secondary headline). Optional with a None sentinel so the certify path can FORBID it.
    coverage: Optional[float] = Field(default=None, ge=0.0, le=1.0)  # pinned / all; None in a certified report
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
        }
        # coverage is a diagnostic present only on non-certified reports (None otherwise).
        if self.coverage is not None:
            out["coverage"] = _pct(self.coverage)
        out["patched-alert density"] = f"{self.patched_alert_density:.2f} flags/KLOC"
        out["adjudicated precision"] = _pct(self.adjudicated_precision)
        if self.achievable_recall is not None:
            out["achievable-recall (diagnostic)"] = _pct(self.achievable_recall)
        return out

    def lines(self) -> list[str]:
        return [self.headline(), *[f"{label}: {value}" for label, value in self.secondaries().items()]]

    def render(self) -> str:
        return "\n".join(self.lines())


# --------------------------------------------------------------------------- #
# Part B5 — the signed Attestation: the single fail-closed root
# --------------------------------------------------------------------------- #


class Attestation(BaseModel):
    """A frozen, signed commitment binding EVERY component root of one certified
    score into a single ``attestation_root``. Certification (``validate(strict=
    True)`` or supplying an ``attestation``) recomputes each root from the
    presented objects and REFUSES unless they all match AND the signature
    verifies — so a certified score cannot be fabricated even by an operator who
    controls storage: you cannot omit, truncate, rewrite, reorder, or re-point
    any component without breaking a root or the signature.

    The signature is ed25519 (round-6): the committed genesis commits ONLY the PUBLIC
    verify-key, so any repo reader can verify but none can forge, and the private key is
    held by a party != the scored subject. The anti-omission property comes from "the
    presented state must reproduce the committed root"; the signature adds non-repudiation
    + tamper-evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    history_root: str
    exclusion_root: str
    exposure_root: str
    evaluation_root: str
    achievability_root: str
    freeze_hash: str
    pool_root: str
    run_id: str
    report_hash: str
    evaluator_id: str
    attested_at: str  # ISO-8601, supplied by the caller (never datetime.now)
    # P1a: the root of the PRIOR committed attestation this one chains from (the
    # committed genesis root for the first attestation). Folding it into
    # ``attestation_root`` makes the chain cryptographically linked: the strict
    # certify path requires the presented history to append-only-EXTEND the prior
    # committed root and the chain base to root in the git-committed genesis — so an
    # operator cannot re-anchor to a truncated genesis relative to a committed
    # predecessor.
    prior_attestation_root: str
    signature: str

    @property
    def component_roots(self) -> list[str]:
        """The ordered component values folded into ``attestation_root``. Order is
        immaterial (``merkle_root`` sorts), but this fixes exactly what is
        committed."""
        return [
            self.history_root,
            self.exclusion_root,
            self.exposure_root,
            self.evaluation_root,
            self.achievability_root,
            self.freeze_hash,
            self.pool_root,
            self.run_id,
            self.report_hash,
            self.evaluator_id,
            self.attested_at,
            self.prior_attestation_root,
        ]

    @property
    def attestation_root(self) -> str:
        """The single root the signature covers: a Merkle root over every bound
        component. Change any component and this root changes."""
        return merkle_root(self.component_roots)


def build_attestation(
    *,
    history: Optional[CohortHistory],
    freeze: FreezeManifest,
    run: EvaluationRun,
    report: "Report",
    evaluator_id: str,
    attested_at: str,
    key: bytes,
    prior_attestation_root: Optional[str] = None,
    exclusions: Optional[ExclusionLog] = None,
    ledger: Optional[ExposureLedger] = None,
    evaluation_ledger: Optional[EvaluationLedger] = None,
    achievability: Optional[AchievabilityLog] = None,
) -> Attestation:
    """Compute every component root from the honest objects and sign the Merkle
    ``attestation_root``. Absent components fold in the reproducible empty root, so
    the attestation is a total function of exactly what was presented. Deterministic:
    ``attested_at`` and ``key`` are passed in.

    P1a: ``prior_attestation_root`` chains this attestation to its committed
    predecessor. Left ``None`` it defaults to the git-committed genesis root
    (:func:`load_committed_genesis_root`) — i.e. this is the chain BASE — so an honest
    first attestation is always anchored without the caller re-typing the constant."""
    history_root = history.history_root if history is not None else _EMPTY_ROOT
    exclusion_root = exclusions.root if exclusions is not None else _EMPTY_ROOT
    exposure_root = ledger.root if ledger is not None else _EMPTY_ROOT
    evaluation_root = evaluation_ledger.root if evaluation_ledger is not None else _EMPTY_ROOT
    achievability_root = achievability.root if achievability is not None else _EMPTY_ROOT
    report_hash = leaf_hash(report.model_dump(mode="json"))
    if prior_attestation_root is None:
        prior_attestation_root = load_committed_genesis_root()

    unsigned = Attestation(
        history_root=history_root,
        exclusion_root=exclusion_root,
        exposure_root=exposure_root,
        evaluation_root=evaluation_root,
        achievability_root=achievability_root,
        freeze_hash=freeze.freeze_hash,
        pool_root=freeze.pool_root,
        run_id=run.run_id,
        report_hash=report_hash,
        evaluator_id=evaluator_id,
        attested_at=attested_at,
        prior_attestation_root=prior_attestation_root,
        signature="",
    )
    return unsigned.model_copy(update={"signature": sign(unsigned.attestation_root, key)})


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
    attestation: Optional[Attestation] = None,
    strict: bool = False,
) -> ContractReport:
    """Validate the Evaluation Contract (FR-14). Checks entry-hash integrity,
    version monotonicity, denominator preservation, blind-reuse, the exposure
    ledger (curator != subject), freeze-before-evaluation, and the blind-access
    counter. Every violation is collected with a typed reason; ``result.ok`` is
    True only when there are none. A ``check`` that raises is itself a failed check
    (Constitution VII), so unexpected errors are captured, not propagated.

    The optional parameters (``freeze``, ``report``, ``precision``,
    ``achievability``, and the ``prior_*`` baselines) let ``validate`` enforce the
    adversarial-audit seals (H1..H9, R1..R8, A1..A6) that previously lived only in
    constructor helpers — bypassed whenever a model is rebuilt from storage. They
    are keyword-only and default to ``None`` so every existing call site keeps
    working unchanged.

    ``attestation`` / ``strict`` drive the CERTIFY path (Part B / Round-5). When an
    ``attestation`` is supplied OR ``strict=True``, ``validate`` runs every ordinary
    check AND additionally RUNS each verification itself from COMMITTED, git-tracked
    state — never a caller argument the scored party could forge. It recomputes every
    component root from the presented objects (``ATTESTATION_MISMATCH``); verifies the
    signature with the COMMITTED evaluator verify-key (``ATTESTATION_INVALID``); requires
    every referenced component present (``ATTESTATION_INCOMPLETE``); requires the
    mandatory certify bindings — exposure ledger, prior evaluations, a non-inert
    ``pool_root`` / ``committed_k`` (``MISSING_LEDGER`` / ``PRECISION_SAMPLE_UNBOUND``);
    binds the history to the COMMITTED prior root and the attestation to the COMMITTED
    chain (``ATTESTATION_NOT_EXTENDING`` / ``GENESIS_UNANCHORED``); binds the certified run
    to the terminal HEAD cohort (``DENOMINATOR_SHRINK`` / ``REPORT_DENOMINATOR_MISMATCH``,
    F1); requires the presented ``prior_evaluations`` to reproduce the committed
    evaluation-ledger root (``EVALUATED_MORE_THAN_ONCE``, F2); and RECOMPUTES the numerator by
    re-running the COMMITTED detector (resolved from the frozen ``detector_id``) on the pinned
    SHAs over the HEAD cohort (``NUMERATOR_UNVERIFIED``).

    F3: certification is STRUCTURAL, not opt-in — a producing run presented together with a
    headline Report WITHOUT ``strict`` or an ``attestation`` is ``UNANCHORED`` (a
    produced+reported result must be certified). A certify request with no signed attestation
    is likewise ``UNANCHORED``. The rest of the non-strict path is unchanged, so existing
    per-check tests are unaffected."""
    result = ContractReport()
    # Certification is active when strict is set OR a signed attestation is supplied. Computed
    # up front so the R8-4 POLICY_REFUSAL check and the R7-1/R8-3 structural-report check share
    # one definition.
    _certifying = strict or attestation is not None

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
            _check_evaluation_ledger(run, prior_evaluations, history, result)  # R5 + A3
            # R6: a run that recorded post-freeze attempts MUST be validated against
            # its FreezeManifest — a fabricated run.freeze_hash cannot stand in for it.
            if run.post_freeze_attempts and freeze is None:
                result.add(
                    ViolationReason.MISSING_FREEZE,
                    "a run with post-freeze attempts must be validated against its FreezeManifest",
                )
            if ledger is not None:
                _check_exposure(run, ledger, history, result)  # R7 + B3
            # A2: a run that demonstrably produced results cannot be laundered to N/A
            # by a POLICY_REFUSAL exclusion, and must present a bound Report.
            if _run_produced_results(run):
                if exclusions is not None and any(
                    e.reason is ExclusionReason.POLICY_REFUSAL for e in exclusions.events
                ):
                    result.add(
                        ViolationReason.POLICY_REFUSAL_ON_PRODUCED_RUN,
                        f"run {run.run_id}: produced results but a POLICY_REFUSAL exclusion scores it N/A",
                    )
                if report is None:
                    result.add(
                        ViolationReason.REPORT_UNBOUND,
                        f"run {run.run_id}: produced results but presents no bound Report",
                    )

        # R8-4: a POLICY_REFUSAL scores a class N/A — but that is only honest when production is
        # PROVABLY ABSENT. The A2 guard above only fires inside ``if run is not None``, so a class
        # whose committed detector actually RUNS and produces a mediocre result could be dropped to
        # N/A by logging a POLICY_REFUSAL and OMITTING the run. Symmetric to R7-1, the refusal is
        # now recompute-checked AND certification-forced, run object or not: (a) an N/A POLICY_REFUSAL
        # must be inside a signed certification (else UNANCHORED); (b) it is VALID only if the
        # committed detector for the class produces NOTHING on the head blind set (recompute) OR no
        # committed detector exists — else POLICY_REFUSAL_ON_PRODUCED_RUN. (The AGGREGATE class-manifest
        # completeness — that a whole class cannot be silently omitted from the mean — is feature 009.)
        if exclusions is not None and any(
            e.reason is ExclusionReason.POLICY_REFUSAL for e in exclusions.events
        ):
            if not _certifying:
                result.add(
                    ViolationReason.UNANCHORED,
                    "a POLICY_REFUSAL that scores a class N/A must be inside a signed certification",
                )
            _check_policy_refusal_production(history, freeze, result)

        if freeze is not None:
            _check_freeze_binding(freeze, run, history, result)

        if report is not None:
            _check_report(report, history, run, freeze, result)

        if precision is not None:
            _check_precision_binding(precision, run, freeze, result)

        if achievability is not None:
            _check_achievability(achievability, prior_achievability, result)

        # Part B5 — the certify path. Additive: it runs after every ordinary check.
        # R7-1 / F3: certification is STRUCTURAL on the REPORT, not opt-in and not keyed on the
        # run's produced flag. ANY presented Report that asserts a numerator (a rediscovery
        # claim) REQUIRES full, signed certification — so the default ``check = validate`` alias
        # cannot bless an unanchored or truncated headline, whether or not a run/produced flag is
        # present. Without certification (strict or a signed attestation) such a Report is
        # UNANCHORED. The legacy F3 clause (a producing run + a Report) is subsumed but kept
        # explicit for a report that claims nothing yet rode a producing run.
        if not _certifying and (
            _report_asserts_numerator(report)
            or (run is not None and _run_produced_results(run) and report is not None)
        ):
            detail = (
                f"a presented Report asserts a rediscovery numerator "
                f"({report.blind_recall.rediscovered}/{report.blind_recall.total}) with no certification "
                "(strict or a signed attestation) — a Report headline must be certified"
                if _report_asserts_numerator(report)
                else f"run {run.run_id}: produced results with a Report but no certification "
                "(strict or a signed attestation) — a produced+reported result must be certified"
            )
            result.add(ViolationReason.UNANCHORED, detail)
        if _certifying:
            _check_certification(
                attestation=attestation,
                strict=strict,
                history=history,
                exclusions=exclusions,
                ledger=ledger,
                evaluation_ledger=prior_evaluations,
                achievability=achievability,
                freeze=freeze,
                run=run,
                report=report,
                precision=precision,
                result=result,
            )
    except ContractViolation as exc:  # a guard that raised mid-check is a failure
        result.violations.append(exc)
    except Exception as exc:  # noqa: BLE001 - any crash in check IS a failed check
        result.add(ViolationReason.IN_PLACE_EDIT, f"unexpected check error: {exc}")

    return result


def _run_produced_results(run: EvaluationRun) -> bool:
    """True iff any post-freeze attempt demonstrably produced detector results."""
    return any(a.produced_results for a in run.post_freeze_attempts)


def _check_policy_refusal_production(
    history: Optional[CohortHistory], freeze: Optional[FreezeManifest], result: ContractReport
) -> None:
    """R8-4: a POLICY_REFUSAL that scores a class N/A is valid ONLY if the committed detector for
    that class produces NOTHING on the head blind set (recompute) OR no committed detector exists
    (a genuine builder-declined class). If the committed detector produces ANY rediscovery on the
    real pinned bytes, the run was PRODUCED and cannot be laundered to N/A — even with the run
    object omitted — so this fails ``POLICY_REFUSAL_ON_PRODUCED_RUN``. The recompute RUNS the
    committed detector (resolved from the frozen ``detector_id``) from committed state, never a
    caller argument, and is INPUT-BYTES-verified (R8-1). SAFETY (Article III): the detector parses
    the fetched source as DATA; no target code is executed."""
    scored = history.latest() if history is not None else None
    if freeze is None or scored is None:
        # No committed detector/cohort to resolve → treat as no committed detector (allowed).
        return
    import verifier  # local import: verifier -> corpus_measure, no cycle back to contract

    try:
        produced = verifier.recompute_certified_numerator(
            scored.by_role(Role.BLIND), detector_id=freeze.bundle.detector_id
        )
    except KeyError:
        # No committed detector registered for this class → genuine builder-declined (allowed).
        return
    except Exception as exc:  # noqa: BLE001 — cannot PROVE absence of production → fail closed
        result.add(
            ViolationReason.POLICY_REFUSAL_ON_PRODUCED_RUN,
            f"a POLICY_REFUSAL scores the class N/A but the committed detector could not be proven "
            f"to produce nothing (detector_id={freeze.bundle.detector_id!r}): {exc}",
        )
        return
    if produced:
        result.add(
            ViolationReason.POLICY_REFUSAL_ON_PRODUCED_RUN,
            "a POLICY_REFUSAL scores the class N/A, but the committed detector produces a "
            f"rediscovery on the head blind set ({len(produced)}); the run was produced, not refused",
        )


def _report_asserts_numerator(report: Optional["Report"]) -> bool:
    """R7-1 + R8-3: True iff a presented Report makes ANY non-trivial SCORING claim — not only
    the blind headline (a non-zero blind numerator/denominator or a non-empty rediscovered set)
    but ALSO any secondary scoring numeric: a non-zero ``fixed_cohort_recall``, a set
    ``patched_alert_density``, or a set ``adjudicated_precision``. Certification is STRUCTURAL on
    the Report: any such claim REQUIRES full, signed certification, so even the default
    ``check = validate`` alias cannot bless an unanchored/truncated number — R7-2's
    recompute/forbid then binds each certified numeric. A genuinely empty report (all-zero, no
    rediscovered ids) asserts nothing and stays exempt."""
    if report is None:
        return False
    return bool(
        report.blind_recall.total > 0
        or report.blind_recall.rediscovered > 0
        or report.rediscovered_blind_ids
        # R8-3: a secondary scoring numeric is just as much a published number as the headline.
        or report.fixed_cohort_recall.total > 0
        or report.fixed_cohort_recall.rediscovered > 0
        or report.patched_alert_density > 0
        or report.adjudicated_precision > 0
    )


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
        curr_ids = curr.identities()
        prev_blind = {e.computed_identity_hash for e in prev.by_role(Role.BLIND)}
        curr_blind = {e.computed_identity_hash for e in curr.by_role(Role.BLIND)}
        left_blind = prev_blind - curr_blind
        # R9-4/R11-1: the blind entries that GUIDED A FIX in their from_version cohort. FR-4
        # legitimizes a blind->regression role-downgrade ONLY for such an entry.
        guided_blind_prev = {
            e.computed_identity_hash for e in prev.by_role(Role.BLIND) if e.guided_fix
        }
        must_authorize = removed | left_blind
        for identity in sorted(must_authorize):
            key = (identity, prev.version, curr.version)
            if available.get(key, 0) <= 0:
                report.add(
                    ViolationReason.DENOMINATOR_SHRINK,
                    f"{prev.version}->{curr.version}: entry {identity[:12]} left the blind denominator "
                    "(removed or role-downgraded) with no matching cohort-correction event",
                )
                continue
            available[key] -= 1  # consume the one event that authorizes this transition
            # R11-1: bind the guided_fix precondition to the STRUCTURAL transition, not to the
            # ROLE_DOWNGRADE reason LABEL. A blind entry ROLE-DOWNGRADED but KEPT in the cohort (in
            # left_blind AND still present in curr) leaves the authoritative denominator while
            # surviving as a softer regression/calibration case; FR-4 legitimizes that move ONLY for
            # an entry that actually guided a fix. Binding the check to the reason label let the
            # identical move relabel as ALIAS_DUPE / TARGET_PATHS_NARROWING / SEED_SWAP / etc. and
            # launder a hard blind MISS out of the denominator behind a mislabeled correction event.
            # Full removals (identity absent from curr) are unaffected — a genuine alias/dup removal
            # authorized by a matched event stays legitimate regardless of guided_fix.
            if identity in left_blind and identity in curr_ids and identity not in guided_blind_prev:
                report.add(
                    ViolationReason.DENOMINATOR_SHRINK,
                    f"{prev.version}->{curr.version}: blind entry {identity[:12]} role-downgraded out of "
                    "the denominator without having guided a fix (guided_fix=False); a blind downgrade is "
                    "legitimate only for a guided_fix entry (FR-4), regardless of the cohort-correction reason",
                )

    # R11-1b (SPLIT-TRANSITION / resurrection guard): the authoritative denominator is the HEAD, so
    # the guided_fix precondition must hold against the TERMINAL head, not merely the adjacent
    # successor. The adjacent-pair check above catches an IN-PLACE downgrade, but a departure can be
    # SPLIT across versions to dodge it: remove a non-guided blind MISS under a matched correction
    # event (a legitimate-looking full removal), then RE-ADD the same pinned identity in a later
    # version as a softer non-blind role (adding entries is ungated). The entry then survives in the
    # HEAD as a formerly-blind, non-guided fixture — exactly the state FR-4 forbids — while the head
    # blind denominator has silently shrunk. Enforce it end-to-end: any identity that was EVER blind,
    # is present in the head as a NON-blind role, and NEVER carried guided_fix==True while blind is a
    # DENOMINATOR_SHRINK, no matter how many versions the departure was split across. Full removals
    # (identity absent from the head) and guided_fix downgrades stay legitimate; a re-add colliding on
    # identity means the SAME pinned target (identity is content-derived), so this never flags a
    # genuinely distinct entry.
    head = history.versions[-1] if history.versions else None
    if head is not None:
        ever_blind: set[str] = set()
        ever_guided_blind: set[str] = set()
        for cohort in history.versions:
            for e in cohort.by_role(Role.BLIND):
                ever_blind.add(e.computed_identity_hash)
                if e.guided_fix:
                    ever_guided_blind.add(e.computed_identity_hash)
        head_blind = {e.computed_identity_hash for e in head.by_role(Role.BLIND)}
        for identity in sorted(head.identities()):
            if identity in ever_blind and identity not in head_blind and identity not in ever_guided_blind:
                report.add(
                    ViolationReason.DENOMINATOR_SHRINK,
                    f"{head.version}: entry {identity[:12]} was blind in an earlier version and survives in "
                    "the head as a non-blind role without ever having guided a fix (guided_fix=False); a "
                    "blind entry may leave the denominator only via a guided_fix downgrade (FR-4) or a full "
                    "removal, never by remove-then-readd-as-regression",
                )


def _history_extends(history: CohortHistory, prior: CohortHistory) -> bool:
    """P1a: True iff ``history`` is an APPEND-ONLY extension of ``prior`` — every prior
    version appears at the same index with an identical content_hash. The boolean form
    of :func:`_check_history_extension`, used by the certify chain check."""
    if len(history.versions) < len(prior.versions):
        return False
    for i, prior_cohort in enumerate(prior.versions):
        curr = history.versions[i]
        if curr.version != prior_cohort.version or curr.content_hash != prior_cohort.content_hash:
            return False
    return True


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
    # CR-2: every attempt's phase must be a KNOWN phase. attempt_evaluation rejects an unknown phase
    # at record time, but a from-storage run (model_construct bypasses it) with an unknown phase would
    # be omitted from BOTH pre_freeze_attempts and post_freeze_attempts and silently escape every
    # blind-access, ordering, and retry check. A malformed attempt makes the run unscoreable.
    for attempt in run.attempts:
        if attempt.phase not in ("pre_freeze", "post_freeze"):
            report.add(
                ViolationReason.RUN_INVALID,
                f"run {run.run_id}: evaluation attempt has unknown phase {attempt.phase!r}",
            )
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
    # A5: mirror the ordering invariant ``attempt_evaluation`` enforces — no attempt
    # may follow a producing one. A from-storage ``[produced=True, produced=False]``
    # would pass the >1 counter (only one producing attempt) yet still records a
    # second blind touch after the semantic evaluation; flag a producing attempt
    # that is not the terminal one.
    post_all = run.post_freeze_attempts
    producing_positions = [i for i, a in enumerate(post_all) if a.produced_results]
    if producing_positions and max(producing_positions) != len(post_all) - 1:
        report.add(
            ViolationReason.BLIND_ACCESS_EXCEEDED,
            f"run {run.run_id}: a post-freeze attempt follows a producing evaluation (must be terminal)",
        )
    # Mirror the infra-retry invariant that ``attempt_evaluation`` enforces at
    # record-time, so a run REBUILT FROM STORAGE cannot launder several blind
    # evaluations as "retries" (H5). Across the post-freeze attempts: every
    # non-producing attempt must have intact logs and the SAME artifact/env hashes
    # as the first post-freeze attempt; any post-freeze attempt with broken logs is
    # itself a violation.
    post = run.post_freeze_attempts
    if post:
        # R9-3: anchor the retry invariant to THE PRODUCING attempt (the real evaluation) when one
        # exists — every non-producing "retry" must carry identical artifact_hash + env_hash to it.
        # Fall back to post[0] for an all-retry run that never produced. Anchoring to the producing
        # attempt makes the intent explicit: a retry that differs from the scored evaluation is a
        # concealed second run.
        producing = next((a for a in post if a.produced_results), None)
        anchor = producing or post[0]
        for attempt in post:
            if not attempt.logs_intact:
                report.add(
                    ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED,
                    f"run {run.run_id}: a post-freeze attempt has logs_intact=False",
                )
                break
        for attempt in post:
            if attempt is anchor:
                continue
            if attempt.artifact_hash != anchor.artifact_hash or attempt.env_hash != anchor.env_hash:
                report.add(
                    ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED,
                    f"run {run.run_id}: post-freeze artifact/env hashes changed across attempts "
                    "(a retry does not match the producing evaluation)",
                )
                break
        # R8-5: bind produced_results to results_hash. A producing attempt MUST carry a
        # non-empty results_hash; a non-producing "infra retry" MUST carry an empty one — else a
        # from-storage rebuild could hide N-1 real evals as produced_results=False "retries".
        for attempt in post:
            if attempt.produced_results and not attempt.results_hash:
                report.add(
                    ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED,
                    f"run {run.run_id}: a producing post-freeze attempt carries an empty results_hash",
                )
                break
        for attempt in post:
            if not attempt.produced_results and attempt.results_hash:
                report.add(
                    ViolationReason.INFRA_RETRY_REQUIRES_UNCHANGED,
                    f"run {run.run_id}: a non-producing infra retry carries a results_hash "
                    "(a concealed real evaluation)",
                )
                break


def _check_exposure(
    run: EvaluationRun,
    ledger: ExposureLedger,
    history: Optional[CohortHistory],
    report: ContractReport,
) -> None:
    """R7 + B3: resolve exposure by ENTRY IDENTITY, not by the version-scoped cohort
    content hash. A version bump (same entries, new hash) must not launder a curator
    into a subject. B3: each ``ExposureRecord`` records ``curated_entry_ids``, so a
    subject whose scored blind identities intersect ANY record's curated identities
    is barred WITHOUT re-supplying the old cohort version — and an UNRESOLVABLE record
    whose actor == subject is a HARD FAILURE (never a silent skip)."""
    # Direct content-hash exposure always bars (works even with no history to resolve).
    if not ledger.can_score(run.cohort_content_hash, run.subject):
        report.add(
            ViolationReason.CURATOR_IS_SUBJECT,
            f"run {run.run_id}: subject {run.subject!r} curated/inspected this cohort",
        )
        return
    # F1: resolve the scored cohort as the HEAD (``history.latest()``), not the run's declared
    # (possibly stale) hash — exposure is judged against the terminal cohort the certify path
    # requires the run to have evaluated.
    scored = history.latest() if history is not None else None
    scored_ids = scored.identities() if scored is not None else set()
    scored_blind = _blind_identities(scored) if scored is not None else set()
    for record in ledger.records:
        if record.actor != run.subject:
            continue
        curated = set(record.curated_entry_ids)
        # Bar 1 (B3): entry-identity resolution via curated_entry_ids — a subject whose scored
        # blind identities intersect this record's curated identities is barred, no old version
        # needed.
        if curated and scored_blind and (curated & scored_blind):
            report.add(
                ViolationReason.CURATOR_IS_SUBJECT,
                f"run {run.run_id}: subject {run.subject!r} curated an entry identity in the scored blind set",
            )
            return
        # Bar 2 (R9-2): a NON-EMPTY curated_entry_ids must NOT short-circuit the content-hash
        # fallback. STILL resolve the record's cohort by content hash (via history) and bar the
        # subject on ANY overlap with the scored cohort's identities — a version bump (new content
        # hash, SAME entries) can otherwise launder a curator into a subject whenever
        # curated_entry_ids happens to miss the presented head.
        record_cohort = _cohort_by_content_hash(history, record.cohort_content_hash)
        if record_cohort is not None:
            if scored_ids & record_cohort.identities():
                report.add(
                    ViolationReason.CURATOR_IS_SUBJECT,
                    f"run {run.run_id}: subject {run.subject!r} curated/inspected a cohort version "
                    "sharing an entry identity with the scored cohort",
                )
                return
            # Resolved by content hash and disjoint from the scored cohort → this record is cleared.
            continue
        # The content hash is UNRESOLVABLE. Cleared ONLY if curated_entry_ids resolved it by
        # identity (non-empty, and checked disjoint from the scored blind set in Bar 1). An
        # actor==subject record resolvable by NEITHER mechanism is a HARD FAIL (fail closed) — a
        # bare cohort_content_hash exposure that no presented history can resolve is never silently
        # skipped.
        if not curated:
            report.add(
                ViolationReason.CURATOR_IS_SUBJECT,
                f"run {run.run_id}: subject {run.subject!r} has an unresolvable exposure record "
                f"({record.cohort_content_hash[:12]!r}); fail closed",
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
    run: EvaluationRun,
    prior_evaluations: Optional[EvaluationLedger],
    history: Optional[CohortHistory],
    report: ContractReport,
) -> None:
    """R5 + A3: evaluate-once, BLIND-SET scoped. The exact (cohort, freeze, subject)
    re-roll is flagged ``EVALUATED_MORE_THAN_ONCE`` (R5). But keying only on the full
    triple lets a trivial re-freeze mint a fresh key: A3 flags ``BLIND_REEVALUATED``
    whenever the scored cohort's BLIND identities overlap ANY prior record's blind set
    for the SAME subject, regardless of ``freeze_hash``. A re-frozen detector must be
    scored on a cohort whose blind identities are disjoint from every prior blind eval
    for that subject.

    R10-3: a prior record's ``blind_ids`` is only trustworthy if it is BOUND to its cohort. When
    the record's ``cohort_content_hash`` resolves in the presented history, require its
    ``blind_ids`` to equal that cohort's actual BLIND identity set — else a record could advertise
    a falsified (smaller/empty) blind set to dodge the A3 overlap check
    (``EVALUATION_RECORD_UNBOUND``). Records whose cohort is unresolvable here are left unchecked
    (they cannot be bound without the version)."""
    if prior_evaluations is None:
        return
    # R10-3: bind every resolvable record's advertised blind_ids to its cohort's actual blind set,
    # so a falsified (smaller/empty) blind set cannot silently dodge the A3 overlap check below.
    if history is not None:
        for record in prior_evaluations.records:
            cohort = _cohort_by_content_hash(history, record.cohort_content_hash)
            if cohort is None:
                continue
            if set(record.blind_ids) != _blind_identities(cohort):
                report.add(
                    ViolationReason.EVALUATION_RECORD_UNBOUND,
                    f"evaluation record for cohort {record.cohort_content_hash[:12]} advertises "
                    "blind_ids that are not the resolved cohort's actual blind identity set",
                )
    if run.freeze_hash is None:
        return
    if prior_evaluations.count(run.cohort_content_hash, run.freeze_hash, run.subject) > 0:
        report.add(
            ViolationReason.EVALUATED_MORE_THAN_ONCE,
            f"run {run.run_id}: (cohort, freeze, subject={run.subject!r}) was already evaluated",
        )
    # A3: blind-set-scoped evaluate-once (freeze-independent).
    scored = _cohort_by_content_hash(history, run.cohort_content_hash)
    if scored is None:
        return
    scored_blind = _blind_identities(scored)
    if not scored_blind:
        return
    for record in prior_evaluations.records:
        if record.subject != run.subject:
            continue
        if scored_blind & set(record.blind_ids):
            report.add(
                ViolationReason.BLIND_REEVALUATED,
                f"run {run.run_id}: subject {run.subject!r} already had these blind identities "
                "evaluated under an earlier freeze (blind-set re-roll across a re-freeze)",
            )
            return


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
    BLIND entries (a seed sitting in the blind set would tune on the denominator).
    A4: the FIRST post-freeze attempt must also be bound to the freeze — its
    ``freeze_hash`` must equal the frozen bundle hash — so you cannot freeze bundle
    B and then evaluate an unrelated bundle B'."""
    if run is not None and run.freeze_hash is not None and run.freeze_hash != freeze.freeze_hash:
        report.add(
            ViolationReason.BAD_FREEZE_BINDING,
            f"run freeze_hash {run.freeze_hash!r} does not equal the frozen bundle hash {freeze.freeze_hash[:12]}",
        )

    # A4 + R5-5 + R9-3: bind EVERY post-freeze attempt to the freeze — not just the first (A4) or
    # the producing one (R5-5). A from-storage run can present a NON-first, NON-producing "retry"
    # carrying a FORGED freeze_hash (a hidden second evaluation of an unrelated bundle B') that the
    # first-only + producing-only binding never inspected. Require each post-freeze attempt's
    # freeze_hash to equal the frozen bundle hash so no attempt — producing or not — evaluates an
    # unrelated bundle.
    if run is not None:
        for i, attempt in enumerate(run.post_freeze_attempts):
            if attempt.freeze_hash != freeze.freeze_hash:
                if i == 0:
                    which = "first post-freeze attempt"
                elif attempt.produced_results:
                    which = "producing post-freeze attempt"
                else:
                    which = f"non-producing post-freeze attempt #{i}"
                report.add(
                    ViolationReason.BAD_FREEZE_BINDING,
                    f"run {run.run_id}: the {which}'s freeze_hash {attempt.freeze_hash!r} is not "
                    f"the frozen bundle hash {freeze.freeze_hash[:12]}",
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
    subset of the actual blind identities and its size must equal the reported count.

    A1: when a ``run`` is present the report must denominate against exactly the run's
    evaluated cohort, and a report bound to a DIFFERENT cohort than the run evaluated is
    ``REPORT_DENOMINATOR_MISMATCH`` — a report can no longer point at an easier earlier
    version than the run scored. With no run, the report must bind to the LATEST cohort
    version (a non-latest sibling is rejected).

    F1: the scored cohort is ALWAYS resolved as ``history.latest()`` — the terminal
    (committed-extended head) version — NEVER as ``run.cohort_content_hash``. A run bound to
    a stale earlier version (which drops a hard miss appended to the head later) therefore
    denominates against the head blind count and mismatches, closing the "bind to an older,
    smaller committed version while presenting the honest full history" hole."""
    if run is not None:
        # A1: the report must denominate against exactly the run's evaluated cohort.
        if (
            report_view.cohort_content_hash is not None
            and report_view.cohort_content_hash != run.cohort_content_hash
        ):
            report.add(
                ViolationReason.REPORT_DENOMINATOR_MISMATCH,
                "report cohort_content_hash is not the run's evaluated cohort",
            )
        # F1: bind the denominator to the HEAD cohort, not the run's declared (stale) hash.
        cohort = history.latest() if history is not None else None
    else:
        cohort = _cohort_by_content_hash(history, report_view.cohort_content_hash)
        latest = history.latest() if history is not None else None
        # A1: with no run, a report may only bind to the LATEST version.
        if cohort is not None and latest is not None and cohort.content_hash != latest.content_hash:
            report.add(
                ViolationReason.REPORT_DENOMINATOR_MISMATCH,
                "report binds to a non-latest cohort version; bind to the latest",
            )
        if cohort is None:
            cohort = latest
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
    """Route precision through validate (H8/R8/R8-2). R8 (P1): a precision object presented with
    no run/freeze to bind to is itself unbound — it is not silently accepted.

    R8-2 changes the SAMPLE authority. Previously the sample had to be the deterministic draw at
    ``precision_sample_seed(cohort, freeze_hash, run_id)`` — but ``freeze_hash`` is GRINDABLE, so
    an operator could tweak an inert bundle param until the seed-derived sample was favorable.
    When the freeze commits a ``sample_root`` (:attr:`FreezeManifest.sample_root`), the sample is
    pinned to that committed value INSTEAD: the presented ``sampled_pairs`` must reproduce it, so
    grinding the hash cannot re-roll the sample. The legacy freeze-derived-seed check is kept only
    for the backwards-compatible path where no ``sample_root`` was committed."""
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
    if freeze.sample_root:
        # R8-2: the committed sample is authoritative. The presented sample must reproduce the
        # freeze's ``sample_root``; the grindable freeze-derived seed no longer decides it.
        if sample_root_of(precision.sampled_pairs) != freeze.sample_root:
            report.add(
                ViolationReason.PRECISION_SAMPLE_UNBOUND,
                "precision sampled_pairs do not reproduce the committed freeze sample_root "
                "(the sample was fixed at freeze time, before adjudication)",
            )
    else:
        # Legacy (no committed sample): the sample must be the freeze-derived deterministic draw.
        expected_seed = precision_sample_seed(run.cohort_content_hash, freeze.freeze_hash, run.run_id)
        if precision.seed != expected_seed:
            report.add(
                ViolationReason.PRECISION_SAMPLE_UNBOUND,
                "precision seed is not precision_sample_seed(cohort, freeze, run_id) for this run",
            )
    # B4: when the freeze committed a pool_root, the presented pool MUST reproduce it.
    # Combined with A6's canonical draw, the sample is then a pure function of the
    # membership frozen BEFORE the seed was derivable — a swapped pool is rejected.
    if freeze.pool_root:
        if pool_root_of(precision.pool) != freeze.pool_root:
            report.add(
                ViolationReason.PRECISION_SAMPLE_UNBOUND,
                "precision pool does not reproduce the committed freeze pool_root",
            )
    # P1d: when the freeze committed a sample size k, the precision MUST use exactly it.
    # k is frozen alongside pool membership BEFORE the seed is derivable, so an operator
    # can no longer choose the k that flatters the sample after seeing the draw.
    if freeze.committed_k:
        if precision.k != freeze.committed_k:
            report.add(
                ViolationReason.PRECISION_SAMPLE_UNBOUND,
                f"precision k ({precision.k}) does not equal the committed freeze k ({freeze.committed_k})",
            )


def _check_precision_panel(
    precision: AdjudicatedPrecision,
    run: Optional[EvaluationRun],
    committed: "CommittedGenesisState",
    report: ContractReport,
) -> None:
    """R10-5 (P-A) + R10-6: RE-ENFORCE the AdjudicatedPrecision structural invariants on the
    certify path. A from-storage precision rebuilt with ``model_construct`` bypasses the
    ``_panel_and_sample_are_valid`` model-validator, so precision 1.0 could be presented with no
    honest adjudication (partial coverage, a builder adjudicator, an under-sized panel). Recompute
    the full invariants here and map any violation to ``PRECISION_PANEL_INVALID``: a non-empty
    sample, a canonical (sorted, unique) pool, the k floor, FULL coverage (every sampled pair
    adjudicated), the exact deterministic draw, and per-pair panel composition (>=2 verdicts, no
    builder, >=1 non-curator).

    R10-6: additionally bind each verdict's adjudicator to the committed roster — the adjudicator
    must be INDEPENDENT of the scored subject, be on the committed roster, and carry the roster's
    ``is_builder`` / ``is_curator`` rather than a self-asserted flag (``ADJUDICATOR_INVALID``)."""
    subject = run.subject if run is not None else None
    roster = committed.adjudicator_roster

    def _panel(detail: str) -> None:
        report.add(ViolationReason.PRECISION_PANEL_INVALID, detail)

    if not precision.sampled_pairs:
        _panel("precision requires a non-empty blind confusion-pair sample")
        return
    if list(precision.pool) != sorted(set(precision.pool)):
        _panel("pool must be canonical: exactly sorted(set(pool)) (unique, sorted)")
    if precision.k < min(len(precision.pool), _MIN_PRECISION_SAMPLE_K):
        _panel(f"k ({precision.k}) is below the minimum min(|pool|, {_MIN_PRECISION_SAMPLE_K})")
    sampled = set(precision.sampled_pairs)
    adjudicated = {a.pair_id for a in precision.adjudications}
    if adjudicated != sampled:
        _panel(
            f"every seeded pair must be adjudicated: sampled={sorted(sampled)} "
            f"adjudicated={sorted(adjudicated)}"
        )
    # R11-2 (CARDINALITY, P-A): re-enforce exactly-one-adjudication-per-sampled-pair on the certify
    # path. A from-storage precision (model_construct) bypasses the constructor validator, so a
    # duplicate-TP-inflated panel (tp/len driven toward 1.0 while coverage's SET is unchanged) would
    # otherwise pass. Require the MULTISET of adjudicated pair_ids to equal the sampled draw exactly.
    adjudicated_ids = [a.pair_id for a in precision.adjudications]
    if sorted(adjudicated_ids) != sorted(precision.sampled_pairs):
        _panel(
            "exactly one adjudication per sampled pair is required (no duplicate/inflating "
            f"adjudications): sampled={sorted(precision.sampled_pairs)} "
            f"adjudicated={sorted(adjudicated_ids)}"
        )
    for adj in precision.adjudications:
        if adj.pair_id not in sampled:
            _panel(f"adjudicated pair {adj.pair_id!r} is not in the seeded sample")
        if len(adj.verdicts) < 2:
            _panel("each pair needs at least two adjudicators")
        # CR-1: re-enforce DISTINCT adjudicator identities on the certify path (from-storage
        # model_construct bypasses the constructor) — one identity double-voting is not a panel.
        if len({v.adjudicator for v in adj.verdicts}) < 2:
            _panel("each pair needs at least two DISTINCT adjudicators (one identity cannot double-vote)")
        if any(v.is_builder for v in adj.verdicts):
            _panel("adjudicators must be non-builders")
        if not any(not v.is_curator for v in adj.verdicts):
            _panel("at least one adjudicator must be a non-curator")
        # R10-6: bind every verdict's adjudicator identity + role to the committed roster.
        for v in adj.verdicts:
            if subject is not None and v.adjudicator == subject:
                report.add(
                    ViolationReason.ADJUDICATOR_INVALID,
                    f"adjudicator {v.adjudicator!r} is the scored subject; the panel must be independent",
                )
            entry = roster.get(v.adjudicator)
            if entry is None:
                report.add(
                    ViolationReason.ADJUDICATOR_INVALID,
                    f"adjudicator {v.adjudicator!r} is not on the committed adjudicator roster",
                )
            elif entry["is_builder"] != v.is_builder or entry["is_curator"] != v.is_curator:
                report.add(
                    ViolationReason.ADJUDICATOR_INVALID,
                    f"adjudicator {v.adjudicator!r} self-asserted is_builder/is_curator "
                    f"({v.is_builder}/{v.is_curator}) does not match the committed roster",
                )
    expected_sample = sample_confusion_pairs(precision.pool, precision.k, precision.seed)
    if list(precision.sampled_pairs) != list(expected_sample):
        _panel("sampled_pairs is not the deterministic sample_confusion_pairs(pool, k, seed) draw")


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


def _check_certification(
    *,
    attestation: Optional[Attestation],
    strict: bool,
    history: Optional[CohortHistory],
    exclusions: Optional[ExclusionLog],
    ledger: Optional[ExposureLedger],
    evaluation_ledger: Optional[EvaluationLedger],
    achievability: Optional[AchievabilityLog],
    freeze: Optional[FreezeManifest],
    run: Optional[EvaluationRun],
    report: Optional["Report"],
    precision: Optional[AdjudicatedPrecision] = None,
    result: ContractReport,
) -> None:
    """B5 + Round-4/5: the fail-closed CERTIFY path. ONE governing principle: a trusted
    value or a verification RESULT must NEVER be a caller argument the scored party could
    forge. ``validate`` RUNS each verification itself and LOADS every trusted root / key /
    detector from COMMITTED, git-tracked state (via monkeypatchable module-level loaders).

    A certified score is bound to a single committed, signed attestation root — so it
    cannot be fabricated even by an operator who controls storage. Every component root is
    RECOMPUTED from the presented objects and must equal the attestation's committed root
    (``ATTESTATION_MISMATCH``); the signature must verify against the COMMITTED evaluator
    verify-key (``ATTESTATION_INVALID``); every referenced component must be present
    (``ATTESTATION_INCOMPLETE``). A certification requested with no signed attestation is
    ``UNANCHORED``.

    Round-5 closes the round-4 bypasses that were OPT-IN / caller-supplied:
    R5-1 the numerator is RECOMPUTED by RUNNING the committed detector (resolved from the
    frozen ``detector_id``) on the pinned SHAs — no caller ``recomputed_rediscovered`` set
    (``NUMERATOR_UNVERIFIED``); R5-2 the prior history baseline + chain root are loaded
    from committed state, and the presented history must append-only-EXTEND the committed
    prior (``ATTESTATION_NOT_EXTENDING`` / ``GENESIS_UNANCHORED``); R5-3 the exposure
    ledger + prior evaluations + a non-inert ``pool_root`` / ``committed_k`` are MANDATORY
    (``MISSING_LEDGER`` / ``PRECISION_SAMPLE_UNBOUND``); R5-4 the verify-key + evaluator id
    are the COMMITTED ones — a subject-minted key or a wrong evaluator fails
    (``ATTESTATION_INVALID``), and the evaluator must not be the subject
    (``CURATOR_IS_SUBJECT``); R5-6 a certified report must not carry a free
    ``achievable_recall`` (``ACHIEVABLE_UNBOUND``). Round-4 seals are retained: P1b one
    producing evaluation (``CERTIFY_WITHOUT_EVALUATION``); P1c a bound precision
    (``PRECISION_UNBOUND``).

    Round-10 comprehensive final seals (all one recurring shape): R10-1 the detector is bound by
    the CONTENT HASH of its loaded module (``DETECTOR_BUNDLE_UNVERIFIED``), not the mutable name;
    R10-2 the exposure ledger must reproduce the committed-monotonic root
    (``EXPOSURE_LEDGER_TRUNCATED``); R10-3 an evaluation record's ``blind_ids`` is bound to its
    resolved cohort (``EVALUATION_RECORD_UNBOUND``); R10-4 the evaluation chain fails closed on the
    inert short-circuit; R10-5 the AdjudicatedPrecision panel/coverage invariants are RE-ENFORCED
    here (``PRECISION_PANEL_INVALID``); R10-6 every adjudicator is bound to the committed roster and
    is independent of the subject (``ADJUDICATOR_INVALID``); R10-7 ``merkle_root`` domain-separates
    leaves from internal nodes (CVE-2012-2459)."""
    # Certification requires a signed attestation. The verify-key is NOT a caller arg — it
    # is loaded from committed state below. Without an attestation there is nothing to
    # reproduce — fail closed rather than pass silently.
    if attestation is None:
        result.add(
            ViolationReason.UNANCHORED,
            "certification requires a signed Attestation; none supplied",
        )
        return

    # The trusted anchor state, loaded from COMMITTED, git-tracked config (monkeypatchable).
    committed = load_committed_genesis_state()

    # 1. The signature over the committed attestation_root must verify against the
    #    COMMITTED evaluator verify-key (R5-4) — never a caller-supplied key. A subject
    #    that mints its own key K and signs with K fails here: ``validate`` uses the
    #    committed key, not K.
    if not verify(attestation.attestation_root, attestation.signature, committed.verify_key):
        result.add(
            ViolationReason.ATTESTATION_INVALID,
            "attestation signature does not verify against the committed evaluator verify-key",
        )

    # 2. Recompute each component root from the presented objects. A component the
    #    attestation references (root != the empty root) but that was not presented
    #    is ATTESTATION_INCOMPLETE (fail closed); a presented component whose
    #    recomputed root differs is ATTESTATION_MISMATCH.
    def _match(name: str, committed_root: str, obj: Any, recompute) -> None:
        if obj is None:
            if committed_root != _EMPTY_ROOT:
                result.add(
                    ViolationReason.ATTESTATION_INCOMPLETE,
                    f"attestation references a {name} root but no {name} was presented",
                )
            return
        if recompute(obj) != committed_root:
            result.add(
                ViolationReason.ATTESTATION_MISMATCH,
                f"presented {name} does not reproduce the attested {name} root",
            )

    _match("history", attestation.history_root, history, lambda h: h.history_root)
    _match("exclusion", attestation.exclusion_root, exclusions, lambda x: x.root)
    _match("exposure", attestation.exposure_root, ledger, lambda le: le.root)
    _match("evaluation", attestation.evaluation_root, evaluation_ledger, lambda e: e.root)
    _match("achievability", attestation.achievability_root, achievability, lambda a: a.root)

    # 3. The scalar commitments: freeze_hash, pool_root, run_id, report_hash. Each is
    #    mandatory for certification — a missing one is ATTESTATION_INCOMPLETE.
    if freeze is None:
        result.add(ViolationReason.ATTESTATION_INCOMPLETE, "no FreezeManifest presented for certification")
    else:
        if attestation.freeze_hash != freeze.freeze_hash:
            result.add(ViolationReason.ATTESTATION_MISMATCH, "presented freeze_hash != attested freeze_hash")
        if attestation.pool_root != freeze.pool_root:
            result.add(ViolationReason.ATTESTATION_MISMATCH, "presented pool_root != attested pool_root")
    if run is None:
        result.add(ViolationReason.ATTESTATION_INCOMPLETE, "no EvaluationRun presented for certification")
    elif attestation.run_id != run.run_id:
        result.add(ViolationReason.ATTESTATION_MISMATCH, "presented run_id != attested run_id")
    if report is None:
        result.add(ViolationReason.ATTESTATION_INCOMPLETE, "no Report presented for certification")
    elif attestation.report_hash != leaf_hash(report.model_dump(mode="json")):
        result.add(ViolationReason.ATTESTATION_MISMATCH, "presented report does not reproduce the attested report_hash")

    # ----------------------------------------------------------------------- #
    # R10-1 (P-C: trust CODE HASHES, not names) — bind the detector by the CONTENT HASH of its
    # loaded module source, not by the mutable ``detector_id``. The freeze commits
    # ``module_hashes``; nothing previously read them, so an operator could swap the detector CODE
    # while keeping the name + freeze. RECOMPUTE the sha256 of the source file(s) of the module the
    # committed registry resolves for ``freeze.bundle.detector_id`` and require it to EQUAL the
    # frozen ``module_hashes``. A mismatch (swapped code) OR an inert (empty) commitment fails
    # closed → ``DETECTOR_BUNDLE_UNVERIFIED``. SAFETY (Article III): the module source is read as
    # TEXT and hashed; no fetched or target code is executed.
    # ----------------------------------------------------------------------- #
    if freeze is not None:
        import verifier  # local import: verifier -> corpus_measure, no cycle back to contract

        frozen_hashes = dict(freeze.bundle.module_hashes)
        if not frozen_hashes:
            result.add(
                ViolationReason.DETECTOR_BUNDLE_UNVERIFIED,
                "certification requires a non-empty committed freeze module_hashes (an inert code "
                "commitment leaves the detector bound only by its mutable name)",
            )
        else:
            try:
                loaded_hashes = verifier.resolve_module_hashes(freeze.bundle.detector_id)
            except Exception as exc:  # noqa: BLE001 — an un-resolvable module hash fails closed
                result.add(
                    ViolationReason.DETECTOR_BUNDLE_UNVERIFIED,
                    f"certification could not recompute the loaded detector module hash for "
                    f"detector_id={freeze.bundle.detector_id!r}: {exc}",
                )
            else:
                if frozen_hashes != loaded_hashes:
                    result.add(
                        ViolationReason.DETECTOR_BUNDLE_UNVERIFIED,
                        "the loaded detector module content hash does not match the frozen bundle "
                        f"module_hashes (detector_id={freeze.bundle.detector_id!r}); the detector code "
                        "was swapped under a preserved name/freeze",
                    )

    # ----------------------------------------------------------------------- #
    # R5-3 — the mandatory certify bindings (no opt-in skips). Every completeness
    # input a strict certify needs is REQUIRED and resolved from committed/presented
    # state; omission or an inert default FAILS CLOSED.
    # ----------------------------------------------------------------------- #
    if ledger is None:
        result.add(
            ViolationReason.MISSING_LEDGER,
            "certification requires an ExposureLedger; without it curator != subject is unverifiable",
        )
    if evaluation_ledger is None:
        result.add(
            ViolationReason.MISSING_LEDGER,
            "certification requires a prior_evaluations EvaluationLedger; without it evaluate-once is "
            "unverifiable",
        )
    if freeze is not None:
        if not freeze.pool_root:
            result.add(
                ViolationReason.PRECISION_SAMPLE_UNBOUND,
                "certification requires a non-empty committed freeze pool_root (an inert pool commitment "
                "leaves the precision sample unbound)",
            )
        pool_size = len(precision.pool) if precision is not None else 0
        min_k = min(pool_size, _MIN_PRECISION_SAMPLE_K) if pool_size else _MIN_PRECISION_SAMPLE_K
        if freeze.committed_k < min_k:
            result.add(
                ViolationReason.PRECISION_SAMPLE_UNBOUND,
                f"certification requires a committed_k >= min(|pool|, {_MIN_PRECISION_SAMPLE_K}); "
                f"committed_k={freeze.committed_k} is inert/too small",
            )
        # R8-2: the precision sample must be COMMITTED in the frozen bundle (not derived from the
        # grindable freeze_hash). An inert sample_root leaves the sample re-rollable by grinding.
        if not freeze.sample_root:
            result.add(
                ViolationReason.PRECISION_SAMPLE_UNBOUND,
                "certification requires a non-empty committed freeze sample_root (the precision "
                "sample must be committed at freeze time, not derived from the grindable freeze_hash)",
            )
        else:
            # R9-1: the committed sample must be the CANONICAL draw from COMMITTED, non-grindable
            # state — the HEAD cohort_content_hash + the committed pool_root + the committed k — NOT
            # an operator-chosen sample. R8-2 pinned the sample to the committed sample_root, but the
            # OPERATOR still chose WHICH pairs to commit (the seed was a free input); R9-1 removes
            # that last degree of freedom. RECOMPUTE the canonical sample root from committed state
            # and require the committed freeze sample_root to EQUAL it; a cherry-picked (favorable)
            # sample is PRECISION_SAMPLE_UNBOUND. ``precision.pool`` is bound to the committed
            # pool_root by ``_check_precision_binding`` (B4), so the recompute is anchored to
            # committed membership; combined with that check (presented sampled_pairs reproduce the
            # committed sample_root), the presented sample is forced to BE the canonical draw.
            _head = history.latest() if history is not None else None
            if _head is not None and precision is not None:
                if freeze.sample_root != canonical_sample_root(
                    _head.content_hash, precision.pool, freeze.committed_k
                ):
                    result.add(
                        ViolationReason.PRECISION_SAMPLE_UNBOUND,
                        "committed freeze sample_root is not the canonical draw from "
                        "(cohort_content_hash, pool_root, k); an operator-chosen precision sample is "
                        "not bound to committed state",
                    )

    # ----------------------------------------------------------------------- #
    # Round-4/5 — attack the irreducible floor a pure validator cannot reach.
    # ----------------------------------------------------------------------- #

    # R5-4 — the evaluator must be the COMMITTED one, and (P1e) must not be the scored
    # subject. Binding evaluator_id to committed state closes the "self-mint an identity"
    # dodge; the private-key-holder boundary remains organizational and documented.
    if attestation.evaluator_id != committed.evaluator_id:
        result.add(
            ViolationReason.ATTESTATION_INVALID,
            f"attestation evaluator_id {attestation.evaluator_id!r} is not the committed evaluator "
            f"{committed.evaluator_id!r}",
        )
    if run is not None and attestation.evaluator_id == run.subject:
        result.add(
            ViolationReason.CURATOR_IS_SUBJECT,
            f"attestation evaluator_id {attestation.evaluator_id!r} equals the scored subject; "
            "the certifier must not be the subject",
        )

    # P1b — a certification must stand on exactly ONE producing post-freeze evaluation.
    # A Report certified against a run that never produced results (attempts==[] or an
    # all-crash run) is a headline with no measurement behind it.
    if run is None or run.semantic_evaluation_count != 1:
        produced = run.semantic_evaluation_count if run is not None else 0
        result.add(
            ViolationReason.CERTIFY_WITHOUT_EVALUATION,
            f"certification requires exactly one producing post-freeze evaluation (found {produced})",
        )

    # P1c — the headline precision must be BOUND to a real adjudication, not a free
    # float. A certified ``report.adjudicated_precision`` must equal the precision of a
    # presented, panel-validated ``AdjudicatedPrecision`` (itself seed/pool/k-bound by
    # ``_check_precision_binding``).
    if report is not None:
        if precision is None:
            result.add(
                ViolationReason.PRECISION_UNBOUND,
                "certification requires a bound AdjudicatedPrecision; a free adjudicated_precision float "
                "is not verifiable",
            )
        elif abs(report.adjudicated_precision - precision.precision) > 1e-9:
            result.add(
                ViolationReason.PRECISION_UNBOUND,
                f"report.adjudicated_precision ({report.adjudicated_precision}) does not equal the bound "
                f"AdjudicatedPrecision.precision ({precision.precision})",
            )

    # R10-5 (P-A) + R10-6 — RE-ENFORCE the AdjudicatedPrecision panel + coverage invariants on the
    # certify path (a from-storage ``model_construct`` object bypasses the constructor validator),
    # and bind every adjudicator to the committed roster + subject-independence. A precision object
    # with partial coverage, a builder adjudicator, or an under-composed panel is
    # ``PRECISION_PANEL_INVALID``; a non-independent / unrostered adjudicator is
    # ``ADJUDICATOR_INVALID``.
    if precision is not None:
        _check_precision_panel(precision, run, committed, result)

    # R5-6 — a certified report must not carry a free ``achievable_recall``. It is a
    # labelled DIAGNOSTIC for non-certified reports only; in the certified bundle it would
    # be an unbound headline number, so forbid it (bind-or-forbid; we forbid).
    if report is not None and report.achievable_recall is not None:
        result.add(
            ViolationReason.ACHIEVABLE_UNBOUND,
            "a certified report must not carry an achievable_recall; it is a labelled diagnostic for "
            "non-certified reports only",
        )

    # R5-2 + PART 3 — attestation chaining and git-anchored, MONOTONIC genesis. The prior
    # baseline is loaded from COMMITTED state (never a caller ``prior_history``): the
    # attestation must chain from the committed latest attestation root, and the presented
    # history must append-only-EXTEND the committed prior history root.
    if attestation.prior_attestation_root != committed.latest_attestation_root:
        result.add(
            ViolationReason.GENESIS_UNANCHORED,
            "attestation prior_attestation_root does not equal the committed latest attestation root; "
            "re-anchoring to an unreviewable genesis is refused",
        )
    if history is None or not _history_reproduces_committed(history, committed.latest_history_root):
        result.add(
            ViolationReason.ATTESTATION_NOT_EXTENDING,
            "presented history does not reproduce + append-only-extend the committed prior history root "
            "(a truncated / rewritten / re-anchored cohort cannot certify)",
        )

    # F1 — the certified run MUST have evaluated the terminal (committed-extended head)
    # cohort version. A run bound to a stale earlier version (or an unresolvable hash)
    # denominates against a smaller blind set that silently dropped a hard miss appended to
    # the head later; require ``run.cohort_content_hash == history.latest().content_hash``.
    head = history.latest() if history is not None else None
    if head is None:
        result.add(
            ViolationReason.REPORT_DENOMINATOR_MISMATCH,
            "certification requires a resolvable head cohort to bind the denominator to",
        )
    elif run is not None and run.cohort_content_hash != head.content_hash:
        result.add(
            ViolationReason.DENOMINATOR_SHRINK,
            f"certified run is bound to cohort {run.cohort_content_hash[:12]} which is not the head "
            f"version {head.content_hash[:12]} (a stale/unresolvable bind drops later-added hard cases)",
        )

    # F2 — the presented prior_evaluations MUST reproduce + append-only-extend the committed
    # evaluation-ledger root. Evaluate-once is COMMITTED monotonic state: an operator cannot
    # present an empty (or truncated) ledger to dodge the A3 blind-set re-roll check — the
    # empty-ledger root only reproduces a committed root that is itself empty (a genuine first
    # evaluation). Combined with A3's blind-set overlap on the truthful ledger, a re-freeze
    # re-score of an already-evaluated blind set is caught either way.
    if evaluation_ledger is not None and not _evaluation_reproduces_committed(
        evaluation_ledger, committed.latest_evaluation_root
    ):
        result.add(
            ViolationReason.EVALUATED_MORE_THAN_ONCE,
            "presented prior_evaluations does not reproduce + append-only-extend the committed "
            "evaluation-ledger root (a truncated / re-anchored ledger cannot dodge evaluate-once)",
        )

    # R10-2 (P-B) — the presented ExposureLedger MUST reproduce + append-only-extend the committed
    # exposure-ledger root, in parity with history (R5-2) and evaluation (F2). The exposure check
    # previously verified only against the freshly-signed attestation's OWN exposure_root, so a
    # truncated ledger (drop the incriminating curator record) could re-sign and pass. Binding it
    # to the committed-monotonic root closes that: a truncated / re-anchored exposure ledger cannot
    # certify (``EXPOSURE_LEDGER_TRUNCATED``).
    if ledger is not None and not _exposure_reproduces_committed(
        ledger, committed.latest_exposure_root
    ):
        result.add(
            ViolationReason.EXPOSURE_LEDGER_TRUNCATED,
            "presented exposure ledger does not reproduce + append-only-extend the committed "
            "exposure-ledger root (a truncated / re-anchored curator ledger cannot certify)",
        )

    # R5-1 + PART 2 — the numerator VERIFIER, RUN from committed state. ``validate`` RUNS
    # ``recompute_rediscovered`` itself: the ``scan_fn`` is resolved from the committed
    # DETECTOR_REGISTRY keyed by the frozen ``detector_id`` and the ``fetch_fn`` from the
    # committed corpus fetcher — neither is a caller argument. The reported set must MATCH
    # the recompute (``NUMERATOR_UNVERIFIED``): an operator can no longer CLAIM a
    # rediscovery the committed detector did not produce on the real code, OMIT a real one,
    # nor substitute a lying detector or a lying recompute. SAFETY (Article III): the
    # detector PARSES fetched source as DATA; no target code is executed.
    if report is not None and report.rediscovered_blind_ids is not None:
        claimed = set(report.rediscovered_blind_ids)
        # F1: the numerator is recomputed over the HEAD cohort's blind entries, never the
        # run's declared (possibly stale) cohort — the recompute cannot be bound to a smaller
        # earlier version that dropped a later-added hard miss.
        scored = history.latest() if history is not None else None
        if freeze is None or scored is None:
            result.add(
                ViolationReason.NUMERATOR_UNVERIFIED,
                "certification cannot recompute the numerator without a FreezeManifest and a resolvable "
                "scored cohort",
            )
        else:
            import verifier  # local import: verifier -> corpus_measure, no cycle back to contract

            blind_entries = scored.by_role(Role.BLIND)
            try:
                recomputed = verifier.recompute_certified_numerator(
                    blind_entries, detector_id=freeze.bundle.detector_id
                )
            except verifier.InputBytesUnverified as exc:
                # R8-1: the fetched pinned bytes do not reproduce the committed per-target blob
                # sha256 — a doctored fetch source/cache. Fail closed on INPUT truthfulness.
                result.add(
                    ViolationReason.INPUT_BYTES_UNVERIFIED,
                    f"the numerator recompute ran on bytes that do not match the committed pinned "
                    f"content (detector_id={freeze.bundle.detector_id!r}): {exc}",
                )
            except Exception as exc:  # noqa: BLE001 — an un-recomputable numerator fails closed
                result.add(
                    ViolationReason.NUMERATOR_UNVERIFIED,
                    f"certification could not recompute the numerator from committed state "
                    f"(detector_id={freeze.bundle.detector_id!r}): {exc}",
                )
            else:
                if claimed != recomputed:
                    result.add(
                        ViolationReason.NUMERATOR_UNVERIFIED,
                        "reported rediscovered_blind_ids do not match the committed detector re-run on the "
                        f"real pinned code (claimed {len(claimed)}, recomputed {len(recomputed)})",
                    )

    # ----------------------------------------------------------------------- #
    # R7-2 — bind EVERY certified numeric: no free secondary floats. Each reported
    # secondary is RECOMPUTED from the committed detector+cohort or FORBIDDEN in a
    # certified report. adjudicated_precision is already bound (P1c) and achievable_recall
    # already forbidden (R5-6); this closes fixed_cohort_recall, patched_alert_density, and
    # the non-recomputable coverage — mirroring ACHIEVABLE_UNBOUND.
    # ----------------------------------------------------------------------- #
    if report is not None:
        # coverage = pinned/all is NOT recomputable from committed state (the denominator
        # includes dropped, uncommitted entries) — FORBID it in a certified report. It stays
        # available as a labelled diagnostic on NON-certified reports only.
        if report.coverage is not None:
            result.add(
                ViolationReason.COVERAGE_UNBOUND,
                "a certified report must not carry a free coverage numeric; coverage (pinned/all) is not "
                "recomputable from committed state and is a diagnostic for non-certified reports only",
            )
        scored = history.latest() if history is not None else None
        if freeze is not None and scored is not None:
            import verifier  # local import: verifier -> corpus_measure, no cycle back to contract

            # fixed_cohort_recall — RECOMPUTED over the HEAD cohort's REGRESSION entries by
            # re-running the committed detector (the fixed-cohort mirror of the blind numerator).
            regression_entries = scored.by_role(Role.REGRESSION)
            try:
                fixed_rediscovered, fixed_total = verifier.recompute_fixed_cohort_recall(
                    regression_entries, detector_id=freeze.bundle.detector_id
                )
            except verifier.InputBytesUnverified as exc:
                result.add(
                    ViolationReason.INPUT_BYTES_UNVERIFIED,
                    f"the fixed_cohort_recall recompute ran on bytes that do not match the committed "
                    f"pinned content (detector_id={freeze.bundle.detector_id!r}): {exc}",
                )
            except Exception as exc:  # noqa: BLE001 — an un-recomputable fixed cohort fails closed
                result.add(
                    ViolationReason.FIXED_COHORT_UNVERIFIED,
                    f"certification could not recompute fixed_cohort_recall from committed state "
                    f"(detector_id={freeze.bundle.detector_id!r}): {exc}",
                )
            else:
                if (
                    report.fixed_cohort_recall.total != fixed_total
                    or report.fixed_cohort_recall.rediscovered != fixed_rediscovered
                ):
                    result.add(
                        ViolationReason.FIXED_COHORT_UNVERIFIED,
                        f"reported fixed_cohort_recall "
                        f"{report.fixed_cohort_recall.rediscovered}/{report.fixed_cohort_recall.total} does not "
                        f"match the committed regression re-run {fixed_rediscovered}/{fixed_total}",
                    )

            # patched_alert_density — RECOMPUTED from the detector run's patched-tree flag counts
            # (corpus_measure's patched_flag_count) over the head cohort's BLIND entries.
            try:
                density = verifier.recompute_patched_alert_density(
                    scored.by_role(Role.BLIND), detector_id=freeze.bundle.detector_id
                )
            except verifier.InputBytesUnverified as exc:
                result.add(
                    ViolationReason.INPUT_BYTES_UNVERIFIED,
                    f"the patched_alert_density recompute ran on bytes that do not match the committed "
                    f"pinned content (detector_id={freeze.bundle.detector_id!r}): {exc}",
                )
            except Exception as exc:  # noqa: BLE001 — an un-recomputable density fails closed
                result.add(
                    ViolationReason.DENSITY_UNVERIFIED,
                    f"certification could not recompute patched_alert_density from committed state "
                    f"(detector_id={freeze.bundle.detector_id!r}): {exc}",
                )
            else:
                if abs(report.patched_alert_density - density) > 1e-9:
                    result.add(
                        ViolationReason.DENSITY_UNVERIFIED,
                        f"reported patched_alert_density ({report.patched_alert_density}) does not match the "
                        f"committed detector's recomputed patched-tree density ({density})",
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
