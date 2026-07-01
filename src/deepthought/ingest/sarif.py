"""SARIF 2.1.0 ingest — tool output into candidate findings + suspected primitives.

A SARIF file is an untrusted, attacker-influenceable, read-only input. This
module reads only the small, explicit subset documented in
``specs/002-improbability-drive/contracts/sarif-ingest.md`` and treats every
string in it as *data*:

1. **SARIF text is data.** Each SARIF string is copied only into a ``Finding``
   data field (``summary``, body narrative, a reference url) or a ``Primitive``
   ``target_locus``. None of it reaches a channel the orchestrator or harness
   interprets as instruction, and each copy is length-bounded.
2. **``ruleId`` -> capability is a closed lookup.** An injected or unknown
   ``ruleId`` can, at worst, miss the table and produce a finding with no
   primitive. It can never mint an arbitrary capability, an ``exec:*``, or a
   command.

Nothing here executes anything or fetches anything: ``load_sarif`` parses JSON
from a local file, and the mappings are pure data transforms.
"""

from __future__ import annotations

import json

from ..schema.envelope import CAPABILITY_TAXONOMY, Confidence, Primitive
from ..schema.finding import Finding, FindingStatus, Reference

# The only SARIF version this ingest accepts. Anything else is rejected rather
# than silently coerced.
SARIF_VERSION = "2.1.0"

# Conservative bound on the one-line summary copied out of SARIF text. The
# Finding.summary field is unbounded in the schema, but OSV summaries are meant
# to be one line, so we cap the untrusted copy here.
_SUMMARY_MAX = 200

# Conservative bound on the finding body assembled from SARIF text. The
# Finding.body field is unbounded in the schema, but the sarif-ingest contract
# (property 1) and data-model require SARIF text to be *length-bounded* into the
# length-capped finding fields — the body copy (and, through it, OSV `details`
# on export) must not carry an unbounded hostile payload. The whole assembled
# body is capped here so no untrusted copy can exceed it.
_BODY_MAX = 4096

# Closed ruleId/tag -> capability lookup. Every right-hand value MUST already be
# a member of CAPABILITY_TAXONOMY; the table can reuse a capability but never
# introduce one. Matching is a case-insensitive substring test against the
# result's ruleId and the resolved rule tags. A row is (needle, capability).
#
# The needles are ordered most-specific-first so that, e.g., "sqli" wins before
# a broader token could. The table's *shape* is fixed; its *rows* grow as real
# tool output is seen.
_HEURISTIC: tuple[tuple[str, str], ...] = (
    # SQL injection
    ("sqli", "inject:sql"),
    ("sql", "inject:sql"),
    ("cwe-89", "inject:sql"),
    # Template injection
    ("ssti", "inject:template"),
    ("template-injection", "inject:template"),
    ("template", "inject:template"),
    ("cwe-1336", "inject:template"),
    # Deserialization
    ("deserial", "deserialize:untrusted"),
    ("unpickle", "deserialize:untrusted"),
    ("unmarshal", "deserialize:untrusted"),
    ("cwe-502", "deserialize:untrusted"),
    # SSRF
    ("ssrf", "ssrf:request"),
    ("cwe-918", "ssrf:request"),
    # Command injection
    ("command-injection", "exec:command"),
    ("os-command", "exec:command"),
    ("shell", "exec:command"),
    ("cwe-78", "exec:command"),
    # Code injection / eval / RCE
    ("code-injection", "exec:code"),
    ("eval", "exec:code"),
    ("rce", "exec:code"),
    ("cwe-94", "exec:code"),
    # Arbitrary file write / path traversal (and conservative memory-write proxy)
    ("path-traversal", "write:arbitrary-file"),
    ("path-injection", "write:arbitrary-file"),
    ("arbitrary-file-write", "write:arbitrary-file"),
    ("file-write", "write:arbitrary-file"),
    ("zip-slip", "write:arbitrary-file"),
    ("cwe-22", "write:arbitrary-file"),
    ("cwe-73", "write:arbitrary-file"),
    ("path", "write:arbitrary-file"),
    ("buffer", "write:arbitrary-file"),
    ("oob-write", "write:arbitrary-file"),
    ("use-after-free", "write:arbitrary-file"),
    ("cwe-787", "write:arbitrary-file"),
    ("cwe-416", "write:arbitrary-file"),
    # Arbitrary file read
    ("arbitrary-file-read", "read:arbitrary-file"),
    ("file-read", "read:arbitrary-file"),
    # Auth bypass
    ("auth-bypass", "auth:bypass"),
    ("missing-auth", "auth:bypass"),
    ("authz", "auth:bypass"),
    ("cwe-287", "auth:bypass"),
    ("cwe-306", "auth:bypass"),
    # Privilege escalation
    ("priv-esc", "escalate:privilege"),
    ("privilege", "escalate:privilege"),
    ("cwe-269", "escalate:privilege"),
    # Secret leak
    ("hardcoded-credential", "leak:secret"),
    ("api-key", "leak:secret"),
    ("secret", "leak:secret"),
    ("cwe-798", "leak:secret"),
    # Info leak
    ("info-leak", "leak:info"),
    ("sensitive-exposure", "leak:info"),
    ("cwe-200", "leak:info"),
)

# Fail fast at import if the table ever names a capability the taxonomy does not
# define. The contract requires this invariant; a test also asserts it.
_unknown_caps = {cap for _, cap in _HEURISTIC if cap not in CAPABILITY_TAXONOMY}
if _unknown_caps:  # pragma: no cover - guards the table, never expected to fire
    raise RuntimeError(f"heuristic table names non-taxonomy capabilities: {_unknown_caps!r}")


class SarifError(ValueError):
    """Raised when a file is not a valid, accepted SARIF 2.1.0 document."""


def load_sarif(path: str) -> dict:
    """Read a SARIF file from disk and return it as a plain dict.

    Parses JSON only. Does not execute anything, does not fetch anything. A file
    that is not valid JSON, not a SARIF-shaped object, or not version 2.1.0
    raises :class:`SarifError`.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise SarifError(f"file is not valid JSON: {exc}") from exc
    except OSError as exc:
        # Missing file, a directory, a permission error — a read failure is a
        # blocked worker, not an orchestrator crash. Callers handle SarifError.
        raise SarifError(f"could not read SARIF file {path!r}: {exc}") from exc
    if not isinstance(data, dict):
        raise SarifError("SARIF document must be a JSON object")
    if data.get("version") != SARIF_VERSION:
        raise SarifError(
            f"unsupported SARIF version {data.get('version')!r}; expected {SARIF_VERSION!r}"
        )
    if not isinstance(data.get("runs", []), list):
        raise SarifError("SARIF 'runs' must be a list")
    return data


# --- internal walkers -------------------------------------------------------


def _runs(sarif: dict) -> list:
    runs = sarif.get("runs")
    return runs if isinstance(runs, list) else []


def _rules_index(run: dict) -> dict:
    """Map ruleId -> rule object for a run, so tags and helpUri resolve.

    SARIF is untrusted: every nested access is type-checked. A ``tool``,
    ``driver``, or ``rules`` of the wrong type yields an empty index rather than
    an ``AttributeError``.
    """
    tool = run.get("tool")
    if not isinstance(tool, dict):
        return {}
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        return {}
    rules = driver.get("rules")
    if not isinstance(rules, list):
        return {}
    index: dict = {}
    for rule in rules:
        if isinstance(rule, dict) and isinstance(rule.get("id"), str):
            index[rule["id"]] = rule
    return index


def _message_text(result: dict) -> str | None:
    message = result.get("message")
    if not isinstance(message, dict):
        return None
    text = message.get("text")
    if isinstance(text, str) and text.strip():
        return text.strip()
    return None


def _first_location(result: dict) -> tuple[str | None, int | None]:
    """Return (uri, startLine) from the first physicalLocation, if any.

    Every nested structure is type-checked: a malformed ``locations`` list (e.g.
    ``["not an object"]``) is skipped rather than dereferenced.
    """
    locations = result.get("locations")
    if not isinstance(locations, list):
        return None, None
    for loc in locations:
        if not isinstance(loc, dict):
            continue
        physical = loc.get("physicalLocation")
        if not isinstance(physical, dict):
            continue
        artifact = physical.get("artifactLocation")
        if not isinstance(artifact, dict):
            continue
        uri = artifact.get("uri")
        region = physical.get("region")
        start_line = region.get("startLine") if isinstance(region, dict) else None
        if isinstance(uri, str) and uri:
            line = start_line if isinstance(start_line, int) else None
            return uri, line
    return None, None


def _rule_help_uri(rule: dict | None) -> str | None:
    if not isinstance(rule, dict):
        return None
    uri = rule.get("helpUri")
    return uri if isinstance(uri, str) and uri else None


def _rule_tags(rule: dict | None) -> list[str]:
    if not isinstance(rule, dict):
        return []
    properties = rule.get("properties")
    if not isinstance(properties, dict):
        return []
    tags = properties.get("tags")
    if not isinstance(tags, list):
        return []
    return [t for t in tags if isinstance(t, str)]


def _accepted_results(sarif: dict):
    """Yield (result, rule) for every result worth turning into a finding.

    A result with no usable ``message.text`` is skipped. Order is the document
    order, which is the ordering contract both public mappings walk.
    """
    for run in _runs(sarif):
        if not isinstance(run, dict):
            continue
        index = _rules_index(run)
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            if _message_text(result) is None:
                continue
            rule_id = result.get("ruleId")
            rule = index.get(rule_id) if isinstance(rule_id, str) else None
            yield result, rule


# --- findings ---------------------------------------------------------------


def sarif_to_findings(sarif: dict, *, project: str, id_start: int = 1) -> list[Finding]:
    """Map the accepted SARIF subset to candidate Findings.

    One Finding per accepted result, status ``candidate``, ids assigned
    sequentially from ``id_start`` (``F-0001``, ``F-0002``, …). Every returned
    Finding is OSV-valid by construction: it carries only ``id`` + fields that
    export to a conformant OSV record, ``affected`` stays empty, and
    ``evidence_ref`` is ``None`` (a candidate carries no evidence).
    """
    findings: list[Finding] = []
    n = id_start
    for result, rule in _accepted_results(sarif):
        message = _message_text(result)
        assert message is not None  # _accepted_results guarantees this
        rule_id = result.get("ruleId")
        rule_id = rule_id if isinstance(rule_id, str) else None

        # OSV summaries are single-line. Both message.text AND ruleId are
        # untrusted SARIF data and may contain newlines, so first-line each
        # before building the summary; the full message still goes into the body.
        first_line = message.splitlines()[0] if message.splitlines() else message
        summary = first_line
        if rule_id:
            rule_line = rule_id.splitlines()[0] if rule_id.splitlines() else rule_id
            summary = f"{rule_line}: {first_line}"
        summary = summary[:_SUMMARY_MAX]

        references: list[Reference] = []
        help_uri = _rule_help_uri(rule)
        if help_uri:
            # type is free-form here; normalised to the OSV enum on export.
            references.append(Reference(type="detection", url=help_uri))

        # Bound the untrusted SARIF text on the way into the body. The body is
        # data (never interpreted as instruction) and flows into OSV `details`
        # on export, so it is capped here to honor the length-bounding contract.
        body = f"## Root cause\n\n{message}"[:_BODY_MAX]

        findings.append(
            Finding(
                id=f"F-{n:04d}",
                project=project,
                summary=summary,
                status=FindingStatus.candidate,
                references=references,
                affected=[],
                evidence_ref=None,
                body=body,
            )
        )
        n += 1
    return findings


# --- primitives -------------------------------------------------------------


def _match_capability(rule_id: str | None, tags: list[str]) -> str | None:
    """Return the mapped capability for a ruleId/tags, or None if unmatched.

    Closed lookup: the ruleId and each tag are lowercased and tested as
    substrings against the fixed table. A ruleId that matches nothing yields
    None (finding only, no primitive). The ruleId is never evaluated, formatted
    into a command, or used as a capability — it is only ever a table key.
    """
    haystacks = [h.lower() for h in ([rule_id] if rule_id else []) + list(tags)]
    for needle, capability in _HEURISTIC:
        for hay in haystacks:
            if needle in hay:
                return capability
    return None


def sarif_to_primitives(sarif: dict, *, finding_ids: list[str]) -> list[Primitive]:
    """Map accepted SARIF results to suspected Primitives via the closed table.

    ``finding_ids`` is the list returned alongside :func:`sarif_to_findings`
    (same order), so each primitive binds to its finding via ``finding_ref``. A
    result whose ruleId/tags are unmapped yields no primitive. Every primitive
    is ``confidence: suspected`` with no ``evidence_ref`` (nothing executed).
    """
    primitives: list[Primitive] = []
    for i, (result, rule) in enumerate(_accepted_results(sarif)):
        if i >= len(finding_ids):
            break
        rule_id = result.get("ruleId")
        rule_id = rule_id if isinstance(rule_id, str) else None
        capability = _match_capability(rule_id, _rule_tags(rule))
        if capability is None:
            continue

        uri, line = _first_location(result)
        if uri and line is not None:
            locus = f"{uri}:{line}"
        elif uri:
            locus = uri
        else:
            locus = rule_id or "unknown"
        locus = locus[:256]

        primitives.append(
            Primitive(
                kind=capability,
                target_locus=locus,
                preconditions=[],
                grants=[capability],
                confidence=Confidence.suspected,
                evidence_ref=None,
                finding_ref=finding_ids[i],
            )
        )
    return primitives
