# Contract: SARIF Ingest (tool output → candidate findings + suspected primitives)

SARIF is how the Improbability Drive consumes results a static-analysis tool
already produced. It is an **untrusted, read-only input**: a SARIF file is
attacker-influenceable, so this contract treats every string in it as *data*,
never as instruction. The module reads only the small, explicit subset documented
here; anything outside the subset is ignored, not trusted. Ingest produces
candidate `Finding`s and, via a closed lookup table, suspected `Primitive`s.

Two properties make this boundary safe (Constitution VIII):

1. **SARIF text is data.** Every SARIF string is copied only into a `Finding` data
   field (`summary`, body narrative, a reference url) or a `Primitive`
   `target_locus`. None of it reaches a channel the orchestrator or the harness
   interprets as instruction. It is length-bounded into the length-capped
   envelope/finding fields.
2. **`ruleId` → capability is a closed lookup.** An injected or unknown `ruleId`
   can, at worst, miss the table and produce a finding with no primitive. It can
   never mint an arbitrary capability, an `exec:*`, or a command.

## Module and public signatures

`src/deepthought/ingest/sarif.py`:

```python
def load_sarif(path: str) -> dict:
    """Read a SARIF file from disk and return it as a plain dict.

    Parses JSON only. Does not execute anything, does not fetch anything. A file
    that is not valid JSON or not a SARIF-shaped object raises."""

def sarif_to_findings(
    sarif: dict, *, project: str, id_start: int = 1
) -> list[Finding]:
    """Map the accepted SARIF subset to candidate Findings.

    One Finding per accepted result, status ``candidate``, ids assigned
    sequentially from ``id_start`` (F-0001, F-0002, ...). Every returned Finding
    is OSV-valid by construction; a result that cannot be made OSV-valid is
    skipped, not emitted."""

def sarif_to_primitives(
    sarif: dict, *, finding_ids: list[str]
) -> list[Primitive]:
    """Map accepted SARIF results to suspected Primitives via the closed
    ruleId/tag -> capability table.

    ``finding_ids`` is the list returned alongside ``sarif_to_findings`` (same
    order), so each primitive binds to its finding via ``finding_ref``. A result
    whose ruleId is unmapped yields no primitive. Every primitive is
    ``confidence: suspected`` with no ``evidence_ref``."""
```

Ordering contract: `sarif_to_findings` and `sarif_to_primitives` walk the
accepted results in the same order, so `finding_ids[i]` corresponds to the i-th
accepted result. A caller ingests SARIF as:

```python
sarif = load_sarif(path)
findings = sarif_to_findings(sarif, project=project, id_start=n)
primitives = sarif_to_primitives(sarif, finding_ids=[f.id for f in findings])
```

## Accepted SARIF 2.1.0 subset

Only these fields are read. Everything else in the file is ignored.

```
$.version                              # must be "2.1.0"
$.runs[]                               # each run
  .tool.driver.rules[]                 # optional; used to resolve rule tags for the heuristic
    .id
    .properties.tags[]                 # optional; e.g. "security", "external/cwe/cwe-89"
  .results[]                           # each result -> one candidate finding
    .ruleId                            # drives the capability heuristic
    .message.text                      # -> finding summary + body narrative (DATA)
    .level                             # error|warning|note|none -> conservative severity band
    .locations[]
      .physicalLocation
        .artifactLocation.uri          # -> reference url / target_locus
        .region.startLine              # -> target_locus line
```

Rules for the subset:

- `version` must be `"2.1.0"`. A file that is not 2.1.0-shaped is rejected by
  `load_sarif`/the ingest, not silently coerced.
- A result with no `ruleId` still produces a finding (from `message.text`); it
  simply cannot map to a primitive.
- A result with no `message.text` is skipped (a finding with no summary is not
  worth writing and risks an empty OSV `summary`).
- A result with no `locations[]` produces a finding with no location reference and
  a primitive (if mapped) whose `target_locus` is the rule id or `unknown`.
- `tool.driver.rules[].properties.tags[]` are read only to resolve the heuristic
  (e.g. a `external/cwe/cwe-89` tag) when `ruleId` alone does not match a table
  row. Tags are matched against the table, never interpreted otherwise.

## Outputs

- **Candidate `Finding`s** — one per accepted result, status `candidate`, ids from
  `id_start`, OSV-valid by construction. See the SARIF-result → Finding map in
  `data-model.md`.
- **Suspected `Primitive`s** — zero or one per accepted result, `confidence:
  suspected`, `finding_ref` bound to the result's finding, `kind`/`grants` from
  the heuristic table. See the SARIF-result → Primitive map in `data-model.md`.

The DISCOVER session carries these outputs the rest of the way: the candidate
findings are written to the Store, and the suspected primitives ride in the
Marvin's `Envelope` so they land in the ledger through the normal ingest boundary.

## Rule → capability heuristic table (starter set)

A **closed lookup**: match a result's `ruleId` (case-insensitive substring) or a
resolved CWE/tag to a capability that is already a member of
`CAPABILITY_TAXONOMY`. The mapping cannot introduce a new capability — only reuse
an existing one. The *shape* is fixed; the *rows* grow as real tool output is
seen. An unmatched result yields **no primitive**.

| Match on `ruleId` substring / CWE / tag | Capability (`kind` and `grants`) |
| --- | --- |
| `sql`, `sqli`, CWE-89 | `inject:sql` |
| `ssti`, `template-injection`, CWE-1336 | `inject:template` |
| `deserial`, `unpickle`, `unmarshal`, CWE-502 | `deserialize:untrusted` |
| `ssrf`, CWE-918 | `ssrf:request` |
| `command-injection`, `os-command`, `shell`, CWE-78 | `exec:command` |
| `code-injection`, `eval`, `rce`, CWE-94 | `exec:code` |
| `path-traversal`, `arbitrary-file-write`, `zip-slip`, CWE-22, CWE-73 | `write:arbitrary-file` |
| `file-read`, `arbitrary-file-read`, CWE-73 (read variants) | `read:arbitrary-file` |
| `auth-bypass`, `authz`, `missing-auth`, CWE-287, CWE-306 | `auth:bypass` |
| `priv-esc`, `privilege`, CWE-269 | `escalate:privilege` |
| `secret`, `hardcoded-credential`, `api-key`, CWE-798 | `leak:secret` |
| `info-leak`, `sensitive-exposure`, CWE-200 | `leak:info` |
| `buffer`, `oob-write`, `use-after-free`, CWE-787, CWE-416 | `write:arbitrary-file` (conservative memory-write proxy) |
| *(no match)* | *(none — finding only, no primitive)* |

Table discipline:

- Every right-hand value is verified against `CAPABILITY_TAXONOMY` at module import
  (a test asserts this), so the table can never name a capability the taxonomy
  does not define.
- Matching is against the fixed table only. There is no code path where a
  `ruleId` string becomes anything but a table key — it is never evaluated,
  formatted into a command, or used as a capability directly.
- The last row is the safe default: an unrecognised rule produces a candidate
  finding for a human/`VERIFY` to look at, but asserts no capability.

## Flow to the Store and the Ledger

```
load_sarif(path) ──▶ dict (JSON only; nothing executed, nothing fetched)
        │
        ▼
sarif_to_findings(project, id_start) ──▶ [Finding(candidate), ...]  ── Store.save_finding()
        │                                        (OSV-valid by construction)
        ▼
sarif_to_primitives(finding_ids) ──▶ [Primitive(suspected), ...]
        │
        ▼
   carried in the Marvin Envelope.primitives[]
        │
        ▼
   Conductor.ingest(envelope) ──▶ Ledger holds the suspected primitives
                                  (hints inert; detail_ref never loaded)
```

- **Findings** flow to the Store through `save_finding` (candidate status, no
  lifecycle obligation, OSV-valid). They page any full detail to
  `state/detail/<session>/…` via `write_detail`, never into the orchestrator.
- **Primitives** flow to the Ledger only through the existing envelope-ingest
  boundary — the same firewall 001 tests cover. They are never inserted into the
  ledger by a side channel; the `Conductor` is the one door.
- **Nothing is transmitted.** `load_sarif` reads a local file; there is no network
  path in this contract.

## What this contract does NOT do

- It does not execute the target, run a repro, or invoke the tool that produced
  the SARIF. It consumes results that already exist.
- It does not promote any finding past `candidate`. Evidence — and therefore
  promotion — is a sandboxed `VERIFY` concern (feature 003).
- It does not trust SARIF `level` as a measured CVSS. A tool level maps only to a
  conservative band or to no severity; it never mints a fabricated CVSS score.
- It does not read any SARIF field outside the documented subset, and it never
  interprets a SARIF string as an instruction.
