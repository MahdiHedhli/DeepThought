# Data Model: Improbability Drive — DISCOVER and MAP (002)

**No new record types.** DISCOVER and MAP reuse the 001 records unchanged:
`Finding` (entering at status `candidate`), `Coverage` (`method='read'`), and
`Session`. The worker `Envelope` and `Primitive` contracts are unchanged. SARIF
results map *into* these existing shapes; nothing new is added to the schema, and
the Store interface is untouched. This document specifies how the two sessions use
the existing records and the two SARIF mappings, and it states the OSV-validity
guarantee.

## Records used, and how

### Finding (status `candidate`)

DISCOVER writes candidate findings. It reuses `deepthought.schema.finding.Finding`
exactly as defined in 001. Constraints specific to this feature:

- `status` is always `FindingStatus.candidate`. DISCOVER never sets a higher
  status: promotion requires a resolving `evidence_ref`, which only a sandboxed
  `VERIFY` produces (Article IV). DISCOVER writes no `evidence_ref`.
- `id` is assigned by the ingest, starting at `id_start` (default `1`), rendered
  in the existing internal form `F-0001`, `F-0002`, … The caller (the DISCOVER
  session) is responsible for choosing an `id_start` that does not collide with
  findings already in the Store.
- `project` is the in-scope project the session runs against.
- `summary` is a one-line description derived from the SARIF result (its
  `message.text`, truncated to the field's bound). Data only.
- `references` may include the SARIF result's `physicalLocation` rendered as a
  reference (type left free-form; normalised to the OSV enum on export — an
  unknown type maps to `WEB`).
- Body narrative (`## Root cause`, `## Impact`) is populated conservatively from
  SARIF text where present; it is data, and it feeds OSV `details` on export.
- `severity` is set only when the SARIF `level` maps to a defensible CVSS band
  (see below); otherwise it is left `None`. A finding with no severity is still
  OSV-valid.

Every field populated from SARIF is treated as untrusted data (Article VIII): it
is copied into a data field, never interpreted as instruction, and the copy is
bounded by the field's length before it reaches the length-capped envelope/finding
surface.

### Coverage (`method='read'`)

Both sessions write coverage through `deepthought.schema.coverage.Coverage`,
unchanged from 001:

- `method` is `CoverageMethod.read` for every coverage record this feature writes.
  MAP surveyed the surface by reading; DISCOVER reasoned over static signals and
  SARIF — neither executed anything, so `read` is the honest method (not
  `static`, which is reserved for tooling passes, nor `fuzz`, which needs the
  sandbox).
- `depth` is `CoverageDepth.touched` for a surveyed-but-not-exhausted path.
  Whether a static reasoning pass ever earns `explored` is an open question in
  `spec.md`; the conservative default is `touched`.
- `area` is an in-scope path or module from the project's `scope_allowlist`. MAP
  never records coverage for a path outside the allowlist.
- `last_session` is the session id that produced the record.

### Session

Both `MapSession` and `DiscoverSession` subclass `BaseSession` and run through the
unchanged `run_session` harness. They set `.type` to the existing enum members
`SessionType.map` and `SessionType.discover` (both already present in the 001
`SessionType` enum — no schema change). Each returns a `SessionOutcome` with a
summary, explicit next steps, and the findings/coverage it touched, so the harness
can close the session. A session with no `## Next steps` does not close.

### Envelope and Primitive (unchanged contract)

DISCOVER dispatches a stub Marvin that returns exactly one `Envelope`, ingested
through the existing `Conductor`. The suspected primitives ride in the envelope's
`primitives[]` and land in the bounded `Ledger` on ingest, exactly as in 001. No
field is added to either contract. Primitives from a discovery pass carry
`confidence: suspected` (nothing was demonstrated, so no `evidence_ref` is
required by the `Primitive` validator).

## SARIF-result → Finding mapping

For each `result` in `runs[].results[]` of an accepted SARIF file, ingest emits
one candidate `Finding`:

| SARIF source | Finding field | Notes |
| --- | --- | --- |
| assigned sequentially from `id_start` | `id` | `F-0001`, `F-0002`, … internal form. |
| the `project` argument | `project` | The in-scope project. |
| `result.message.text` | `summary` | One line, truncated to the field bound. Data only. |
| (fixed) | `status` | Always `candidate`. |
| `result.level` → CVSS band | `severity` | Only when the level maps to a defensible band; else `None`. See level map below. |
| `result.locations[].physicalLocation` (`artifactLocation.uri` + `region.startLine`) | `references[]` (a `{type, url}` locating the code) and body `## Root cause` context | Rendered as a location reference; text is data. |
| `result.message.text` (+ ruleId context) | body `## Impact` / `downstream_impact` | Conservative narrative from the tool's message. Data only. |
| `result.ruleId` | recorded in the body / a reference | Also drives the primitive heuristic below. |

Level → severity band (conservative; a static tool's level is a hint, not a
measured CVSS):

| SARIF `level` | Finding `severity` |
| --- | --- |
| `error` | a low-to-moderate CVSS placeholder band, or left `None` if no defensible vector exists |
| `warning` | `None` (or a low band) |
| `note` / `none` / absent | `None` |

The implementer MAY leave `severity` `None` across the board in 002 and let a
later, evidence-bearing session set it. A `None` severity is OSV-valid; a
fabricated CVSS score is not defensible and must not be minted from a tool level.

## SARIF-result → suspected Primitive mapping

The `ruleId`/tag → capability heuristic is a **closed, conservative lookup table**
(the injection-resistant property: an attacker-influenced `ruleId` can, at worst,
miss the table). For each result whose `ruleId` (or a rule tag) matches an entry,
ingest emits one suspected `Primitive` bound to the result's finding:

- `kind` — the mapped capability from `CAPABILITY_TAXONOMY`.
- `grants` — the same capability (a discovery pass asserts what the finding
  *grants*, conservatively equal to its kind).
- `target_locus` — the result's `physicalLocation` as `uri:line`.
- `confidence` — always `suspected` (nothing executed; no `evidence_ref`).
- `finding_ref` — the id of the finding this result produced.
- `preconditions` — empty by default; a static pass rarely establishes them.

An **unmapped `ruleId` yields a finding but no primitive.** A finding without a
suspected primitive is allowed and expected. This keeps the taxonomy honest: the
platform never invents a capability from a rule it does not understand.

The starter table (`ruleId` substring / CWE / tag → capability) lives in
`contracts/sarif-ingest.md`. The table's *shape* is fixed here; its *rows* grow as
real tool output is seen. Every mapped capability must already be a member of
`CAPABILITY_TAXONOMY` — the mapping cannot introduce a new capability, only reuse
an existing one.

## OSV-validity guarantee

Every `Finding` generated by DISCOVER must pass `check`. Concretely:

- `finding_to_osv(finding)` followed by `validate_osv(...)` returns no errors for
  every generated finding (the same path `check._check_osv` runs).
- The ingest constructs findings only from fields it can guarantee are OSV-valid:
  a candidate finding needs only `id` + a `modified` timestamp on export (OSV
  requires just `id` + `modified`; `affected` may be empty), both of which the
  mapping always supplies. `summary`, `references`, and `severity` are added only
  in OSV-valid forms (severity only with a parseable CVSS vector; references
  normalised to the OSV type enum on export).
- A candidate finding at status `candidate` has no lifecycle-at-rest obligation in
  `check` (only `verified`/`disclosed`/`patched` do), so DISCOVER output is
  lifecycle-clean by construction.
- **If a SARIF result cannot be turned into an OSV-valid finding, it is not
  written.** The ingest never emits a finding that would fail `check`. This is the
  contract the DISCOVER acceptance criterion depends on.

## Notes

- All writes go through the `Store`. Neither session reads or writes `state/`
  directly. MAP walks the target repository's working tree (read-only, in-scope
  paths only) to build coverage; that traversal reads the *target's* files, not
  the *state store*, and writes coverage back only through the Store.
- No record type, no Store method, and no schema field is added in this feature.
  The capability taxonomy may gain vocabulary; its shape is fixed.
- Nothing here executes target code. MAP reads; DISCOVER reasons over static
  signals and a SARIF file a tool already produced. The sandbox (003) is what
  gates anything that runs code.
