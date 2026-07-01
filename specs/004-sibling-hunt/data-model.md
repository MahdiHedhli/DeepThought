# Data Model: Sibling Hunt — variant analysis (004)

**No new record types.** SIBLING HUNT reuses the existing records unchanged:
`Finding` (variants entering at status `candidate`), `Coverage` (`method='read'`),
and `Session`. The worker `Envelope` and `Primitive` contracts are unchanged.
Variant instances map *into* these existing shapes exactly as SARIF results do in
DISCOVER; nothing new is added to the schema, and the Store interface is untouched.
The one new type is a **runtime `Signature`** (not a persisted `Record`) that the
session derives and hands to the worker — analogous to `SandboxSpec` in 003. This
document specifies the `Signature`, how the session uses the existing records, the
variant-instance mappings (which reuse the DISCOVER/SARIF path), and the
OSV-validity guarantee.

## The variant `Signature` (runtime type, not a Record)

`deepthought.sibling.signature.Signature` is a Pydantic model with
`extra='forbid'`. It is **not** a `Record`: it is never serialized to the Store,
never validated from front-matter, and holds no `body`. It is a typed value passed
from the session to the worker, describing the bug class to hunt for.

| Field | Type | Meaning |
| --- | --- | --- |
| `source_finding` | `str` | The `id` of the *verified* finding this signature was derived from (e.g. `F-0007`). Provenance only; not a match term. |
| `source_project` | `str` | The project id the source finding belongs to. Provenance only. |
| `capability` | `str` | The bug class's capability — the source `Primitive.kind`. **Must be a member of `CAPABILITY_TAXONOMY`.** This is the spine of the signature: a variant is an instance that grants the same capability. |
| `locus_pattern` | `str` \| `None` | The normalized location/pattern shape of the source (e.g. the file/module stem or the sink token), length-bounded. A hint for the hunt, never a filesystem path executed or opened. |
| `match_terms` | `list[str]` | The **closed-lookup keys** the hunt matches on — the same ruleId/tag/CWE vocabulary `ingest.sarif` maps to `capability`. Bounded in count and length. An empty list is legal (capability alone still hunts). |

Constraints (all enforced by the model or its constructor):

- `capability` **must** be in `CAPABILITY_TAXONOMY`; a signature naming a
  capability the taxonomy does not define fails construction. The signature can
  never introduce a capability, only reuse one — the same invariant the
  `ingest.sarif` heuristic table carries.
- Every string field is length-bounded (reusing the envelope's `Short`/`Locus`
  bounds or equivalent) so an over-long derived value cannot smuggle a large
  payload downstream.
- `match_terms` is bounded in length (count) and each term is bounded and drawn
  from the closed heuristic vocabulary; a term that is not a known lookup key is
  dropped at derivation. An injected term can, at worst, be dropped — it can never
  become an instruction.

## Derivation: `signature_from_finding(finding, primitives) -> Signature`

The signature is **derived from typed fields only** — this is the input-side
injection boundary (Article VIII):

- `capability` comes from the source finding's `Primitive.kind` (the primitive(s)
  bound to the finding via `finding_ref`, read from the ledger or the passed list).
  When several primitives are present, the derivation picks the primitive whose
  `finding_ref` equals the source finding id; ties resolve deterministically (first
  in taxonomy order). If no primitive is bound, the derivation MAY fall back to the
  closed-lookup match of the finding's `summary`/`references` (the same
  `_match_capability` path DISCOVER uses) — still a closed lookup, never free-text.
  If that also yields nothing, **no signature is derived** and the hunt reports
  that it has no class to hunt (it never invents a capability).
- `locus_pattern` comes from the finding's location shape — the `**Location:**`
  reference or `references[]` url stem — normalized and length-bounded. It is a
  match hint only; it is never resolved, opened, or executed.
- `match_terms` are the closed-lookup keys that map to `capability` (e.g. for
  `inject:sql`: the CWE-89/`sql`/`sqli` needles), plus any ruleId/tag terms present
  on the source finding that are themselves known lookup keys. Unknown terms are
  dropped.

The finding's free-text `body` is **never** parsed for instructions. The
derivation reads only the typed `capability`, the typed location reference, and
closed-lookup terms. A source finding whose body carries an injected instruction
changes nothing: the body is not an input to derivation.

## Records used, and how

### Finding (status `candidate`) — the variants

Each sibling instance a worker finds becomes one candidate `Finding` — a *variant*.
It reuses `deepthought.schema.finding.Finding` exactly. Constraints specific to
this feature:

- `status` is always `FindingStatus.candidate`. SIBLING HUNT never sets a higher
  status: promotion requires a resolving `evidence_ref`, which only a sandboxed
  VERIFY produces (Article IV). SIBLING HUNT writes no `evidence_ref`.
- `id` is assigned past the current store max (the same `_next_finding_index`
  discipline DISCOVER uses), so a variant never collides with, overwrites, or
  orphans an existing finding — including the source finding and variants from a
  prior hunt. Ids are rendered `F-0001`, `F-0002`, ….
- `project` is the **target** project the variant was found in — the source project
  for same-project variants, or the *sibling* project for cross-project variants.
  A variant is always bound to the project whose gate authorized its hunt.
- `summary` and body narrative are derived from the sibling instance's SARIF/static
  signal (its `message.text`/location), truncated to bounds. Data only. The
  narrative may reference the source finding as the sibling-of provenance (data,
  e.g. "sibling of F-0007"), never an instruction.
- `references` may include the instance's location rendered as a reference; the
  type is free-form and normalised to the OSV enum on export.
- `severity` is left `None` unless a defensible band exists (same conservative rule
  as DISCOVER). A `None` severity is OSV-valid.

Every field populated from an untrusted signal (SARIF text, the source finding's
own SARIF-derived fields) is treated as data: copied into a data field, never
interpreted as instruction, and length-bounded before it reaches the length-capped
envelope/finding surface.

### Coverage (`method='read'`)

SIBLING HUNT writes coverage through `deepthought.schema.coverage.Coverage`,
unchanged:

- `method` is `CoverageMethod.read` for every coverage record this feature writes.
  The hunt reasoned over the areas by reading static signals and SARIF — nothing
  executed — so `read` is the honest method (not `static`, reserved for tooling
  passes; never `fuzz`, which needs the sandbox).
- `depth` is `CoverageDepth.touched` for a reasoned-over-but-not-exhausted area
  (same conservative default as DISCOVER).
- `area` is an in-scope path/module from the **target** project's `scope_allowlist`
  — the source project's areas for the source hunt, the sibling's own areas for a
  sibling hunt. A coverage record is never written for a path outside the target's
  allowlist.
- `last_session` is the session id that produced the record.

Coverage is written per target, from each target's *validated envelope's*
`coverage_delta`, re-validated against that target's own contained scope — the same
firewall re-validation DISCOVER performs, so a worker cannot record coverage for an
out-of-scope area or with a non-`read` method through the coverage channel.

### Session

`SiblingHuntSession` subclasses `BaseSession` and runs through the unchanged
`run_session` harness. It sets `.type` to `SessionType.sibling_hunt` (already in
the 001 `SessionType` enum — no schema change). It returns a `SessionOutcome` with
a summary, explicit next steps, and the variant findings + coverage it touched, so
the harness can close the session. A session with no `## Next steps` does not close.

The session's own `project` is the *source* project (the gate the harness
evaluates). Sibling-project gate outcomes are recorded in the session summary/next
steps and (for a proceed) reflected in the findings/coverage touched.

### Envelope and Primitive (unchanged contract)

Each worker returns exactly one `Envelope`, ingested through the existing
`Conductor`. Suspected sibling primitives ride in the envelope's `primitives[]` and
land in the bounded `Ledger` on ingest, exactly as in DISCOVER. No field is added
to either contract. Sibling primitives carry `confidence: suspected` (nothing was
demonstrated, so no `evidence_ref` is required by the `Primitive` validator). Each
sibling primitive's `finding_ref` binds it to the variant finding it describes.

## Variant-instance → Finding and → Primitive mappings

SIBLING HUNT reuses the DISCOVER/SARIF mapping path. A worker gathers candidate
sibling instances the same way DISCOVER does — from an optional SARIF (via
`sarif_to_findings`/`sarif_to_primitives` with the target's `scope`/`root`
containment) and/or from static reasoning over the signature's `match_terms`. The
result is:

- **Variant `Finding`s** — one per accepted sibling instance, status `candidate`,
  ids assigned past the store max, OSV-valid by construction, `project` = the
  target project. The mapping is the SARIF-result → Finding map from the DISCOVER
  data-model, filtered so an instance whose capability does not match the
  signature's `capability` is dropped (a variant must be the *same bug class*).
- **Suspected `Primitive`s** — zero or one per accepted instance, `confidence:
  suspected`, `finding_ref` bound to the variant's id, `kind`/`grants` from the
  closed lookup — and only kept when the `kind` equals the signature's
  `capability`. An instance mapping to a different capability is not a sibling of
  this class and is dropped.

The **same-class filter** is what makes this variant analysis rather than a second
DISCOVER: an instance is a sibling only if its derived capability equals the
signature's `capability`. Out-of-scope instances are dropped by the reused
`scope`/`root` containment *before* the class filter, so nothing out of scope is
ever considered.

## OSV-validity guarantee

Every variant `Finding` generated by SIBLING HUNT must pass `check`. This is
inherited directly from the DISCOVER/SARIF construction, which the hunt reuses:

- `finding_to_osv(finding)` followed by `validate_osv(...)` returns no errors for
  every generated variant (the same path `check._check_osv` runs).
- Variants are constructed only from fields guaranteed OSV-valid: a candidate needs
  only `id` + a `modified` timestamp on export; `summary`, `references`, and
  `severity` are added only in OSV-valid forms.
- A candidate at status `candidate` has no lifecycle-at-rest obligation in `check`,
  so SIBLING HUNT output is lifecycle-clean by construction.
- **If a sibling instance cannot be turned into an OSV-valid finding, it is not
  written.** The hunt never emits a finding that would fail `check`.

## Authority-widening: what SIBLING HUNT never does

The data-model's hardest guarantee is negative — the records SIBLING HUNT never
writes:

- It **never writes a `Project`.** It reads projects via `get_project`; it never
  calls `save_project`. A named sibling that is not already registered is skipped
  and logged — never created.
- It **never mutates a `scope_allowlist`** or sets an `authorization_basis`. The
  scope and basis of every target are exactly what `NEW PROJECT` recorded.
- It **never writes a finding or coverage for a target that did not proceed at its
  own gate.** A refused/held sibling produces no records at all.

## Notes

- All writes go through the `Store`. The session reads or writes no `state/` path
  directly. It walks a target's working tree (read-only, in-scope areas only) to
  reason for variants; that traversal reads the *target's* files, not the *state
  store*, and writes findings/coverage back only through the Store.
- No record type, no Store method, and no schema field is added in this feature.
  The capability taxonomy is reused unchanged.
- Nothing here executes target code. SIBLING HUNT reads and reasons; the sandbox
  (003) is what gates anything that runs code, and it is untouched.
