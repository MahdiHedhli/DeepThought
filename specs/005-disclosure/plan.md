# Implementation Plan: Disclosure — draft-only advisory & VEX

> Draft-only. The plan below adds drafting and local emission; it adds no way to
> transmit and no way to advance a finding to `disclosed`. Those are human acts.

## Summary

Feature 005 turns a `verified` finding into four local draft artifacts (advisory
Markdown, CVE JSON 5.1 draft, CSAF 2.0, OpenVEX) and stops. It reuses the
existing OSV-exporter shape, the session harness, the `check` gate, and the
`publish` scaffold with its HUMAN GATE banner. The only new *behavioural* surface
is a `DisclosureSession`, four exporters, two new `check` validators, a
`playbook disclose` verb, and a `--format` selector on `publish`. Every write is
a local artifact; there is no network code anywhere in the feature.

## Decisions

1. **Persistence split.** The session writes durable, auditable drafts through
   `Store.write_detail` (they live in state, diff as text, and are re-checkable);
   `publish` emits an ephemeral bundle to `--out/<fmt>/`. Rationale: the session
   is the audit record of what was drafted; `publish` is the operator's
   fill-in-the-blanks handoff bundle.
2. **OpenVEX validation is programmatic.** OSV, CSAF, and the CVE Record format
   have authoritative JSON Schemas we can bundle and drive with `jsonschema`.
   OpenVEX's spec is prose-normative without an equally-canonical machine schema,
   so `validate_openvex` implements explicit required-field / enum /
   status-conditional checks. Rationale: mirror `validate_osv`'s contract
   (`list[str]` of errors) without pinning to an unstable third-party schema.
3. **CVSS band derived, or omitted.** `Severity` carries a vector and a float
   score but no `baseSeverity` word; derive the band from the score by the CVSS
   3.1 thresholds. When `severity is None`, omit the whole metrics/scores block —
   never fabricate a score. Rationale: standards-correct without inventing data.
4. **CWE omitted when absent.** The `Finding` model has no CWE field; when none
   is derivable, omit CVE `problemTypes` rather than guess. Rationale: a wrong
   CWE is worse than an absent one; a human adds it later.
5. **`publish` status filter.** Disclosure formats are emitted only for
   `verified`/`disclosed`/`patched` findings; OSV keeps its current unfiltered
   behaviour. Rationale: a `candidate` is not disclosure-ready.
6. **Detail-only, no finding mutation.** The session does not touch
   `finding.disclosure`. Rationale: the safest draft-only default — no
   agent-authored metadata persists on the durable finding.
7. **Placeholders, not fabrications.** Human/config-owned fields (CNA/publisher
   identity, CVE id) are obvious `PLACEHOLDER` strings, a zeroed UUID
   (`00000000-0000-4000-8000-000000000000`), and a sentinel cveId
   (`CVE-XXXX-XXXXX`) that intentionally fails `^CVE-[0-9]{4}-[0-9]{4,19}$`.
   Rationale: a draft must be recognisably a draft, and unsubmittable by
   construction.

## Technical Context

- **Language/runtime:** Python 3.12+ (running 3.14), Pydantic v2.
- **Existing deps reused:** `jsonschema` (already used by `validate_osv`),
  `importlib.resources` (schema bundling), Typer (CLI). No new dependency.
- **Standards targeted:** CSAF 2.0 (OASIS), OpenVEX v0.2.0 (OpenSSF), CVE Record
  Format 5.1 (CVE Program). Bundled schemas: `csaf_schema.json`, `cve_schema.json`
  (alongside the existing `osv_schema.json`).
- **Reuse anchors:** `export/osv.py` (`_osv_schema` `@lru_cache`, `validate_osv`,
  `osv_id_for`, `_section`/`_details`); `cli.py:368-395` (`publish` scaffold,
  check-hard-gate, HUMAN GATE banner); `check.py:144-148` (`_check_osv`);
  `protocol/session.py` (`BaseSession`, `run_session`, `SessionOutcome`);
  `sessions/verify.py` (closest session analogue).

## Constitution Check

- **Article I (Gate before work).** `DisclosureSession.build_gate_context`
  returns `GateContext.from_project(project, disclosure)`; `run_session` gates
  before `run`. A hold/refuse still logs a session with a reason. ✔
- **Article IV (Evidence & lifecycle).** The session reads a `verified` finding
  and never advances lifecycle. `verified → disclosed` (requires a CVE + advisory
  reference) stays exclusively at the Store boundary and is a human action. The
  draft artifacts do not, and cannot, satisfy that guard, because they never set
  a real `cve` or add an `advisory` reference. ✔
- **Article V (Coordinated disclosure).** This is the article the whole feature
  serves. Drafting is done by the agent; sending is done by a person. `publish`
  prepares local artifacts and asserts the human gate; it never transmits. 005
  adds no transmit affordance at all — there is nothing to send from and no flag
  to enable it. ✔
- **Article VI (Durable state).** Drafts are written only through the Store
  (`write_detail`); the session teaches back a summary and explicit next steps
  and so closes clean. ✔
- **Article VII (Validate-first).** Tests precede code. `check` remains the hard
  gate before `publish` and now also validates the CSAF and OpenVEX drafts; a
  raising exporter counts as a failed check, not a pass. ✔
- **Article VIII (Injection resistance).** Exporters read typed fields only;
  finding free-text is carried as inert string values, never as document
  structure or a `$ref`. An injection-inertness test guards each format. ✔

No article requires an exception; the Complexity Tracking section is empty.

## Architecture

### The draft flow

```
verified Finding
      │  (read-only, typed fields)
      ▼
finding_to_advisory  → Markdown str
finding_to_csaf      → dict  ─┐
finding_to_openvex   → dict   ├─ validate_<fmt> → [] on conformance
finding_to_cve_draft → dict  ─┘
      │
      ▼
DisclosureSession.run → Store.write_detail(session_id, "disclosure-*.{md,json}")
      │
      ▼
teach-back: 4 refs + "nothing transmitted; status unchanged (verified)"
            next steps: the human gate
```

Nothing in this flow mutates the finding or reaches the network.

### `check` and `publish` integration

- `check` gains `_check_csaf` and `_check_openvex`, each a copy of the
  `_check_osv` template: for every finding, `validate_<fmt>(finding_to_<fmt>(f))`,
  folding each error into `report.fail`. `run_check`'s try/except means a raising
  exporter degrades to a failed check. The CVE draft is **not** wired into
  `check` (its sentinel cveId is intentionally invalid), so a strict schema would
  otherwise (correctly) reject it.
- `publish` gains `--format osv|csaf|openvex|cve-draft|advisory|all` (default
  `osv`, back-compatible). It writes into `out/<fmt>/` subdirectories, filters
  disclosure formats to `verified`/`disclosed`/`patched`, stays hard-gated on a
  green `check`, and prints the same HUMAN GATE banner. No send path is added.

### The intentional CVE-draft invalidity

The CVE draft is deliberately non-submittable: its `cveId` is `CVE-XXXX-XXXXX`
(fails the official pattern) and its assigner/provider org ids are zeroed UUIDs.
`validate_cve_draft` checks the CNA container's structural completeness
(`providerMetadata`, ≥1 `descriptions`, ≥1 `affected`, ≥1 `references`) while
tolerating those placeholders, so the exporter's own tests can assert a
well-formed draft; a separate test asserts the sentinel fails the strict
official CVE id pattern.

## Project structure (delta from 001–004)

```
src/deepthought/export/
  advisory.py         # NEW  finding_to_advisory(finding) -> str
  csaf.py             # NEW  finding_to_csaf / validate_csaf / CSAF_VERSION
  openvex.py          # NEW  finding_to_openvex / validate_openvex / OPENVEX_CONTEXT
  cve.py              # NEW  finding_to_cve_draft / validate_cve_draft / CVE_SCHEMA_DATAVERSION
  csaf_schema.json    # NEW  bundled OASIS CSAF 2.0 schema
  cve_schema.json     # NEW  bundled CVE Record 5.1 schema
  __init__.py         # EDIT re-export the new builders/validators
src/deepthought/sessions/
  disclosure.py       # NEW  DisclosureSession(BaseSession)
  __init__.py         # EDIT export DisclosureSession
src/deepthought/
  cli.py              # EDIT `playbook disclose` + `publish --format`
  check.py            # EDIT `_check_csaf`, `_check_openvex`
scripts/smoke_005.sh  # NEW
tests/export/test_{advisory,csaf,openvex,cve}.py   # NEW
tests/sessions/test_disclosure.py                  # NEW
tests/test_check.py, tests/test_cli.py             # EDIT (wiring tests)
```

## Phase 0 — unknowns

Resolved by the feature-005 understand phase: the four external schema shapes and
their Finding→field mappings, the OpenVEX validation approach (programmatic), the
CVE draft non-submittability guarantee, and the seven design decisions above.

## Phase 1 — design outputs

- `data-model.md` — the four artifact shapes, the Finding→field mapping tables,
  and the lifecycle-untouched / non-submittability guarantees.
- `contracts/disclosure.md` — the exact public signatures, the session flow, the
  draft-only boundary, and the `check`/`publish` integration.
- `tasks.md` — the ordered, test-first task list.

## Complexity Tracking

None. No constitutional exception is required; no new dependency is introduced.

## Validation — the 005 smoke

`scripts/smoke_005.sh` runs the full flow on a fresh state: register a project
(basis + scope so the gate proceeds) → `discover` a candidate → `playbook verify`
(Noop sandbox) to `verified` → `playbook disclose` (asserts CLEAN close, four
detail refs, the no-transmit teach-back) → assert the finding is **still**
`verified` → `check` green → `publish --format all --out <dir>` (asserts every
`out/<fmt>/` populated, the HUMAN GATE banner, exit 0) → negative: `publish` on a
red `check` is refused. The run's output and touched files are grepped to assert
no CVE was assigned and no advisory reference added.
