# Feature Spec: Platform Spine and Agent Session Protocol (001)

**Feature Branch:** `001-core-loop`
**Created:** 2026-06-30
**Status:** Implemented

## Problem

An infographic describes a launcher for typed agent sessions that run on Claude
Code. That launcher is not yet a governed system: there is no durable state, no
enforced authorization, no typed contract between the orchestrator and its
workers, and no validation gate. Without those, an autonomous research loop is
unsafe to build. This feature is the spine that makes the dangerous capabilities
of later features safe to add.

## Goal

Build the governed spine: durable file-based state behind a Store interface, a
typed Agent Session Protocol, an orchestrator-plus-workers execution model, and
the three operator verbs. Prove it end to end with the two lowest-risk session
types — `NEW PROJECT` and `STATUS`. No code execution, no discovery, no
disclosure transmission.

## Scope

**In scope**

- Canonical schema (Pydantic v2) for Project, Finding, Session, Coverage,
  Methodology, and the worker Envelope/Primitive, with Markdown + YAML
  front-matter serialization.
- The Store interface and a files-in-git implementation, including the finding
  lifecycle guard at the Store boundary.
- The pre-dispatch Gate (three outcomes) and a HermesUltraCode adapter stub.
- The Agent Session Protocol harness: load → gate → work → teach back →
  validate → close.
- The orchestrator boundary: envelope ingest (the injection firewall) and the
  primitive ledger + exploit graph.
- `check` (schema, lifecycle, orphans, identity, OSV conformance) and the OSV
  export it validates against.
- The three verbs in a CLI: `playbook`, `check`, `publish`.
- The two session types: `NEW PROJECT` and `STATUS`.

**Out of scope** (later features, behind their own gates)

- Code execution and the sandbox (003).
- `DISCOVER` and `MAP` (002).
- `VERIFY`, `SIBLING HUNT`, `DISCLOSURE` (003–005).
- The autonomous loop and limit awareness (006).
- CSAF/OpenVEX export and SARIF ingest.

## User scenarios

1. **Register a target.** An operator runs a `NEW PROJECT` session with a git
   URL, an authorization basis, and a scope allowlist. State shows a new Project.
   A repeat registration resolves to the same project, never a duplicate. A
   missing basis, a blackbox target without a reference, or an unresolvable URL
   is refused with a recorded reason.
2. **Review state.** An operator runs a `STATUS` session. A session log appears
   with a summary and explicit next steps. No finding status changes.
3. **Guarded lifecycle.** An attempt to move a finding to `disclosed` without a
   CVE is rejected at the Store boundary, and the blocking reason is recorded on
   the finding.
4. **Validate.** `check` passes on consistent state and fails on a hand-corrupted
   record, an illegal lifecycle state, an orphan reference, a duplicate identity,
   or a non-conformant OSV. A `check` that raises is a failed check.
5. **Publish.** `publish` prepares local OSV artifacts and asserts the human
   gate. Nothing is transmitted.

## Functional requirements

- **FR-1** Every session passes the Gate before work; outcomes and reasons are
  logged. (Constitution I)
- **FR-2** Projects carry an authorization basis and scope; the Gate refuses
  sessions that violate Article II.
- **FR-3** The finding lifecycle guard is enforced at the Store boundary with the
  transitions and evidence requirements of the data model. (Constitution IV)
- **FR-4** Every session writes findings touched, coverage changed, and a log
  with next steps; a session with no next steps does not close. (Constitution VI)
- **FR-5** The orchestrator ingests only a schema-validated, length-capped
  envelope; it never reads worker free-text, a hint never acts on its own, and
  `detail_ref` content is never loaded. (Constitution VIII)
- **FR-6** `check` validates schema, lifecycle, orphans, identity, and OSV
  conformance and is a required gate before `publish`. (Constitution VII)
- **FR-7** `publish` emits local artifacts only and asserts a human gate; it
  never transmits. (Constitution V)

## Open questions

Four blockers were resolved 2026-06-30 (state model, schema standards, topology,
runtime — see `plan.md`). Two feature-005 questions remain and are non-blocking
for 001: the Threatpedia/Store repository boundary, and the disclosure export
formats' exact templates.

## Success criteria

The five-step 001 smoke in `plan.md` passes: durable state, the protocol, the
gate, the lifecycle guard, and the envelope boundary, with nothing dangerous
wired yet. `check` is green on consistent state and red on a corrupted record.
Every record reads and diffs as clean text in git.
