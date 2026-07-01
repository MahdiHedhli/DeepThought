# Contract: Worker Envelope (Marvin to Deep Thought core)

A worker, a Marvin, runs one narrow task in isolated context. It returns exactly
one envelope. The orchestrator reads the envelope and nothing else from the
worker. This is the single channel between the two planes.

Two reasons this boundary exists:
1. Context economy. The orchestrator keeps a small working set so it can hold the
   exploit chain in mind. Worker detail pages to the Store, not the orchestrator.
2. Injection resistance. A worker that gets prompt-injected by hostile target
   content can only return this typed, schema-validated structure. There is no
   free-text field the orchestrator interprets as instruction. The schema is the
   firewall.

## Envelope schema

- `envelope_version` string.
- `session_ref` string, the session that dispatched the worker.
- `worker_id` string.
- `task_ref` string, the task the worker was given.
- `outcome` enum: `resolved`, `partial`, `empty`, `blocked`, `error`.
- `primitives` list of Primitive. May be empty.
- `findings_written` list of finding ids the worker created or updated in the Store.
- `coverage_delta` list: each `{ area, method, depth }`.
- `next_step_hints` list of strings, compact. Suggestions the orchestrator may act on.
- `context_cost` object: `{ tokens, wall_seconds }`.
- `detail_ref` string, pointer to full worker output under `state/detail/`. The orchestrator does not load it.
- `gate_attestation` object: `{ scope_ok bool, authorization_ref string }`. The worker asserts it stayed in scope.

Rules:
- The orchestrator rejects any envelope that fails schema validation. A rejected envelope is treated as `outcome: error`, logged, and does not update the ledger.
- Every string field has a length cap. Oversized fields fail validation. This prevents a worker from smuggling a large free-text payload through a structured field.
- `next_step_hints` are hints, not commands. The orchestrator decides. A hint cannot dispatch a worker or change state on its own.
- The orchestrator never reads `detail_ref` content into its own context. It may dispatch a fresh worker to read it.

## Primitive

A primitive is a capability a finding grants. Primitives are the nodes the
orchestrator composes into chains.

- `kind` string from the capability taxonomy below.
- `target_locus` string: `file:line`, an endpoint, a parameter, or a component.
- `preconditions` list of strings. What must hold for the primitive to fire.
- `grants` list of strings from the taxonomy. What the primitive yields.
- `confidence` enum: `suspected`, `demonstrated`, `verified`.
- `evidence_ref` string, pointer to the repro in the Store. Required when confidence is `demonstrated` or `verified`.
- `finding_ref` string, the finding this primitive belongs to.

## Capability taxonomy, starter set

Extensible. Features 002 and 003 will add as real primitives appear. The shape
is fixed in 001; the vocabulary grows.

- `read:arbitrary-file`
- `read:memory`
- `write:arbitrary-file`
- `write:logfile`
- `exec:command`
- `exec:code`
- `leak:info`
- `leak:secret`
- `control:flow`
- `auth:bypass`
- `escalate:privilege`
- `ssrf:request`
- `inject:sql`
- `inject:template`
- `deserialize:untrusted`

A chain is a path through primitives where one primitive's `grants` satisfy
another's `preconditions`. Example, drawn from real work: `write:logfile` plus
`exec:code` via log inclusion composes to `exec:command`. The orchestrator holds
that graph. Workers supply the nodes.

## Ingest rule, in one line

The orchestrator consumes the envelope, validates it, updates the primitive
ledger and exploit graph, and pages detail to the Store. It never reads worker
free-text, and a hint never acts on its own.

## Example envelope

```yaml
envelope_version: "1.0"
session_ref: "S-2026-06-30-0007"
worker_id: "marvin-04"
task_ref: "analyze module streambucket for memory-safety primitives"
outcome: "partial"
primitives:
  - kind: "write:arbitrary-file"
    target_locus: "ext/soap/php_streams.c:412"
    preconditions: ["attacker controls stream filter chain"]
    grants: ["write:arbitrary-file"]
    confidence: "demonstrated"
    evidence_ref: "detail/S-2026-06-30-0007/repro-01.txt"
    finding_ref: "F-0019"
findings_written: ["F-0019"]
coverage_delta:
  - { area: "ext/soap", method: "static", depth: "explored" }
next_step_hints:
  - "F-0019 write primitive may compose with F-0014 include path to reach exec:code"
context_cost: { tokens: 38120, wall_seconds: 41 }
detail_ref: "detail/S-2026-06-30-0007/"
gate_attestation: { scope_ok: true, authorization_ref: "permissive_oss" }
```

The orchestrator reads this, records one `write:arbitrary-file` node against
F-0019, notes the suggested composition with F-0014, and decides whether to
dispatch a Marvin to test the chain. The worker's reasoning, its full transcript,
and any content it pulled from the target stay in the Store, out of the
orchestrator's context.
