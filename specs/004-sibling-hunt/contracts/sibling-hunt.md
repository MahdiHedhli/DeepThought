# Contract: Sibling Hunt (verified finding → variant signature → sibling candidates)

SIBLING HUNT is read-only variant analysis. It takes a **verified** finding — a
confirmed bug class — derives a **variant signature** from it, and hunts for
**sibling instances** of the same class across the finding's own in-scope areas
and across *pre-registered, independently-authorized* sibling projects. Each
sibling instance becomes a new candidate `Finding` (a variant). It executes
nothing, transmits nothing, and — the property this contract most exists to
guarantee — **it never creates a project, widens a scope, or hunts a target that
lacks its own authorization basis.**

Four properties make this session safe:

1. **The signature is derived from typed fields, never authored.** The bug class is
   described by the source finding's `Primitive.kind` (a `CAPABILITY_TAXONOMY`
   member), its location shape, and closed-lookup `match_terms` — not by any
   free-text. A hostile source finding can, at worst, fail to yield a signature.
2. **Every target is gated independently, and the target set never grows.** The
   source project and each *named* sibling project are gated through the same
   three-outcome `DefaultGate` on a `GateContext.from_project`. A sibling must
   already exist in the Store with its own basis; only a `proceed` target is hunted.
3. **Scope containment is reused unchanged.** Sibling instances outside a target's
   `scope_allowlist` (or escaping its root via traversal/symlink) are dropped by
   `deepthought.scope` / the `ingest.sarif` `scope`/`root` filter before any finding
   is created — exactly as in DISCOVER.
4. **The worker envelope is the firewall.** The orchestrator ingests only the
   schema-validated, length-capped `Envelope` through the `Conductor`; hints are
   inert; `detail_ref` content is never loaded; the coverage delta is re-validated
   against the orchestrator's own authorization.

## Module and public signatures

`src/deepthought/sibling/signature.py`:

```python
class Signature(BaseModel):
    """The variant signature: a typed description of a confirmed bug class.

    A runtime value (extra='forbid'), NOT a persisted Record. Derived from a
    verified Finding and its bound Primitive(s); the finding's free-text body is
    never read. ``capability`` must be a CAPABILITY_TAXONOMY member."""
    source_finding: str
    source_project: str
    capability: str          # == source Primitive.kind; a CAPABILITY_TAXONOMY member
    locus_pattern: str | None = None
    match_terms: list[str] = []

def signature_from_finding(
    finding: Finding, primitives: list[Primitive]
) -> Signature | None:
    """Derive a variant Signature from a VERIFIED finding and its primitives.

    Reads typed fields only: the bound Primitive.kind (via finding_ref), the
    finding's location reference, and closed-lookup terms. Returns None when no
    capability can be derived (the hunt then has no class to hunt); never invents
    a capability and never parses the finding body as instruction."""
```

`src/deepthought/sessions/sibling_hunt.py`:

```python
class SiblingHuntSession(BaseSession):
    type = SessionType.sibling_hunt

    def __init__(
        self,
        project_id: str,
        finding_id: str,
        sibling_project_ids: list[str] | None = None,
        sarif_path: str | None = None,
        root: str | None = None,
    ): ...

    def build_gate_context(self, store) -> GateContext: ...  # from the SOURCE project
    def run(self, store, session_id) -> SessionOutcome: ...

    # Exposed after run() for inspection:
    #   self.signature: Signature | None
    #   self.conductor: Conductor | None   # holds the sibling primitives
    #   self.envelopes: list[Envelope]     # the validated envelopes ingested
```

## Session flow

```
1. LOAD the source finding (store.get_finding). REFUSE if:
     - it does not exist, or
     - it belongs to a different project than project_id, or
     - its status is not `verified` (there is no confirmed class to hunt).
   A refusal closes the session clean with a next step; no worker runs.

2. DERIVE the signature: signature_from_finding(finding, primitives-for-finding).
     - primitives are the ones bound to the finding (finding_ref == finding.id),
       read from the ledger the source DISCOVER produced, or re-derived by the
       closed lookup over the finding's typed fields.
     - If no capability can be derived, close clean: "no huntable class"; no worker.

3. BUILD the target list (fixed here; never grows later):
     - the SOURCE project (always), then
     - each NAMED sibling project id, loaded via store.get_project.
       A sibling id that does not resolve to a stored project is SKIPPED and logged
       (never created).

4. For EACH target, GATE it independently:
     GateContext.from_project(target, SessionType.sibling_hunt) -> DefaultGate
       - refuse (no basis / blackbox w/o ref / scoped w/o ref): log, NO worker,
         NO finding, NO coverage for this target.
       - hold (empty scope allowlist): log, NO worker, NO finding, NO coverage.
       - proceed: dispatch ONE worker for this target.

5. For each PROCEED target, DISPATCH one stub Marvin worker:
     - it reasons over the signature + the target's in-scope areas (+ any SARIF),
       gathers sibling instances of signature.capability, drops out-of-scope
       instances (scope/root containment) and instances of a DIFFERENT capability
       (the same-class filter), writes the surviving instances as candidate variant
       Findings (project = this target, ids past the store max), pages detail, and
       returns exactly one Envelope (primitives + findings_written + coverage_delta).

6. INGEST each envelope through the Conductor (the firewall). Read teach-back
   fields ONLY from the validated envelope. Primitives land in the shared ledger.

7. TEACH BACK: write Coverage(method='read') per target from each validated
   envelope's coverage_delta, RE-VALIDATED against that target's own contained
   scope; return the variant findings + coverage touched + explicit next steps.
```

## Same-project vs sibling-project gating

The rule is identical in mechanism and differs only in which project is evaluated:

| | Source project | Sibling project |
| --- | --- | --- |
| Must pre-exist in Store | yes (the source finding names it) | **yes — a sibling is only ever loaded, never created** |
| Gate evaluated | `GateContext.from_project(source)` | `GateContext.from_project(sibling)` — **independently** |
| No `authorization_basis` | refuse (source hunt does not run) | refuse (sibling not hunted; no records) |
| Empty `scope_allowlist` | hold (nothing in scope) | hold (sibling not hunted; no records) |
| Proceed | hunt over the source's in-scope areas | hunt over the **sibling's own** in-scope areas |
| Variant `Finding.project` | the source project id | the **sibling** project id |
| Coverage `area` | the source's allowlist areas (contained) | the **sibling's** allowlist areas (contained) |

Hard invariants (asserted by tests):

- SIBLING HUNT **never** calls `store.save_project`, never mutates a
  `scope_allowlist`, and never sets an `authorization_basis`. A grep of the session
  for those mutations must find none.
- A sibling project lacking a basis is **refused**, a sibling with empty scope is
  **held**, and in both cases **no `Finding` and no `Coverage` is written for that
  sibling**.
- The huntable target set is exactly `{source} ∪ {named siblings that resolve and
  proceed}`. There is no code path that adds a target the operator did not name, and
  none that registers or widens one.

## The signature: derived from typed fields only

The signature derivation is the input-side injection firewall:

- `capability` = the source finding's `Primitive.kind`. When no primitive is bound,
  the closed-lookup match of the finding's typed `summary`/`references` may supply
  it (the same `_match_capability` closed table `ingest.sarif` uses). Never a
  free-text read.
- `locus_pattern` = the normalized stem of the finding's location reference — a
  match hint, never a path opened or executed.
- `match_terms` = the closed-lookup keys that map to `capability`, plus any
  ruleId/tag terms on the source finding that are themselves known lookup keys.
  Unknown terms are dropped.

Because every input is a typed field or a closed-lookup key, an injected
instruction in the source finding's body — or in the SARIF that produced it —
never becomes a hunt instruction. At worst it is ignored; the derivation can fail
(returning `None`), which stops the hunt safely, but it can never widen the hunt or
mint a capability.

## Flow to the Store and the Ledger

```
signature_from_finding(finding, primitives) ──▶ Signature (typed; capability ∈ TAXONOMY)
        │
        ▼   for each PROCEED target:
   worker reasons over signature + target in-scope areas (+ SARIF)
        │        (scope/root containment drops out-of-scope; class filter drops other capabilities)
        ▼
   [Finding(candidate, project=target), ...]  ── Store.save_finding()  (OSV-valid by construction)
   [Primitive(suspected, finding_ref=variant), ...]
        │
        ▼   carried in the Marvin Envelope.primitives[]
   Conductor.ingest(envelope) ──▶ Ledger holds the sibling primitives
                                  (hints inert; detail_ref never loaded)
        │
        ▼
   Coverage(method='read', target areas)  ── Store.save_coverage()  (re-validated vs target scope)
```

- **Variant findings** flow to the Store through `save_finding` (candidate status,
  no lifecycle obligation, OSV-valid), bound to the target project. Worker detail
  pages to `state/detail/<session>/…` via `write_detail`, never into the
  orchestrator.
- **Sibling primitives** flow to the Ledger only through the envelope-ingest
  boundary — the same firewall DISCOVER uses. They are never inserted by a side
  channel; the `Conductor` is the one door.
- **Coverage** flows to the Store per target, re-validated against that target's own
  contained scope, so a worker cannot record coverage for a path outside the
  target's authorized scope.
- **Nothing is transmitted.** The session reads local files and stored records;
  there is no network path in this contract.

## What this contract does NOT do

- It does not execute the target, run a repro, or invoke any tool. It reasons over
  results and code that already exist. Promotion of a variant to `verified` is a
  sandboxed VERIFY (003) concern, unchanged; the sandbox hard stop is untouched.
- It does not create, register, or widen any project, scope allowlist, or
  authorization basis. A sibling that is not already authorized is simply not
  hunted.
- It does not promote any finding past `candidate`. Variants enter at `candidate`
  and wait for their own VERIFY.
- It does not read any SARIF field outside the DISCOVER-documented subset, and it
  never interprets a SARIF string, a source-finding body, or a worker's free-text as
  an instruction.
