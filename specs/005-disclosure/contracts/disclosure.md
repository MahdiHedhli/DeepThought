# Contract: Disclosure (verified finding → draft advisory/CVE/CSAF/OpenVEX)

Draft-only. Every signature below produces or persists a **local** artifact.
None transmits; none advances lifecycle; none fabricates a CVE or advisory
reference.

## Module and public signatures

### `src/deepthought/export/advisory.py`
```python
def finding_to_advisory(finding: Finding) -> str: ...
```
Returns a human-readable Markdown advisory. No validator (prose, not a schema
type).

### `src/deepthought/export/csaf.py`
```python
CSAF_VERSION = "2.0"
def finding_to_csaf(finding: Finding) -> dict: ...
def validate_csaf(doc: dict) -> list[str]: ...   # [] == conformant
```
`validate_csaf` mirrors `validate_osv`: bundle `csaf_schema.json` via
`importlib.resources` behind an `@lru_cache`, drive it with `jsonschema`, and
return sorted `"path: message"` strings.

### `src/deepthought/export/openvex.py`
```python
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
def finding_to_openvex(finding: Finding) -> dict: ...
def validate_openvex(doc: dict) -> list[str]: ...   # [] == conformant
```
`validate_openvex` is **programmatic** (no bundled schema): it checks the
required document fields (`@context`, `@id`, `author`, `timestamp`, `version`),
each statement's required fields (`vulnerability.name`, `products[]`, `status`
∈ {`not_affected`, `affected`, `fixed`, `under_investigation`}), and the
status-conditional rule (`affected` ⇒ `action_statement` present). Returns the
same `list[str]` contract.

### `src/deepthought/export/cve.py`
```python
CVE_SCHEMA_DATAVERSION = "5.1"
def finding_to_cve_draft(finding: Finding) -> dict: ...
def validate_cve_draft(doc: dict) -> list[str]: ...   # structural; tolerates the sentinel cveId
```
`validate_cve_draft` checks the CNA container's structural completeness
(`providerMetadata`, ≥1 `descriptions`, ≥1 `affected`, ≥1 `references`) while
tolerating the placeholder `cveId`/org ids. It is **not** wired into `check`.

### `src/deepthought/export/__init__.py`
Re-export the four `finding_to_*` builders, the three `validate_*` functions, and
the constants alongside the existing OSV exports.

### `src/deepthought/sessions/disclosure.py`
```python
class DisclosureSession(BaseSession):
    type = SessionType.disclosure           # already in the enum (schema/session.py)

    def __init__(self, project_id: str, finding_id: str) -> None: ...
    def build_gate_context(self, store: Store) -> GateContext: ...   # from_project(project, self.type)
    def run(self, store: Store, session_id: str) -> SessionOutcome: ...
```

### `src/deepthought/check.py`
```python
def _check_csaf(findings, report) -> None: ...      # copy of _check_osv, using finding_to_csaf/validate_csaf
def _check_openvex(findings, report) -> None: ...   # copy of _check_osv, using finding_to_openvex/validate_openvex
```
Both are registered inside `run_check`; its existing try/except means a raising
exporter is a failed check, not a crash. The CVE draft is not checked.

### `src/deepthought/cli.py`
```python
@playbook_app.command("disclose")   # the `playbook` sub-group, mirroring `verify`
def playbook_disclose(project: str, finding: str, state: Path = _STATE_OPTION) -> None: ...

@app.command("publish")
def publish(
    out: Path = typer.Option("out", "--out", ...), state: Path = _STATE_OPTION,
    format: str = typer.Option("osv", "--format"),   # osv|csaf|openvex|cve-draft|advisory|all
) -> None: ...
```
`playbook disclose` runs `run_session(_store(state), HermesUltraCodeGate(),
DisclosureSession(project, finding))`. `publish` dispatches on `format`, writes
into `out/<fmt>/`, filters disclosure formats to `verified`/`disclosed`/`patched`,
stays hard-gated on a green `check`, and prints the HUMAN GATE banner. No
transmit path is added.

## Session flow

1. **Gate.** `build_gate_context` → `GateContext.from_project(project,
   disclosure)`. `run_session` gates before `run`; a hold/refuse logs a session
   with a reason and remediation next steps.
2. **Load.** `store.get_finding(finding_id)`; raise `NotFoundError` if `None`
   (harness records the session `interrupted`).
3. **Refuse (non-raising) if not disclosable.** `finding.project != project_id`
   → refusal outcome; `finding.status is not FindingStatus.verified` → refusal
   outcome naming the actual status. Nothing is drafted.
4. **Draft.** Build the four artifacts from typed fields:
   `finding_to_advisory`, `finding_to_csaf`, `finding_to_openvex`,
   `finding_to_cve_draft`.
5. **Persist.** `store.write_detail(session_id, name, content)` for each
   (`disclosure-advisory.md`, `disclosure-csaf.json`, `disclosure-openvex.json`,
   `disclosure-cve-draft.json`; JSON `indent=2, sort_keys=True`).
6. **Teach back.** Summary names the four refs and states "nothing transmitted;
   no CVE assigned; status unchanged (still verified)". Next steps (always
   non-empty) name the human gate. `findings_touched=[finding.id]`,
   `coverage_changed=[]`.

No step mutates the finding or touches the network.

## The draft-only boundary (named hard stops)

The session and exporters MUST NOT:

- **Transmit / send / submit / publish externally.** No network client is
  imported or invoked. Enforced by omission and by `test_transmits_nothing`.
- **Advance lifecycle.** Never call the Store's `verified → disclosed`
  transition (or any transition). Guarded by `test_does_not_transition_to_disclosed`.
- **Fabricate authority.** Never set `finding.cve`; never add an `advisory`
  reference. Guarded by `test_does_not_set_cve_or_advisory_ref`.
- **Finalize a draft.** CSAF `tracking.status` stays `draft`; the CVE cveId is
  the failing sentinel; the OpenVEX `@id` stays in the draft namespace.

Crossing any of these is a hard stop requiring Mahdi's sign-off (URGENT NTFY +
wait), not an autonomous step.

## `check` and `publish` integration

- `check` validates OSV (existing) plus CSAF and OpenVEX drafts for every
  finding; any `validate_*` error fails the check. A green `check` is still
  required before `publish` (Constitution Article VII).
- `publish` emits the selected format(s) as local artifacts under the HUMAN GATE
  banner; it never transmits. `--format all` writes every format into its own
  `out/<fmt>/` subdirectory.

## What this contract does NOT do

- It does not request, reserve, or assign a CVE.
- It does not contact a CNA, vendor, PSIRT, feed, or any network endpoint.
- It does not move a finding to `disclosed` or `patched`.
- It does not write anything outside the Store or the operator's `--out` dir.
- It does not read the finding body as instruction — only as prose for the
  advisory/notes, via the existing typed scraper.
