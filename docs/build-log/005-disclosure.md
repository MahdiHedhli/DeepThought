# Build Session Log — Feature 005, Disclosure (draft-only advisory & VEX)

> **STATUS: built on branch `005-disclosure` (off `main`, features 001–004
> merged). DRAFT-ONLY build — DISCLOSURE transmits nothing.** From a *verified*
> finding it drafts four LOCAL artifacts (advisory Markdown, CVE JSON 5.1 draft,
> CSAF 2.0, OpenVEX) and stops. It never advances a finding to `disclosed`, never
> fabricates a CVE or advisory reference, and adds no network code.
> **428 tests green (380 baseline + 48 new); all five smokes (`smoke.sh`,
> `smoke_002.sh`, `smoke_003.sh`, `smoke_004.sh`, `smoke_005.sh`) pass.**

**Feature:** 005-disclosure
**Branch:** `005-disclosure`
**Predecessor gate:** 004 merged to `main` (PR #3, squash `93ce057`).

## What shipped

DISCLOSURE — the coordinated-disclosure *drafting* pipeline. It mirrors the
existing OSV exporter's shape and reuses the session harness, the `check` gate,
and the `publish` scaffold with its HUMAN GATE banner.

- **Four exporters** in `src/deepthought/export/`:
  - `advisory.py` — `finding_to_advisory(finding) -> str` (Markdown; no schema).
  - `csaf.py` — `finding_to_csaf` / `validate_csaf`, against the bundled OASIS
    CSAF 2.0 schema (draft 2020-12). CVSS refs are resolved to faithful **local**
    CVSS 3.x schemas via a `referencing.Registry`, so validation is hermetic (no
    network).
  - `openvex.py` — `finding_to_openvex` / `validate_openvex` (programmatic
    required-field / enum / status-conditional checks; no bundled schema).
  - `cve.py` — `finding_to_cve_draft` / `validate_cve_draft`, against the bundled
    official CVE Record 5.1 schema. `validate_cve_draft` drops the intentional
    `cveId` deviation so a structurally-complete draft validates while remaining
    non-submittable.
- **`DisclosureSession`** (`sessions/disclosure.py`) — gates, refuses any
  non-`verified` finding, drafts the four artifacts read-only, and persists them
  via `Store.write_detail`. It never transitions the finding, sets `cve`, adds an
  advisory reference, or touches `finding.disclosure`.
- **`check` wiring** — `_check_csaf` and `_check_openvex` validate every finding's
  drafts (the CVE draft is intentionally non-submittable and is not gate-checked).
- **CLI** — `playbook disclose --project --finding` runs the session under the
  human gate; `publish --format osv|csaf|openvex|cve-draft|advisory|all` emits
  local artifacts (OSV at `out/` root for back-compat, disclosure formats
  namespaced under `out/<fmt>/`, status-filtered to verified/disclosed/patched),
  still hard-gated on a green `check`, with no transmit path.
- **`scripts/smoke_005.sh`** — the hermetic new-project → discover → verify →
  disclose → check → publish flow, plus the red-check refusal.
- **Packaging** — the CSAF and CVE schemas are bundled as wheel `artifacts`;
  `referencing` is declared as a direct dependency.

## Safety invariants (structural, not by filtering)

1. **Nothing transmitted.** No HTTP client, no CVE Services API, no CNA/vendor
   submission, no feed push, no signing — enforced by omission. A test asserts the
   disclosure session imports no network module.
2. **No lifecycle change.** The session never calls `transition_finding`; a test
   forbids `transition_finding`/`save_finding` during a draft and asserts the
   persisted finding is byte-for-byte unchanged (still `verified`).
3. **No fabricated authority.** The CVE draft's `cveId` sentinel `CVE-XXXX-XXXXX`
   fails the official pattern by design; org ids are the zeroed UUID; CSAF uses an
   internal `ids[]` entry, never a fake `cve`; no advisory reference is ever added.
4. **Injection inertness (Article VIII).** Finding free-text is carried only as
   inert string values; each exporter has an injection-inertness test.
5. **`check` before `publish`** stays the hard gate (Article VII); a raising
   exporter degrades to a failed check, not a crash.

## Tests

- `tests/test_advisory.py` (7), `tests/test_csaf.py` (11), `tests/test_openvex.py`
  (6), `tests/test_cve.py` (7) — per-exporter: schema-validity, field mapping,
  no-fabricated-cve, injection-inertness, plus per-format specials (draft status,
  affected⇒action_statement, sentinel-cveId rejection, zeroed UUID, no CWE).
- `tests/test_disclosure_session.py` (6) — drafts-all-four, refuse-wrong-project,
  refuse-non-verified, no-transition/no-mutation, transmits-nothing, human-gate
  next steps.
- `tests/test_cli_005.py` (7) — `disclose` human gate + refusal, `publish
  --format` selector, namespacing, status filter, unknown-format + red-check
  refusal.
- `tests/test_check.py` (+4) — CSAF/OpenVEX draft conformance in the gate; a
  raising exporter is a failed check.

**428 passed** (380 baseline + 48 new). All five smokes pass.

## Review & merge

To be reviewed under the standing dual-gate (both clean on the same HEAD):
**codex** (GitHub bot, or the local `codex review --base main` CLI when the bot
lags) and **agy** (Antigravity/Gemini adversarial CLI). The transmit /
auto-transition / fabricate-authority hard stops remain human-only.
