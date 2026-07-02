# Feature Spec: Disclosure — draft-only advisory & VEX (005)

> **DRAFT-ONLY.** This feature drafts disclosure artifacts and stops. It never
> transmits, never sends, never publishes to any external party, and never
> advances a finding to `disclosed`. Sending is a human act, performed outside
> this tool. (Constitution Article V.)

## Problem

A `verified` finding is a confirmed bug with evidence, but it is not yet a
disclosure. Turning it into one is manual, error-prone, and standards-heavy: a
coordinated advisory wants a human-readable write-up, a CVE record request, a
CSAF 2.0 document, and an OpenVEX statement — each with its own schema, each
easy to get subtly wrong, and each carrying the risk that a draft is mistaken
for something ready to send.

Two failure modes matter more than convenience:

1. **Premature transmission.** An automated pipeline that can *send* a
   disclosure can send the wrong one, to the wrong party, at the wrong time.
   Coordinated disclosure is a human judgement call.
2. **Fabricated authority.** A draft that invents a CVE id or an advisory URL to
   look complete can trick the lifecycle guard into promoting a finding to
   `disclosed` on facts that do not exist.

Feature 005 removes the drudgery of *drafting* while structurally refusing both
failure modes.

## Goal

From a single `verified` finding, generate four **local draft artifacts** —

- a human-readable **advisory** (Markdown),
- a **CVE JSON 5.1** draft record (the CNA container),
- a **CSAF 2.0** security advisory, and
- an **OpenVEX** statement —

write them durably as session detail, assert the human gate, and teach back
exactly what a human must still do. Nothing leaves the machine. The finding's
status is unchanged.

## Scope

### In scope

- A `DisclosureSession` that gates like every other session, refuses any finding
  that is not `verified`, and drafts the four artifacts read-only from the
  finding's typed fields.
- Four exporters in `src/deepthought/export/` (`advisory.py`, `csaf.py`,
  `openvex.py`, `cve.py`), each mirroring the existing OSV exporter's shape:
  a `finding_to_<fmt>` builder and, for the JSON formats, a `validate_<fmt>`.
- Extending the `check` gate to validate the CSAF and OpenVEX drafts (the same
  way it already validates OSV).
- A new `playbook disclose` verb and a `--format` selector on `publish` that can
  emit any of the disclosure formats as **local artifacts only**, under the
  existing HUMAN GATE banner.
- `scripts/smoke_005.sh` — a hermetic end-to-end draft run.

### Out of scope (and the named HARD STOPS)

These are not deferred niceties; they are refusals. Each requires Mahdi's
sign-off and is a hard stop for the autonomous build:

- **Any transmission.** No HTTP client, no CVE Services API call, no CNA/MITRE
  submission, no vendor or PSIRT email, no feed/ROLIE push, no artifact signing.
  Enforced by **omission** — 005 introduces no network code.
- **Any auto-transition to `disclosed`.** The session never calls the Store's
  transition to `disclosed`. That transition needs a real CVE and a real
  advisory reference, both of which only a human can supply.
- **Fabricating a CVE or advisory reference.** Drafts use a sentinel CVE id
  (`CVE-XXXX-XXXXX`) that intentionally fails the real CVE pattern, and never
  add an `advisory` reference to the finding.
- **Finalizing a draft.** CSAF `tracking.status` is pinned to `draft`; the CVE
  record is labelled draft-only; the OpenVEX `@id` lives in a draft namespace.
- Real CNA/publisher identity, CWE enrichment, and coordinated-timeline dates —
  these are human/config inputs left as clearly-marked placeholders.

## User scenarios

1. **Draft a disclosure.** An operator has `F-0007` verified. They run
   `deepthought playbook disclose --project acme --finding F-0007`. The session
   gates, drafts all four artifacts, writes them to session detail, and closes
   clean with a summary that names the four refs and a next-steps block naming
   the human gate. `F-0007` is still `verified`.

2. **Refuse an unverified finding.** The operator points `disclose` at a
   `candidate`. The session refuses with a reason ("not verified"), drafts
   nothing, and closes with next steps to verify first.

3. **Emit a local bundle.** After `check` is green, the operator runs
   `deepthought publish --format all --out ./out`. The tool writes
   `out/{advisory,csaf,openvex,cve-draft,osv}/…`, prints the HUMAN GATE banner,
   and exits 0. Nothing is transmitted.

4. **The gate holds.** With a corrupted record making `check` red, `publish`
   refuses for every format and exits non-zero.

## Functional requirements

- **FR-1** `DisclosureSession(project_id, finding_id)` passes the Gate via
  `GateContext.from_project` before any work (Constitution Article I).
- **FR-2** The session refuses (non-raising outcome, logged with a reason) if
  the finding does not exist in the named project, or if its status is not
  `verified`.
- **FR-3** On a verified finding, the session drafts exactly four artifacts and
  persists each via `Store.write_detail` under the session id: `disclosure-advisory.md`,
  `disclosure-csaf.json`, `disclosure-openvex.json`, `disclosure-cve-draft.json`.
- **FR-4** The session never mutates the finding: no status transition, no
  `cve`, no `advisory` reference, no `disclosure` sub-object (draft-only,
  detail-only).
- **FR-5** Each exporter derives solely from the finding's **typed fields**
  (summary, severity, affected, references, aliases, cve, body scraped only for
  human-readable prose). Free text is carried as inert string values, never as
  document structure, keys, or a JSON `$ref`.
- **FR-6** When the finding has no CVE, the CVE draft emits the sentinel
  `CVE-XXXX-XXXXX`, CSAF emits an internal `ids[]` entry (never a fake `cve`),
  and OpenVEX falls back to the finding id. No format invents a CVE.
- **FR-7** When `severity` is absent, the CVSS/metrics block is omitted, not
  faked. When no CWE is derivable, CVE `problemTypes` is omitted.
- **FR-8** `validate_csaf` and `validate_openvex` return `[]` for a conformant
  draft and a list of `"path: message"` strings otherwise; `check` folds their
  errors into failures. A raising exporter degrades to a failed check, never a
  crash (Constitution Article VII).
- **FR-9** `validate_cve_draft` validates the CNA container's **structural**
  completeness while tolerating the sentinel cveId; it is not wired into the
  `check` gate. A separate test proves the sentinel fails the strict official
  CVE pattern (so an accidental submission would be rejected).
- **FR-10** `playbook disclose` runs the session; `publish --format` emits the
  selected format(s) as local artifacts under the HUMAN GATE banner, remains
  hard-gated on a green `check`, and adds no transmit path. Disclosure formats
  are status-filtered to `verified`/`disclosed`/`patched`.
- **FR-11** The session's teach-back always has non-empty next steps naming the
  human gate (assign a CVE, publish the advisory and add its reference, then run
  the `verified → disclosed` transition).

## Acceptance criteria

- A verified finding drafts four schema-valid artifacts; the finding remains
  `verified` and gains no `cve`/`advisory` reference.
- A non-verified finding is refused with nothing drafted.
- `check` goes red on a malformed CSAF/OpenVEX draft and green on conformant
  drafts; `publish` is refused whenever `check` is red.
- The CVE draft's sentinel cveId fails the strict official CVE pattern.
- No network module is imported or invoked anywhere in the disclosure path.
- `pytest` is green (all new tests plus the existing suite), and all smokes
  (`smoke.sh`, `smoke_002.sh`, `smoke_003.sh`, `smoke_004.sh`, `smoke_005.sh`)
  pass.

## Open questions

All resolved as locked decisions for this build (see `plan.md` for rationale):

1. **Draft persistence** — session writes durable drafts via `write_detail`;
   `publish` emits an ephemeral bundle to `--out/<fmt>/`.
2. **OpenVEX validation** — programmatic required-field / enum / status-conditional
   checks (no single authoritative JSON Schema); OSV/CSAF/CVE use bundled schemas.
3. **CVSS band** — derive `baseSeverity` from `cvss_score` by CVSS 3.1
   thresholds; omit the metrics block entirely when `severity` is `None`.
4. **CWE** — omit CVE `problemTypes` when no CWE is derivable (the `Finding`
   model has no CWE field yet).
5. **`publish` status filter** — disclosure formats only for
   `verified`/`disclosed`/`patched`.
6. **Finding mutation** — detail-only; the session does not mutate
   `finding.disclosure`.
7. **Identity placeholders** — obvious `PLACEHOLDER` strings, a zeroed UUID, and
   a sentinel cveId that fails the real pattern.

## Success criteria

The `smoke_005.sh` flow passes end to end: a fresh state, a project gated to
proceed, a discovered candidate verified through the Noop sandbox, a
`playbook disclose` that drafts four artifacts and leaves the finding
`verified`, a green `check`, a `publish --format all` that writes every format
locally under the human gate, and a negative case where a red `check` refuses
`publish`. Every artifact reads as clean text; nothing is transmitted; no CVE is
assigned and no advisory reference is added anywhere in the run.
