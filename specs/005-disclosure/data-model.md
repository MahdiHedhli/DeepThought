# Data Model: Disclosure — draft-only advisory & VEX (005)

Disclosure introduces **no new persisted Record type**. It reads one `verified`
`Finding` and produces four *draft artifacts* written as session detail. The
finding, its lifecycle, and every other record are untouched.

Source fields available on `Finding` (`schema/finding.py`): `id`, `project`,
`summary`, `status`, `severity` (`Severity.cvss_vector: str`,
`Severity.cvss_score: float`), `affected` (`AffectedPackage[]`), `references`
(`Reference[]` of `{type, url}`), `aliases`, `cve`, `disclosure` (`Disclosure`),
`downstream_impact`, `published`, `modified`, `body`.

## The four draft artifacts

### 1. Advisory — `finding_to_advisory(finding) -> str` (Markdown, no validator)

```
# Advisory: <summary>

## Summary        <- finding.summary
## Severity       <- severity.cvss_vector / cvss_score (omitted if severity is None)
## Affected       <- finding.affected
## Details        <- _details(finding)   (reuses the OSV body scraper)
## Impact         <- finding.downstream_impact
## References     <- finding.references
## Disclosure timeline   <- finding.disclosure.timeline (only if present)
## Status         <- fixed footer: "DRAFT — no CVE assigned, nothing transmitted,
                     finding remains verified."
```

### 2. CSAF 2.0 — `finding_to_csaf(finding) -> dict` / `validate_csaf(doc) -> list[str]`

```json
{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "publisher": {"category": "vendor", "name": "<PLACEHOLDER>", "namespace": "<PLACEHOLDER-URI>"},
    "title": "<summary>",
    "tracking": {
      "current_release_date": "<utcnow Z>", "id": "<osv_id_for(id) or PLACEHOLDER>",
      "initial_release_date": "<utcnow Z>",
      "revision_history": [{"date": "<utcnow Z>", "number": "1", "summary": "Initial draft generated from code finding."}],
      "status": "draft", "version": "1"
    }
  },
  "product_tree": {"branches": [{"category": "vendor", "name": "<vendor|PLACEHOLDER>", "branches": [
    {"category": "product_name", "name": "<affected[0].name>", "branches": [
      {"category": "product_version", "name": "<version>", "product": {"name": "<name version>", "product_id": "CSAFPID-0001"}}]}]}]},
  "vulnerabilities": [{
    "title": "<summary>",
    "notes": [{"category": "summary", "text": "<details/downstream_impact>"}],
    "product_status": {"known_affected": ["CSAFPID-0001"]},
    "scores": [{"cvss_v3": {"version": "3.1", "vectorString": "<cvss_vector>", "baseScore": <cvss_score>, "baseSeverity": "<band>"}, "products": ["CSAFPID-0001"]}],
    "references": [{"category": "self", "summary": "Source location", "url": "<from references>"}]
  }]
}
```

| CSAF field | Finding source |
|---|---|
| `document.title`, `vulnerabilities[0].title` | `summary` |
| `vulnerabilities[0].notes[].text` | `_details(finding)` or `downstream_impact` |
| `vulnerabilities[0].scores[0].cvss_v3` | `severity` (whole `scores` **omitted** if `severity is None`) |
| `product_tree` name/version | `affected[0]` |
| `vulnerabilities[0].references` | `references` (external types → `external`, else `self`) |
| `vulnerabilities[0].cve` **or** `ids[]` | `cve` **iff** it matches the real pattern; else internal `ids[{system_name:"DeepThought", text: osv_id_for(id)}]` — never a fake `cve` |
| `document.tracking.status` | pinned `"draft"` |
| `publisher.name`/`namespace`, `tracking.id` | `PLACEHOLDER` (human) |

### 3. OpenVEX — `finding_to_openvex(finding) -> dict` / `validate_openvex(doc) -> list[str]`

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://deepthought.local/vex/draft/<utcdate>-<finding-id>",
  "author": "Deep Thought (local draft)", "timestamp": "<utcnow Z>", "version": 1,
  "statements": [{
    "vulnerability": {"name": "<finding.cve or finding.id>"},
    "products": [{"@id": "<purl from affected[0]>", "subcomponents": [{"@id": "<dep purl>"}]}],
    "status": "affected",
    "action_statement": "<PLACEHOLDER — human remediation guidance>"
  }]
}
```

Required document fields: `@context`, `@id`, `author`, `timestamp`, `version`.
Required statement fields: `vulnerability.name`, `products[]`, `status`.

| OpenVEX field | Finding source |
|---|---|
| `statements[0].vulnerability.name` | `cve` if set, else `id` |
| `statements[0].products[].@id` | PURL from `affected[0]` (`pkg:<ecosystem>/<name>@<version>`) |
| `statements[0].status` | always `"affected"` (a verified finding **is** affected) |
| `statements[0].action_statement` | `PLACEHOLDER` (human) |
| `@id`, `timestamp`, `version` | generated |

**Normative rule (`validate_openvex` enforces it):** `status == "affected"` MUST
carry an `action_statement`. The exporter never asserts `not_affected`, `fixed`,
or `under_investigation` — those are human triage conclusions requiring
justification/analysis.

### 4. CVE draft — `finding_to_cve_draft(finding) -> dict` / `validate_cve_draft(doc) -> list[str]`

```json
{
  "dataType": "CVE_RECORD", "dataVersion": "5.1",
  "cveMetadata": {"cveId": "CVE-XXXX-XXXXX", "assignerOrgId": "00000000-0000-4000-8000-000000000000", "state": "PUBLISHED"},
  "containers": {"cna": {
    "providerMetadata": {"orgId": "00000000-0000-4000-8000-000000000000", "shortName": "PLACEHOLDER_CNA"},
    "descriptions": [{"lang": "en", "value": "<summary + details, 1..4096 chars>"}],
    "affected": [{"vendor": "<vendor|PLACEHOLDER>", "product": "<affected[0].name>",
      "versions": [{"version": "<from|0>", "lessThan": "<fixed|unknown>", "status": "affected", "versionType": "semver"}],
      "defaultStatus": "unaffected"}],
    "problemTypes": [{"descriptions": [{"lang": "en", "description": "<CWE text>", "cweId": "<CWE-N>", "type": "CWE"}]}],
    "metrics": [{"cvssV3_1": {"version": "3.1", "vectorString": "<cvss_vector>", "baseScore": <cvss_score>, "baseSeverity": "<band>"}}],
    "references": [{"url": "<from references>", "tags": ["vdb-entry"]}]
  }}
}
```

Required CNA members: `providerMetadata`, `descriptions` (≥1), `affected` (≥1),
`references` (≥1).

| CVE field | Finding source |
|---|---|
| `containers.cna.descriptions[].value` | `summary` + `_details(finding)` |
| `containers.cna.affected[]` | `affected` (vendor/product + versions) |
| `containers.cna.metrics[].cvssV3_1` | `severity` (**omitted** if `severity is None`) |
| `containers.cna.references` | `references` |
| `containers.cna.problemTypes[].cweId` | CWE if derivable; **omitted** otherwise |
| `cveMetadata.cveId` | sentinel `CVE-XXXX-XXXXX` (human assigns real one) |
| `cveMetadata.assignerOrgId`, `providerMetadata.orgId` | zeroed UUID (human/CNA) |

## Records used, and how

- **Finding** — read only. Loaded via `Store.get_finding`; never saved,
  transitioned, or mutated. Its `status` stays `verified`.
- **Session** (`type = disclosure`) — the normal harness record: gate outcome,
  summary, next steps, `findings_touched=[finding.id]`, `coverage_changed=[]`.
- **Detail artifacts** — four files written via
  `Store.write_detail(session_id, name, content)`:
  `disclosure-advisory.md`, `disclosure-csaf.json`, `disclosure-openvex.json`,
  `disclosure-cve-draft.json` (JSON dumped `indent=2, sort_keys=True` for stable
  diffs). These are the durable audit of what was drafted.
- **Coverage** — none. Disclosure claims no surface coverage.

Per decision #6, the session does **not** populate `finding.disclosure`
(`Disclosure` sub-object). Drafts live only in detail.

## The CVE-draft non-submittability guarantee

The CVE draft is unsubmittable by construction: `cveId = "CVE-XXXX-XXXXX"`
intentionally fails the official pattern `^CVE-[0-9]{4}-[0-9]{4,19}$`, and the
assigner/provider org ids are the zeroed UUID. `validate_cve_draft` checks
structural completeness while tolerating these placeholders (so a well-formed
draft passes its own tests); a separate test asserts the sentinel fails the
strict official pattern. The CVE draft is deliberately **not** part of the
`check` gate.

## What DISCLOSURE never writes or mutates

- Never advances a finding to `disclosed` (or any status).
- Never sets `finding.cve`.
- Never adds a `Reference(type="advisory", …)` to the finding.
- Never populates `finding.disclosure`.
- Never touches the network, `state/` outside the Store, or another finding.

## Notes

- Injection inertness: finding free-text (`summary`/`body`/`downstream_impact`)
  is placed only in string-typed leaves (`notes[].text`, `descriptions[].value`,
  `action_statement`, Markdown prose) — never as a key, structure, or `$ref`. The
  body is scraped for prose with the existing OSV `_details` helper, never
  interpreted as instruction.
- Timestamps come from the session clock (`iso_z`/`utcnow`), matching the rest of
  the platform; they are not read from the finding's free text.
