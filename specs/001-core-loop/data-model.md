# Data Model: Platform Spine (001)

State is flat files in git, accessed only through the `Store` interface. Each
record is Markdown with YAML front-matter. Front-matter holds structured fields.
The body holds human narrative. This keeps diffs clean and lets a reviewer read
the work from the repository alone.

## State layout

```
state/
  projects/    <project-id>.md
  findings/    <finding-id>.md
  sessions/    <session-id>.md
  coverage/    <project-id>/<area-id>.md
  methodology/ <rubric-id>.md
  detail/      <session-id>/...        # paged worker detail, never inlined to the orchestrator
```

Identifiers are short, stable, human-readable slugs. Example: `php-src`,
`F-0007`, `S-2026-06-30-0003`.

## Project

Front-matter:
- `id` string, stable slug.
- `name` string.
- `source_type` enum: `open_source` or `blackbox`.
- `git_url` string, or `local_path` string.
- `authorization_basis` enum: `own_code`, `permissive_oss`, `scoped_engagement`.
- `authorization_ref` string, required when basis is `scoped_engagement`. The engagement or license reference.
- `scope_allowlist` list of strings. Paths, modules, hosts, or endpoints in scope. Empty means nothing is in scope, not everything.
- `status` enum: `active`, `paused`, `closed`.

Body: notes on the target, its layout, and known context.

Rules:
- A session against a project with no `authorization_basis` is refused at the gate.
- `blackbox` with no `authorization_ref` is refused.
- Project identity is resolved on `git_url` or `local_path`. The Store does not create a duplicate.

## Finding

This is the record that exports to OSV. Front-matter mirrors OSV field names
where it can, so export is a mapping, not a translation.

Front-matter:
- `id` string, internal id, for example `F-0007`.
- `project` string, the Project id.
- `summary` string, one line. Maps to OSV `summary`.
- `status` enum: `candidate`, `verified`, `disclosed`, `patched`.
- `severity` object: `cvss_vector` string, `cvss_score` number. Maps to OSV `severity[]` with `type CVSS_V3` or `CVSS_V4`.
- `affected` list: each `{ ecosystem, package, ranges, versions }`. Maps to OSV `affected[]`.
- `references` list: each `{ type, url }`. Maps to OSV `references[]`.
- `aliases` list of strings. CVE and other ids. Maps to OSV `aliases`.
- `cve` string or null. Mirrored into `aliases` on export.
- `disclosure` object: `{ reported, vendor_contact, embargo_until, timeline[] }`.
- `evidence_ref` string, pointer to the repro artifact in `state/detail/`.
- `downstream_impact` string, the written impact statement, also rendered in the body.

Body, the human narrative blocks:
- `## Root cause`
- `## Affected versions`
- `## Minimized repro`
- `## Impact` the standardized statement
- `## Suggested fix`

Finding-to-OSV field map:

| Finding field | OSV field |
| --- | --- |
| `id` and `aliases` | `id`, `aliases` |
| `summary` | `summary` |
| body root cause and impact | `details` |
| `severity.cvss_vector` | `severity[].score` with matching `type` |
| `affected[]` | `affected[]` with `ranges` and `versions` |
| `references[]` | `references[]` |
| timestamps | `published`, `modified` |

Lifecycle rules, enforced at the Store boundary:
- `candidate -> verified` requires a non-empty `evidence_ref` that resolves.
- `verified -> disclosed` requires a `cve` and at least one `references` entry of type advisory.
- `verified -> patched` requires a `cve` and a fix reference.
- Any rejected transition records the blocking reason on the finding and leaves status unchanged.
- Backward transitions are allowed and logged when evidence weakens.

## Session

Front-matter:
- `id` string.
- `type` enum: `new_project`, `status`, and later `discover`, `map`, `verify`, `sibling_hunt`, `disclosure`.
- `project` string or null. NEW PROJECT may run before a project exists.
- `started` and `closed` timestamps.
- `gate_outcome` enum: `proceed`, `hold`, `refuse`.
- `gate_reason` string, required when hold or refuse.
- `close_state` enum: `clean` or `interrupted`.
- `findings_touched` list of finding ids.
- `coverage_changed` list of coverage refs.
- `context_cost` object: `{ tokens, wall_seconds }`. Feeds the limit-awareness layer later.

Body:
- `## Summary` what was done.
- `## Next steps` explicit, the input to the next session.

Rules:
- A session with no `## Next steps` is incomplete and does not close.
- An interrupted session is detectable by the next session, which can resume.

## Coverage

Front-matter:
- `project` string.
- `area` string, the surface or module.
- `method` enum: `read`, `static`, `fuzz`, `manual`.
- `depth` enum: `touched`, `explored`, `exhausted`.
- `last_session` string, the session id.

Body: what was looked at and what remains.

## Methodology

Versioned reference data, not code. Front-matter `{ id, purpose, version }`.
Body holds the rubric. Examples: the severity rubric, the impact-statement
template. Sessions cite a methodology by id and version so scoring is
reproducible.

## Notes

- All writes go through the Store. Nothing reads or writes `state/` directly. This is what makes the vector-DB swap a single-file change later.
- Front-matter is validated against the Pydantic models on every read. A malformed record fails `check`.
- The `detail/` tree holds full worker output. The orchestrator references it but does not load it into context.
