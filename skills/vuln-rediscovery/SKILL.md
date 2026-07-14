---
name: vuln-rediscovery
description: Rediscover, verify, and prepare coordinated disclosure for a class of vulnerability. Use when hunting for a known bug pattern (memory safety, injection, deserialization, path traversal, prototype pollution, SSRF, XXE, ReDoS) in a target, or benchmarking detection against known CVEs. Detects the class, verifies inside the sandbox where execution is required, and drafts disclosure. Ships bug-class detectors that generalize, not CVE signatures.
---

# Vuln rediscovery

This skill turns Deep Thought's pipeline into a repeatable hunt for a known class
of bug. Each class below carries a detection strategy, a verification strategy,
and a disclosure shape, calibrated against a seed CVE and proven on held-out CVEs
it never saw. Load the section for the class you are hunting.

Governing law is `.specify/memory/constitution.md`. Execution happens only in the
signed-off sandbox. Disclosure is drafted, never sent.

## How to use a class section

1. Read the class section. It tells you the sink to look for, how to detect it,
   and how to verify it.
2. Run the pipeline: NEW PROJECT, MAP, DISCOVER with the class detector, then
   `check`. For memory classes, VERIFY inside the sandbox after sign-off.
3. Draft disclosure with the template. Do not send. Route to human triage.

## Ship the class, not the CVE

A detector is a rule for the bug class. It must flag the vulnerable shape and skip
the patched shape, and it must fire on packages it was never tuned on. A rule that
only matches its seed CVE is overfit and does not belong here. Generalization on
held-out CVEs is the acceptance bar.

## Improving a class (standing)

A class is never finished. Its held-out set is a permanent regression test. When a
detector misses a real CVE of its class, whether in the held-out set or in a live
hunt, that CVE becomes a new fixture, the detector is tightened to catch the
pattern without overfitting to it, and the full held-out set is re-run. The change
merges only if no class's rate drops, and a new snapshot is logged. Additions come
from real misses, never speculative hardening. See `docs/IMPROVEMENT-PROTOCOL.md`.

This loop touches detectors, fixtures, and this file only. It never changes the
constitution, the gates, the sandbox, or the disclosure boundary.

## Two tiers

- **Deterministic.** Static and taint detection emitting SARIF. Runs in CI, no
  target code executes. Prototype pollution, SSRF, XXE, path traversal,
  deserialization, ReDoS, command injection.
- **Sandbox.** Fuzzing plus a sanitizer, executed only in the signed-off sandbox.
  Heap overflow, use-after-free, and any class whose proof is a crash.

## Disclosure and triage

Lead with the reproduction and the sanitizer or static evidence. Name the tool
honestly as machine-assisted. Never overstate impact. A human reads every draft
before anything leaves the machine. See `docs/DISCLOSURE-TEMPLATE.md` and the
pre-send triage gate.

---

## Class sections

Each build round appends one section here using this template:

    ### <class name> (CWE-XXX)
    - When to use: <the shape a hunter is looking for>
    - Detection: <static rule, taint query, or fuzz harness; the sink>
    - Rule id: <DT-...>, emits SARIF / harness template ref
    - Verification: <static confirmation, or sandbox crash reproduction>
    - OSV / disclosure shape: <severity basis, references policy>
    - Fixtures: <seed CVE, plus any added from real misses>
    - Held-out generalization: <latest rediscovered / total; logged over versions>
    - Notes: <false-positive traps, patched-shape discriminator>

<!-- rounds append below this line -->

### Prototype pollution (CWE-1321)

- **When to use:** hunting a JS/TS target that merges, copies, clones, or deletes
  object properties with a key drawn from parsed/untrusted input (config/YAML/JSON
  loaders, deep-merge/extend/set/unset utilities, deserializers). The shape: a
  computed-member **write** (`obj[key] = v`) or **delete** (`delete obj[key]`) where
  `key` can be `__proto__` / `constructor` / `prototype`.
- **Detection:** static AST (`benchmarks/pp_detector.py`, tree-sitter). Flags a
  computed-member write/delete whose key is dynamic AND externally derived (bound by a
  `for..in`/`for..of`, a function parameter, or copied from another object) when the
  **enclosing function** does not guard that object/key. Guard scoping is per-function,
  so an unguarded merge path is caught even when a sibling path in the same file guards
  `__proto__` (the js-yaml seed).
- **Rule id:** `DT-PP-MERGE`, emits SARIF 2.1.0 (`scan_file` / `scan_source`) into the
  shipped `deepthought.ingest.sarif`.
- **Verification:** static (deterministic tier) — discriminate vulnerable from patched
  on the fixture and rediscover through NEW PROJECT → MAP → DISCOVER → `check`. No
  execution.
- **OSV / disclosure shape:** severity basis `permissive_oss`; the analyzer emits
  **CWE-1321** and, for a known target, the CVE as an informational **alias** only —
  never an authoritative `Finding.cve`, `advisory`, or `fix`.
- **Fixtures:** seed js-yaml **CVE-2025-64718** (unguarded merge assignment); held-out
  (real, pinned by SHA) devalue CVE-2025-57820 (for-in copy), lodash CVE-2025-13465
  (delete by path), min-document CVE-2025-57352 (delete by namespace). Dropped for no
  NVD record: convict CVE-2026-33863, js-object-utilities CVE-2025-28269.
- **Held-out generalization:** **2/3 (67%)** — devalue and lodash rediscovered;
  min-document missed (logged `v1-2026-07-04`).
- **Notes.** Patched-shape discriminators recognized: a `key === '__proto__'` /
  skiplist check, `Object.defineProperty`, or an `Object.create(null)` target (tied to
  the specific object). A bare `hasOwnProperty` is deliberately NOT treated as a guard
  (the seed writes inside a benign `!hasOwnProperty` duplicate-key check). **Known
  miss:** min-document's patch guards via `hasOwnProperty` with skip-polarity, which is
  indistinguishable from a benign check without control-flow analysis — the next
  improvement-loop fixture. Precision is high at the sink but lower across a large file
  (a static heuristic flags other dynamic writes); refining precision is future work.

### SSRF (CWE-918)

- **When to use:** hunting a Python target that fetches a URL/host derived from
  untrusted input — document/media loaders, webhook/avatar fetchers, LLM URL loaders,
  proxy endpoints. The shape: an outbound-request call whose URL can be attacker-chosen
  (an internal service or the cloud metadata endpoint).
- **Detection:** static taint-lite (`benchmarks/ssrf_detector.py`, Python `ast`). Flags
  a call to an outbound-request **sink** (`requests`/`httpx`/`aiohttp`/`urllib`/`urllib3`,
  incl. `.stream("GET", url)` and client-variable methods) whose **URL argument is
  non-literal** when the enclosing **scope** applies no SSRF guard. Scope-local, so a
  guard in a sibling helper does not mask an unguarded request.
- **Rule id:** `DT-SSRF-TAINT`, emits SARIF 2.1.0 into the shipped
  `deepthought.ingest.sarif`.
- **Verification:** static (deterministic tier) — discriminate vulnerable from patched
  on the fixture and rediscover through NEW PROJECT → MAP → DISCOVER → `check`. No
  execution.
- **OSV / disclosure shape:** severity basis `permissive_oss`; emits **CWE-918** and,
  for a known target, the CVE as an informational **alias** only.
- **Fixtures:** seed **dify CVE-2025-0184** (raw `requests.get(url)` → `ssrf_proxy.get`);
  held-out (real, pinned by SHA) gradio CVE-2024-4325 (`httpx` + `check_public_url`),
  pydantic-ai CVE-2026-25580 (`httpx` + `safe_download`), lmdeploy CVE-2026-33626
  (`requests` + `_is_safe_url`/`ipaddress.is_global`), langchain CVE-2023-46229
  (`requests`/`aiohttp` + same-domain). **Seed swapped** from urllib3 CVE-2025-50181
  (authoritatively CWE-601, not SSRF).
- **Held-out generalization:** **3/4 (75%)** — dify seed + gradio + pydantic-ai +
  lmdeploy rediscovered; langchain missed (logged `v2-2026-07-05`; skill mean 70.9%).
- **Notes.** Two SSRF-fix shapes handled: **sink substitution** (the raw sink replaced
  by a safe wrapper like `ssrf_proxy.get`/`safe_download`, recognized by a safe-wrapper
  name so it is never a sink) and **guard added** (a validation of the URL/host —
  `check_public_url`, an `ipaddress.is_global` / `getaddrinfo` check, a scheme/netloc
  allowlist). **Known miss:** langchain's `prevent_outside` same-domain *bool flag* is
  not a validation call, so its patched sink still flags — the next improvement-loop
  fixture. A non-literal URL is treated as potentially tainted (taint-lite), so
  file-level precision on hardcoded-config requests is a documented limitation. A syntactic taint-lite rule handles module/import aliasing, request()/stream() arg positions, client-variable and safe-wrapper naming, order-aware and URL-tied guards (assignment/for-loop alias chains url->host->ip, IP-range and hostname-allowlist checks); it does NOT model control flow, so ternary-conditional guards, log-only comparisons, or post-sink derivations are documented, not chased.

### XXE (CWE-611)

- **When to use:** hunting a Java or Python target that parses untrusted XML (document
  extractors, config/SAML/SOAP loaders, office-file readers). The shape: an XML parser
  constructed with DTDs / external entities left enabled.
- **Detection:** static config rule (`benchmarks/xxe_detector.py`), multi-language.
  Java (tree-sitter): an XML-parser factory (`XMLInputFactory.newFactory()`,
  `DocumentBuilderFactory/SAXParserFactory.newInstance()`, `new SAXReader()`,
  `createXMLReader()`) whose enclosing method does not disable DTDs/external entities
  (`SUPPORT_DTD`=false, `disallow-doctype-decl`, `external-general-entities`,
  `FEATURE_SECURE_PROCESSING`, `ACCESS_EXTERNAL_DTD`, …). Python (ast): an lxml
  `etree.XMLParser(...)` without `resolve_entities=False`/`no_network`, in a module not
  using `defusedxml`.
- **Rule id:** `DT-XXE-PARSER`, emits SARIF 2.1.0 into `deepthought.ingest.sarif`.
- **Verification:** static (deterministic tier) — discriminate vulnerable from hardened
  and rediscover through NEW PROJECT → MAP → DISCOVER → `check`.
- **OSV / disclosure shape:** CWE-611, CVE as an informational alias only.
- **Fixtures:** seed apache/tika **CVE-2025-66516** (Java StAX); held-out (real, pinned)
  python-docx CVE-2016-5851 (lxml), dom4j CVE-2020-10683, JDOM2 CVE-2021-33813.
- **Held-out generalization:** **1/3 (33%)** — python-docx rediscovered; dom4j and JDOM2
  are documented hard misses (logged `v3-2026-07-05`).
- **Notes.** `IGNORING_STAX_ENTITY_RESOLVER` is deliberately NOT treated as hardening (the
  Tika seed had it in its vulnerable version; the real fix added `SUPPORT_DTD`=false).
  **Known misses:** dom4j (fix adds a safe `createDefault()` alternative, leaving the
  flagged path) and JDOM2 (fix reorders existing `setFeature` calls) — the static XXE
  signal persists in both patched trees, so a config rule (like mainstream SAST) flags
  both; discriminating needs dataflow/ordering analysis. Future improvement-loop fixtures.

### OS command injection (CWE-78)

- **When to use:** hunting a JS/Node or Python target that runs a shell command built from
  untrusted input — CLI tools, build/bundler steps, MCP servers, git drivers, cloud SDKs.
- **Detection:** static taint-lite (`benchmarks/cmdinj_detector.py`). JS (tree-sitter):
  `child_process` `exec`/`execSync`(dynamic string), `spawn`/`execFile`/`foregroundChild`
  with `{shell:true}`, or an `exec('bash', ['-c', <dynamic>])` shell invocation. Python
  (ast): `subprocess.*(shell=<non-False>)`, `os.system`/`os.popen`(dynamic). Skipped when
  the scope applies a shell-escape guard (`shell-quote`/`shlex.quote`/`.quote(`).
- **Rule id:** `DT-CMDI-EXEC`, emits SARIF 2.1.0 into the shipped `deepthought.ingest.sarif`.
- **Verification:** static (deterministic tier) — discriminate + rediscover through NEW
  PROJECT → MAP → DISCOVER → `check`. No execution.
- **OSV / disclosure shape:** CWE-78, CVE as an informational alias only.
- **Fixtures:** seed node-glob **CVE-2025-64756** (`foregroundChild(..., {shell:true})`);
  held-out (real, pinned, re-curated to user-code-misuse) cyclonedx-npm CVE-2026-55849
  (execSync→execFile), dulwich CVE-2026-42563 (shlex.quote guard), ansys-geometry
  CVE-2024-29189 (Popen shell=), aws-cdk CVE-2026-11417.
- **Held-out generalization:** **3/4 (75%)** — cyclonedx, dulwich, ansys rediscovered;
  aws-cdk missed (logged `v4-2026-07-05`).
- **Notes.** The held-out was re-curated to user-code-misuse CVEs whose fix VISIBLY changes
  the sink (dropped: systeminformation — sanitize-only, sink persists; shell-quote —
  library-internal). **Known miss:** aws-cdk's patched tree keeps a `bash -c` exec for the
  explicit command-hooks case, so the signal persists — a future improvement-loop fixture.
