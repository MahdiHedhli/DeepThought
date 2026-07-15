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
  deserialization, ReDoS, command injection, SQL injection, LDAP injection.
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

### Path traversal (CWE-22)

- **When to use:** hunting JS or Python code that joins an archive member, request path,
  upload name, or other untrusted path component to a trusted destination before a file
  operation. The dangerous shape is a dynamic `path.join` / `path.resolve`,
  `os.path.join`, or `Path.joinpath` without containment.
- **Detection:** static AST (`benchmarks/pathtrav_detector.py`). The JavaScript backend
  uses tree-sitter and follows `path` import aliases; the Python backend uses `ast`. A
  sink is suppressed only by a containment idiom in its own scope. `startsWith` and
  `realpath` checks are bound to the path produced by the sink so an unrelated URL-prefix
  check or nested helper cannot bless it.
- **Rule id:** `DT-PATH-TRAVERSAL`, emitting SARIF 2.1.0 into the shipped DISCOVER ingest.
- **Verification:** deterministic static discrimination and the real NEW PROJECT → MAP →
  DISCOVER → `check` pipeline. No archive extraction or target code execution.
- **OSV / disclosure shape:** CWE-22; a known CVE is an informational alias only, never
  authoritative finding lifecycle evidence.
- **Fixtures:** seed decompress **CVE-2020-12265**; held-out adm-zip
  CVE-2018-1002204, aiohttp CVE-2024-23334, and NLTK CVE-2019-14751. The original
  CPython tarfile-filter seed was swapped because it is a library-internal filter bug,
  not user-code path-join misuse.
- **Held-out generalization:** **2/3 (67%)** — adm-zip and NLTK rediscovered on pinned
  real trees; aiohttp is the honest miss.
- **Notes:** aiohttp's vulnerable and patched functions both contain `relative_to`; the
  security difference is branch-sensitive (`follow_symlinks=True` gained normalization
  and containment). A scope-level static rule cannot distinguish that polarity without
  path-sensitive control-flow analysis. Patched-file context contains 11 unrelated path
  flags, reported honestly as false-positive context rather than hidden.

### Deserialization (CWE-502)

- **When to use:** hunting JavaScript, Python, or Java application code that passes
  untrusted serialized input to a code-generation, unsafe object-loader, or unrestricted
  object-graph sink.
- **Detection:** static AST (`benchmarks/deserial_detector.py`). JavaScript covers the
  global `Function`/`eval`, Node `vm.runIn*`, and known deserializer imports; execution-like
  member names require global or imported-module provenance. Python covers import-bound
  `pickle`/`dill`/`joblib` loads and unsafe PyYAML loaders. Java covers provenanced
  `ObjectInputStream.readObject` and XStream `fromXML` receivers.
- **Guards:** Java filters and XStream permissions must dominate and bind to the exact sink
  receiver; `setObjectInputFilter(null)` is not hardening. XStream wrapper summaries bind
  to method arity. JavaScript sanitizers and Python safe loaders require trusted import
  provenance, so a same-named local helper or unrelated guarded receiver cannot bless a sink.
- **Rule id:** `DT-DESERIAL`, emitting SARIF 2.1.0 into the shipped DISCOVER
  ingest. Verification is deterministic vulnerable/patched discrimination plus NEW PROJECT
  → MAP → DISCOVER → `check`; no target code executes.
- **Cohort:** seed serialize-to-js **CVE-2017-5954**; held-out Superset
  **CVE-2018-8021**, suricata-update **CVE-2018-1000167**, and Struts
  **CVE-2017-9805**, all pinned to real vulnerable/patched trees. The React RSC seed was
  swapped because its property-traversal mechanism was off-shape. Dropped CVE-2013-4660
  (authoritative CWE-20), CVE-2020-7729 (authoritative CWE-1188), and CVE-2020-7660
  (library-internal serializer escaping; no changed consumer sink).
- **Held-out generalization:** **3/3 (100%)**, with **0 patched-file flags**. The ceiling
  reflects visible sink removal/replacement for the Python cases and receiver-bound XStream
  hardening for Struts; it does not claim coverage of library-internal serialization bugs.

### SQL injection (CWE-89)

- **When to use:** hunting Python, PHP, or Velocity application code that turns request or
  function-input data into SQL/HQL syntax rather than a separately bound value.
- **Detection:** static AST (`benchmarks/sqli_detector.py`). Python models DB-API query
  arguments and treats a separate parameter collection as the safe discriminator. PHP uses
  tree-sitter to follow tainted query/fragment construction into database sinks, recognizing
  expression-bound quoting such as `db_qstr`. Velocity tracks request-derived values into
  dynamic `ORDER BY` fragments and recognizes allowlist normalization.
- **Rule id:** `DT-SQLI-QUERY`, emitting SARIF 2.1.0 into the shipped DISCOVER ingest.
  Verification is deterministic vulnerable/patched discrimination plus NEW PROJECT → MAP →
  DISCOVER → `check`; no target code executes.
- **Cohort:** seed Arches **CVE-2022-41892**; held-out OpenCart **CVE-2024-21514**,
  Cacti **CVE-2024-31445**, and XWiki Platform **CVE-2025-32429**, all pinned to real
  vulnerable/patched trees. OpenCart's fix removes the target, so the manifest's narrowly
  scoped `patched_absent_paths` is accepted only after the patched commit and exact 404 are
  independently verified; all other fetch errors fail closed.
- **Held-out generalization:** **2/3 (67%)** — OpenCart and Cacti rediscovered; XWiki is
  the honest miss. Its vulnerable and patched trees retain the same dynamic `ORDER BY` line;
  the fix reorders a framework-specific safety check after location rewriting, beyond this
  syntax-only rule. Patched-file context contains **48 flags**, reported honestly rather than
  hidden; most are unrelated query-building sites in Cacti/XWiki's large target files. The
  first real-tree pass found only 1/3 because a later constant PHP append stole attribution
  from the tainted construction; binding reports to the unsafe construction site fixed that
  generic defect and moved the honest result to 2/3.

### LDAP injection (CWE-90)

- **When to use:** hunting Java, Python, or PHP application code that incorporates
  untrusted values into LDAP search filters.
- **Detection:** static AST (`benchmarks/ldapinj_detector.py`). Java follows filter values
  through direct `DirContext.search` calls and local wrapper methods. Python binds helper
  summaries to the exact sanitized value and recognizes provenanced `ldap`/`ldap3` searches.
  PHP covers `ldap_search` and LDAP wrapper sinks such as `simple_search`. All three analyzers
  update taint and escaping state in source order, so a later sanitizer cannot retroactively
  protect an earlier sink.
- **Guards:** safe filter values require RFC 4515 filter escaping. DN escaping is deliberately
  not equivalent: it encodes a different LDAP grammar and cannot guard a search filter.
- **Rule id:** `DT-LDAP-FILTER`, emitting SARIF 2.1.0 into the shipped DISCOVER ingest.
  Verification is deterministic vulnerable/patched discrimination plus NEW PROJECT → MAP →
  DISCOVER → `check`; no target code executes.
- **Cohort:** seed Yamcs **CVE-2026-42568**; held-out mitmproxy **CVE-2026-40606**,
  Apache Airflow **CVE-2026-46745**, and Joomla **CVE-2017-14596**, all pinned to real
  vulnerable/patched trees.
- **Held-out generalization:** **3/3 (100%)**, with **0 patched-file flags**. Each fix visibly
  adds filter-context escaping to the value that reaches the sink; this result does not claim
  that DN escaping or unrelated sanitized values protect filter construction.
