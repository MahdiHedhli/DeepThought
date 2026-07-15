# Deep Thought: Vuln-Rediscovery Corpus (calibration set)

This is a yardstick, not training data. Each seed CVE is used to build one
bug-class detector, and the detector must ship as a rule for the class, never a
signature for the one CVE. The real test is the held-out column: does the finished
detector find the same pattern in CVEs it never saw. All targets are public and
patched, so rediscovery carries ground truth and no disclosure risk.

Two axes on purpose: distinct exploitation classes, and distinct discovery
patterns, so the skill exercises every Deep Thought engine and both tiers.

## The 10 seeds

| # | Seed CVE | Package | Class (CWE) | Discovery pattern | Engine | Tier | Lang |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | CVE-2025-67306 | FFmpeg (IAMF parser) | Heap buffer overflow (CWE-122) | Coverage-guided fuzzing (AFL++) + ASan | Improbability Drive | sandbox | C |
| 2 | CVE-2025-10996 | Open Babel | Heap buffer overflow (CWE-122) | OSS-Fuzz continuous fuzzing + ASan/UBSan | Improbability Drive | sandbox | C++ |
| 3 | CVE-2025-31498 | c-ares | Use-after-free (CWE-416) | OSS-Fuzz + ASan (distinct UAF trace) | Improbability Drive | sandbox | C |
| 4 | CVE-2025-64718 | js-yaml | Prototype pollution (CWE-1321) | Static AST, unguarded key merge | DISCOVER static | deterministic | JS |
| 5 | CVE-2025-50181 | urllib3 | SSRF (CWE-918) | Taint, redirect/source to request sink | DISCOVER taint | deterministic | Python |
| 6 | CVE-2025-66516 | Apache Tika | XXE (CWE-611) | Static config rule, insecure XML parser | DISCOVER static | deterministic | Java |
| 7 | CVE-2024-12718 | CPython tarfile | Path traversal (CWE-22) | Static + variant analysis | SIBLING HUNT | deterministic | Python |
| 8 | CVE-2017-5954 | serialize-to-js | Insecure deserialization to RCE (CWE-502) | Static AST, untrusted data to execution/object sink | DISCOVER static | deterministic | JS |
| 9 | CVE-2025-3933 | Hugging Face Transformers | ReDoS (CWE-1333) | Regex-complexity + input fuzz | DISCOVER static + fuzz | deterministic | Python |
| 10 | CVE-2025-64756 | glob CLI | OS command injection (CWE-78) | Taint, untrusted value to shell exec | DISCOVER taint | deterministic | JS |

Seed 7 is deliberate. The tarfile extraction-filter bypass is a variant of
CVE-2007-4559, the Tier 1 case, and it belongs to a cluster of sibling bypass
CVEs. It is the SIBLING HUNT exemplar: one root pattern, several CVEs.

## Detection and verification per class

- **Heap overflow, use-after-free (1, 2, 3).** Detect by building a libFuzzer or AFL++ harness around the parsing entry and compiling with ASan. Verify by reproducing the sanitizer crash inside the signed-off sandbox. UAF is kept separate from overflow because the ASan signature and the harness lifecycle differ.
- **Prototype pollution (4).** Detect an assignment or recursive merge that writes a user-controlled key into an object without a `__proto__` and `constructor` guard. Verify by asserting a crafted key reaches `Object.prototype` in a boxed run, or by static confirmation for the deterministic tier.
- **SSRF (5).** Taint from a request-target source to an outbound-request sink where the host is not allowlisted, including the redirect path. Verify against a local sink, never a real external host.
- **XXE (6).** Detect an XML parser constructed without external-entity and DTD processing disabled. Verify by parsing a benign entity that resolves to a local marker file in the sandbox.
- **Path traversal (7).** Detect an archive member or path joined to a destination without normalization and containment. Verify by staging a crafted member and confirming it would escape, without extracting.
- **Deserialization (8).** Detect untrusted serialized input flowing to a dynamic execution or object-construction sink, with import/receiver provenance and receiver-bound hardening. Verify by static vulnerable/patched discrimination and the DISCOVER pipeline; no target code executes.
- **ReDoS (9).** Detect a regex with nested or overlapping quantifiers reachable from untrusted input, using a complexity checker. Verify by measuring superlinear match time on a crafted input under a wall bound.
- **Command injection (10).** Taint from an untrusted value to a shell execution sink, especially `shell: true` or string-built commands. Verify with a benign marker command in the sandbox, never a real payload.

## Reproducibility contract (pin or drop)

The held-out numbers must be reproducible, so ground truth is pinned, never
implied. When a class is built, every seed and held-out entry below is resolved
against an authoritative source (NVD/GHSA or the project's own advisory/commit)
and pinned in that class's fixture manifest to a **repo URL + vulnerable commit
SHA + patched commit SHA + target path**. The detector runs over the real trees at
those SHAs.

- An entry that **cannot** be resolved to fetchable ground truth at build time is
  **dropped from the denominator** with a recorded reason (in the RoundRecord and
  the manifest). It is never counted as a `missed` and never replaced by a
  hand-written sample — a dropped entry lowers *coverage*, reported honestly, not
  the generalization *rate*.
- The lists below are therefore *candidates*. The manifest, with its pinned SHAs,
  is the reproducible source of truth; a reader re-fetches from the SHAs and re-runs.
- Sandbox seeds/held-out are verified at sandbox-phase entry (they also need a
  buildable target + a fuzz harness); an unresolvable sandbox seed is swapped for a
  resolvable public equivalent of the same class before that class is built.
- Each seed's bug CLASS / CWE is confirmed against the authoritative source (NVD/GHSA
  or the project advisory) at that class's build. A seed whose authoritative weakness
  class does not match its row is **relabeled or swapped** for a true public example
  of the class before the detector is calibrated — the detector is never trained on an
  off-class seed. Known boundary case to resolve at build: the SSRF seed
  **CVE-2025-50181 (urllib3)** sits on the CWE-601 (redirect) / CWE-918 (SSRF)
  boundary; if the authoritative record classes it as redirect-only, it is swapped for
  a genuine CWE-918 request-sink SSRF CVE (or the row is relabeled to match).

## Held-out generalization sets (candidate lists — pinned per class at build)

For each class, run the finished detector against these CVEs, which were not used
to build it. Generalization rate is rediscovered over (rediscovered + missed),
counting only entries pinned to real ground truth.

- **Prototype pollution:** devalue CVE-2025-57820, lodash CVE-2025-13465, convict CVE-2026-33863, min-document CVE-2025-57352, js-object-utilities CVE-2025-28269.
- **ReDoS:** ajv CVE-2025-69873, valibot CVE-2025-66020, picomatch CVE-2026-33671, path-to-regexp CVE-2024-52798, fedify CVE-2025-68475, octokit/endpoint GHSA-x4c5-c7rf-jjgv.
- **Command injection:** systeminformation CVE-2025-68154, node-code-sandbox-mcp CVE-2025-53372, shell-quote CVE-2026-9277.
- **Heap overflow:** HDF5 CVE-2025-6816, HDF5 CVE-2025-6270, HDF5 CVE-2025-2914, iniparser CVE-2025-0633, Open Babel CVE-2025-10997.
- **Use-after-free:** HDF5 heap-UAF in H5FL (issue 5574, issue 5376), c-ares SOA double-free family.
- **Path traversal:** the tarfile-filter-bypass cluster (CVE-2025-4138, CVE-2025-4330, CVE-2025-4435) and CVE-2007-4559 as the anchor.
- **SSRF:** LangChain CVE-2023-46229, Apache HTTP Server CVE-2024-40898.
- **XXE:** pin three or more public CVEs of the class at build time (e.g. Java/XML-parser XXE advisories), each with vuln/patched SHAs in the manifest — not chosen ad hoc at run time.
- **Deserialization:** serialize-to-js CVE-2017-5954 is the verified seed; held-out Superset CVE-2018-8021, suricata-update CVE-2018-1000167, and Struts CVE-2017-9805 are pinned in the manifest. The React RSC seed was swapped because its property-traversal mechanism did not match this unsafe-deserialization sink class.
- **LDAP injection:** Yamcs CVE-2026-42568 is the verified seed; held-out mitmproxy CVE-2026-40606, Apache Airflow CVE-2026-46745, and Joomla CVE-2017-14596 are pinned in the manifest.
- **Open redirect:** Archivy CVE-2022-0697 is the verified seed; held-out Spirit CVE-2022-0869, Django Grappelli CVE-2021-46898, and Jupyter Notebook CVE-2020-26215 are pinned in the manifest.

## Acceptance

A class is done when its detector discriminates vulnerable from patched on the
seed fixture, rediscovers the seed through the real pipeline, and clears a held-out
generalization bar on CVEs it never saw. Fixture pass alone is not acceptance. A
detector that only matches its seed is overfit and does not ship.

## Round 3 broad-surface extension: SQL injection

The Round 3 SQL-injection class extends the corpus beyond the original ten seeds into
Python DB-API, PHP database wrappers, and Velocity/HQL templates. The manifest at
`benchmarks/corpus/sql_injection/manifest.json` is the executable source of truth:

| Role | CVE / package | Vulnerable SHA | Patched SHA | Result |
| --- | --- | --- | --- | --- |
| seed | CVE-2022-41892 / Arches | `75ce8f7cb9c08caf608569797a40ca9be585b182` | `7ed53e23a616edf3301d95814d9d64de5e3072a9` | pipeline rediscovered |
| held-out | CVE-2024-21514 / OpenCart | `ff0e1e21182aff8ab1ddab2420b904bbcadefc3f` | `46bd5f5a8056ff9aad0aa7d71729c4cf593d67e2` | rediscovered; patched target removed and verified fail-closed |
| held-out | CVE-2024-31445 / Cacti | `f946fa537d19678f938ddbd784a10e3290d275cf` | `fd93c6e47651958b77c3bbe6a01fff695f81e886` | rediscovered |
| held-out | CVE-2025-32429 / XWiki Platform | `cf6c843dee0aa8a02d38d5a3bfc710132877603d` | `f502b5d5fd36284a50890ad26d168b7d8dc80bd3` | honest miss; sink line persists |

The held-out score is **2/3** with 48 patched-file flags. A deleted target is never
inferred from a generic fetch failure: `patched_absent_paths` requires an exact manifest
declaration, independent commit verification, and an exact raw-path 404.

## Round 3 broad-surface extension: LDAP injection

The Round 3 LDAP-injection class extends the corpus into directory-service filter
construction across Java, Python, and PHP. The manifest at
`benchmarks/corpus/ldap_injection/manifest.json` is the executable source of truth:

| Role | CVE / package | Vulnerable SHA | Patched SHA | Result |
| --- | --- | --- | --- | --- |
| seed | CVE-2026-42568 / Yamcs | `e90099fba98e96214217c195b6a5b87b5f46e51c` | `c79cd966be6c28b8ce2916775426de6ec0cc4d03` | pipeline rediscovered |
| held-out | CVE-2026-40606 / mitmproxy | `cc58fc9f38e5865c4fa1eb07d7cc598eca1ebd4d` | `71c9234057922bc29b9734ec408d712113d294d2` | rediscovered |
| held-out | CVE-2026-46745 / Apache Airflow | `d3ea3ef0bccb23786e5b69a5534806ed6ed67c5e` | `3f7756bea71a7c7988511ec0557314ffb15fbe5e` | rediscovered |
| held-out | CVE-2017-14596 / Joomla | `220802a6f6d2ab431ab938057220a5f51f3184dd` | `590fd61dfacabe0f776880864667631ff8ec9014` | rediscovered |

The held-out score is **3/3** with **0 patched-file flags**. The rule distinguishes
RFC 4515 search-filter escaping from DN escaping and keeps sanitizer state bound to the
exact value and source position that reaches the directory search.

The honest ceiling is path-sensitive control flow: source-order state is not a complete
CFG/dominance proof, so a raw intermediate assigned on one conditional arm and a safe or
constant value assigned on another can be lost before a filter is built after the merge.
That shape is documented rather than represented as covered by the measured 3/3 cohort.

## Round 3 broad-surface extension: open redirect

The Round 3 open-redirect class extends the corpus into Python web-framework redirects and
same-origin validation. The manifest at `benchmarks/corpus/open_redirect/manifest.json` is
the executable source of truth:

| Role | CVE / package | Vulnerable SHA | Patched SHA | Result |
| --- | --- | --- | --- | --- |
| seed | CVE-2022-0697 / Archivy | `fa389e7d59f91980693965830839d6de1f1db45f` | `2d8cb29853190d42572b36deb61127e68d6be574` | pipeline rediscovered |
| held-out | CVE-2022-0869 / Spirit | `8b48d18e44f1dbb4b0f0a0a975d0dc14b88f0f41` | `8f32f89654d6c30d56e0dd167059d32146fb32ef` | rediscovered |
| held-out | CVE-2021-46898 / Django Grappelli | `55f88d661c28598d059cf81dbfd38dacb945662f` | `4ca94bcda0fa2720594506853d85e00c8212968f` | rediscovered |
| held-out | CVE-2020-26215 / Jupyter Notebook | `d8308e13803ba1c6e92f129381e615af6c6e00d3` | `3cec4bbe21756de9f0c4bccf18cf61d840314d74` | rediscovered; one unrelated patched flag |

The held-out score is **3/3** with **1 patched-file flag**. Jupyter's surviving
`self.redirect(url)` uses `url_path_join(..., url_escape(path))` and does not contain the
distinctive vulnerable sink probe, so line-precise rediscovery remains valid. Archivy's
patched seed also contains three unrelated `request.referrer` redirect flags; they are
outside the held-out metric and are not represented as clean.

urllib3 **CVE-2025-50181** is authoritatively CWE-601 but is dropped from this user-code
cohort because its fix changes library-internal redirect bookkeeping rather than an
application redirect sink. It is not counted as a miss.
