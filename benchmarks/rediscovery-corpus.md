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
| 8 | CVE-2025-55182 | React / Next.js (RSC Flight) | Insecure deserialization to RCE (CWE-502) | Semantic, untrusted data to exec sink | DISCOVER taint | deterministic | JS |
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
- **Deserialization (8).** Detect untrusted serialized input flowing to an execution or object-construction sink. Verify by confirming attacker-controlled data reaches the sink, boxed, with a benign marker rather than a payload.
- **ReDoS (9).** Detect a regex with nested or overlapping quantifiers reachable from untrusted input, using a complexity checker. Verify by measuring superlinear match time on a crafted input under a wall bound.
- **Command injection (10).** Taint from an untrusted value to a shell execution sink, especially `shell: true` or string-built commands. Verify with a benign marker command in the sandbox, never a real payload.

## Held-out generalization sets (the real test)

For each class, run the finished detector against these CVEs, which were not used
to build it. Generalization rate is rediscovered over total.

- **Prototype pollution:** devalue CVE-2025-57820, lodash CVE-2025-13465, convict CVE-2026-33863, min-document CVE-2025-57352, js-object-utilities CVE-2025-28269.
- **ReDoS:** ajv CVE-2025-69873, valibot CVE-2025-66020, picomatch CVE-2026-33671, path-to-regexp CVE-2024-52798, fedify CVE-2025-68475, octokit/endpoint GHSA-x4c5-c7rf-jjgv.
- **Command injection:** systeminformation CVE-2025-68154, node-code-sandbox-mcp CVE-2025-53372, shell-quote CVE-2026-9277.
- **Heap overflow:** HDF5 CVE-2025-6816, HDF5 CVE-2025-6270, HDF5 CVE-2025-2914, iniparser CVE-2025-0633, Open Babel CVE-2025-10997.
- **Use-after-free:** HDF5 heap-UAF in H5FL (issue 5574, issue 5376), c-ares SOA double-free family.
- **Path traversal:** the tarfile-filter-bypass cluster (CVE-2025-4138, CVE-2025-4330, CVE-2025-4435) and CVE-2007-4559 as the anchor.
- **SSRF:** LangChain CVE-2023-46229, Apache HTTP Server CVE-2024-40898.
- **XXE, deserialization:** source additional recent CVEs of the class at run time. These classes are common, so a held-out set of three or more each is easy to assemble.

## Acceptance

A class is done when its detector discriminates vulnerable from patched on the
seed fixture, rediscovers the seed through the real pipeline, and clears a held-out
generalization bar on CVEs it never saw. Fixture pass alone is not acceptance. A
detector that only matches its seed is overfit and does not ship.
