# Deep Thought Rediscovery Benchmark

A deterministic CI benchmark that proves the platform **rediscovers a known,
already-patched vulnerability through the real pipeline** — without executing the
vulnerable sink. Because the target CVE is public and fixed, there is ground truth
and **no disclosure risk**.

## Why rediscovery
An end-to-end benchmark answers a sharper question than a unit test: given nothing
but the vulnerable source, does the *shipped* pipeline (static rule → SARIF → the
real ingest → a candidate Finding → OSV → `check`) arrive at the known answer? And
does it stop exactly where the Constitution says it must — at the execution hard
stop (Article III)?

## Tier 1 — CVE-2007-4559 (Python `tarfile` path traversal) — **built**

The bug: `tarfile.extract` / `extractall` do not sanitize member paths, so a
crafted archive member named `../x` writes outside the destination (CWE-22). The
fix (PEP 706, Python 3.12) is `extractall(..., filter='data')`.

### Pieces
- **Fixture** — [`fixtures/vulnerable_extract.py`](fixtures/vulnerable_extract.py):
  one unsanitized `extractall` (vulnerable) and one `extractall(filter='data')`
  (patched). **Never called** — they exist to be read.
- **Static rule** — [`tarfile_detector.py`](tarfile_detector.py): an AST rule that
  flags an `extract`/`extractall` call with no `filter=` keyword and emits SARIF
  2.1.0 (rule `DT-TARFILE-EXTRACTALL`). Each result and the rule carry
  `cwe: CWE-22` and `cve: CVE-2007-4559` in `properties`. It flags the vulnerable
  call and skips the patched one.
- **Real ingest wiring** — the SARIF feeds the **shipped** `deepthought.ingest.sarif`
  (`sarif_to_findings`), which was extended (not forked) to carry a *validated*
  `cve`/`cwe`. Because SARIF is **untrusted**, a claimed CVE is recorded only as an
  informational **alias** (a cross-reference — "this candidate looks like CVE-…"),
  **never** the authoritative `Finding.cve` that gates `verified → disclosed`; the
  CWE goes into the body. A malformed/sentinel value is dropped — SARIF stays
  untrusted, bounded data.
- **Repro** — a tar with a single member `../deep_thought_poc_marker`. A benign
  marker, no payload; staged and inspected, never extracted.
- **Test** — [`test_cve_2007_4559.py`](test_cve_2007_4559.py): the rediscovery plus
  the full real-verb integration path (NEW PROJECT `permissive_oss` scoped to the
  fixture → MAP → DISCOVER → `check` → the autonomous loop's `verify_escalation`).

### The execution hard stop (Article III) — never crossed
Tier 1 must not extract the archive. Only `NoopSandbox` is wired; real
reproduction needs a real sandbox and Mahdi's sign-off. The candidate stays a
candidate — the autonomous loop reaches it and records a **`verify_escalation`**,
never a run. **Every test in the module runs with `TarFile.extractall` and
`TarFile.extract` monkeypatched to raise**, so any accidental extraction fails the
build loudly.

### Acceptance (all green in CI)
1. The rule flags exactly the vulnerable `extractall` and skips the patched one.
2. The real ingest files **one candidate** Finding, tagged `CWE-22`, aliased to
   `CVE-2007-4559`, with ids from the session (not hardcoded) and a proposed repro.
3. The finding exports to valid OSV and `check` passes.
4. The repro is staged; the extraction sink is never executed; the hard stop is
   recorded as a `verify_escalation` with the candidate left unpromoted.
5. `deepthought playbook discover --sarif <detector-output>` on the fixture project
   produces the candidate through the shipped `DiscoverSession`.

## Tier 2 — cJSON heap over-read (issue #800) — **built**
`benchmarks/test_cjson_issue_800.py`. A deterministic rediscovery of the cJSON
heap out-of-bounds read (GitHub issue #800, fixed in 1.7.18): `cJSON_ParseWithLength`
on `{"1":1,` (7 bytes, no trailing NUL) over-reads in `parse_string` (CWE-125).
Ground truth is public and patched, so there is no disclosure risk — but the
reproduction **runs the target**, so it crosses the Article III execution hard stop
and required Mahdi's sign-off (granted, scoped to `cjson`, 2026-07-04).

### Pieces
- **The image** (`benchmarks/tier2/`) — a libFuzzer + AddressSanitizer harness
  (`harness.c`) around `cJSON_ParseWithLength` on pinned cJSON **v1.7.17**, the
  7-byte `trigger`, and a trusted authenticity wrapper (`runner.c`) as the
  entrypoint. Built as `deepthought/cjson-asan:tier2`.
- **The trusted wrapper** — `runner.c` forks the harness and returns exit **99**
  ONLY when the OS reports the child died by a deadly signal (`WIFSIGNALED`). A
  crash is credited on that code alone, so target-printed ASan text with any
  self-chosen exit cannot forge a reproduction (docker cannot tell a `SIGABRT`
  death from `exit(134)` by code — the wrapper's OS-level check can).
- **The real sandbox seam** — VERIFY reproduces the crash **only** inside the
  hardened `DockerSandbox` (`--network=none --read-only --cap-drop=ALL
  --security-opt=no-new-privileges --user 65534:65534`, memory/pid/cpu limits,
  `--pull=never`), and **only** with a valid `Signoff` scoped to `cjson` **and**
  `execution_enabled=True`. Missing runtime → `IsolationUnavailable` (fail closed);
  no sign-off → `SignoffRequired`; not enabled → `SandboxExecutionDisabled`.
- **ASan → evidence** — `parse_asan` distils the report to a typed `CrashReport`
  (error class, faulting access, top frames, stable dedup key). A header-only report
  (no access line and no frame) is refused as non-credible, so a crash is credited
  only on **structural** evidence. VERIFY pages the full report to the store and
  promotes candidate → verified **through the guard**, which requires the resolving
  `evidence_ref`.
- **Trust hardening (driven by the dual-gate review)** — before it trusts anything
  the image produces, `run()` **attests the image by content digest** and launches by
  the resolved `sha256:` ID (not the mutable tag, closing a tag-repoint TOCTOU); it
  **binds provenance** by reading the baked input back byte-for-byte against the
  stored repro; and it is **local-only, fail closed** — docker is pinned to the local
  daemon (`--context default` + stripped remote-endpoint env), and a runtime that
  cannot be pinned is refused rather than run off-host. The benchmark's own
  no-opt-in tests never contact the docker daemon.

### The execution hard stop (Article III) — crossed once, behind a sign-off
The module **SKIPS (never fails)** where docker or the ASan image is absent — the
sandbox fails closed rather than falling back to unisolated execution. The
non-executing sign-off refusals (no/expired/wrong-project sign-off, not-enabled,
missing runtime) are covered in `tests/test_sandbox_signoff.py`.

### Acceptance (green in CI where docker is present, else skipped)
1. NEW PROJECT registers cJSON (basis `permissive_oss`, scope the parser); the gate
   proceeds. MAP + DISCOVER file **one candidate** carrying `CWE-125` and an
   **informational** `detection` reference to issue #800 — **no** authoritative
   `cve`, **no** `advisory`/`fix` reference.
2. VERIFY runs the harness in the signed-off, enabled `DockerSandbox`; the crash
   reproduces (`heap-buffer-overflow READ 1` faulting `parse_string`), the ASan
   report is paged, and the candidate is promoted to **verified**.
3. verified is earned by evidence: a candidate whose `evidence_ref` does not resolve
   is refused by the lifecycle guard.
4. Megadodo drafts OSV + CVE 5.1 draft + CSAF 2.0 + OpenVEX; every artifact
   validates, the finding stays verified with no `cve` and no `advisory`/`fix`
   reference, and **nothing is transmitted** — a human sends.

## Round 2 — the vuln-rediscovery skill (corpus-driven generalization)

Tiers 1–2 prove the *pipeline* rediscovers one CVE each. Round 2 proves the platform
learns a reusable **detector per bug class** that generalizes to CVEs it never saw. Each
class calibrates on a seed and is scored on a held-out set, measured on the **real
package source at pinned vulnerable/patched SHAs** (`benchmarks/corpus/<class>/manifest.json`,
`benchmarks/harness/corpus_measure.py`). Rediscovery is line-precise: a *flagged* line's
own text must contain the sink probe in the vulnerable tree and not in the patched tree.

| Class (CWE) | Detector | Seed | Held-out generalization | Notes |
|---|---|---|---|---|
| Prototype pollution (1321) | `DT-PP-MERGE` (JS) | js-yaml CVE-2025-64718 | **2/3** | min-document miss: `hasOwnProperty`-polarity guard |
| SSRF (918) | `DT-SSRF-TAINT` (Python) | dify CVE-2025-0184 | **3/4** | seed swapped from mis-classed urllib3 (CWE-601) |
| XXE (611) | `DT-XXE-PARSER` (Java+Python) | tika CVE-2025-66516 | **1/3** | dom4j/JDOM2: fix is additive/reorder, signal persists |
| OS command injection (78) | `DT-CMDI-EXEC` (JS+Python) | node-glob CVE-2025-64756 | **3/4** | one command-hook sink persists after patch |
| Path traversal (22) | `DT-PATH-TRAVERSAL` (JS+Python) | decompress CVE-2020-12265 | **2/3** | aiohttp needs branch-sensitive containment reasoning |

The generalization log (`benchmarks/data/generalization-log.json`) versions the score
under a **regression bar** — no merged change may lower any class's rate. Discipline held:
CVEs with no authoritative NVD record are **dropped-with-reason**, seeds whose authoritative
CWE doesn't match the class are **swapped-with-reason**, and misses are documented as
improvement-loop fixtures — the numbers are the honest measurement, never gamed. The
sandbox tier (heap-overflow / UAF) executes target code and runs only behind the Article
III sign-off (`benchmarks/corpus/SIGNOFF-sandbox-tier.md`).

```bash
# reproduce a class on the real pinned trees (network); default runs skip these
DEEPTHOUGHT_BENCHMARK_NET=1 .venv/bin/python -m pytest benchmarks/test_prototype_pollution.py benchmarks/test_ssrf.py benchmarks/test_xxe.py
```

## Run it
```bash
uv pip install --python .venv -e ".[dev]"
.venv/bin/pytest benchmarks/            # the benchmark suite
.venv/bin/pytest                        # full suite (tests/ + benchmarks/)

# Tier 2 executes the target, so its sandbox tests need the ASan image; without
# docker or the image they SKIP (they never fail the build):
docker build -t deepthought/cjson-asan:tier2 benchmarks/tier2/
```
