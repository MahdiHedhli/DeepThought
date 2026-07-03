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
  (`harness.c`) around `cJSON_ParseWithLength` on pinned cJSON **v1.7.17**, and the
  7-byte `trigger`. Built as `deepthought/cjson-asan:tier2`.
- **The real sandbox seam** — VERIFY reproduces the crash **only** inside the
  hardened `DockerSandbox` (`--network=none --read-only --cap-drop=ALL
  --security-opt=no-new-privileges --user 65534:65534`, memory/pid/cpu limits,
  `--pull=never`), and **only** with a valid `Signoff` scoped to `cjson` **and**
  `execution_enabled=True`. Missing runtime → `IsolationUnavailable` (fail closed);
  no sign-off → `SignoffRequired`; not enabled → `SandboxExecutionDisabled`.
- **ASan → evidence** — `parse_asan` distils the report to a typed `CrashReport`
  (error class, faulting access, top frames, stable dedup key). VERIFY pages the
  full report to the store and promotes candidate → verified **through the guard**,
  which requires the resolving `evidence_ref`.

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

## Run it
```bash
uv pip install --python .venv -e ".[dev]"
.venv/bin/pytest benchmarks/            # the benchmark suite
.venv/bin/pytest                        # full suite (tests/ + benchmarks/)

# Tier 2 executes the target, so its sandbox tests need the ASan image; without
# docker or the image they SKIP (they never fail the build):
docker build -t deepthought/cjson-asan:tier2 benchmarks/tier2/
```
