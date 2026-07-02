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

## Tier 2 — cJSON memory-safety — **out of scope here**
Tier 2 crosses the execution hard stop (it needs a wired sandbox to actually run a
memory-safety reproduction) and therefore requires a real sandbox and Mahdi's
sign-off. **Do not start it from the Tier 1 work.**

## Run it
```bash
uv pip install --python .venv -e ".[dev]"
.venv/bin/pytest benchmarks/            # the benchmark suite
.venv/bin/pytest                        # full suite (tests/ + benchmarks/)
```
