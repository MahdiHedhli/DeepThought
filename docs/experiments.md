# Early experiments

> **These are early, exploratory experiments.** The numbers below are preliminary, come from
> small internal corpora, and should be read as directional signals — not settled benchmarks.
> Methods, corpora, and results are expected to change. Nothing here should drive an operational
> or disclosure decision.

DeepThought is a harness; these experiments are early research programs running on it. They are
kept out of the main pitch on purpose. What matters more than any single number is the
*discipline*: real code at pinned SHAs, calibrate-on-seed-only, line-precise scoring, pin-or-drop,
and honest reporting of misses.

---

## 1. Vulnerability-class rediscovery (preliminary)

The [`vuln-rediscovery`](../skills/vuln-rediscovery/) skill builds a static detector for a
vulnerability *class*, calibrated on a single **seed CVE** and graded on **held-out CVEs it was
never tuned on** — real package source pinned to vulnerable and patched commit SHAs, not synthetic
fixtures. The goal is a rule for the class, never a signature for one CVE.

<div align="center">

<img src="assets/rediscovery-classes.svg" alt="Held-out generalization by class" width="820">

<img src="assets/rediscovery-curve.svg" alt="Mean generalization, v1 to v12" width="820">

</div>

| Class | Detector | Language | Held-out |
|---|---|---|:--:|
| Deserialization · CWE-502 | `DT-DESERIAL` | JS · Python · Java | 3/3 |
| LDAP injection · CWE-90 | `DT-LDAP-FILTER` | Java · Python · PHP | 3/3 |
| Open redirect · CWE-601 | `DT-OPEN-REDIRECT` | Python | 3/3 |
| SSTI · CWE-1336 | `DT-SSTI-TEMPLATE` | Python · JS | 4/4 |
| CRLF injection · CWE-113 | `DT-CRLF-HEADER` | Python · Go | 3/3 |
| SSRF · CWE-918 | `DT-SSRF-TAINT` | Python | 3/4 |
| Command injection · CWE-78 | `DT-CMDI-EXEC` | JS · Python | 3/4 |
| Prototype pollution · CWE-1321 | `DT-PP-MERGE` | JavaScript | 2/3 |
| Path traversal · CWE-22 | `DT-PATH-TRAVERSAL` | JS · Python | 2/3 |
| SQL injection · CWE-89 | `DT-SQLI-QUERY` | Python · PHP | 2/3 |
| NoSQL injection · CWE-943 | `DT-NOSQL-OP` | JS · Python | 2/3 |
| XXE · CWE-611 | `DT-XXE-PARSER` | Java · Python | 1/3 |

**Preliminary mean held-out generalization: ~79%** across twelve classes, versioned under a
regression bar (no class rate may drop when a new one lands). XXE sits at an honest 1/3 — its
fixes disable DTD processing in configuration, which a line-precise static rule legitimately
cannot always discriminate. That ceiling is reported, not hidden. Unresolvable CVEs are dropped
with a reason; misses become regression fixtures.

Sources: [benchmark report](../benchmarks/deep-thought-benchmark.md),
[rediscovery corpus](../benchmarks/rediscovery-corpus.md),
[generalization log](../benchmarks/data/generalization-log.json).

```bash
DEEPTHOUGHT_BENCHMARK_NET=1 .venv/bin/python -m pytest benchmarks/test_xxe.py
```

---

## 2. Cross-model field note (preliminary, very rough)

Because the harness is model-agnostic, the same rediscovery task was run through several frontier
models under two conditions. This surfaced a methodology observation worth recording.

<div align="center">

<img src="assets/model-standardization.svg" alt="Self-curated held-out vs a blind fixed corpus" width="820">

</div>

When a model **curates its own held-out set**, generalization looks strong (≈ 80–90%). When the
*same* detectors are graded against a **fixed, hidden corpus the model never saw** — train (seed)
and test (held-out) cleanly separated — real single-seed generalization drops roughly
**four-fold**, to ≈ 20%.

**Read this narrowly.** It is a floor on single-seed generalization and a caution about
self-graded benchmarks — **not a model leaderboard**. Caveats that swamp any ranking:

- The absolute numbers come from a small, caveated internal corpus.
- Reasoning-effort settings differ per harness and are not comparable knobs.
- One model declined the task on safety-policy grounds rather than engaging.
- A scoring artifact (a stray module shadowing the standard library) briefly produced a wrong
  number before it was caught and corrected — a reminder that these harnesses need scrutiny.

The durable takeaway is only this: **a fixed corpus with hidden held-out is the honest way to
measure**, and it is how the rediscovery numbers above are produced.
