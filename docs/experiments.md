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
- One model (Gemini 3.1 Pro) declined on safety-policy grounds, including after a
  narrowly-scoped retry. Its outcome is recorded as a **policy refusal** — a
  task-completion failure with detector score **N/A**, never a measured 0. A 0
  would falsely imply a detector was built and evaluated; nothing was.
- A scoring artifact (a stray module shadowing the standard library) briefly produced a wrong
  number before it was caught and corrected — a reminder that these harnesses need scrutiny.

The durable takeaway is only this: **a fixed corpus with hidden held-out is the honest way to
measure**, and it is how the rediscovery numbers above are produced.

---

## 3. Direct rediscovery eval — find-the-bug on the fixed corpus (preliminary)

Section 2 measured a model *building a detector*. A lighter, complementary instrument asks the
sharper question directly: given the real vulnerable source of a held-out CVE, can a model find the
sink **line-precise** and name the class? [`benchmarks/model_rediscovery_eval.py`](../benchmarks/model_rediscovery_eval.py)
feeds each held-out CVE's pinned vulnerable file(s) to a model and scores its answer against the
corpus `sink_probe` — the exact rule the deterministic detectors are graded on (a located line's own
text must contain the sink probe, and must actually appear in the source, to guard against a
hallucinated line). Honest by construction: fixed/blind corpus the model never curated, **refusal →
N/A (never a measured 0)**, pin-or-drop, exact fractions, **single-sample**.

A panel over the 39 held-out CVEs (reasoning effort held at `-high`, read-only, answer-only):

| Model | Located (line-precise) | CWE classified | Refused | Dropped |
|---|---|---|---|---|
| `gemini-3.5-flash-high` | 14/32 (44%) | 25/32 | 5/39 | 2 |
| `gemini-3.6-flash-high` | 6/17 (35%) | 12/17 | **20/39** | 2 |
| `gpt-oss-120b-medium` (contrast) | 16/37 (43%) | 26/37 | 0/39 | 2 |

**The notable result is a refusal regression, and it was verified.** `gemini-3.6-flash-high`
declined ~half the corpus (20/39, across 11 classes) — even to *identify* a **known, already-patched,
public** vulnerability in read-only source. Sampled raw replies were genuine policy declines
("Sorry, I cannot fulfill your request to analyze or find vulnerabilities in the provided code…"),
reproduced on re-run and distinguished by the harness from *tooling* failures (a headless
tool-permission denial or timeout is retried and dropped, never scored as a refusal or a miss —
conflating the two was a real bug caught and fixed before these numbers were taken). The *newer*
Gemini flash refuses defensive analysis far more than 3.5-flash (5) and than the open contrast model
(0), echoing and worsening the Gemini-3.1-Pro refusal noted above. On the subset each model *did*
answer, the three cluster (~35–44%): no model is clearly better at find-the-bug, and the hard classes
are hard for everyone (XXE 0 across all, SSTI / NoSQL / prototype-pollution mostly 0) — the walls are
**task-structural, not model-specific**.

**Read this as narrowly as the note above.** It is **single-sample** (model non-determinism is real
— one case flipped refuse↔answer between runs); it is a **different task** from the section-2
detector-build numbers, so it is **not comparable** to them; it is **not a leaderboard**. In
particular `gemini-3.6-flash`'s rate is computed only over the subset it *chose* to answer — refusals
are not missing-at-random, so its 6/17 is not apples-to-apples with a model that answered everything.
Two CVEs whose single source file exceeds the single-prompt cap are dropped (never truncated, which
could hide the sink). Raw per-entry results:
[`benchmarks/data/model-rediscovery-eval.json`](../benchmarks/data/model-rediscovery-eval.json).
