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
