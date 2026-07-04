# Deep Thought: Build the Vuln-Rediscovery Skill (autonomous, corpus-driven)

Feed this to the orchestrator. It builds a reusable hunting skill by calibrating
one bug-class detector per round against a seed CVE, proving each generalizes on
held-out CVEs, and capturing the data for the benchmark. Gate-first, test-first.

## Role and law

You are Deep Thought core. Read `.specify/memory/constitution.md` and `CLAUDE.md`
first. The corpus is `benchmarks/rediscovery-corpus.md`. The skill you are
building is `skills/vuln-rediscovery/SKILL.md`. Instrumentation is
`benchmarks/harness/roundrecord.py`.

## Objective

Build the `vuln-rediscovery` skill, one bug class per round, until the corpus is
complete. Every round appends a class section to the skill and emits a
RoundRecord. The corpus is a yardstick, not training data. Ship a rule for the
class, never a signature for the one CVE.

## Order

Do the seven deterministic classes first (prototype pollution, SSRF, XXE, path
traversal, deserialization, ReDoS, command injection). They execute no target
code and run in CI. Then the three sandbox classes (heap overflow, use-after-free,
the second overflow), each behind a sandbox sign-off. Depth on the foundation was
paid once. This is breadth on the corpus.

## Per-round contract

For the next seed CVE in the corpus:

1. Build the class fixture: a vulnerable sample and a patched sample in one file,
   so a single scan proves the detector discriminates.
2. Build the detector as a rule for the class. Static or taint emitting SARIF for
   the deterministic tier, a fuzz harness plus sanitizer for the sandbox tier.
   Do not hardcode the seed CVE's specific strings, paths, or identifiers. If the
   rule would not fire on a different package with the same bug, it is wrong.
3. Rediscover through the real pipeline: NEW PROJECT with basis `permissive_oss`
   scoped to the fixture, MAP, DISCOVER with the detector, `check`. For a sandbox
   class, VERIFY inside the signed-off sandbox.
4. Append the class section to `SKILL.md` using the template there: class, CWE,
   when to use, detection, rule id, verification, OSV and disclosure shape, and
   the patched-shape discriminator.
5. Run the held-out check. Point the finished detector at the class's held-out
   CVEs from the corpus, the ones it was never tuned on. Record rediscovered over
   total, the detector's precision and recall across those packages, and the exact
   CVEs it missed. Append a Snapshot to the generalization log with the harness.
   The missed CVEs are the input to the improvement loop below.
6. Emit a RoundRecord: wall seconds, tokens in and out, review rounds, findings
   fixed, lines changed, fixture precision and recall, held-out generalization,
   and the artifact paths. Write it under `benchmarks/data/`.

## Acceptance per class

All of these, or the class does not merge:

- The detector flags the vulnerable shape and skips the patched shape.
- It rediscovers the seed through the real pipeline, and `check` passes.
- It clears the held-out generalization bar on CVEs it never saw. Fixture pass
  alone is not acceptance. An overfit detector that only matches its seed is a
  fail, not a pass.
- It does not regress. `GeneralizationLog.accepts(candidate)` must be true, so no
  class's held-out rate drops. The held-out set is a permanent test, not a
  one-time gate.
- The disclosure boundary holds: analyzer and harness output is informational.
  Only a human or a verified process sets the authoritative `cve` or an `advisory`
  or `fix` reference.

## Review discipline (the revised loop)

The sandbox is already hardened and is not being changed here, so these are
benchmark rounds, not execution-surface rounds. Use the light bounded gate:

- Write the trust model and the out-of-scope list into the review brief up front.
- Merge bar is no open in-scope P0, P1, or real P2. Out-of-scope re-files,
  defense-in-depth beyond the stated model, and P3 polish are tracked issues, not
  blockers.
- Cap at two or three review rounds per class. If a round surfaces only
  out-of-scope or P3, stop and merge, do not iterate.
- The full adversarial gate applies only if a round changes execution surface or
  sandbox capability. It should not. If a class needs that, stop and flag it.

Push, run the gate, merge on the bar, commit as `MahdiHedhli`. NTFY on each class
merge and on the final skill completion.

## Data capture, per round, for the benchmark

Capture and store under `benchmarks/data/<cve>/`:

- A terminal session recording of the run (script or asciinema). This is the
  visual evidence for the docs. Headless runs have no screenshots, so record the
  session instead.
- The unified diff of the round, the SARIF or the sanitizer report, and the
  review verdicts.
- The RoundRecord JSON, and the metric snapshot.

At the end, aggregate with `roundrecord.py`: the build-cost table and the
generalization table. The headline is the mean held-out generalization across all
classes. That number, not a candidate count, goes in the README.

## Continuous improvement (standing)

The corpus build is the baseline, not the finish line. When the ten classes are
built, do not stop. Keep the flywheel running, per `docs/IMPROVEMENT-PROTOCOL.md`.

- Every held-out miss and every triaged finding from a live hunt becomes a new
  fixture for its class. Tighten the detector to catch the pattern without
  overfitting to that one CVE.
- Re-measure against the full held-out set. Merge only if
  `GeneralizationLog.accepts(candidate)` holds, then append a new Snapshot so the
  curve is captured.
- Additions come from real misses, not speculative hardening. If a finding is a
  class the skill does not cover, spawn a new class section through the build
  contract above.
- Discipline, not churn. Cap improvement rounds per change. If a round yields only
  noise or out-of-scope ideas, stop and take the human decision.
- Boundary. This loop touches detectors, fixtures, and the skill file only. It
  never modifies the constitution, the gates, the sandbox, or the disclosure
  boundary. Compound the hunting rules, do not erode the platform's discipline.

## Hard stops and safety

- Every target is public and already patched. This is rediscovery, not zero-day
  hunting.
- Execution only in the signed-off sandbox, no network, enforced limits.
- Disclosure is drafted, never sent. A human triages every draft before send.
- Keep SIBLING HUNT restraint. One well-characterized detector per class beats a
  pile of variants that read like a scanner dump.

## The real test

After all ten classes, the benchmark is the mean held-out generalization: how well
each detector finds its pattern in CVEs it never saw. Build cost, wall time, and
tokens are recorded for documentation. Generalization is the score.

And it is not a single number. The generalization log versions that score from the
first build snapshot onward, so the README shows the curve climbing as misses and
live findings fold back in. A rising curve under a regression bar is the proof
that the skill compounds.
