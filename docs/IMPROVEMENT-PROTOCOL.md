# Deep Thought: Skill Improvement Protocol (standing)

The corpus build is the baseline, not the finish line. This protocol keeps the
`vuln-rediscovery` skill compounding after the ten classes are built, so it climbs
with the bug landscape instead of freezing at day-one accuracy.

Two loops, kept separate. The build loop iterates within a class until it passes.
This improvement loop iterates across the skill's whole life, feeding every real
result back into the detectors. Only the second one makes it a skill rather than a
fixed ruleset.

## The flywheel

Miss, add fixture, generalize, re-measure. Every real result feeds it, whether a
held-out miss during the build or a triaged finding from a live hunt.

1. **Miss.** A detector fails to catch a real CVE of its class. The held-out set
   surfaces these during the build. Live hunts surface them afterward.
2. **Add fixture.** The missed CVE becomes a new fixture, a vulnerable and patched
   pair, added to the class.
3. **Generalize.** Tighten the detector until it catches the pattern, without
   overfitting to that single CVE. The rule still has to fire on the rest of the
   class, not just the new fixture.
4. **Re-measure.** Re-run the full held-out set. Confirm the fix did not regress
   any other case, then log a new snapshot.

## The regression bar

The held-out set is the detector's permanent test, not a one-time gate. No
detector change ships if it lowers any class's held-out rate. This is enforced in
`benchmarks/harness/roundrecord.py`: build a candidate `Snapshot`, and
`GeneralizationLog.accepts(candidate)` is true only when it regresses no class. A
fix for one miss that quietly drops another is rejected.

## Miss to fixture

Additions come from real misses, not speculative hardening. A `HeldOutResult`
records `missed_cves`, the exact CVEs the detector did not catch. Each becomes a
fixture. Do not invent fixtures to feel thorough. Do not add a detector branch for
a bug no real CVE demonstrates. The corpus grows only from ground truth.

## The living metric

The generalization table is versioned over time in a `GeneralizationLog`, captured
from round one. Show the curve, not a single number. A rate that climbs from 78 to
96 to 100 across versions is a stronger story than a lone figure, and it is what
goes in the README as the skill matures.

## The real-world feedback path

A triaged finding from an actual hunt loops back the same way a held-out miss
does. If it is a gap in an existing class, add it as a fixture and improve the
detector. If it is a class the skill does not cover yet, spawn a new class section
through the normal build contract. Either way it enters through fixtures and the
regression bar, never as a one-off patch.

## Discipline, not churn

Continuous improvement is not continuous churn. The same restraint the sandbox
loop needed applies here.

- The regression bar clears before any change merges.
- Improve on a real miss, not on noise. No tuning against speculative inputs.
- Cap improvement rounds per change. If a round yields only noise or out-of-scope
  ideas, stop and take the human decision. Do not rebuild the many-round problem
  inside a single detector.

## The boundary

The detectors improve continuously. Deep Thought's own discipline does not drift
with them. This loop touches detectors, fixtures, and the skill file only. It
never modifies the constitution, the gates, the sandbox, or the disclosure
boundary. Those are out of scope for improvement and are changed only through
their own deliberate process. You are compounding the hunting rules, not eroding
the platform's guardrails.
