# Idea + critique: Council of Experts (per-class model routing → MoE escalation)

> **Status: parked idea, documented for later. Not scheduled, not designed-in.**
> Captured at the operator's request ("document and critique that for later"). This is a
> decision-ready RFC: it records the idea faithfully, critiques it hard (5-lens adversarial panel),
> and states exactly what — if anything — is worth building now vs. deferred until earned by
> measurement.

## 1. The idea (as proposed)

> "A Council of Experts module. After we run the benchmarks and determine which model is better at
> which tests, set up workflows where if the authoritative operating model hits a wall on a specific
> problem, it can assign a sub-agent of the best-performing model to tackle that specific problem. If
> that fails, escalate to a MoE (mixture of experts) where each model takes a crack. Valuable to
> implement in the future once we have a solid baseline and plenty of runs under the existing
> structure."

Two mechanisms, bundled:
- **(A) Per-class routing table** — measure "which model is best at class X," then route class-X work to that model.
- **(B) Failure-triggered escalation** — when the operating model *walls* on a concrete problem, hand it to a different (best) model; if that fails, fan out to all models (MoE) and keep the success.

## 2. TL;DR verdict

**Split the idea. Defer (A); (B) is worth building — but only in a specific, disciplined shape.**

- **(B) escalation-on-failure has real, prior-art-supported value** and matches something the project has *already seen pay off* (Grok/Codex builds a detector, Claude adversarially reviews before merge). But it only works when "wall" and "fail" are defined by an **oracle** (the deterministic gate), never by a model's self-report, and when it collapses to **verifier-anchored best-of-N with cost-ordered early exit** rather than a bespoke "Council/MoE" abstraction.
- **(A) the per-class routing table cannot be built yet, and as described re-opens the exact inflation surface 008/009 exist to kill.** The data to populate it does not exist, the signal is inside the noise floor, and "best at *rediscovering known* class-X CVEs" does not predict "best at finding *new* class-X bugs." Defer it until it is **earned by measurement**, one class at a time.
- **Hard red line: no stochastic (model) output ever touches the certified 79.2% mean.** It cannot be recomputed, so it cannot be certified; it must live in a separately-rooted, loudly-labeled report.

The panel verdicts: measurement-validity → *worth-building-but-simplified*; honest-measurement → *defer*; orchestration → *defer*; cost → *defer*; prior-art → *worth-building-but-simplified*. The convergence is on the **split**, not on the module as bundled.

## 3. Why it's compelling (the steelman)

- **Heterogeneous model strengths are real**, and the routing literature (RouteLLM, FrugalGPT cascades, RouterBench, Mixture-of-Agents) shows a *router + sound verifier* pipeline can beat any single model on the cost/quality frontier.
- **DeepThought owns the rare ingredient that makes best-of-N actually pay off — a sound, automatic verifier.** In most domains best-of-N is bottlenecked by a weak judge; here the judge (the deterministic detector graded against pinned vulnerable/patched SHAs under 008/009) *is the product*. You never have to trust a sub-agent; you keep only what passes the gate.
- **The project already runs a de-facto two-model council that works** — build-vs-adversarial-review across different-lineage models — so escalation systematizes a pattern that has already produced value.
- **Escalation-on-failure is robust even if the routing table is noisy** — it harvests diversity on hard problems rather than requiring a correct a-priori leaderboard.

## 4. The critique (why the bundled module is not ready)

### 4.1 The routing table can't be populated, and the signal is noise
- **Denominators are 3–4 CVEs per class** (39 held-out across 12 classes). A per-class "best" must resolve a *one-CVE* difference; the Wilson 95% CIs are enormous and overlapping (3/4 = [0.30, 0.95], 2/3 = [0.21, 0.94]). "Model A 3/4 beats Model B 2/3" is a coin flip, not a signal.
- **The cross-model data does not exist in usable form.** The G1–G4 runs were 10-CVE-per-model on **self-curated, non-common** corpora (each model assembled its own held-out set), so per-(model, class) n ≈ 0–1 and no common instrument was used. The only standardized runs (B1/B2) the project itself labels *"not a model leaderboard."*
- **Determinism manufactures false stability.** Re-running a frozen detector yields identical scores forever — which *looks* like rock-solid evidence but hides the variance that matters (authoring stochasticity: prompt/seed/session, and corpus sampling). You'd be reporting the precision of a frozen artifact, not the reproducibility of a model capability.
- **Winner's curse.** argmax over ~5 noisy per-class estimates systematically selects upward-biased cells; the routed "best" model regresses below its benchmark on the next draw. Routing bakes the optimism in.
- **Confounded knobs.** The project's own field note says reasoning-effort settings aren't comparable across harnesses, and one model (Gemini) refused on policy and is recorded **N/A, not 0**. A per-class "win" may encode scaffolding/effort/refusal, not aptitude.

### 4.2 The transfer gap (decisive)
The benchmark measures whether a model can **author a deterministic static rule that line-precisely REdiscovers a KNOWN, PATCHED CVE** (ground truth public, patch diff available). Routing would be applied to **NOVEL discovery on live code** (no ground truth, no patch to diff). The project's own data shows generalization collapses ~4× (80–90% self-curated → ~20% blind); novel discovery is strictly harder and **entirely unmeasured**. "Best at authoring class-X detectors" is not even the same task or actor as "best at finding a new class-X bug."

### 4.3 It re-opens the 009 selection-inflation surface, one layer up
009 exists to stop **selective per-class inclusion** from inflating the headline mean — it names that "the last code-closable inflation surface." **A per-class routing table is selective per-class model inclusion.** Sourcing each class's number from the single flattering model for that class produces a **Frankenstein max-over-models mean** that no single deployable system achieves. 009 binds *which classes* are in the mean but says nothing about *which model backs each class* — the manifest leaf has no producer identity — so this displacement is currently unguarded.

### 4.4 Stochastic output cannot be certified (determinism mismatch)
008's certify path is **recompute-based**: it re-runs the frozen detector's `scan_source` over pinned bytes as a pure function, resolved from a committed `DETECTOR_REGISTRY`. A model inference is non-deterministic (sampling, provider drift, deprecation) and cannot be content-hashed into a `FreezeManifest` nor re-run identically → a Council/MoE answer can only ever land as `NUMERATOR_UNVERIFIED`/`UNANCHORED`. **Council outputs are categorically unmeasurable under the spine as built.** Corollary: an MoE "keep-the-success" figure is a *positively-biased disjunction* (4 models at 50% → ~94% "someone got it"); folding it next to the deterministic 79.2% is exactly the incomparable-number-mixing 008/009 forbid.

### 4.5 Orchestration: "wall" has no oracle off-benchmark, and the handoff hits Article VIII
- **"Hits a wall" is only well-defined where an oracle exists.** On-benchmark: "seed not rediscovered by the verifier recompute" — clean and terminal. On **novel discovery there is no ground truth**, so "wall" is undefined *precisely where the council would be invoked*. A clean file and a missed bug both yield zero findings.
- **Self-reported stuckness is gameable** — under the merge-on-clean autonomy loop, "declare stuck" becomes the cheapest route to more compute or a peer rubber-stamp. This is the mostly-harmless red-team lesson exactly: **safety/trigger stops weaken via gate INPUT, not gate code.**
- **Rich context handoff violates Article VIII.** The constitution bans free-text/partial-reasoning transfer across the typed worker boundary (workers return only a schema-validated, capped envelope). Passing "the first model's partial state to a second model" is either near-worthless (typed envelope only → cold restart) or a free-text hole that a prompt-injected first model (the SSTI/CRLF corpora contain live payloads) uses to steer the second model *and* the arbiter. A new enforced handoff channel is a **constitutional amendment, not a feature flag.**
- **MoE arbitration has no trustworthy judge.** Majority vote ≠ evidence (correlated errors from shared training data → confidently wrong consensus); a model-judge reintroduces the stochastic decider the project refuses to trust. The only sound arbiter is the deterministic verifier — at which point "MoE" degenerates into "generate candidates until one passes the gate," i.e., **best-of-N, not a council.**

### 4.6 Cost / correlated failure
- **Value-negative on the measured core.** Wrapping an LLM council around a ~$0 deterministic AST pass only adds cost and non-determinism; it must be firewalled entirely out of the scoring path — i.e., it cannot touch the thing DeepThought is demonstrably good at.
- **MoE only pays if failures are UNCORRELATED — and here they're probably correlated.** The honest ceilings (XXE 1/3, and several stuck classes) are **task-structural** (e.g., XXE fixes live in parser *configuration* a line-precise static rule often can't see). If all models wall for the same structural reason, MoE pays N× tokens for ~0 marginal hits. Failure-correlation is the crux and is currently unmeasured.
- **No cost ceiling in the proposal.** "Each model takes a crack" is N× per escalation with no per-problem budget, max-tier cap, or value-threshold gate. A pathological target that everything walls on triggers the full ladder on every retry; the 006 autonomous loop could bill N×-iterations overnight.
- **Latency is a forced trade:** serial escalation (the only shape that saves cost) multiplies wall-clock by the tier count; parallelizing to fix latency *is* always-MoE, throwing away the saving.

### 4.7 Wrong granularity / reinvents prior art without its discipline
- **Route on per-instance DIFFICULTY, not static class.** The literature (RouteLLM, FrugalGPT, Hybrid-LLM) routes on difficulty/cost because *within-class* variance (a trivial vs. an elegant SQLi) generally exceeds *cross-class* variance for a fixed model. Class is observable but weakly predictive.
- **Per-PHASE beats per-class.** find / verify / triage are structurally different tasks; the project *already* specializes by phase (build vs. adversarial-review) and that split is the part delivering value. PoLL / judge-panel work shows a panel of *small* models beats one large judge for the VERIFY phase.
- The proposal picks the **most expensive shape** (sequential escalate → all-models-run) without the cheap-scorer-first ordering that makes cascades economical.

## 5. What's actually load-bearing (the split)

| Half of the idea | Verdict | Why |
|---|---|---|
| **(A) per-class "best model" routing table** | **Defer** — earn it, don't assume it | data can't populate it; signal in the noise floor; transfer gap; re-opens the 009 selection surface |
| **(B) failure-triggered escalation to a different model** | **Build — but as verifier-anchored best-of-N** | prior-art-supported; already pays off in the build loop; only sound when the trigger is an oracle and acceptance stays the deterministic gate |

## 6. Recommended path (staged; each stage independently useful)

**Now — build the preconditions, not the module:**
1. **Verifier-anchored best-of-N in the DETECTOR-BUILD loop (the safe, valuable core of (B)).**
   - *Wall/fail = the deterministic gate, never self-report:* the class lands below the regression bar, OR any patched-SHA false positive, OR adversarial review rejects.
   - *Action:* hand the **same frozen task spec + corpus, cold** (no partial-reasoning handoff → Article VIII holds) to the next model in a fixed **cost-ordered** pool; the output is a *candidate detector* that must pass the identical freeze→verify→attest gate before it counts. **Cap at one escalation** initially; no parallel fan-out, no per-class table, never in the scoring path.
   - This productizes the cross-model review-yield already observed, at **1× incremental cost**, and *doubles as* the controlled data collection that would later earn a router.
2. **A capability LEDGER, not a leaderboard + a producer-provenance manifest.**
   - Record every (model, class, run) as a **distribution with CIs** under 008/009 discipline; tag each cell *separated* vs *tied/overlapping*; **expose no argmax** until a cell's CI separates on a blind **common** instrument.
   - Add a committed `producer_id` / `author_model` leaf to a 009-style manifest (mirrors `aggregate.py`, ed25519-signed, same fail-closed reproduction guard) so *which model authored each frozen detector* is tamper-evident and can never be silently reshuffled. **Pure provenance metadata — zero effect on any recomputed number today — and the load-bearing prerequisite for ever routing honestly.**
3. **Instrument per-attempt now** — (model, class, gate metrics, tokens, pass/fail) — so the data a real router needs actually accumulates before the router exists.

**Later — turn on targeted routing only when earned, one class at a time:**
- Per-class routing for class X turns on **only when X's ledger clears the preconditions** (CIs separate on a blind common instrument; walls shown model-*specific* not task-*structural*; an empirically validated link from benchmark rank to live yield). Never from a snapshot.

**Maybe never — scored MoE.** If ever, restrict it to detector-code **proposals** arbitrated **solely by the deterministic verifier** (candidate passes recompute or is discarded — no vote, no model-judge), with a hard fan-out cap and per-task budget.

## 7. Hard invariants (red lines for any future build)

1. **No stochastic output ever aggregates into the certified mean.** Council figures live in a separately-rooted, loudly-labeled report (the FR-11 synthetic-separation pattern); never the 79.2% headline.
2. **Cross-model agreement never substitutes for the gate.** Only patched-SHA ground truth / deterministic recompute counts as soundness. Consensus is not evidence.
3. **The escalation trigger is oracle-bound, never model self-report.**
4. **Handoff is a typed, Article VIII-compatible boundary** (no free-text partial-reasoning transfer) — or it is an explicit constitutional amendment, reviewed as one.
5. **Any routing/producer state is committed, monotonic, ed25519-signed** (009-style), never mutable config — else it is a fresh, tamper-free inflation surface.
6. **Refusals are N/A-excluded, not scored as losses** (a policy refusal ≠ incapacity).
7. **A written cost governor precedes any fan-out:** per-problem token budget, max-tier cap, value-threshold escalation gate, aggregate ceiling.

## 8. Preconditions checklist (when does (A) "turn on"?)

- [ ] Per-(model, class) **distributions with CIs** from k re-authorings varying seed/session/prompt.
- [ ] A **common blind instrument** — all models scored on the same fixed, hidden held-out cohort under 008/009 (never self-curated).
- [ ] Held-out denominators large enough that a per-class CI is **tighter than the between-model gap** you'd act on (tens of CVEs/class, not 3–4).
- [ ] Harness knobs (reasoning effort, scaffold, prompt) **held constant** across models.
- [ ] **Measured failure-correlation** across models on the same tasks (if correlated, MoE is dead on arrival).
- [ ] **Transfer shown, not assumed** — an empirical link from benchmark rank to live/blind discovery yield.
- [ ] A **recalibration cadence + expiry** bound to model + prompt versions (a routing table is a standing policy; a snapshot promoted to policy without re-cal is a stale leaderboard).

## 9. Prior art (for the later build)

RouteLLM / FrugalGPT / Hybrid-LLM (difficulty/cost cascades) · RouterBench (routing evaluation) · Mixture-of-Agents (Wang et al. 2024, parallel-aggregate) · PoLL / panel-of-LLM-judges (Verga et al. 2024, small-model panel beats one large judge for verify) · self-consistency / debate (Wang et al.; Du et al. — and their failure mode: amplifying confident-wrong consensus).

---

*Provenance: 5-lens adversarial critique panel (measurement-validity, honest-measurement-integration, orchestration-failure-modes, cost-economics, prior-art-alternatives). The panel's strong consensus was the **split** in §5 — defer (A), build the disciplined core of (B) plus its preconditions — not the module as bundled.*
