# Deep Thought Constitution

The platform is an autonomous security-research system. An autonomous loop is
only safe behind gates. These nine articles are the gates. They are
non-negotiable and load into every session. Where an article and a convenience
conflict, the article wins.

> Working title in earlier drafts was "Anvil". The platform is **Deep Thought**;
> the orchestrator is **Deep Thought core**; the workers are **Marvins**.

## Article I — Gate-first

Every session passes the pre-dispatch Gate before any work. The Gate returns
exactly one of three outcomes — `proceed`, `hold`, `refuse` — and every `hold`
and `refuse` records a reason. No session does scoped work ahead of a `proceed`.
The harness enforces this ordering; it is not left to the agent's discretion.

## Article II — Authorization and scope

Every Project carries an authorization basis (`own_code`, `permissive_oss`, or
`scoped_engagement`) and a scope allowlist. A session against a project with no
authorization basis is refused at the Gate. A `blackbox` target with no
authorization reference is refused. A `scoped_engagement` names its reference. An
empty scope allowlist means nothing is in scope, not everything.

## Article III — Sandbox

No target code executes outside an isolated, egress-controlled sandbox. Feature
001 executes no target code at all, so there is nothing to sandbox yet; the
sandbox lands in feature 003 before any `VERIFY` session may run code. This
article is honored in 001 by sequencing: capability that needs a sandbox does
not exist until the sandbox that contains it does.

## Article IV — Evidence and lifecycle

A finding advances only on evidence. The lifecycle is guarded at the Store
boundary, not at the session:

- `candidate → verified` requires a non-empty `evidence_ref` that resolves.
- `verified → disclosed` requires a CVE and an advisory reference.
- `verified → patched` requires a CVE and a fix reference.
- An illegal transition is rejected and its blocking reason is recorded on the
  finding; the status is unchanged.
- Backward transitions are allowed and logged when evidence weakens.

## Article V — Coordinated disclosure

Disclosure leaves the machine only past a human. `publish` prepares local
artifacts and asserts a human gate; it never transmits. Drafting may be done by
an agent; sending is done by a person.

## Article VI — Durable state

State is the asset, not the chat log. Every session learns current state, works,
then teaches the platform back: findings, coverage, and a session log with
explicit next steps. State is version-controlled, human-readable, and read and
written only through the Store interface. A session with no next steps is
incomplete and does not close.

## Article VII — Validate-first

Test-first. `check` is a required hard gate before `publish`; it validates
schema, lifecycle legality, reference integrity, project identity, and OSV
conformance. A `check` that errors or times out counts as a failed check, not a
pass. Code arrives with the tests that constrain it.

## Article VIII — Injection resistance

Workers return only a schema-validated, length-capped envelope. The orchestrator
ingests the envelope and never worker free-text. A prompt-injected worker cannot
propagate the injection past the typed boundary: there is no free-text field the
orchestrator interprets as instruction, hints never act on their own, and
`detail_ref` content is never loaded into orchestrator context. The envelope
schema is the firewall — a structural property of the topology, not a filter.

## Article IX — Minimalism and least privilege

Workers hold the minimum context and capability for one task. The orchestrator
keeps a bounded working set — a primitive ledger and an exploit graph — and pages
detail to the Store rather than holding it. The autonomous loop cannot expand its
own scope; scope changes require a new, gated authorization. Added structure must
buy context economy or a safety property, or it does not earn its place.

---

**Ratified:** 2026-06-30. Amendments are themselves gated: a change to this
document is a change to the platform's safety envelope and is reviewed as such.
