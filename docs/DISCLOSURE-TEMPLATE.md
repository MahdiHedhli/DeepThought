# Deep Thought: Disclosure Template & Pre-Send Triage Gate

Disclosure leaves the machine only past a human (Constitution Article V). Drafting is
machine-assisted; **sending is done by a person.** This template is the shape a draft
takes; the mechanics are the feature-005 `DisclosureSession`
(`src/deepthought/sessions/disclosure.py`), which emits the artifacts below and
asserts the human gate without transmitting.

## What the machine drafts (never sends)

`DisclosureSession` prepares, as local artifacts only:

- **OSV** record (severity basis, affected ranges, references).
- **CVE 5.1** JSON draft.
- **CSAF 2.0** document.
- **OpenVEX** statement.

Every artifact validates through `check` before it is considered drafted. The finding
stays `verified` — the machine never sets an authoritative `cve`, `advisory`, or `fix`
reference (those require a human or a verified process, per Article IV and the
benchmark's disclosure boundary).

## Draft narrative shape

1. **Reproduction first.** Lead with the minimized repro and the evidence — the
   sanitizer crash (sandbox tier) or the static/taint finding with the SARIF rule id
   (deterministic tier). Evidence before claim.
2. **Honest attribution.** Name the tool as **machine-assisted rediscovery**. State the
   detector rule id and that a human is triaging.
3. **No overstatement.** Impact is described conservatively and only as the evidence
   supports. No speculative exploit chains, no severity inflation.
4. **Patched-shape note.** State the fix/patched shape the detector discriminates
   against, so a triager can confirm the report is not a false positive on fixed code.

## Pre-send triage gate (human)

Before anything leaves the machine, a person:

- Reads the full draft and confirms the reproduction is real and correctly scoped.
- Confirms the target authorization and that the finding is in scope.
- Sets any authoritative `cve` / `advisory` / `fix` reference — the machine never does.
- Decides whether, when, and to whom to send. The machine's job ends at a validated,
  human-readable draft.

For the rediscovery benchmark every target is **public and already patched**, so drafts
are exercised end-to-end but there is nothing new to disclose — the gate is proven, not
crossed.
