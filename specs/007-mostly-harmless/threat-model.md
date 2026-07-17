# Threat model — Mostly Harmless profile (007)

A convenience mode on a safety-critical harness is dangerous precisely because it
looks harmless. Before writing the spec, a first-draft profile was put through an
adversarial red-team along the three load-bearing stops it promised to preserve.
**All three lenses returned "weakens."** None of the holes were in the gate code —
each was a way to feed the *unchanged* gate a weaker input, or to erode the
signal around a stop, under an "additive config" framing. This document records
those findings and maps each mitigation to the requirement and test that
neutralizes it, so the reasoning is not lost when the code is written.

The first-draft streamlines that were **rejected** as a result: auto-filling an
empty scope; a new `local_lab` authorization basis on the no-reference path; and a
profile-carried `state_path` / output-directory default.

## Lens 1 — authorization & scope (verdict: weakens)

- **F1.1 (HIGH) — durable whole-checkout scope via `default_scope_for_local=['.']`.**
  The draft auto-filled an empty `--scope` with `.`. Verified against the code:
  the gate HOLDs on `[]` but PROCEEDs on `['.']`; `scope._syntactically_safe('.')`
  is true and `resolve_within(root, '.')` equals the checkout root, and
  `MapSession`'s blank-entry guard is dodged because `'.' != ''`. Because scope is
  written into the persisted Project, the whole-tree grant is **durable** — every
  later session, even with the profile OFF, sees `['.']` and passes CHECK 4. This
  turns Article II's "empty means nothing is in scope, not everything" into its
  opposite.
  → **Mitigation:** do not auto-fill scope at all; empty stays HOLD with a helpful
  message. **FR-5**; tests **AC-2, AC-3**.

- **F1.2 (MEDIUM) — `local_lab` is an unverifiable ownership claim.** The gate
  cannot verify ownership; CHECK 2 fires only for `blackbox`, CHECK 3 only for
  `scoped_engagement`. So `local_lab` + `open_source` + any `local_path` +
  no reference PROCEEDS, extending the no-reference low-ceremony set from "own code
  + OSS" to "anything an operator labels a lab" — the broadest, least-falsifiable
  category.
  → **Mitigation:** add no new basis in v1. Any future `local_lab` requires a
  non-empty attestation reference and an explicit scope — never the no-reference
  path. **FR-6**; tests **AC-5, AC-6**; Open question 1.

- **F1.3 (MEDIUM) — an un-reviewed constitutional expansion.** Article II
  enumerates exactly three bases, and the constitution footer states amendments
  are themselves gated. A fourth *enforced* basis makes the gate accept an
  authorization the governing document does not name; if `constitution.md` is not
  amended in lockstep, the enforced surface silently exceeds the reviewed surface.
  → **Mitigation:** treat any new basis as an Article II amendment reviewed as
  such, with an enum↔constitution lockstep test. Deferred out of v1. **FR-6**;
  Open question 1.

- **F1.4 (MEDIUM) — flag-free loop removes the conscious-bound step and compounds
  F1.1.** A profile-default budget lets `loop` run without the operator ever
  bounding it; combined with auto-scope, a single flag-free run could recon the
  whole checkout unattended.
  → **Mitigation:** budget stays finite/frozen and is echoed; removing the scope
  auto-fill (F1.1) removes the dangerous compounding. **FR-3, FR-11**; tests
  **AC-11, AC-12, AC-13**.

## Lens 2 — execution / Article III (verdict: weakens)

- **F2.1 (MEDIUM) — `terse_output` dims the execution-stop signal.** The draft's
  `terse_output` cited the `verify` "no execution — sandbox sign-off pending"
  banner in its mechanism, and env-activation applies it to every invocation
  silently. Refactoring that banner block also puts new code around the hard-stop
  refusal.
  → **Mitigation:** scope terse strictly to informational banners on read-only
  verbs; the sign-off refusal and dry-run banner always render in full; the
  refusal stays the literal first statement of the command body. **FR-7, FR-8**;
  tests **AC-10, AC-7**.

- **F2.2 (MEDIUM) — coupling the exec-gating command to the profile subsystem.**
  Adding `--profile` to `verify` — the one command whose only theoretical path to
  execution is its refusing flag — couples it to a new `profile.py` that could
  import the already-exported `DockerSandbox` the CLI deliberately never imports.
  → **Mitigation:** structural/AST test that `cli.py` and `profile.py` never
  import an executing backend; `verify` constructs only `NoopSandbox` dry-run
  under every profile value; `Profile` carries no sandbox field. **FR-8**; tests
  **AC-9, AC-8**.

- **F2.3 (LOW) — `local_lab` as latent execution pressure.** A basis narrated as
  "safe to run in my lab" creates pressure to later wire real execution for it.
  → **Mitigation:** no new basis in v1; were one added, an invariant test must
  assert it confers zero execution privilege. **FR-6**; Open question 1.

- **F2.4 (LOW) — hands-off loop must still hard-stop on candidates.** A flag-free
  loop plus auto-next-steps yields a fully unattended run that must still escalate,
  not silently advance, any candidate needing reproduction.
  → **Mitigation:** loop repertoire frozen; candidates become `verify_escalation`;
  `auto_next_steps` never applies to a verify session. **FR-11, FR-9**; tests
  **AC-13, AC-12, AC-14**.

## Lens 3 — disclosure / Article V (verdict: weakens)

- **F3.1 (HIGH) — off-machine leak via a profile-carried output path.** The draft's
  `Profile.state_path` (and a possible `--out` default), combined with a flag-free
  loop, means drafts written under that directory. Nothing validates the directory
  is local; a synced/networked path (Dropbox/iCloud/OneDrive/NFS/SMB) replicates
  every embargoed draft off-machine automatically — no DeepThought network code
  required. The drafts' physical location *is* the Article V machine boundary.
  → **Mitigation:** drop `Profile.state_path` and any output-path default
  entirely. **FR-10**; test **AC-16**. Optional backstop: a `check` assertion that
  `--out`/`--state` are local/non-synced/non-symlink (Open question 4).

- **F3.2 (MEDIUM) — loop autonomy amplifies the send surface.** The only thing
  between "draft everything automatically" and "send" is that the runnable
  repertoire excludes `disclosure_send`. The profile removes the per-run human
  keystroke, so that structural exclusion must be un-loosenable.
  → **Mitigation:** freeze the repertoire independent of any profile; no `Profile`
  field can register a session kind. **FR-11**; test **AC-12**.

- **F3.3 (MEDIUM) — `auto_next_steps` overwrites the "sending is human" record.**
  The disclosure next-steps and loop teach-back are the persisted signal that a
  human send is still owed; auto-filling "complete; no follow-up required" would
  erase it and make an embargoed finding look finished.
  → **Mitigation:** `auto_next_steps` structurally inapplicable to disclosure, to
  any session with non-empty `findings_touched`, and to the loop teach-back.
  **FR-9**; test **AC-14**.

- **F3.4 (LOW) — terse elides the "not transmitted / human must send" notice.**
  Collapsing the publish/disclose human-gate banner raises the chance an operator
  treats drafts as sent.
  → **Mitigation:** the terse banner must preserve "nothing was transmitted" and
  "a human must review and send." **FR-7**; test **AC-15**.

## Residual posture

With the three rejected streamlines removed and the mitigations above encoded as
requirements, the profile changes only: a finite default loop budget, a
read-only `--root` default, terse *informational* banners on read-only verbs,
truthful auto next-steps for read-only finding-neutral sessions, and a read-only
introspection command. It writes no scope, defaults no basis, carries no output
path, adds no gate class, and cannot extend the loop repertoire. The four
load-bearing stops are asserted to behave identically with the profile on and off
by the **AC-1 default-mode-byte-for-byte** and the per-stop tests above. Whether
`local_lab` ever earns its place is left as a gated constitutional decision, not a
convenience default.
