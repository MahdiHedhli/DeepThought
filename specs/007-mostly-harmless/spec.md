# Feature Spec: Mostly Harmless — Low-Friction Profile (007)

**Feature Branch:** `007-mostly-harmless`
**Created:** 2026-07-16
**Status:** Draft

## Problem

DeepThought's ceremony is calibrated for the highest-stakes case: a live,
blackbox, scoped engagement against someone else's production system. That
calibration is correct, and it is the point of the platform. But it is also paid
in full on the *lowest*-stakes case — an operator mapping their own repository, a
permissively-licensed dependency, or a deliberately-vulnerable practice app in a
local lab. On every read-only invocation that operator re-types `--state`,
re-types `--root`, must supply an explicit `--scope`, must hand the `loop` an
explicit budget or it exits 2, and reads multi-line human-gate teach-back after
work that executed nothing and transmitted nothing.

The naive fix — "fork it without the gates" — would delete the safety envelope
that makes DeepThought defensible at all. The interesting question is whether
the *ceremony* can be reduced without touching any of the four load-bearing
stops: authorization-and-scope (Article II), sandboxed execution behind a human
sign-off (Article III), no self-directed scope expansion (Articles II/IX), and
draft-only disclosure that a human transmits (Article V).

An adversarial red-team of a first-draft profile (recorded in
[`threat-model.md`](threat-model.md)) found that the three most tempting
streamlines each silently *weakened* a stop: auto-filling an empty scope with
`.` durably granted whole-checkout scope even with the profile off; a new
low-ceremony authorization basis was an unverifiable ownership claim CHECK 2
never guards for non-blackbox targets — and adding it is a constitutional
amendment, not "config"; and a profile-carried output path pointed at a synced
folder would replicate every embargoed draft off-machine with no DeepThought
network code. This spec is therefore defined as much by **what it refuses to
touch** as by what it streamlines.

## Goal

A named, opt-in, **purely ergonomic** `mostly_harmless` profile.

- **Opt-in and inert by default.** Activated by `--profile <name>` or the
  `DEEPTHOUGHT_PROFILE` env var (mirroring the existing `DEEPTHOUGHT_STATE`
  precedent). Unset means today's behavior, byte-for-byte.
- **Configuration, not authority.** The profile is frozen data (a new
  `src/deepthought/profile.py`) that fills unset CLI defaults and trims
  informational output. It feeds the *same* unchanged `DefaultGate` /
  `HermesUltraCodeGate`; it introduces no new gate class and no gate-logic
  change.
- **It streamlines only ceremony on read-only work** and provides a finite
  default loop budget. It changes no authorization decision, no scope, no
  execution posture, and no transmission boundary.

## Scope

**In scope**

- A frozen `Profile` registry and its resolution from `--profile` /
  `DEEPTHOUGHT_PROFILE`, default `None` (today's behavior verbatim), resolved
  per-invocation and **never persisted on the Project record**.
- A finite default `LoopBudget` so `loop` runs flag-free while staying bounded
  and frozen.
- Defaulting `--root` to `project.local_path` on the read-only verbs.
- `terse_output` for purely-informational post-work banners on the read-only
  verbs only.
- `auto_next_steps` truthful default `## Next steps` for read-only,
  finding-neutral clean sessions only.
- A read-only `deepthought profiles` introspection command.
- The full invariant test battery in [Acceptance criteria](#acceptance-criteria).

**Out of scope** (later features, behind their own gates and amendments)

- **Any new authorization basis** (e.g. `local_lab`). It would require a
  reviewed **Article II amendment** naming the basis and its exact
  reference/scope obligations, plus an enum↔constitution lockstep test. Deferred
  entirely; v1 adds no enum member.
- **Any scope auto-fill.** An empty scope stays a HOLD; the operator delimits the
  surface consciously.
- **Any profile-carried output/state path default.** Dropped as an off-machine
  exfiltration vector.
- Any change to the `verify`, `disclose`, or `publish` control flow; any
  execution wiring; any change to `scope.py`, the sandbox path, the envelope
  firewall, or the loop's runnable repertoire.
- Global refusal of root-equivalent scope areas (`.`/`./`/trailing-slash) — a
  defensible defense-in-depth hardening, but it changes default-mode semantics
  and so must be its own change, not smuggled in here (see Open questions).

## User scenarios

1. **Own-code recon loop, flag-free.** An operator registers their own repo with
   an explicit `--scope src`, then runs `deepthought loop --profile
   mostly_harmless --project my-app`. The loop bounds itself with the profile's
   finite default budget, auto-advances only read-only sessions, and surfaces any
   candidate as a human `verify_escalation`. No budget flag was typed; the run is
   still bounded and the effective budget is printed.

2. **Local OSS map without re-typing `--root`.** With the profile active,
   `deepthought playbook map --project lodash` defaults `--root` to the project's
   `local_path`. Every mapped area still passes `scope.py` containment; nothing
   outside the checkout is reachable.

3. **Audit the profile before trusting it.** `deepthought profiles` prints the
   exact defaults `mostly_harmless` would apply — budget, root default, terse and
   auto-next-steps flags — and changes no state.

4. **An engagement is unaffected.** With no profile set, a scoped-engagement
   operator sees the platform behave exactly as in features 001–006: empty scope
   HOLDs, `loop` still exits 2 without a budget, every human-gate banner renders
   in full.

5. **Misuse is still refused with the profile on.** Under `mostly_harmless`: a
   basis-less project still REFUSES; an empty scope still HOLDs (no default is
   invented); a blackbox target still needs a reference; `verify
   --i-have-sandbox-signoff` still refuses and executes nothing; `disclose` still
   writes only local drafts and transmits nothing.

## Functional requirements

- **FR-1 — Opt-in, per-invocation resolution.** A `--profile <name>` option and a
  `DEEPTHOUGHT_PROFILE` env var resolve to a frozen `Profile`; unset is default
  mode. The active profile is resolved per invocation and is **never written to
  the Project record**, so no project silently carries low-ceremony defaults
  (Constitution VI, IX).

- **FR-2 — Data, not authority.** The profile is frozen configuration consumed as
  gate *input* and CLI *defaults* only. It adds no `Gate` subclass; the CLI keeps
  instantiating the existing gate; `gate.evaluate`, `scope.py`, the sandbox path,
  the disclosure boundary, the envelope firewall, and the loop's runnable
  repertoire are unchanged (Constitution I, VIII, IX).

- **FR-3 — Finite default budget.** Under the profile, `loop` with no `--max-*`
  flag constructs a `LoopBudget` from finite profile defaults instead of exiting
  2. The result still satisfies the ≥1-positive-finite-limit invariant and stays
  `frozen`; the effective budget is echoed in run output; an explicit flag always
  overrides (Constitution IX).

- **FR-4 — Read-only root default.** Under the profile, `--root` defaults to
  `project.local_path` on `map`, `discover`, and `sibling-hunt`.
  `scope.py` `resolve_within` / `area_in_scope` still refuse every area escaping
  that root (Constitution II).

- **FR-5 — Scope is never auto-filled.** The profile MUST NOT write, default, or
  widen `scope_allowlist`. An empty allowlist still yields CHECK 4 HOLD; the CLI
  emits a helpful "pass `--scope`" message rather than manufacturing a default.
  There is no `default_scope_for_local` (Constitution II, IX).

- **FR-6 — No new authorization basis.** The profile adds no `AuthorizationBasis`
  member and never supplies, guesses, or defaults a basis. CHECK 1/2/3 hold
  identically. Any future low-ceremony basis is out of scope and gated behind a
  reviewed Article II amendment with an enum↔constitution lockstep test
  (Constitution II).

- **FR-7 — Terse banners, read-only only.** `terse_output` collapses only
  purely-informational post-work banners on `status`/`map`/`discover`/
  `sibling-hunt`. It MUST NOT touch the `verify` sign-off refusal or the "no
  execution — sandbox sign-off pending" dry-run banner, and MUST preserve, on
  `publish`/`disclose`, the clauses "nothing was transmitted" and "a human must
  review and send" (Constitution III, V).

- **FR-8 — Verify stays isolated.** The `verify` command constructs only a
  `NoopSandbox` dry-run under every profile value; the `--i-have-sandbox-signoff`
  refusal remains the literal first action of the command body, before any
  profile resolution; and neither `cli.py` nor the new `profile.py` imports or
  references `DockerSandbox` or any executing backend. The `Profile` type carries
  no sandbox or execution field (Constitution III).

- **FR-9 — Auto next-steps, read-only clean sessions only.** `auto_next_steps`
  fills a truthful default `## Next steps` only for a read-only session
  (`status`/`map`/`discover`/`sibling-hunt`) that did in-scope work and changed no
  finding state. It is structurally inapplicable to `DISCLOSURE`, to any session
  with non-empty `findings_touched`, and to the loop teach-back; those retain
  their full human-gate text. An interrupted/exception path still leaves the
  session interrupted (Constitution VI, V).

- **FR-10 — No output-path default.** The `Profile` type carries no `state_path`
  or output-directory default; drafts and artifacts are never written to a
  profile-chosen location. The physical location of drafts is the machine
  boundary and is not a convenience knob (Constitution V).

- **FR-11 — Loop repertoire frozen.** Under any profile, the loop's runnable
  repertoire stays exactly `{status, map, discover, sibling-hunt,
  disclosure-draft}`; `_build_session` still raises for `verify`, `new_project`,
  and `disclosure_send`; no `Profile` field can register a session kind;
  candidates surface as `verify_escalation` and drafted findings as
  `disclosure_send`, never executed (Constitution III, V, IX).

- **FR-12 — Auditable introspection.** `deepthought profiles` lists available
  profiles and the exact defaults each applies so the operator can audit a
  profile before trusting it; it changes no state (Constitution VII).

- **FR-13 — Default-mode invariance.** With `DEEPTHOUGHT_PROFILE` unset and no
  `--profile`, every existing 001–006 behavior — gate outcomes (including
  empty-scope HOLD), session records, `loop` budget-required exit 2, and all
  banners — is byte-for-byte identical (Constitution I, II, III, V).

## Acceptance criteria

Every test below must pass. Tests marked (RT) trace to a red-team finding in
[`threat-model.md`](threat-model.md).

1. **Default mode byte-for-byte unchanged** — profile unset; all 001–006 tests
   and smokes pass identically. (FR-13)
2. **Scope never auto-filled** — `new-project` under the profile with empty
   `--scope` writes no scope; the gate still HOLDs; a later session with the
   profile OFF yields the identical gate decision (no durable widening). (FR-5, RT)
3. **Root-equivalent area never walked as whole checkout via the profile** — the
   profile never emits `.`/`./`/`''`/`/`/trailing-slash as scope. (FR-5, RT)
4. **Containment still enforced under the profile** — `map`/`discover`/
   `sibling-hunt` refuse `../secret`, absolute, backslash, and symlink-escape
   areas with the profile active. (FR-4, RT)
5. **Basis never defaulted** — `new-project` with no `--basis` under the profile
   yields `authorization_basis=None`; a later session REFUSES on CHECK 1. (FR-6, RT)
6. **Blackbox still needs a ref** — `basis` set, `source_type=blackbox`,
   `authorization_ref=None` still REFUSES on CHECK 2 under the profile. (FR-6)
7. **Verify sign-off still refuses** — `verify --i-have-sandbox-signoff` exits 2,
   constructs no `DockerSandbox`, spawns no subprocess, mutates no finding, for
   profile in {unset, `mostly_harmless`, arbitrary} and via env. (FR-8, RT)
8. **Verify is Noop dry-run under the profile** — a reproduced verdict does not
   promote, pages no evidence, writes no transition. (FR-8)
9. **No executing backend imported** — AST/structural assertion that `cli.py` and
   `profile.py` never import or reference `DockerSandbox` or any executing
   backend, even though `sandbox/__init__.py` exports it. (FR-8, RT)
10. **Execution-stop messaging not trimmed** — the sign-off refusal and the "no
    execution — sandbox sign-off pending" banner render in full under
    `terse_output`. (FR-7, RT)
11. **Profile budget finite, frozen, echoed** — the flag-free profile loop budget
    has ≥1 positive finite limit, is never all-None, passes the loop validator,
    stays frozen, and is printed. (FR-3, RT)
12. **Loop repertoire frozen under the profile** — `_build_session` raises for
    `verify`/`new_project`/`disclosure_send`; no trace step for those kinds
    carries a `session_id`; no `Profile` field extends the repertoire. (FR-11, RT)
13. **Loop escalates, never executes** — the flag-free profile loop routes a
    candidate to `verify_escalation` and stops `hard_stop`; never runs a
    `VerifySession`; `VerifySession` stays out of the loop import closure. (FR-11, RT)
14. **Auto-next-steps never touches disclosure/loop teach-back** — a profile-
    active `disclose` still emits the full human-gate `## Next steps` (naming
    "Sending is a human action"); a session with non-empty `findings_touched` is
    never auto-closed; the loop teach-back still lists `disclosure_send`. (FR-9, RT)
15. **Terse banner preserves transmission notice** — `publish` and `disclose`
    output under `terse_output` still contain "nothing was transmitted" and an
    explicit "human must review and send." (FR-7, RT)
16. **No profile output path** — the `Profile` type has no `state_path`/out
    field; `disclose` under the profile writes only local artifacts, sets no
    `cve`, advances no lifecycle, opens no socket/HTTP. (FR-10, RT)
17. **Explicit flags override defaults** — an explicit `--max-sessions` and an
    explicit `--root` always win over profile defaults (profile fills only unset
    values). (FR-3, FR-4)
18. **Introspection is read-only** — `deepthought profiles` prints the exact
    per-profile deltas and changes no state. (FR-12)

## Open questions

- **Non-blocking.** Should a low-ceremony basis (`local_lab`) ever exist? If so it
  is an Article II amendment requiring a non-empty attestation reference, an
  explicit operator scope, and an enum↔constitution lockstep test — never the
  no-ref path of `own_code`/`permissive_oss`. Carried out of scope from the
  red-team; decide before any v2.
- **Non-blocking.** Default budget magnitudes (`max_sessions` / `max_wall_seconds`
  / `max_context_tokens`) — start conservative (e.g. 25 / 1800 / 200000) and
  calibrate against a typical read-only recon run.
- **Non-blocking.** Should `scope.py` globally refuse root-equivalent areas
  (`.`/`./`/trailing-slash) mirroring the existing blank-entry guard? This is
  sound defense-in-depth but changes default-mode semantics, so it must be its
  own change and must not break FR-13.
- **Non-blocking.** Should `check` gain an optional assertion that `--out`/
  `--state` resolve to a local, non-synced, non-symlink directory, backstopping
  the (now dropped) synced-path exfiltration risk for all modes?
- **Non-blocking.** Is auto-filling `## Next steps` acceptable under Article VI's
  durable-state discipline, or should the profile emit a template the operator
  confirms? This is the most debatable streamline.

## Success criteria

An end-to-end smoke (`scripts/smoke_007.sh`) demonstrates:

1. With `DEEPTHOUGHT_PROFILE` unset, the 001–006 smokes pass byte-for-byte.
2. With `DEEPTHOUGHT_PROFILE=mostly_harmless`: register an `own_code` project with
   an explicit `--scope`, run a flag-free `loop` that bounds itself with the
   profile default budget (printed), auto-advances only read-only sessions,
   clean-closes them with truthful next-steps, surfaces any candidate as a human
   `verify_escalation`, and transmits nothing.
3. The full invariant battery in [Acceptance criteria](#acceptance-criteria) is
   green — every load-bearing stop behaves identically with the profile on and
   off.
