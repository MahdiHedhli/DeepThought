# Feature Spec: Execution sandbox and VERIFY (003)

**Feature Branch:** `003-execution-sandbox`
**Created:** 2026-07-01
**Status:** Draft

## Problem

Features 001 and 002 built the governed spine and the read-only half of the
Improbability Drive. DISCOVER now produces candidate `Finding`s and suspected
`Primitive`s, but no candidate can ever advance. The lifecycle guard at the Store
boundary is explicit: `candidate → verified` requires a non-empty `evidence_ref`
that resolves (`FileStore._evaluate_transition`), and the only thing that can
produce that evidence honestly is *running a minimized repro and observing it
fail*. There is no way to run anything. Every candidate is stuck at `candidate`,
which is exactly correct — Article III forbids executing target code until an
isolated, egress-controlled sandbox exists to contain it.

This feature builds that sandbox and the `VERIFY` session that will one day use
it. It is deliberately split from the act of execution. This slice delivers the
sandbox as a **typed, tested interface** — the `Sandbox.run(spec) → SandboxResult`
contract, a hardened `SandboxPolicy`, a `DockerSandbox` that *builds* its run
configuration (argv/options) but does not execute untrusted code, and a
`NoopSandbox` test double that records the requested run and returns a
caller-supplied canned result without executing anything. Isolation is proven by
**inspecting the hardened run configuration** the sandbox *would* use, not by
running containers. `VERIFY` is wired end to end against the `NoopSandbox` so the
whole lifecycle — candidate → repro-in-sandbox → resolving evidence → `verified`
through the Store guard — is exercised hermetically, with no Docker daemon and no
network.

The one thing this slice does **not** do is execute an untrusted proof-of-concept.
That is the hard stop (see below), gated by Article III and requiring Mahdi's
sign-off before it is enabled.

## Goal

Land the sandbox as an interface and prove it, then wire `VERIFY` behind it —
without ever executing untrusted target code:

- **The `Sandbox` interface** — `Sandbox.run(spec: SandboxSpec) → SandboxResult`,
  mirroring the `Store`/`Gate` pattern so the backing technology is a
  single-adapter swap (Phase 0 §0.3).
- **`SandboxPolicy`** — the hardened, default-deny run configuration: ephemeral
  per-run and torn down, network egress default-DENY, read-only rootfs, no host
  mounts, all capabilities dropped, `no-new-privileges`, non-root user, and
  `pids`/`memory`/`cpu`/wall-time limits.
- **`NoopSandbox`** — a test double that records the `SandboxSpec` it was handed
  and returns a caller-supplied canned `SandboxResult`, executing nothing.
- **`DockerSandbox` (config only)** — maps a `SandboxSpec` + `SandboxPolicy` to
  the exact `docker run` argv/options a hardened run *would* use. Isolation tests
  assert over this argv. Its actual execution path is guarded off (see HARD STOP)
  and never invoked in tests.
- **The `VERIFY` session** — takes a candidate finding with a real minimized
  repro, runs it *inside the sandbox* (the `NoopSandbox` in tests), pages the
  typed `SandboxResult` to the Store as the resolving evidence artifact, and moves
  the candidate to `verified` **through the lifecycle guard** — never by writing
  the status directly.

Prove the whole loop: the sandbox's isolation config is tested and signed off by
inspection; `VERIFY` runs only inside the sandbox; a candidate with a real repro
reaches `verified` through the Store guard with a resolving `evidence_ref`; and
nothing executes outside the sandbox — indeed, in this slice nothing executes
untrusted code at all.

## Scope

**In scope**

- A **sandbox module** (`deepthought.sandbox`): the `Sandbox` abstract base, the
  `SandboxSpec` and `SandboxResult` typed models, the `SandboxPolicy` (hardened
  defaults, `extra='forbid'`), the `NoopSandbox` test double, and the
  `DockerSandbox` **argv/config builder** (`build_argv(spec, policy) → list[str]`)
  with its execution path guarded off by default.
- The **`VERIFY` session** (`deepthought.sessions.verify.VerifySession`):
  subclasses `BaseSession`, `.type = SessionType.verify` (already in the enum),
  runs through the unchanged `run_session` harness and gate. It loads a candidate
  finding, hands a `SandboxSpec` (the minimized repro + `SandboxPolicy`) to an
  injected `Sandbox`, receives a typed `SandboxResult`, pages it to the Store via
  `write_detail`, sets the finding's `evidence_ref` to that resolving ref, and
  calls `store.transition_finding(id, verified)` — the guard promotes it only if
  the evidence resolves.
- **CLI wiring:** `playbook verify --project <id> --finding <F-NNNN>` runs a
  `VERIFY` session. In this slice it is wired to the `NoopSandbox` (no execution).
- **Docs:** `contracts/sandbox.md` (the interface contract), the session-type
  playbook entry for VERIFY in the protocol skill, and a note that execution is
  off pending sign-off.
- A **Noop-backed 003 smoke** (`scripts/smoke_003.sh` + a test) that drives the
  full lifecycle through the CLI with the `NoopSandbox`: DISCOVER a candidate,
  VERIFY it to `verified` with a resolving evidence artifact, `check` green,
  nothing executed, nothing transmitted.

**Out of scope** (later, or behind the hard stop)

- **Executing an untrusted proof-of-concept through `DockerSandbox` (or any real
  backend).** This is the HARD STOP. The `DockerSandbox` builds its config in this
  slice; wiring it to actually run untrusted code requires Mahdi's sign-off and is
  gated by a default-OFF `execution_enabled` flag. No test ever calls it.
- A running Docker daemon, a microVM backend, or any network path. Tests are
  hermetic: they pass with no daemon and no network.
- The ephemeral Linux **microVM** primary backend from Phase 0 §0.3. The interface
  is designed so the microVM is a later single-adapter swap; only the
  `DockerSandbox` config builder and the `NoopSandbox` land here.
- Egress **allowlisting** beyond default-deny. Any allowed egress is a later,
  explicit, per-engagement, logged opt-in; the default and the only behavior in
  this slice is deny-all.
- `SIBLING HUNT`, `DISCLOSURE`, the autonomous loop (004–006).
- New record types. `VERIFY` reuses `Finding`, `Session`, `Coverage` unchanged;
  the sandbox models are runtime types, not persisted `Record`s.
- Any scope or authorization widening. A `VERIFY` against an out-of-scope or
  unauthorized project is refused/held at the Gate, never expanded.

## User scenarios

1. **Prove isolation without running anything.** An engineer inspects the
   hardened run configuration the sandbox would use. `build_argv(spec, policy)`
   for the hardened `SandboxPolicy` contains `--network=none`, `--read-only`,
   `--cap-drop=ALL`, `--security-opt=no-new-privileges`, a non-root `--user`,
   `--pids-limit`, `--memory`, `--cpus`, and a wall-time bound; it mounts no host
   path and is marked `--rm` (ephemeral, torn down). The assertion is over the
   argv, not a container run. No Docker daemon is required.
2. **VERIFY a candidate through the sandbox (Noop-backed).** An operator runs a
   `VERIFY` session on a candidate finding that carries a minimized repro. The
   session builds a `SandboxSpec`, hands it to the injected `Sandbox` (a
   `NoopSandbox` returning a canned "repro reproduced the crash" `SandboxResult`),
   pages that result to the Store as the evidence artifact, sets the finding's
   `evidence_ref` to the resolving ref, and transitions the finding to `verified`
   **through `store.transition_finding`**. `check` stays green: the verified
   finding has a resolving `evidence_ref`.
3. **The lifecycle guard still owns promotion.** VERIFY never writes
   `status=verified` directly. If the `SandboxResult` does not resolve the repro
   (e.g. the repro did not reproduce, or the evidence ref does not resolve), the
   transition is rejected by the guard, the finding stays `candidate`, and the
   blocking reason is recorded on the finding. The session closes clean with a
   next step.
4. **The sandbox is the only door to execution.** VERIFY calls the `Sandbox`
   interface and nothing else to run a repro. It never shells out, never calls
   `subprocess`, and never runs the repro in-process. The `NoopSandbox` records
   the `SandboxSpec` it was given and executes nothing; the test asserts the spec
   was recorded and no execution occurred.
5. **The orchestrator sees only a typed result.** VERIFY (the orchestrator) reads
   only the typed `SandboxResult` — an exit status, a wall-clock duration and
   timeout flag, and `stdout_ref`/`stderr_ref` pointers to the paged raw output. It
   never reads the raw target
   stdout/stderr into its own context. Raw target output is paged to the Store,
   exactly as worker detail is; the `SandboxResult` is the firewall, the same
   discipline as the worker `Envelope`.
6. **The gate still governs.** A `VERIFY` against a project with no authorization
   basis is refused; an empty scope allowlist is held. No session widens scope or
   authorization to proceed.

## Functional requirements

Each requirement names the constitution article it serves.

- **FR-1** Every `VERIFY` session passes the Gate before any work; the outcome and
  reason are logged on the session. (Constitution I)
- **FR-2** `VERIFY` runs only against a project that carries an authorization
  basis and a scope allowlist; it verifies only in-scope findings and widens no
  scope or authorization. (Constitution II, IX)
- **FR-3** No target code executes outside the sandbox — and in this slice no
  untrusted target code executes at all. `VERIFY` runs a repro only through the
  `Sandbox` interface; isolation is proven by inspecting the hardened run
  configuration, and the tests use the `NoopSandbox`, which executes nothing.
  (Constitution III)
- **FR-4** The hardened `SandboxPolicy` is: ephemeral per-run and torn down;
  network egress default-DENY; read-only rootfs; no host mounts; all capabilities
  dropped; `no-new-privileges`; non-root user; and `pids`, `memory`, `cpu`, and
  wall-time limits. `DockerSandbox.build_argv` renders exactly this policy, and a
  test asserts every clause is present. (Constitution III)
- **FR-5** A candidate advances to `verified` only through the Store's lifecycle
  guard (`store.transition_finding`), which requires a non-empty `evidence_ref`
  that resolves. `VERIFY` pages the `SandboxResult` to the Store and sets that
  resolving ref; it never writes `status=verified` directly. A repro that does not
  resolve leaves the finding `candidate` with the blocking reason recorded.
  (Constitution IV)
- **FR-6** The orchestrator ingests only the typed `SandboxResult`; raw target
  stdout/stderr is paged to the Store under `state/detail/` and is never read into
  orchestrator context. The `SandboxResult` is the firewall, mirroring the worker
  `Envelope`. (Constitution VIII)
- **FR-7** Nothing leaves the machine. The sandbox's default egress is deny-all;
  `VERIFY` and the sandbox open no network path; `publish` still emits local
  artifacts and asserts the human gate. (Constitution V)
- **FR-8** Each `VERIFY` session teaches back: it writes the evidence artifact,
  updates the finding, and writes a session log with explicit `## Next steps`. A
  session with no next steps does not close. (Constitution VI)
- **FR-9** The sandbox is reached only through the `Sandbox` interface; `VERIFY`
  depends on the interface, not the backend. The `DockerSandbox` execution path is
  guarded by a default-OFF `execution_enabled` flag and is never invoked in tests
  or wired to run untrusted code. Added structure buys a safety property (the
  execution boundary) and no more. (Constitution III, IX)
- **FR-10** Test-first. The sandbox interface, policy, both backends, the VERIFY
  session, the CLI, and the smoke arrive with the tests that constrain them. Tests
  are hermetic — no Docker daemon, no network — and `check` is a required gate
  before `publish`. (Constitution VII)

## Acceptance criteria

The four roadmap criteria for 003, each a check the 003 tests and Noop-backed
smoke assert:

1. **The sandbox is tested and signed off.** The `Sandbox` interface,
   `SandboxPolicy`, and the `DockerSandbox` argv builder exist; the isolation
   configuration is asserted by inspecting the hardened argv (every clause of
   FR-4 present), with no Docker daemon and no network. This is the "prove
   isolation" gate.
2. **VERIFY runs only inside the sandbox.** The `VERIFY` session executes a repro
   only through the injected `Sandbox` interface. It never shells out, never calls
   `subprocess`, and the `NoopSandbox` used in tests executes nothing. A test
   asserts VERIFY reaches execution through the `Sandbox` seam alone.
3. **A candidate with a real repro reaches `verified` through the lifecycle
   guard.** With a `NoopSandbox` returning a resolving `SandboxResult`, a candidate
   finding is promoted to `verified` via `store.transition_finding`, with a
   non-empty `evidence_ref` that resolves. `check` is green on the result.
4. **Nothing executes outside the sandbox.** No `VERIFY`, test, or smoke path runs
   untrusted target code; the `DockerSandbox` execution path is off and
   uninvoked; the whole slice is hermetic.

## HARD STOP

**This feature builds the sandbox and tests its isolation configuration WITHOUT
executing untrusted target code. Wiring `VERIFY` to actually execute an untrusted
proof-of-concept requires Mahdi's sign-off.** (Constitution Article III.)

Precisely:

- The **hard-stop location** is `DockerSandbox.run()` in
  `src/deepthought/sandbox/docker.py` — the one method that would shell out to a
  real backend to execute untrusted code. In this slice it is guarded by an
  explicit, default-OFF `execution_enabled: bool = False` flag: with the flag off
  (the only state that ships), `run()` raises `SandboxExecutionDisabled` and does
  **not** execute. `DockerSandbox.build_argv()` — the pure config builder — is
  always available and is what the isolation tests inspect. `build_argv` never
  executes; only `run()` would, and it is disabled.
- No test, smoke, or CLI path enables `execution_enabled` or calls
  `DockerSandbox.run()`. `VERIFY` is wired to the `NoopSandbox`, which records the
  spec and returns a canned result, executing nothing.
- `subprocess` is never called with untrusted input anywhere in this slice. The
  `build_argv` output is data (a `list[str]` for inspection), not a command that
  is run.
- Enabling execution is a distinct, later change: it flips `execution_enabled` on
  behind Mahdi's sign-off, adds a real backend run (microVM per Phase 0 §0.3, or
  the hardened container fallback), and lands with its own tests that run *only*
  vetted, self-authored repros against *authorized, in-scope* targets. Nothing in
  003 does that.
- Until then, Article III is honored the same way 001 and 002 honored it — by
  sequencing: the capability to execute exists only as a disabled, inspected
  config, and the first real execution is a gated event, not a side effect of
  merging this feature.

## Open questions

- **Minimized-repro provenance.** In this slice a candidate's repro is supplied to
  `VERIFY` (via the finding/spec) rather than synthesized. Where a real minimized
  repro comes from — a DISCOVER artifact, an operator-provided PoC, or a later
  minimizer — is refined against real runs. The `SandboxSpec` shape (command +
  input artifact + policy) is fixed here. Non-blocking.
- **Resource-limit defaults.** The concrete numbers for `pids`/`memory`/`cpu`/
  wall-time in the hardened `SandboxPolicy` are conservative starters; they are
  tuned against real repros once execution is enabled. Their *presence* (each
  limit is set and non-empty) is fixed and tested here. Non-blocking.
- **microVM backend.** Phase 0 §0.3 pins an ephemeral Linux microVM as the primary
  execution backend; the hardened container is the dev-fast fallback. Only the
  container config builder lands in 003. The `Sandbox` interface makes the microVM
  a later single-adapter swap. Non-blocking, carried from Phase 0.
- Carried from earlier features, still non-blocking: the confirmed HermesUltraCode
  gate interface (Phase 0 §0.1) and the real pooled-worker runtime.

## Success criteria

The Noop-backed 003 smoke passes end to end: register a real in-scope target (001
`NEW PROJECT`), DISCOVER a candidate over the bundled SARIF fixture (002), run a
`VERIFY` session backed by the `NoopSandbox` that promotes the candidate to
`verified` with a resolving evidence artifact, `check` green, then a
non-resolving `NoopSandbox` result leaves a candidate `candidate` with the
blocking reason recorded and `check` still green. The isolation tests assert the
hardened argv over `DockerSandbox.build_argv` with no daemon and no network. No
untrusted target code executes anywhere; `DockerSandbox.run()` is never invoked;
`publish` still transmits nothing. Every 001 and 002 test stays green.
