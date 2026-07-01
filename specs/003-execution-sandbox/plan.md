# Implementation Plan: Execution sandbox and VERIFY

**Feature Branch:** `003-execution-sandbox`
**Spec:** `specs/003-execution-sandbox/spec.md`
**Created:** 2026-07-01

## Summary

Build the sandbox first, prove its isolation, then wire `VERIFY` behind it —
without ever executing untrusted target code. Add a `deepthought.sandbox` module:
the `Sandbox` interface (`run(spec) → SandboxResult`, mirroring `Store`/`Gate`), a
hardened default-deny `SandboxPolicy`, a `NoopSandbox` test double that records
the requested run and returns a caller-supplied canned result, and a
`DockerSandbox` that *builds* the hardened `docker run` argv but whose actual
execution is guarded off by a default-OFF `execution_enabled` flag (the HARD
STOP). Add the `VERIFY` session, which runs a minimized repro *inside the
sandbox*, pages the typed `SandboxResult` to the Store as evidence, and promotes a
candidate to `verified` **through the Store lifecycle guard** — never by writing
the status directly. Isolation is proven by inspecting the argv the sandbox would
use; the whole lifecycle is exercised with the `NoopSandbox`. Nothing executes
untrusted code, no Docker daemon is required, and no network path exists.

## Decisions

1. **No new record types.** `VERIFY` reuses `Finding` (candidate → verified),
   `Session`, and `Coverage`. The sandbox models (`SandboxSpec`, `SandboxPolicy`,
   `SandboxResult`) are runtime Pydantic models with `extra='forbid'`, not
   persisted `Record`s — the *evidence* that reaches the Store is a paged detail
   artifact plus the finding's `evidence_ref`, exactly the shape the lifecycle
   guard already checks. Added structure that does not buy a capability or a safety
   property does not earn its place (Article IX).
2. **The sandbox is an interface, not a technology.** `Sandbox` is an ABC with one
   method, `run(spec) → SandboxResult`, mirroring the `Store` and `Gate` seams. The
   backing technology (Phase 0 §0.3: ephemeral microVM primary, hardened container
   fallback) is a single-adapter swap. `VERIFY` depends only on the interface.
3. **Prove isolation by inspection, not execution.** The `DockerSandbox` splits
   into a pure `build_argv(spec, policy) → list[str]` config builder and a guarded
   `run()`. Isolation tests assert over `build_argv` output — every hardening
   clause present — with no daemon and no network. `build_argv` never executes.
4. **Execution is the hard stop.** `DockerSandbox.run()` is the only method that
   would shell out to execute untrusted code. It is guarded by a default-OFF
   `execution_enabled: bool = False`; with the flag off (the only state that
   ships) it raises `SandboxExecutionDisabled` and does not execute. No test,
   smoke, or CLI path enables it or calls it. Enabling execution is a later,
   Mahdi-signed-off change. `subprocess` is never called with untrusted input
   anywhere in this slice.
5. **The `SandboxResult` is a firewall.** `VERIFY` (the orchestrator) reads only
   the typed `SandboxResult` — an exit status, a wall-clock duration and timeout
   flag, a `reproduced` verdict, and `stdout_ref`/`stderr_ref` pointers. Raw target
   stdout/stderr is paged to the
   Store, never read into orchestrator context. This is the same discipline as the
   worker `Envelope` and the `Conductor`.
6. **Promotion stays at the Store boundary.** `VERIFY` sets the finding's
   `evidence_ref` to the paged, resolving artifact and calls
   `store.transition_finding(id, verified)`. The guard — unchanged from 001 —
   promotes only if the evidence resolves. A non-resolving or
   repro-did-not-reproduce result leaves the finding `candidate` with the blocking
   reason recorded. VERIFY never writes `status=verified`.

## Technical Context

- **Language:** Python 3.12, matching 001/002.
- **Schema and validation:** Pydantic v2. No new record types. New runtime models
  `SandboxSpec`, `SandboxPolicy`, `SandboxResult` with `extra='forbid'` and
  length/limit bounds, living in `deepthought.sandbox`, not `deepthought.schema`
  (they are not persisted records). `Finding`, `Session`, `Coverage` are reused
  unchanged; `SessionType.verify` is already in the enum.
- **New module:** `deepthought.sandbox` with `base.py` (`Sandbox` ABC, `SandboxSpec`,
  `SandboxResult`), `policy.py` (`SandboxPolicy` hardened defaults), `noop.py`
  (`NoopSandbox` test double), `docker.py` (`DockerSandbox` argv builder +
  guarded-off `run()`), and `__init__.py` exports.
- **New session:** `deepthought.sessions.verify.VerifySession`, subclassing
  `BaseSession`, run through the unchanged `run_session`. Takes an injected
  `Sandbox` (defaulting to `NoopSandbox` in this slice) so tests supply a canned
  result and no execution occurs.
- **CLI:** one new Typer subcommand, `playbook verify --project <id> --finding
  <F-NNNN>`, wired to the `NoopSandbox`, matching the existing `StoreError`
  handling.
- **Store:** unchanged interface. `VERIFY` pages the `SandboxResult` via the
  existing `write_detail(session_id, name, content) → detail/...` and promotes via
  the existing `transition_finding`; the guard's `detail_exists` check resolves the
  evidence. No Store method or schema field is added.
- **Execution / sandbox:** the `DockerSandbox` builds argv but does not execute;
  `run()` is guarded off. The `NoopSandbox` executes nothing. No microVM backend
  in this slice.
- **Network:** none. Default egress is deny-all; no transmission path is added.
- **Testing:** pytest, test-first per Article VII. Tests are hermetic — they pass
  with no Docker daemon and no network. A guard test asserts `DockerSandbox.run()`
  raises with the flag off and is never called elsewhere. `check` remains a runtime
  gate, tested against VERIFY output.
- **Target platform:** the operator's Mac Studio dev lab (Phase 0 §0.3).

## Phase 0 — the sandbox decision (from `docs/phase-0-decisions.md` §0.3)

The sandbox technology was **chosen** in Phase 0 and is honored here:

- **Primary (later): ephemeral Linux microVM, egress default-deny.** A per-run
  microVM (Apple `Virtualization.framework` on Apple Silicon, or a
  Firecracker-class VM via Lima/Krun). VM-level isolation is stronger than
  container namespaces for running untrusted target code — the point of Article
  III. This backend is a later single-adapter swap; it is **not built** in 003.
- **Fallback / dev-fast: a rootless hardened container** — `--network none`,
  read-only root, dropped capabilities, `no-new-privileges`, non-root user, and
  resource limits. Acceptable for low-risk repro during development. Only this
  backend's **config builder** (`DockerSandbox.build_argv`) lands in 003, and only
  as inspectable config — its execution is the hard stop.
- **Egress control: default-DENY.** No network by default. Any required egress is a
  later explicit, logged, per-engagement allowlist, off by default. This slice does
  deny-all only.
- **Lifecycle:** built fresh per VERIFY run, torn down after (`--rm`); no
  persistence of target code or side effects beyond the paged evidence artifact.
- **The interface, not the implementation.** The `Sandbox` interface (mirroring
  `Store`/`Gate`) means VERIFY depends on the seam; microVM vs container is one
  adapter. The evidence-artifact contract (a resolving `evidence_ref` paged to the
  Store) is independent of the backend.
- **Hard stop reaffirmed (Phase 0 §0.3):** nothing executes target code until this
  sandbox exists, is tested for isolation and egress control, and is **signed off
  by Mahdi**. 003 delivers the tested config and the Noop-backed VERIFY; it does
  not enable execution.

No new unknown blocks 003. The open questions in `spec.md` (repro provenance,
resource-limit defaults, the microVM backend) are non-blocking and refined against
real runs.

## Constitution Check

Each of the nine articles, and how this design satisfies it.

- **I, gate-first.** `VERIFY` runs through the same `run_session` harness that
  gates before work. `VerifySession.build_gate_context` is built from the stored
  project; `hold`/`refuse` are logged with reasons. Pass.
- **II, authorization and scope.** `VERIFY` runs only against a project with an
  authorization basis and a scope allowlist, and verifies only in-scope findings.
  No session widens scope or authorization. Pass.
- **III, sandbox. Highlighted.** This is the article the whole feature serves. No
  target code executes outside an isolated, egress-controlled sandbox — and in this
  slice no untrusted code executes at all. The hardened `SandboxPolicy` is
  default-deny (network none, read-only rootfs, no mounts, caps dropped,
  no-new-privileges, non-root, resource + wall-time limits), proven by inspecting
  `DockerSandbox.build_argv`. The real execution path (`DockerSandbox.run()`) is
  guarded by a default-OFF `execution_enabled` flag, raises when off, and is never
  invoked; `VERIFY` uses the `NoopSandbox`, which executes nothing. Enabling
  execution is Mahdi's sign-off (the HARD STOP). Pass, and the highlight.
- **IV, evidence and lifecycle.** A candidate advances to `verified` only through
  `store.transition_finding`, which requires a non-empty `evidence_ref` that
  resolves. `VERIFY` pages the `SandboxResult` to the Store and sets that resolving
  ref; it never writes `status=verified`. A repro that does not resolve leaves the
  finding `candidate` with the blocking reason recorded. The guard is unchanged and
  untouched. Pass.
- **V, coordinated disclosure.** Nothing leaves the machine. The sandbox's default
  egress is deny-all; VERIFY opens no network path; `publish` still emits local
  artifacts and asserts the human gate. Pass.
- **VI, durable state.** `VERIFY` teaches back: it writes the evidence artifact,
  updates the finding, and writes a session log with `## Next steps`. A session
  with no next steps does not close. Pass.
- **VII, validate-first.** Test-first: the sandbox interface, policy, both
  backends, the VERIFY session, the CLI, and the smoke arrive with the tests that
  constrain them, written to fail first and hermetic (no daemon, no network).
  `check` is a required gate before `publish`, and stays green on VERIFY output.
  Pass.
- **VIII, injection resistance. Highlighted.** A repro's raw output is hostile,
  attacker-influenceable content. The `SandboxResult` is the firewall, mirroring
  the worker `Envelope`: VERIFY reads only the typed result (exit status,
  wall-clock duration, timeout flag, a `reproduced` verdict, `stdout_ref`/
  `stderr_ref`), never the raw stdout/stderr,
  which is paged to the Store and never loaded into orchestrator context. Raw
  target output is never interpreted as instruction. Pass, and a highlight.
- **IX, minimalism and least privilege.** The sandbox is reached only through the
  one-method `Sandbox` interface; VERIFY depends on the interface, not the backend.
  The hardened policy is least-privilege by construction (drop everything, allow
  nothing). The one new module and one new session each buy a concrete safety
  property (the execution boundary) or the VERIFY capability. No session widens its
  own scope. Pass.

Tension noted: 003 introduces the platform's first *execution* capability, which
is inherently the highest-risk surface. The mitigation is that the capability
ships **disabled and inspected** — the hard stop is a default-OFF flag plus a
Noop-backed VERIFY, so the surface buys the tested isolation contract without ever
running untrusted code. See Complexity Tracking.

## Architecture

### VERIFY behind the sandbox (Noop-backed in this slice)

```
        operator
           │
   launcher (VERIFY --project --finding)
           │
           ▼
  ┌──────────────────────────────────────┐
  │  Deep Thought core (orchestrator)     │
  │  reads ONLY the typed SandboxResult   │
  └──────────────────────────────────────┘
     │  SandboxSpec (repro + policy)      ▲  SandboxResult (typed) + stdout/stderr refs
     ▼                                    │
  ┌───────────────────────────────────────────────────┐
  │  Sandbox interface  (run(spec) -> SandboxResult)   │
  │   ├── NoopSandbox   records spec, returns canned   │  ← used by VERIFY here
  │   └── DockerSandbox build_argv(spec, policy)       │  ← config only; run() OFF
  └───────────────────────────────────────────────────┘
     │  raw target output paged to the Store (never inlined)
     ▼
   Store: evidence artifact under state/detail/<session>/
           │  finding.evidence_ref = detail/<session>/verify-result.txt
           ▼
   store.transition_finding(F-NNNN, verified)  ── the lifecycle guard
           │  resolves evidence_ref? → candidate becomes verified
           ▼
   check green: verified finding has a resolving evidence_ref
```

- **The sandbox is the only door to execution.** VERIFY runs a repro only through
  `Sandbox.run`. `NoopSandbox` executes nothing; `DockerSandbox.build_argv` is
  pure config; `DockerSandbox.run` is guarded off (the hard stop).
- **The `SandboxResult` is the firewall.** The orchestrator reads the typed result
  and its `stdout_ref`/`stderr_ref` pointers only. Raw target output pages to the
  Store, exactly as worker detail does, and is never read into orchestrator context.
- **Promotion is at the Store boundary.** VERIFY pages evidence, sets the resolving
  `evidence_ref`, and asks the guard to transition. The guard owns the decision.

### The hardened run configuration (proven by inspection)

`DockerSandbox.build_argv(spec, policy)` renders the hardened `SandboxPolicy` into
the exact `docker run` argv a real run *would* use. The isolation test asserts
every clause is present — `--rm`, `--network=none`, `--read-only`, `--cap-drop=ALL`,
`--security-opt=no-new-privileges`, a non-root `--user`, `--pids-limit`,
`--memory`, `--cpus`, no `-v`/`--mount` host bind, and a wall-time bound — with no
Docker daemon and no network. The argv is data for inspection, never a command
that is run in this slice. Full mapping in `contracts/sandbox.md`.

## Project structure (delta from 002)

New and changed paths only; everything else in the 001/002 tree is unchanged.

```
src/deepthought/
  sandbox/
    __init__.py           # NEW — exposes Sandbox, SandboxSpec, SandboxResult,
                          #        SandboxPolicy, NoopSandbox, DockerSandbox,
                          #        SandboxExecutionDisabled
    base.py               # NEW — Sandbox ABC + SandboxSpec + SandboxResult
    policy.py             # NEW — SandboxPolicy hardened default-deny config
    noop.py               # NEW — NoopSandbox: records spec, returns canned result
    docker.py             # NEW — DockerSandbox.build_argv (config) + run() (guarded OFF)
  sessions/
    verify.py             # NEW — VerifySession: repro -> Sandbox -> evidence -> guard
    __init__.py           # CHANGED — export VerifySession
  cli.py                  # CHANGED — add `playbook verify`
tests/
  test_sandbox_policy.py  # NEW — hardened SandboxPolicy defaults
  test_sandbox_docker.py  # NEW — build_argv isolation assertions; run() guarded OFF
  test_sandbox_noop.py    # NEW — NoopSandbox records spec, executes nothing
  test_verify_session.py  # NEW — VERIFY promotes via guard; non-resolving stays candidate
  test_cli_003.py         # NEW — `playbook verify` Noop-backed
  test_smoke_003.py       # NEW — the 003 Noop-backed lifecycle smoke
scripts/
  smoke_003.sh            # NEW — DISCOVER candidate -> VERIFY (Noop) -> verified -> check
specs/003-execution-sandbox/{spec.md, plan.md, data-model.md, contracts/, tasks.md}
```

The `.claude/skills/deep-thought-protocol/SKILL.md` session-type playbook gains a
VERIFY entry (documentation, not code): VERIFY runs a minimized repro only inside
the sandbox and promotes on resolving evidence through the Store guard; execution
of untrusted code is off pending sign-off.

## Phase 1 — design outputs

- `data-model.md`: no new record types; how VERIFY reuses `Finding`
  (candidate → verified via the guard) and pages the repro result as evidence under
  `state/detail/`; the `SandboxSpec`, `SandboxPolicy`, and `SandboxResult` models
  and the VERIFY evidence artifact.
- `contracts/sandbox.md`: the `Sandbox` interface contract, the hardened
  `SandboxPolicy`, the `DockerSandbox` argv mapping, the `NoopSandbox` double, and
  the `SandboxResult`-as-firewall rule.

## Complexity Tracking

| Added complexity | Why it is justified | How it is bounded |
| --- | --- | --- |
| A sandbox module (interface + policy + two backends) | Article III requires an isolated, egress-controlled sandbox before any code runs; this is the roadmap's "build the sandbox first" | One-method interface mirroring `Store`/`Gate`; hardened policy is default-deny; the Docker backend is config-only with execution guarded OFF; `NoopSandbox` executes nothing. |
| The platform's first execution capability | VERIFY cannot produce evidence without running a repro | Ships **disabled**: `execution_enabled=False`, `run()` raises and is never called; VERIFY is Noop-backed; isolation is proven by argv inspection, not by running containers. |
| A `SandboxResult` firewall on top of the worker `Envelope` | Repro output is hostile, attacker-influenceable content | Same discipline as the envelope: the orchestrator reads only the typed result; raw output pages to the Store and is never inlined or interpreted as instruction. |
| A new VERIFY session type | VERIFY is the roadmap's promotion path and the first consumer of the sandbox | Runs through the unchanged gate + harness; promotes only through the unchanged Store lifecycle guard; cannot widen scope or write `verified` directly. |

## Validation — the 003 smoke (Noop-backed)

1. Register a real in-scope target with a `NEW PROJECT` session (reuse 001).
2. Run a `DISCOVER` session over the bundled SARIF fixture (002) to produce a
   candidate finding.
3. Run a `VERIFY` session on that candidate, backed by a `NoopSandbox` returning a
   resolving "reproduced" `SandboxResult`. The session pages the result as
   evidence, sets the finding's `evidence_ref`, and the finding reaches `verified`
   through `store.transition_finding`.
4. `check` is green: the verified finding has a resolving `evidence_ref`.
5. Run a second `VERIFY` on another candidate backed by a `NoopSandbox` returning a
   non-resolving result (repro did not reproduce). The finding stays `candidate`
   with the blocking reason recorded; `check` stays green.
6. `publish` prepares local OSV artifacts and asserts the human gate — nothing is
   transmitted. `DockerSandbox.run()` is never invoked; no untrusted code executes.

Passing all six proves the sandbox-and-VERIFY slice: a tested isolation config, a
VERIFY that runs only inside the sandbox, a candidate reaching `verified` through
the lifecycle guard on resolving evidence, and nothing executing outside the
sandbox — with the first real execution still behind Mahdi's sign-off.
