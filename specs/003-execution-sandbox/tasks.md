# Tasks: Execution sandbox and VERIFY (003)

Test-first per constitution Article VII. For each task with tests, write the
tests, see them fail, then implement to green. `[P]` marks tasks that can run in
parallel because they touch different files. Dependencies are noted. **Do not
weaken any 001 or 002 test.** Run the suite with `.venv/bin/pytest -q`; if
`import deepthought` fails, `uv pip install --python .venv -e ".[dev]"` first.

**Tests are hermetic.** Every test in this feature passes with **no Docker daemon
and no network**. No test enables `execution_enabled`, calls `DockerSandbox.run()`,
or executes untrusted target code. `subprocess` is never called with untrusted
input anywhere in this slice.

## Setup

- **T001** Feature scaffold. Create `specs/003-execution-sandbox/` with `spec.md`,
  `plan.md`, `data-model.md`, `contracts/sandbox.md`, and this `tasks.md` (this
  task — done). Add the `src/deepthought/sandbox/` package with an empty
  `__init__.py`. No app logic. Depends on 002.

## Sandbox interface, spec, and result (the firewall types)

- **T002** `SandboxSpec` and `SandboxResult` + the `Sandbox` ABC in
  `sandbox/base.py`. Tests first: `SandboxSpec` requires a `policy`, a `command`
  that is a `list[str]` (a shell string / non-list `command` fails validation), and
  `extra='forbid'` rejects unknown keys; `SandboxResult` carries `reproduced`,
  `exit_code`, `timed_out`, `wall_seconds`, and `stdout_ref`/`stderr_ref` pointers,
  with `extra='forbid'`; `Sandbox` is an ABC whose `run` is abstract (cannot be
  instantiated). No execution occurs constructing any of these. Depends on T001.

## Hardened policy

- **T003** [P] `SandboxPolicy` in `sandbox/base.py`. Tests first: the
  **default-constructed** `SandboxPolicy()` is fully hardened —
  `network == "none"`, `read_only_rootfs is True`, `allow_host_mounts is False`,
  `drop_all_caps is True`, `no_new_privileges is True`, `run_as_non_root is True`
  with a non-root `user` (never `root`/`0`), and positive `pids_limit`,
  `memory_mib`, `cpus`, and `wall_timeout_seconds`, with `ephemeral is True`;
  `extra='forbid'`; the network default is `"none"` (no allowlist field is honored
  in this slice). Depends on T001.

## Docker argv builder (config only) — the hard stop guards run()

- **T004** `DockerSandbox.build_argv(spec, policy) -> list[str]` in
  `sandbox/docker.py`. Tests first (the **prove-isolation** gate): `build_argv` for
  the hardened default policy contains `--rm`, `--network=none`, `--read-only`,
  `--cap-drop=ALL`, `--security-opt=no-new-privileges`, a non-root `--user`,
  `--pids-limit`, `--memory`, `--cpus`, and the `spec.image` + `spec.command` argv;
  it renders **no** `-v`/`--mount` host bind and **no** host `--env`; the returned
  value is a `list[str]` (data for inspection, not run). Assertions are over the
  argv with **no Docker daemon and no network**. `build_argv` executes nothing.
  Depends on T002, T003.
- **T005** `DockerSandbox.run()` guarded off (the **HARD STOP**). Tests first: a
  `DockerSandbox()` has `execution_enabled is False` by default; calling `run(spec)`
  raises `SandboxExecutionDisabled` and executes nothing (no `subprocess`, no
  daemon); the guard message points at Mahdi's sign-off. Assert (e.g. by patching
  `subprocess`) that no subprocess is ever spawned. **No test enables the flag.**
  Depends on T004.

## Noop test double

- **T006** [P] `NoopSandbox(result)` in `sandbox/noop.py`. Tests first: `run(spec)`
  appends the `spec` to `recorded` and returns the exact canned `SandboxResult`
  it was constructed with; it executes nothing (no subprocess, no container);
  constructing and running it needs no Docker daemon and no network. Depends on
  T002.

## Package exports

- **T007** Wire `sandbox/__init__.py` to export `Sandbox`, `SandboxSpec`,
  `SandboxResult`, `SandboxPolicy`, `NoopSandbox`, `DockerSandbox`, and
  `SandboxExecutionDisabled`. Tests first for the exports. Depends on T003, T005,
  T006.

## VERIFY session (Noop-backed; promotes through the guard)

- **T008** `VerifySession(project_id, finding_id, sandbox=None)` in
  `sessions/verify.py`, subclassing `BaseSession` with `.type =
  SessionType.verify`. `sandbox` defaults to a `NoopSandbox` in wiring but is
  **injected** in tests. Tests first:
  - `build_gate_context` is built from the stored project; a `VERIFY` against a
    project with no basis is refused and an empty scope allowlist is held, via the
    unchanged gate through `run_session`.
  - Given a candidate finding and a `NoopSandbox` returning a **resolving**
    `SandboxResult(reproduced=True)`: the session builds a hardened `SandboxSpec`
    (asserted via `NoopSandbox.recorded`), pages the result via
    `store.write_detail` to `detail/<session>/verify-result.txt`, sets the finding's
    `evidence_ref` to that ref, and the finding reaches `verified` **through
    `store.transition_finding`** (assert the finding's status and that its
    `evidence_ref` resolves). The session never assigns `status=verified` directly.
  - Given a `NoopSandbox` returning a **non-resolving** `SandboxResult(
    reproduced=False)`: the transition is rejected by the guard, the finding stays
    `candidate`, the blocking reason is recorded on the finding, and the session
    still closes clean with a next step.
  - The session runs a repro **only** through the injected `Sandbox` (assert no
    `subprocess` is spawned; the sandbox seam is the only execution door).
  - The orchestrator reads only the typed `SandboxResult` — raw target output is
    paged and never inlined (assert the session summary/next-steps contain no raw
    output, only the typed verdict and the detail ref).
  - Teaches back: the finding touched, a summary, and explicit `## Next steps`; a
    session with no next steps does not close.
  Depends on T007.

- **T009** Wire `VerifySession` into `sessions/__init__.py` (export
  `VerifySession`). Tests first for the export. Depends on T008.

## CLI wiring

- **T010** `playbook verify --project <id> --finding <F-NNNN>` in `cli.py`. Tests
  first (Typer runner): the command runs a `VERIFY` session through `run_session`
  with the gate, wired to a `NoopSandbox` (default-constructed with a canned
  resolving result, or a flag/env for tests); it prints the session record like
  `status`/`map`/`discover`; a `StoreError` (unknown project or unknown finding)
  exits non-zero with a message, matching the existing handling. No CLI path enables
  `execution_enabled` or calls `DockerSandbox.run()`. Depends on T009.

## Validation and gate-before-done

- **T011** `check` stays a hard gate over VERIFY output. Tests first: `check` is
  green on the state a Noop-backed VERIFY produces (a `verified` finding has a
  resolving `evidence_ref`; a `candidate` left by a non-resolving result has no
  lifecycle-at-rest obligation); `check` fails if a `verified` finding's evidence
  ref is removed/does not resolve; `publish` still refuses when `check` is red and
  transmits nothing when green. No change to `check.py` is expected — this task
  asserts the existing lifecycle-at-rest guard holds for VERIFY output. Depends on
  T010.

- **T012** The 003 smoke script `scripts/smoke_003.sh` and `tests/test_smoke_003.py`
  (mirroring the 001/002 smokes), **Noop-backed**. Drives the full lifecycle through
  the CLI: NEW PROJECT (real in-scope target) → DISCOVER (bundled SARIF fixture,
  produce a candidate) → VERIFY (Noop resolving result, candidate reaches
  `verified` with a resolving evidence artifact) → `check` green → a second VERIFY
  with a Noop non-resolving result leaves a candidate `candidate` with the blocking
  reason recorded and `check` still green → `publish` (local artifacts, human gate,
  nothing transmitted). Asserts `DockerSandbox.run()` is never invoked and no
  untrusted code executes. Self-heals the editable install like the 001/002 smokes.
  Depends on T011.

- **T013** Update the session-type playbook in
  `.claude/skills/deep-thought-protocol/SKILL.md` with a VERIFY entry
  (documentation only): VERIFY runs a minimized repro **only inside the sandbox**,
  reads only the typed `SandboxResult`, pages raw output to the Store, and promotes
  a candidate to `verified` **through the Store lifecycle guard** on a resolving
  `evidence_ref`; execution of untrusted code is OFF pending Mahdi's sign-off (the
  hard stop). Depends on T009.

- **T014** Run `/analyze` across the constitution, this spec, plan, data-model, the
  sandbox contract, and these tasks; resolve any drift. Then run the full suite
  (`.venv/bin/pytest -q`) — 001, 002, and 003 green — and the 003 Noop-backed smoke
  end to end. Confirm no test enables `execution_enabled`, no test calls
  `DockerSandbox.run()`, and no `subprocess` runs untrusted input. Depends on all
  above.

## Definition of done for 003

- The four acceptance criteria hold: the sandbox is tested and signed off by
  inspecting the hardened argv (every FR-4 clause present, no daemon, no network);
  VERIFY runs a repro **only** through the `Sandbox` interface; a candidate with a
  real repro reaches `verified` **through the Store lifecycle guard** with a
  resolving `evidence_ref`; and nothing executes outside the sandbox — indeed
  nothing untrusted executes at all.
- The 003 Noop-backed smoke passes end to end; `check` is green on the produced
  state (a `verified` finding with resolving evidence; a `candidate` left by a
  non-resolving result) and red if a verified finding's evidence stops resolving.
- The `SandboxResult` firewall holds: the orchestrator reads only the typed result;
  raw target output is paged to the Store and never inlined or interpreted as
  instruction — the same discipline as the worker envelope.
- **The HARD STOP holds.** `DockerSandbox.run()` is guarded by a default-OFF
  `execution_enabled` flag, raises when off, and is never invoked. No test, smoke,
  or CLI path executes untrusted target code or calls `subprocess` with untrusted
  input. Enabling execution — and a real backend run (microVM per Phase 0 §0.3, or
  the container fallback) — is a distinct, later change behind **Mahdi's sign-off**.
- Every 001 and 002 test is still green and unweakened. No network transmission and
  no scope/authorization widening exists in the build. Those still arrive behind
  their own gates (004+).
