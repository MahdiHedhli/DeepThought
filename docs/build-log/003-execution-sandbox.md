# Build Session Log — Feature 003, Execution Sandbox (VERIFY)

> **STATUS: MERGED to `main` 2026-07-01 (squash commit `440485a`), PR #2.** SAFE
> build — the sandbox is a typed, isolation-tested interface; **no target code
> executes**. `DockerSandbox.run()` is guarded OFF and raises
> `SandboxExecutionDisabled` (the HARD STOP). **310 tests green; all three smokes
> (`smoke.sh`, `smoke_002.sh`, `smoke_003.sh`) pass on `main`.**
>
> **Review: clean by codex + an independent Antigravity/Gemini adversarial review**
> (the `agy` CLI, substituting for the quota-blocked `gemini-code-assist` bot). The
> loop ran ~6 GitHub-bot rounds (findings 11→5→2→1→1→2, all fixed test-first) plus
> a 2-round `agy` adversarial pass that caught **6 further real defects both bots
> missed**: the isolation flags were tunable booleans (now `Literal`-locked); a
> named `--user` could alias to UID 0 (now numeric-only); `cpus=inf` crashed the
> argv renderer (now finite); the CLI didn't catch `SandboxError`; the image
> `ENTRYPOINT` could run instead of the repro (now forced via `--entrypoint`); an
> empty `command[0]` cleared the entrypoint (now rejected); the `--user` gate
> rendered the raw string (now normalized). Both reviewers were CLEAN on the merged
> commit `495a2ef`.
>
> Next: **HARD STOP** — wiring VERIFY to execute real target code needs Mahdi's
> sandbox sign-off before `execution_enabled` is ever flipped. The safe next
> feature (004) proceeds per the gate-first/test-first pattern.

**Feature:** 003-execution-sandbox
**Branch:** `003-execution-sandbox`
**Predecessor gate:** 002 merged to `main` (PR #1, squash `2d200fa`).

## What shipped

The execution sandbox as a typed seam, and the VERIFY session behind it. Isolation
is proven by **inspecting** the hardened run configuration, never by running
containers.

- **Sandbox interface** (`sandbox/base.py`): `SandboxPolicy` (hardened,
  default-deny: `network='none'`, `read_only_rootfs`, `allow_host_mounts=False`,
  `drop_all_caps`, `no_new_privileges`, `run_as_non_root` with a non-root `user`,
  positive `pids_limit`/`memory_mib`/`cpus`/`wall_timeout_seconds`, `ephemeral`;
  `extra='forbid'`), `SandboxSpec` (an argv `command: list[str]` — never a shell
  string — plus a required `policy` and a `repro_ref` pointer), `SandboxResult`
  (the typed firewall: `reproduced`, `exit_code`, `timed_out`, `wall_seconds`,
  and `stdout_ref`/`stderr_ref` *pointers* — never raw output inline), the
  `Sandbox` ABC, `SandboxError`, and `SandboxExecutionDisabled(SandboxError)`.
- **DockerSandbox** (`sandbox/docker.py`): `build_argv(spec, policy)` (aliased by
  the `build_command(spec)` wrapper) renders the hardened `docker run` argv —
  `--rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges
  --user <nonroot> --pids-limit --memory Nm --cpus N --stop-timeout N --workdir` and
  the `spec.image` + `spec.command` argv, with **no** `-v`/`--mount` host bind and
  **no** host `--env`. It returns a `list[str]` for inspection and executes
  nothing. `run()` is the **HARD STOP**: guarded by `execution_enabled` (default
  `False`, the only shipped state), it raises `SandboxExecutionDisabled` and never
  reaches a `subprocess` call.
- **NoopSandbox** (`sandbox/noop.py`): the test double. Records the spec it was
  handed and returns a caller-supplied canned `SandboxResult`. Executes nothing.
- **VERIFY session** (`sessions/verify.py`): promotes a *candidate* to *verified*
  on sandboxed evidence. The injected `Sandbox` is the only door to execution; in
  tests it is a `NoopSandbox`, so no target code runs. VERIFY reads only the typed
  `SandboxResult`, pages a short evidence artifact, sets the resolving
  `evidence_ref`, and promotes **through the Store lifecycle guard** (never a
  hand-written `status = verified`). A non-reproducing run pages the negative
  artifact and leaves the finding a candidate. A non-candidate finding is refused
  outright.
- **CLI**: `playbook verify` (Noop-backed; never enables execution, never calls
  `DockerSandbox.run()`). **Smoke**: `scripts/smoke_003.sh`.
- **Spec Kit artifacts**: `specs/003-execution-sandbox/{spec,plan,data-model,tasks}.md`
  and `contracts/sandbox.md`.

## Gate results (the done-gate)

| Gate | Result |
| --- | --- |
| Tests written first, `pytest -q` green | **280 passed** (224 from the 001/002 baseline preserved, none weakened; +56 for 003) |
| Feature smoke end to end | `scripts/smoke_003.sh` **PASS** — Noop-backed VERIFY promotes a candidate on a resolving (`reproduced=True`) result; `check` stays green |
| 001 + 002 smokes still green | `scripts/smoke.sh` **PASS**, `scripts/smoke_002.sh` **PASS** |
| Constitution check | **pass** — III (execution) HELD: `run()` guarded OFF, raises `SandboxExecutionDisabled`, zero `subprocess`/`exec`/daemon anywhere; IV promotion only through the Store guard on resolving evidence; VIII `SandboxResult` firewall (raw output paged, pointers only); IX least privilege (hardened default policy) |
| Independent review | In-workflow adversarial safety review: `executes_untrusted_code=false`, `hard_stop_intact=true`, `isolation_locked_down=true`, verdict **PASS** |

## The HARD STOP

Feature 003 delivers the sandbox and VERIFY **without ever executing target
code**. `execution_enabled` ships `False`; no test, smoke, or CLI path flips it.
Wiring VERIFY to execute a real repro against a real backend is a **distinct,
later change** that must not land until Mahdi signs off on the sandbox (Phase 0
§0.3: ephemeral microVM primary, default-deny egress; hardened container
fallback). An NTFY HARD-STOP alert to `Mahdi-Dev` precedes that change; it waits
on sign-off.

## Review status & advance decision

**NOT merged.** Per the directive, the done-gate requires a real, independent
external review; silence / quota / error is an incomplete review, never a pass.
Branch pushed and a PR opened with `@codex review` / `/gemini review` requested;
the merge waits on a clean external pass. The advance beyond the SAFE slice (real
execution) additionally waits on Mahdi's sandbox sign-off.
