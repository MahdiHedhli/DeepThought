# Data Model: Execution sandbox and VERIFY (003)

**No new record types.** `VERIFY` reuses the existing records unchanged: `Finding`
(moving `candidate → verified`), `Session`, and `Coverage`. The Store interface is
untouched — no new method, no new schema field. Promotion happens through the
existing lifecycle guard at the Store boundary (`store.transition_finding`), and
the repro result is paged as *evidence* under `state/detail/` via the existing
`store.write_detail` / `store.detail_exists` pair.

The sandbox introduces three **runtime** models — `SandboxSpec`, `SandboxPolicy`,
and `SandboxResult`. These are Pydantic models with `extra='forbid'`, but they are
**not** persisted `Record`s: they live in `deepthought.sandbox`, not
`deepthought.schema`. What reaches the Store is a paged detail artifact plus the
finding's `evidence_ref` — exactly the shape the lifecycle guard already checks.
This document specifies how VERIFY uses the existing records, defines the three
runtime models, and documents the VERIFY evidence artifact.

## Records used, and how

### Finding (candidate → verified)

`VERIFY` reuses `deepthought.schema.finding.Finding` exactly as defined in 001.
Constraints specific to this feature:

- The input is a finding at `status = FindingStatus.candidate` (produced by
  DISCOVER in 002). VERIFY loads it, runs its minimized repro inside the sandbox,
  and — on a resolving result — promotes it to `FindingStatus.verified`.
- **Promotion is not a field write.** VERIFY sets `finding.evidence_ref` to the
  resolving detail ref and calls `store.transition_finding(finding.id,
  FindingStatus.verified)`. The guard (`FileStore._evaluate_transition`) enforces
  the `candidate → verified` edge: it requires a non-empty `evidence_ref` **and**
  `store.detail_exists(evidence_ref)`. VERIFY never assigns `status = verified`
  directly, and never bypasses the guard.
- `evidence_ref` is the `detail/<session>/verify-result.txt` ref returned by
  `store.write_detail` — a resolving pointer to the paged `SandboxResult`
  artifact. It is non-empty and resolves by construction when the repro
  reproduced; that is exactly what the guard checks.
- On a **non-resolving** result (the repro did not reproduce, or no evidence was
  paged), VERIFY does **not** set a resolving `evidence_ref`, so the guard rejects
  the transition. The finding stays `candidate`, and the guard records the blocking
  reason on the finding's `transition_log` (the Store already does this on a
  rejected transition). VERIFY surfaces that reason in its session summary.
- Backward transitions remain the Store's concern (allowed and logged when
  evidence weakens); VERIFY does not perform them in this slice.

Every field VERIFY touches is validated by the existing Finding model; nothing new
is added to the schema.

### Session (`SessionType.verify`)

`VerifySession` subclasses `BaseSession`, sets `.type = SessionType.verify` (already
present in the 001 `SessionType` enum — no schema change), and runs through the
unchanged `run_session` harness. It returns a `SessionOutcome` with a summary,
explicit next steps, and the finding it touched, so the harness can close the
session. A session with no `## Next steps` does not close.

### Coverage (optional)

VERIFY's primary teach-back is the finding transition and the evidence artifact;
it does not need to add coverage. If it records coverage at all it reuses
`deepthought.schema.coverage.Coverage` with `method = CoverageMethod.read`
unchanged (VERIFY read the finding and its repro; the actual execution — when later
enabled — happens inside the sandbox and is attested through the `SandboxResult`,
not by claiming `fuzz`/`static` coverage here). No new coverage method or depth is
introduced.

## Runtime models (not persisted records)

These live in `deepthought.sandbox`. They are Pydantic `BaseModel`s with
`extra='forbid'` and bounded fields, so an ill-formed spec/result fails validation
at the boundary — the same discipline as the envelope. The full field contract is
in `contracts/sandbox.md`; the summary shape:

### SandboxSpec — what to run

The typed request handed to `Sandbox.run`. It describes the minimized repro and
carries the policy under which it must run.

- `image` — the runtime image/base for the ephemeral environment (a pinned,
  minimal image; data only).
- `command` — the repro command as an argv `list[str]` (never a shell string; no
  `shell=True` semantics anywhere).
- `repro_ref` — a Store ref (under `state/detail/`) to the minimized repro
  artifact/input the run consumes. A pointer, not inlined content.
- `workdir` — the in-sandbox working directory (default a non-privileged path).
- `env` — an explicit, bounded environment map (default empty; no host env
  leaks in).
- `policy` — the `SandboxPolicy` (below). Required; there is no unpoliced run.

### SandboxPolicy — the hardened, default-deny configuration

The isolation contract, hardened by default. Its **presence** and its **default
values** are what the isolation tests assert (via `DockerSandbox.build_argv`, the
policy renderer behind the `build_command` convenience wrapper):

- `network` — egress mode, `Literal["none"]` default `"none"` (renders
  `--network=none`). No allowlist in this slice.
- `read_only_rootfs` — default `True` (renders `--read-only`).
- `allow_host_mounts` — default `False` and enforced in this slice (no `-v`/`--mount`
  host bind is ever rendered).
- `drop_all_caps` — default `True` (renders `--cap-drop=ALL`).
- `no_new_privileges` — default `True` (renders
  `--security-opt=no-new-privileges`).
- `run_as_non_root` — default `True`; with `user` (default `"65534:65534"`) it
  renders `--user <uid>:<gid>`, never `root`/`0`.
- `pids_limit` — a positive integer cap, default `128` (renders `--pids-limit`).
- `memory_mib` — a positive MiB cap, default `512` (renders `--memory 512m`).
- `cpus` — a positive fractional CPU cap, default `1.0` (renders `--cpus`).
- `wall_timeout_seconds` — a positive wall-clock timeout, default `30`. Renders
  `--stop-timeout` (the SIGKILL grace period on stop); the wall-clock EXECUTION
  limit itself is enforced externally by the runner when a real backend is wired,
  not by this flag. The ephemeral container is `--rm`, torn down after.
- `ephemeral` — default `True` (renders `--rm`; built fresh per run, torn down
  after; no persistence of target code or side effects beyond the paged evidence).

The default-constructed `SandboxPolicy()` is fully hardened: an operator opts into
*less* isolation explicitly (and, for network egress, only later behind a logged
per-engagement allowlist), never into *more* by omission.

### SandboxResult — the typed outcome (a firewall)

What `Sandbox.run` returns, and the **only** thing VERIFY reads back from a run.
Mirrors the worker `Envelope`: it is typed, bounded, and carries a pointer to
paged detail, never the raw output itself.

- `reproduced` — a bool verdict: did the minimized repro reproduce the vulnerable
  behavior? This is the evidence gate for promotion.
- `exit_code` — the run's exit status (int).
- `timed_out` — a bool: did the run hit `wall_timeout_seconds` and get torn down?
- `wall_seconds` — the wall-clock duration (`float`, `>= 0`). Data, for
  observability.
- `stdout_ref` / `stderr_ref` — optional Store refs to the paged raw stdout/stderr
  artifacts under `state/detail/`. Pointers only; **the orchestrator never loads
  their content**.

VERIFY reads `reproduced`, `exit_code`, `timed_out`, and `wall_seconds` — all
typed. It never reads the raw target stdout/stderr; that is what `stdout_ref` /
`stderr_ref` point at, and it stays in the Store, out of orchestrator context.
This is the `SandboxResult`-as-firewall rule (Article VIII), the same discipline
the `Conductor` applies to a worker `Envelope`.

## The VERIFY evidence artifact

The evidence that unlocks `candidate → verified` is a paged detail artifact, not a
new record type:

1. VERIFY builds a `SandboxSpec` (the candidate's minimized repro + a hardened
   `SandboxPolicy`) and calls the injected `Sandbox.run(spec)`. In this slice the
   injected sandbox is a `NoopSandbox`, which records the spec and returns a
   caller-supplied canned `SandboxResult` — nothing executes.
2. VERIFY pages the run's raw output (and a short, typed summary of the
   `SandboxResult`: the `reproduced` verdict, exit code, resource usage, and the
   enforced policy) to the Store:
   `evidence_ref = store.write_detail(session_id, "verify-result.txt", <content>)`
   → `detail/<session>/verify-result.txt`.
3. If `SandboxResult.reproduced` is true, VERIFY sets `finding.evidence_ref =
   evidence_ref`, saves the finding, and calls
   `store.transition_finding(finding.id, FindingStatus.verified)`. The guard checks
   the ref is non-empty and `detail_exists(evidence_ref)` — both true — and
   promotes the finding.
4. If `SandboxResult.reproduced` is false, VERIFY still pages the artifact (the
   negative result is durable state), but does **not** set a resolving
   `evidence_ref` for promotion. The transition is rejected by the guard; the
   finding stays `candidate`; the blocking reason is recorded on the finding.

`check` then holds: a `verified` finding has a resolving `evidence_ref` (the
`_check_lifecycle_at_rest` rule for `verified`), and a `candidate` has no
lifecycle-at-rest obligation — so both outcomes leave the Store green.

## Notes

- All writes go through the `Store`. VERIFY reads the finding, pages the evidence
  via `write_detail`, saves the finding, and transitions via `transition_finding`.
  It never touches `state/` directly and never writes `status=verified` by hand.
- The sandbox models are runtime types, not persisted records — no on-disk record,
  no Store method, and no schema field is added in this feature.
- Nothing here executes untrusted target code. The `NoopSandbox` executes nothing;
  the `DockerSandbox` builds config only, its `run()` guarded off. The first real
  execution is behind Mahdi's sign-off (the HARD STOP in `spec.md`).
- Nothing is transmitted. The default sandbox egress is deny-all; VERIFY opens no
  network path.
