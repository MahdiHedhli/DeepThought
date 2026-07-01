# Contract: Sandbox (VERIFY's isolated, egress-controlled execution boundary)

The sandbox is how the platform will one day run a minimized repro to produce the
evidence that promotes a candidate to `verified`. Running untrusted target code is
the highest-risk act in the platform, so it happens **only** behind this
interface, under a hardened, default-deny policy, and **only** after Mahdi's
sign-off (Constitution Article III; Phase 0 §0.3).

This slice delivers the sandbox as a *typed, tested interface*. Isolation is
proven by **inspecting the hardened run configuration** the sandbox would use — not
by running containers. A `NoopSandbox` test double lets VERIFY be exercised end to
end with **no execution**. The real executing backend's run path is the hard stop:
guarded off by default and never invoked here.

Two properties make this boundary safe, mirroring the worker `Envelope` firewall:

1. **The sandbox is the only door to execution.** VERIFY runs a repro only through
   `Sandbox.run`. There is no `subprocess`, no shell, no in-process execution of
   target code anywhere in VERIFY or the tests.
2. **The `SandboxResult` is a firewall.** The orchestrator reads only the typed
   result and its `stdout_ref`/`stderr_ref` pointers. Raw target stdout/stderr is
   paged to the Store and is never read into orchestrator context — the same
   discipline as the worker envelope.

## Module and public surface

`src/deepthought/sandbox/`:

```python
# base.py
class SandboxSpec(BaseModel):        # extra='forbid'
    """What to run: the minimized repro + the policy it runs under."""

class SandboxResult(BaseModel):      # extra='forbid'
    """The typed outcome. The ONLY thing VERIFY reads back from a run.
    Raw output is paged to the Store; this carries stdout_ref/stderr_ref only."""

class Sandbox(ABC):
    @abstractmethod
    def run(self, spec: SandboxSpec) -> SandboxResult:
        """Run the repro under spec.policy and return a typed result.
        Implementations must NOT return raw target output inline — they page it
        to the Store and return stdout_ref/stderr_ref pointers."""

# base.py
class SandboxPolicy(BaseModel):      # extra='forbid'
    """The hardened, default-deny run configuration. Default-constructed is fully
    hardened; an operator opts into LESS isolation explicitly, never MORE by
    omission."""

class SandboxError(RuntimeError):
    """Base error for the sandbox module."""

class SandboxExecutionDisabled(SandboxError):
    """The hard stop: raised by DockerSandbox.run when execution_enabled is False
    (the only shipped state)."""

# noop.py
class NoopSandbox(Sandbox):
    """Test double. Records the SandboxSpec it was handed and returns a
    caller-supplied canned SandboxResult. Executes NOTHING."""

class DockerSandbox(Sandbox):
    def __init__(self, *, execution_enabled: bool = False) -> None: ...
    def build_argv(self, spec: SandboxSpec, policy: SandboxPolicy) -> list[str]:
        """Pure config builder: the hardened `docker run` argv this run WOULD use.
        Never executes. This is what the isolation tests inspect."""
    def run(self, spec: SandboxSpec) -> SandboxResult:
        """HARD STOP. With execution_enabled False (the only shipped state) this
        raises SandboxExecutionDisabled and executes nothing. Enabling it — and a
        real backend run — requires Mahdi's sign-off."""
```

`Sandbox` mirrors the `Store` and `Gate` seams: one small interface, swappable
backends. VERIFY depends on the interface, not the backend, so the Phase 0 §0.3
microVM primary is a later single-adapter swap.

## `SandboxSpec`

The typed request. All fields validated; `extra='forbid'`.

```
image           str            # pinned, minimal runtime image. Data only.
command         list[str]      # the repro argv. NEVER a shell string.
repro_ref       str            # Store ref (detail/...) to the minimized repro input. A pointer.
workdir         str            # in-sandbox working dir. Default a non-privileged path.
env             dict[str,str]  # explicit, bounded. Default empty; no host env leaks in.
policy          SandboxPolicy  # required. There is no unpoliced run.
```

Rules:

- `command` is an argv list, never a shell string. Nothing in the sandbox ever
  builds a shell command from spec fields; there is no `shell=True` anywhere.
- `repro_ref` is a pointer to a Store artifact; the spec never inlines repro
  content.
- `policy` is required. A spec without a policy fails validation — there is no
  default-unhardened path.

## `SandboxPolicy` — hardened, default-deny

The isolation contract. The **default-constructed** policy is fully hardened; the
isolation tests assert its rendered argv contains every clause below.

```
network              Literal["none"] = "none"  # -> --network=none  (no egress; no allowlist in this slice)
read_only_rootfs     bool  = True        # -> --read-only
allow_host_mounts    bool  = False       # enforced off: NO -v / --mount host bind is ever rendered
drop_all_caps        bool  = True        # -> --cap-drop=ALL
no_new_privileges    bool  = True        # -> --security-opt=no-new-privileges
run_as_non_root      bool  = True        # gate: refuses to render a root run
user                 str   = "65534:65534" # -> --user <uid>:<gid>  (never root / 0)
pids_limit           int   = 128         # -> --pids-limit 128
memory_mib           int   = 512         # -> --memory 512m
cpus                 float = 1.0         # -> --cpus 1
wall_timeout_seconds int   = 30          # -> --stop-timeout 30  (ephemeral container torn down after)
ephemeral            bool  = True        # -> --rm   (built fresh per run, torn down after)
```

Policy discipline:

- **Default-deny.** Network egress is `Literal["none"]`, default `"none"` — the
  only value this slice honors. Any allowed egress is a later, explicit, logged,
  per-engagement opt-in, absent from this slice.
- **No host mounts.** `allow_host_mounts` is `False` and enforced off: `build_argv`
  never renders a `-v`/`--mount` host bind. The repro input reaches the sandbox as
  a controlled artifact, not a host-path bind.
- **Least privilege.** All capabilities dropped, `no-new-privileges`, non-root
  user. An operator can only opt into *less* isolation explicitly; omission always
  yields *more*.
- **Ephemeral.** `--rm` plus the wall-time bound: the environment is built fresh
  per run and torn down after, with no persistence of target code or side effects
  beyond the paged evidence artifact.

## `DockerSandbox` argv mapping

`build_argv(spec, policy)` renders the hardened policy into the exact `docker run`
argv a real run *would* use. It is a **pure function** returning a `list[str]` for
inspection; it executes nothing. The isolation test asserts every clause is
present:

```
docker run
  --rm                                   # policy.ephemeral
  --network=none                         # policy.network == "none"
  --read-only                            # policy.read_only_rootfs
  --cap-drop=ALL                         # policy.drop_all_caps
  --security-opt=no-new-privileges       # policy.no_new_privileges
  --user <uid>:<gid>                     # policy.user (non-root; never 0/root)
  --pids-limit <N>                       # policy.pids_limit
  --memory <N>m                          # policy.memory_mib
  --cpus <N>                             # policy.cpus
  --stop-timeout <N>                     # policy.wall_timeout_seconds
  --workdir <spec.workdir>               # spec.workdir
  # (NO -v / --mount host bind — allow_host_mounts enforced off)
  # (NO --env from host; only spec.env, explicit and bounded)
  <spec.image>
  <spec.command ...>                     # argv, never a shell string
```

Argv discipline:

- **Inspection, not execution.** `build_argv` output is data. The isolation tests
  assert over the list; nothing runs it in this slice. `subprocess` is never called
  with this (or any untrusted) input anywhere in 003.
- **Every hardening clause is present or the build fails a test.** A missing
  `--network=none`, a `root` user, an absent limit, or a rendered host mount is a
  test failure. The wall-time bound renders as `--stop-timeout` on the ephemeral
  (`--rm`) container and is asserted in the argv alongside the other clauses.
- **`run()` is the hard stop.** `DockerSandbox.run` is guarded by
  `execution_enabled` (default `False`). With the flag off — the only shipped state
  — `run()` raises `SandboxExecutionDisabled` and executes nothing. No test, smoke,
  or CLI path enables the flag or calls `run()`. Enabling it and adding a real
  backend run (microVM per Phase 0 §0.3, or the container fallback) is a distinct,
  later, Mahdi-signed-off change.

## `NoopSandbox` test double

The double VERIFY uses in this slice. It executes nothing.

```python
class NoopSandbox(Sandbox):
    def __init__(self, result: SandboxResult) -> None:
        self._result = result
        self.recorded: list[SandboxSpec] = []   # the specs it was handed

    def run(self, spec: SandboxSpec) -> SandboxResult:
        self.recorded.append(spec)               # RECORD the requested run
        return self._result                      # return the CANNED result; run nothing
```

- It **records** the `SandboxSpec` it was handed (so a test can assert VERIFY built
  a hardened, in-scope spec) and returns a caller-supplied canned `SandboxResult`.
- It **executes nothing** — no container, no subprocess, no daemon. This is what
  makes the VERIFY session tests hermetic: they pass with no Docker daemon and no
  network.
- A test supplies a *resolving* result (`reproduced=True`) to exercise promotion,
  and a *non-resolving* result (`reproduced=False`) to exercise the guard's
  rejection path.

## The firewall rule: the orchestrator sees only a typed `SandboxResult`

VERIFY (the orchestrator) reads **only** the typed `SandboxResult` and its
`stdout_ref`/`stderr_ref` pointers — never the raw target output. This is the same
firewall discipline as the worker `Envelope`/`Conductor`:

```
Sandbox.run(spec) ──▶ SandboxResult { reproduced, exit_code, timed_out, wall_seconds, stdout_ref, stderr_ref }
        │                       (raw stdout/stderr paged to the Store, NOT returned inline)
        ▼
VERIFY reads the TYPED result only ──▶ pages evidence via store.write_detail(...)
        │                              evidence_ref = detail/<session>/verify-result.txt
        ▼
if reproduced:  finding.evidence_ref = evidence_ref
                store.transition_finding(F-NNNN, verified)   ── the lifecycle guard
                       │  guard: evidence_ref non-empty AND detail_exists(evidence_ref)?
                       ▼  yes → candidate becomes verified
else:           finding stays candidate; blocking reason recorded on the finding
```

- **Raw output never reaches orchestrator context.** The `SandboxResult` carries
  `stdout_ref`/`stderr_ref` pointers only; the raw stdout/stderr lives in the Store
  under `state/detail/`. A repro whose output carries an injected instruction changes
  nothing beyond a data artifact — it is never read as instruction (Article VIII).
- **Promotion is at the Store boundary.** VERIFY pages evidence, sets the resolving
  `evidence_ref`, and asks `store.transition_finding` to promote. The guard —
  unchanged from 001 — owns the decision and requires the evidence to resolve
  (Article IV).
- **Nothing is transmitted.** The default policy egress is deny-all; the sandbox
  and VERIFY open no network path (Article V).

## What this contract does NOT do

- It does not execute an untrusted proof-of-concept. `NoopSandbox` executes
  nothing; `DockerSandbox.build_argv` is pure config; `DockerSandbox.run` is
  guarded off. Enabling execution is Mahdi's sign-off — the HARD STOP in `spec.md`.
- It does not require a Docker daemon, a microVM, or any network. Isolation is
  proven by inspecting the argv; VERIFY is proven with the `NoopSandbox`. Every
  test is hermetic.
- It does not call `subprocess` with untrusted input anywhere.
- It does not promote a finding by writing its status. Promotion is only ever
  through the Store lifecycle guard on a resolving `evidence_ref`.
- It does not add a network egress allowlist. The only behavior in this slice is
  default-deny; allowlisting is a later, explicit, logged, per-engagement opt-in.
