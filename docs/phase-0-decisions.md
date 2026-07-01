# Phase 0 — Pre-flight Decisions (recorded once, before feature 002)

Per the UltraCode build directive. These are decisions and confirmations, not
implementations. Feature 003's sandbox is **chosen** here but **not built**.

## 0.1 Gate interface — UNCONFIRMED → running on the default gate

The real HermesUltraCode pre-dispatch gate interface is **not confirmed**. Until
it is, the platform runs on the built-in default gate adapter, which enforces the
constitution's authorization and scope rules locally. Every status report says
so. When the HermesUltraCode interface is confirmed, the adapter is wired behind
the same three-outcome contract (`proceed` / `hold` / `refuse`) with no change to
callers.

- Current adapter: `deepthought.protocol.gate` — the default gate. `HermesUltraCodeGate`
  remains as the named seam; it currently delegates to the default behavior.

## 0.2 OSV schema version — PINNED

- **OSV schema version: `1.7.0`** (`OSV_SCHEMA_VERSION` in `export/osv.py`).
- The schema JSON is vendored at `src/deepthought/export/osv_schema.json`
  (draft 2020-12) and is the validator used by `check`. No network fetch at
  runtime.

## 0.3 Sandbox technology for feature 003 — CHOSEN (not built)

Target platform is the operator's Mac Studio dev lab. VERIFY must run a minimized
repro in an **isolated, egress-controlled** environment before any candidate is
promoted.

**Decision: ephemeral Linux microVM, network egress default-deny.**

- **Primary:** a per-run, ephemeral Linux **microVM** (Apple `Virtualization.framework`
  on Apple Silicon, or a Firecracker-class VM via a Lima/Krun backend). VM-level
  isolation is stronger than container namespaces for running untrusted target
  code, which is the whole point of Article III.
- **Egress control:** no network by default (default-deny). Any required egress is
  an explicit, logged allowlist per engagement, off by default.
- **Lifecycle:** built fresh per VERIFY run, torn down after. No persistence of
  target code or its side effects outside the paged evidence artifact.
- **Fallback / dev-fast path:** a rootless container with `--network none`,
  read-only root, dropped capabilities, and a seccomp profile — acceptable for
  low-risk repro during development, but the microVM is the default for anything
  that executes untrusted target code.

**Why this does not paint 003 into a corner:** the sandbox is reached only through
a `Sandbox` interface (mirroring the `Store`/`Gate` pattern), so the backing
technology (microVM vs container) is a single-adapter swap. VERIFY depends on the
interface, not the implementation. The evidence artifact contract (a resolving
`evidence_ref` paged to the Store) is independent of the sandbox technology.

**Hard stop reaffirmed:** nothing executes target code until this sandbox exists,
is tested for isolation and egress control, and is **signed off by Mahdi**.

## 0.4 001 re-verified GREEN

- `uv pip install -e .` (this venv is uv-created and has no `pip`; use `uv pip`).
- `pytest -q` → **95 passed**.
- `bash scripts/smoke.sh` → **PASS** end to end (real git-URL resolution, gate,
  lifecycle guard rejecting an illegal transition, corruption detected by
  `check`, human-gated `publish` transmitting nothing).

### Note: editable-install reproducibility fix

On Python 3.14, a cold/stale editable `.pth` install can silently drop `src/` from
`sys.path`, breaking the console script. `scripts/smoke.sh` now self-heals by
reinstalling if `import deepthought` fails, so a reviewer running the pre-flight
on a cold checkout gets a green smoke. Reproducible install command:
`uv pip install -e ".[dev]"`.
