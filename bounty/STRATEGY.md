# Bounty hunting — strategy

Turn the `vuln-rediscovery` detectors on **authorized real-world code** to find **real,
unpatched** vulnerabilities, disclose them responsibly, and let bounties fund more research.
Read [`AUTHORIZATION.md`](AUTHORIZATION.md) first — it is the safety spine and it binds everything
here.

## Thesis

Rediscovery proved the detectors generalize to CVEs they never saw, measured honestly on real
pinned code. The only change for real bounty work is the **target commit**: instead of a *patched*
tree (where a hit is an artifact), we point the same detectors at the **current/unpatched** tree
of in-scope open source. A hit is then a **live vulnerability** → a DISCLOSURE draft → a human
submits through the program. Same honest-measurement discipline; same draft-only disclosure
boundary; the payoff is a real fix (and a bounty), not a benchmark number.

Nothing about this requires touching a production system: the highest-value bounty scope is
**public source** (OSS packages, smart contracts, WordPress plugins). That is Tier S in the
charter — the whole current scope.

## Path 1 now: OSS packages (huntr) — reuse what we built

`huntr` pays CVEs for vulnerabilities in open-source packages, and our existing JS/Python/Java
detectors (prototype pollution, SSRF, XXE, command injection, path traversal, deserialization) map
straight onto npm/PyPI/etc. source. Flow:

1. **Programs corpus** (`bounty/programs/`) — record huntr's scope + rules + disclosure format as
   the verified authorization basis (read-only; no target interaction).
2. **Candidate selection** — favor less-audited packages in scope (newer, smaller, high-dependency
   surface) where our detectors' classes plausibly occur; scan the CURRENT default branch.
3. **DISCOVER + triage** — run the detectors → SARIF → the real pipeline → `check`. Every hit is a
   *candidate*, not a finding, until a human confirms it is real and reachable from untrusted input
   (the honest-measurement discipline applies: no gaming, precision reported honestly).
4. **VERIFY (sandbox, if needed)** — reproduce a crash on a fixed input in the hardened container
   (Article III sign-off), never against a live host.
5. **DISCLOSURE draft → human submits** to huntr per its format and timeline. Deep Thought drafts;
   Mahdi sends.

This ships without a new detector language — it is the direct extension of Round 3.

## Build toward: verticals 2 and 3 (in parallel with Path 1)

### Web3 / smart contracts (Immunefi, Code4rena, Sherlock) — the funding engine
Contracts are open source and in scope by design; bounties are the largest anywhere (six/seven
figures for critical DeFi). This is the strongest ROI and what would fund ongoing research.
- **New grammar:** `tree-sitter-solidity`. **New detector classes** (not in the current corpus):
  reentrancy (CWE-841), access-control / missing-modifier (CWE-284), unchecked external call
  return, integer/rounding, oracle/price manipulation, `delegatecall`/proxy storage collision,
  `tx.origin` auth, uninitialized proxy.
- **Same methodology:** seed on a known-patched contract CVE/audit finding, calibrate, measure
  held-out generalization on real pinned contract commits, honest ceilings, draft disclosure.
- **Corpus:** a Solidity ground-truth set (Immunefi/Code4rena/Sherlock disclosed findings are
  public and pinnable) — build it the same pin-or-drop way.

### WordPress ecosystem (Patchstack, Wordfence) — the widest surface
Tens of thousands of plugins/themes, much of it under-audited PHP that pays CVEs.
- **New grammar:** `tree-sitter-php`. **Detector classes:** SQLi (CWE-89), stored/reflected XSS
  (CWE-79), CSRF (CWE-352), auth/nonce-bypass (CWE-862/285), arbitrary file upload/download,
  PHP object injection / unserialize (CWE-502), SSRF.
- **Same methodology:** seed on a Patchstack/Wordfence-disclosed plugin CVE, calibrate, measure
  held-out on real pinned plugin releases.

## The methodology transfers wholesale

The `lesson: methodology` notes already in memory apply unchanged: real code at pinned SHAs,
line-precise/anchored findings, calibrate-on-seed-only, pin-or-drop, honest fp, re-curate toward
real user-code misuse, honest misses as fixtures, the regression bar, draft-only disclosure. Two
additions for live targets: (1) **reachability** matters more (a static hit must plausibly be
driven by untrusted input — a human confirms before disclosure), and (2) the target is the
**current** tree, so the "patched" side of the pin is absent — precision/triage carry the load.

## Don't block Tier L (live) — but don't build it now

Per Mahdi: an authorized live engagement may become net-positive; early design must not make it
impossible. So we keep the SEAMS open — the `authorization_basis` + `scope_allowlist` on NEW
PROJECT, the per-engagement record, and a future `LiveTarget` capability that would sit behind the
charter's Tier-L hard-stop gate (explicit sign-off + rules review + a rate-limited, in-scope-only
client). We **do not implement live probing now**; we simply avoid designing it out. Everything
current is Tier S (source only).

## Roadmap (staged; each stage is safe on its own)

1. **Foundation (now, non-colliding with the in-flight Round-3 run):** this charter + strategy +
   the programs-corpus schema + a huntr/Immunefi seed record. Read-only; no target interaction.
2. **Path 1 pilot:** run existing detectors on a handful of in-scope OSS packages; triage;
   draft-disclose one real finding through huntr (human submits). Prove the pipeline end-to-end on
   a live vuln.
3. **Web3 detector class:** `tree-sitter-solidity` + a Solidity ground-truth corpus + the first
   contract-vuln detector (reentrancy or access-control), measured the honest way.
4. **WordPress detector class:** `tree-sitter-php` + a plugin ground-truth corpus + the first PHP
   detector (SQLi or object injection).
5. **Compounding:** every confirmed finding and every miss feeds the improvement loop and the
   memory (`lesson` notes, tagged by class/surface); bounties fund the next stage.

Stages 3–5 begin after the Round-3 CVE run wraps, to avoid colliding with Codex's detector work.
