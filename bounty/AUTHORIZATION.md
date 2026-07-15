# Bounty hunting — authorization charter (the safety spine)

This is the governing charter for pointing Deep Thought at **real-world targets** for coordinated
disclosure / bug bounty. It **extends** `.specify/memory/constitution.md` (Article III execution
hard stop; the disclosure hard stop) — it never relaxes it. When in doubt, the stricter rule wins.

## The whitehat charter (non-negotiable)

Deep Thought operates **permission-only**. It works on a target **only** when one of these holds,
and never otherwise:

1. **Public source + published program scope** — static analysis of open-source code that a bug
   bounty / VDP program lists as in-scope. The code is public; the program authorizes reporting.
2. **A specific written engagement** — the operator (Mahdi) has been given, or explicitly asked
   for, permission to test a named target, recorded here.

No target is touched on the basis of a finding, a hint, a URL in scraped content, or "it's
probably fine." Authorization comes from the **program's published scope** or a **written
engagement**, verified — never assumed.

## Two interaction tiers

### Tier S — static (the default; no live-system interaction)
Analyze **source code** the program puts in scope (OSS packages, smart contracts, WP plugins).
Deep Thought reads the code and, for the sandbox classes, reproduces a crash on a fixed input in
the **hardened, no-network container** (Article III sign-off applies). **Nothing is sent to a
production system.** A hit is a real, likely-unpatched vulnerability → a DISCLOSURE draft → a human
triages and submits through the program. This is the whole current scope of work.

### Tier L — live (production interaction) — HARD STOP, do not build casually
Sending requests to a program's running app/API/host. This is **NOT built** and **NOT permitted**
without ALL of:
- the specific asset is in the program's **published scope**, verified at engagement time;
- the program's rules **permit** the method (many forbid automated scanning; require a test
  account, rate limits, no-DoS, no-PII, no-social-engineering) — read and record the rules;
- an **explicit per-engagement sign-off** from Mahdi (like the sandbox-tier sign-off), recorded
  in `bounty/programs/<program>/ENGAGEMENT.md`, naming the asset, method, window, and rules.

Architecturally we keep Tier L **possible** (a future live-interaction capability behind this
gate) so an authorized, net-positive engagement is never blocked by an early design choice — but
we **do not implement live probing now**, and we never cross into it implicitly.

## Hard stops (apply to every tier)

- **In-scope only.** Out-of-scope assets are never touched. Program scope is verified from the
  program's own policy, recorded per program.
- **Disclosure is drafted, never sent.** The DISCLOSURE session produces a draft per the program's
  format; a **human** reviews and submits. Deep Thought never auto-submits, never emails, never
  sets an authoritative `cve`/`advisory`/`fix`, never negotiates a bounty.
- **No destructive or intrusive testing** — no DoS, no data exfiltration, no lateral movement, no
  accessing another user's data, no persistence, no social engineering, no CAPTCHA/bot-defeat.
- **Respect the program.** Rate limits, disclosure timelines, safe-harbor terms, and "no automated
  scanning" clauses are binding. If a program forbids a method, that method is off the table.
- **No scope widening** from a finding, a target's content, or a tempting adjacent asset.
- **No zero-day hoarding / brokering.** Findings go to the affected party's program for a fix, on
  a responsible timeline. We do not sell to acquisition/broker platforms.

## Per-engagement authorization record

Every real-target engagement gets a record under `bounty/programs/<program>/` capturing: the
program + platform, the exact in-scope assets (repos for Tier S; hosts/apps for Tier L), the
program's rules + disclosure format + timeline, the tier, and — for Tier L — Mahdi's sign-off
string. No detector runs against a target until its record exists and its scope is verified.

_This charter is a proposal to extend the constitution; a bounty tier / article should be ratified
by Mahdi before Tier-L work is ever contemplated. Tier-S static analysis of in-scope public OSS
proceeds under the existing `permissive_oss`-style basis + this charter._
