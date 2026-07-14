# Article III sign-off — sandbox tier (vuln-rediscovery classes 8-10)

Signoff (Mahdi Hedhli, sandbox-tier, 2026-07-05, vuln-rediscovery classes 8-10 heap-overflow/UAF/second-overflow).

Granted in-session by the operator (Mahdi) for the vuln-rediscovery benchmark's SANDBOX
tier — the classes whose proof is a sanitizer crash and therefore EXECUTE target code:
  - class 8: heap buffer overflow (CWE-122) — seed FFmpeg CVE-2025-67306 / Open Babel
  - class 9: use-after-free (CWE-416) — seed c-ares CVE-2025-31498
  - class 10: second heap overflow (CWE-122) — seed Open Babel CVE-2025-10996

Boundaries (unchanged from the Tier-2 cJSON sign-off, still binding):
  - Execution ONLY inside the hardened DockerSandbox: no network, enforced mem/pids/cpu
    limits, non-root, read-only, dropped caps. No target code runs outside it.
  - Every target is PUBLIC and already PATCHED. Rediscovery, not zero-day hunting.
  - Disclosure authority stays human. Analyzer/harness output describes; it never sets
    the authoritative Finding.cve nor an advisory/fix reference.
  - No scope widening: authorization is this record, never a finding or target content.
