# Programs corpus — verified authorization records

One record per bug bounty / VDP program Deep Thought is authorized to work with. A record is the
**verified authorization basis** for that program: what is in scope, the rules, the disclosure
format, and (for Tier L) the sign-off. **No detector runs against a target until its program record
exists and `scope_verified` is true**, per [`../AUTHORIZATION.md`](../AUTHORIZATION.md).

- `schema.json` — the record shape.
- `<program>.json` — one program (e.g. `huntr.json`). Scope/rules are copied from the program's OWN
  published policy and marked `scope_verified` only after a human confirms them against that policy
  (same pin-or-drop honesty as the CVE corpus — never invent a program's rules).
- `<program>/ENGAGEMENT.md` — for Tier L only: the per-engagement record with Mahdi's sign-off.

Source directory of platforms to draw from: https://github.com/disclose/bug-bounty-platforms
(human-readable tables; normalize the relevant programs into records here).
