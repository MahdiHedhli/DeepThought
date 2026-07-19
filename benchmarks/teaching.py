"""teaching.py — canonical pedagogy for DeepThought's static vuln classes.

The single source of teaching truth behind the public "learn" experience (``benchmarks/learn.py``)
and, later, the bounty harness's follow-along mode. For each CWE a DeepThought detector can emit it
holds: a plain-language name, WHY the class matters, a DISPROVE-FIRST triage checklist (rule these
out and the candidate is likely real), common FALSE-POSITIVE shapes, and a deeper LEARN note.

Teaching principle, stated once and meant throughout: **static analysis surfaces a PATTERN, not a
proven bug.** A candidate is not a finding until a human confirms it is reachable from untrusted
input. The detector reads source as DATA (an AST) — it never executes it.
"""
from __future__ import annotations

from typing import Any, Optional

# CWE-keyed teaching. Keyed by the exact CWE string the detectors emit.
CWE_TEACHING: dict[str, dict[str, Any]] = {
    "CWE-918": {
        "name": "SSRF (server-side request forgery)",
        "why": "an attacker-controlled URL/host reaches an outbound request, letting them pivot to "
               "internal services, cloud metadata (169.254.169.254), or loopback.",
        "confirm": [
            "trace the URL/host back to untrusted input (request param, body, header, webhook)",
            "confirm no allowlist / IP-block / scheme check sits between the source and the request",
            "confirm the sink actually makes a network request with the tainted value (not a constant)",
        ],
        "refute": [
            "the host is a hardcoded constant or trusted config, not from the request",
            "an SSRF-proxy / allowlist wraps the call",
        ],
        "learn": "The dangerous move is letting user input decide WHERE the server connects. Fixes "
                 "pin the destination (allowlist of hosts/schemes) or resolve+block private IP ranges "
                 "before connecting — DeepThought's detector flags the sink that swaps a validated URL "
                 "for a raw one.",
    },
    "CWE-1321": {
        "name": "prototype pollution",
        "why": "a computed property write/merge with an externally-derived key can set __proto__ / "
               "constructor.prototype, corrupting every object and enabling auth bypass / RCE gadgets.",
        "confirm": [
            "the written/merged key is derived from untrusted input (parsed JSON, query, path)",
            "no guard rejects __proto__ / constructor / prototype before the write",
            "the merge/clone recurses into nested keys (deep-merge is the classic sink)",
        ],
        "refute": [
            "keys are validated against an allowlist, or Object.create(null) / Map is used",
            "the write target is a fresh object never used as a prototype",
        ],
        "learn": "JavaScript objects share a prototype chain; writing __proto__.x sets x on EVERY "
                 "object. The bug is a recursive merge that trusts attacker-chosen keys — the fix is a "
                 "key guard on the exact write.",
    },
    "CWE-611": {
        "name": "XXE (XML external entity)",
        "why": "an XML parser with DTD/external-entity resolution enabled on untrusted input can read "
               "local files, SSRF, or DoS (billion-laughs).",
        "confirm": [
            "the parsed XML is untrusted (upload, request body, third-party feed)",
            "DTDs / external general + parameter entities are NOT disabled on this parser instance",
            "this parser is the one used on the tainted input (not a hardened sibling)",
        ],
        "refute": [
            "secure-processing / disallow-doctype-decl / resolve-entities=false is set",
            "a hardened parser factory wraps every parse",
        ],
        "learn": "XXE is a CONFIGURATION bug: the same parser is safe or unsafe depending on one flag. "
                 "That is why the detector keys on how the parser is constructed, and why the honest "
                 "ceiling is lower — some fixes live in config a line-precise rule can't always see.",
    },
    "CWE-78": {
        "name": "OS command injection",
        "why": "untrusted input reaches a shell-exec sink without escaping, giving arbitrary command "
               "execution.",
        "confirm": [
            "the command/argument string contains untrusted input",
            "the sink runs via a shell (shell=True / exec / system / backticks), not an argv array",
            "no shell-escaping / allowlist guards the tainted segment",
        ],
        "refute": [
            "the call uses an argv list with shell=False and a constant binary",
            "input is validated against a strict allowlist first",
        ],
        "learn": "The fix is almost always 'stop using a shell': pass an argv array so the OS never "
                 "re-parses metacharacters. The detector flags the string-built shell command reachable "
                 "from input.",
    },
    "CWE-502": {
        "name": "unsafe deserialization",
        "why": "deserializing untrusted bytes with a format that can instantiate arbitrary types "
               "(pickle, node-serialize, unsafe YAML) yields RCE via gadget chains.",
        "confirm": [
            "the deserialized bytes are untrusted (cookie, body, cache, message)",
            "the deserializer can construct arbitrary objects (not a pure data JSON.parse)",
            "the receiver is bound to that untrusted source (import + call provenance)",
        ],
        "refute": [
            "a safe loader / schema-validated JSON is used, or the input is signed+verified first",
        ],
        "learn": "Deserialization can be Turing-complete: some formats rebuild live objects (and run "
                 "their constructors). Treat serialized input as executable — sign it, or use a "
                 "data-only format.",
    },
    "CWE-22": {
        "name": "path traversal / archive slip",
        "why": "an untrusted path segment reaches a filesystem sink without containment, allowing ../ "
               "escape to read/write outside the intended directory (or tar/zip slip on extract).",
        "confirm": [
            "the path/name is untrusted (upload filename, request param, archive entry name)",
            "no containment (realpath-under-base / basename / normalize+prefix-check) guards it",
            "the exact tainted path is the one passed to open/join/extract",
        ],
        "refute": [
            "the resolved path is checked to stay under a fixed base before use",
            "only a basename is used, or entries are validated on extract",
        ],
        "learn": "The escape is ../../. The fix is to resolve the final path and assert it stays under a "
                 "trusted base BEFORE touching the filesystem. tarfile.extractall on untrusted archives "
                 "is the classic 'zip slip' variant.",
    },
    "CWE-113": {
        "name": "CRLF injection / HTTP response splitting",
        "why": "unsanitized input carrying \\r\\n into a response header lets an attacker inject headers "
               "or split the response (cache poisoning, XSS, session fixation).",
        "confirm": [
            "the value written into a header/cookie/redirect contains untrusted input",
            "no CR/LF stripping or header-API encoding sits before the write",
            "the sink serializes name+': '+value+CRLF (or sets a header/cookie) with the raw value",
        ],
        "refute": [
            "the framework's header API rejects/encodes CR/LF (most modern ones do)",
            "the value is a constant or strictly validated (e.g. an enum)",
        ],
        "learn": "Headers are newline-delimited; a newline in a value starts a new header (or body). "
                 "Fixes strip CR/LF or use an API that forbids them — the detector flags the raw "
                 "serialize/store.",
    },
    "CWE-90": {
        "name": "LDAP injection",
        "why": "untrusted input concatenated into an LDAP filter without RFC-4515 escaping lets an "
               "attacker alter the query (auth bypass, data disclosure).",
        "confirm": [
            "the value goes into an LDAP search FILTER (not just an attribute value)",
            "no RFC-4515 filter-context escaping is applied to the tainted value",
            "the value's provenance is untrusted and reaches the exact filter build",
        ],
        "refute": [
            "the input is escaped with the library's filter-escape before concatenation",
            "a parameterized/assertion API is used instead of string-built filters",
        ],
        "learn": "Like SQLi but for directories: the fix is filter-context escaping of the exact "
                 "operand, which is why the detector tracks value + receiver provenance in filter "
                 "position.",
    },
    "CWE-943": {
        "name": "NoSQL operator injection",
        "why": "an untrusted identity field passed as an object into a Mongo-style query lets an "
               "attacker inject operators ($ne, $gt, $where) to bypass auth or dump data.",
        "confirm": [
            "an identity/login field from the request reaches a query WITHOUT a typeof-string guard",
            "the value can be an object (JSON body / parsed query) rather than a scalar",
            "the query engine interprets operator keys ($ne, $gt, $where)",
        ],
        "refute": [
            "a typeof === 'string' (or schema/cast) guard forces the value to a scalar first",
            "the field is bound as a value, never as an object",
        ],
        "learn": "{'password': {'$ne': null}} matches any password. The one-line fix is to require the "
                 "field be a string before it reaches the query — exactly the guard the detector looks "
                 "for.",
    },
    "CWE-601": {
        "name": "open redirect",
        "why": "an untrusted URL used as a redirect target sends users to an attacker site (phishing, "
               "OAuth token theft) under the trusted domain's name.",
        "confirm": [
            "the redirect target is derived from untrusted input (a 'next'/'returnUrl' param)",
            "no same-origin / allowlist / safe-path-prefix check dominates the redirect",
            "the sink is an actual redirect (Location header / res.redirect) with the tainted value",
        ],
        "refute": [
            "the target is validated same-origin, or restricted to a relative path prefix",
            "the redirect uses a fixed/allowlisted URL",
        ],
        "learn": "The subtlety is bypasses: //evil.com, /\\evil.com, and absolute URLs all escape a "
                 "naive check. A correct fix enforces same-origin or a safe relative prefix — the "
                 "detector models that guard's dominance.",
    },
    "CWE-89": {
        "name": "SQL injection",
        "why": "untrusted input concatenated into a SQL query changes its structure, enabling data "
               "theft, auth bypass, or writes.",
        "confirm": [
            "the tainted value is part of the query STRUCTURE construction (not a later constant append)",
            "no parameterization/binding is used for that value",
            "the value's provenance is untrusted and reaches the exact query build",
        ],
        "refute": [
            "the value is bound as a parameter (? / :name), not concatenated",
            "an ORM/query-builder parameterizes it",
        ],
        "learn": "The fix is parameterized queries — the DB then treats the value as data, never as "
                 "SQL. The detector reports the UNSAFE construction site, not a later safe append, so "
                 "the fix location is honest.",
    },
    "CWE-1336": {
        "name": "SSTI (server-side template injection)",
        "why": "untrusted input rendered by an UNSANDBOXED template engine can reach the object graph "
               "and achieve RCE (Jinja/Twig/etc.).",
        "confirm": [
            "untrusted input is used to build or render a template (not just passed as a bound variable)",
            "the engine/environment is NOT sandboxed (e.g. Jinja Environment vs SandboxedEnvironment)",
            "the import provenance shows the unsandboxed constructor",
        ],
        "refute": [
            "a SandboxedEnvironment (or autoescape + no template-from-input) is used",
            "input is only a rendered VALUE, never part of the template source",
        ],
        "learn": "The bug is treating user input as TEMPLATE CODE. The discriminator is the sandbox: "
                 "the detector keys on the unsandboxed Environment/Template constructor via import "
                 "provenance.",
    },
}

# CWE aliases some detectors/reports may use for the same class.
_ALIASES = {"CWE-94": "CWE-1336"}


def teaching_for(cwe: str, rule: str = "") -> Optional[dict[str, Any]]:
    """The teaching note for a candidate's CWE (rule id accepted but CWE is the key)."""
    key = (cwe or "").upper()
    key = _ALIASES.get(key, key)
    return CWE_TEACHING.get(key) or CWE_TEACHING.get((rule or "").upper())


def methodology_notes() -> list[str]:
    """The DeepThought way of thinking — the meta-lessons a student should carry away, independent of
    any single CWE."""
    return [
        "A candidate is NOT a finding. Static analysis surfaces a PATTERN; only a human who confirms "
        "the sink is reachable from untrusted input turns a candidate into a finding.",
        "Disprove first. Try hardest to REFUTE each candidate (find the guard, the sanitizer, the "
        "constant) before believing it — the same discipline that keeps the benchmark numbers honest.",
        "Line-precise. A real finding names the EXACT sink line and the unsafe construction, not a "
        "vague 'somewhere in this file' — that precision is what makes rediscovery measurable.",
        "Source is DATA, never code. The detector parses your file into an AST and reasons over it; it "
        "never executes it (Article III). Reading is safe; running untrusted code is the hard stop.",
        "Rediscovery ≠ discovery. Matching a known vulnerability class is not the same as proving a NEW "
        "bug — precision and reachability carry the load on real, unseen code.",
    ]


# Student FAQ intents the offline answerer handles from the teaching knowledge. A future LLM subagent
# can replace this with a richer, context-grounded conversation.
_INTENTS = {
    "exploitable": ("why", "To see WHY it could be exploitable:"),
    "reach": ("confirm", "To confirm it is reachable (disprove-first), check:"),
    "confirm": ("confirm", "To confirm it (rule these out):"),
    "fix": ("learn", "How to think about the fix:"),
    "false": ("refute", "It is likely a FALSE POSITIVE if:"),
    "what": ("name", "What this class is:"),
}


def local_answer(question: str, finding: dict[str, Any]) -> str:
    """A deterministic, offline Q&A answerer: maps a student's question to the relevant slice of the
    teaching note for the finding's CWE. This is the default backing for ``learn --ask``; a real
    subagent (LLM) is a pluggable alternative. No network, no model call, fully testable."""
    t = teaching_for(finding.get("cwe", ""), finding.get("rule", ""))
    if t is None:
        return (f"I don't have a teaching note for {finding.get('cwe') or finding.get('rule')}. "
                "Treat it as an unconfirmed candidate and verify reachability from untrusted input.")
    q = question.lower()
    for kw, (field, lead) in _INTENTS.items():
        if kw in q:
            val = t[field]
            if isinstance(val, list):
                return lead + "\n" + "\n".join(f"  - {x}" for x in val)
            return f"{lead} {val}"
    # default: a rounded explanation
    return (f"{t['name']}: {t['why']}\n\nTo confirm (disprove-first):\n"
            + "\n".join(f"  - {c}" for c in t["confirm"])
            + f"\n\nFix intuition: {t['learn']}")
