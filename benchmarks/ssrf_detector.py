"""DT-SSRF-TAINT — a static taint-lite detector for server-side request forgery
(CWE-918) in Python, emitting SARIF 2.1.0 so it feeds the SAME real ingest DISCOVER
uses (``deepthought.ingest.sarif``). It only parses source into a Python ``ast`` and
reads it; nothing here imports, runs, or evaluates the target code.

Ship the CLASS, not the CVE. The rule flags the SSRF SHAPE — a call to an
outbound-request SINK (``requests``/``httpx``/``aiohttp``/``urllib``/``urllib3``) whose
URL argument is NON-LITERAL (so it may carry an attacker-controlled host) when the
enclosing scope applies NO SSRF guard. Calibrated on one seed (dify CVE-2025-0184, a
raw ``requests.get(url)`` later routed through an SSRF-safe proxy) and measured on
held-out CVEs with DIFFERENT sinks and guards (gradio httpx + ``check_public_url``;
pydantic-ai httpx + ``safe_download``; langchain requests/aiohttp + same-domain) — a
signature for the seed would miss those, so the rule targets the class.

An SSRF fix takes two shapes, both handled:
  * SINK SUBSTITUTION — the raw sink is replaced by a safe wrapper
    (``requests.get`` -> ``ssrf_proxy.get``; ``client.get`` -> ``safe_download``). The
    wrapper is not in the sink set, so the patched code simply has no sink.
  * GUARD ADDED — a validation of the URL/host is introduced before the request
    (``check_public_url``, an ``ipaddress.is_global`` check, ``getaddrinfo`` + an
    allowlist, a scheme/netloc allowlist). See _scope_has_ssrf_guard.

Guard analysis is scope-local (the enclosing function, or the module for a top-level
sink) and does not descend into nested functions, so a guard in a sibling helper does
not mask an unguarded request.
"""

from __future__ import annotations

import ast
from pathlib import Path

RULE_ID = "DT-SSRF-TAINT"
GROUND_TRUTH_CWE = "CWE-918"

# Outbound-request HTTP verbs used as method names on a client/module.
_HTTP_METHODS = frozenset(
    {"get", "post", "put", "delete", "patch", "head", "options", "request"}
)
# Modules/qualifiers that make ``<x>.get(...)`` unambiguously an HTTP request (not a
# dict ``.get``).
_REQUEST_MODULES = frozenset({"requests", "httpx", "aiohttp", "urllib3", "session"})
# Base-name substrings that mark a value as an HTTP client (so ``<x>.get(url)`` is a
# request, not a dict lookup).
_CLIENT_NAME_SIGNALS = ("client", "session", "http", "conn", "pool", "fetch")
# A ``.get``/``.post`` whose base name carries one of these is the SAFE WRAPPER an SSRF
# fix substitutes in (``ssrf_proxy.get``); it is the guarded replacement, never a sink.
_SAFE_WRAPPER_SIGNALS = ("ssrf", "safe", "guard", "sanitiz", "validat", "allowlist")
# Constructors whose result is an HTTP client — a variable bound to one of these makes
# its ``.get``/``.post`` a request sink.
_CLIENT_CTORS = frozenset(
    {"Session", "Client", "AsyncClient", "ClientSession", "PoolManager"}
)
# Guard signals: an SSRF fix validates the URL/host before the request.
_GUARD_VERBS = ("check", "validate", "verify", "ensure", "assert", "guard",
                "sanitize", "is_", "allow", "block", "filter", "safe", "restrict")
_GUARD_NOUNS = ("url", "host", "ip", "ssrf", "public", "private", "global",
                "internal", "address", "domain", "netloc", "redirect", "outside")
# The actual VALIDATION step of an SSRF guard — an IP RANGE check. Merely parsing a URL
# (.netloc/.hostname) or instantiating an IP (ipaddress.ip_address) is NOT a guard; the
# guard is testing the resolved IP's range (is_global/is_private/...).
_RANGE_CHECKS = frozenset(
    {"is_global", "is_private", "is_loopback", "is_reserved", "is_link_local",
     "is_multicast", "is_unspecified"}
)


def _parents(tree: ast.AST) -> dict:
    parent: dict = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node
    return parent


def _enclosing_scope(node: ast.AST, parent: dict) -> ast.AST:
    """The nearest enclosing function, or the Module for a top-level sink."""
    cur = parent.get(node)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return cur
        cur = parent.get(cur)
    return node


def _iter_scope(scope: ast.AST):
    """Iterate scope's body but NOT into nested function/class bodies — a guard in a
    nested helper belongs to that helper, not this scope."""
    for child in ast.iter_child_nodes(scope):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield child
        yield from _iter_scope(child)


def _name_of(func: ast.AST) -> tuple[str, str]:
    """(base, attr) for a call target: ``requests.get`` -> ('requests','get');
    ``a.b.get`` -> ('b','get'); bare ``urlopen`` -> ('', 'urlopen')."""
    if isinstance(func, ast.Attribute):
        base = func.value
        if isinstance(base, ast.Name):
            return base.id, func.attr
        if isinstance(base, ast.Attribute):
            return base.attr, func.attr
        if isinstance(base, ast.Call):  # httpx.Client().get(...)
            b, _ = _name_of(base.func)
            return b, func.attr
        return "", func.attr
    if isinstance(func, ast.Name):
        return "", func.id
    return "", ""


def _client_vars(scope: ast.AST) -> set[str]:
    """Local variables bound to an HTTP-client constructor in this scope
    (``client = httpx.Client()``), so ``client.get(url)`` is recognised as a request."""
    names: set[str] = set()
    for node in _iter_scope(scope):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            _, ctor = _name_of(node.value.func)
            if ctor in _CLIENT_CTORS:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        names.add(tgt.id)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call) and isinstance(item.optional_vars, ast.Name):
                    _, ctor = _name_of(item.context_expr.func)
                    if ctor in _CLIENT_CTORS:
                        names.add(item.optional_vars.id)
    return names


def _url_arg(call: ast.Call, attr: str) -> ast.AST | None:
    """The URL argument of a request call: the 2nd positional for the
    ``(verb/method, url)`` signatures ``.stream("GET", url)`` and
    ``.request("GET", url)``, the ``url=`` kwarg if present, else the 1st positional."""
    for kw in call.keywords:
        if kw.arg == "url":
            return kw.value
    if attr in ("stream", "request") and len(call.args) >= 2:
        return call.args[1]
    return call.args[0] if call.args else None


def _is_literal_url(node: ast.AST | None) -> bool:
    """A hardcoded string URL (or f-string of only literals) — not attacker-controlled
    at this site, so not a taint source."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    return False


def _is_request_sink(call: ast.Call, client_vars: set[str], imported: set[str]) -> bool:
    base, attr = _name_of(call.func)
    if attr == "urlopen":
        return True  # urllib.request.urlopen / urlopen
    # a bare call to a directly-imported request function: from requests import get -> get(url)
    if base == "" and attr in imported:
        return True
    if attr == "stream":
        # httpx .stream("GET", url, ...) — first arg an HTTP verb literal
        if call.args and isinstance(call.args[0], ast.Constant) and \
                str(call.args[0].value).upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"):
            return True
    if attr in _HTTP_METHODS:
        bl = base.lower()
        # The SAFE WRAPPER an SSRF fix substitutes in (ssrf_proxy.get) is never a sink.
        if any(s in bl for s in _SAFE_WRAPPER_SIGNALS):
            return False
        if base in _REQUEST_MODULES or base in client_vars:
            return True
        # a base whose NAME marks it an HTTP client (client/session/http/conn/pool)
        if any(c in bl for c in _CLIENT_NAME_SIGNALS):
            return True
    return False


def _looks_like_guard_call(func: ast.AST) -> bool:
    """A named validation call — ``check_public_url``, ``validate_host``, ``is_safe_url``
    — carrying both a guard verb (check/validate/is_/...) and a guard noun (url/host/ip/
    ssrf/...). Merely parsing/resolving (ip_address, getaddrinfo, urlparse) is NOT a guard
    on its own; the range-check is."""
    base, attr = _name_of(func)
    name = f"{base}_{attr}".lower()
    return any(v in name for v in _GUARD_VERBS) and any(n in name for n in _GUARD_NOUNS)


def _idents(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _call_idents(call: ast.Call) -> set[str]:
    out: set[str] = set()
    for a in call.args:
        out |= _idents(a)
    for kw in call.keywords:
        out |= _idents(kw.value)
    return out


def _related_idents(scope: ast.AST) -> dict:
    """Undirected relation between identifiers linked by an assignment — for
    ``url = url_spec.geturl()`` (or ``url_spec = urlparse(url)``) the target and each
    identifier in the value are related BOTH ways, so a guard on either name covers a
    request on the other (the same logical URL). Two genuinely different variables never
    linked by an assignment stay unrelated."""
    rel: dict = {}
    for node in _iter_scope(scope):
        if isinstance(node, ast.Assign):
            values = _idents(node.value)
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    for b in values:
                        rel.setdefault(tgt.id, set()).add(b)
                        rel.setdefault(b, set()).add(tgt.id)
    return rel


def _scope_guards_url(scope: ast.AST, url_node: ast.AST) -> bool:
    """Whether the scope VALIDATES *this sink's* URL before the request. Tied to the
    sink's URL (expanded across assignment-linked names) so validating a DIFFERENT url
    does not suppress the sink. Three guard shapes:
      1. an IP RANGE check (``ip.is_global``/``is_private``/...) — the actual SSRF test;
      2. a named validation call (``check_public_url``/``is_safe_url``) referencing the
         sink's URL (or an assignment-linked alias of it);
      3. a hostname/netloc COMPARISON or allowlist membership on the sink's URL
         (``urlparse(url).hostname not in ALLOW``) — but NOT a bare parse/log of it.
    """
    rel = _related_idents(scope)
    relevant = set(_idents(url_node))
    for _ in range(3):  # bounded closure over assignment-linked aliases
        grown = set(relevant)
        for v in relevant:
            grown |= rel.get(v, set())
        if grown == relevant:
            break
        relevant = grown
    for node in _iter_scope(scope):
        if isinstance(node, ast.Attribute) and node.attr in _RANGE_CHECKS:
            return True
        if isinstance(node, ast.Call) and _looks_like_guard_call(node.func):
            if relevant & _call_idents(node):
                return True
        if isinstance(node, ast.Compare):
            attrs = {a.attr for a in ast.walk(node) if isinstance(a, ast.Attribute)}
            if ({"hostname", "netloc"} & attrs) and (relevant & _idents(node)):
                return True
    return False


def _imported_request_names(tree: ast.AST) -> set[str]:
    """Local names bound to a request function by a direct import — ``from requests import
    get`` / ``from urllib.request import urlopen as fetch`` — so a bare ``get(url)`` /
    ``fetch(url)`` call is recognised as a sink."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in ("requests", "httpx", "aiohttp", "urllib", "urllib3"):
                for alias in node.names:
                    if alias.name in _HTTP_METHODS or alias.name in ("urlopen", "request"):
                        names.add(alias.asname or alias.name)
    return names


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    """SARIF result objects for unguarded SSRF request sinks.

    ``cve`` (optional) is the ground-truth label for THIS scan — the informational alias
    the ingest mirrors onto a candidate. The detector never derives a CVE itself; it
    detects the class (CWE-918). Omit it in a real hunt.
    """
    tree = ast.parse(source)
    parent = _parents(tree)
    imported = _imported_request_names(tree)
    results: list[dict] = []
    clientvars_cache: dict[int, set] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        scope = _enclosing_scope(node, parent)
        cvars = clientvars_cache.setdefault(id(scope), _client_vars(scope))
        if not _is_request_sink(node, cvars, imported):
            continue
        base, attr = _name_of(node.func)
        url = _url_arg(node, attr)
        if url is None or _is_literal_url(url):
            continue  # hardcoded / no URL — not an attacker-controlled request target
        if _scope_guards_url(scope, url):
            continue  # patched shape — the scope validates THIS URL before the request
        results.append(_result(node, uri, base, attr, cve))

    return results


def _result(call: ast.Call, uri: str, base: str, attr: str, cve: str | None) -> dict:
    props = {"cwe": GROUND_TRUTH_CWE}
    if cve:
        props["cve"] = cve
    call_txt = f"{base + '.' if base else ''}{attr}"
    return {
        "ruleId": RULE_ID,
        "level": "error",
        "message": {
            "text": (
                f"SSRF (CWE-918): outbound request {call_txt}(...) with a non-literal, "
                f"potentially attacker-controlled URL and no host/scheme validation in "
                f"the enclosing scope."
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": call.lineno, "startColumn": call.col_offset + 1},
                }
            }
        ],
        "properties": props,
    }


def scan_file(path: str | Path, uri: str | None = None, cve: str | None = None) -> dict:
    """Scan one file and return a full SARIF 2.1.0 log (same shape any external analyzer
    DISCOVER ingests). ``uri`` overrides the reported path for scope matching."""
    p = Path(path)
    results = scan_source(p.read_text(encoding="utf-8"), uri=uri or p.name, cve=cve)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deepthought-ssrf-rule",
                        "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                        "rules": [
                            {
                                "id": RULE_ID,
                                "name": "UnguardedOutboundRequest",
                                "shortDescription": {
                                    "text": "Outbound request with a non-literal URL and no SSRF guard (CWE-918)"
                                },
                                "defaultConfiguration": {"level": "error"},
                                "helpUri": "https://cwe.mitre.org/data/definitions/918.html",
                                "properties": {
                                    "cwe": GROUND_TRUTH_CWE,
                                    "tags": ["security", "CWE-918", "ssrf"],
                                },
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
