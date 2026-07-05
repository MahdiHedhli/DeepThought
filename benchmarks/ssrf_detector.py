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

Known limitations (a syntactic taint-lite rule, not full dataflow): guard recognition is
position-ordered and syntactic, so a guard reached only through control flow the rule
does not model — a ternary-conditional guard (``get(url) if check(url) else None``), a
hostname comparison that merely logs rather than blocks, or a URL derivation that appears
textually after the sink — may be mis-judged. Catching those needs control-flow/dataflow
analysis beyond this class's scope; they are documented, not chased. A non-literal URL is
treated as potentially tainted, so file-level precision on hardcoded-config requests is
low by design.
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


def _url_arg(call: ast.Call, request_style: bool) -> ast.AST | None:
    """The URL argument of a request call: the 2nd positional for a ``(verb/method, url)``
    signature (``.stream("GET", url)`` / ``.request("GET", url)`` / an aliased bare
    ``request``), the ``url=`` kwarg if present, else the 1st positional."""
    for kw in call.keywords:
        if kw.arg == "url":
            return kw.value
    if request_style and len(call.args) >= 2:
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


def _is_request_sink(call: ast.Call, client_vars: set[str], imported: dict, mod_aliases: dict) -> bool:
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
        # A CONFIRMED request module (possibly via ``import requests as req``) or a client
        # VARIABLE is a sink regardless of its name — a Session named ``safe_client`` is
        # still a client. Check this BEFORE the name-based safe-wrapper exclusion.
        if mod_aliases.get(base, base) in _REQUEST_MODULES or base in client_vars:
            return True
        # A name-based SAFE WRAPPER (the guarded replacement, e.g. ssrf_proxy.get) is not a
        # sink — matched on underscore WORD parts, so ``unsafe_client`` is NOT excluded.
        parts = base.lower().split("_")
        if any(p.startswith(s) for p in parts for s in _SAFE_WRAPPER_SIGNALS):
            return False
        # a base whose NAME marks it an HTTP client (client/session/http/conn/pool)
        if any(c in base.lower() for c in _CLIENT_NAME_SIGNALS):
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


def _link(rel: dict, target: str, others: set[str]) -> None:
    for b in others:
        rel.setdefault(target, set()).add(b)
        rel.setdefault(b, set()).add(target)


def _related_idents(scope: ast.AST) -> dict:
    """Undirected relation between identifiers linked by an assignment or a for-loop —
    ``url = url_spec.geturl()``, ``host = urlparse(url).hostname``,
    ``for info in getaddrinfo(host, None)`` all relate their names both ways, so a guard
    on any link in the URL->host->IP chain covers a request on another. Two variables
    never linked stay unrelated (validating a DIFFERENT url does not count)."""
    rel: dict = {}
    for node in _iter_scope(scope):
        if isinstance(node, ast.Assign):
            values = _idents(node.value)
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    _link(rel, tgt.id, values)
        elif isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(node.target, ast.Name):
            _link(rel, node.target.id, _idents(node.iter))
    return rel


def _pos(node: ast.AST) -> tuple:
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


def _scope_guards_url(scope: ast.AST, url_node: ast.AST, sink: ast.Call) -> bool:
    """Whether the scope VALIDATES *this sink's* URL, BEFORE the request. A guard is tied
    to the sink's URL (expanded across assignment/for-loop-linked names) and must PRECEDE
    the sink — a check after the request, or one on a genuinely different value, is no
    guard. Three guard shapes:
      1. an IP RANGE check (``ip.is_global``/``is_private``/...) whose checked object is
         URL-derived, in a scope that resolves an IP;
      2. a named validation call (``check_public_url``/``is_safe_url``) on the sink's URL;
      3. a hostname/netloc COMPARISON or allowlist on the sink's URL — not a bare parse.
    """
    rel = _related_idents(scope)
    relevant = set(_idents(url_node))
    for _ in range(4):  # bounded closure over linked aliases (url -> host -> ip)
        grown = set(relevant)
        for v in relevant:
            grown |= rel.get(v, set())
        if grown == relevant:
            break
        relevant = grown
    ip_context = _has_ip_context(scope)
    sink_pos = _pos(sink)
    for node in _iter_scope(scope):
        if _pos(node) >= sink_pos:
            continue  # a guard must PRECEDE the sink to protect it
        if (ip_context and isinstance(node, ast.Attribute) and node.attr in _RANGE_CHECKS
                and (relevant & _idents(node.value))):
            return True  # a range check on a URL-derived IP
        if isinstance(node, ast.Call) and _looks_like_guard_call(node.func):
            if relevant & _call_idents(node):
                return True
        if isinstance(node, ast.Compare):
            attrs = {a.attr for a in ast.walk(node) if isinstance(a, ast.Attribute)}
            if ({"hostname", "netloc"} & attrs) and (relevant & _idents(node)):
                return True
    return False


def _imported_request_names(tree: ast.AST) -> dict:
    """Local name -> ORIGINAL request-function name for direct imports — ``from requests
    import get`` -> {'get':'get'}, ``... import request as req`` -> {'req':'request'} — so
    a bare ``get(url)`` / ``req('GET', url)`` call is recognised as a sink AND its URL
    argument is read from the right position (``request`` puts the URL 2nd)."""
    names: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in ("requests", "httpx", "aiohttp", "urllib", "urllib3"):
                for alias in node.names:
                    if alias.name in _HTTP_METHODS or alias.name in ("urlopen", "request"):
                        names[alias.asname or alias.name] = alias.name
    return names


def _has_ip_context(scope: ast.AST) -> bool:
    """Whether the scope resolves/parses an IP — ``ipaddress``, ``ip_address``,
    ``ip_network``, ``getaddrinfo``, ``gethostbyname``. An ``.is_global``/``.is_private``
    attribute is an IP RANGE check only in this context; otherwise ``user.is_global`` is
    just a config flag, not an SSRF guard."""
    ip_names = ("ipaddress", "ip_address", "ip_network", "getaddrinfo", "gethostbyname",
                "IPv4Address", "IPv6Address")
    for node in _iter_scope(scope):
        if isinstance(node, ast.Attribute) and node.attr in ip_names:
            return True
        if isinstance(node, ast.Name) and node.id in ip_names:
            return True
    return False


def _module_aliases(tree: ast.AST) -> dict:
    """Local alias -> request module for ``import <module> as <alias>`` — ``import
    requests as req`` -> {'req':'requests'}, ``import httpx`` -> {'httpx':'httpx'} — so
    ``req.get(url)`` is matched as a request-module sink."""
    aliases: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in ("requests", "httpx", "aiohttp", "urllib3"):
                    aliases[alias.asname or alias.name] = root
    return aliases


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    """SARIF result objects for unguarded SSRF request sinks.

    ``cve`` (optional) is the ground-truth label for THIS scan — the informational alias
    the ingest mirrors onto a candidate. The detector never derives a CVE itself; it
    detects the class (CWE-918). Omit it in a real hunt.
    """
    tree = ast.parse(source)
    parent = _parents(tree)
    imported = _imported_request_names(tree)
    mod_aliases = _module_aliases(tree)
    results: list[dict] = []
    clientvars_cache: dict[int, set] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        scope = _enclosing_scope(node, parent)
        cvars = clientvars_cache.setdefault(id(scope), _client_vars(scope))
        if not _is_request_sink(node, cvars, imported, mod_aliases):
            continue
        base, attr = _name_of(node.func)
        # (verb/method, url) 2-arg signature: an ATTRIBUTE .stream/.request call, or a
        # bare call to an imported function whose ORIGINAL name is `request` (so an
        # `import urlopen as request` — original urlopen — keeps the URL 1st).
        request_style = (base != "" and attr in ("stream", "request")) or \
            (base == "" and imported.get(attr) == "request")
        url = _url_arg(node, request_style)
        if url is None or _is_literal_url(url):
            continue  # hardcoded / no URL — not an attacker-controlled request target
        if _scope_guards_url(scope, url, node):
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
