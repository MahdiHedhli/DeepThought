"""DT-CRLF-HEADER — static Python detector for HTTP CRLF / response splitting (CWE-113).

Parses Python with :mod:`ast` only; never executes target code.

Class shape: building an HTTP header or Set-Cookie value from untrusted pieces
without neutralizing CR/LF. Two high-signal sinks:

1. Header serialization that concatenates name + ``": "`` + value + a CRLF
   terminator without a sanitizer on both pieces (``_safe_header``, ``_nocrlf``,
   ``sanitize_header``, replace of ``\\r``/``\\n``).
2. A ``set_cookie``-style method that builds a cookie string and stores it under
   ``Set-Cookie`` without a dominating ``\\r``/``\\n`` membership check.
"""

from __future__ import annotations

import ast
from pathlib import Path

RULE_ID = "DT-CRLF-HEADER"
GROUND_TRUTH_CWE = "CWE-113"

_SANITIZER_NAMES = frozenset(
    {
        "_safe_header",
        "safe_header",
        "_nocrlf",
        "nocrlf",
        "sanitize_header",
        "_sanitize_header",
        "sanitize_header_value",
        "sanitizeHeaderValue",
    }
)
_CRLF_TOKENS = ("\\r", "\\n", "\r", "\n", "b'\\r'", 'b"\\r"', "b'\\n'", 'b"\\n"')


def _name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _dotted(node: ast.AST | None) -> str:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _result(uri: str, line: int, col: int, msg: str, cve: str | None) -> dict:
    props: dict[str, str] = {"cwe": GROUND_TRUTH_CWE}
    if cve:
        props["cve"] = cve
    return {
        "ruleId": RULE_ID,
        "level": "error",
        "message": {"text": msg},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "startColumn": col},
                }
            }
        ],
        "properties": props,
    }


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        if isinstance(node.value, bytes):
            try:
                return node.value.decode("utf-8", "replace")
            except Exception:
                return None
        return node.value
    return None


def _is_colon_sep(node: ast.AST | None) -> bool:
    s = _const_str(node)
    return s in (": ", ":", b": ", b":") if not isinstance(s, bytes) else s in (b": ", b":")


def _is_crlf_term(node: ast.AST | None) -> bool:
    s = _const_str(node)
    if s is None:
        return False
    if isinstance(s, bytes):
        return s in (b"\r\n", b"\n")
    return s in ("\r\n", "\n", "\\r\\n")


def _call_name(node: ast.Call) -> str:
    return _name(node.func)


def _wrapped_in_sanitizer(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        if _call_name(node) in _SANITIZER_NAMES:
            return True
        # value.replace(b"\r", b"").replace(b"\n", b"") chain
        if isinstance(node.func, ast.Attribute) and node.func.attr == "replace":
            return True
    return False


def _bin_parts(node: ast.AST) -> list[ast.AST]:
    """Flatten left-associative + concatenations."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _bin_parts(node.left) + _bin_parts(node.right)
    return [node]


def _is_unsanitized_header_serialize(node: ast.AST) -> bool:
    """name + ': ' + value + '\\r\\n' (or bytes) without sanitizer wrappers."""
    parts = _bin_parts(node)
    if len(parts) < 3:
        return False
    # Look for a ': ' separator and a trailing CRLF among constant parts.
    has_colon = any(_is_colon_sep(p) for p in parts)
    has_crlf = any(_is_crlf_term(p) for p in parts)
    if not (has_colon and has_crlf):
        return False
    # Non-constant pieces must all be sanitizer-wrapped.
    dynamic = [p for p in parts if _const_str(p) is None]
    if not dynamic:
        return False
    return not all(_wrapped_in_sanitizer(p) for p in dynamic)


def _func_has_crlf_guard(func: ast.AST, source: str) -> bool:
    """True if the function body rejects CR/LF in the cookie/header value."""
    text = ast.get_source_segment(source, func) or ""
    # Membership checks on \r / \n that raise or return.
    if ("'\\r'" in text or '"\\r"' in text or "b'\\r'" in text or 'b"\\r"' in text) and (
        "'\\n'" in text or '"\\n"' in text or "b'\\n'" in text or 'b"\\n"' in text
    ):
        if "raise" in text or "return" in text or "ValueError" in text:
            return True
    if any(s in text for s in _SANITIZER_NAMES):
        return True
    if ".replace(" in text and ("\\r" in text or "\r" in text):
        return True
    return False


def _is_set_cookie_key(node: ast.AST) -> bool:
    s = _const_str(node)
    if s in ("Set-Cookie", "set-cookie"):
        return True
    if isinstance(node, ast.Constant) and node.value in ("Set-Cookie", "set-cookie"):
        return True
    return False


def scan_python(source: str, uri: str, cve: str | None = None) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    out: list[dict] = []
    seen: set[tuple[int, str]] = set()

    # Map child -> parent for scope walking
    parent: dict[ast.AST, ast.AST] = {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parent[c] = p

    def enclosing_func(node: ast.AST) -> ast.AST | None:
        cur: ast.AST | None = node
        while cur is not None:
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return cur
            cur = parent.get(cur)
        return None

    for node in ast.walk(tree):
        # Sink 1: any expression that serializes name+": "+value+"\r\n" without sanitizers
        # (return, assign, list/generator comprehension element, call argument, join body).
        if _is_unsanitized_header_serialize(node):
            key = (node.lineno, "header-serialize")
            if key not in seen:
                seen.add(key)
                out.append(
                    _result(
                        uri,
                        node.lineno,
                        getattr(node, "col_offset", 0) + 1,
                        "HTTP CRLF injection (CWE-113): header serialization concatenates "
                        "name/value with a CRLF terminator without sanitizing CR/LF",
                        cve,
                    )
                )

        # Sink 2: Set-Cookie store of a dynamic cookie without a CR/LF guard in the function
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "append" and node.args:
                recv = node.func.value
                if isinstance(recv, ast.Subscript) and _is_set_cookie_key(recv.slice):
                    fn = enclosing_func(node)
                    if fn is not None and not _func_has_crlf_guard(fn, source):
                        key = (node.lineno, "set-cookie-append")
                        if key not in seen:
                            seen.add(key)
                            out.append(
                                _result(
                                    uri,
                                    node.lineno,
                                    node.col_offset + 1,
                                    "HTTP CRLF injection (CWE-113): Set-Cookie value stored "
                                    "without rejecting CR/LF in the cookie string",
                                    cve,
                                )
                            )
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Subscript) and _is_set_cookie_key(t.slice):
                    fn = enclosing_func(node)
                    if fn is not None and not _func_has_crlf_guard(fn, source):
                        key = (node.lineno, "set-cookie-assign")
                        if key not in seen:
                            seen.add(key)
                            out.append(
                                _result(
                                    uri,
                                    node.lineno,
                                    node.col_offset + 1,
                                    "HTTP CRLF injection (CWE-113): Set-Cookie value stored "
                                    "without rejecting CR/LF in the cookie string",
                                    cve,
                                )
                            )

        # Sink 3: CONTENT_TYPE / content-type header assignment from a name without CR/LF guard
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if not isinstance(t, ast.Subscript):
                    continue
                # headers[hdrs.CONTENT_TYPE] or headers['Content-Type']
                key_node = t.slice
                key_txt = _const_str(key_node) or _dotted(key_node) or _name(key_node)
                if key_txt in (
                    "Content-Type",
                    "content-type",
                    "CONTENT_TYPE",
                    "hdrs.CONTENT_TYPE",
                ) or (isinstance(key_node, ast.Attribute) and key_node.attr == "CONTENT_TYPE"):
                    fn = enclosing_func(node)
                    if fn is not None and not _func_has_crlf_guard(fn, source):
                        # only if RHS is dynamic (Name/Attribute/Call), not a constant
                        if not isinstance(node.value, ast.Constant):
                            key = (node.lineno, "content-type-assign")
                            if key not in seen:
                                seen.add(key)
                                out.append(
                                    _result(
                                        uri,
                                        node.lineno,
                                        node.col_offset + 1,
                                        "HTTP CRLF injection (CWE-113): Content-Type header "
                                        "assigned from a dynamic value without rejecting CR/LF",
                                        cve,
                                    )
                                )

    return out


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    if uri.endswith((".js", ".ts", ".java", ".php", ".go", ".rb", ".jsx", ".tsx", ".gleam", ".ex")):
        return []
    return scan_python(source, uri, cve)


def scan_file(path: str | Path, uri: str | None = None, cve: str | None = None) -> dict:
    p = Path(path)
    results = scan_source(p.read_text(encoding="utf-8"), uri=uri or p.name, cve=cve)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deepthought-crlf-rule",
                        "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                        "rules": [
                            {
                                "id": RULE_ID,
                                "name": "HttpCrlfInjection",
                                "shortDescription": {
                                    "text": "HTTP header/cookie CRLF injection (CWE-113)"
                                },
                                "defaultConfiguration": {"level": "error"},
                                "helpUri": "https://cwe.mitre.org/data/definitions/113.html",
                                "properties": {
                                    "cwe": GROUND_TRUTH_CWE,
                                    "tags": ["security", "CWE-113", "crlf"],
                                },
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
