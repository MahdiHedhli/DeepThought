"""DT-NOSQL-OP — static JS/TS detector for NoSQL operator injection (CWE-943).

Parses source with tree-sitter JavaScript; never executes target code.

Class shape: values drawn from untrusted config/request surfaces are placed into
MongoDB identity or filter fields without proving they are scalar strings (or
other allowed id types). Attackers pass objects like ``{"$gt":""}`` to expand
queries. The patched discriminator is a same-scope ``typeof … === "string"``
(or dedicated string-coercion helper such as ``getStringConfigValue``) that
rejects non-strings before the query runs.
"""

from __future__ import annotations

from pathlib import Path

import tree_sitter_javascript as _tsjs
import tree_sitter_typescript as _tsts
from tree_sitter import Language, Node, Parser

RULE_ID = "DT-NOSQL-OP"
GROUND_TRUTH_CWE = "CWE-943"

_JS = Language(_tsjs.language())
_TS = Language(_tsts.language_typescript())
_PARSER_JS = Parser(_JS)
_PARSER_TS = Parser(_TS)

_MONGO_SINKS = frozenset(
    {
        "find",
        "findOne",
        "findOneAndUpdate",
        "findOneAndDelete",
        "deleteMany",
        "deleteOne",
        "updateOne",
        "updateMany",
        "replaceOne",
        "countDocuments",
        "aggregate",
    }
)
_ID_FIELDS = frozenset(
    {
        "thread_id",
        "checkpoint_id",
        "checkpoint_ns",
        "token",
        "id",
        "_id",
        "objectId",
        "userId",
        "user_id",
    }
)
_UNTRUSTED_ROOTS = frozenset(
    {
        "config",
        "configurable",
        "req",
        "request",
        "body",
        "query",
        "params",
        "authData",
        "providerAuthData",
    }
)
_STRING_GUARDS = (
    'typeof',
    '==="string"',
    "== 'string'",
    '!=="string"',
    "!= 'string'",
    'getStringConfigValue',
    'toString()',
)
_FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
        "function",
    }
)


def _text(src: bytes, n: Node) -> str:
    return src[n.start_byte : n.end_byte].decode("utf-8", "replace")


def _iter(n: Node):
    st = [n]
    while st:
        c = st.pop()
        yield c
        st.extend(reversed(c.children))


def _enclosing_scope(node: Node, root: Node) -> Node:
    cur = node.parent
    while cur is not None:
        if cur.type in _FUNCTION_TYPES:
            return cur
        cur = cur.parent
    return root


def _call_name(src: bytes, call: Node) -> str:
    fn = call.child_by_field_name("function")
    if fn is None:
        return ""
    if fn.type == "member_expression":
        prop = fn.child_by_field_name("property")
        return _text(src, prop) if prop is not None else ""
    if fn.type == "identifier":
        return _text(src, fn)
    return ""


def _scope_has_string_guard(src: bytes, scope: Node) -> bool:
    text = _text(src, scope).replace(" ", "")
    # typeof x === "string" / !== "string" or helper that enforces strings
    if "typeof" in text and ("==='string'" in text or '==="string"' in text or "=='string'" in text or '=="string"' in text):
        return True
    if "typeof" in text and ("!=='string'" in text or '!=="string"' in text or "!='string'" in text or '!="string"' in text):
        return True
    if "getStringConfigValue" in text:
        return True
    if "mustbeastring" in text.lower() or "must be a string" in _text(src, scope).lower():
        return True
    if "Invalid id" in _text(src, scope) and "typeof" in text:
        return True
    return False


def _expr_looks_untrusted(src: bytes, node: Node) -> bool:
    t = _text(src, node)
    # config.configurable… / req.body… / authData…
    if any(r in t for r in ("config.configurable", "req.body", "request.body", "authData", "providerAuthData")):
        return True
    if "configurable" in t and ("config" in t or "??" in t):
        return True
    return False


def _object_has_id_field(src: bytes, obj: Node) -> bool:
    if obj.type != "object":
        return False
    for ch in obj.children:
        if ch.type == "pair":
            k = ch.child_by_field_name("key")
            if k is not None and _text(src, k).strip("\"'") in _ID_FIELDS:
                return True
        if ch.type == "shorthand_property_identifier":
            if _text(src, ch) in _ID_FIELDS:
                return True
    return False


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


def scan_js(source: str, uri: str, cve: str | None = None) -> list[dict]:
    src = source.encode("utf-8")
    parser = _PARSER_TS if uri.endswith((".ts", ".tsx")) else _PARSER_JS
    root = parser.parse(src).root_node
    out: list[dict] = []
    seen: set[tuple[int, str]] = set()

    # Pattern A: destructuring from config.configurable without string guard in scope
    for node in _iter(root):
        if node.type != "lexical_declaration" and node.type != "variable_declaration":
            continue
        text = _text(src, node)
        if "config.configurable" not in text and "configurable" not in text:
            continue
        if "={" not in text.replace(" ", "") and "}= " not in text.replace(" ", "") and "}=" not in text.replace(" ", ""):
            # require object destructuring
            if not any(c.type == "object_pattern" for c in _iter(node)):
                continue
        # object_pattern from configurable
        if "configurable" not in text:
            continue
        scope = _enclosing_scope(node, root)
        if _scope_has_string_guard(src, scope):
            continue
        # only if an id-like field is destructured
        if not any(f in text for f in _ID_FIELDS):
            continue
        key = (node.start_point[0] + 1, "destructure-configurable")
        if key in seen:
            continue
        seen.add(key)
        out.append(
            _result(
                uri,
                node.start_point[0] + 1,
                node.start_point[1] + 1,
                "NoSQL operator injection (CWE-943): untrusted configurable fields "
                "destructured into Mongo identity values without a string-type guard",
                cve,
            )
        )

    # Pattern B: Mongo sink call whose query object carries id fields, scope lacks string guard,
    # and the function also reads untrusted config/request surfaces.
    for node in _iter(root):
        if node.type != "call_expression":
            continue
        name = _call_name(src, node)
        if name not in _MONGO_SINKS:
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        scope = _enclosing_scope(node, root)
        if _scope_has_string_guard(src, scope):
            continue
        scope_txt = _text(src, scope)
        if not any(u in scope_txt for u in ("configurable", "req.body", "request.body", "authData", "providerAuthData", "req.")):
            # still allow if query object is clearly built from id shorthand near untrusted
            pass
        query_obj = None
        for a in args.children:
            if a.type == "object":
                query_obj = a
                break
            if a.type == "identifier":
                # find(query) — treat as sink if scope has untrusted and id field names
                if any(f in scope_txt for f in _ID_FIELDS) and (
                    "configurable" in scope_txt or "req.body" in scope_txt or "authData" in scope_txt
                ):
                    key = (node.start_point[0] + 1, f"mongo-{name}")
                    if key not in seen:
                        seen.add(key)
                        out.append(
                            _result(
                                uri,
                                node.start_point[0] + 1,
                                node.start_point[1] + 1,
                                f"NoSQL operator injection (CWE-943): MongoDB {name}(...) uses "
                                f"identity fields from untrusted input without a string-type guard",
                                cve,
                            )
                        )
                continue
        if query_obj is not None and _object_has_id_field(src, query_obj):
            if "configurable" in scope_txt or "req.body" in scope_txt or "authData" in scope_txt or "req." in scope_txt:
                key = (node.start_point[0] + 1, f"mongo-obj-{name}")
                if key not in seen:
                    seen.add(key)
                    out.append(
                        _result(
                            uri,
                            node.start_point[0] + 1,
                            node.start_point[1] + 1,
                            f"NoSQL operator injection (CWE-943): MongoDB {name}(...) query "
                            f"object includes identity fields without a string-type guard",
                            cve,
                        )
                    )

    # Pattern C: authData/provider id or token from body used without typeof string
    for node in _iter(root):
        if node.type not in ("lexical_declaration", "variable_declaration", "assignment_expression"):
            continue
        text = _text(src, node)
        if "req.body" not in text and "request.body" not in text and "authData" not in text and "providerAuthData" not in text:
            continue
        if not any(f in text for f in ("token", ".id", "authData", "providerAuthData")):
            continue
        scope = _enclosing_scope(node, root)
        if _scope_has_string_guard(src, scope):
            continue
        scope_txt = _text(src, scope)
        if "token" not in scope_txt and "authData" not in scope_txt and ".id" not in scope_txt:
            continue
        key = (node.start_point[0] + 1, "body-token")
        if key in seen:
            continue
        seen.add(key)
        out.append(
            _result(
                uri,
                node.start_point[0] + 1,
                node.start_point[1] + 1,
                "NoSQL operator injection (CWE-943): request/auth identity value bound "
                "without a string-type guard before use as a query key",
                cve,
            )
        )

    # Pattern D: providerAuthData.id / authData.*.id placed into a query object without string guard
    for node in _iter(root):
        if node.type not in ("return_statement", "expression_statement", "pair"):
            continue
        text = _text(src, node)
        if "providerAuthData.id" not in text and "authData." not in text:
            continue
        if ".id" not in text:
            continue
        scope = _enclosing_scope(node, root)
        if _scope_has_string_guard(src, scope):
            continue
        if "providerAuthData" not in text and "authData" not in text:
            continue
        # require it looks like a query key binding
        if "authData." not in text and "providerAuthData.id" not in text:
            continue
        key = (node.start_point[0] + 1, "auth-id-query")
        if key in seen:
            continue
        seen.add(key)
        out.append(
            _result(
                uri,
                node.start_point[0] + 1,
                node.start_point[1] + 1,
                "NoSQL operator injection (CWE-943): auth provider id used as a query "
                "value without a string-type guard",
                cve,
            )
        )

    return out


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    if uri.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")) or "checkpoint" in uri or "Router" in uri or "adapter" in uri:
        return scan_js(source, uri, cve)
    if uri.endswith((".py", ".java", ".go", ".php", ".rb")):
        return []
    # default try JS for unknown
    if "function" in source or "const " in source or "=>" in source:
        return scan_js(source, uri, cve)
    return []


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
                        "name": "deepthought-nosql-rule",
                        "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                        "rules": [
                            {
                                "id": RULE_ID,
                                "name": "NoSqlOperatorInjection",
                                "shortDescription": {
                                    "text": "Untrusted non-string identity in Mongo query (CWE-943)"
                                },
                                "defaultConfiguration": {"level": "error"},
                                "helpUri": "https://cwe.mitre.org/data/definitions/943.html",
                                "properties": {
                                    "cwe": GROUND_TRUTH_CWE,
                                    "tags": ["security", "CWE-943", "nosql"],
                                },
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
