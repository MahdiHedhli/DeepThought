"""DT-LDAP-FILTER — static LDAP-filter injection detection (CWE-90).

The detector parses Java, Python, and PHP source and emits SARIF 2.1.0.  It never
imports or executes target code.  The class shape is an untrusted function/request
value interpolated into an LDAP *search filter* which then reaches a directory search
API without RFC 4515 filter escaping.

The reported location is deliberately the filter-construction expression when the
filter is built separately from the search call.  This keeps rediscovery line-precise:
the vulnerable Yamcs and Airflow probes are builder assignments, while the mitmproxy
and Joomla probes construct the filter directly at the search sink.
"""

from __future__ import annotations

import ast
from pathlib import Path

import tree_sitter_java as _tsjava
import tree_sitter_php as _tsphp
from tree_sitter import Language, Node, Parser

RULE_ID = "DT-LDAP-FILTER"
GROUND_TRUTH_CWE = "CWE-90"

_JAVA = Language(_tsjava.language())
_JAVA_PARSER = Parser(_JAVA)
_PHP = Language(_tsphp.language_php())
_PHP_PARSER = Parser(_PHP)

_JAVA_NESTED_SCOPES = frozenset(
    {
        "lambda_expression",
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
        "method_declaration",
        "constructor_declaration",
    }
)
_PHP_SCOPES = frozenset(
    {
        "function_definition",
        "method_declaration",
        "anonymous_function_creation_expression",
        "arrow_function",
    }
)


def _text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _iter_nodes(node: Node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _result(uri: str, line: int, column: int, message: str, cve: str | None) -> dict:
    properties = {"cwe": GROUND_TRUTH_CWE}
    if cve:
        properties["cve"] = cve
    return {
        "ruleId": RULE_ID,
        "level": "error",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "startColumn": column},
                }
            }
        ],
        "properties": properties,
    }


# ---------------------------------------------------------------------------
# Java (tree-sitter)
# ---------------------------------------------------------------------------


def _java_scope_nodes(method: Node):
    """Walk one Java method without borrowing facts from nested scopes."""
    stack = list(reversed(method.children))
    while stack:
        node = stack.pop()
        if node.type in _JAVA_NESTED_SCOPES:
            continue
        yield node
        stack.extend(reversed(node.children))


def _java_method_name(source: bytes, method: Node) -> str:
    return _text(source, method.child_by_field_name("name"))


def _java_params(source: bytes, method: Node) -> list[str]:
    params = method.child_by_field_name("parameters")
    if params is None:
        return []
    out: list[str] = []
    for node in params.named_children:
        if node.type not in ("formal_parameter", "spread_parameter", "receiver_parameter"):
            continue
        name = node.child_by_field_name("name")
        if name is not None:
            out.append(_text(source, name))
    return out


def _java_call_name(source: bytes, call: Node) -> str:
    return _text(source, call.child_by_field_name("name"))


def _java_args(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return list(args.named_children) if args is not None else []


def _java_identifiers(source: bytes, node: Node | None) -> set[str]:
    if node is None:
        return set()
    return {_text(source, n) for n in _iter_nodes(node) if n.type == "identifier"}


def _java_filter_sanitized(source: bytes, node: Node) -> bool:
    """Recognize RFC 4515 *filter* escaping, not DN escaping."""
    for call in _iter_nodes(node):
        if call.type != "method_invocation":
            continue
        name = _java_call_name(source, call).lower().replace("_", "")
        call_text = _text(source, call).lower()
        if name in {
            "escapeldapfilter",
            "escapefilterchars",
            "encodefiltervalue",
            "filterencode",
        }:
            return True
        if "escape" in name and "filter" in name and "dn" not in name:
            return True
        if "ldap_escape_filter" in call_text or "ldapescapefilter" in call_text:
            return True
    return False


def _java_looks_filter(source: bytes, node: Node) -> bool:
    value = _text(source, node)
    lowered = value.lower()
    if (".replace(" in value or ".replaceAll(" in value) and (
        "filter" in lowered or "{0}" in value or "[search]" in lowered
    ):
        return True
    if any(token in value for token in ("String.format", "MessageFormat.format")):
        return "=" in value and "(" in value
    # Direct concatenation / formatted expression containing LDAP filter grammar.
    return "=" in value and "(" in value and any(
        n.type in ("binary_expression", "string_template_expression") for n in _iter_nodes(node)
    )


def _java_ldap_context(source: str) -> bool:
    return any(
        marker in source
        for marker in (
            "javax.naming",
            "jakarta.naming",
            "DirContext",
            "InitialDirContext",
            "SearchControls",
            "LdapContext",
        )
    )


def _java_native_filter_arg(source: bytes, call: Node, ldap_context: bool) -> Node | None:
    if not ldap_context or _java_call_name(source, call) != "search":
        return None
    args = _java_args(call)
    if len(args) < 3:
        return None
    receiver = _text(source, call.child_by_field_name("object")).lower()
    # Avoid treating arbitrary application search engines as LDAP merely because a file
    # happens to import an LDAP API. JNDI contexts conventionally carry one of these names.
    if not any(token in receiver for token in ("ctx", "context", "ldap", "directory", "dir")):
        return None
    return args[1]


def _java_wrapper_summaries(source: bytes, root: Node, ldap_context: bool) -> dict[str, set[int]]:
    """Method name -> parameter indexes forwarded to a native JNDI filter argument."""
    summaries: dict[str, set[int]] = {}
    methods = [n for n in _iter_nodes(root) if n.type in ("method_declaration", "constructor_declaration")]
    for method in methods:
        params = _java_params(source, method)
        if not params:
            continue
        for call in _java_scope_nodes(method):
            if call.type != "method_invocation":
                continue
            arg = _java_native_filter_arg(source, call, ldap_context)
            if arg is None or arg.type != "identifier":
                continue
            name = _text(source, arg)
            if name in params:
                summaries.setdefault(_java_method_name(source, method), set()).add(params.index(name))
    return summaries


def _java_sink_filter_arg(
    source: bytes, call: Node, ldap_context: bool, wrappers: dict[str, set[int]]
) -> Node | None:
    native = _java_native_filter_arg(source, call, ldap_context)
    if native is not None:
        return native
    args = _java_args(call)
    for index in wrappers.get(_java_call_name(source, call), set()):
        if index < len(args):
            return args[index]
    return None


def _java_bound_name(source: bytes, value: Node) -> str | None:
    parent = value.parent
    while parent is not None and parent.type not in _JAVA_NESTED_SCOPES:
        if parent.type == "variable_declarator":
            name = parent.child_by_field_name("name")
            return _text(source, name) if name is not None else None
        if parent.type == "assignment_expression":
            left = parent.child_by_field_name("left")
            return _text(source, left) if left is not None and left.type == "identifier" else None
        parent = parent.parent
    return None


def _java_reaches_sink(
    source: bytes,
    method: Node,
    value: Node,
    bound_name: str,
    ldap_context: bool,
    wrappers: dict[str, set[int]],
) -> bool:
    for call in _java_scope_nodes(method):
        if call.type != "method_invocation" or call.start_byte <= value.start_byte:
            continue
        arg = _java_sink_filter_arg(source, call, ldap_context, wrappers)
        if arg is not None and bound_name in _java_identifiers(source, arg):
            return True
    return False


def scan_java(source: str, uri: str, cve: str | None = None) -> list[dict]:
    src = source.encode("utf-8")
    root = _JAVA_PARSER.parse(src).root_node
    ldap_context = _java_ldap_context(source)
    if not ldap_context:
        return []
    wrappers = _java_wrapper_summaries(src, root, ldap_context)
    results: list[dict] = []
    seen: set[tuple[int, int]] = set()

    methods = [n for n in _iter_nodes(root) if n.type in ("method_declaration", "constructor_declaration")]
    for method in methods:
        tainted = set(_java_params(src, method))
        tainted.discard("this")
        safe: set[str] = set()
        reported_names: set[str] = set()
        nodes = sorted(_java_scope_nodes(method), key=lambda n: (n.start_byte, n.end_byte))

        for node in nodes:
            if node.type not in ("variable_declarator", "assignment_expression"):
                continue
            value = node.child_by_field_name("value") or node.child_by_field_name("right")
            name_node = node.child_by_field_name("name") or node.child_by_field_name("left")
            if value is None or name_node is None or name_node.type != "identifier":
                continue
            name = _text(src, name_node)
            sanitized = _java_filter_sanitized(src, value)
            value_tainted = bool((_java_identifiers(src, value) - safe) & tainted)
            if sanitized:
                safe.add(name)
                tainted.discard(name)
            elif value_tainted:
                tainted.add(name)
                safe.discard(name)
            elif value.type in ("string_literal", "decimal_integer_literal", "true", "false", "null_literal"):
                tainted.discard(name)
                safe.discard(name)

            if not value_tainted or sanitized or not _java_looks_filter(src, value):
                continue
            if not _java_reaches_sink(src, method, value, name, ldap_context, wrappers):
                continue
            key = (value.start_point[0], value.start_point[1])
            if key in seen:
                continue
            seen.add(key)
            reported_names.add(name)
            results.append(
                _result(
                    uri,
                    value.start_point[0] + 1,
                    value.start_point[1] + 1,
                    "LDAP injection (CWE-90): unescaped input constructs a filter used by an LDAP search",
                    cve,
                )
            )

        for call in nodes:
            if call.type != "method_invocation":
                continue
            arg = _java_sink_filter_arg(src, call, ldap_context, wrappers)
            if arg is None or _java_filter_sanitized(src, arg):
                continue
            ids = _java_identifiers(src, arg)
            if ids & reported_names:
                continue
            if not ((ids - safe) & tainted) or not _java_looks_filter(src, arg):
                continue
            key = (call.start_point[0], call.start_point[1])
            if key in seen:
                continue
            seen.add(key)
            results.append(
                _result(
                    uri,
                    call.start_point[0] + 1,
                    call.start_point[1] + 1,
                    "LDAP injection (CWE-90): dynamic unescaped filter passed to an LDAP search",
                    cve,
                )
            )
    return results


# ---------------------------------------------------------------------------
# Python (stdlib ast)
# ---------------------------------------------------------------------------


def _py_name(func: ast.AST) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _py_iter_scope(scope: ast.AST):
    for child in ast.iter_child_nodes(scope):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield child
        yield from _py_iter_scope(child)


def _py_params(scope: ast.AST) -> set[str]:
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return set()
    args = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
    out = {a.arg for a in args}
    if scope.args.vararg:
        out.add(scope.args.vararg.arg)
    if scope.args.kwarg:
        out.add(scope.args.kwarg.arg)
    out -= {"self", "cls"}
    return out


def _py_filter_sanitized(node: ast.AST) -> bool:
    for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
        name = _py_name(call.func).lower().replace("_", "")
        if name in {
            "escapefilterchars",
            "escapeldapfilter",
            "encodefiltervalue",
            "filterencode",
        }:
            return True
        if "escape" in name and "filter" in name and "dn" not in name:
            return True
    return False


def _py_looks_filter(node: ast.AST, source: str) -> bool:
    segment = ast.get_source_segment(source, node) or ""
    lowered = segment.lower()
    if isinstance(node, ast.JoinedStr):
        literals = "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
        return "(" in literals and "=" in literals
    if isinstance(node, ast.Call) and _py_name(node.func) in ("replace", "format"):
        return "filter" in lowered or "[search]" in lowered or "{0}" in segment
    if isinstance(node, (ast.BinOp, ast.Call)):
        return "(" in segment and "=" in segment
    return False


def _py_ldap_context(tree: ast.AST, source: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(a.name.split(".")[0] in ("ldap", "ldap3") for a in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in ("ldap", "ldap3"):
            return True
    return any(marker in source for marker in ("auth_ldap", "AUTH_LDAP", "ldap.SCOPE_", "ldap3.Connection"))


def _py_sink_filter_arg(call: ast.Call, source: str, ldap_context: bool) -> ast.AST | None:
    if not ldap_context:
        return None
    name = _py_name(call.func)
    for kw in call.keywords:
        if kw.arg in ("search_filter", "filterstr", "filter_str"):
            return kw.value
    func_text = (ast.get_source_segment(source, call.func) or "").lower()
    if name == "search" and len(call.args) >= 2:
        if any(part in func_text for part in ("conn", "ldap", "directory")):
            return call.args[1]
    if name in ("search_s", "search_ext", "search_ext_s") and len(call.args) >= 3:
        return call.args[2]
    return None


def _py_safe_helpers(tree: ast.AST, source: str) -> set[str]:
    safe: set[str] = set()
    for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        body_nodes = list(_py_iter_scope(fn))
        if not any(isinstance(n, ast.Call) and _py_filter_sanitized(n) for n in body_nodes):
            continue
        if any(isinstance(n, ast.Return) and n.value is not None and _py_looks_filter(n.value, source) for n in body_nodes):
            safe.add(fn.name)
    return safe


def _py_call_is_safe_helper(node: ast.AST, safe_helpers: set[str]) -> bool:
    return isinstance(node, ast.Call) and _py_name(node.func) in safe_helpers


def _py_targets(node: ast.Assign | ast.AnnAssign | ast.NamedExpr) -> list[str]:
    targets: list[ast.AST]
    if isinstance(node, ast.Assign):
        targets = node.targets
    else:
        targets = [node.target]
    return [t.id for t in targets if isinstance(t, ast.Name)]


def scan_python(source: str, uri: str, cve: str | None = None) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    ldap_context = _py_ldap_context(tree, source)
    if not ldap_context:
        return []
    safe_helpers = _py_safe_helpers(tree, source)
    scopes: list[ast.AST] = [tree]
    scopes.extend(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
    results: list[dict] = []
    seen: set[tuple[int, int]] = set()

    for scope in scopes:
        nodes = sorted(_py_iter_scope(scope), key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0)))
        tainted = _py_params(scope)
        safe_names: set[str] = set()
        candidate_defs: list[tuple[ast.AST, str]] = []

        sink_calls = [
            n
            for n in nodes
            if isinstance(n, ast.Call) and _py_sink_filter_arg(n, source, ldap_context) is not None
        ]

        for node in nodes:
            if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                continue
            value = node.value
            targets = _py_targets(node)
            if not targets:
                continue
            sanitized = _py_filter_sanitized(value) or _py_call_is_safe_helper(value, safe_helpers)
            identifiers = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
            value_tainted = bool((identifiers - safe_names) & tainted)
            for name in targets:
                if sanitized:
                    safe_names.add(name)
                    tainted.discard(name)
                elif value_tainted:
                    tainted.add(name)
                    safe_names.discard(name)
                elif isinstance(value, ast.Constant):
                    tainted.discard(name)
                    safe_names.discard(name)

            if value_tainted and not sanitized and _py_looks_filter(value, source):
                for name in targets:
                    reaches = False
                    for call in sink_calls:
                        if (call.lineno, call.col_offset) <= (node.lineno, node.col_offset):
                            continue
                        arg = _py_sink_filter_arg(call, source, ldap_context)
                        if arg is not None and name in {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}:
                            reaches = True
                            break
                    if reaches:
                        candidate_defs.append((value, name))

        reported_names: set[str] = set()
        for value, name in candidate_defs:
            key = (value.lineno, value.col_offset)
            if key in seen:
                continue
            seen.add(key)
            reported_names.add(name)
            results.append(
                _result(
                    uri,
                    value.lineno,
                    value.col_offset + 1,
                    "LDAP injection (CWE-90): unescaped input constructs a filter used by an LDAP search",
                    cve,
                )
            )

        for call in sink_calls:
            arg = _py_sink_filter_arg(call, source, ldap_context)
            assert arg is not None
            if _py_filter_sanitized(arg) or _py_call_is_safe_helper(arg, safe_helpers):
                continue
            identifiers = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
            if identifiers & reported_names:
                continue
            if not ((identifiers - safe_names) & tainted) or not _py_looks_filter(arg, source):
                continue
            key = (call.lineno, call.col_offset)
            if key in seen:
                continue
            seen.add(key)
            results.append(
                _result(
                    uri,
                    call.lineno,
                    call.col_offset + 1,
                    "LDAP injection (CWE-90): dynamic unescaped filter passed to an LDAP search",
                    cve,
                )
            )
    return results


# ---------------------------------------------------------------------------
# PHP (tree-sitter)
# ---------------------------------------------------------------------------


def _php_scope_nodes(scope: Node):
    stack = list(reversed(scope.children))
    while stack:
        node = stack.pop()
        if node.type in _PHP_SCOPES:
            continue
        yield node
        stack.extend(reversed(node.children))


def _php_call_name(source: bytes, call: Node) -> str:
    if call.type == "member_call_expression":
        return _text(source, call.child_by_field_name("name"))
    function = call.child_by_field_name("function")
    return _text(source, function)


def _php_args(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    out: list[Node] = []
    for arg in args.named_children:
        if arg.type == "argument" and arg.named_children:
            out.append(arg.named_children[0])
        else:
            out.append(arg)
    return out


def _php_vars(source: bytes, node: Node | None) -> set[str]:
    if node is None:
        return set()
    return {_text(source, n) for n in _iter_nodes(node) if n.type == "variable_name"}


def _php_params(source: bytes, scope: Node) -> set[str]:
    params = scope.child_by_field_name("parameters")
    if params is None:
        return set()
    return {_text(source, n) for n in _iter_nodes(params) if n.type == "variable_name"}


def _php_filter_sanitized(source: bytes, node: Node) -> bool:
    for call in _iter_nodes(node):
        if call.type not in ("function_call_expression", "member_call_expression", "scoped_call_expression"):
            continue
        name = _php_call_name(source, call).lower().replace("_", "")
        call_text = _text(source, call)
        if name in ("escapefilterchars", "escapeldapfilter", "encodefiltervalue", "filterencode"):
            return True
        if name in ("escape", "ldapescape") and "LDAP_ESCAPE_FILTER" in call_text:
            return True
        if "escape" in name and "filter" in name and "dn" not in name:
            return True
    return False


def _php_looks_filter(source: bytes, node: Node) -> bool:
    value = _text(source, node)
    lowered = value.lower()
    if "str_replace" in lowered and ("[search]" in lowered or "filter" in lowered):
        return True
    if any(token in lowered for token in ("sprintf", "vsprintf", "format")):
        return "(" in value and "=" in value
    return "(" in value and "=" in value


def _php_sink_arg(source: bytes, call: Node, ldap_context: bool) -> Node | None:
    if not ldap_context:
        return None
    name = _php_call_name(source, call).lower()
    args = _php_args(call)
    if call.type == "member_call_expression" and name in ("simple_search", "search") and args:
        obj = _text(source, call.child_by_field_name("object")).lower()
        if "ldap" in obj:
            return args[0]
    if call.type == "function_call_expression" and name in ("ldap_search", "ldap_list", "ldap_read"):
        if len(args) >= 3:
            return args[2]
    return None


def scan_php(source: str, uri: str, cve: str | None = None) -> list[dict]:
    src = source.encode("utf-8")
    root = _PHP_PARSER.parse(src).root_node
    ldap_context = "ldap" in source.lower()
    if not ldap_context:
        return []
    scopes = [root]
    scopes.extend(n for n in _iter_nodes(root) if n.type in _PHP_SCOPES)
    results: list[dict] = []
    seen: set[tuple[int, int]] = set()

    for scope in scopes:
        nodes = sorted(_php_scope_nodes(scope), key=lambda n: (n.start_byte, n.end_byte))
        tainted = _php_params(src, scope)
        safe_names: set[str] = set()
        sink_calls = [
            n
            for n in nodes
            if n.type in ("function_call_expression", "member_call_expression")
            and _php_sink_arg(src, n, ldap_context) is not None
        ]
        reported_names: set[str] = set()

        for node in nodes:
            if node.type != "assignment_expression":
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None or left.type != "variable_name":
                continue
            name = _text(src, left)
            sanitized = _php_filter_sanitized(src, right)
            value_tainted = bool((_php_vars(src, right) - safe_names) & tainted)
            if sanitized:
                safe_names.add(name)
                tainted.discard(name)
            elif value_tainted:
                tainted.add(name)
                safe_names.discard(name)
            elif right.type in ("string", "integer", "float", "boolean", "null"):
                tainted.discard(name)
                safe_names.discard(name)

            if not value_tainted or sanitized or not _php_looks_filter(src, right):
                continue
            reaches = any(
                call.start_byte > node.start_byte
                and name in _php_vars(src, _php_sink_arg(src, call, ldap_context))
                for call in sink_calls
            )
            if not reaches:
                continue
            key = (right.start_point[0], right.start_point[1])
            if key in seen:
                continue
            seen.add(key)
            reported_names.add(name)
            results.append(
                _result(
                    uri,
                    right.start_point[0] + 1,
                    right.start_point[1] + 1,
                    "LDAP injection (CWE-90): unescaped input constructs a filter used by an LDAP search",
                    cve,
                )
            )

        for call in sink_calls:
            arg = _php_sink_arg(src, call, ldap_context)
            assert arg is not None
            if _php_filter_sanitized(src, arg):
                continue
            variables = _php_vars(src, arg)
            if variables & reported_names:
                continue
            if not ((variables - safe_names) & tainted) or not _php_looks_filter(src, arg):
                continue
            key = (call.start_point[0], call.start_point[1])
            if key in seen:
                continue
            seen.add(key)
            results.append(
                _result(
                    uri,
                    call.start_point[0] + 1,
                    call.start_point[1] + 1,
                    "LDAP injection (CWE-90): dynamic unescaped filter passed to an LDAP search",
                    cve,
                )
            )
    return results


# ---------------------------------------------------------------------------
# Shared dispatch / SARIF
# ---------------------------------------------------------------------------


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    lowered = uri.lower()
    if lowered.endswith(".java"):
        return scan_java(source, uri, cve)
    if lowered.endswith(".php"):
        return scan_php(source, uri, cve)
    if lowered.endswith(".py"):
        return scan_python(source, uri, cve)
    return []


def scan_file(path: str | Path, uri: str | None = None, cve: str | None = None) -> dict:
    p = Path(path)
    target_uri = uri or p.name
    results = scan_source(p.read_text(encoding="utf-8"), target_uri, cve)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deepthought-ldap-filter-rule",
                        "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                        "rules": [
                            {
                                "id": RULE_ID,
                                "name": "LDAPFilterInjection",
                                "shortDescription": {
                                    "text": "Unescaped input in an LDAP search filter (CWE-90)"
                                },
                                "defaultConfiguration": {"level": "error"},
                                "helpUri": "https://cwe.mitre.org/data/definitions/90.html",
                                "properties": {
                                    "cwe": GROUND_TRUTH_CWE,
                                    "tags": ["security", "CWE-90", "ldap-injection"],
                                },
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
