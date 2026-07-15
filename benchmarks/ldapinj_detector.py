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


def _is_structural_parameter(name: str) -> bool:
    """Exclude directory handles and filter templates from untrusted value sources."""
    normalized = name.lstrip("$").lower().replace("_", "")
    return normalized in {
        "base",
        "client",
        "con",
        "conn",
        "connection",
        "context",
        "control",
        "controls",
        "ctx",
        "dc",
        "directory",
        "ldap",
        "scope",
        "searchbase",
        "searchstring",
        "template",
        "userbase",
        "userfilter",
    }


def _ts_branch_arms(node: Node) -> dict[int, str]:
    """Return enclosing tree-sitter if identities and the arm containing node."""
    arms: dict[int, str] = {}
    current = node
    while current.parent is not None:
        parent = current.parent
        if parent.type == "if_statement":
            field = None
            for index, child in enumerate(parent.children):
                if child == current:
                    field = parent.field_name_for_child(index)
                    break
            if field in ("body", "consequence"):
                arms[parent.id] = "body"
            elif field == "alternative":
                arms[parent.id] = "orelse"
        current = parent
    return arms


def _ts_mutually_exclusive(left: Node, right: Node) -> bool:
    left_arms = _ts_branch_arms(left)
    right_arms = _ts_branch_arms(right)
    return any(
        branch in right_arms and right_arms[branch] != arm
        for branch, arm in left_arms.items()
    )


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


def _java_local_filter_sanitizers(source: bytes, root: Node) -> set[str]:
    """Prove local RFC 4515 encoders by the five required metacharacter escapes."""
    methods: dict[str, list[Node]] = {}
    for method in _iter_nodes(root):
        if method.type != "method_declaration":
            continue
        methods.setdefault(_java_method_name(source, method), []).append(method)

    required_pairs = (
        (r"case '\\'", r"\\5c"),
        ("case '*'", r"\\2a"),
        ("case '('", r"\\28"),
        ("case ')'", r"\\29"),
        (r"case '\0'", r"\\00"),
    )

    def proves_filter_encoding(method: Node) -> bool:
        groups = [
            _text(source, node).lower()
            for node in _iter_nodes(method)
            if node.type in ("switch_rule", "switch_block_statement_group")
        ]
        return all(
            any(case in group and encoded in group for group in groups)
            for case, encoded in required_pairs
        )

    return {
        name
        for name, declarations in methods.items()
        if name and all(proves_filter_encoding(method) for method in declarations)
    }


def _java_call_is_filter_sanitizer(
    source: bytes, call: Node, local_sanitizers: set[str]
) -> bool:
    if call.type != "method_invocation":
        return False
    raw_name = _java_call_name(source, call)
    name = raw_name.lower().replace("_", "")
    owner = _text(source, call.child_by_field_name("object")).lower()

    # A local helper is trusted only after its implementation proves all RFC 4515
    # escapes. Name-only helpers are attacker-controlled code, not sanitizers.
    if raw_name in local_sanitizers and owner in ("", "this"):
        return True
    source_text = source.decode("utf-8", "replace").lower()
    spring_encoder_imported = (
        "import org.springframework.ldap.support.ldapencoder;" in source_text
    )
    if (
        name == "filterencode"
        and (
            owner == "org.springframework.ldap.support.ldapencoder"
            or (owner == "ldapencoder" and spring_encoder_imported)
        )
    ):
        return True
    if any(token in owner for token in ("ldapfilter", "filterencoder")) and name in {
        "escapefilterchars",
        "escapeldapfilter",
        "encodefiltervalue",
        "filterencode",
    }:
        return True
    return False


def _java_filter_sanitized(
    source: bytes, node: Node, local_sanitizers: set[str]
) -> bool:
    """Recognize proven RFC 4515 *filter* escaping, not DN escaping."""
    for call in _iter_nodes(node):
        if _java_call_is_filter_sanitizer(source, call, local_sanitizers):
            return True
    return False


def _java_unsanitized_identifiers(
    source: bytes, node: Node, local_sanitizers: set[str]
) -> set[str]:
    """Identifiers reaching an expression outside a proven sanitizer subtree."""
    if _java_call_is_filter_sanitizer(source, node, local_sanitizers):
        return set()
    if node.type == "identifier":
        return {_text(source, node)}
    out: set[str] = set()
    for child in node.named_children:
        out.update(_java_unsanitized_identifiers(source, child, local_sanitizers))
    return out


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


def _java_field_ldap_receivers(source: bytes, method: Node) -> set[str]:
    receivers: set[str] = set()
    ldap_types = ("dircontext", "ldapcontext", "initialdircontext")
    owner = method.parent
    while owner is not None and owner.type not in (
        "class_declaration",
        "enum_declaration",
        "record_declaration",
    ):
        owner = owner.parent
    body = owner.child_by_field_name("body") if owner is not None else None
    if body is None:
        return receivers
    for node in body.named_children:
        if node.type != "field_declaration":
            continue
        type_text = _text(source, node.child_by_field_name("type")).lower()
        if any(kind in type_text for kind in ldap_types):
            for declarator in node.named_children:
                if declarator.type == "variable_declarator":
                    name = declarator.child_by_field_name("name")
                    if name is not None:
                        receivers.add(_text(source, name))
    return receivers


def _java_owner_id(node: Node) -> int:
    owner = node.parent
    while owner is not None:
        if owner.type in (
            "class_declaration",
            "enum_declaration",
            "record_declaration",
        ):
            return owner.id
        owner = owner.parent
    return 0


def _java_scope_ldap_receivers(
    source: bytes, method: Node, field_receivers: set[str]
) -> set[str]:
    receivers = set(field_receivers)
    ldap_types = ("dircontext", "ldapcontext", "initialdircontext")
    for node in (method, *_java_scope_nodes(method)):
        if node.type in ("formal_parameter", "spread_parameter", "receiver_parameter"):
            type_text = _text(source, node.child_by_field_name("type")).lower()
            name = node.child_by_field_name("name")
            if name is None:
                continue
            receiver_name = _text(source, name)
            if any(kind in type_text for kind in ldap_types):
                receivers.add(receiver_name)
            else:
                receivers.discard(receiver_name)
        elif node.type == "local_variable_declaration":
            type_text = _text(source, node.child_by_field_name("type")).lower()
            is_ldap = any(kind in type_text for kind in ldap_types)
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                if name is None:
                    continue
                receiver_name = _text(source, name)
                if is_ldap:
                    receivers.add(receiver_name)
                else:
                    receivers.discard(receiver_name)
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            name = node.child_by_field_name("name")
            value_text = _text(source, value).lower()
            if name is not None and "new " in value_text and any(kind in value_text for kind in ldap_types):
                receivers.add(_text(source, name))
    return receivers


def _java_native_filter_arg(
    source: bytes, call: Node, ldap_context: bool, ldap_receivers: set[str]
) -> Node | None:
    if not ldap_context or _java_call_name(source, call) != "search":
        return None
    args = _java_args(call)
    if len(args) < 3:
        return None
    receiver = call.child_by_field_name("object")
    if receiver is None or not (_java_identifiers(source, receiver) & ldap_receivers):
        return None
    return args[1]


def _java_wrapper_summaries(
    source: bytes, root: Node, ldap_context: bool
) -> dict[int, dict[tuple[str, int], int]]:
    """Unambiguous name/arity -> parameter index forwarded to a JNDI filter."""
    declarations: dict[int, dict[tuple[str, int], list[int | None]]] = {}
    methods = [n for n in _iter_nodes(root) if n.type in ("method_declaration", "constructor_declaration")]
    for method in methods:
        params = _java_params(source, method)
        if not params:
            continue
        ldap_receivers = _java_scope_ldap_receivers(
            source, method, _java_field_ldap_receivers(source, method)
        )
        forwarded: set[int] = set()
        for call in _java_scope_nodes(method):
            if call.type != "method_invocation":
                continue
            arg = _java_native_filter_arg(source, call, ldap_context, ldap_receivers)
            if arg is None or arg.type != "identifier":
                continue
            name = _text(source, arg)
            if name in params:
                forwarded.add(params.index(name))
        key = (_java_method_name(source, method), len(params))
        owner_declarations = declarations.setdefault(_java_owner_id(method), {})
        owner_declarations.setdefault(key, []).append(
            next(iter(forwarded)) if len(forwarded) == 1 else None
        )

    summaries: dict[int, dict[tuple[str, int], int]] = {}
    for owner, owner_declarations in declarations.items():
        for key, indexes in owner_declarations.items():
            index = next((value for value in indexes if value is not None), None)
            if index is not None and None not in indexes and len(set(indexes)) == 1:
                summaries.setdefault(owner, {})[key] = index
    return summaries


def _java_sink_filter_arg(
    source: bytes,
    call: Node,
    ldap_context: bool,
    ldap_receivers: set[str],
    wrappers: dict[tuple[str, int], int],
) -> Node | None:
    native = _java_native_filter_arg(source, call, ldap_context, ldap_receivers)
    if native is not None:
        return native
    args = _java_args(call)
    receiver = _text(source, call.child_by_field_name("object"))
    if receiver not in ("", "this"):
        return None
    index = wrappers.get((_java_call_name(source, call), len(args)))
    if index is not None and index < len(args):
        return args[index]
    return None


def scan_java(source: str, uri: str, cve: str | None = None) -> list[dict]:
    src = source.encode("utf-8")
    root = _JAVA_PARSER.parse(src).root_node
    ldap_context = _java_ldap_context(source)
    if not ldap_context:
        return []
    local_sanitizers = _java_local_filter_sanitizers(src, root)
    wrappers_by_owner = _java_wrapper_summaries(src, root, ldap_context)
    results: list[dict] = []
    seen: set[tuple[int, int]] = set()

    methods = [n for n in _iter_nodes(root) if n.type in ("method_declaration", "constructor_declaration")]
    for method in methods:
        wrappers = wrappers_by_owner.get(_java_owner_id(method), {})
        ldap_receivers = _java_scope_ldap_receivers(
            src, method, _java_field_ldap_receivers(src, method)
        )
        tainted = {
            name for name in _java_params(src, method) if not _is_structural_parameter(name)
        }
        tainted.discard("this")
        safe: set[str] = set()
        active_candidates: dict[str, list[Node]] = {}
        nodes = list(_java_scope_nodes(method))
        # An assignment takes effect after its RHS has been evaluated.  Using its end
        # byte as the event position also keeps a search nested in that RHS on the old
        # state, while ordinary definitions still precede later statements.
        events = sorted(
            (
                (
                    node.end_byte
                    if node.type in ("variable_declarator", "assignment_expression")
                    else node.start_byte
                ),
                index,
                node,
            )
            for index, node in enumerate(nodes)
            if node.type in ("variable_declarator", "assignment_expression", "method_invocation")
        )

        for _, _, node in events:
            if node.type in ("variable_declarator", "assignment_expression"):
                value = node.child_by_field_name("value") or node.child_by_field_name("right")
                name_node = node.child_by_field_name("name") or node.child_by_field_name("left")
                if value is None or name_node is None or name_node.type != "identifier":
                    continue
                name = _text(src, name_node)
                unsanitized = _java_unsanitized_identifiers(src, value, local_sanitizers)
                value_tainted = bool((unsanitized - safe) & tainted)
                sanitized = _java_filter_sanitized(src, value, local_sanitizers) and not value_tainted
                if sanitized:
                    safe.add(name)
                    tainted.discard(name)
                elif value_tainted:
                    tainted.add(name)
                    safe.discard(name)
                elif value.type in ("string_literal", "decimal_integer_literal", "true", "false", "null_literal"):
                    tainted.discard(name)
                    safe.discard(name)

                # Sequential definitions replace prior state, while alternate arms
                # both reach a sink after the branch and must both remain candidates.
                alternatives = [
                    candidate
                    for candidate in active_candidates.get(name, [])
                    if _ts_mutually_exclusive(candidate, value)
                ]
                active_candidates[name] = alternatives
                if value_tainted and not sanitized and _java_looks_filter(src, value):
                    active_candidates[name].append(value)
                if not active_candidates[name]:
                    active_candidates.pop(name)
                continue

            call = node
            arg = _java_sink_filter_arg(src, call, ldap_context, ldap_receivers, wrappers)
            if arg is None:
                continue
            unsanitized = _java_unsanitized_identifiers(src, arg, local_sanitizers)
            value_tainted = bool((unsanitized - safe) & tainted)
            if _java_filter_sanitized(src, arg, local_sanitizers) and not value_tainted:
                continue
            ids = _java_identifiers(src, arg)
            candidates = [
                candidate
                for name in ids
                for candidate in active_candidates.get(name, [])
                if not _ts_mutually_exclusive(candidate, call)
            ]
            if candidates:
                for value in candidates:
                    key = (value.start_point[0], value.start_point[1])
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append(
                        _result(
                            uri,
                            value.start_point[0] + 1,
                            value.start_point[1] + 1,
                            "LDAP injection (CWE-90): unescaped input constructs a filter used by an LDAP search",
                            cve,
                        )
                    )
                continue
            if not value_tainted or not _java_looks_filter(src, arg):
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


def _py_dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _py_dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
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


def _py_sanitizer_context(tree: ast.AST) -> tuple[dict[str, str], set[str]]:
    """Resolve only known python-ldap/ldap3 filter encoders and their aliases."""
    module_aliases: dict[str, str] = {}
    imported_functions: set[str] = set()
    safe_modules = ("ldap.filter", "ldap3.utils.conv")
    safe_names = {"escape_filter_chars"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "ldap" or alias.name == "ldap3" or alias.name.startswith(safe_modules):
                    bound = alias.asname or alias.name.split(".")[0]
                    module_aliases[bound] = alias.name if alias.asname else bound
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith(safe_modules):
                for alias in node.names:
                    if alias.name in safe_names:
                        imported_functions.add(alias.asname or alias.name)
            elif node.module in ("ldap", "ldap3.utils"):
                for alias in node.names:
                    full = f"{node.module}.{alias.name}"
                    if full in safe_modules:
                        module_aliases[alias.asname or alias.name] = full
    rebound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound.add(node.name)
        elif isinstance(node, ast.arg):
            rebound.add(node.arg)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            rebound.update(_py_targets(node))
    for name in rebound:
        module_aliases.pop(name, None)
        imported_functions.discard(name)
    return module_aliases, imported_functions


def _py_is_filter_sanitizer_call(
    call: ast.Call, sanitizer_context: tuple[dict[str, str], set[str]]
) -> bool:
    module_aliases, imported_functions = sanitizer_context
    dotted = _py_dotted(call.func)
    if dotted in imported_functions:
        return True
    parts = dotted.split(".")
    if parts and parts[0] in module_aliases:
        parts[0] = module_aliases[parts[0]]
    canonical = ".".join(parts)
    return canonical in {
        "ldap.filter.escape_filter_chars",
        "ldap3.utils.conv.escape_filter_chars",
    }


def _py_filter_sanitized(
    node: ast.AST, sanitizer_context: tuple[dict[str, str], set[str]]
) -> bool:
    return any(
        _py_is_filter_sanitizer_call(call, sanitizer_context)
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
    )


def _py_local_helper_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in ("self", "cls")
    ):
        return call.func.attr
    return ""


def _py_unsanitized_names(
    node: ast.AST,
    sanitizer_context: tuple[dict[str, str], set[str]],
    safe_helpers: set[str] | None = None,
) -> set[str]:
    """Names whose values reach an expression without filter encoding."""
    helpers = safe_helpers or set()
    if isinstance(node, ast.Call) and (
        _py_is_filter_sanitizer_call(node, sanitizer_context)
        or _py_local_helper_name(node) in helpers
    ):
        return set()
    if isinstance(node, ast.Name):
        return {node.id}
    out: set[str] = set()
    for child in ast.iter_child_nodes(node):
        out.update(_py_unsanitized_names(child, sanitizer_context, helpers))
    return out


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


def _py_ldap_receivers(scope: ast.AST, source: str) -> set[str]:
    receivers: set[str] = set()
    conventional = {"client", "con", "conn", "dc", "directory", "ldap"}
    for node in (scope, *_py_iter_scope(scope)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            for arg in args:
                annotation = ast.get_source_segment(source, arg.annotation) if arg.annotation else ""
                if arg.arg.lower() in conventional or "ldap" in (annotation or "").lower():
                    receivers.add(arg.arg)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            if value is None:
                continue
            value_name = _py_dotted(value.func) if isinstance(value, ast.Call) else ""
            annotation = (
                ast.get_source_segment(source, node.annotation)
                if isinstance(node, ast.AnnAssign)
                else ""
            )
            if value_name.startswith(("ldap.", "ldap3.")) or "ldap" in (annotation or "").lower():
                receivers.update(_py_targets(node))
    return receivers


def _py_sink_filter_arg(
    call: ast.Call,
    source: str,
    ldap_context: bool,
    ldap_receivers: set[str],
) -> ast.AST | None:
    if not ldap_context:
        return None
    name = _py_name(call.func)
    if not isinstance(call.func, ast.Attribute) or name not in {
        "search",
        "search_s",
        "search_ext",
        "search_ext_s",
    }:
        return None
    receiver = _py_dotted(call.func.value)
    terminal = receiver.split(".")[-1].lower()
    if (
        receiver.split(".")[0] not in ldap_receivers
        and terminal not in {"client", "con", "conn", "dc", "directory", "ldap"}
        and "ldap" not in receiver.lower()
    ):
        return None
    for kw in call.keywords:
        if kw.arg in ("search_filter", "filterstr", "filter_str"):
            return kw.value
    if name == "search" and len(call.args) >= 2:
        return call.args[1]
    if name in ("search_s", "search_ext", "search_ext_s") and len(call.args) >= 3:
        return call.args[2]
    return None


def _py_targets(node: ast.Assign | ast.AnnAssign | ast.NamedExpr) -> list[str]:
    targets: list[ast.AST]
    if isinstance(node, ast.Assign):
        targets = node.targets
    else:
        targets = [node.target]

    def names(target: ast.AST) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [name for element in target.elts for name in names(element)]
        if isinstance(target, ast.Starred):
            return names(target.value)
        return []

    return [name for target in targets for name in names(target)]


def _py_target_bindings(
    node: ast.Assign | ast.AnnAssign | ast.NamedExpr,
) -> list[tuple[str, ast.AST]]:
    """Pair unpacked targets with their corresponding RHS elements when knowable."""
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]

    def bind(target: ast.AST, value: ast.AST) -> list[tuple[str, ast.AST]]:
        if isinstance(target, ast.Name):
            return [(target.id, value)]
        if isinstance(target, ast.Starred):
            return bind(target.value, value)
        if (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(target.elts) == len(value.elts)
            and not any(isinstance(element, ast.Starred) for element in target.elts)
        ):
            return [
                binding
                for target_element, value_element in zip(target.elts, value.elts)
                for binding in bind(target_element, value_element)
            ]
        return [(name, value) for name in _py_targets_from_target(target)]

    return [binding for target in targets for binding in bind(target, node.value)]


def _py_targets_from_target(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [
            name for element in target.elts for name in _py_targets_from_target(element)
        ]
    if isinstance(target, ast.Starred):
        return _py_targets_from_target(target.value)
    return []


def _py_helper_summaries(
    tree: ast.AST,
    source: str,
    sanitizer_context: tuple[dict[str, str], set[str]],
) -> tuple[set[str], set[str]]:
    analyses: dict[str, list[tuple[bool, bool]]] = {}
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        tainted = {name for name in _py_params(fn) if not _is_structural_parameter(name)}
        sanitized_names: set[str] = set()
        filter_names: set[str] = set()
        body_nodes = sorted(
            _py_iter_scope(fn),
            key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0)),
        )
        saw_return = False
        all_returns_are_filters = True
        all_filter_returns_safe = True
        for node in body_nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                value = node.value
                if value is None:
                    continue
                bindings = _py_target_bindings(node)
                if not bindings:
                    continue
                for name, bound_value in bindings:
                    unsanitized = _py_unsanitized_names(
                        bound_value, sanitizer_context
                    )
                    value_tainted = bool(
                        (unsanitized - sanitized_names) & tainted
                    )
                    carries_sanitized = _py_filter_sanitized(
                        bound_value, sanitizer_context
                    ) or bool(
                        {
                            n.id
                            for n in ast.walk(bound_value)
                            if isinstance(n, ast.Name)
                        }
                        & sanitized_names
                    )
                    if value_tainted:
                        tainted.add(name)
                        sanitized_names.discard(name)
                    elif carries_sanitized and parents.get(node) is fn:
                        # Only straight-line sanitizer assignments dominate every
                        # later return. Branch-local writes need a full control-flow
                        # proof and are therefore not trusted by this summary.
                        tainted.discard(name)
                        sanitized_names.add(name)
                    elif isinstance(bound_value, ast.Constant):
                        tainted.discard(name)
                        sanitized_names.discard(name)
                    if _py_looks_filter(bound_value, source):
                        filter_names.add(name)
                    elif isinstance(bound_value, ast.Constant):
                        filter_names.discard(name)
                continue
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            saw_return = True
            returned_names = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
            is_filter = _py_looks_filter(node.value, source) or bool(returned_names & filter_names)
            all_returns_are_filters &= is_filter
            has_sanitized_value = _py_filter_sanitized(
                node.value, sanitizer_context
            ) or bool(returned_names & sanitized_names)
            all_filter_returns_safe &= is_filter and has_sanitized_value and not (
                (_py_unsanitized_names(node.value, sanitizer_context) - sanitized_names)
                & tainted
            )
        analyses.setdefault(fn.name, []).append(
            (saw_return and all_returns_are_filters, saw_return and all_filter_returns_safe)
        )

    filter_builders = {
        name for name, outcomes in analyses.items() if any(builder for builder, _ in outcomes)
    }
    safe = {
        name
        for name, outcomes in analyses.items()
        if outcomes and all(builder and safe_return for builder, safe_return in outcomes)
    }
    return safe, filter_builders


def _py_call_is_safe_helper(node: ast.AST, safe_helpers: set[str]) -> bool:
    return isinstance(node, ast.Call) and _py_local_helper_name(node) in safe_helpers


def _py_branch_arms(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> dict[int, str]:
    """Return enclosing if identities and the branch containing node."""
    arms: dict[int, str] = {}
    current = node
    while current in parents:
        parent = parents[current]
        if isinstance(parent, ast.If):
            if current in parent.body:
                arms[id(parent)] = "body"
            elif current in parent.orelse:
                arms[id(parent)] = "orelse"
        current = parent
    return arms


def _py_mutually_exclusive(
    left: ast.AST, right: ast.AST, parents: dict[ast.AST, ast.AST]
) -> bool:
    left_arms = _py_branch_arms(left, parents)
    right_arms = _py_branch_arms(right, parents)
    return any(
        branch in right_arms and right_arms[branch] != arm
        for branch, arm in left_arms.items()
    )


def scan_python(source: str, uri: str, cve: str | None = None) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    ldap_context = _py_ldap_context(tree, source)
    if not ldap_context:
        return []
    sanitizer_context = _py_sanitizer_context(tree)
    safe_helpers, filter_helpers = _py_helper_summaries(
        tree, source, sanitizer_context
    )
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    scopes: list[ast.AST] = [tree]
    scopes.extend(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
    results: list[dict] = []
    seen: set[tuple[int, int]] = set()

    for scope in scopes:
        nodes = list(_py_iter_scope(scope))
        ldap_receivers = _py_ldap_receivers(scope, source)
        tainted = {
            name for name in _py_params(scope) if not _is_structural_parameter(name)
        }
        safe_names: set[str] = set()
        active_candidates: dict[str, list[ast.AST]] = {}

        def event_position(node: ast.AST) -> tuple[int, int]:
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                return (getattr(node, "end_lineno", node.lineno), getattr(node, "end_col_offset", node.col_offset))
            return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))

        events = sorted(
            (event_position(node), index, node)
            for index, node in enumerate(nodes)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.Call))
        )

        for _, _, node in events:
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                value = node.value
                if value is None:
                    continue
                bindings = _py_target_bindings(node)
                if not bindings:
                    continue
                for name, bound_value in bindings:
                    helper_safe = _py_call_is_safe_helper(
                        bound_value, safe_helpers
                    )
                    unsanitized = _py_unsanitized_names(
                        bound_value, sanitizer_context, safe_helpers
                    )
                    value_tainted = bool((unsanitized - safe_names) & tainted)
                    sanitized = helper_safe or (
                        _py_filter_sanitized(bound_value, sanitizer_context)
                        and not value_tainted
                    )
                    if sanitized:
                        safe_names.add(name)
                        tainted.discard(name)
                    elif value_tainted:
                        tainted.add(name)
                        safe_names.discard(name)
                    elif isinstance(bound_value, ast.Constant):
                        tainted.discard(name)
                        safe_names.discard(name)

                    alternatives = [
                        candidate
                        for candidate in active_candidates.get(name, [])
                        if _py_mutually_exclusive(candidate, bound_value, parents)
                    ]
                    active_candidates[name] = alternatives
                    if value_tainted and not sanitized and (
                        _py_looks_filter(bound_value, source)
                        or (
                            isinstance(bound_value, ast.Call)
                            and _py_name(bound_value.func) in filter_helpers
                        )
                    ):
                        active_candidates[name].append(bound_value)
                    if not active_candidates[name]:
                        active_candidates.pop(name)
                continue

            call = node
            arg = _py_sink_filter_arg(
                call, source, ldap_context, ldap_receivers
            )
            if arg is None:
                continue
            helper_safe = _py_call_is_safe_helper(arg, safe_helpers)
            unsanitized = _py_unsanitized_names(
                arg, sanitizer_context, safe_helpers
            )
            value_tainted = bool((unsanitized - safe_names) & tainted)
            if helper_safe or (
                _py_filter_sanitized(arg, sanitizer_context)
                and not value_tainted
            ):
                continue
            identifiers = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
            candidates = [
                candidate
                for name in identifiers
                for candidate in active_candidates.get(name, [])
                if not _py_mutually_exclusive(candidate, call, parents)
            ]
            if candidates:
                for value in candidates:
                    key = (value.lineno, value.col_offset)
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append(
                        _result(
                            uri,
                            value.lineno,
                            value.col_offset + 1,
                            "LDAP injection (CWE-90): unescaped input constructs a filter used by an LDAP search",
                            cve,
                        )
                    )
                continue
            if not value_tainted or not (
                _py_looks_filter(arg, source)
                or (isinstance(arg, ast.Call) and _py_name(arg.func) in filter_helpers)
            ):
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
    if call.type in ("member_call_expression", "scoped_call_expression"):
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


def _php_ldap_receivers(source: bytes, root: Node) -> set[str]:
    receivers: set[str] = set()
    for node in _iter_nodes(root):
        if node.type == "simple_parameter":
            type_text = _text(source, node.child_by_field_name("type")).lower()
            name = node.child_by_field_name("name")
            if name is not None and "ldap" in type_text:
                receivers.add(_text(source, name))
        elif node.type == "property_declaration" and "ldap" in _text(source, node).lower():
            receivers.update(_php_vars(source, node))
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if (
                left is not None
                and left.type == "variable_name"
                and right is not None
                and right.type == "object_creation_expression"
                and "ldap" in _text(source, right).lower()
            ):
                receivers.add(_text(source, left))
    return receivers


def _php_local_classes(source: bytes, root: Node) -> set[str]:
    return {
        _text(source, node.child_by_field_name("name")).lower()
        for node in _iter_nodes(root)
        if node.type == "class_declaration"
        and node.child_by_field_name("name") is not None
    }


def _php_receiver_is_ldap(
    source: bytes, receiver: Node | None, ldap_receivers: set[str]
) -> bool:
    if receiver is None:
        return False
    if _php_vars(source, receiver) & ldap_receivers:
        return True
    receiver_text = _text(source, receiver).lower()
    normalized = receiver_text.lstrip("$")
    return normalized.startswith("ldap") or "->ldap" in receiver_text


def _php_call_is_filter_sanitizer(
    source: bytes,
    call: Node,
    ldap_receivers: set[str],
    local_classes: set[str],
) -> bool:
    if call.type not in (
        "function_call_expression",
        "member_call_expression",
        "scoped_call_expression",
    ):
        return False
    raw_name = _php_call_name(source, call).lower()
    name = raw_name.replace("_", "")
    call_text = _text(source, call).lower()
    has_filter_flag = "ldap_escape_filter" in call_text

    if call.type == "function_call_expression":
        return name == "ldapescape" and has_filter_flag
    if call.type == "member_call_expression":
        if not _php_receiver_is_ldap(
            source, call.child_by_field_name("object"), ldap_receivers
        ):
            return False
        if name in ("escape", "ldapescape"):
            return has_filter_flag
        return name in {
            "escapefilterchars",
            "escapeldapfilter",
            "encodefiltervalue",
            "filterencode",
        }

    owner = _text(source, call.child_by_field_name("scope")).lower()
    if "ldap" not in owner:
        return False
    if owner.lstrip("\\").split("\\")[-1] in local_classes:
        return False
    return (name == "escape" and has_filter_flag) or name in {
        "escapefilterchars",
        "escapeldapfilter",
        "encodefiltervalue",
        "filterencode",
    }


def _php_filter_sanitized(
    source: bytes,
    node: Node,
    ldap_receivers: set[str],
    local_classes: set[str],
) -> bool:
    for call in _iter_nodes(node):
        if _php_call_is_filter_sanitizer(
            source, call, ldap_receivers, local_classes
        ):
            return True
    return False


def _php_unsanitized_vars(
    source: bytes,
    node: Node,
    ldap_receivers: set[str],
    local_classes: set[str],
) -> set[str]:
    if _php_call_is_filter_sanitizer(
        source, node, ldap_receivers, local_classes
    ):
        return set()
    if node.type == "variable_name":
        return {_text(source, node)}
    out: set[str] = set()
    for child in node.named_children:
        out.update(
            _php_unsanitized_vars(
                source, child, ldap_receivers, local_classes
            )
        )
    return out


def _php_looks_filter(source: bytes, node: Node) -> bool:
    value = _text(source, node)
    lowered = value.lower()
    if "str_replace" in lowered and ("[search]" in lowered or "filter" in lowered):
        return True
    if any(token in lowered for token in ("sprintf", "vsprintf", "format")):
        return "(" in value and "=" in value
    return "(" in value and "=" in value


def _php_sink_arg(
    source: bytes,
    call: Node,
    ldap_context: bool,
    ldap_receivers: set[str],
) -> Node | None:
    if not ldap_context:
        return None
    name = _php_call_name(source, call).lower()
    args = _php_args(call)
    if call.type == "member_call_expression" and name in ("simple_search", "search") and args:
        if _php_receiver_is_ldap(
            source, call.child_by_field_name("object"), ldap_receivers
        ):
            return args[0]
    if call.type == "scoped_call_expression" and name == "search" and args:
        owner = _text(source, call.child_by_field_name("scope")).lower()
        if "ldap" in owner:
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
    local_classes = _php_local_classes(src, root)
    scopes = [root]
    scopes.extend(n for n in _iter_nodes(root) if n.type in _PHP_SCOPES)
    results: list[dict] = []
    seen: set[tuple[int, int]] = set()

    for scope in scopes:
        nodes = list(_php_scope_nodes(scope))
        ldap_receivers = _php_ldap_receivers(src, scope)
        tainted = {
            name for name in _php_params(src, scope) if not _is_structural_parameter(name)
        }
        safe_names: set[str] = set()
        active_candidates: dict[str, list[Node]] = {}
        events = sorted(
            (
                node.end_byte if node.type == "assignment_expression" else node.start_byte,
                index,
                node,
            )
            for index, node in enumerate(nodes)
            if node.type
            in (
                "assignment_expression",
                "function_call_expression",
                "member_call_expression",
                "scoped_call_expression",
            )
        )

        for _, _, node in events:
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is None or right is None or left.type != "variable_name":
                    continue
                name = _text(src, left)
                unsanitized = _php_unsanitized_vars(
                    src, right, ldap_receivers, local_classes
                )
                value_tainted = bool((unsanitized - safe_names) & tainted)
                sanitized = _php_filter_sanitized(
                    src, right, ldap_receivers, local_classes
                ) and not value_tainted
                if sanitized:
                    safe_names.add(name)
                    tainted.discard(name)
                elif value_tainted:
                    tainted.add(name)
                    safe_names.discard(name)
                elif right.type in ("string", "integer", "float", "boolean", "null"):
                    tainted.discard(name)
                    safe_names.discard(name)

                alternatives = [
                    candidate
                    for candidate in active_candidates.get(name, [])
                    if _ts_mutually_exclusive(candidate, right)
                ]
                active_candidates[name] = alternatives
                if value_tainted and not sanitized and _php_looks_filter(src, right):
                    active_candidates[name].append(right)
                if not active_candidates[name]:
                    active_candidates.pop(name)
                continue

            call = node
            arg = _php_sink_arg(src, call, ldap_context, ldap_receivers)
            if arg is None:
                continue
            unsanitized = _php_unsanitized_vars(
                src, arg, ldap_receivers, local_classes
            )
            value_tainted = bool((unsanitized - safe_names) & tainted)
            if _php_filter_sanitized(
                src, arg, ldap_receivers, local_classes
            ) and not value_tainted:
                continue
            variables = _php_vars(src, arg)
            candidates = [
                candidate
                for name in variables
                for candidate in active_candidates.get(name, [])
                if not _ts_mutually_exclusive(candidate, call)
            ]
            if candidates:
                for right in candidates:
                    key = (right.start_point[0], right.start_point[1])
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append(
                        _result(
                            uri,
                            right.start_point[0] + 1,
                            right.start_point[1] + 1,
                            "LDAP injection (CWE-90): unescaped input constructs a filter used by an LDAP search",
                            cve,
                        )
                    )
                continue
            if not value_tainted or not _php_looks_filter(src, arg):
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
