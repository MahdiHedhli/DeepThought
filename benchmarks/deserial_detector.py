"""DT-DESERIAL -- static unsafe-deserialization detection (CWE-502).

The detector reads JavaScript, Python, and Java syntax trees and emits SARIF 2.1.0.
It never imports or executes target code.  The class rule is an untrusted/dynamic
serialized value reaching an execution or object-construction sink without a guard
that is bound to that sink:

* JavaScript: dynamic ``Function``/``eval``/``vm.runIn*`` code construction and
  provenance-backed unsafe YAML/serialization APIs;
* Python: dynamic input to pickle-family loaders or unsafe PyYAML loaders;
* Java: XStream ``fromXML`` without a receiver-bound deny-by-default permission,
  plus ``ObjectInputStream.readObject`` without a receiver-bound object filter.

The guard analysis is deliberately local and conservative.  It never treats a safe
call elsewhere in a file, a nested scope, a comment, or a similarly named overload as
hardening for the flagged sink.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
import warnings
from pathlib import Path

import tree_sitter_java as _tsjava
import tree_sitter_javascript as _tsjs
from tree_sitter import Language, Node, Parser

RULE_ID = "DT-DESERIAL"
GROUND_TRUTH_CWE = "CWE-502"

_JS_PARSER = Parser(Language(_tsjs.language()))
_JAVA_PARSER = Parser(Language(_tsjava.language()))


# --------------------------------------------------------------------------- #
# JavaScript
# --------------------------------------------------------------------------- #

_JS_FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
        "generator_function",
        "function",
    }
)
_JS_VM_SINKS = frozenset({"runInContext", "runInNewContext", "runInThisContext"})
_JS_CODE_SINKS = frozenset({"eval", "Function"}) | _JS_VM_SINKS
_SAFE_MODULE_MARKERS = ("sanit", "validat", "allowlist")


def _jstext(source: bytes, node: Node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _jsiter(node: Node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(current.children)


def _jsiter_scope(scope: Node):
    """Walk one JS scope, excluding every nested function and its body."""
    yield scope
    stack = list(scope.children)
    while stack:
        current = stack.pop()
        if current.type in _JS_FUNCTION_TYPES:
            continue
        yield current
        stack.extend(current.children)


def _js_enclosing_scope(node: Node, root: Node) -> Node:
    current = node.parent
    while current is not None:
        if current.type in _JS_FUNCTION_TYPES:
            return current
        current = current.parent
    return root


def _js_arguments(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    return [
        child
        for child in args.children
        if child.type not in ("(", ")", ",", "comment")
    ]


def _js_callee_parts(source: bytes, call: Node) -> tuple[str, str]:
    """Return ``(receiver, name)`` for a call/new expression."""
    function = call.child_by_field_name("function")
    if function is None:
        function = call.child_by_field_name("constructor")
    if function is None:
        return "", ""
    if function.type == "member_expression":
        obj = function.child_by_field_name("object")
        prop = function.child_by_field_name("property")
        return (
            _jstext(source, obj) if obj is not None else "",
            _jstext(source, prop) if prop is not None else "",
        )
    return "", _jstext(source, function)


def _js_is_dynamic(node: Node) -> bool:
    if node.type in ("string", "number", "true", "false", "null", "undefined"):
        return False
    if node.type == "template_string":
        return any(child.type == "template_substitution" for child in node.children)
    return True


def _js_identifiers(node: Node, source: bytes) -> set[str]:
    return {
        _jstext(source, child)
        for child in _jsiter(node)
        if child.type == "identifier"
    }


def _js_string_value(node: Node, source: bytes) -> str:
    return _jstext(source, node).strip("'\"`")


def _js_require_module(node: Node | None, source: bytes) -> str | None:
    if node is None or node.type != "call_expression":
        return None
    receiver, name = _js_callee_parts(source, node)
    args = _js_arguments(node)
    if receiver or name != "require" or not args or args[0].type != "string":
        return None
    return _js_string_value(args[0], source)


def _js_module_bindings(root: Node, source: bytes) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for node in _jsiter(root):
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            module = _js_require_module(node.child_by_field_name("value"), source)
            if name is not None and module:
                for identifier in _js_identifiers(name, source):
                    bindings[identifier] = module
        elif node.type == "import_statement":
            text = _jstext(source, node)
            match = re.search(r"\bfrom\s+['\"]([^'\"]+)['\"]", text)
            if match is None:
                match = re.search(r"\bimport\s+['\"]([^'\"]+)['\"]", text)
            if match is None:
                continue
            module = match.group(1)
            for identifier in _js_identifiers(node, source):
                if identifier not in {"from", "as"}:
                    bindings[identifier] = module
    return bindings


def _js_sanitizer_bindings(root: Node, source: bytes) -> set[str]:
    return {
        name
        for name, module in _js_module_bindings(root, source).items()
        if any(marker in module.lower() for marker in _SAFE_MODULE_MARKERS)
    }


def _js_call_is_bound_sanitizer(
    call: Node, source: bytes, sanitizer_bindings: set[str]
) -> bool:
    if call.type != "call_expression":
        return False
    receiver, name = _js_callee_parts(source, call)
    if not receiver:
        return name in sanitizer_bindings
    receiver_root = receiver.split(".", 1)[0]
    return receiver_root in sanitizer_bindings


def _js_contains_bound_sanitizer(
    node: Node, source: bytes, sanitizer_bindings: set[str]
) -> bool:
    return any(
        child.type == "call_expression"
        and _js_call_is_bound_sanitizer(child, source, sanitizer_bindings)
        for child in _jsiter(node)
    )


def _js_assignment_is_default_safe(
    assignment: Node, scope: Node, source: bytes
) -> bool:
    """Accept an unconditional assignment or the seed's default-safe ``!unsafe`` arm.

    Arbitrary conditionals do not dominate a later sink, and a sanitizer on an
    explicitly unsafe arm is not a guard.
    """
    current = assignment.parent
    while current is not None and current != scope:
        if current.type in _JS_FUNCTION_TYPES:
            return False
        if current.type == "if_statement":
            condition = current.child_by_field_name("condition")
            consequence = current.child_by_field_name("consequence")
            alternative = current.child_by_field_name("alternative")
            if condition is None:
                return False
            compact = re.sub(r"\s+|[()]", "", _jstext(source, condition))
            in_consequence = (
                consequence is not None
                and consequence.start_byte <= assignment.start_byte
                and assignment.end_byte <= consequence.end_byte
            )
            in_alternative = (
                alternative is not None
                and alternative.start_byte <= assignment.start_byte
                and assignment.end_byte <= alternative.end_byte
            )
            negative_unsafe = compact.startswith("!unsafe") or any(
                token in compact
                for token in ("unsafe===false", "unsafe==false", "false===unsafe", "false==unsafe")
            )
            positive_unsafe = compact in {"unsafe", "allowUnsafe"}
            return (in_consequence and negative_unsafe) or (
                in_alternative and positive_unsafe
            )
        if current.type in (
            "switch_statement",
            "for_statement",
            "for_in_statement",
            "while_statement",
            "do_statement",
            "ternary_expression",
        ):
            return False
        current = current.parent
    return current == scope


def _js_code_argument_is_hardened(
    sink: Node,
    argument: Node,
    root: Node,
    source: bytes,
    sanitizer_bindings: set[str],
) -> bool:
    if _js_contains_bound_sanitizer(argument, source, sanitizer_bindings):
        return True
    variables = _js_identifiers(argument, source)
    if not variables:
        return False
    scope = _js_enclosing_scope(sink, root)
    for node in _jsiter_scope(scope):
        if node.type != "assignment_expression" or node.start_byte >= sink.start_byte:
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None or left.type != "identifier":
            continue
        name = _jstext(source, left)
        if name not in variables or right.type != "call_expression":
            continue
        args = _js_arguments(right)
        if (
            _js_call_is_bound_sanitizer(right, source, sanitizer_bindings)
            and args
            and name in _js_identifiers(args[0], source)
            and _js_assignment_is_default_safe(node, scope, source)
        ):
            return True
    return False


def _js_sink_kind(
    node: Node, source: bytes, module_bindings: dict[str, str]
) -> str | None:
    if node.type == "new_expression":
        receiver, name = _js_callee_parts(source, node)
        if name.split(".")[-1] != "Function":
            return None
        if receiver and receiver.split(".", 1)[0] not in {"global", "globalThis", "window"}:
            return None
        return "new Function"
    if node.type != "call_expression":
        return None
    receiver, name = _js_callee_parts(source, node)
    receiver_root = receiver.split(".", 1)[0]
    if name in {"eval", "Function"} and (
        not receiver or receiver_root in {"global", "globalThis", "window"}
    ):
        return name
    if name in _JS_VM_SINKS:
        binding = module_bindings.get(receiver_root if receiver else name, "")
        if binding in {"vm", "node:vm"}:
            return name
    module = module_bindings.get(receiver_root, "")
    if name == "load" and (
        receiver.split(".")[-1].lower() in {"yaml", "jsyaml"}
        or "yaml" in module.lower()
    ):
        return "yaml.load"
    if name in {"deserialize", "unserialize"} and receiver and (
        "serializ" in module.lower()
        or receiver.split(".")[-1].lower() in {"serializer", "nodeserialize"}
    ):
        return name
    return None


def scan_js(source: str, uri: str, cve: str | None = None) -> list[dict]:
    raw = source.encode("utf-8")
    root = _JS_PARSER.parse(raw).root_node
    modules = _js_module_bindings(root, raw)
    sanitizers = _js_sanitizer_bindings(root, raw)
    results: list[dict] = []
    for node in _jsiter(root):
        kind = _js_sink_kind(node, raw, modules)
        if kind is None:
            continue
        args = _js_arguments(node)
        if not args or not _js_is_dynamic(args[0]):
            continue
        if kind in _JS_CODE_SINKS | {"new Function"} and _js_code_argument_is_hardened(
            node, args[0], root, raw, sanitizers
        ):
            continue
        results.append(
            _result(
                uri,
                node.start_point[0] + 1,
                node.start_point[1] + 1,
                f"unsafe deserialization (CWE-502): dynamic input reaches {kind} without a sink-bound guard",
                cve,
            )
        )
    return results


# --------------------------------------------------------------------------- #
# Python
# --------------------------------------------------------------------------- #

_PY_PICKLE_MODULES = frozenset(
    {"pickle", "cPickle", "dill", "cloudpickle", "joblib"}
)
_PY_SAFE_YAML_LOADERS = frozenset({"SafeLoader", "CSafeLoader", "BaseLoader"})


def _py_ast_parse(source: str) -> ast.AST:
    # Old corpora often contain escapes accepted historically but warned on by a
    # current interpreter.  Scanner diagnostics must be SARIF results, not parser noise.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(source)


def _py_parse_compat(source: str) -> ast.AST | None:
    """Parse current Python, then retry legacy ``async`` identifiers statically.

    Python 2/early-3 corpora can use ``async`` as an ordinary variable.  Python 3.14
    rejects the whole file, hiding otherwise valid calls from ``ast``.  The fallback
    rewrites only NAME tokens used outside ``async def/for/with`` to an equal-length
    placeholder, preserving line/column locations.  It does not execute or translate
    target code.
    """
    try:
        return _py_ast_parse(source)
    except SyntaxError:
        pass
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (IndentationError, tokenize.TokenError):
        return None
    significant = [
        index
        for index, token in enumerate(tokens)
        if token.type not in {tokenize.ENCODING, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT}
    ]
    next_significant: dict[int, tokenize.TokenInfo | None] = {}
    for position, index in enumerate(significant):
        next_significant[index] = (
            tokens[significant[position + 1]] if position + 1 < len(significant) else None
        )
    changed = False
    rewritten: list[tokenize.TokenInfo] = []
    for index, token in enumerate(tokens):
        replacement = token
        if token.type == tokenize.NAME and token.string == "async":
            following = next_significant.get(index)
            if following is None or following.string not in {"def", "for", "with"}:
                replacement = token._replace(string="_sync")
                changed = True
        rewritten.append(replacement)
    if not changed:
        return None
    try:
        return _py_ast_parse(tokenize.untokenize(rewritten))
    except SyntaxError:
        return None


def _py_scope_nodes(scope: ast.AST):
    """Walk one Python scope without importing facts from nested functions/classes."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _py_smallest_function(tree: ast.AST, node: ast.AST) -> ast.AST | None:
    matches = [
        candidate
        for candidate in ast.walk(tree)
        if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        and getattr(candidate, "lineno", 0) <= getattr(node, "lineno", 0)
        <= (getattr(candidate, "end_lineno", None) or getattr(candidate, "lineno", 0))
    ]
    return max(matches, key=lambda candidate: getattr(candidate, "lineno", 0), default=None)


def _py_add_import_binding(node: ast.AST, bindings: dict[str, str]) -> None:
    if isinstance(node, ast.Import):
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            bindings[local] = alias.name
    elif isinstance(node, ast.ImportFrom) and node.module:
        for alias in node.names:
            if alias.name == "*":
                continue
            bindings[alias.asname or alias.name] = f"{node.module}.{alias.name}"


def _py_bindings(tree: ast.AST, call: ast.Call) -> dict[str, str]:
    """Imports visible to this call: module scope plus its smallest function only."""
    bindings: dict[str, str] = {}
    for node in _py_scope_nodes(tree):
        if getattr(node, "lineno", 0) <= call.lineno:
            _py_add_import_binding(node, bindings)
    function = _py_smallest_function(tree, call)
    if function is not None:
        for node in _py_scope_nodes(function):
            if getattr(node, "lineno", 0) <= call.lineno:
                _py_add_import_binding(node, bindings)
    return bindings


def _py_dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _py_dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _py_resolve_call(call: ast.Call, bindings: dict[str, str]) -> str:
    dotted = _py_dotted(call.func)
    if not dotted:
        return ""
    first, *rest = dotted.split(".")
    resolved = bindings.get(first, first)
    return ".".join([resolved, *rest]) if rest else resolved


def _py_dynamic_argument(call: ast.Call) -> bool:
    return bool(call.args) and not isinstance(call.args[0], ast.Constant)


def _py_yaml_loader_is_safe(call: ast.Call) -> bool:
    loader: ast.AST | None = None
    for keyword in call.keywords:
        if keyword.arg and keyword.arg.lower() == "loader":
            loader = keyword.value
            break
    if loader is None and len(call.args) >= 2:
        loader = call.args[1]
    if loader is None:
        return False
    return _py_dotted(loader).split(".")[-1] in _PY_SAFE_YAML_LOADERS


def _py_sink_kind(call: ast.Call, bindings: dict[str, str]) -> str | None:
    resolved = _py_resolve_call(call, bindings)
    if "." not in resolved:
        return None
    module, name = resolved.rsplit(".", 1)
    if name in {"load", "loads"} and any(
        module == candidate or module.startswith(candidate + ".")
        for candidate in _PY_PICKLE_MODULES
    ):
        return f"{module}.{name}"
    is_yaml = module == "yaml" or module.startswith("yaml.") or "ruamel.yaml" in module
    if is_yaml and name == "unsafe_load":
        return f"{module}.{name}"
    if is_yaml and name == "load" and not _py_yaml_loader_is_safe(call):
        return f"{module}.{name}"
    return None


def scan_python(source: str, uri: str, cve: str | None = None) -> list[dict]:
    tree = _py_parse_compat(source)
    if tree is None:
        return []
    results: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _py_dynamic_argument(node):
            continue
        bindings = _py_bindings(tree, node)
        kind = _py_sink_kind(node, bindings)
        if kind is None:
            continue
        results.append(
            _result(
                uri,
                node.lineno,
                node.col_offset + 1,
                f"unsafe deserialization (CWE-502): dynamic input reaches {kind} without a safe loader",
                cve,
            )
        )
    return results


# --------------------------------------------------------------------------- #
# Java
# --------------------------------------------------------------------------- #

_JAVA_TYPE_NODES = frozenset(
    {
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "annotation_type_declaration",
        "record_declaration",
    }
)
_JAVA_CONTROL_NODES = frozenset(
    {
        "if_statement",
        "switch_expression",
        "switch_block_statement_group",
        "for_statement",
        "enhanced_for_statement",
        "while_statement",
        "do_statement",
        "lambda_expression",
        "catch_clause",
        "conditional_expression",
    }
)


def _javatext(source: bytes, node: Node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _javaiter(node: Node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(current.children)


def _javaiter_method(method: Node):
    """Walk a Java method without entering nested/anonymous types or lambdas."""
    yield method
    stack = list(method.children)
    while stack:
        current = stack.pop()
        if current.type in _JAVA_TYPE_NODES or current.type == "lambda_expression":
            continue
        yield current
        stack.extend(current.children)


def _java_enclosing(node: Node, types: frozenset[str]) -> Node | None:
    current = node.parent
    while current is not None:
        if current.type in types:
            return current
        current = current.parent
    return None


def _java_enclosing_method(node: Node) -> Node | None:
    return _java_enclosing(node, frozenset({"method_declaration", "constructor_declaration"}))


def _java_enclosing_type(node: Node) -> Node | None:
    return _java_enclosing(node, _JAVA_TYPE_NODES)


def _java_args(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    return [child for child in args.named_children if child.type != "comment"]


def _java_invocation_parts(source: bytes, call: Node) -> tuple[str, str]:
    if call.type != "method_invocation":
        return "", ""
    obj = call.child_by_field_name("object")
    name = call.child_by_field_name("name")
    return (
        _javatext(source, obj) if obj is not None else "",
        _javatext(source, name) if name is not None else "",
    )


def _java_method_name(source: bytes, method: Node) -> str:
    name = method.child_by_field_name("name")
    return _javatext(source, name) if name is not None else ""


def _java_parameter_count(method: Node) -> int:
    params = method.child_by_field_name("parameters")
    if params is None:
        return 0
    return sum(
        child.type in {"formal_parameter", "spread_parameter", "receiver_parameter"}
        for child in params.named_children
    )


def _same_node(left: Node | None, right: Node | None) -> bool:
    return bool(
        left is not None
        and right is not None
        and left.start_byte == right.start_byte
        and left.end_byte == right.end_byte
        and left.type == right.type
    )


def _java_methods_in_type(type_node: Node) -> list[Node]:
    methods: list[Node] = []
    for node in _javaiter(type_node):
        if node.type != "method_declaration":
            continue
        if _same_node(_java_enclosing_type(node), type_node):
            methods.append(node)
    return methods


def _java_initializer(
    method: Node, receiver: str, before_byte: int, source: bytes
) -> tuple[Node | None, str]:
    best: tuple[Node | None, str, int] = (None, "", -1)
    for node in _javaiter_method(method):
        if node.start_byte >= before_byte:
            continue
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is None or _javatext(source, name) != receiver:
                continue
            declaration = node.parent
            type_node = declaration.child_by_field_name("type") if declaration else None
            declared_type = _javatext(source, type_node) if type_node is not None else ""
            if node.start_byte > best[2]:
                best = (value, declared_type, node.start_byte)
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and _javatext(source, left) == receiver and node.start_byte > best[2]:
                best = (right, "", node.start_byte)
    return best[0], best[1]


def _java_parameter_type(method: Node, receiver: str, source: bytes) -> str:
    parameters = method.child_by_field_name("parameters")
    if parameters is None:
        return ""
    for parameter in parameters.named_children:
        if parameter.type not in {"formal_parameter", "spread_parameter", "receiver_parameter"}:
            continue
        name = parameter.child_by_field_name("name")
        type_node = parameter.child_by_field_name("type")
        if name is not None and type_node is not None and _javatext(source, name) == receiver:
            return _javatext(source, type_node)
    return ""


def _java_call_is_unconditional(call: Node, method: Node) -> bool:
    current = call.parent
    while current is not None and not _same_node(current, method):
        if current.type in _JAVA_CONTROL_NODES:
            return False
        current = current.parent
    return current is not None


def _java_xstream_permission_call(
    call: Node, receiver: str, source: bytes
) -> bool:
    obj, name = _java_invocation_parts(source, call)
    if name != "addPermission" or obj != receiver:
        return False
    args = _java_args(call)
    return len(args) == 1 and re.sub(r"\s+", "", _javatext(source, args[0])) == "NoTypePermission.NONE"


def _java_receiver_hardened_before(
    method: Node, receiver: str, sink: Node, source: bytes, kind: str
) -> bool:
    for call in _javaiter_method(method):
        if call.type != "method_invocation" or call.start_byte >= sink.start_byte:
            continue
        if not _java_call_is_unconditional(call, method):
            continue
        if kind == "xstream" and _java_xstream_permission_call(call, receiver, source):
            return True
        if kind == "object-input":
            obj, name = _java_invocation_parts(source, call)
            args = _java_args(call)
            if obj == receiver and name == "setObjectInputFilter" and args:
                argument = re.sub(r"[\s()]", "", _javatext(source, args[0]))
                if argument != "null":
                    return True
    return False


def _java_return_identifier(return_node: Node, source: bytes) -> str | None:
    identifiers = [
        _javatext(source, node)
        for node in _javaiter(return_node)
        if node.type == "identifier"
    ]
    return identifiers[0] if len(identifiers) == 1 else None


def _java_factory_is_hardened(method: Node, source: bytes) -> bool:
    returns = [node for node in _javaiter_method(method) if node.type == "return_statement"]
    if not returns:
        return False
    returned = {_java_return_identifier(node, source) for node in returns}
    if None in returned or len(returned) != 1:
        return False
    receiver = next(iter(returned))
    for call in _javaiter_method(method):
        if call.type != "method_invocation":
            continue
        if not _java_xstream_permission_call(call, receiver, source):
            continue
        if not _java_call_is_unconditional(call, method):
            continue
        if all(call.start_byte < ret.start_byte for ret in returns):
            return True
    return False


def _java_resolve_factory(
    sink: Node, initializer: Node, source: bytes
) -> Node | None:
    if initializer.type != "method_invocation":
        return None
    _obj, name = _java_invocation_parts(source, initializer)
    argc = len(_java_args(initializer))
    enclosing_type = _java_enclosing_type(sink)
    if enclosing_type is None:
        return None
    candidates = [
        method
        for method in _java_methods_in_type(enclosing_type)
        if _java_method_name(source, method) == name
        and _java_parameter_count(method) == argc
        and (
            (return_type := method.child_by_field_name("type")) is None
            or _javatext(source, return_type).split(".")[-1] == "XStream"
        )
    ]
    return candidates[0] if len(candidates) == 1 else None


def _java_has_import(root: Node, source: bytes, suffix: str) -> bool:
    return any(
        node.type == "import_declaration" and suffix in _javatext(source, node)
        for node in _javaiter(root)
    )


def _java_object_creation_type(node: Node | None, source: bytes) -> str:
    if node is None or node.type != "object_creation_expression":
        return ""
    type_node = node.child_by_field_name("type")
    return _javatext(source, type_node).split(".")[-1] if type_node is not None else ""


def _java_xstream_provenance(
    sink: Node, receiver: str, root: Node, source: bytes
) -> tuple[bool, Node | None, str]:
    method = _java_enclosing_method(sink)
    if method is None:
        return False, None, ""
    if receiver.startswith("new XStream"):
        return True, None, "XStream"
    initializer, declared_type = _java_initializer(method, receiver, sink.start_byte, source)
    if declared_type.split(".")[-1] == "XStream" or _java_object_creation_type(initializer, source) == "XStream":
        return True, initializer, declared_type
    if initializer is not None and initializer.type == "method_invocation":
        factory = _java_resolve_factory(sink, initializer, source)
        if factory is not None:
            return True, initializer, "XStream"
    # A field receiver may not have a local declaration.  A real XStream import is
    # sufficient provenance, but an arbitrary method named fromXML is not.
    if _java_has_import(root, source, "com.thoughtworks.xstream.XStream"):
        return True, initializer, declared_type
    return False, initializer, declared_type


def _java_ois_provenance(
    sink: Node, receiver: str, root: Node, source: bytes
) -> bool:
    method = _java_enclosing_method(sink)
    if method is None:
        return False
    initializer, declared_type = _java_initializer(method, receiver, sink.start_byte, source)
    parameter_type = _java_parameter_type(method, receiver, source)
    if declared_type.split(".")[-1] == "ObjectInputStream":
        return True
    if parameter_type.split(".")[-1] == "ObjectInputStream":
        return True
    if _java_object_creation_type(initializer, source) == "ObjectInputStream":
        return True
    return receiver.startswith("new ObjectInputStream") and _java_has_import(
        root, source, "java.io.ObjectInputStream"
    )


def scan_java(source: str, uri: str, cve: str | None = None) -> list[dict]:
    raw = source.encode("utf-8")
    root = _JAVA_PARSER.parse(raw).root_node
    results: list[dict] = []
    for node in _javaiter(root):
        if node.type != "method_invocation":
            continue
        receiver, name = _java_invocation_parts(raw, node)
        method = _java_enclosing_method(node)
        if not receiver or method is None:
            continue
        if name == "fromXML":
            proven, initializer, _declared_type = _java_xstream_provenance(
                node, receiver, root, raw
            )
            if not proven:
                continue
            if _java_receiver_hardened_before(method, receiver, node, raw, "xstream"):
                continue
            factory = _java_resolve_factory(node, initializer, raw) if initializer else None
            if factory is not None and _java_factory_is_hardened(factory, raw):
                continue
            kind = "XStream.fromXML"
        elif name == "readObject" and _java_ois_provenance(node, receiver, root, raw):
            if _java_receiver_hardened_before(method, receiver, node, raw, "object-input"):
                continue
            kind = "ObjectInputStream.readObject"
        else:
            continue
        results.append(
            _result(
                uri,
                node.start_point[0] + 1,
                node.start_point[1] + 1,
                f"unsafe deserialization (CWE-502): {kind} lacks a receiver-bound deny-by-default guard",
                cve,
            )
        )
    return results


# --------------------------------------------------------------------------- #
# Shared SARIF
# --------------------------------------------------------------------------- #


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


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    lower = uri.lower()
    if lower.endswith(".py"):
        return scan_python(source, uri, cve)
    if lower.endswith(".java"):
        return scan_java(source, uri, cve)
    return scan_js(source, uri, cve)


def scan_file(path: str | Path, uri: str | None = None, cve: str | None = None) -> dict:
    file = Path(path)
    artifact_uri = uri or file.name
    results = scan_source(file.read_text(encoding="utf-8"), artifact_uri, cve)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deepthought-deserialization-rule",
                        "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                        "rules": [
                            {
                                "id": RULE_ID,
                                "name": "UnsafeDeserialization",
                                "shortDescription": {
                                    "text": "Dynamic input reaches an unsafe deserialization sink (CWE-502)"
                                },
                                "defaultConfiguration": {"level": "error"},
                                "helpUri": "https://cwe.mitre.org/data/definitions/502.html",
                                "properties": {
                                    "cwe": GROUND_TRUTH_CWE,
                                    "tags": ["security", "CWE-502", "deserialization"],
                                },
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
