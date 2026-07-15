"""DT-SQLI-QUERY -- static SQL-injection detection for Python, PHP, and Velocity.

The rule reports untrusted data that becomes SQL/HQL syntax instead of a separately
bound value (CWE-89).  It is deliberately intraprocedural and syntax-only: Python is
parsed with :mod:`ast`, PHP with tree-sitter, and the small Velocity backend recognizes
directives without evaluating a template.  Target code is never imported or executed.

Guards are bound to the value they protect.  A parameter collection protects a constant
query at that call site; ``db_qstr($filter)`` protects that expression.  A sanitizer name
elsewhere in the function does not bless an unrelated query.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable

import tree_sitter_php as _tsphp
from tree_sitter import Language, Node, Parser

RULE_ID = "DT-SQLI-QUERY"
GROUND_TRUTH_CWE = "CWE-89"

_PHP = Language(_tsphp.language_php())
_PHP_PARSER = Parser(_PHP)

_SQL_TEXT = re.compile(
    r"\b(?:select|insert|update|delete|replace|merge|from|where|having|join|like|order\s+by)\b",
    re.IGNORECASE,
)

Point = tuple[int, int]


@dataclass(frozen=True)
class _Flow:
    """Minimal value-flow facts needed by the rule.

    ``tainted`` records that an untrusted value is present. ``unsafe`` records that at
    least one such value is still syntax-bearing rather than bound/quoted/coerced.
    ``constructions`` identifies SQL-fragment construction sites so builder functions
    can report the dangerous line rather than their later return statement.
    """

    sqlish: bool = False
    tainted: bool = False
    unsafe: bool = False
    constructions: tuple[Point, ...] = ()


_EMPTY = _Flow()


def _dedupe_points(points: Iterable[Point]) -> tuple[Point, ...]:
    return tuple(dict.fromkeys(points))


def _merge(*flows: _Flow) -> _Flow:
    return _Flow(
        sqlish=any(f.sqlish for f in flows),
        tainted=any(f.tainted for f in flows),
        unsafe=any(f.unsafe for f in flows),
        constructions=_dedupe_points(p for f in flows for p in f.constructions),
    )


def _literal(text: str) -> _Flow:
    return _Flow(sqlish=bool(_SQL_TEXT.search(text)))


def _source() -> _Flow:
    return _Flow(tainted=True, unsafe=True)


def _sanitized(flow: _Flow) -> _Flow:
    return _Flow(sqlish=flow.sqlish, tainted=flow.tainted, unsafe=False)


def _constructed(flow: _Flow, point: Point) -> _Flow:
    if not (flow.sqlish and flow.unsafe):
        return flow
    return replace(flow, constructions=_dedupe_points((*flow.constructions, point)))


# ---------------------------------------------------------------------------
# Python AST backend
# ---------------------------------------------------------------------------

_PY_SINKS = frozenset({"execute", "executemany", "executescript", "raw"})
_PY_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_PY_REQUEST = re.compile(
    r"(?:\brequest\.(?:GET|POST|args|form|json|values|query_params)\b|"
    r"\b(?:GET|POST|REQUEST)\s*\[)",
    re.IGNORECASE,
)
_PY_PRESERVING_CALLS = frozenset(
    {"lower", "upper", "strip", "lstrip", "rstrip", "replace", "casefold", "join"}
)
_PY_NUMERIC_CALLS = frozenset({"int", "float"})


def _py_segment(source: str, node: ast.AST) -> str:
    return ast.get_source_segment(source, node) or ""


def _py_call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return ""


def _py_eval(node: ast.AST | None, env: dict[str, _Flow], source: str) -> _Flow:
    if node is None:
        return _EMPTY
    if isinstance(node, ast.Constant):
        return _literal(node.value) if isinstance(node.value, str) else _EMPTY
    if isinstance(node, ast.Name):
        return env.get(node.id, _EMPTY)
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        text = _py_segment(source, node)
        if _PY_REQUEST.search(text):
            return _source()
        base = node.value if isinstance(node, (ast.Attribute, ast.Subscript)) else None
        return _py_eval(base, env, source)
    if isinstance(node, ast.JoinedStr):
        pieces: list[_Flow] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                pieces.append(_literal(value.value))
            elif isinstance(value, ast.FormattedValue):
                pieces.append(_py_eval(value.value, env, source))
        return _merge(*pieces)
    if isinstance(node, ast.BinOp):
        return _merge(_py_eval(node.left, env, source), _py_eval(node.right, env, source))
    if isinstance(node, ast.Call):
        text = _py_segment(source, node)
        if _PY_REQUEST.search(text):
            return _source()
        name = _py_call_name(node)
        args = [_py_eval(a, env, source) for a in node.args]
        args.extend(_py_eval(k.value, env, source) for k in node.keywords)
        receiver = _py_eval(node.func.value, env, source) if isinstance(node.func, ast.Attribute) else _EMPTY
        combined = _merge(receiver, *args)
        if name in _PY_NUMERIC_CALLS:
            return _sanitized(combined)
        if name == "format" or name in _PY_PRESERVING_CALLS:
            return combined
        return combined
    if isinstance(node, ast.Dict):
        return _merge(*(_py_eval(n, env, source) for n in (*node.keys, *node.values) if n is not None))
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return _merge(*(_py_eval(n, env, source) for n in node.elts))
    if isinstance(node, ast.UnaryOp):
        return _py_eval(node.operand, env, source)
    if isinstance(node, ast.BoolOp):
        return _merge(*(_py_eval(n, env, source) for n in node.values))
    if isinstance(node, ast.IfExp):
        return _merge(_py_eval(node.body, env, source), _py_eval(node.orelse, env, source))
    if isinstance(node, ast.Compare):
        return _merge(_py_eval(node.left, env, source), *(_py_eval(n, env, source) for n in node.comparators))
    return _EMPTY


def _py_scope_nodes(scope: ast.AST) -> list[ast.AST]:
    """All nodes in one lexical scope, excluding nested function bodies."""
    out: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        if isinstance(node, _PY_FUNCTIONS):
            continue
        out.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return out


def _py_target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for elt in node.elts for name in _py_target_names(elt)]
    return []


def _py_conditional(node: ast.AST, parents: dict[ast.AST, ast.AST], scope: ast.AST) -> bool:
    cur = parents.get(node)
    while cur is not None and cur is not scope:
        if isinstance(cur, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.Match)):
            return True
        cur = parents.get(cur)
    return False


def _scan_python_scope(scope: ast.AST, source: str, results: list[dict], uri: str, cve: str | None) -> None:
    env: dict[str, _Flow] = {}
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        arguments = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
        if scope.args.vararg:
            arguments.append(scope.args.vararg)
        if scope.args.kwarg:
            arguments.append(scope.args.kwarg)
        env.update({arg.arg: _source() for arg in arguments})

    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(scope):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    nodes = _py_scope_nodes(scope)

    def priority(node: ast.AST) -> int:
        return 0 if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) else 1

    nodes.sort(key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0), priority(n)))
    seen: set[Point] = set()
    for node in nodes:
        if isinstance(node, ast.Assign):
            flow = _py_eval(node.value, env, source)
            flow = _constructed(flow, (node.lineno, node.col_offset + 1))
            for target in node.targets:
                for name in _py_target_names(target):
                    env[name] = _merge(env.get(name, _EMPTY), flow) if _py_conditional(node, parents, scope) else flow
        elif isinstance(node, ast.AnnAssign):
            flow = _py_eval(node.value, env, source)
            flow = _constructed(flow, (node.lineno, node.col_offset + 1))
            for name in _py_target_names(node.target):
                env[name] = _merge(env.get(name, _EMPTY), flow) if _py_conditional(node, parents, scope) else flow
        elif isinstance(node, ast.NamedExpr):
            flow = _constructed(_py_eval(node.value, env, source), (node.lineno, node.col_offset + 1))
            for name in _py_target_names(node.target):
                env[name] = flow
        elif isinstance(node, ast.AugAssign):
            flow = _merge(_py_eval(node.target, env, source), _py_eval(node.value, env, source))
            flow = _constructed(flow, (node.lineno, node.col_offset + 1))
            for name in _py_target_names(node.target):
                env[name] = flow
        elif isinstance(node, ast.Call) and _py_call_name(node) in _PY_SINKS and node.args:
            query = _py_eval(node.args[0], env, source)
            if not query.unsafe:
                continue
            point = (node.lineno, node.col_offset + 1)
            if point in seen:
                continue
            seen.add(point)
            results.append(
                _result(
                    uri,
                    *point,
                    "SQL injection (CWE-89): untrusted data reaches a database query as SQL syntax instead of a bound parameter",
                    cve,
                )
            )


def scan_python(source: str, uri: str, cve: str | None = None) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    results: list[dict] = []
    _scan_python_scope(tree, source, results, uri, cve)
    for node in ast.walk(tree):
        if isinstance(node, _PY_FUNCTIONS):
            _scan_python_scope(node, source, results, uri, cve)
    return results


# ---------------------------------------------------------------------------
# PHP tree-sitter backend
# ---------------------------------------------------------------------------

_PHP_SCOPE_TYPES = frozenset({"function_definition", "method_declaration", "anonymous_function", "arrow_function"})
_PHP_MEMBER_SINKS = frozenset({"query", "exec", "execute", "rawquery"})
_PHP_FUNCTION_SINKS = frozenset(
    {
        "mysqli_query", "pg_query", "db_query", "db_execute", "db_fetch_assoc",
        "db_fetch_row", "db_fetch_cell", "db_fetch_object", "mysql_query",
    }
)
_PHP_QUOTERS = frozenset(
    {"db_qstr", "quote", "escape", "real_escape_string", "mysqli_real_escape_string", "pg_escape_literal"}
)
_PHP_NUMERIC = frozenset({"intval", "floatval"})
_PHP_SOURCES = frozenset({"get_request_var", "filter_input"})
_PHP_SUPERGLOBALS = ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE")
_PHP_CONDITIONALS = frozenset(
    {"if_statement", "switch_statement", "foreach_statement", "for_statement", "while_statement", "try_statement"}
)


def _pt(src: bytes, node: Node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _piter(node: Node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _piter_scope(scope: Node):
    stack = list(reversed(scope.children))
    while stack:
        current = stack.pop()
        if current.type in _PHP_SCOPE_TYPES:
            continue
        yield current
        stack.extend(reversed(current.children))


def _php_call_name(src: bytes, node: Node) -> str:
    if node.type == "function_call_expression":
        function = node.child_by_field_name("function")
        return _pt(src, function).split("\\")[-1].lower() if function is not None else ""
    if node.type in ("member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression"):
        name = node.child_by_field_name("name")
        return _pt(src, name).lower() if name is not None else ""
    return ""


def _php_arguments(node: Node) -> list[Node]:
    args = node.child_by_field_name("arguments")
    return list(args.named_children) if args is not None else []


def _php_eval(node: Node | None, env: dict[str, _Flow], src: bytes) -> _Flow:
    if node is None:
        return _EMPTY
    text = _pt(src, node)
    if any(marker in text for marker in _PHP_SUPERGLOBALS):
        return _source()
    if node.type == "variable_name":
        return env.get(text, _EMPTY)
    if node.type in ("string", "encapsed_string", "heredoc", "nowdoc", "string_content"):
        children = [_php_eval(child, env, src) for child in node.named_children]
        return _merge(_literal(text), *children)
    if node.type == "binary_expression":
        return _merge(
            _php_eval(node.child_by_field_name("left"), env, src),
            _php_eval(node.child_by_field_name("right"), env, src),
        )
    if node.type == "cast_expression":
        value = _php_eval(node.child_by_field_name("value"), env, src)
        cast_type = node.child_by_field_name("type")
        if cast_type is not None and _pt(src, cast_type).lower() in {"int", "integer", "float", "double", "bool", "boolean"}:
            return _sanitized(value)
        return value
    if node.type in ("function_call_expression", "member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression"):
        name = _php_call_name(src, node)
        combined = _merge(*(_php_eval(arg, env, src) for arg in _php_arguments(node)))
        if name in _PHP_SOURCES:
            return _source()
        if name in _PHP_QUOTERS or name in _PHP_NUMERIC:
            return _sanitized(combined)
        return combined
    if node.type in ("parenthesized_expression", "argument"):
        return _merge(*(_php_eval(child, env, src) for child in node.named_children))
    return _merge(*(_php_eval(child, env, src) for child in node.named_children))


def _php_conditional(node: Node, scope: Node) -> bool:
    current = node.parent
    while current is not None and current != scope:
        if current.type in _PHP_CONDITIONALS:
            return True
        current = current.parent
    return False


def _php_query_argument(src: bytes, node: Node) -> Node | None:
    name = _php_call_name(src, node)
    if "prepared" in name or name in {"prepare", "bindparam", "bindvalue"}:
        return None
    args = _php_arguments(node)
    if node.type in ("member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression"):
        return args[0] if name in _PHP_MEMBER_SINKS and args else None
    if name not in _PHP_FUNCTION_SINKS or not args:
        return None
    if name in {"mysqli_query", "mysql_query"}:
        return args[1] if len(args) > 1 else None
    if name == "pg_query" and len(args) > 1:
        return args[1]
    return args[0]


def _scan_php_scope(scope: Node, src: bytes, uri: str, cve: str | None, results: list[dict]) -> None:
    env: dict[str, _Flow] = {}
    params = scope.child_by_field_name("parameters")
    if params is not None:
        for node in _piter(params):
            if node.type == "variable_name":
                env[_pt(src, node)] = _source()

    interesting = [
        node
        for node in _piter_scope(scope)
        if node.type
        in {
            "assignment_expression", "augmented_assignment_expression", "member_call_expression",
            "nullsafe_member_call_expression", "scoped_call_expression", "function_call_expression", "return_statement",
        }
    ]

    def priority(node: Node) -> int:
        return 0 if node.type in {"assignment_expression", "augmented_assignment_expression"} else 1

    interesting.sort(key=lambda n: (n.start_byte, priority(n), n.end_byte))
    seen: set[Point] = set()
    for node in interesting:
        if node.type in {"assignment_expression", "augmented_assignment_expression"}:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None or left.type != "variable_name":
                continue
            name = _pt(src, left)
            right_flow = _php_eval(right, env, src)
            flow = right_flow
            introduces_unsafe = right_flow.unsafe
            if node.type == "augmented_assignment_expression":
                operator = node.child_by_field_name("operator")
                if operator is not None and _pt(src, operator) == ".=":
                    flow = _merge(env.get(name, _EMPTY), flow)
            point = (node.start_point[0] + 1, node.start_point[1] + 1)
            # Preserve the line where unsafe input first entered the SQL fragment.
            # A later constant suffix (for example, a closing parenthesis) must not
            # steal attribution merely because the accumulated variable is tainted.
            if node.type != "augmented_assignment_expression" or introduces_unsafe:
                flow = _constructed(flow, point)
            env[name] = _merge(env.get(name, _EMPTY), flow) if _php_conditional(node, scope) else flow
            continue

        if node.type == "return_statement":
            expressions = list(node.named_children)
            returned_node = expressions[-1] if expressions else None
            # A returned query call is already reported at the sink.  Builder functions
            # such as Cacti's return a SQL-fragment variable instead; only those need an
            # origin-line finding here.
            if returned_node is not None and _php_query_argument(src, returned_node) is not None:
                continue
            returned = _php_eval(returned_node, env, src)
            if returned.sqlish and returned.unsafe and returned.constructions:
                point = returned.constructions[-1]
                if point not in seen:
                    seen.add(point)
                    results.append(
                        _result(
                            uri,
                            *point,
                            "SQL injection (CWE-89): a returned SQL fragment contains an unquoted untrusted value",
                            cve,
                        )
                    )
            continue

        query_node = _php_query_argument(src, node)
        if query_node is None:
            continue
        query = _php_eval(query_node, env, src)
        if not query.unsafe:
            continue
        point = (node.start_point[0] + 1, node.start_point[1] + 1)
        if point in seen:
            continue
        seen.add(point)
        results.append(
            _result(
                uri,
                *point,
                "SQL injection (CWE-89): untrusted data is concatenated into a database query",
                cve,
            )
        )


def scan_php(source: str, uri: str, cve: str | None = None) -> list[dict]:
    src = source.encode("utf-8")
    root = _PHP_PARSER.parse(src).root_node
    results: list[dict] = []
    _scan_php_scope(root, src, uri, cve, results)
    for node in _piter(root):
        if node.type in _PHP_SCOPE_TYPES:
            _scan_php_scope(node, src, uri, cve, results)
    return results


# ---------------------------------------------------------------------------
# Velocity directive backend
# ---------------------------------------------------------------------------

_VELOCITY_SET = re.compile(r"^\s*#set\s*\(\s*\$([A-Za-z_][\w]*)\s*=\s*(.*)\)\s*$")
_VELOCITY_VAR = re.compile(r"\$!?\{?([A-Za-z_][\w]*)")
_VELOCITY_REQUEST = re.compile(r"\$!?\{?request(?:\b|[.}])", re.IGNORECASE)


def _blank_velocity_block_comment(match: re.Match[str]) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group(0))


def _velocity_eval(text: str, env: dict[str, _Flow]) -> _Flow:
    flows = [_literal(text)]
    for name in _VELOCITY_VAR.findall(text):
        flows.append(env.get(name, _EMPTY))
    if _VELOCITY_REQUEST.search(text):
        flows.append(_source())
    return _merge(*flows)


def _velocity_literal_value(text: str) -> bool:
    stripped = text.strip()
    return (
        len(stripped) >= 2
        and stripped[0] == stripped[-1]
        and stripped[0] in {"'", '"'}
        and "$" not in stripped
    )


def _velocity_finite_normalization(condition: str, name: str, assigned_value: str) -> bool:
    """Recognize a finite literal allowlist expressed as an if/assignment.

    Example: ``#if ("$!dir" != '' && "$!dir" != 'asc')`` followed by
    ``#set ($dir = 'desc')`` leaves only ``''``, ``asc``, or ``desc``.  The check is
    intentionally narrow: one variable, inequality comparisons joined only by ``&&``,
    and a literal replacement.
    """
    if not _velocity_literal_value(assigned_value) or "||" in condition:
        return False
    refs = set(_VELOCITY_VAR.findall(condition))
    if refs != {name}:
        return False
    inner = condition.strip()
    inner = re.sub(r"^#if\s*\(", "", inner)
    inner = re.sub(r"\)\s*$", "", inner)
    variable = rf"[\"']?\$!?\{{?{re.escape(name)}\}}?[\"']?"
    comparison = re.compile(rf"^\s*{variable}\s*!=\s*[\"'][^\"']*[\"']\s*$")
    return bool(inner) and all(comparison.match(part.strip().strip("()")) for part in inner.split("&&"))


def scan_velocity(source: str, uri: str, cve: str | None = None) -> list[dict]:
    cleaned = re.sub(r"#\*.*?\*#", _blank_velocity_block_comment, source, flags=re.DOTALL)
    env: dict[str, _Flow] = {}
    results: list[dict] = []
    frames: list[dict[str, object]] = []
    for line_number, raw_line in enumerate(cleaned.splitlines(), 1):
        line = raw_line.split("##", 1)[0]
        stripped = line.lstrip()
        if stripped.startswith("#end"):
            if frames:
                frame = frames.pop()
                condition = str(frame["condition"])
                for name, value in dict(frame["assignments"]).items():
                    if _velocity_finite_normalization(condition, name, value):
                        env[name] = _sanitized(env.get(name, _EMPTY))
        match = _VELOCITY_SET.match(line)
        if match:
            name, value = match.groups()
            flow = _velocity_eval(value, env)
            point = (line_number, len(line) - len(stripped) + 1)
            flow = _constructed(flow, point)
            env[name] = _merge(env.get(name, _EMPTY), flow) if frames else flow
            if frames:
                assignments = frames[-1]["assignments"]
                assert isinstance(assignments, dict)
                assignments[name] = value
            if flow.sqlish and flow.unsafe:
                results.append(
                    _result(
                        uri,
                        *point,
                        "SQL injection (CWE-89): a Velocity SQL/HQL fragment interpolates request-derived data",
                        cve,
                    )
                )
        if stripped.startswith("#if"):
            frames.append({"condition": stripped, "assignments": {}})
        elif stripped.startswith("#foreach"):
            frames.append({"condition": "", "assignments": {}})
    return results


# ---------------------------------------------------------------------------
# SARIF and dispatch
# ---------------------------------------------------------------------------


def _result(uri: str, line: int, col: int, message: str, cve: str | None) -> dict:
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
                    "region": {"startLine": line, "startColumn": col},
                }
            }
        ],
        "properties": properties,
    }


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    lowered = uri.lower()
    if lowered.endswith(".py"):
        return scan_python(source, uri, cve)
    if lowered.endswith(".php"):
        return scan_php(source, uri, cve)
    if lowered.endswith(".vm"):
        return scan_velocity(source, uri, cve)
    return []


def scan_file(path: str | Path, uri: str | None = None, cve: str | None = None) -> dict:
    file_path = Path(path)
    target_uri = uri or file_path.name
    results = scan_source(file_path.read_text(encoding="utf-8"), target_uri, cve)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deepthought-sqli-rule",
                        "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                        "rules": [
                            {
                                "id": RULE_ID,
                                "name": "UnboundSQLSyntax",
                                "shortDescription": {
                                    "text": "Untrusted data becomes SQL syntax instead of a bound value (CWE-89)"
                                },
                                "defaultConfiguration": {"level": "error"},
                                "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
                                "properties": {
                                    "cwe": GROUND_TRUTH_CWE,
                                    "tags": ["security", "CWE-89", "sql-injection"],
                                },
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
