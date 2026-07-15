"""DT-OPEN-REDIRECT — static Python open-redirect detection (CWE-601).

The detector parses Python with :mod:`ast`; it never imports or executes target code.
It follows request-derived redirect targets within one function, recognizes a small set
of framework redirect sinks, and suppresses a finding only when the exact target is
validated on the path to the sink or normalized to a single-leading-slash internal path.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

RULE_ID = "DT-OPEN-REDIRECT"
GROUND_TRUTH_CWE = "CWE-601"

_REDIRECT_MODULES = {
    "flask",
    "django.shortcuts",
    "django.http",
    "starlette.responses",
    "fastapi.responses",
}
_REDIRECT_NAMES = {"redirect", "HttpResponseRedirect", "RedirectResponse"}
_VALIDATORS = {
    "is_safe_redirect_url",
    "url_has_allowed_host_and_scheme",
    "is_safe_url",
    "is_same_origin",
    "same_origin",
}
_REQUEST_CONTAINERS = {"args", "GET", "POST", "values", "form", "query_params"}
_REQUEST_URL_ATTRS = {"referrer", "url", "uri"}
_PRESERVING_TRANSFORMS = {
    "get",
    "rstrip",
    "lstrip",
    "strip",
    "partition",
    "split",
    "format",
    "lower",
    "replace",
    "decode",
}
_INTERNAL_BUILDERS = {"url_for", "reverse"}
_WEB_HANDLER_BASES = {
    "RequestHandler",
    "RedirectHandler",
    "IPythonHandler",
    "APIHandler",
    "JupyterHandler",
}


class Flow(Enum):
    UNTAINTED = 0
    TAINTED = 1
    INTERNAL = 2


@dataclass
class State:
    env: dict[str, Flow]
    validated: set[str]

    def branch(self) -> "State":
        return State(dict(self.env), set(self.validated))


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


def _root_name(node: ast.AST | None) -> str:
    cur = node
    while isinstance(cur, (ast.Attribute, ast.Call, ast.Subscript)):
        if isinstance(cur, ast.Attribute):
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        else:
            cur = cur.value
    return cur.id if isinstance(cur, ast.Name) else ""


def _literal_slash(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("/")


def _request_source(node: ast.AST) -> bool:
    dotted = _dotted(node)
    if dotted in {"request.path", "self.request.path"}:
        return False
    if dotted in {"request.referrer", "request.url", "request.uri", "self.request.uri"}:
        return True
    if isinstance(node, ast.Attribute) and node.attr in _REQUEST_CONTAINERS:
        return _root_name(node) in {"request", "self"} and "request" in dotted
    if isinstance(node, ast.Call):
        callee = _dotted(node.func)
        if callee in {"request.get_full_path", "self.request.get_full_path"}:
            return False
        if _name(node.func) in {"get_argument", "get_query_argument"}:
            return _root_name(node.func) in {"self", "request"}
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            return _request_source(node.func.value)
    if isinstance(node, ast.Subscript):
        return _request_source(node.value)
    return False


def _internal_source(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and _dotted(node) in {"request.path", "self.request.path"}:
        return True
    if not isinstance(node, ast.Call):
        return False
    callee = _name(node.func)
    dotted = _dotted(node.func)
    return (
        callee in _INTERNAL_BUILDERS
        or callee == "get_absolute_url"
        or dotted in {"request.get_full_path", "self.request.get_full_path"}
    )


def _join_values(values: list[Flow]) -> Flow:
    if Flow.TAINTED in values:
        return Flow.TAINTED
    if Flow.INTERNAL in values:
        return Flow.INTERNAL
    return Flow.UNTAINTED


def _flow(node: ast.AST | None, state: State) -> Flow:
    if node is None:
        return Flow.UNTAINTED
    if _internal_source(node):
        return Flow.INTERNAL
    if _request_source(node):
        return Flow.TAINTED
    if isinstance(node, ast.Name):
        if node.id in state.validated:
            return Flow.INTERNAL
        return state.env.get(node.id, Flow.UNTAINTED)
    if isinstance(node, ast.Constant):
        return Flow.UNTAINTED
    if isinstance(node, ast.BoolOp):
        return _join_values([_flow(value, state) for value in node.values])
    if isinstance(node, ast.IfExp):
        return _join_values([_flow(node.body, state), _flow(node.orelse, state)])
    if isinstance(node, ast.JoinedStr):
        return _join_values(
            [_flow(value.value, state) for value in node.values if isinstance(value, ast.FormattedValue)]
        )
    if isinstance(node, ast.BinOp):
        left = _flow(node.left, state)
        right = _flow(node.right, state)
        if isinstance(node.op, ast.Add):
            # A single-leading-slash base cannot be reinterpreted as an authority.
            if _literal_slash(node.left) and right is Flow.TAINTED:
                return Flow.INTERNAL
            if left is Flow.INTERNAL:
                return Flow.INTERNAL
        return _join_values([left, right])
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return _join_values([_flow(elt.value if isinstance(elt, ast.Starred) else elt, state) for elt in node.elts])
    if isinstance(node, ast.Dict):
        return _join_values([_flow(value, state) for value in node.values])
    if isinstance(node, ast.Subscript):
        return _flow(node.value, state)
    if isinstance(node, ast.Attribute):
        return _flow(node.value, state)
    if isinstance(node, ast.Call):
        callee = _name(node.func)
        if callee in _VALIDATORS:
            return Flow.UNTAINTED
        if callee in _INTERNAL_BUILDERS or callee == "get_absolute_url":
            return Flow.INTERNAL
        if isinstance(node.func, ast.Attribute):
            receiver = _flow(node.func.value, state)
            if callee == "join" and node.args:
                elements: list[ast.AST] = []
                for arg in node.args:
                    if isinstance(arg, (ast.List, ast.Tuple)):
                        elements.extend(
                            elt.value if isinstance(elt, ast.Starred) else elt for elt in arg.elts
                        )
                    else:
                        elements.append(arg)
                values = [_flow(arg, state) for arg in elements]
                # Joining query/suffix pieces to an established internal path stays internal.
                if values and values[0] is Flow.INTERNAL:
                    return Flow.INTERNAL
                return _join_values(values)
            if callee in _PRESERVING_TRANSFORMS:
                return receiver
        return _join_values([_flow(arg, state) for arg in node.args])
    return Flow.UNTAINTED


def _assigned_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Starred):
        return _assigned_names(target.value)
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for elt in target.elts for name in _assigned_names(elt)]
    return []


def _call_arg_name(call: ast.Call) -> str | None:
    candidate: ast.AST | None = call.args[0] if call.args else None
    for keyword in call.keywords:
        if keyword.arg in {"url", "target", "redirect_url", "next_url"}:
            candidate = keyword.value
            break
    return candidate.id if isinstance(candidate, ast.Name) else None


def _positive_validations(test: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(test):
        if not isinstance(node, ast.Call) or _name(node.func) not in _VALIDATORS:
            continue
        parent_is_not = any(
            isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not) and parent.operand is node
            for parent in ast.walk(test)
        )
        if not parent_is_not and (name := _call_arg_name(node)):
            names.add(name)
    return names


def _negative_validations(test: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(test):
        if not isinstance(node, ast.UnaryOp) or not isinstance(node.op, ast.Not):
            continue
        call = node.operand
        if isinstance(call, ast.Call) and _name(call.func) in _VALIDATORS:
            if name := _call_arg_name(call):
                names.add(name)
    return names


def _block_always_exits(statements: list[ast.stmt]) -> bool:
    if not statements:
        return False
    last = statements[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    return isinstance(last, ast.If) and _block_always_exits(last.body) and _block_always_exits(last.orelse)


def _imports(source_tree: ast.Module) -> tuple[set[str], set[str]]:
    redirect_aliases: set[str] = set()
    validator_aliases: set[str] = set(_VALIDATORS)
    for node in source_tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            if module in _REDIRECT_MODULES and alias.name in _REDIRECT_NAMES:
                redirect_aliases.add(local)
            if alias.name in _VALIDATORS:
                validator_aliases.add(local)
    return redirect_aliases, validator_aliases


class _Scanner:
    def __init__(self, redirect_aliases: set[str], validator_aliases: set[str], uri: str, cve: str | None):
        self.redirect_aliases = redirect_aliases
        self.validator_aliases = validator_aliases
        self.uri = uri
        self.cve = cve
        self.results: list[dict] = []

    def _is_sink(self, call: ast.Call, web_handler: bool) -> bool:
        if isinstance(call.func, ast.Name):
            return call.func.id in self.redirect_aliases
        return (
            web_handler
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "redirect"
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "self"
        )

    def _scan_expr(self, expr: ast.AST | None, state: State, web_handler: bool) -> None:
        if expr is None:
            return
        for node in ast.walk(expr):
            if not isinstance(node, ast.Call) or not self._is_sink(node, web_handler):
                continue
            target = node.args[0] if node.args else None
            if target is not None and _flow(target, state) is Flow.TAINTED:
                self.results.append(
                    _result(
                        self.uri,
                        node.lineno,
                        node.col_offset + 1,
                        "open redirect (CWE-601): request-derived URL reaches a framework redirect "
                        "without same-origin validation",
                        self.cve,
                    )
                )

    def _scan_block(self, statements: list[ast.stmt], state: State, web_handler: bool) -> None:
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                value = stmt.value
                self._scan_expr(value, state, web_handler)
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                value_flow = _flow(value, state)
                for target in targets:
                    for name in _assigned_names(target):
                        state.env[name] = value_flow
                        state.validated.discard(name)
                continue
            if isinstance(stmt, ast.AugAssign):
                self._scan_expr(stmt.value, state, web_handler)
                value_flow = _join_values([_flow(stmt.target, state), _flow(stmt.value, state)])
                for name in _assigned_names(stmt.target):
                    state.env[name] = value_flow
                    state.validated.discard(name)
                continue
            if isinstance(stmt, ast.If):
                self._scan_expr(stmt.test, state, web_handler)
                positive = self._validator_names(_positive_validations(stmt.test))
                negative = self._validator_names(_negative_validations(stmt.test))
                body_state = state.branch()
                body_state.validated.update(positive)
                self._scan_block(stmt.body, body_state, web_handler)
                self._scan_block(stmt.orelse, state.branch(), web_handler)
                if negative and _block_always_exits(stmt.body):
                    state.validated.update(negative)
                continue
            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                self._scan_expr(stmt.iter if hasattr(stmt, "iter") else stmt.test, state, web_handler)
                self._scan_block(stmt.body, state.branch(), web_handler)
                self._scan_block(stmt.orelse, state.branch(), web_handler)
                continue
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    self._scan_expr(item.context_expr, state, web_handler)
                self._scan_block(stmt.body, state.branch(), web_handler)
                continue
            if isinstance(stmt, (ast.Try, ast.TryStar)):
                self._scan_block(stmt.body, state.branch(), web_handler)
                for handler in stmt.handlers:
                    self._scan_block(handler.body, state.branch(), web_handler)
                self._scan_block(stmt.orelse, state.branch(), web_handler)
                self._scan_block(stmt.finalbody, state.branch(), web_handler)
                continue
            if isinstance(stmt, ast.Match):
                self._scan_expr(stmt.subject, state, web_handler)
                for case in stmt.cases:
                    self._scan_block(case.body, state.branch(), web_handler)
                continue
            for field in ("value", "test", "exc", "cause"):
                value = getattr(stmt, field, None)
                if isinstance(value, ast.AST):
                    self._scan_expr(value, state, web_handler)

    def _validator_names(self, names: set[str]) -> set[str]:
        # _positive/_negative only emit calls whose original name is in _VALIDATORS.
        # Import aliases are handled below by a second exact AST pass in scan_function.
        return names

    def scan_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, web_handler: bool) -> None:
        env = {
            arg.arg: Flow.TAINTED
            for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if arg.arg not in {"self", "cls", "request"}
        }
        self._scan_block(node.body, State(env, set()), web_handler)


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    redirect_aliases, validator_aliases = _imports(tree)
    scanner = _Scanner(redirect_aliases, validator_aliases, uri, cve)

    # Module-level redirects are rare but valid.
    scanner._scan_block(tree.body, State({}, set()), False)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scanner.scan_function(node, False)
        elif isinstance(node, ast.ClassDef):
            base_names = {_name(base) for base in node.bases}
            web_handler = bool(base_names & _WEB_HANDLER_BASES)
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    scanner.scan_function(member, web_handler)
    return scanner.results


def _result(uri: str, line: int, col: int, msg: str, cve: str | None) -> dict:
    properties = {"cwe": GROUND_TRUTH_CWE}
    if cve:
        properties["cve"] = cve
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
        "properties": properties,
    }


def scan_file(path: str | Path, uri: str | None = None, cve: str | None = None) -> dict:
    source_path = Path(path)
    results = scan_source(source_path.read_text(encoding="utf-8"), uri or source_path.name, cve)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deepthought-open-redirect-rule",
                        "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                        "rules": [
                            {
                                "id": RULE_ID,
                                "name": "UnvalidatedRedirect",
                                "shortDescription": {"text": "Request-derived open redirect (CWE-601)"},
                                "defaultConfiguration": {"level": "error"},
                                "helpUri": "https://cwe.mitre.org/data/definitions/601.html",
                                "properties": {
                                    "cwe": GROUND_TRUTH_CWE,
                                    "tags": ["security", "CWE-601", "open-redirect"],
                                },
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
