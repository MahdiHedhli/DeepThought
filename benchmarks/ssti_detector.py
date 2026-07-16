"""DT-SSTI-TEMPLATE — static Python detector for server-side template injection (CWE-1336).

Parses Python with :mod:`ast` only; never imports or executes target code.

The class shape this rule covers: constructing an unsandboxed Jinja2
``Environment`` / ``Template`` (or import-bound Flask ``render_template_string``)
that can render attacker-controlled template source. The patched discriminator is
a sandbox constructor (``SandboxedEnvironment`` / ``ImmutableSandboxedEnvironment``)
or replacing the engine with a non-Jinja substitution path.

Import provenance is binding-aware so
``from jinja2.sandbox import SandboxedEnvironment as Environment`` does not flag
the safe alias, while ``from jinja2 import Environment`` does. Local rebinding
shadows module bindings so a function that reassigns ``Environment = str`` is not
flagged.
"""

from __future__ import annotations

import ast
from pathlib import Path

RULE_ID = "DT-SSTI-TEMPLATE"
GROUND_TRUTH_CWE = "CWE-1336"

_UNSAFE = "unsafe"
_SAFE = "safe"
_NEUTRAL = "neutral"  # local shadow that is not a Jinja/Flask constructor
_FLASK = "flask_render"

_SANDBOX_NAMES = frozenset({"SandboxedEnvironment", "ImmutableSandboxedEnvironment"})
_UNSAFE_ENV_NAMES = frozenset({"Environment", "NativeEnvironment"})
_UNSAFE_TEMPLATE_NAMES = frozenset({"Template"})
_UNSAFE_CTOR_NAMES = _UNSAFE_ENV_NAMES | _UNSAFE_TEMPLATE_NAMES
_FLASK_SINKS = frozenset({"render_template_string"})
_JINJA_ROOTS = frozenset({"jinja2", "jinja2.environment", "jinja2.nativetypes"})
_SAFE_ROOTS = frozenset({"jinja2.sandbox"})


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


class _BindingCollector(ast.NodeVisitor):
    """Module- and function-local name bindings for Jinja constructors."""

    def __init__(self) -> None:
        self.module: dict[str, str] = {}
        self.function: dict[str, dict[str, str]] = {}
        self._stack: list[str] = []

    def _bind(self, name: str, kind: str) -> None:
        if self._stack:
            self.function.setdefault(self._stack[-1], {})[name] = kind
        else:
            self.module[name] = kind

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._stack.append(f"{node.name}:{node.lineno}")
        # Parameters shadow outer names (not Jinja constructors).
        for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
            self._bind(arg.arg, _NEUTRAL)
        if node.args.vararg:
            self._bind(node.args.vararg.arg, _NEUTRAL)
        if node.args.kwarg:
            self._bind(node.args.kwarg.arg, _NEUTRAL)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "jinja2" or alias.name.startswith("jinja2."):
                # `import jinja2.environment as environment` binds the full path.
                # `import jinja2.environment` (no as) binds the top-level package name
                # `jinja2` in Python's import system — keep that name as "jinja2".
                if alias.asname:
                    self._bind(alias.asname, alias.name)
                else:
                    self._bind(alias.name.split(".")[0], "jinja2")
            elif alias.name == "flask" or alias.name.startswith("flask."):
                if alias.asname:
                    self._bind(alias.asname, alias.name)
                else:
                    self._bind(alias.name.split(".")[0], "flask")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            if mod in _SAFE_ROOTS or mod.endswith(".sandbox"):
                if alias.name in _SANDBOX_NAMES or alias.name == "Environment":
                    self._bind(local, _SAFE)
                continue
            if mod in _JINJA_ROOTS:
                if alias.name in _SANDBOX_NAMES:
                    self._bind(local, _SAFE)
                elif alias.name in _UNSAFE_CTOR_NAMES:
                    self._bind(local, _UNSAFE)
                elif alias.name == "sandbox":
                    self._bind(local, "jinja2.sandbox")
                elif alias.name == "environment":
                    self._bind(local, "jinja2.environment")
                elif alias.name == "nativetypes":
                    self._bind(local, "jinja2.nativetypes")
                continue
            if mod in ("flask", "flask.templating") and alias.name in _FLASK_SINKS:
                self._bind(local, _FLASK)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        kind = self._value_kind(node.value)
        for t in node.targets:
            if isinstance(t, ast.Name):
                # Any simple-name assignment shadows; unknown RHS → neutral.
                self._bind(t.id, kind if kind is not None else _NEUTRAL)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            kind = self._value_kind(node.value)
            self._bind(node.target.id, kind if kind is not None else _NEUTRAL)
        self.generic_visit(node)

    def _value_kind(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.lookup(node.id)
        if isinstance(node, ast.Attribute):
            return self._attr_kind(node)
        return None

    def _attr_kind(self, node: ast.Attribute) -> str | None:
        dotted = _dotted(node)
        if dotted in (
            "jinja2.sandbox.SandboxedEnvironment",
            "jinja2.sandbox.ImmutableSandboxedEnvironment",
            "jinja2.SandboxedEnvironment",
        ):
            return _SAFE
        if dotted in (
            "jinja2.Environment",
            "jinja2.Template",
            "jinja2.environment.Environment",
            "jinja2.environment.Template",
            "jinja2.nativetypes.NativeEnvironment",
            "jinja2.nativetypes.Environment",
        ):
            return _UNSAFE
        if isinstance(node.value, ast.Name):
            base = self.lookup(node.value.id)
            return self._kind_from_base_attr(base, node.attr)
        if isinstance(node.value, ast.Attribute):
            # j2.nativetypes.NativeEnvironment / j2.sandbox.SandboxedEnvironment
            outer = _dotted(node.value)
            resolved = self._resolve_dotted_base(outer)
            return self._kind_from_base_attr(resolved, node.attr)
        return None

    def _resolve_dotted_base(self, dotted: str) -> str | None:
        """Map a dotted expression using the first name's binding."""
        if not dotted:
            return None
        parts = dotted.split(".")
        head = self.lookup(parts[0])
        if head is None:
            return dotted if dotted.startswith("jinja2") else None
        if head in (_SAFE, _UNSAFE, _NEUTRAL, _FLASK):
            return head
        # head is a module path like "jinja2" or "jinja2.sandbox"
        return ".".join([head, *parts[1:]])

    def _kind_from_base_attr(self, base: str | None, attr: str) -> str | None:
        if base is None:
            return None
        if base in (_SAFE, _UNSAFE, _NEUTRAL, _FLASK):
            return None  # instance method, not a constructor binding
        if base in _SAFE_ROOTS or base.endswith(".sandbox"):
            if attr in _SANDBOX_NAMES or attr == "Environment":
                return _SAFE
            return None
        if base in _JINJA_ROOTS or base == "jinja2" or base.startswith("jinja2."):
            if attr in _SANDBOX_NAMES:
                return _SAFE
            if attr in _UNSAFE_CTOR_NAMES:
                return _UNSAFE
            if attr == "sandbox":
                return "jinja2.sandbox"
            if attr == "environment":
                return "jinja2.environment"
            if attr == "nativetypes":
                return "jinja2.nativetypes"
        if base in ("flask", "flask.templating") and attr in _FLASK_SINKS:
            return _FLASK
        return None

    def lookup(self, name: str, func_key: str | None = None) -> str | None:
        if func_key and func_key in self.function and name in self.function[func_key]:
            return self.function[func_key][name]
        # When inside a function, only fall back to module if the name is not
        # recorded as a local shadow. Presence in function map is required for
        # shadow; absence means use module.
        return self.module.get(name)


def _enclosing_func_key(node: ast.AST, tree: ast.AST) -> str | None:
    parent_map: dict[ast.AST, ast.AST] = {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parent_map[c] = p
    cur: ast.AST | None = node
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return f"{cur.name}:{cur.lineno}"
        cur = parent_map.get(cur)
    return None


def _call_kind(node: ast.Call, binds: _BindingCollector, fkey: str | None) -> tuple[str | None, str]:
    """Return (kind, label) for a Call node."""
    if isinstance(node.func, ast.Name):
        name = node.func.id
        kind = binds.lookup(name, fkey)
        if kind == _SAFE:
            return _SAFE, name
        if kind == _UNSAFE:
            return _UNSAFE, name
        if kind == _FLASK:
            return _FLASK, name
        if kind == _NEUTRAL:
            return _NEUTRAL, name
        if name in _SANDBOX_NAMES:
            return _SAFE, name
        return None, name

    if isinstance(node.func, ast.Attribute):
        dotted = _dotted(node.func)
        label = dotted
        # Literal / fully-qualified safe constructors
        if dotted.endswith(".SandboxedEnvironment") or dotted.endswith(
            ".ImmutableSandboxedEnvironment"
        ):
            return _SAFE, label
        if dotted in (
            "jinja2.Environment",
            "jinja2.Template",
            "jinja2.environment.Environment",
            "jinja2.environment.Template",
            "jinja2.nativetypes.NativeEnvironment",
            "jinja2.nativetypes.Environment",
        ):
            return _UNSAFE, label

        if isinstance(node.func.value, ast.Name):
            base = binds.lookup(node.func.value.id, fkey)
            attr = node.func.attr
            k = binds._kind_from_base_attr(base, attr)
            if k in (_SAFE, _UNSAFE, _FLASK):
                return k, label
            # flask.render_template_string only when base is flask module
            if attr in _FLASK_SINKS and base in ("flask", "flask.templating"):
                return _FLASK, attr
            return None, label

        if isinstance(node.func.value, ast.Attribute):
            outer = _dotted(node.func.value)
            resolved = binds._resolve_dotted_base(outer)
            # Fix head resolution with function-local bindings for the first name.
            if isinstance(node.func.value, ast.Attribute) or isinstance(node.func.value, ast.Name):
                # Re-resolve using fkey for the head identifier.
                parts = outer.split(".")
                if parts:
                    head = binds.lookup(parts[0], fkey)
                    if head and head not in (_SAFE, _UNSAFE, _NEUTRAL, _FLASK):
                        resolved = ".".join([head, *parts[1:]])
                    elif head is None and outer.startswith("jinja2"):
                        resolved = outer
            k = binds._kind_from_base_attr(resolved, node.func.attr)
            if k in (_SAFE, _UNSAFE, _FLASK):
                return k, label
            # j2.nativetypes.NativeEnvironment exact after resolve
            if resolved and f"{resolved}.{node.func.attr}" in (
                "jinja2.nativetypes.NativeEnvironment",
                "jinja2.environment.Environment",
                "jinja2.environment.Template",
                "jinja2.Environment",
                "jinja2.Template",
            ):
                return _UNSAFE, label
            return None, label

    return None, ""


def scan_python(source: str, uri: str, cve: str | None = None) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    binds = _BindingCollector()
    binds.visit(tree)
    out: list[dict] = []
    seen: set[tuple[int, str]] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fkey = _enclosing_func_key(node, tree)
        kind, label = _call_kind(node, binds, fkey)
        if kind in (None, _SAFE, _NEUTRAL):
            continue
        if kind == _UNSAFE:
            key = (node.lineno, label)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                _result(
                    uri,
                    node.lineno,
                    node.col_offset + 1,
                    f"Server-side template injection (CWE-1336): unsandboxed Jinja2 "
                    f"constructor {label}(...) can evaluate attacker-controlled templates",
                    cve,
                )
            )
        elif kind == _FLASK:
            key = (node.lineno, "render_template_string")
            if key in seen:
                continue
            seen.add(key)
            out.append(
                _result(
                    uri,
                    node.lineno,
                    node.col_offset + 1,
                    "Server-side template injection (CWE-1336): Flask "
                    "render_template_string evaluates a template string in-process",
                    cve,
                )
            )
    return out


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    if uri.endswith((".js", ".ts", ".java", ".php", ".go", ".rb", ".jsx", ".tsx")):
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
                        "name": "deepthought-ssti-rule",
                        "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                        "rules": [
                            {
                                "id": RULE_ID,
                                "name": "ServerSideTemplateInjection",
                                "shortDescription": {
                                    "text": "Unsandboxed Jinja2 template construction (CWE-1336)"
                                },
                                "defaultConfiguration": {"level": "error"},
                                "helpUri": "https://cwe.mitre.org/data/definitions/1336.html",
                                "properties": {
                                    "cwe": GROUND_TRUTH_CWE,
                                    "tags": ["security", "CWE-1336", "ssti"],
                                },
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
