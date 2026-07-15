"""DT-PATH-TRAVERSAL — a static detector for path traversal / Zip-Slip (CWE-22),
multi-language (JS tree-sitter + Python ast), emitting SARIF 2.1.0 into the shipped
``deepthought.ingest.sarif``. It parses source into an AST and reads it; nothing runs.

The class: an untrusted path component (an archive entry name, a request path) is joined
to a destination and used in a file operation WITHOUT a containment check, so a ``..``
segment escapes the destination. The rule flags a path-join sink with a non-literal
component when the enclosing scope applies no containment guard.

  * JS: ``path.join(dest, x)`` / ``path.resolve(dest, x)`` with a non-literal component.
  * Python: ``os.path.join(dest, x)`` / ``<dir>.joinpath(x)`` with a non-literal component.

Guards (patched shape) recognized in scope: a containment check — ``startsWith`` /
``startswith`` on the resolved path, ``is_relative_to`` / ``relative_to``,
``path.relative`` / ``os.path.relpath`` + a ``..`` test, ``commonpath`` / ``commonprefix``,
or an explicit ``..`` rejection (``indexOf('..')`` / ``includes('..')`` / a sanitize call).
"""

from __future__ import annotations

import ast
from pathlib import Path

import tree_sitter_javascript as _tsjs
from tree_sitter import Language, Node, Parser

RULE_ID = "DT-PATH-TRAVERSAL"
GROUND_TRUTH_CWE = "CWE-22"

_JS = Language(_tsjs.language())
_JPARSER = Parser(_JS)

# Containment-guard markers (either language). Presence in the sink's scope = hardened.
# NOTE: a bare startsWith/startswith is deliberately EXCLUDED — it matches unrelated
# absolute-path assertions (aiohttp's ``path.startswith("/")``) and is not by itself a
# containment check. The real containment idioms are relative_to / commonpath / a realpath
# boundary / a ``..`` rejection / a path-stripping helper.
_GUARDS = (
    "is_relative_to", "relative_to", "relpath", "commonpath", "commonprefix",
    ".relative(", "indexOf('..')", 'indexOf("..")', "includes('..')", 'includes("..")',
    "strip-dirs", "stripDirs", "sanitize", "safeJoin",
    "safe_join", "isInside", "is_within", "within_directory", "normalize-path",
    "path-is-inside",
)
_JS_FUNCS = frozenset({"function_declaration", "function_expression", "arrow_function",
                       "method_definition", "generator_function_declaration", "function"})


# ------------------------------- JS ---------------------------------------- #

def _jt(src: bytes, n: Node) -> str:
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def _jiter(n: Node):
    st = [n]
    while st:
        c = st.pop(); yield c; st.extend(c.children)


def _jiter_scope(scope: Node):
    """Walk one JS function only. A guard in a nested callback cannot sanitize a
    sibling or outer sink, so nested function bodies are separate scopes."""
    yield scope
    stack = list(scope.children)
    while stack:
        node = stack.pop()
        if node.type in _JS_FUNCS:
            continue
        yield node
        stack.extend(node.children)


def _js_scope_text(src: bytes, scope: Node) -> str:
    """Source for one function with nested function bodies blanked out."""
    data = bytearray(src[scope.start_byte:scope.end_byte])
    nested: list[Node] = []
    stack = list(scope.children)
    while stack:
        node = stack.pop()
        if node.type in _JS_FUNCS:
            nested.append(node)
            continue
        stack.extend(node.children)
    for node in nested:
        start = node.start_byte - scope.start_byte
        end = node.end_byte - scope.start_byte
        data[start:end] = b" " * (end - start)
    return bytes(data).decode("utf-8", "replace")


def _js_scope(node: Node, root: Node) -> Node:
    cur = node.parent
    while cur is not None:
        if cur.type in _JS_FUNCS:
            return cur
        cur = cur.parent
    return root


def _js_path_aliases(src: bytes, root: Node) -> set[str]:
    """Identifiers bound to the ``path`` module — ``const pth = require('path')`` — so an
    aliased ``pth.resolve(dest, entry)`` (adm-zip) is recognized, not only literal ``path.``."""
    aliases = {"path", "posix", "win32"}
    for n in _jiter(root):
        if n.type == "variable_declarator":
            name = n.child_by_field_name("name")
            value = n.child_by_field_name("value")
            if name is not None and value is not None and name.type == "identifier":
                vt = _jt(src, value)
                if "require('path')" in vt.replace('"', "'") or vt.strip() in ("require('path')", 'require("path")'):
                    aliases.add(_jt(src, name))
    return aliases


def _js_join_sink(src: bytes, call: Node, aliases: set[str]) -> bool:
    """A path.join / path.resolve with a non-literal (untrusted) component."""
    fn = call.child_by_field_name("function")
    if fn is None or fn.type != "member_expression":
        return False
    prop = fn.child_by_field_name("property")
    if prop is None or _jt(src, prop) not in ("join", "resolve"):
        return False
    obj = fn.child_by_field_name("object")
    if obj is None or _jt(src, obj).split(".")[-1] not in aliases:
        return False
    args = call.child_by_field_name("arguments")
    if args is None:
        return False
    comps = [a for a in args.children if a.type not in ("(", ",", ")", "comment")]
    # Need >=2 components and at least one dynamic path segment. A template literal
    # without a substitution is a fixed string just like a quoted literal.
    def dynamic(component: Node) -> bool:
        if component.type in ("string", "number"):
            return False
        if component.type == "template_string":
            return any(child.type == "template_substitution" for child in component.children)
        return True

    return len(comps) >= 2 and any(dynamic(component) for component in comps[1:])


def _js_bound_names(src: bytes, call: Node) -> set[str]:
    """Names that receive this exact path-join call."""
    names: set[str] = set()
    cur = call.parent
    while cur is not None and cur.type not in _JS_FUNCS:
        if cur.type == "variable_declarator":
            value = cur.child_by_field_name("value")
            name = cur.child_by_field_name("name")
            if value is not None and name is not None and value.start_byte <= call.start_byte <= call.end_byte <= value.end_byte:
                names.add(_jt(src, name))
            break
        if cur.type == "assignment_expression":
            right = cur.child_by_field_name("right")
            left = cur.child_by_field_name("left")
            if right is not None and left is not None and right.start_byte <= call.start_byte <= call.end_byte <= right.end_byte:
                names.add(_jt(src, left))
            break
        cur = cur.parent
    return names


def _js_has_bound_startswith_guard(src: bytes, scope: Node, sink: Node) -> bool:
    """Recognize a containment check tied to the path produced by *sink*.

    A bare ``startsWith`` token is intentionally insufficient: URL/prefix checks in
    the same function must not bless an unrelated filesystem path. The receiver must
    be either the sink expression itself or a variable assigned from it.
    """
    bound = _js_bound_names(src, sink)
    sink_text = _jt(src, sink)
    for node in _jiter_scope(scope):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        prop = fn.child_by_field_name("property")
        obj = fn.child_by_field_name("object")
        if prop is None or obj is None or _jt(src, prop) != "startsWith":
            continue
        receiver = _jt(src, obj)
        if receiver == sink_text or receiver in bound:
            return True
    return False


def _js_has_bound_realpath_guard(src: bytes, scope: Node, sink: Node) -> bool:
    """A realpath call is a guard only when it normalizes this sink's result.

    Promise callbacks are allowed because the seed's containment check resolves the
    destination in a nested callback. Requiring the bound destination identifier keeps
    an unrelated nested helper from suppressing the sink.
    """
    bound = _js_bound_names(src, sink)
    cur = sink.parent
    while cur is not None and cur.type not in _JS_FUNCS:
        if cur.type == "call_expression":
            fn = cur.child_by_field_name("function")
            if fn is not None and _jt(src, fn).split(".")[-1] in ("realpath", "realpathSync"):
                return True
        cur = cur.parent
    if not bound:
        return False
    for node in _jiter(scope):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or _jt(src, fn).split(".")[-1] not in ("realpath", "realpathSync"):
            continue
        identifiers = {_jt(src, child) for child in _jiter(node) if child.type == "identifier"}
        if identifiers & bound:
            return True
    return False


def scan_js(source: str, uri: str, cve: str | None = None) -> list[dict]:
    src = source.encode("utf-8")
    root = _JPARSER.parse(src).root_node
    aliases = _js_path_aliases(src, root)
    out: list[dict] = []
    for n in _jiter(root):
        if n.type != "call_expression" or not _js_join_sink(src, n, aliases):
            continue
        scope = _js_scope(n, root)
        if (
            any(g in _js_scope_text(src, scope) for g in _GUARDS)
            or _js_has_bound_startswith_guard(src, scope, n)
            or _js_has_bound_realpath_guard(src, scope, n)
        ):
            continue
        out.append(_result(uri, n.start_point[0] + 1, n.start_point[1] + 1,
                           f"path traversal (CWE-22): dynamic path component joined to a destination "
                           f"without a containment check ({_jt(src, n)[:50]})", cve))
    return out


# ----------------------------- Python -------------------------------------- #

def _py_call_name(call: ast.Call) -> str:
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")


def _python_node_bounds(node: ast.AST, line_offsets: list[int]) -> tuple[int, int]:
    """Return byte bounds without treating a valid zero end column as missing."""
    start = line_offsets[node.lineno - 1] + node.col_offset
    end_line = getattr(node, "end_lineno", None)
    if end_line is None:
        end_line = node.lineno
    end_col = getattr(node, "end_col_offset", None)
    if end_col is None:
        end_col = node.col_offset
    return start, line_offsets[end_line - 1] + end_col


def scan_python(source: str, uri: str, cve: str | None = None) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    encoded_lines = source.splitlines(keepends=True)
    line_offsets: list[int] = []
    offset = 0
    for line in encoded_lines:
        line_offsets.append(offset)
        offset += len(line.encode("utf-8"))

    def scope_text(node: ast.AST) -> str:
        best = None
        for f in funcs:
            if f.lineno <= node.lineno <= (getattr(f, "end_lineno", None) or f.lineno):
                if best is None or f.lineno > best.lineno:
                    best = f
        scope: ast.AST = best or tree
        scope_start, scope_end = (
            _python_node_bounds(scope, line_offsets)
            if best is not None
            else (0, len(source.encode("utf-8")))
        )
        data = bytearray(source.encode("utf-8")[scope_start:scope_end])
        for nested in funcs:
            if nested is best:
                continue
            nested_start, nested_end = _python_node_bounds(nested, line_offsets)
            if scope_start <= nested_start and nested_end <= scope_end:
                data[nested_start - scope_start:nested_end - scope_start] = b" " * (nested_end - nested_start)
        return bytes(data).decode("utf-8", "replace")

    out: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _py_call_name(node)
        if name not in ("join", "joinpath"):
            continue
        # os.path.join / Path().joinpath with a non-constant component
        comps = node.args if name == "join" else node.args
        if name == "join":
            # require it to be os.path.join (or path.join)
            seg = ast.get_source_segment(source, node.func) or ""
            if "path.join" not in seg and "os.path.join" not in seg and "posixpath.join" not in seg:
                continue
        if len(comps) < (2 if name == "join" else 1):
            continue
        dynamic = any(not isinstance(a, ast.Constant) for a in (comps[1:] if name == "join" else comps))
        if not dynamic:
            continue
        if any(g in scope_text(node) for g in _GUARDS):
            continue
        out.append(_result(uri, node.lineno, node.col_offset + 1,
                           f"path traversal (CWE-22): dynamic path component joined to a destination "
                           f"without a containment check", cve))
    return out


# ------------------------------ shared ------------------------------------- #

def _result(uri: str, line: int, col: int, msg: str, cve: str | None) -> dict:
    props = {"cwe": GROUND_TRUTH_CWE}
    if cve:
        props["cve"] = cve
    return {"ruleId": RULE_ID, "level": "error", "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                          "region": {"startLine": line, "startColumn": col}}}],
            "properties": props}


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    if uri.endswith(".py"):
        return scan_python(source, uri, cve)
    return scan_js(source, uri, cve)


def scan_file(path: str | Path, uri: str | None = None, cve: str | None = None) -> dict:
    p = Path(path)
    results = scan_source(p.read_text(encoding="utf-8"), uri=uri or p.name, cve=cve)
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "deepthought-pathtrav-rule",
                     "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                     "rules": [{"id": RULE_ID, "name": "UncontainedPathJoin",
                               "shortDescription": {"text": "Path join without containment (CWE-22)"},
                               "defaultConfiguration": {"level": "error"},
                               "helpUri": "https://cwe.mitre.org/data/definitions/22.html",
                               "properties": {"cwe": GROUND_TRUTH_CWE, "tags": ["security", "CWE-22", "path-traversal"]}}]}},
                     "results": results}]}
