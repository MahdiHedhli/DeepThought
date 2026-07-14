"""DT-CMDI-EXEC — a static detector for OS command injection (CWE-78) in JavaScript,
emitting SARIF 2.1.0 into the shipped ``deepthought.ingest.sarif``. It parses source into
a tree-sitter AST and reads it; nothing here runs the target.

The class: untrusted data reaching a shell-execution sink. The rule flags a call to a
shell-exec sink whose command is built dynamically (a non-literal string — an identifier,
a template with a substitution, or a string concatenation) OR that opts into a shell for
dynamic args (``{ shell: true }``), when the enclosing scope applies no shell-escaping
guard (``shell-quote``/``shell-escape``/``quote``).

Sinks: ``child_process`` ``exec``/``execSync``/``execFile``/``spawn`` (and *Sync), and
``foregroundChild`` (the node-glob seed CVE-2025-64756: ``foregroundChild(cmd, matches,
{ shell: true })`` — the fix drops ``shell: true`` / passes array args).
"""

from __future__ import annotations

import ast
from pathlib import Path

import tree_sitter_javascript as _tsjs
from tree_sitter import Language, Node, Parser

RULE_ID = "DT-CMDI-EXEC"
GROUND_TRUTH_CWE = "CWE-78"

_JS = Language(_tsjs.language())
_PARSER = Parser(_JS)

# Shell-exec sinks (bare name or member .name). exec/execSync run a shell command string;
# spawn/execFile are shell only with {shell:true}; foregroundChild forwards to a child.
_STRING_CMD_SINKS = frozenset({"exec", "execSync"})           # first arg IS a shell string
_ARGV_SINKS = frozenset({"spawn", "spawnSync", "execFile", "execFileSync", "foregroundChild"})
_ALL_SINKS = _STRING_CMD_SINKS | _ARGV_SINKS
# Escaping/allowlist guards that neutralize the injection.
_GUARDS = ("shell-quote", "shellQuote", "shell-escape", "shellEscape", "shescape", ".quote(", "quote(")
_FUNCTION_TYPES = frozenset({"function_declaration", "function_expression", "arrow_function",
                             "method_definition", "generator_function_declaration", "function"})


def _text(src: bytes, n: Node) -> str:
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def _iter(n: Node):
    st = [n]
    while st:
        c = st.pop()
        yield c
        st.extend(c.children)


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


def _is_dynamic_string(node: Node) -> bool:
    """A command string that is not a fixed literal: an identifier, a template with a
    substitution, a concatenation, or a call — i.e. it can carry attacker data."""
    if node.type == "string":
        return False
    if node.type == "template_string":
        return any(c.type == "template_substitution" for c in node.children)
    if node.type in ("identifier", "member_expression", "binary_expression", "call_expression"):
        return True
    return False


_SHELL_NAMES = ("sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh")


def _has_shell_true(src: bytes, args: Node) -> bool:
    """An options object with a dangerous ``shell`` value — ``shell: true`` OR a shell
    STRING (``shell: '/bin/bash'``). Node runs the command through a shell for any
    non-empty string too, so a string value is as dangerous as ``true``; only ``false``
    (or absent) is safe."""
    for a in args.children:
        if a.type != "object":
            continue
        for pair in _iter(a):
            if pair.type != "pair":
                continue
            k = pair.child_by_field_name("key")
            v = pair.child_by_field_name("value")
            if k is None or v is None or _text(src, k).strip("\"'") != "shell":
                continue
            # dangerous unless the value is literally false/undefined/null/0
            if _text(src, v) not in ("false", "undefined", "null", "0"):
                return True
    return False


def _first_positionals(args: Node) -> list[Node]:
    return [a for a in args.children if a.type not in ("(", ",", ")", "comment")]


def _enclosing_scope(node: Node, root: Node) -> Node:
    cur = node.parent
    while cur is not None:
        if cur.type in _FUNCTION_TYPES:
            return cur
        cur = cur.parent
    return root


def _first_positional(args: Node) -> Node | None:
    for a in args.children:
        if a.type not in ("(", ",", ")", "comment"):
            return a
    return None


def _has_shell_dash_c(src: bytes, args: Node) -> bool:
    """An explicit shell invocation ``exec(SHELL, ['-c', <dynamic>])`` — the FIRST positional
    must be a shell (``bash``/``sh``/``cmd``/…), the SECOND must be an argv ARRAY containing a
    ``-c``/``/c`` flag AND a dynamic element (the command). This is precise: a ``-c`` flag on a
    non-shell program (``git -c``, ``ssh -c``), or a dynamic *option value* like ``{cwd: dir}``,
    does not match — only a dynamic command handed to a shell's ``-c``."""
    pos = _first_positionals(args)
    if len(pos) < 2:
        return False
    first = _text(src, pos[0]).strip("'\"`")
    if not any(s == first or s in first.split("'") or s in first.split('"') for s in _SHELL_NAMES):
        # allow a ternary/expr that names a shell, e.g. (win ? 'cmd' : 'bash')
        if not (pos[0].type in ("ternary_expression", "parenthesized_expression") and any(s in _text(src, pos[0]) for s in _SHELL_NAMES)):
            return False
    arr = pos[1]
    if arr.type != "array":
        return False
    arrtxt = _text(src, arr)
    if "-c" not in arrtxt and "/c" not in arrtxt:
        return False
    for el in arr.children:
        if el.type == "identifier" or el.type == "binary_expression" or (
            el.type == "template_string" and any(c.type == "template_substitution" for c in el.children)
        ):
            return True
    return False


def scan_js(source: str, uri: str, cve: str | None = None) -> list[dict]:
    src = source.encode("utf-8")
    root = _PARSER.parse(src).root_node
    results: list[dict] = []
    for node in _iter(root):
        if node.type != "call_expression":
            continue
        name = _call_name(src, node)
        if name not in _ALL_SINKS:
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        cmd = _first_positional(args)
        if cmd is None:
            continue
        shell_true = _has_shell_true(src, args)
        dynamic_cmd = _is_dynamic_string(cmd)
        # string-command sinks (exec/execSync): a dynamic command string is the injection;
        # argv sinks (spawn/execFile/foregroundChild): dangerous with shell:true or an
        # explicit `-c` shell invocation carrying a dynamic command.
        if name in _STRING_CMD_SINKS:
            flagged = dynamic_cmd or _has_shell_dash_c(src, args)
        else:
            flagged = shell_true or _has_shell_dash_c(src, args)
        if not flagged:
            continue
        scope = _enclosing_scope(node, root)
        if any(g in _text(src, scope) for g in _GUARDS):
            continue  # command escaped/sanitized in scope
        results.append(_result(uri, node.start_point[0] + 1, node.start_point[1] + 1,
                               f"OS command injection (CWE-78): dynamic input reaches shell-exec sink "
                               f"{name}(...){' with shell:true' if shell_true else ''}", cve))
    return results


# --- Python backend (subprocess/os.system with a shell) --------------------- #

_PY_SHELL_SINKS = frozenset({"system", "popen", "getoutput", "getstatusoutput"})  # os.*
_PY_SUBPROCESS = frozenset({"run", "call", "check_call", "check_output", "Popen"})
_PY_GUARDS = ("shlex.quote", "shlex_quote", "shell_quote", "quote(", "shell-escape", "sh_escape")


def _py_cmdi_name(call: ast.Call) -> str:
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")


def scan_python(source: str, uri: str, cve: str | None = None) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    def scope_text(node: ast.AST) -> str:
        best = None
        for f in funcs:
            if f.lineno <= node.lineno <= (getattr(f, "end_lineno", None) or f.lineno):
                if best is None or f.lineno > best.lineno:
                    best = f
        return (ast.get_source_segment(source, best) if best is not None else None) or source

    out: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _py_cmdi_name(node)
        first = node.args[0] if node.args else None
        dynamic_first = first is not None and not isinstance(first, ast.Constant)
        flagged = False
        if name in _PY_SUBPROCESS:
            # dangerous when shell=<truthy or non-literal>, i.e. present and not the
            # literal False (ansys CVE-2024-29189: shell=os.name != "nt").
            for kw in node.keywords:
                if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
                    flagged = True
        elif name in _PY_SHELL_SINKS:
            seg = ast.get_source_segment(source, node.func) or ""
            # os.system(...) or a bare system(...) from `from os import system`
            if name != "system" or "os" in seg or "from os import" in source:
                flagged = dynamic_first
        if not flagged:
            continue
        if any(g in scope_text(node) for g in _PY_GUARDS):
            continue  # shlex.quote / shell-escape applied in scope
        out.append(_result(uri, node.lineno, node.col_offset + 1,
                           f"OS command injection (CWE-78): shell execution via {name}(...) "
                           f"without escaping in scope", cve))
    return out


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    if uri.endswith(".py"):
        return scan_python(source, uri, cve)
    return scan_js(source, uri, cve)


def _result(uri: str, line: int, col: int, msg: str, cve: str | None) -> dict:
    props = {"cwe": GROUND_TRUTH_CWE}
    if cve:
        props["cve"] = cve
    return {"ruleId": RULE_ID, "level": "error", "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                          "region": {"startLine": line, "startColumn": col}}}],
            "properties": props}


def scan_file(path: str | Path, uri: str | None = None, cve: str | None = None) -> dict:
    p = Path(path)
    results = scan_source(p.read_text(encoding="utf-8"), uri=uri or p.name, cve=cve)
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "deepthought-cmdinj-rule",
                     "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                     "rules": [{"id": RULE_ID, "name": "ShellCommandInjection",
                               "shortDescription": {"text": "Dynamic input to a shell-exec sink (CWE-78)"},
                               "defaultConfiguration": {"level": "error"},
                               "helpUri": "https://cwe.mitre.org/data/definitions/78.html",
                               "properties": {"cwe": GROUND_TRUTH_CWE, "tags": ["security", "CWE-78", "command-injection"]}}]}},
                     "results": results}]}
