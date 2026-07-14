"""DT-XXE-PARSER — a static config detector for XML External Entity injection
(CWE-611), emitting SARIF 2.1.0 into the SAME real ingest DISCOVER uses
(``deepthought.ingest.sarif``). It parses source into an AST and reads it; nothing
here imports, runs, or evaluates the target code.

XXE is a CONFIGURATION class: an XML parser used on untrusted input with DTDs /
external entities left ENABLED. The rule is multi-language because the class is:

  * Java (tree-sitter): an XML-parser factory is constructed
    (``XMLInputFactory.newFactory()``, ``DocumentBuilderFactory.newInstance()``,
    ``SAXParserFactory.newInstance()``, ``new SAXReader()``, ``createXMLReader()`` …)
    and the ENCLOSING METHOD does not disable DTDs / external entities (no
    ``SUPPORT_DTD``=false, ``disallow-doctype-decl``, ``external-general-entities``,
    ``FEATURE_SECURE_PROCESSING``, ``ACCESS_EXTERNAL_DTD`` …). The seed, Apache Tika
    CVE-2025-66516, is exactly this: ``XMLInputFactory.newFactory()`` in
    ``getXMLInputFactory()``; the fix adds ``SUPPORT_DTD``/``IS_SUPPORTING_EXTERNAL_
    ENTITIES`` = false in that method.

  * Python (ast): an lxml parser (``etree.XMLParser(...)`` / ``etree.parse`` /
    ``fromstring``) is constructed WITHOUT ``resolve_entities=False`` (or ``no_network``),
    and the module does not use ``defusedxml``. python-docx CVE-2016-5851 is this: the
    fix adds ``resolve_entities=False`` to the ``etree.XMLParser`` call.

Calibrated on the Tika (Java) seed; measured on held-out Java and Python CVEs.
"""

from __future__ import annotations

import ast
from pathlib import Path

import tree_sitter_java as _tsjava
from tree_sitter import Language, Node, Parser

RULE_ID = "DT-XXE-PARSER"
GROUND_TRUTH_CWE = "CWE-611"

_JAVA = Language(_tsjava.language())
_JPARSER = Parser(_JAVA)

# Java: constructing one of these is constructing an XML parser over (untrusted) input.
_JAVA_FACTORY_METHODS = frozenset({"newFactory", "newInstance", "newDefaultInstance", "createXMLReader"})
_JAVA_FACTORY_TYPES = frozenset(
    {
        "XMLInputFactory", "DocumentBuilderFactory", "SAXParserFactory",
        "TransformerFactory", "SchemaFactory", "XMLReaderFactory", "SAXReader",
    }
)
_JAVA_CTOR_TYPES = frozenset({"SAXReader", "SAXBuilder"})  # `new SAXReader()` etc.

# Java: any of these tokens in the enclosing method means the parser is hardened —
# i.e. DTDs / external entities are actually DISABLED. Deliberately NOT included:
#  * IGNORING_STAX_ENTITY_RESOLVER — a partial StAX mitigation that the Tika seed already
#    had in its VULNERABLE version (the fix still had to add SUPPORT_DTD=false), so it does
#    not by itself harden the parser;
#  * a method name like createDefault — a name, not a hardening API call.

# Python: constructing one of these builds an XML parser.
_PY_PARSER_CALLS = frozenset({"XMLParser", "ETCompatXMLParser", "make_parser"})
# Python hardening kwargs / markers.
_PY_HARDENING_KWARGS = frozenset({"resolve_entities", "no_network", "forbid_dtd", "forbid_entities"})


# ---------------------------------------------------------------------------- #
# Java
# ---------------------------------------------------------------------------- #


def _jtext(src: bytes, node: Node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _jiter(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _enclosing_method(node: Node) -> Node | None:
    cur = node.parent
    while cur is not None:
        if cur.type in ("method_declaration", "constructor_declaration"):
            return cur
        cur = cur.parent
    return None


def _java_factory_node(src: bytes, node: Node) -> Node | None:
    """The parser-construction node if this is an XML-parser factory call/ctor, else None."""
    if node.type == "method_invocation":
        name = node.child_by_field_name("name")
        obj = node.child_by_field_name("object")
        if name is not None and _jtext(src, name) in _JAVA_FACTORY_METHODS:
            # the receiver's rightmost identifier is the factory type
            recv = _jtext(src, obj) if obj is not None else ""
            tail = recv.split(".")[-1] if recv else ""
            if tail in _JAVA_FACTORY_TYPES or _jtext(src, name) == "createXMLReader":
                return node
    if node.type == "object_creation_expression":
        t = node.child_by_field_name("type")
        if t is not None and _jtext(src, t).split(".")[-1] in _JAVA_CTOR_TYPES:
            return node
    return None


def _java_call_hardens(src: bytes, call: Node) -> bool:
    """Whether a single call actually DISABLES DTDs/external entities — argument-sensitive,
    so ``setProperty(SUPPORT_DTD, true)`` (which ENABLES DTDs) is not mistaken for
    hardening, and a bare token in a comment/log string never matches (only real calls are
    inspected). Pairs each feature with the value that makes it safe."""
    txt = _jtext(src, call)
    # DTD/external-entity feature flags are safe only when set to false.
    if any(t in txt for t in ("SUPPORT_DTD", "IS_SUPPORTING_EXTERNAL_ENTITIES",
                              "external-general-entities", "external-parameter-entities",
                              "load-external-dtd")) and "false" in txt:
        return True
    # These are safe only when set to true.
    if any(t in txt for t in ("disallow-doctype-decl", "FEATURE_SECURE_PROCESSING")) and "true" in txt:
        return True
    if "setExpandEntityReferences" in txt and "false" in txt:
        return True
    if "setXIncludeAware" in txt and "false" in txt:
        return True
    # ACCESS_EXTERNAL_* are safe when set to the empty string.
    if any(t in txt for t in ("ACCESS_EXTERNAL_DTD", "ACCESS_EXTERNAL_SCHEMA",
                              "ACCESS_EXTERNAL_STYLESHEET")) and ('""' in txt or "''" in txt):
        return True
    return False


def _java_scope_hardened(src: bytes, node: Node, root: Node) -> bool:
    """Whether the parser's enclosing method (or, if none, the whole compilation unit)
    contains a real DTD/external-entity DISABLING call. Scope is the method — hardening
    factored into a separate helper is not seen (an interprocedural limitation, a possible
    false positive, documented) and per-variable binding is not modeled (two parsers in one
    method share the verdict)."""
    scope = _enclosing_method(node) or root
    for n in _jiter(scope):
        if n.type == "method_invocation" and _java_call_hardens(src, n):
            return True
    return False


def scan_java(source: str, uri: str, cve: str | None = None) -> list[dict]:
    src = source.encode("utf-8")
    root = _JPARSER.parse(src).root_node
    results: list[dict] = []
    seen: set[int] = set()
    for node in _jiter(root):
        factory = _java_factory_node(src, node)
        if factory is None or factory.start_point[0] in seen:
            continue
        if _java_scope_hardened(src, factory, root):
            continue  # hardened parser — DTDs/external entities disabled in scope
        seen.add(factory.start_point[0])
        results.append(_result(uri, factory.start_point[0] + 1, factory.start_point[1] + 1,
                               f"XXE (CWE-611): XML parser {_jtext(src, factory)[:60]!r} constructed "
                               f"without disabling DTDs/external entities in its scope", cve))
    return results


# ---------------------------------------------------------------------------- #
# Python
# ---------------------------------------------------------------------------- #


def _py_call_name(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


_PY_SAX_HARDENING = ("external-general-entities", "external-parameter-entities",
                     "feature_external_ges", "feature_external_pes", "load-external-dtd")


def scan_python(source: str, uri: str, cve: str | None = None) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    def scope_text(node: ast.AST) -> str:
        """The source of the SMALLEST function enclosing node, else the whole module —
        so SAX setFeature hardening is bound to THIS parser's function, not any make_parser
        elsewhere in the module (a module-wide check masked unrelated unhardened parsers)."""
        best = None
        for f in funcs:
            if f.lineno <= node.lineno <= (getattr(f, "end_lineno", None) or f.lineno):
                if best is None or f.lineno > best.lineno:
                    best = f
        return (ast.get_source_segment(source, best) if best is not None else None) or source

    results: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _py_call_name(node) not in _PY_PARSER_CALLS:
            continue
        # A defusedxml-qualified parser is safe — but only THIS call, not the whole module
        # (a mixed module using defusedxml on one path and raw lxml on another is common).
        func_seg = ast.get_source_segment(source, node.func) or ""
        if "defusedxml" in func_seg:
            continue
        hardened = False
        for kw in node.keywords:
            if kw.arg not in _PY_HARDENING_KWARGS or not isinstance(kw.value, ast.Constant):
                continue
            # resolve_entities safe when FALSY (False/0); no_network/forbid_* safe when TRUTHY.
            if kw.arg == "resolve_entities" and not kw.value.value:
                hardened = True
            elif kw.arg in ("no_network", "forbid_dtd", "forbid_entities") and kw.value.value:
                hardened = True
        # SAX/xml parsers hardened via setFeature(...external...) on the parser object — bound
        # to the enclosing function's source, not the whole module.
        if not hardened and any(m in scope_text(node) for m in _PY_SAX_HARDENING):
            hardened = True
        if hardened:
            continue
        results.append(_result(uri, node.lineno, node.col_offset + 1,
                               f"XXE (CWE-611): XML parser constructed without disabling external "
                               f"entities (resolved on untrusted XML)", cve))
    return results


# ---------------------------------------------------------------------------- #
# shared SARIF
# ---------------------------------------------------------------------------- #


def _result(uri: str, line: int, col: int, msg: str, cve: str | None) -> dict:
    props = {"cwe": GROUND_TRUTH_CWE}
    if cve:
        props["cve"] = cve
    return {
        "ruleId": RULE_ID,
        "level": "error",
        "message": {"text": msg},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line, "startColumn": col},
        }}],
        "properties": props,
    }


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    """Dispatch by file extension: .java -> Java backend, else Python."""
    if uri.endswith(".java"):
        return scan_java(source, uri, cve)
    return scan_python(source, uri, cve)


def scan_file(path: str | Path, uri: str | None = None, cve: str | None = None) -> dict:
    p = Path(path)
    u = uri or p.name
    results = scan_source(p.read_text(encoding="utf-8"), uri=u, cve=cve)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "deepthought-xxe-rule",
                "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                "rules": [{
                    "id": RULE_ID, "name": "UnhardenedXMLParser",
                    "shortDescription": {"text": "XML parser without DTD/external-entity hardening (XXE, CWE-611)"},
                    "defaultConfiguration": {"level": "error"},
                    "helpUri": "https://cwe.mitre.org/data/definitions/611.html",
                    "properties": {"cwe": GROUND_TRUTH_CWE, "tags": ["security", "CWE-611", "xxe"]},
                }],
            }},
            "results": results,
        }],
    }
