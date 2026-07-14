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
_JAVA_HARDENING = (
    "disallow-doctype-decl", "external-general-entities", "external-parameter-entities",
    "load-external-dtd", "SUPPORT_DTD", "IS_SUPPORTING_EXTERNAL_ENTITIES",
    "FEATURE_SECURE_PROCESSING", "ACCESS_EXTERNAL_DTD", "ACCESS_EXTERNAL_SCHEMA",
    "ACCESS_EXTERNAL_STYLESHEET", "setExpandEntityReferences", "setXIncludeAware",
)

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


def _java_scope_hardened(src: bytes, node: Node) -> bool:
    """Whether the parser's enclosing method (or, if none, the whole compilation unit)
    disables DTDs / external entities."""
    method = _enclosing_method(node)
    scope_text = _jtext(src, method) if method is not None else src.decode("utf-8", "replace")
    return any(tok in scope_text for tok in _JAVA_HARDENING)


def scan_java(source: str, uri: str, cve: str | None = None) -> list[dict]:
    src = source.encode("utf-8")
    root = _JPARSER.parse(src).root_node
    results: list[dict] = []
    seen: set[int] = set()
    for node in _jiter(root):
        factory = _java_factory_node(src, node)
        if factory is None or factory.start_point[0] in seen:
            continue
        if _java_scope_hardened(src, factory):
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


def scan_python(source: str, uri: str, cve: str | None = None) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    if "defusedxml" in source:
        return []  # module uses the safe-by-default library
    results: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _py_call_name(node) not in _PY_PARSER_CALLS:
            continue
        kwargs = {kw.arg for kw in node.keywords if kw.arg}
        # hardened if it passes resolve_entities=False / no_network=True / forbid_*
        hardened = False
        for kw in node.keywords:
            if kw.arg in _PY_HARDENING_KWARGS:
                val = kw.value
                # resolve_entities=False (safe) vs =True (unsafe); no_network=True (safe)
                if kw.arg == "resolve_entities" and isinstance(val, ast.Constant) and val.value is False:
                    hardened = True
                elif kw.arg in ("no_network", "forbid_dtd", "forbid_entities") and isinstance(val, ast.Constant) and val.value is True:
                    hardened = True
        if hardened:
            continue
        results.append(_result(uri, node.lineno, node.col_offset + 1,
                               f"XXE (CWE-611): lxml parser constructed without resolve_entities=False "
                               f"(external entities resolved on untrusted XML)", cve))
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
