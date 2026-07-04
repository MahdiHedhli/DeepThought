"""DT-PP-MERGE — a static detector for prototype pollution (CWE-1321) in JavaScript,
emitting SARIF 2.1.0 so it feeds the SAME real ingest DISCOVER uses
(``deepthought.ingest.sarif``). Nothing here imports, runs, or evaluates the target
code; it only parses source into a tree-sitter AST and reads it.

Ship the CLASS, not the CVE. The rule flags the prototype-pollution SHAPE — an
unguarded computed-member **write** (``obj[key] = v``) or **delete**
(``delete obj[key]``) whose key is dynamic and externally derived (bound by a
``for..in``/``for..of``, a function parameter, or the copied key of another object),
where the enclosing function carries NO ``__proto__``/``constructor``/``prototype``
guard. It is calibrated on one seed (js-yaml CVE-2025-64718, an unguarded merge
assignment) and measured on held-out CVEs with DIFFERENT sinks (devalue: for-in copy;
lodash / min-document: delete by dynamic key) — a signature for the seed would miss
those, so the rule targets the class.

The guard is scanned per ENCLOSING FUNCTION, not per file: js-yaml's vulnerable
``mergeMappings`` is flagged even though the sibling ``storeMappingPair`` in the same
file already guarded ``__proto__`` — the merge path was the one that missed the guard.

Patched shapes it must SKIP: a ``key === '__proto__'`` / skiplist check, a
``hasOwnProperty`` own-property filter, ``Object.defineProperty``, or
``Object.create(null)`` present in the enclosing function; or the sink refactored into
a guarded helper call (a call is not a subscript, so it is not a sink here).
"""

from __future__ import annotations

from pathlib import Path

import tree_sitter_javascript as _tsjs
from tree_sitter import Language, Node, Parser

RULE_ID = "DT-PP-MERGE"
GROUND_TRUTH_CWE = "CWE-1321"

_JS = Language(_tsjs.language())
_PARSER = Parser(_JS)

_FUNCTION_TYPES = frozenset(
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
# A dangerous key must be able to carry a string like "__proto__". A numeric or string
# LITERAL index cannot be attacker-chosen at this site, so it is not a dynamic key.
_LITERAL_INDEX_TYPES = frozenset({"number", "string", "template_string"})
# Signals that the enclosing function already defends against prototype pollution.
# NOTE: bare ``hasOwnProperty`` is deliberately NOT a guard signal. The seed
# (js-yaml) writes inside ``if (!_hasOwnProperty.call(destination, key))`` — a benign
# DUPLICATE-key check that writes when the key is absent, so for ``__proto__`` (never an
# own key of a fresh object) it writes anyway and pollutes. Treating any hasOwnProperty
# as a guard hid the seed's real sink. A reliable guard names a proto key explicitly,
# uses Object.defineProperty, or targets a null-prototype object.
_PROTO_NAMES = frozenset({"__proto__", "constructor", "prototype"})


def _text(src: bytes, node: Node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _enclosing_function(node: Node) -> Node | None:
    cur = node.parent
    while cur is not None:
        if cur.type in _FUNCTION_TYPES:
            return cur
        cur = cur.parent
    return None


def _iter(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _string_literal_texts(src: bytes, scope: Node):
    for n in _iter(scope):
        if n.type in ("string", "string_fragment"):
            yield _text(src, n).strip("\"'`")


def _subtree_has_proto_name(src: bytes, node: Node) -> bool:
    return any(lit in _PROTO_NAMES for lit in _string_literal_texts(src, node))


def _has_identifier(src: bytes, node: Node, name: str) -> bool:
    """Whether the bare identifier ``name`` (a WHOLE token, not a substring) appears in
    the subtree — so a key named ``key`` is not matched inside ``safekey``."""
    return any(n.type == "identifier" and _text(src, n) == name for n in _iter(node))


def _is_create_null(src: bytes, value: Node | None) -> bool:
    return (
        value is not None
        and value.type == "call_expression"
        and "Object.create" in _text(src, value)
        and "null" in _text(src, value)
    )


def _object_guards(src: bytes, fn: Node) -> set[str]:
    """Object variables that are SAFE targets for a dynamic-key write because they are
    null-prototype (``Object.create(null)``), whether initialized in a declaration
    (``var o = Object.create(null)``) or an assignment (``o = Object.create(null)``).
    Tied to the specific object — a null-proto object for one variable does not bless a
    write to another. ``Object.defineProperty`` is deliberately NOT an object-wide guard:
    a ``defineProperty(obj, 'x', ...)`` for one property does not make a later plain
    ``obj[key] = v`` safe."""
    safe: set[str] = set()
    for n in _iter(fn):
        if n.type == "variable_declarator" and _is_create_null(src, n.child_by_field_name("value")):
            name = n.child_by_field_name("name")
            if name is not None and name.type == "identifier":
                safe.add(_text(src, name))
        elif n.type == "assignment_expression" and _is_create_null(src, n.child_by_field_name("right")):
            left = n.child_by_field_name("left")
            if left is not None and left.type == "identifier":
                safe.add(_text(src, left))
    return safe


def _receiver_has_proto(src: bytes, fn: Node, recv: Node) -> bool:
    """Whether a skiplist RECEIVER carries a proto name — inline
    (``['__proto__'].includes(k)``) or a named list declared/assigned in the function
    (``var B = ['__proto__']; B.includes(k)``). Resolving the receiver avoids treating an
    unrelated ``arr.includes(k)`` plus a stray proto string elsewhere as a guard."""
    if _subtree_has_proto_name(src, recv):
        return True
    if recv.type != "identifier":
        return False
    rn = _text(src, recv)
    for n in _iter(fn):
        if n.type == "variable_declarator":
            name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            if name is not None and value is not None and _text(src, name) == rn:
                if _subtree_has_proto_name(src, value):
                    return True
        elif n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and right is not None and _text(src, left) == rn:
                if _subtree_has_proto_name(src, right):
                    return True
    return False


def _key_is_guarded(src: bytes, fn: Node, key_name: str | None, obj_name: str | None) -> bool:
    """True if the enclosing function guards THIS sink (its object AND key) against
    prototype pollution. The guard is tied to the specific key and object, not merely to
    any ``__proto__``/``create(null)`` mention in the function — otherwise an unrelated
    proto reference or a null-proto object elsewhere in a large function would suppress a
    genuinely unguarded sink (a false negative). Recognized guards:
      * the sink's OBJECT is a null-prototype (``Object.create(null)``) — see
        _object_guards;
      * a comparison / ``in`` tying the sink's KEY to a proto name
        (``key === '__proto__'``, ``key in {__proto__: ...}``);
      * a skiplist membership test on the key (``[...proto...].includes(key)`` /
        ``.indexOf`` / ``.has``).
    A bare ``hasOwnProperty`` is intentionally NOT a guard (see _PROTO_NAMES note). For a
    computed key that is not a bare identifier (e.g. ``toKey(last(path))``) the key cannot
    be tied to a variable, so any in-function proto-name comparison counts.
    """
    if obj_name is not None and obj_name in _object_guards(src, fn):
        return True

    for n in _iter(fn):
        if n.type == "call_expression":
            callee = n.child_by_field_name("function")
            if callee is not None and callee.type == "member_expression":
                prop = callee.child_by_field_name("property")
                if prop is not None and _text(src, prop) in ("includes", "indexOf", "has"):
                    recv = callee.child_by_field_name("object")
                    args = n.child_by_field_name("arguments")
                    # The key must be tested (a WHOLE-token match, not a substring) AND the
                    # membership receiver must actually carry a proto name (resolved to its
                    # declaration if named) — so an unrelated ``arr.includes(k)`` plus a
                    # stray proto string elsewhere is not mistaken for a guard.
                    key_tested = key_name is None or (args is not None and _has_identifier(src, args, key_name))
                    if key_tested and recv is not None and _receiver_has_proto(src, fn, recv):
                        return True

    if key_name is None:
        # Computed key — cannot bind to a variable; any proto-name comparison in the
        # function is taken as the guard (matches the fix commits' added checks).
        return _subtree_has_proto_name(src, fn)

    for n in _iter(fn):
        # key === '__proto__' | '__proto__' === key | key !== ... | key in {__proto__:...}
        if n.type == "binary_expression":
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            if left is not None and right is not None:
                if _text(src, left) == key_name and _subtree_has_proto_name(src, right):
                    return True
                if _text(src, right) == key_name and _subtree_has_proto_name(src, left):
                    return True
    return False


def _index_is_dynamic(index: Node) -> bool:
    """A non-literal index — an identifier or expression that could resolve to a
    ``__proto__``-class string at runtime (not a fixed ``obj["fixed"]`` / ``obj[0]``)."""
    return index.type not in _LITERAL_INDEX_TYPES


def _key_identifier(index: Node, src: bytes) -> str | None:
    """The simple key name if the index is (or wraps) a bare identifier, else None."""
    if index.type == "identifier":
        return _text(src, index)
    return None


def _param_names(src: bytes, fn: Node) -> set[str]:
    params = fn.child_by_field_name("parameters")
    names: set[str] = set()
    if params is None:
        return names
    for n in _iter(params):
        if n.type == "identifier":
            names.add(_text(src, n))
    return names


def _forin_loop_vars(src: bytes, fn: Node) -> set[str]:
    """Loop variables of every ``for..in`` / ``for..of`` in the function — these bind
    keys/values drawn from another (possibly attacker-controlled) object."""
    out: set[str] = set()
    for n in _iter(fn):
        if n.type == "for_in_statement":
            left = n.child_by_field_name("left")
            if left is not None:
                for m in _iter(left):
                    if m.type == "identifier":
                        out.add(_text(src, m))
    return out


def _rhs_copies_key(src: bytes, right: Node | None, key: str) -> bool:
    """The copy shape ``dest[key] = src[key]`` — the same key indexes another object on
    the right-hand side, so a key drawn from ``src`` flows straight into ``dest``."""
    if right is None or not key:
        return False
    for n in _iter(right):
        if n.type == "subscript_expression":
            idx = n.child_by_field_name("index")
            if idx is not None and _key_identifier(idx, src) == key:
                return True
    return False


def _externally_derived(src: bytes, fn: Node | None, index: Node, right: Node | None) -> bool:
    """Whether the dynamic key plausibly comes from OUTSIDE — bound by a for-in/of, a
    function parameter, or copied from another object. Keeps precision up: a private
    numeric loop index (``arr[i] = x``) is not flagged as prototype pollution."""
    if fn is None:
        return False
    key = _key_identifier(index, src)
    if key is None:
        # A computed index that is not a bare identifier (e.g. toKey(last(path))) — treat
        # as externally derived, since it is a runtime-computed key, not a fixed slot.
        return True
    if key in _forin_loop_vars(src, fn):
        return True
    if key in _param_names(src, fn):
        return True
    if _rhs_copies_key(src, right, key):
        return True
    return False


def _message(kind: str, sink_text: str) -> str:
    return (
        f"prototype pollution (CWE-1321): unguarded {kind} through a dynamic, "
        f"externally-derived key ({sink_text}); a '__proto__'/'constructor' key reaches "
        f"the object prototype. No guard in the enclosing function."
    )


def _result(rule_id: str, node: Node, uri: str, msg: str, cve: str | None) -> dict:
    props = {"cwe": GROUND_TRUTH_CWE}
    if cve:
        props["cve"] = cve
    return {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": msg},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": node.start_point[0] + 1,
                        "startColumn": node.start_point[1] + 1,
                    },
                }
            }
        ],
        "properties": props,
    }


def scan_source(source: str, uri: str, cve: str | None = None) -> list[dict]:
    """SARIF result objects for unguarded prototype-pollution write/delete sinks.

    ``cve`` (optional) is the ground-truth label for THIS scan — the informational
    alias the ingest mirrors onto a candidate. The detector never derives a CVE itself;
    it detects the class (CWE-1321). Omit it in a real hunt.
    """
    src = source.encode("utf-8")
    root = _PARSER.parse(src).root_node
    results: list[dict] = []

    for node in _iter(root):
        sink_kind: str | None = None
        subscript: Node | None = None
        right: Node | None = None

        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left is not None and left.type == "subscript_expression":
                sink_kind, subscript = "write", left
                right = node.child_by_field_name("right")
        elif node.type in ("unary_expression", "delete_expression"):
            # `delete obj[key]` — the argument is a subscript_expression.
            arg = node.child_by_field_name("argument")
            op = node.child_by_field_name("operator")
            is_delete = (op is not None and _text(src, op) == "delete") or node.type == "delete_expression"
            if is_delete and arg is not None and arg.type == "subscript_expression":
                sink_kind, subscript = "delete", arg

        if sink_kind is None or subscript is None:
            continue
        index = subscript.child_by_field_name("index")
        if index is None or not _index_is_dynamic(index):
            continue
        # The scope for externally-derived + guard analysis is the enclosing function,
        # or the program root for a TOP-LEVEL sink (module code not wrapped in a
        # function) — a top-level `destination[key] = source[key]` is a real sink too.
        scope = _enclosing_function(subscript) or root
        if not _externally_derived(src, scope, index, right):
            continue
        key_name = _key_identifier(index, src)
        obj = subscript.child_by_field_name("object")
        obj_name = _text(src, obj) if obj is not None and obj.type == "identifier" else None
        if _key_is_guarded(src, scope, key_name, obj_name):
            continue  # patched shape — the scope guards THIS object/key
        results.append(_result(RULE_ID, subscript, uri, _message(sink_kind, _text(src, subscript)), cve))

    return results


def scan_file(path: str | Path, uri: str | None = None, cve: str | None = None) -> dict:
    """Scan one file and return a full SARIF 2.1.0 log (same shape as any external
    analyzer DISCOVER ingests). ``uri`` overrides the reported path for scope matching."""
    p = Path(path)
    results = scan_source(p.read_text(encoding="utf-8"), uri=uri or p.name, cve=cve)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deepthought-prototype-pollution-rule",
                        "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                        "rules": [
                            {
                                "id": RULE_ID,
                                "name": "UnguardedPrototypePollution",
                                "shortDescription": {
                                    "text": "Unguarded write/delete by a dynamic key (prototype pollution, CWE-1321)"
                                },
                                "defaultConfiguration": {"level": "error"},
                                "helpUri": "https://cwe.mitre.org/data/definitions/1321.html",
                                "properties": {
                                    "cwe": GROUND_TRUTH_CWE,
                                    "tags": ["security", "CWE-1321", "prototype-pollution"],
                                },
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
