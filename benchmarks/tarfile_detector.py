"""A small static detector for the CVE-2007-4559 pattern, emitting SARIF 2.1.0.

It flags a call to ``.extractall(...)`` or ``.extract(...)`` that has no
``filter=`` keyword. The filter argument is the 3.12 mitigation (PEP 706), so a
call without it is the vulnerable shape and a call with it is the fixed shape.
This is the same heuristic Bandit's tarfile check and common Semgrep rules use,
and it is enough to distinguish vulnerable from patched for the benchmark.

Output is SARIF 2.1.0 so it feeds the **same real ingest** DISCOVER uses for any
external analyzer (``deepthought.ingest.sarif``). The rule and each result carry
``cwe: CWE-22`` and ``cve: CVE-2007-4559`` in ``properties`` — the ingest copies a
validated CVE onto the candidate finding (mirrored into OSV aliases) and the CWE
into the finding body. Nothing here imports, calls, or executes the target code;
it only parses source into an AST and reads it.
"""

from __future__ import annotations

import ast
from pathlib import Path

RULE_ID = "DT-TARFILE-EXTRACTALL"
GROUND_TRUTH_CVE = "CVE-2007-4559"
GROUND_TRUTH_CWE = "CWE-22"
_SINKS = {"extractall", "extract"}


def _has_filter_kwarg(call: ast.Call) -> bool:
    return any(kw.arg == "filter" for kw in call.keywords)


def scan_source(source: str, uri: str) -> list[dict]:
    """Return SARIF result objects for unsanitized extraction sinks."""
    tree = ast.parse(source)
    results: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in _SINKS:
            continue
        if _has_filter_kwarg(node):
            continue  # patched shape — the extraction filter is present
        results.append(
            {
                "ruleId": RULE_ID,
                "level": "error",
                "message": {
                    "text": (
                        "unsanitized tar member path passed to "
                        f"{func.attr}, enables directory traversal (CVE-2007-4559)"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {
                                "startLine": node.lineno,
                                "startColumn": node.col_offset + 1,
                            },
                        }
                    }
                ],
                "properties": {"cwe": GROUND_TRUTH_CWE, "cve": GROUND_TRUTH_CVE},
            }
        )
    return results


def scan_file(path: str | Path, uri: str | None = None) -> dict:
    """Scan one file and return a full SARIF 2.1.0 log.

    ``uri`` overrides the reported artifact path (default: the file name), so a
    caller can report a path relative to a project root for scope matching.
    """
    p = Path(path)
    results = scan_source(p.read_text(encoding="utf-8"), uri=uri or p.name)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deepthought-tarfile-rule",
                        "informationUri": "https://github.com/MahdiHedhli/DeepThought",
                        "rules": [
                            {
                                "id": RULE_ID,
                                "name": "UnsanitizedTarExtraction",
                                "shortDescription": {
                                    "text": "Unsanitized tar extraction (CVE-2007-4559)"
                                },
                                "defaultConfiguration": {"level": "error"},
                                "helpUri": "https://www.trellix.com/blogs/research/tarfile-exploiting-the-world/",
                                "properties": {
                                    "cwe": GROUND_TRUTH_CWE,
                                    "cve": GROUND_TRUTH_CVE,
                                    "tags": ["security", "CWE-22", "path-traversal"],
                                },
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
