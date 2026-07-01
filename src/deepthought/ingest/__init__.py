"""Ingest — untrusted, read-only tool output into candidate findings.

The Improbability Drive (feature 002) consumes results a static-analysis tool
already produced. SARIF is the first such input. Everything in this package
treats its input as *data*, never as instruction (Constitution VIII): a SARIF
string is only ever copied into a data field, and a ``ruleId`` becomes a key
into a closed lookup table, never a capability directly.
"""

from .sarif import load_sarif, sarif_to_findings, sarif_to_primitives

__all__ = ["load_sarif", "sarif_to_findings", "sarif_to_primitives"]
