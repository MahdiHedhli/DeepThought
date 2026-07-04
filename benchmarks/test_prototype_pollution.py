"""Class 1 of the vuln-rediscovery skill: prototype pollution (CWE-1321).

Three layers:
  * OFFLINE unit tests pin the DT-PP-MERGE rule's behaviour — it flags an unguarded
    write/delete by a dynamic, externally-derived key and skips the guarded shape,
    across the real sink variants (assignment and deletion) and their guards.
  * A REAL-PIPELINE test rediscovers the seed shape through the shipped
    ``sarif_to_findings`` + ``DiscoverSession`` (no benchmark-local finding builder),
    filing one CWE-1321 candidate that carries the seed CVE as an informational alias
    only — never an authoritative ``Finding.cve``.
  * A NETWORK-gated test measures held-out generalization on the REAL package files at
    their pinned vulnerable/patched SHAs (devalue, lodash, min-document). It is opt-in
    (``DEEPTHOUGHT_BENCHMARK_NET=1``) so a default run never touches the network.

Nothing here executes target code; the detector only parses source into an AST.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_javascript")  # the JS grammar the detector needs

from pp_detector import GROUND_TRUTH_CWE, RULE_ID, scan_file, scan_source  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "prototype_pollution.js"
FIXTURE_URI = "prototype_pollution.js"
MANIFEST = Path(__file__).parent / "corpus" / "prototype_pollution" / "manifest.json"
SEED_CVE = "CVE-2025-64718"


def _lines(results: list) -> set[int]:
    return {r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results}


# --------------------------------------------------------------------------- #
# offline: the rule discriminates vulnerable from patched
# --------------------------------------------------------------------------- #


def test_fixture_flags_the_vulnerable_write_and_skips_the_patched_one():
    src = FIXTURE.read_text()
    results = scan_source(src, FIXTURE_URI)
    assert len(results) == 1, [r["message"]["text"] for r in results]
    # the flagged sink is in mergeVulnerable, above the mergePatched definition
    flagged = min(_lines(results))
    patched_def = next(i for i, l in enumerate(src.splitlines(), 1) if "function mergePatched" in l)
    assert flagged < patched_def
    assert results[0]["properties"]["cwe"] == GROUND_TRUTH_CWE


WRITE_VULN = "function m(d,s){ for(const k in s){ d[k]=s[k]; } }"
DELETE_VULN = "function u(o,name){ delete o[name]; }"


@pytest.mark.parametrize(
    "src,expected",
    [
        # --- vulnerable shapes (flagged) ---
        (WRITE_VULN, 1),                                                   # for-in copy write
        ("function h(v){var o={};for(const k in v){o[k]=v[k];}return o;}", 1),  # devalue shape
        ("function b(o,p){return delete o[toKey(last(p))];}", 1),         # lodash delete shape
        (DELETE_VULN, 1),                                                  # min-document delete shape
        # --- guarded shapes (skipped) ---
        ("function m(d,s){for(const k in s){if(k==='__proto__')continue;d[k]=s[k];}}", 0),  # key compare
        ("function m(d,s){var B=['__proto__','constructor'];for(const k in s){if(B.includes(k))continue;d[k]=s[k];}}", 0),  # skiplist
        ("function sp(o,k,v){if(k==='__proto__'){Object.defineProperty(o,k,{value:v});}else{o[k]=v;}}", 0),  # defineProperty + compare
        ("function m(s){var o=Object.create(null);for(const k in s){o[k]=s[k];}return o;}", 0),  # null-proto target
        # --- precision: not prototype pollution (skipped) ---
        ("function fill(a){for(var i=0;i<a.length;i++){a[i]=0;}}", 0),     # numeric loop index
        ("function f(o){o['name']=1;o.count=2;}", 0),                      # fixed/static keys
        # object-specific guard: create(null) on ANOTHER var must NOT bless this sink
        ("function m(d,s){var safe=Object.create(null);for(const k in s){d[k]=s[k];}return d;}", 1),
        # --- review regressions (agy + codex adversarial PoCs) ---
        # an UNRELATED defineProperty must not bless every write to that object
        ("function m(obj,key,val){Object.defineProperty(obj,'x',{value:1});obj[key]=val;}", 1),
        # a skiplist on a DIFFERENT variable must not guard this key (whole-token match)
        ("function p(dest,src,safekey,key){var B=['__proto__'];if(B.includes(safekey))return;dest[key]=src[key];}", 1),
        # a stray proto string + a non-proto skiplist must not fake a guard (resolve receiver)
        ("function p(d,s,k){console.log('constructor');var a=['name'];if(a.includes(k))return;d[k]=s[k];}", 1),
        ("function m(d,s,ok){var B=['__proto__'];for(const k in s){if(B.includes(ok)){}d[k]=s[k];}}", 1),  # codex PoC
        # for..of loop var is externally derived (delete/static-RHS write still flagged)
        ("function c(dest,keys){for(const key of keys){dest[key]=true;}}", 1),
        # create(null) via ASSIGNMENT (not just declaration) is a valid guard
        ("function p(src,key){var dest;dest=Object.create(null);dest[key]=src[key];}", 0),
        # a top-level (non-function) sink is still a sink
        ("var k=getQ('k');destination[k]=source[k];", 1),
        # scope isolation (agy round 2): a NESTED function's guard/for-in must not leak
        # into the top-level scope's analysis
        ("function g(k){if(k==='__proto__')return;} var k=getQ('k'); destination[k]=source[k];", 1),  # nested guard doesn't cover top-level sink
        ("function u(){for(const k in obj){}} destination[k]=true;", 0),  # nested for-in doesn't derive top-level k
        # --- codex round 3 PoCs ---
        # an OBSERVE-only proto check (no break/else) does not block the sink
        ("function m(d,s){for(const k in s){if(k==='__proto__')console.log(k);d[k]=s[k];}}", 1),
        # an interpolated template index can still be __proto__
        ("function m(d,s,key){d[`${key}`]=s[key];}", 1),
        # Object.create(NON-null) is not a null-prototype target
        ("function m(s,key){var d=Object.create(proto);d[key]=s[key];}", 1),
        # but a blocking else-branch guard (the seed shape) IS recognized
        ("function sp(o,k,v){if(k==='__proto__'){Object.defineProperty(o,k,{value:v});}else{o[k]=v;}}", 0),
    ],
)
def test_rule_variants(src, expected):
    assert len(scan_source(src, "t.js")) == expected


# --------------------------------------------------------------------------- #
# the REAL pipeline: rediscover through the shipped DISCOVER, filing a candidate
# --------------------------------------------------------------------------- #


def test_full_pipeline_rediscovers_the_seed_shape(tmp_path):
    from deepthought.check import run_check
    from deepthought.export.osv import finding_to_osv, validate_osv
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.schema.finding import FindingStatus
    from deepthought.sessions import DiscoverSession, MapSession, NewProjectSession
    from deepthought.store import FileStore

    gate = HermesUltraCodeGate()
    store = FileStore(str(tmp_path / "state"))
    pid = "js-yaml-cve-2025-64718"
    root = tmp_path / "checkout"
    root.mkdir()
    (root / FIXTURE_URI).write_text(FIXTURE.read_text())

    reg = NewProjectSession(
        name="js-yaml prototype pollution",
        source_type="open_source",
        local_path=str(root),
        authorization_basis="permissive_oss",
        scope_allowlist=[FIXTURE_URI],
        project_id=pid,
        verify_url=lambda _u: True,
    )
    assert run_session(store, gate, reg).gate_outcome.value == "proceed"
    run_session(store, gate, MapSession(pid, root=str(root)))

    sarif_path = tmp_path / "pp.sarif"
    sarif_path.write_text(json.dumps(scan_file(root / FIXTURE_URI, uri=FIXTURE_URI, cve=SEED_CVE)))
    run_session(store, gate, DiscoverSession(pid, sarif_path=str(sarif_path), root=str(root)))

    findings = store.list_findings(project=pid)
    assert len(findings) == 1
    f = findings[0]
    assert f.status is FindingStatus.candidate
    assert f.cve is None                     # never authoritatively assigned by the analyzer
    assert SEED_CVE in f.aliases             # informational cross-reference only
    assert GROUND_TRUTH_CWE in f.body
    assert validate_osv(finding_to_osv(f)) == []
    assert run_check(store).ok, run_check(store).errors


# --------------------------------------------------------------------------- #
# held-out generalization on REAL pinned trees (opt-in; never on a default run)
# --------------------------------------------------------------------------- #


def _net() -> bool:
    if os.environ.get("DEEPTHOUGHT_BENCHMARK_NET") != "1":
        return False
    try:
        socket.create_connection(("raw.githubusercontent.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


requires_net = pytest.mark.skipif(
    not _net(), reason="held-out fetch needs DEEPTHOUGHT_BENCHMARK_NET=1 and network"
)


@requires_net
def test_heldout_generalization_on_real_pinned_trees():
    import sys

    sys.path.insert(0, str(Path(__file__).parent / "harness"))
    from corpus_measure import load_manifest, measure_entry, measure_heldout

    man = load_manifest(MANIFEST)
    # the seed itself must be rediscovered (calibration gate)
    assert measure_entry(man["seed"], scan_source)["rediscovered"], "seed not rediscovered"

    result = measure_heldout(man, scan_source, RULE_ID)
    # devalue + lodash generalize; min-document is the documented miss (hasOwnProperty
    # guard, indistinguishable from a benign check without control-flow polarity).
    assert result.rediscovered == 2
    assert result.missed_cves == ["CVE-2025-57352"]  # min-document
    assert result.generalization == round(2 / 3, 3)
