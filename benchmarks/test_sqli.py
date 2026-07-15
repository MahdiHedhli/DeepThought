"""Round 3 SQL-injection class (CWE-89), Python + PHP + Velocity, static-only."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_php")

from sqli_detector import GROUND_TRUTH_CWE, RULE_ID, scan_file, scan_source  # noqa: E402

FIX_PY = Path(__file__).parent / "fixtures" / "sqli.py"
FIX_PHP = Path(__file__).parent / "fixtures" / "sqli.php"
FIX_VM = Path(__file__).parent / "fixtures" / "sqli.vm"
MANIFEST = Path(__file__).parent / "corpus" / "sql_injection" / "manifest.json"
SEED_CVE = "CVE-2022-41892"


def test_fixtures_discriminate_bound_values_from_sql_syntax():
    assert len(scan_file(FIX_PY)["runs"][0]["results"]) == 1
    assert len(scan_file(FIX_PHP)["runs"][0]["results"]) == 2
    assert len(scan_file(FIX_VM)["runs"][0]["results"]) == 1


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "def f(request,cursor):\n"
            " q=request.GET.get('q','')\n"
            " sql=\"SELECT value FROM values WHERE value='{q}'\"\n"
            " sql=sql.format(q=q)\n"
            " cursor.execute(sql)",
            1,
        ),
        ("def f(request,cursor): cursor.execute(f\"SELECT * FROM t WHERE x='{request.GET['x']}'\")", 1),
        ("def f(value,cursor): cursor.execute(\"SELECT * FROM t WHERE x='%s'\" % value)", 1),
        ("def f(value,cursor): cursor.execute(\"SELECT * FROM t WHERE x='\" + value + \"'\")", 1),
        (
            "def f(request,cursor):\n"
            " cursor.execute('SELECT * FROM t WHERE x=%(x)s', {'x': request.GET['x']})",
            0,
        ),
        ("def f(cursor): cursor.execute('SELECT 1')", 0),
        ("def f(cursor):\n sql='SELECT 1'\n cursor.execute(sql)", 0),
        # A params argument protects values only; it cannot protect a dynamic identifier.
        ("def f(table,cursor): cursor.execute('SELECT * FROM '+table+' WHERE id=%s', (1,))", 1),
        # A sanitizer-like call elsewhere in the scope cannot bless this query.
        (
            "def f(user,other,cursor,quote):\n"
            " safe=quote(other)\n"
            " cursor.execute(\"SELECT * FROM t WHERE name='\"+user+\"'\")",
            1,
        ),
        # Nested scopes do not exchange guard facts.
        (
            "def outer(value,cursor):\n"
            " def inner(x): return int(x)\n"
            " cursor.execute('SELECT * FROM t WHERE x='+value)",
            1,
        ),
        ("# cursor.execute('SELECT '+request.GET['x'])\ndef f(cursor): cursor.execute('SELECT 1')", 0),
    ],
)
def test_python_rule_variants(source, expected):
    assert len(scan_source(source, "a.py")) == expected


@pytest.mark.parametrize(
    "source,expected",
    [
        ("<?php function f($id){ return $this->db->query('SELECT * FROM t WHERE id=' . $id); }", 1),
        ("<?php function f($id){ return $this->db->query('SELECT * FROM t WHERE id=' . (int)$id); }", 0),
        ("<?php function f($id){ return $this->db->query('SELECT * FROM t WHERE id=' . intval($id)); }", 0),
        ("<?php function f($id){ return db_fetch_assoc_prepared('SELECT * FROM t WHERE id=?', [$id]); }", 0),
        (
            "<?php function f($filter){ $sql=' HAVING ('; "
            "$sql .= 'name LIKE ' . db_qstr('%' . $filter . '%'); return $sql; }",
            0,
        ),
        (
            "<?php function f($filter,$other){ $safe=db_qstr($other); $sql=' HAVING ('; "
            "$sql .= 'name LIKE \"%' . $filter . '%\"'; return $sql; }",
            1,
        ),
        (
            "<?php function f($rule,$filter){ $fields=get_field_names($rule['id']); $sql_having=' HAVING ('; "
            "foreach($fields as $column){ $sql_having .= '`' . $column['field_name'] . '` LIKE \"%' . $filter . '%\"'; } "
            "return $sql_having; }",
            1,
        ),
        ("<?php function f($name){ $message='hello '.$name; return $message; }", 0),
        ("<?php /* $db->query('SELECT '.$_GET['x']); */ function f(){ return 'ok'; }", 0),
        # Report the database sink once; do not duplicate it as a returned fragment.
        (
            "<?php function f($id,$db){ $sql='SELECT * FROM t WHERE id=' . $id; return $db->query($sql); }",
            1,
        ),
    ],
)
def test_php_rule_variants(source, expected):
    assert len(scan_source(source, "a.php")) == expected


def test_php_builder_reports_the_unsafe_append_not_a_later_constant_suffix():
    source = """<?php function f($filter) {
  $sql = ' HAVING (';
  $sql .= 'name LIKE \"%' . $filter . '%\"';
  $sql .= ')';
  return $sql;
}"""
    results = scan_source(source, "a.php")
    assert len(results) == 1
    line = results[0]["locations"][0]["physicalLocation"]["region"]["startLine"]
    assert line == 3
    assert "$filter" in source.splitlines()[line - 1]


@pytest.mark.parametrize(
    "source,expected",
    [
        ('#set ($order = "$!request.sort")\n#set ($sql = "order by ${order}")', 1),
        ('#set ($order = "ddoc.fullName")\n#set ($sql = "order by ${order}")', 0),
        ('#set ($where = "where ddoc.batchId = ?1")', 0),
        ('## #set ($sql = "order by $request.sort")', 0),
        ('#* #set ($sql = "order by $request.sort") *#', 0),
        (
            '#set ($dir = "$!request.dir")\n'
            '#if ("$!dir" != "" && "$!dir" != "asc")\n'
            "  #set ($dir = 'desc')\n"
            '#end\n#set ($sql = "order by ddoc.fullName ${dir}")',
            0,
        ),
    ],
)
def test_velocity_rule_variants(source, expected):
    assert len(scan_source(source, "a.vm")) == expected


def test_xwiki_validator_reordering_remains_a_documented_static_limit():
    before = """#set ($order = "$!request.sort")
#if ($order != '')
  #set($discard = $services.query.hql.checkOrderBySafe(['ddoc.'], $order))
  #if ($order == 'doc.location')
    #set ($order = 'ddoc.fullName')
  #end
  #set ($orderQueryPart = "order by ${order} asc")
#end"""
    after = """#set ($order = "$!request.sort")
#if ($order != '')
  #if ($order == 'doc.location')
    #set ($order = 'ddoc.fullName')
  #end
  #set($discard = $services.query.hql.checkOrderBySafe(['ddoc.'], $order))
  #set ($orderQueryPart = "order by ${order} asc")
#end"""
    assert len(scan_source(before, "getdeleteddocuments.vm")) == 1
    assert len(scan_source(after, "getdeleteddocuments.vm")) == 1


def test_manifest_has_exact_pinned_cohort_and_explicit_deleted_target():
    manifest = json.loads(MANIFEST.read_text())
    assert manifest["seed"]["cve"] == SEED_CVE
    assert [entry["cve"] for entry in manifest["heldout"]] == [
        "CVE-2024-21514",
        "CVE-2024-31445",
        "CVE-2025-32429",
    ]
    opencart = manifest["heldout"][0]
    assert opencart["patched_absent_paths"] == opencart["target_paths"]


def test_full_pipeline_rediscovers_the_seed_shape(tmp_path):
    from deepthought.check import run_check
    from deepthought.export.osv import finding_to_osv, validate_osv
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.schema.finding import FindingStatus
    from deepthought.sessions import DiscoverSession, MapSession, NewProjectSession
    from deepthought.store import FileStore

    store = FileStore(str(tmp_path / "state"))
    gate = HermesUltraCodeGate()
    root = tmp_path / "checkout"
    root.mkdir()
    uri = FIX_PY.name
    (root / uri).write_text(FIX_PY.read_text())
    project_id = "arches-cve-2022-41892"

    registration = NewProjectSession(
        name="Arches SQL injection",
        source_type="open_source",
        local_path=str(root),
        authorization_basis="permissive_oss",
        scope_allowlist=[uri],
        project_id=project_id,
        verify_url=lambda _url: True,
    )
    assert run_session(store, gate, registration).gate_outcome.value == "proceed"
    run_session(store, gate, MapSession(project_id, root=str(root)))
    sarif = tmp_path / "sqli.sarif"
    sarif.write_text(json.dumps(scan_file(root / uri, uri=uri, cve=SEED_CVE)))
    run_session(store, gate, DiscoverSession(project_id, sarif_path=str(sarif), root=str(root)))

    findings = store.list_findings(project=project_id)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.status is FindingStatus.candidate
    assert finding.cve is None
    assert SEED_CVE in finding.aliases
    assert GROUND_TRUTH_CWE in finding.body
    assert validate_osv(finding_to_osv(finding)) == []
    assert run_check(store).ok, run_check(store).errors


def _network_enabled() -> bool:
    if os.environ.get("DEEPTHOUGHT_BENCHMARK_NET") != "1":
        return False
    try:
        socket.create_connection(("raw.githubusercontent.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _network_enabled(), reason="real-tree measurement needs explicit network opt-in")
def test_heldout_generalization_on_real_pinned_trees():
    import sys

    sys.path.insert(0, str(Path(__file__).parent / "harness"))
    from corpus_measure import load_manifest, measure_entry, measure_heldout

    manifest = load_manifest(MANIFEST)
    assert measure_entry(manifest["seed"], scan_source)["rediscovered"]
    result = measure_heldout(manifest, scan_source, RULE_ID)
    assert result.rediscovered == 2
    assert result.missed_cves == ["CVE-2025-32429"]
    assert result.generalization == round(2 / 3, 3)
