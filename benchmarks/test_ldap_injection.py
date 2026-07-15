"""LDAP-filter injection class (CWE-90), static-only across Java/Python/PHP."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_java")
pytest.importorskip("tree_sitter_php")

from ldapinj_detector import GROUND_TRUTH_CWE, RULE_ID, scan_file, scan_source  # noqa: E402

FIXTURE_JAVA = Path(__file__).parent / "fixtures" / "ldap_injection.java"
FIXTURE_PYTHON = Path(__file__).parent / "fixtures" / "ldap_injection.py"
FIXTURE_PHP = Path(__file__).parent / "fixtures" / "ldap_injection.php"
MANIFEST = Path(__file__).parent / "corpus" / "ldap_injection" / "manifest.json"
SEED_CVE = "CVE-2026-42568"


def _lines(results: list[dict]) -> list[int]:
    return [r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results]


def test_language_fixtures_each_flag_only_the_unescaped_filter():
    expected_markers = {
        FIXTURE_JAVA: "userFilter.replace(\"{0}\", username)",
        FIXTURE_PYTHON: 'filter_str = f"(uid={username})"',
        FIXTURE_PHP: "return $ldap->simple_search(",
    }
    for fixture, marker in expected_markers.items():
        source = fixture.read_text()
        results = scan_source(source, fixture.name)
        assert len(results) == 1, (fixture, [r["message"]["text"] for r in results])
        assert marker in source.splitlines()[_lines(results)[0] - 1]
        assert results[0]["properties"]["cwe"] == GROUND_TRUTH_CWE


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "import javax.naming.directory.*; class A { void f(DirContext ctx, String base, "
            "String username, SearchControls c) throws Exception { "
            'ctx.search(base, "(uid=" + username + ")", c); } }',
            1,
        ),
        (
            "import javax.naming.directory.*; class A { void f(DirContext ctx, String base, "
            "String username, SearchControls c) throws Exception { "
            'ctx.search(base, "(uid=" + org.springframework.ldap.support.LdapEncoder.filterEncode(username) + ")", c); } }',
            0,
        ),
        # A sanitizer assignment after the search cannot retroactively protect it.
        (
            "import javax.naming.directory.*; class A { void f(DirContext ctx, String base, "
            "String username, SearchControls c) throws Exception { "
            'ctx.search(base, "(uid=" + username + ")", c); '
            "username = org.springframework.ldap.support.LdapEncoder.filterEncode(username); } }",
            1,
        ),
        # The same reassignment is safe when it precedes the search.
        (
            "import javax.naming.directory.*; class A { void f(DirContext ctx, String base, "
            "String username, SearchControls c) throws Exception { "
            "username = org.springframework.ldap.support.LdapEncoder.filterEncode(username); "
            'ctx.search(base, "(uid=" + username + ")", c); } }',
            0,
        ),
        # DN escaping is not RFC 4515 search-filter escaping.
        (
            "import javax.naming.directory.*; import javax.naming.ldap.Rdn; class A { "
            "void f(DirContext ctx, String base, String username, SearchControls c) throws Exception { "
            'ctx.search(base, "(uid=" + Rdn.escapeValue(username) + ")", c); } }',
            1,
        ),
        # Local wrapper summary: parameter 2 reaches DirContext.search's filter argument.
        (
            "import javax.naming.directory.*; class A { "
            "void f(DirContext ctx,String b,String username,SearchControls c)throws Exception { "
            'var filter = "(uid=" + username + ")"; lookup(ctx,b,filter,c); } '
            "void lookup(DirContext ctx,String b,String filter,SearchControls c)throws Exception { "
            "ctx.search(b,filter,c); } }",
            1,
        ),
        # A generic search API is not LDAP, even if its query is dynamic.
        ('class A { void f(Index index, String user) { index.search("(uid=" + user + ")"); } }', 0),
        # Comments and log strings never become AST sinks.
        (
            "import javax.naming.directory.*; class A { void f(String username) { "
            'System.out.println("ctx.search(base, (uid=" + username + "), controls)"); } }',
            0,
        ),
    ],
)
def test_java_rule_variants(source, expected):
    assert len(scan_source(source, "A.java")) == expected


def test_java_review_regressions_provenance_mixed_values_overloads_and_branches():
    mixed = (
        "import javax.naming.directory.*; class A { void f(DirContext dc, String base, "
        "String username, SearchControls c) throws Exception { dc.search(base, "
        '"(uid=" + org.springframework.ldap.support.LdapEncoder.filterEncode(username) + username + ")", c); } }'
    )
    typed_client = (
        "import javax.naming.directory.*; class A { void f(DirContext client, String base, "
        "String username, SearchControls c) throws Exception { "
        'client.search(base, "(uid=" + username + ")", c); } }'
    )
    unrelated = (
        "import javax.naming.directory.*; class A { void f(Index context, String username) { "
        'context.search("(uid=" + username + ")", null, null); } }'
    )
    no_op_sanitizer = (
        "import javax.naming.directory.*; class A { void f(DirContext dc, String base, "
        "String username, SearchControls c) throws Exception { "
        'dc.search(base, "(uid=" + escapeLdapFilter(username) + ")", c); } '
        "String escapeLdapFilter(String value) { return value; } }"
    )
    overloads = (
        "import javax.naming.directory.*; class A { "
        "void f(DirContext dc,String b,String username,SearchControls c)throws Exception { "
        'String filter = "(uid=" + username + ")"; lookup(dc,b,filter,c); lookup("constant", 1); } '
        "void lookup(DirContext dc,String b,String filter,SearchControls c)throws Exception { "
        "dc.search(b,filter,c); } void lookup(String query,int limit) {} }"
    )
    branches = (
        "import javax.naming.directory.*; class A { void f(DirContext dc,String b,String username,"
        "SearchControls c,boolean configured)throws Exception { String filter; if(configured) { "
        'filter = "(uid=" + username + ")"; } else { filter = "(uid=" + '
        'org.springframework.ldap.support.LdapEncoder.filterEncode(username) + ")"; } dc.search(b,filter,c); } }'
    )
    safe_branch_sink = (
        "import javax.naming.directory.*; class A { void f(DirContext dc,String b,String username,"
        "SearchControls c,boolean configured)throws Exception { String filter; if(configured) { "
        'filter = "(uid=" + username + ")"; } else { filter = "(uid=" + '
        "org.springframework.ldap.support.LdapEncoder.filterEncode(username) + "
        '")"; dc.search(b,filter,c); } } }'
    )
    unrelated_wrapper_receiver = (
        "import javax.naming.directory.*; class A { "
        "void f(Index index,String username){ index.lookup(\"a\",\"b\",\"(uid=\"+username+\")\",\"d\"); } "
        "void lookup(DirContext dc,String b,String filter,SearchControls c)throws Exception { "
        "dc.search(b,filter,c); } }"
    )
    token_only_sanitizer = (
        "import javax.naming.directory.*; class A { void f(DirContext dc,String b,String username,"
        "SearchControls c)throws Exception { dc.search(b,\"(uid=\"+escapeLdapFilter(username)+\")\",c); } "
        'String escapeLdapFilter(String value){ String tokens="case \\\\ \\\\5c case * \\\\2a '
        'case ( \\\\28 case ) \\\\29 case \\\\0 \\\\00"; return value; } }'
    )

    assert len(scan_source(mixed, "A.java")) == 1
    assert len(scan_source(typed_client, "A.java")) == 1
    assert scan_source(unrelated, "A.java") == []
    assert len(scan_source(no_op_sanitizer, "A.java")) == 1
    assert len(scan_source(overloads, "A.java")) == 1
    assert len(scan_source(branches, "A.java")) == 1
    assert scan_source(safe_branch_sink, "A.java") == []
    assert scan_source(unrelated_wrapper_receiver, "A.java") == []
    assert len(scan_source(token_only_sanitizer, "A.java")) == 1


@pytest.mark.parametrize(
    "source,expected",
    [
        ("import ldap3\ndef f(conn, base, username):\n    conn.search(base, f'(uid={username})')", 1),
        (
            "import ldap\ndef f(con, base, username):\n"
            "    filter_str = f'(uid={username})'\n"
            "    return con.search_s(base, ldap.SCOPE_SUBTREE, filter_str)",
            1,
        ),
        (
            "import ldap\ndef f(con, base, username):\n"
            "    escaped = ldap.filter.escape_filter_chars(username)\n"
            "    filter_str = f'(uid={escaped})'\n"
            "    return con.search_s(base, ldap.SCOPE_SUBTREE, filter_str)",
            0,
        ),
        # A helper is trusted only because its body demonstrably applies a filter sanitizer.
        (
            "import ldap3\ndef make_filter(username):\n"
            "    username = ldap3.utils.conv.escape_filter_chars(username)\n"
            "    return f'(uid={username})'\n"
            "def f(conn, base, username):\n    return conn.search(base, make_filter(username))",
            0,
        ),
        # A helper is not safe merely because it sanitizes an unrelated value.
        (
            "import ldap3\ndef make_filter(username, other):\n"
            "    escaped = ldap3.utils.conv.escape_filter_chars(other)\n"
            "    return f'(uid={username})'\n"
            "def f(conn, base, username, other):\n"
            "    return conn.search(base, make_filter(username, other))",
            1,
        ),
        # Every filter-returning path must carry the encoded value.
        (
            "import ldap3\ndef make_filter(username, encode):\n"
            "    if encode:\n"
            "        return f'(uid={ldap3.utils.conv.escape_filter_chars(username)})'\n"
            "    return f'(uid={username})'\n"
            "def f(conn, base, username, encode):\n"
            "    return conn.search(base, make_filter(username, encode))",
            1,
        ),
        # Escaping another value does not sanitize the username sent to this sink.
        (
            "import ldap3\ndef f(conn, base, username, other):\n"
            "    ldap3.utils.conv.escape_filter_chars(other)\n"
            "    return conn.search(base, f'(uid={username})')",
            1,
        ),
        # A sanitizer after the directory search cannot protect it.
        (
            "import ldap3\ndef f(conn, base, username):\n"
            "    out = conn.search(base, f'(uid={username})')\n"
            "    ldap3.utils.conv.escape_filter_chars(username)\n    return out",
            1,
        ),
        # Rebinding the source after the search is likewise too late.
        (
            "import ldap3\ndef f(conn, base, username):\n"
            "    conn.search(base, f'(uid={username})')\n"
            "    username = ldap3.utils.conv.escape_filter_chars(username)",
            1,
        ),
        # LDAP imports elsewhere do not turn a generic index search into an LDAP sink.
        ("import ldap3\ndef f(index, base, username):\n    return index.search(base, f'(uid={username})')", 0),
        # A nested helper's sanitizer does not sanitize its outer scope.
        (
            "import ldap3\ndef f(conn, base, username):\n"
            "    def helper(value): return ldap3.utils.conv.escape_filter_chars(value)\n"
            "    return conn.search(base, f'(uid={username})')",
            1,
        ),
        ("import ldap3\n# conn.search(base, f'(uid={username})')\ndef f(): return None", 0),
    ],
)
def test_python_rule_variants(source, expected):
    assert len(scan_source(source, "a.py")) == expected


def test_python_if_else_filter_definitions_both_reach_the_merged_sink():
    source = (
        "import ldap\n"
        "def f(con, base, username, configured):\n"
        "    if configured:\n"
        "        filter_str = f'(&(active=1)(uid={username}))'\n"
        "    else:\n"
        "        filter_str = f'(uid={username})'\n"
        "    return con.search_s(base, ldap.SCOPE_SUBTREE, filter_str)\n"
    )
    assert _lines(scan_source(source, "a.py")) == [4, 6]


def test_python_review_regressions_helpers_unpacking_provenance_and_sanitizers():
    mixed = (
        "import ldap3\ndef f(conn, base, username):\n"
        "    return conn.search(base, f'(uid={ldap3.utils.conv.escape_filter_chars(username)}{username})')"
    )
    helper_variable = (
        "import ldap3\ndef build_filter(username):\n"
        "    filter_str = f'(uid={username})'\n    return filter_str\n"
        "def f(conn, base, username):\n    return conn.search(base, build_filter(username))"
    )
    unpacked = (
        "import ldap3\ndef f(conn, base, supplied):\n"
        "    username, other = supplied, 'x'\n"
        "    return conn.search(base, f'(uid={username})')"
    )
    colliding_helpers = (
        "import ldap3\nclass Safe:\n"
        "    def build_filter(self, username):\n"
        "        return f'(uid={ldap3.utils.conv.escape_filter_chars(username)})'\n"
        "class Unsafe:\n"
        "    def build_filter(self, username):\n        return f'(uid={username})'\n"
        "    def run(self, conn, base, username):\n"
        "        return conn.search(base, self.build_filter(username))"
    )
    local_no_op = (
        "import ldap3\ndef escape_filter_chars(value): return value\n"
        "def f(conn, base, username):\n"
        "    return conn.search(base, f'(uid={escape_filter_chars(username)})')"
    )
    imported_alias = (
        "from ldap3.utils.conv import escape_filter_chars as encode\n"
        "def f(conn, base, username):\n"
        "    return conn.search(base, f'(uid={encode(username)})')"
    )
    unrelated = (
        "import ldap3\ndef f(index, username):\n"
        "    return index.query(search_filter=f'(uid={username})')"
    )
    safely_unpacked = (
        "import ldap3\ndef f(conn, base, supplied):\n"
        "    username, other = 'fixed', supplied\n"
        "    return conn.search(base, f'(uid={username})')"
    )
    unrelated_helper_collision = (
        "import ldap3\ndef build_filter(value): return value + 'x'\n"
        "class Unsafe:\n"
        "    def build_filter(self, username): return f'(uid={username})'\n"
        "    def run(self, conn, base, username):\n"
        "        return conn.search(base, self.build_filter(username))"
    )
    shadowed_import = (
        "from ldap3.utils.conv import escape_filter_chars\n"
        "def f(conn, base, username):\n"
        "    def escape_filter_chars(value): return value\n"
        "    return conn.search(base, f'(uid={escape_filter_chars(username)})')"
    )
    safe_branch_sink = (
        "import ldap3\ndef f(conn, base, username, configured):\n"
        "    if configured:\n        filter_str = f'(uid={username})'\n"
        "    else:\n"
        "        filter_str = f'(uid={ldap3.utils.conv.escape_filter_chars(username)})'\n"
        "        return conn.search(base, filter_str)"
    )
    generic_connection = (
        "import ldap3\ndef f(connection, base, username):\n"
        "    return connection.search(base, f'(uid={username})')"
    )
    ldap_client = (
        "import ldap3\ndef f(client, base, username):\n"
        "    return client.search(base, f'(uid={username})')"
    )

    assert len(scan_source(mixed, "a.py")) == 1
    assert len(scan_source(helper_variable, "a.py")) == 1
    assert len(scan_source(unpacked, "a.py")) == 1
    assert len(scan_source(colliding_helpers, "a.py")) == 1
    assert len(scan_source(local_no_op, "a.py")) == 1
    assert scan_source(imported_alias, "a.py") == []
    assert scan_source(unrelated, "a.py") == []
    assert scan_source(safely_unpacked, "a.py") == []
    assert len(scan_source(unrelated_helper_collision, "a.py")) == 1
    assert len(scan_source(shadowed_import, "a.py")) == 1
    assert scan_source(safe_branch_sink, "a.py") == []
    assert scan_source(generic_connection, "a.py") == []
    assert len(scan_source(ldap_client, "a.py")) == 1


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "<?php function f($ldap,$credentials,$template){ return $ldap->simple_search("
            "str_replace('[search]',$credentials['username'],$template)); } ?>",
            1,
        ),
        (
            "<?php function f($ldap,$credentials,$template){ return $ldap->simple_search("
            "str_replace('[search]',$ldap->escape($credentials['username'],null,LDAP_ESCAPE_FILTER),"
            "$template)); } ?>",
            0,
        ),
        # DN escaping is the wrong encoding for an LDAP search filter.
        (
            "<?php function f($ldap,$credentials,$template){ return $ldap->simple_search("
            "str_replace('[search]',$ldap->escape($credentials['username'],null,LDAP_ESCAPE_DN),"
            "$template)); } ?>",
            1,
        ),
        (
            "<?php function f($conn,$base,$username){ return ldap_search($conn,$base,"
            "sprintf('(uid=%s)',$username)); } ?>",
            1,
        ),
        (
            "<?php function f($conn,$base,$username){ $filter = sprintf('(uid=%s)',$username); "
            "return ldap_search($conn,$base,$filter); } ?>",
            1,
        ),
        # Direct sinks use the state at the call site: a later sanitizer cannot
        # retroactively protect them, and a later re-taint cannot make them unsafe.
        (
            "<?php function f($ldap,$username){ $ldap->simple_search('(uid=' . $username . ')'); "
            "$username = $ldap->escape($username,null,LDAP_ESCAPE_FILTER); } ?>",
            1,
        ),
        (
            "<?php function f($ldap,$username,$other){ "
            "$username = $ldap->escape($username,null,LDAP_ESCAPE_FILTER); "
            "$ldap->simple_search('(uid=' . $username . ')'); $username = $other; } ?>",
            0,
        ),
        ("<?php function f($index,$username){ return $index->search('(uid=' . $username . ')'); } ?>", 0),
        ("<?php // $ldap->simple_search('(uid=' . $username . ')'); ?>", 0),
    ],
)
def test_php_rule_variants(source, expected):
    assert len(scan_source(source, "a.php")) == expected


def test_php_review_regressions_provenance_mixed_values_flags_and_branches():
    mixed = (
        "<?php function f($ldap,$username){ $ldap->search('(uid=' . "
        "$ldap->escape($username,null,LDAP_ESCAPE_FILTER) . $username . ')'); } ?>"
    )
    typed_client = (
        "<?php function f(LdapInterface $client,$username){ "
        "$client->search('(uid=' . $username . ')'); } ?>"
    )
    static_sink = (
        "<?php function f($username){ Ldap::search('(uid=' . $username . ')'); } ?>"
    )
    lowercase_flag = (
        "<?php function f($ldap,$username){ $ldap->search('(uid=' . "
        "$ldap->escape($username,null,ldap_escape_filter) . ')'); } ?>"
    )
    local_no_op = (
        "<?php function escape_filter_chars($value){ return $value; } "
        "function f($ldap,$username){ $ldap->search('(uid=' . "
        "escape_filter_chars($username) . ')'); } ?>"
    )
    branches = (
        "<?php function f($ldap,$username,$configured){ if($configured){ "
        "$filter = '(uid=' . $username . ')'; } else { $filter = '(uid=' . "
        "$ldap->escape($username,null,LDAP_ESCAPE_FILTER) . ')'; } "
        "$ldap->search($filter); } ?>"
    )
    safe_branch_sink = (
        "<?php function f($ldap,$username,$configured){ if($configured){ "
        "$filter = '(uid=' . $username . ')'; } else { $filter = '(uid=' . "
        "$ldap->escape($username,null,LDAP_ESCAPE_FILTER) . ')'; "
        "$ldap->search($filter); } } ?>"
    )
    local_static_no_op = (
        "<?php class Ldap { static function escape($value){ return $value; } "
        "static function search($filter){} } function f($username){ "
        "Ldap::search('(uid=' . Ldap::escape($username) . ')'); } ?>"
    )
    misleading_receiver = (
        "<?php function f($notLdapIndex,$username){ "
        "$notLdapIndex->search('(uid=' . $username . ')'); } ?>"
    )

    assert len(scan_source(mixed, "a.php")) == 1
    assert len(scan_source(typed_client, "a.php")) == 1
    assert len(scan_source(static_sink, "a.php")) == 1
    assert scan_source(lowercase_flag, "a.php") == []
    assert len(scan_source(local_no_op, "a.php")) == 1
    assert len(scan_source(branches, "a.php")) == 1
    assert scan_source(safe_branch_sink, "a.php") == []
    assert len(scan_source(local_static_no_op, "a.php")) == 1
    assert scan_source(misleading_receiver, "a.php") == []


def test_sarif_carries_cwe_and_cve_only_as_analyzer_metadata():
    sarif = scan_file(FIXTURE_JAVA, uri=FIXTURE_JAVA.name, cve=SEED_CVE)
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == RULE_ID
    assert results[0]["properties"] == {"cwe": GROUND_TRUTH_CWE, "cve": SEED_CVE}


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
    uri = FIXTURE_JAVA.name
    (root / uri).write_text(FIXTURE_JAVA.read_text())
    project_id = "yamcs-cve-2026-42568"

    registration = NewProjectSession(
        name="Yamcs LDAP injection",
        source_type="open_source",
        local_path=str(root),
        authorization_basis="permissive_oss",
        scope_allowlist=[uri],
        project_id=project_id,
        verify_url=lambda _url: True,
    )
    assert run_session(store, gate, registration).gate_outcome.value == "proceed"
    run_session(store, gate, MapSession(project_id, root=str(root)))

    sarif_path = tmp_path / "ldap-injection.sarif"
    sarif_path.write_text(json.dumps(scan_file(root / uri, uri=uri, cve=SEED_CVE)))
    run_session(
        store,
        gate,
        DiscoverSession(project_id, sarif_path=str(sarif_path), root=str(root)),
    )

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
    assert result.rediscovered == 3
    assert result.missed_cves == []
    assert result.generalization == 1.0
