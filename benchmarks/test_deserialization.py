"""Round 3 unsafe-deserialization class (CWE-502), static JS/Python/Java."""

from __future__ import annotations

import json
import os
import socket
import warnings
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_java")

from deserial_detector import GROUND_TRUTH_CWE, RULE_ID, scan_file, scan_source  # noqa: E402

FIX_JS = Path(__file__).parent / "fixtures" / "deserialization.js"
FIX_PY = Path(__file__).parent / "fixtures" / "deserialization.py"
FIX_JAVA = Path(__file__).parent / "fixtures" / "deserialization.java"
MANIFEST = Path(__file__).parent / "corpus" / "deserialization" / "manifest.json"
SEED_CVE = "CVE-2017-5954"


def test_fixtures_discriminate_unsafe_from_guarded_sinks():
    assert len(scan_file(FIX_JS, uri=FIX_JS.name)["runs"][0]["results"]) == 1
    assert len(scan_file(FIX_PY, uri=FIX_PY.name)["runs"][0]["results"]) == 1
    assert len(scan_file(FIX_JAVA, uri=FIX_JAVA.name)["runs"][0]["results"]) == 1


@pytest.mark.parametrize(
    "source,expected",
    [
        ("function d(str){return (new Function('return '+str))()}", 1),
        ("function d(){return (new Function('return 1'))()}", 0),
        ("function d(){return (new Function(`return 1`))()}", 0),
        (
            "const sanitize=require('./internal/sanitize');"
            "function d(str,unsafe){if(!unsafe)str=sanitize(str);return new Function(str)}",
            0,
        ),
        # A sanitizer-looking local function is not trusted provenance.
        (
            "function sanitize(x){return x} function d(str){str=sanitize(str);return new Function(str)}",
            1,
        ),
        # Sanitization in a nested scope cannot harden the outer sink.
        (
            "const sanitize=require('./sanitize');function d(str){"
            "function helper(){str=sanitize(str)} return new Function(str)}",
            1,
        ),
        # Sanitization only on the explicitly unsafe arm is not a default guard.
        (
            "const sanitize=require('./sanitize');function d(str,unsafe){"
            "if(unsafe)str=sanitize(str);return new Function(str)}",
            1,
        ),
        # Safe YAML use elsewhere must never suppress this unsafe loader.
        ("YAML.safeLoad(other); function d(payload){return YAML.load(payload)}", 1),
        ("function d(payload){return YAML.safeLoad(payload)}", 0),
        ("const s=require('node-serialize');function d(x){return s.unserialize(x)}", 1),
        ("function d(x){return arbitrary.deserialize(x)}", 0),
    ],
)
def test_javascript_rule_variants(source, expected):
    assert len(scan_source(source, "a.js")) == expected


@pytest.mark.parametrize(
    "source,expected",
    [
        ("import pickle\ndef d(f): return pickle.load(f)", 1),
        ("import pickle as p\ndef d(data): return p.loads(data)", 1),
        ("from pickle import loads as decode\ndef d(data): return decode(data)", 1),
        ("import dill\ndef d(data): return dill.loads(data)", 1),
        ("import joblib\ndef d(path): return joblib.load(path)", 1),
        ("import yaml\ndef d(data): return yaml.load(data)", 1),
        ("import yaml\ndef d(data): return yaml.unsafe_load(data)", 1),
        ("import yaml\ndef d(data): return yaml.load(data, Loader=yaml.Loader)", 1),
        ("import yaml\ndef d(data): return yaml.load(data, Loader=yaml.SafeLoader)", 0),
        ("import yaml\ndef d(data): return yaml.load(data, yaml.CSafeLoader)", 0),
        ("import yaml\ndef d(data): return yaml.safe_load(data)", 0),
        ("import json\ndef d(data): return json.loads(data)", 0),
        ("class Store:\n def load(self,x): return x\ndef d(s,data): return s.load(data)", 0),
        ("import pickle\ndef d(): return pickle.loads(b'fixed')", 0),
        # Legacy Python may use async as an identifier; one later syntax error must not
        # hide an earlier unsafe sink from the static AST pass.
        ("import pickle\ndef d(f): return pickle.load(f)\ndef old():\n async = 1\n return async", 1),
        # A nested import alias cannot give provenance to an outer callable.
        (
            "def helper():\n from pickle import loads as decode\n return decode\n"
            "def outer(decode,data):\n return decode(data)",
            0,
        ),
    ],
)
def test_python_rule_variants(source, expected):
    assert len(scan_source(source, "a.py")) == expected


def test_legacy_python_escape_warnings_do_not_leak_from_the_scanner():
    source = "import pickle\nlegacy = '\\/'\ndef d(f): return pickle.load(f)"
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert len(scan_source(source, "legacy.py")) == 1
    assert not [warning for warning in caught if warning.category is SyntaxWarning]


_UNSAFE_XSTREAM = """
import com.thoughtworks.xstream.XStream;
class A { Object read(Object in) { XStream x = new XStream(); return x.fromXML(in); } }
"""

_SAFE_XSTREAM = """
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;
class A { Object read(Object in) { XStream x = new XStream();
  x.addPermission(NoTypePermission.NONE); return x.fromXML(in); } }
"""


@pytest.mark.parametrize(
    "source,expected",
    [
        (_UNSAFE_XSTREAM, 1),
        (_SAFE_XSTREAM, 0),
        # The safe one-argument overload must not bless the called unsafe zero-arg one.
        (
            "import com.thoughtworks.xstream.XStream;"
            "import com.thoughtworks.xstream.security.NoTypePermission;"
            "class A{Object read(Object in){XStream x=create();return x.fromXML(in);}"
            "XStream create(){return new XStream();}"
            "XStream create(Object p){XStream x=new XStream();"
            "x.addPermission(NoTypePermission.NONE);return x;}}",
            1,
        ),
        # The matching one-argument overload is hardened.
        (
            "import com.thoughtworks.xstream.XStream;"
            "import com.thoughtworks.xstream.security.NoTypePermission;"
            "class A{Object read(Object in,Object p){XStream x=create(p);return x.fromXML(in);}"
            "XStream create(){return new XStream();}"
            "XStream create(Object p){XStream x=new XStream();"
            "x.addPermission(NoTypePermission.NONE);return x;}}",
            0,
        ),
        # Guard must be bound to the sink receiver.
        (
            "import com.thoughtworks.xstream.XStream;"
            "import com.thoughtworks.xstream.security.NoTypePermission;"
            "class A{Object read(Object in){XStream x=new XStream();XStream other=new XStream();"
            "other.addPermission(NoTypePermission.NONE);return x.fromXML(in);}}",
            1,
        ),
        # Conditional hardening does not dominate the sink.
        (
            "import com.thoughtworks.xstream.XStream;"
            "import com.thoughtworks.xstream.security.NoTypePermission;"
            "class A{Object read(Object in,boolean safe){XStream x=new XStream();"
            "if(safe)x.addPermission(NoTypePermission.NONE);return x.fromXML(in);}}",
            1,
        ),
        # Comments/log strings and permissive permissions are not guards.
        (
            "import com.thoughtworks.xstream.XStream;class A{Object read(Object in){"
            "XStream x=new XStream();String s=\"NoTypePermission.NONE\";return x.fromXML(in);}}",
            1,
        ),
        (
            "import com.thoughtworks.xstream.XStream;"
            "import com.thoughtworks.xstream.security.AnyTypePermission;"
            "class A{Object read(Object in){XStream x=new XStream();"
            "x.addPermission(AnyTypePermission.ANY);return x.fromXML(in);}}",
            1,
        ),
        ("class A{Object read(Object in){Other x=new Other();return x.fromXML(in);}}", 0),
        # ObjectInputStream is receiver-provenanced and filter-sensitive.
        (
            "import java.io.ObjectInputStream;class A{Object read(ObjectInputStream in)"
            " throws Exception{return in.readObject();}}",
            1,
        ),
        (
            "import java.io.ObjectInputStream;class A{Object read(ObjectInputStream in,Object f)"
            " throws Exception{in.setObjectInputFilter(f);return in.readObject();}}",
            0,
        ),
    ],
)
def test_java_rule_variants(source, expected):
    assert len(scan_source(source, "A.java")) == expected


def test_manifest_pins_the_recurated_cwe_502_cohort():
    manifest = json.loads(MANIFEST.read_text())
    assert manifest["seed"]["cve"] == SEED_CVE
    assert [entry["cve"] for entry in manifest["heldout"]] == [
        "CVE-2018-8021",
        "CVE-2018-1000167",
        "CVE-2017-9805",
    ]
    assert all(entry["cwe"] == GROUND_TRUTH_CWE for entry in [manifest["seed"], *manifest["heldout"]])
    assert {entry["cve"] for entry in manifest["dropped"]} == {
        "CVE-2013-4660",
        "CVE-2020-7729",
        "CVE-2020-7660",
    }


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
    uri = FIX_JS.name
    (root / uri).write_text(FIX_JS.read_text())
    project_id = "serialize-to-js-cve-2017-5954"

    registration = NewProjectSession(
        name="serialize-to-js unsafe deserialization",
        source_type="open_source",
        local_path=str(root),
        authorization_basis="permissive_oss",
        scope_allowlist=[uri],
        project_id=project_id,
        verify_url=lambda _url: True,
    )
    assert run_session(store, gate, registration).gate_outcome.value == "proceed"
    run_session(store, gate, MapSession(project_id, root=str(root)))
    sarif = tmp_path / "deserialization.sarif"
    sarif.write_text(json.dumps(scan_file(root / uri, uri=uri, cve=SEED_CVE)))
    run_session(
        store,
        gate,
        DiscoverSession(project_id, sarif_path=str(sarif), root=str(root)),
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
    seed = measure_entry(manifest["seed"], scan_source)
    assert seed["rediscovered"]
    assert seed["patched_flag_count"] == 0
    result = measure_heldout(manifest, scan_source, RULE_ID)
    assert result.rediscovered == 3
    assert result.missed_cves == []
    assert result.generalization == 1.0
