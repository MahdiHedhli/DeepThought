"""Tests for the public learning switch (benchmarks/teaching.py + benchmarks/learn.py).

Covers: the teaching knowledge (every public CWE has a note), the offline Q&A answerer, the
end-to-end static scan + pedagogical render, the pluggable subagent hook, and — importantly — the
Article-III guarantee that ``learn`` reads source as DATA and never EXECUTES it.
"""
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))          # benchmarks/
sys.path.insert(0, str(Path(__file__).parent.parent / "harness"))

import learn  # noqa: E402
import teaching  # noqa: E402

# every CWE the public detectors can emit (see benchmarks/*_detector.py)
_PUBLIC_CWES = ["CWE-78", "CWE-113", "CWE-502", "CWE-90", "CWE-943", "CWE-601",
                "CWE-22", "CWE-1321", "CWE-89", "CWE-1336", "CWE-918", "CWE-611"]

_TARVULN = "import tarfile\ndef f(p):\n    t = tarfile.open(p)\n    t.extractall()\n"
_BENIGN = "def add(a, b):\n    return a + b\n"


# --------------------------------------------------------------------------- #
# teaching.py
# --------------------------------------------------------------------------- #
def test_every_public_cwe_has_a_teaching_note():
    for cwe in _PUBLIC_CWES:
        t = teaching.teaching_for(cwe)
        assert t is not None, f"no teaching note for {cwe}"
        assert t["name"] and t["why"] and t["confirm"] and t["refute"] and t["learn"]


def test_ssti_cwe_alias_resolves():
    assert teaching.teaching_for("CWE-94") is teaching.teaching_for("CWE-1336")  # code-injection alias


def test_local_answer_maps_intents():
    finding = {"cwe": "CWE-918", "rule": "DT-SSRF-TAINT"}
    assert "exploitable" in learn.answer("why is this exploitable?", finding).lower() or \
           "pivot" in learn.answer("why is this exploitable?", finding).lower()
    assert "FALSE POSITIVE" in learn.answer("could this be a false positive?", finding)
    assert "allowlist" in learn.answer("how do I fix it?", finding)
    assert "SSRF" in learn.answer("what is this?", finding)


def test_local_answer_unknown_cwe_is_graceful():
    ans = learn.answer("why?", {"cwe": "CWE-0000", "rule": "DT-NOPE"})
    assert "don't have a teaching note" in ans


def test_methodology_notes_present():
    notes = teaching.methodology_notes()
    assert any("candidate is NOT a finding" in n.lower() or "not a finding" in n.lower() for n in notes)
    assert any("never execut" in n.lower() or "data" in n.lower() for n in notes)


# --------------------------------------------------------------------------- #
# learn.py end-to-end (static scan)
# --------------------------------------------------------------------------- #
def test_scan_path_surfaces_tarfile_candidate(tmp_path):
    (tmp_path / "vuln.py").write_text(_TARVULN)
    detectors, _skipped = learn.load_detectors()
    findings, coverage = learn.scan_path(tmp_path, detectors)
    assert coverage["scanned"] >= 1
    assert any(f["cwe"] == "CWE-22" and f["rule"] == "DT-TARFILE-EXTRACTALL" for f in findings)


def test_scan_path_benign_file_no_findings(tmp_path):
    (tmp_path / "ok.py").write_text(_BENIGN)
    detectors, _ = learn.load_detectors()
    findings, coverage = learn.scan_path(tmp_path, detectors)
    assert findings == [] and coverage["scanned"] == 1


def test_scan_path_reads_source_never_executes_it(tmp_path):
    # Article III: `learn` parses source as DATA. A file whose top-level code would create a marker
    # IF executed must NOT create it — scanning reads, it never runs.
    marker = tmp_path / "EXECUTED"
    (tmp_path / "sideeffect.py").write_text(
        f"open({str(marker)!r}, 'w').write('x')\nimport tarfile\ntarfile.open('x').extractall()\n")
    detectors, _ = learn.load_detectors()
    learn.scan_path(tmp_path, detectors)
    assert not marker.exists(), "learn must not execute scanned source"


def test_render_includes_teaching_and_methodology_and_coverage():
    out = io.StringIO()
    finding = {"rule": "DT-SSRF-TAINT", "cwe": "CWE-918", "file": "a.py", "line": 3, "col": 5,
               "message": "untrusted host reaches an outbound request"}
    learn.render([finding], {"scanned": 1, "skipped": 0}, out=out, skipped_detectors=[])
    text = out.getvalue()
    assert "to CONFIRM" in text and "FALSE POSITIVE" in text and "fix intuition" in text
    assert "coverage" in text and "Not scanned is not clean" in text
    assert "How DeepThought thinks" in text
    assert "NONE is a confirmed bug" in text  # candidate framing


def test_answer_accepts_a_pluggable_subagent_answerer():
    calls = {}
    def fake_subagent(q, f):
        calls["q"], calls["cwe"] = q, f["cwe"]
        return "subagent says: verify reachability"
    finding = {"cwe": "CWE-89", "rule": "DT-SQLI-QUERY"}
    ans = learn.answer("explain", finding, answerer=fake_subagent)
    assert ans == "subagent says: verify reachability"
    assert calls == {"q": "explain", "cwe": "CWE-89"}  # the hook received the finding context


def test_main_json_mode(tmp_path, capsys):
    (tmp_path / "vuln.py").write_text(_TARVULN)
    rc = learn.main([str(tmp_path), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(f["cwe"] == "CWE-22" for f in payload["findings"])
    assert payload["coverage"]["scanned"] >= 1


def test_main_ask_mode_answers_first_candidate(tmp_path, capsys):
    (tmp_path / "vuln.py").write_text(_TARVULN)
    rc = learn.main([str(tmp_path), "--ask", "how do I fix it?"])
    assert rc == 0
    text = capsys.readouterr().out
    assert "Q: how do I fix it?" in text and "A:" in text


def test_main_missing_path_errors(capsys):
    assert learn.main(["/no/such/path/here"]) == 2
