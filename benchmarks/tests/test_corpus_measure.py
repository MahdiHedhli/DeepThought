from __future__ import annotations

import io
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "harness"))

import corpus_measure


TARGET = "removed.php"


def _entry(**updates):
    entry = {
        "cve": "CVE-TEST",
        "package": "example",
        "repo": "https://github.com/example/project",
        "vuln_ref": "a" * 40,
        "patched_ref": "b" * 40,
        "target_paths": [TARGET],
        "sink_probe": "dangerous_query()",
    }
    entry.update(updates)
    return entry


def _scan(source: str, uri: str):
    if "dangerous_query()" not in source:
        return []
    return [
        {
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }
            ]
        }
    ]


def test_explicit_deleted_patched_target_is_measured(monkeypatch):
    fetched = []
    confirmed = []

    def fake_fetch(repo, sha, path):
        fetched.append((repo, sha, path))
        assert sha == "a" * 40  # patched fetch must be skipped only after explicit declaration
        return "dangerous_query()\n"

    monkeypatch.setattr(corpus_measure, "fetch", fake_fetch)
    monkeypatch.setattr(
        corpus_measure,
        "_confirm_patched_absent",
        lambda repo, sha, path: confirmed.append((repo, sha, path)),
    )
    result = corpus_measure.measure_entry(_entry(patched_absent_paths=[TARGET]), _scan)
    assert result["rediscovered"] is True
    assert result["patched_flag_count"] == 0
    assert result["patched_absent_paths"] == [TARGET]
    assert len(fetched) == 1 and confirmed == [("https://github.com/example/project", "b" * 40, TARGET)]


def test_missing_patched_target_without_declaration_fails_closed(monkeypatch):
    def fake_fetch(repo, sha, path):
        if sha == "a" * 40:
            return "dangerous_query()\n"
        raise urllib.error.HTTPError("raw", 404, "missing", {}, None)

    monkeypatch.setattr(corpus_measure, "fetch", fake_fetch)
    with pytest.raises(urllib.error.HTTPError):
        corpus_measure.measure_entry(_entry(), _scan)


@pytest.mark.parametrize(
    "declared",
    [["not-a-target.php"], [TARGET, TARGET], "removed.php", [1]],
)
def test_invalid_absence_declaration_is_rejected(monkeypatch, declared):
    monkeypatch.setattr(corpus_measure, "fetch", lambda *_args: pytest.fail("validation must run before fetch"))
    with pytest.raises(ValueError):
        corpus_measure.measure_entry(_entry(patched_absent_paths=declared), _scan)


class _Response:
    def __init__(self, data: bytes = b""):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.data


def test_confirmed_404_creates_a_scoped_absence_marker(tmp_path, monkeypatch):
    monkeypatch.setattr(corpus_measure, "_CACHE", tmp_path)
    monkeypatch.setattr(corpus_measure, "_confirm_ref_exists", lambda *_args: None)
    calls = []

    def missing(url, timeout):
        calls.append((url, timeout))
        raise urllib.error.HTTPError(url, 404, "missing", {}, None)

    monkeypatch.setattr(corpus_measure, "_urlopen", missing)
    corpus_measure._confirm_patched_absent("https://github.com/example/project", "b" * 40, TARGET)
    assert len(calls) == 1
    assert list(tmp_path.glob("*.absent.json"))

    monkeypatch.setattr(corpus_measure, "_urlopen", lambda *_args: pytest.fail("cached proof should be reused"))
    corpus_measure._confirm_patched_absent("https://github.com/example/project", "b" * 40, TARGET)


def test_declared_absent_target_that_exists_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(corpus_measure, "_CACHE", tmp_path)
    monkeypatch.setattr(corpus_measure, "_confirm_ref_exists", lambda *_args: None)
    monkeypatch.setattr(corpus_measure, "_urlopen", lambda *_args: _Response(b"<?php"))
    with pytest.raises(ValueError, match="it exists"):
        corpus_measure._confirm_patched_absent("https://github.com/example/project", "b" * 40, TARGET)


@pytest.mark.parametrize("status", [403, 429, 500, 503])
def test_non_404_http_failures_never_become_absence(tmp_path, monkeypatch, status):
    monkeypatch.setattr(corpus_measure, "_CACHE", tmp_path)
    monkeypatch.setattr(corpus_measure, "_confirm_ref_exists", lambda *_args: None)

    def failed(url, _timeout):
        raise urllib.error.HTTPError(url, status, "failure", {}, None)

    monkeypatch.setattr(corpus_measure, "_urlopen", failed)
    with pytest.raises(urllib.error.HTTPError) as raised:
        corpus_measure._confirm_patched_absent("https://github.com/example/project", "b" * 40, TARGET)
    assert raised.value.code == status


def test_network_failure_never_becomes_absence(tmp_path, monkeypatch):
    monkeypatch.setattr(corpus_measure, "_CACHE", tmp_path)
    monkeypatch.setattr(corpus_measure, "_confirm_ref_exists", lambda *_args: None)
    monkeypatch.setattr(corpus_measure, "_urlopen", lambda *_args: (_ for _ in ()).throw(TimeoutError("timeout")))
    with pytest.raises(TimeoutError):
        corpus_measure._confirm_patched_absent("https://github.com/example/project", "b" * 40, TARGET)


def test_invalid_or_unresolvable_patched_ref_never_becomes_absence(tmp_path, monkeypatch):
    monkeypatch.setattr(corpus_measure, "_CACHE", tmp_path)
    with pytest.raises(ValueError, match="full lowercase commit SHA"):
        corpus_measure._confirm_ref_exists("https://github.com/example/project", "main")

    def missing_ref(url, _timeout):
        raise urllib.error.HTTPError(url, 404, "unknown commit", {}, io.BytesIO())

    monkeypatch.setattr(corpus_measure, "_urlopen", missing_ref)
    with pytest.raises(urllib.error.HTTPError):
        corpus_measure._confirm_ref_exists("https://github.com/example/project", "c" * 40)
