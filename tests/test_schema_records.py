"""T002 — Project, Session, Coverage, Methodology models and Markdown IO.

Valid records load, malformed front-matter fails, enums reject unknown values,
and every record round-trips through its on-disk Markdown form.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from deepthought.schema import (
    Coverage,
    Finding,
    Methodology,
    Project,
    Session,
)
from deepthought.schema.common import RecordError

from .conftest import make_coverage, make_project, make_session


def test_project_round_trips_through_markdown():
    project = make_project()
    text = project.to_markdown()
    assert text.startswith("---\n")
    assert "## " not in text.split("---", 2)[1]  # body is below the front-matter
    reloaded = Project.from_markdown(text)
    assert reloaded == project


def test_markdown_has_front_matter_then_body():
    project = make_project()
    text = project.to_markdown()
    head, fm, body = text.split("---", 2)
    assert head == ""
    assert "id: php-src" in fm
    assert "The PHP interpreter" in body


def test_unknown_enum_value_fails():
    with pytest.raises(ValidationError):
        make_project(source_type="proprietary")


def test_unknown_front_matter_key_fails():
    # extra='forbid' — a corrupted record with a stray key is caught on read.
    with pytest.raises(ValidationError):
        make_project(bogus_key="whatever")


def test_missing_required_field_fails():
    with pytest.raises(ValidationError):
        Project.model_validate({"id": "x", "source_type": "open_source", "git_url": "u"})


def test_project_requires_identity():
    with pytest.raises(ValidationError):
        make_project(git_url=None, local_path=None)


def test_scoped_engagement_requires_authorization_ref():
    with pytest.raises(ValidationError):
        make_project(authorization_basis="scoped_engagement", authorization_ref=None)
    ok = make_project(
        authorization_basis="scoped_engagement", authorization_ref="ENG-42"
    )
    assert ok.authorization_ref == "ENG-42"


def test_project_without_basis_is_valid_but_gate_refuses_later():
    # Absence of a basis is meaningful, not malformed — the Gate refuses it.
    project = make_project(authorization_basis=None)
    assert project.authorization_basis is None


def test_record_missing_front_matter_fails():
    with pytest.raises(RecordError):
        Project.from_markdown("no front matter here")


def test_session_next_steps_detection():
    session = make_session()
    assert session.has_next_steps()
    assert "Map ext/soap" in session.next_steps()


def test_session_without_next_steps_is_detectable():
    session = make_session(body="## Summary\n\nDid a thing.")
    assert not session.has_next_steps()


def test_coverage_enums_reject_unknown():
    with pytest.raises(ValidationError):
        make_coverage(method="telepathy")
    with pytest.raises(ValidationError):
        make_coverage(depth="skimmed")


def test_coverage_ref():
    assert make_coverage().ref == "php-src/ext-soap"


def test_methodology_round_trips():
    m = Methodology(
        id="severity-rubric",
        purpose="Score findings reproducibly",
        version="1.0",
        body="Use CVSS 3.1. Environmental metrics per engagement.",
    )
    reloaded = Methodology.from_markdown(m.to_markdown())
    assert reloaded == m


def test_session_round_trips():
    session = make_session()
    assert Session.from_markdown(session.to_markdown()) == session


def test_coverage_round_trips():
    coverage = make_coverage()
    assert Coverage.from_markdown(coverage.to_markdown()) == coverage


def test_record_ids_reject_unsafe_values():
    """A record id is used verbatim as a filename, so the model rejects any id that
    is not a single safe path segment — no traversal, separators, whitespace,
    control chars, or leading/trailing punctuation — at construction."""
    unsafe = [
        "../../pwned", "a/b", "a\\b", "..", ".", "a b", "a\tb", "a\nb",
        "", "-lead", ".lead", "_lead", "trail-", "trail.", "x" * 200,
    ]
    for bad in unsafe:
        with pytest.raises(ValidationError):
            Finding.model_validate({"id": bad, "project": "p", "summary": "x"})
    # the project reference and other record ids are constrained too.
    with pytest.raises(ValidationError):
        Finding.model_validate({"id": "F-1", "project": "../../x", "summary": "x"})
    with pytest.raises(ValidationError):
        Project.model_validate({"id": "a/b", "name": "n", "source_type": "open_source",
                                "git_url": "https://x.test/a", "authorization_basis": "own_code"})

    # Real ids used across the codebase remain valid.
    for good in ("F-0007", "php-src", "S-2026-07-02-0001", "a", "A1", "x._-9"):
        Finding.model_validate({"id": good, "project": "php-src", "summary": "x"})


def test_derive_project_id_always_yields_a_safe_id():
    """A derived project id feeds straight into ``Project.id`` (a RecordId), so the
    generator must never emit a value the model rejects — a source tail with
    leading/trailing punctuation, path separators, or excess length must be
    normalised to a valid single safe path segment, and a Project must construct
    from it."""
    from deepthought.schema.common import safe_record_id
    from deepthought.sessions.new_project import derive_project_id

    hostile = [
        ("n", None, "/tmp/_repo"),          # leading '_'
        ("n", None, "/tmp/repo_"),          # trailing '_'
        ("n", None, "/tmp/repo."),          # trailing '.'
        (".hidden", None, None),            # leading '.'
        ("a" * 200, None, None),            # over the 128-char bound
        ("n", "https://x/._.git", None),    # collapses to punctuation only
        ("...", None, None),                # nothing safe survives -> fallback
        ("n", None, "/tmp/a b/c d"),        # whitespace in the tail
    ]
    for name, git_url, local_path in hostile:
        did = derive_project_id(name, git_url, local_path)
        # The id must build a Project without raising.
        Project.model_validate(
            {"id": did, "name": "n", "source_type": "open_source",
             "git_url": "https://x.test/a", "authorization_basis": "own_code"}
        )

    # Backward-compatibility: an already-clean tail is unchanged.
    assert derive_project_id("n", "https://github.com/php/php-src", None) == "php-src"
    assert derive_project_id("n", None, "/repos/curl") == "curl"

    # The shared coercion helper is idempotent on a value it already accepts.
    for good in ("F-0007", "php-src", "a", "x._-9"):
        assert safe_record_id(good, fallback="project") == good
