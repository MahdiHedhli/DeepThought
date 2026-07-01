"""T002 — Project, Session, Coverage, Methodology models and Markdown IO.

Valid records load, malformed front-matter fails, enums reject unknown values,
and every record round-trips through its on-disk Markdown form.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from deepthought.schema import (
    Coverage,
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
