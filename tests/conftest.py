"""Shared fixtures and builders for the test suite."""

from __future__ import annotations

import pytest

from deepthought.schema import (
    AffectedPackage,
    Coverage,
    Finding,
    Project,
    Reference,
    Session,
    Severity,
)
from deepthought.schema.common import iso_z, utcnow

VALID_CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def make_project(**overrides) -> Project:
    data = dict(
        id="php-src",
        name="PHP src",
        source_type="open_source",
        git_url="https://github.com/php/php-src",
        authorization_basis="permissive_oss",
        scope_allowlist=["ext/soap", "ext/standard"],
        status="active",
        body="The PHP interpreter. Focus on the SOAP and standard extensions.",
    )
    data.update(overrides)
    return Project.model_validate(data)


def make_finding(**overrides) -> Finding:
    data = dict(
        id="F-0007",
        project="php-src",
        summary="Arbitrary file write via stream filter chain in ext/soap",
        status="candidate",
        severity=Severity(cvss_vector=VALID_CVSS, cvss_score=9.8),
        affected=[
            AffectedPackage(
                ecosystem="Packagist",
                package="php/php-src",
                versions=["8.3.0", "8.3.1"],
            )
        ],
        references=[Reference(type="advisory", url="https://example.test/advisory/1")],
        aliases=[],
        cve=None,
        body=(
            "## Root cause\n\nUnchecked stream filter chain lets an attacker "
            "direct a write.\n\n## Impact\n\nArbitrary file write in the server "
            "context."
        ),
    )
    data.update(overrides)
    return Finding.model_validate(data)


def make_coverage(**overrides) -> Coverage:
    data = dict(
        project="php-src",
        area="ext-soap",
        method="static",
        depth="explored",
        last_session="S-2026-06-30-0001",
        body="Read the SOAP stream handling. Filter chain path remains.",
    )
    data.update(overrides)
    return Coverage.model_validate(data)


def make_session(**overrides) -> Session:
    data = dict(
        id="S-2026-06-30-0001",
        type="status",
        project="php-src",
        started=iso_z(utcnow()),
        body="## Summary\n\nReviewed state.\n\n## Next steps\n\nMap ext/soap.",
    )
    data.update(overrides)
    return Session.model_validate(data)


@pytest.fixture
def project() -> Project:
    return make_project()


@pytest.fixture
def finding() -> Finding:
    return make_finding()


@pytest.fixture
def state_dir(tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    return root
