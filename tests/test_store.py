"""T005 — Store interface and FileStore.

Create, read, update, list for each record type; diffs are clean text; project
identity resolves on git_url with no duplicate.
"""

from __future__ import annotations

import pytest

from deepthought.schema import Methodology
from deepthought.store import DuplicateProjectError, FileStore

from .conftest import make_coverage, make_finding, make_project, make_session


def test_project_crud_and_list(state_dir):
    store = FileStore(state_dir)
    project = make_project()
    store.save_project(project)

    assert store.get_project("php-src") == project
    assert [p.id for p in store.list_projects()] == ["php-src"]

    updated = make_project(name="PHP (renamed)")
    store.save_project(updated)
    assert store.get_project("php-src").name == "PHP (renamed)"


def test_finding_crud_and_list_filter(state_dir):
    store = FileStore(state_dir)
    store.save_finding(make_finding(id="F-0001", project="php-src"))
    store.save_finding(make_finding(id="F-0002", project="curl"))

    assert store.get_finding("F-0001").id == "F-0001"
    assert {f.id for f in store.list_findings()} == {"F-0001", "F-0002"}
    assert [f.id for f in store.list_findings(project="curl")] == ["F-0002"]


def test_session_and_coverage_and_methodology_crud(state_dir):
    store = FileStore(state_dir)
    store.save_session(make_session())
    store.save_coverage(make_coverage())
    store.save_methodology(
        Methodology(id="rubric", purpose="score", version="1.0", body="use cvss")
    )

    assert store.get_session("S-2026-06-30-0001").project == "php-src"
    assert store.get_coverage("php-src", "ext-soap").depth.value == "explored"
    assert store.get_methodology("rubric").version == "1.0"
    assert len(store.list_coverage(project="php-src")) == 1
    assert len(store.list_methodology()) == 1


def test_diffs_are_clean_text(state_dir):
    store = FileStore(state_dir)
    store.save_project(make_project())
    text = (state_dir / "projects" / "php-src.md").read_text()
    assert text.startswith("---\n")
    assert "id: php-src" in text
    assert "authorization_basis: permissive_oss" in text
    # A round-trip through the file yields an identical record.
    assert store.get_project("php-src") == make_project()


def test_project_identity_resolves_on_git_url(state_dir):
    store = FileStore(state_dir)
    store.save_project(make_project())
    resolved = store.resolve_project(git_url="https://github.com/php/php-src")
    assert resolved is not None and resolved.id == "php-src"
    assert store.resolve_project(git_url="https://github.com/other/repo") is None


def test_duplicate_project_identity_is_refused(state_dir):
    store = FileStore(state_dir)
    store.save_project(make_project(id="php-src"))
    # Same git_url under a different id must not create a duplicate.
    with pytest.raises(DuplicateProjectError):
        store.save_project(make_project(id="php-src-2"))


def test_saving_same_id_updates_not_duplicates(state_dir):
    store = FileStore(state_dir)
    store.save_project(make_project())
    store.save_project(make_project(status="paused"))
    assert len(store.list_projects()) == 1
    assert store.get_project("php-src").status.value == "paused"


def test_write_and_resolve_detail(state_dir):
    store = FileStore(state_dir)
    ref = store.write_detail("S-2026-06-30-0007", "repro-01.txt", "crash trace")
    assert ref == "detail/S-2026-06-30-0007/repro-01.txt"
    assert store.detail_exists(ref)
    assert store.detail_exists("state/" + ref)
    assert not store.detail_exists("detail/nope/missing.txt")


def test_coverage_slug_is_injective_no_collision(state_dir):
    from deepthought.schema import Coverage

    store = FileStore(state_dir)
    store.save_coverage(
        Coverage(project="p", area="ext/soap", method="read", depth="touched",
                 last_session="S-1", body="alpha")
    )
    store.save_coverage(
        Coverage(project="p", area="ext-soap", method="read", depth="touched",
                 last_session="S-1", body="beta")
    )
    # Distinct areas that used to slug to the same file are now separate records.
    areas = {c.area for c in store.list_coverage(project="p")}
    assert areas == {"ext/soap", "ext-soap"}
    assert store.get_coverage("p", "ext/soap").body == "alpha"
    assert store.get_coverage("p", "ext-soap").body == "beta"


def test_coverage_slug_is_traversal_safe(state_dir):
    from deepthought.schema import Coverage

    store = FileStore(state_dir)
    # A path-separator-laden area must stay inside the coverage dir (flat file).
    store.save_coverage(
        Coverage(project="p", area="../../etc/passwd", method="read",
                 depth="touched", last_session="S-1", body="x")
    )
    files = list((state_dir / "coverage").rglob("*.md"))
    assert len(files) == 1
    assert files[0].parent == state_dir / "coverage" / "p"  # never escaped


def test_coverage_reads_and_migrates_legacy_slug(state_dir):
    from deepthought.schema import Coverage

    store = FileStore(state_dir)
    # Simulate a store written by the OLD slugger: ext/soap -> ext-soap.md
    legacy = state_dir / "coverage" / "p" / "ext-soap.md"
    legacy.parent.mkdir(parents=True)
    legacy.write_text(
        Coverage(project="p", area="ext/soap", method="read", depth="touched",
                 last_session="S-1", body="legacy").to_markdown()
    )
    # Direct lookup still resolves via the legacy fallback.
    assert store.get_coverage("p", "ext/soap").body == "legacy"
    # Re-saving migrates it to the new slug and removes the stale legacy file.
    store.save_coverage(
        Coverage(project="p", area="ext/soap", method="read", depth="explored",
                 last_session="S-2", body="new")
    )
    assert not legacy.exists()
    assert len(store.list_coverage(project="p")) == 1
    assert store.get_coverage("p", "ext/soap").depth.value == "explored"


def test_migration_does_not_delete_unrelated_area(state_dir):
    from deepthought.schema import Coverage

    store = FileStore(state_dir)
    # A real record for area "ext-soap" (its file is ext-soap.md).
    store.save_coverage(
        Coverage(project="p", area="ext-soap", method="read", depth="touched",
                 last_session="S", body="unrelated")
    )
    # Saving area "ext/soap" (legacy slug ext-soap.md) must NOT delete the
    # unrelated ext-soap record.
    store.save_coverage(
        Coverage(project="p", area="ext/soap", method="read", depth="touched",
                 last_session="S", body="slashed")
    )
    areas = {c.area for c in store.list_coverage(project="p")}
    assert areas == {"ext-soap", "ext/soap"}
    assert store.get_coverage("p", "ext-soap").body == "unrelated"


def test_save_coverage_survives_legacy_unlink_failure(state_dir, monkeypatch):
    import pathlib

    from deepthought.schema import Coverage

    store = FileStore(state_dir)
    legacy = state_dir / "coverage" / "p" / "ext-soap.md"
    legacy.parent.mkdir(parents=True)
    legacy.write_text(
        Coverage(project="p", area="ext/soap", method="read", depth="touched",
                 last_session="S", body="old").to_markdown()
    )
    orig_unlink = pathlib.Path.unlink

    def boom(self, *a, **k):
        if self.name == "ext-soap.md":
            raise OSError("locked")
        return orig_unlink(self, *a, **k)

    monkeypatch.setattr(pathlib.Path, "unlink", boom)
    # The primary write must still succeed even though the legacy cleanup fails.
    store.save_coverage(
        Coverage(project="p", area="ext/soap", method="read", depth="explored",
                 last_session="S2", body="new")
    )
    assert store.get_coverage("p", "ext/soap").depth.value == "explored"
