"""The three operator verbs: ``playbook``, ``check``, ``publish``.

* ``playbook`` runs the Agent Session Protocol for a chosen session type and
  lists or operates on findings.
* ``check`` validates state consistency. It is a required hard gate before
  ``publish``; an error or timeout is a failed check.
* ``publish`` emits prepared local artifacts and asserts the human gate. In 001
  it never transmits.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from .check import run_check
from .export.osv import finding_to_osv, osv_id_for
from .protocol import HermesUltraCodeGate, run_session
from .sessions import (
    DiscoverSession,
    MapSession,
    NewProjectSession,
    StatusSession,
)
from .store import FileStore, StoreError

app = typer.Typer(
    help="Deep Thought — the governed spine. Three verbs: playbook, check, publish.",
    no_args_is_help=True,
    add_completion=False,
)
playbook_app = typer.Typer(
    help="Run the Agent Session Protocol for a session type; list findings.",
    no_args_is_help=True,
)
app.add_typer(playbook_app, name="playbook")

_STATE_OPTION = typer.Option(
    "state", "--state", envvar="DEEPTHOUGHT_STATE", help="Path to the state store."
)


def _store(state: Path) -> FileStore:
    return FileStore(state)


def _echo_session(record) -> None:
    typer.echo(f"session : {record.id}")
    typer.echo(f"gate    : {record.gate_outcome.value if record.gate_outcome else '-'}")
    if record.gate_reason:
        typer.echo(f"reason  : {record.gate_reason}")
    typer.echo(f"close   : {record.close_state.value}")
    typer.echo("")
    typer.echo(record.body)


# --- playbook ------------------------------------------------------------
@playbook_app.command("new-project")
def playbook_new_project(
    name: str = typer.Option(..., help="Human-readable project name."),
    source_type: str = typer.Option(
        "open_source", help="open_source or blackbox."
    ),
    git_url: Optional[str] = typer.Option(None, help="Git URL (identity)."),
    local_path: Optional[str] = typer.Option(None, help="Local path (identity)."),
    basis: Optional[str] = typer.Option(
        None, help="own_code | permissive_oss | scoped_engagement."
    ),
    authorization_ref: Optional[str] = typer.Option(
        None, help="Engagement/license reference; required for scoped_engagement or blackbox."
    ),
    scope: list[str] = typer.Option(
        [], "--scope", help="An in-scope path/module/host. Repeatable."
    ),
    project_id: Optional[str] = typer.Option(None, help="Override the derived id."),
    notes: str = typer.Option("", help="Free notes for the project body."),
    state: Path = _STATE_OPTION,
) -> None:
    """Register a project (NEW PROJECT session)."""
    session = NewProjectSession(
        name=name,
        source_type=source_type,
        git_url=git_url,
        local_path=local_path,
        authorization_basis=basis,
        authorization_ref=authorization_ref,
        scope_allowlist=list(scope),
        project_id=project_id,
        notes=notes,
    )
    record = run_session(_store(state), HermesUltraCodeGate(), session)
    _echo_session(record)


@playbook_app.command("status")
def playbook_status(
    project: str = typer.Option(..., help="Project id to summarize."),
    state: Path = _STATE_OPTION,
) -> None:
    """Summarize state without changing it (STATUS session)."""
    try:
        record = run_session(
            _store(state), HermesUltraCodeGate(), StatusSession(project)
        )
    except StoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)
    _echo_session(record)


@playbook_app.command("map")
def playbook_map(
    project: str = typer.Option(..., help="Project id to map."),
    root: Optional[str] = typer.Option(
        None, "--root", help="Local checkout to walk; defaults to the project's local_path."
    ),
    state: Path = _STATE_OPTION,
) -> None:
    """Record the in-scope attack surface, READ-ONLY (MAP session, feature 002).

    Walks only the project's in-scope areas and records Coverage. Executes no
    target code, transmits nothing, and never widens scope.
    """
    try:
        record = run_session(
            _store(state), HermesUltraCodeGate(), MapSession(project, root=root)
        )
    except StoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)
    _echo_session(record)


@playbook_app.command("discover")
def playbook_discover(
    project: str = typer.Option(..., help="Project id to discover over."),
    sarif: Optional[str] = typer.Option(
        None, "--sarif", help="SARIF file to reason over for candidate findings."
    ),
    root: Optional[str] = typer.Option(
        None, "--root", help="Local checkout for code reasoning; defaults to local_path."
    ),
    state: Path = _STATE_OPTION,
) -> None:
    """Reason over code and SARIF for candidates, READ-ONLY (DISCOVER, feature 002).

    Dispatches one worker that reads any SARIF and writes candidate findings; the
    orchestrator ingests only the typed envelope. Executes no target code,
    transmits nothing, and never widens scope.
    """
    try:
        record = run_session(
            _store(state),
            HermesUltraCodeGate(),
            DiscoverSession(project, sarif_path=sarif, root=root),
        )
    except StoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)
    _echo_session(record)


@playbook_app.command("findings")
def playbook_findings(
    project: Optional[str] = typer.Option(None, help="Filter by project id."),
    state: Path = _STATE_OPTION,
) -> None:
    """List findings."""
    findings = _store(state).list_findings(project=project)
    if not findings:
        typer.echo("no findings")
        return
    for finding in findings:
        typer.echo(f"{finding.id}  {finding.status.value:<10}  {finding.summary}")


# --- check ---------------------------------------------------------------
@app.command("check")
def check(state: Path = _STATE_OPTION) -> None:
    """Validate state: schema, lifecycle, orphans, identity, OSV conformance."""
    report = run_check(_store(state))
    if report.ok:
        typer.echo("check: OK")
        return
    typer.echo(f"check: FAILED ({len(report.errors)} error(s))", err=True)
    for err in report.errors:
        typer.echo(f"  - {err}", err=True)
    raise typer.Exit(code=1)


# --- publish -------------------------------------------------------------
@app.command("publish")
def publish(
    out: Path = typer.Option("out", "--out", help="Local artifact directory."),
    state: Path = _STATE_OPTION,
) -> None:
    """Emit prepared local artifacts. Asserts the human gate. Transmits nothing."""
    store = _store(state)

    # check is a required hard gate before publish.
    report = run_check(store)
    if not report.ok:
        typer.echo("publish refused: check is not green. Run `deepthought check`.", err=True)
        raise typer.Exit(code=1)

    out.mkdir(parents=True, exist_ok=True)
    written = []
    for finding in store.list_findings():
        osv = finding_to_osv(finding)
        path = out / f"{osv_id_for(finding.id)}.json"
        path.write_text(json.dumps(osv, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(path)

    typer.echo(f"prepared {len(written)} OSV artifact(s) under {out}/")
    for path in written:
        typer.echo(f"  - {path}")
    typer.echo("")
    typer.echo("HUMAN GATE: nothing was transmitted. Coordinated disclosure requires")
    typer.echo("a human to review and send. Deep Thought emits local artifacts only.")


if __name__ == "__main__":  # pragma: no cover
    app()
