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
from .sandbox import NoopSandbox, SandboxError, SandboxPolicy, SandboxResult, SandboxSpec
from .sessions import (
    DiscoverSession,
    MapSession,
    NewProjectSession,
    StatusSession,
    VerifySession,
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


# The dry-run repro spec. It is DATA the NoopSandbox merely records — an argv
# command (never a shell string) under a default-hardened, default-deny policy.
# Nothing here is executed in this slice; the NoopSandbox runs nothing.
_DRY_RUN_IMAGE = "deepthought/verify-dry-run:noop"
_DRY_RUN_COMMAND = ["/repro/run"]
_DRY_RUN_REPRO_REF = "detail/pending/repro.bin"


def _dry_run_spec() -> SandboxSpec:
    """A hardened, default-deny spec the NoopSandbox records but never runs."""
    return SandboxSpec(
        image=_DRY_RUN_IMAGE,
        command=list(_DRY_RUN_COMMAND),
        repro_ref=_DRY_RUN_REPRO_REF,
        policy=SandboxPolicy(),  # default-constructed = fully locked down
    )


@playbook_app.command("verify")
def playbook_verify(
    project: str = typer.Option(..., help="Project id the finding belongs to."),
    finding: str = typer.Option(..., help="Candidate finding id to verify (F-NNNN)."),
    noop_reproduced: bool = typer.Option(
        False,
        "--noop-reproduced",
        help=(
            "DEV/TEST ONLY: change the verdict the NoopSandbox REPORTS to reproduced "
            "(still executes nothing). This is a DRY-RUN: it does NOT promote the "
            "finding, page evidence, or write any verification state — the finding "
            "stays a candidate. Promotion happens only when a signed-off sandbox "
            "actually reproduces the finding."
        ),
    ),
    i_have_sandbox_signoff: bool = typer.Option(
        False,
        "--i-have-sandbox-signoff",
        help=(
            "The 003 HARD STOP escape hatch. No real executing backend is wired in "
            "this slice, so this exits with a message and runs nothing. Enabling real "
            "execution is a distinct, later change behind Mahdi's sign-off."
        ),
    ),
    state: Path = _STATE_OPTION,
) -> None:
    """Verify a candidate finding in the sandbox (VERIFY session, feature 003).

    By default this NEVER executes untrusted target code. It constructs a
    ``VerifySession`` backed by a ``NoopSandbox`` — the injected sandbox seam that
    records the requested run and returns a canned result without running anything
    — and reports a dry-run that plainly says no execution happened while the
    sandbox sign-off is pending (Constitution Article III; Phase 0 §0.3).

    A real executing backend (``DockerSandbox``) is never enabled here. Passing
    ``--i-have-sandbox-signoff`` is the hard stop: because no executing backend is
    wired in this slice, it exits with a clear message and runs nothing.
    """
    # --- the 003 HARD STOP -------------------------------------------------
    # The sign-off flag is the only path that would ever reach a real executing
    # backend. In this slice no such backend is wired, so we refuse outright and
    # execute nothing. We NEVER construct a DockerSandbox with execution enabled,
    # never call DockerSandbox.run(), and never spawn a subprocess.
    if i_have_sandbox_signoff:
        typer.echo(
            "verify refused: no real executing sandbox backend is wired in this "
            "slice (003). Executing untrusted target code is the hard stop and "
            "requires Mahdi's sign-off plus a signed-off backend (Constitution "
            "Article III; Phase 0 §0.3). Nothing was executed.",
            err=True,
        )
        raise typer.Exit(code=2)

    # --- default: a NoopSandbox dry-run that executes NOTHING --------------
    # The canned verdict is non-reproducing by default (a true dry-run: the
    # candidate is not promoted). --noop-reproduced flips ONLY the recorded verdict
    # the NoopSandbox returns; it still runs nothing. Real execution stays off.
    canned = SandboxResult(
        exit_code=0,
        timed_out=False,
        wall_seconds=0.0,
        reproduced=noop_reproduced,
    )
    sandbox = NoopSandbox(canned)
    session = VerifySession(
        project_id=project,
        finding_id=finding,
        spec=_dry_run_spec(),
        sandbox=sandbox,
        # ALWAYS a dry-run in this slice: no signed-off executing backend exists,
        # so the CLI must never write verification state (evidence / promotion /
        # audit entry) from a synthetic Noop verdict — that would corrupt a real
        # finding's results and audit trail. --noop-reproduced only changes the
        # verdict the dry-run REPORTS; it never promotes. A finding is verified
        # only when a signed-off sandbox actually reproduces it. The
        # promote-through-guard path is exercised at the session level (tests +
        # the 003 smoke), never by a user-facing CLI command on real state.
        dry_run=True,
    )
    try:
        record = run_session(_store(state), HermesUltraCodeGate(), session)
    except (StoreError, SandboxError) as exc:
        # SandboxError covers the sandbox seam (e.g. a backend returning no result,
        # or the guarded-off run() hard stop) — exit cleanly, never a traceback.
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)

    _echo_session(record)
    # Make the dry-run's meaning unmistakable in the operator's output — for BOTH
    # verdicts. Nothing executed and nothing was mutated in either case.
    typer.echo("")
    if noop_reproduced:
        typer.echo(
            "no execution — sandbox sign-off pending. --noop-reproduced only sets "
            "the verdict the NoopSandbox REPORTS; no container was built, no target "
            "code ran, and the finding is UNCHANGED. A finding is promoted to "
            "verified only when a signed-off sandbox actually reproduces it."
        )
    else:
        typer.echo(
            "no execution — sandbox sign-off pending. This was a NoopSandbox "
            "dry-run: no container was built, no target code ran, nothing was "
            "transmitted. The finding is unchanged until a signed-off sandbox "
            "reproduces it."
        )


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
