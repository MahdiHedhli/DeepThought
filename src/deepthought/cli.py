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
from urllib.parse import quote

import typer
from pydantic import ValidationError

from .check import run_check
from .export.advisory import finding_to_advisory
from .export.csaf import finding_to_csaf
from .export.cve import finding_to_cve_draft
from .export.openvex import finding_to_openvex
from .export.osv import finding_to_osv, osv_id_for
from .loop import LoopBudget, run_loop
from .profile import (
    Profile,
    UnknownProfileError,
    available_profiles,
    profile_fields,
    resolve_profile,
)
from .protocol import HermesUltraCodeGate, run_session
from .sandbox import NoopSandbox, SandboxError, SandboxPolicy, SandboxResult, SandboxSpec
from .schema import FindingStatus, GateOutcome
from .sessions import (
    DisclosureSession,
    DiscoverSession,
    MapSession,
    NewProjectSession,
    SiblingHuntSession,
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

# Opt-in, per-invocation, and NEVER persisted (FR-1). Unset (or an empty env var)
# is default mode — today's behavior, byte-for-byte (FR-13). Mirrors the
# DEEPTHOUGHT_STATE precedent.
_PROFILE_OPTION = typer.Option(
    None,
    "--profile",
    envvar="DEEPTHOUGHT_PROFILE",
    help=(
        "Opt-in low-friction profile (e.g. mostly_harmless). Unset = default "
        "behavior. Fills unset defaults and trims informational output only; it "
        "changes no gate decision, scope, basis, execution, or transmission."
    ),
)


def _store(state: Path) -> FileStore:
    return FileStore(state)


def _resolve_profile_or_exit(name: Optional[str]) -> Optional[Profile]:
    """Resolve the profile name to a frozen Profile (or None), exiting cleanly on
    an unknown name rather than raising a traceback."""
    try:
        return resolve_profile(name)
    except UnknownProfileError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)


def _echo_session(record, *, profile: Optional[Profile] = None,
                  read_only: bool = False) -> None:
    # terse_output applies ONLY to the read-only verbs
    # (status/map/discover/sibling-hunt). verify/disclose pass no profile here, so
    # their sign-off/execution/transmission banners always render in full (FR-7).
    terse = bool(profile and profile.terse_output and read_only)
    if terse:
        # Collapse the purely-informational header block to one compact line; the
        # body (summary + next steps) is preserved in full.
        gate = record.gate_outcome.value if record.gate_outcome else "-"
        reason = f" reason={record.gate_reason}" if record.gate_reason else ""
        typer.echo(
            f"session {record.id} gate={gate} close={record.close_state.value}{reason}"
        )
    else:
        typer.echo(f"session : {record.id}")
        typer.echo(
            f"gate    : {record.gate_outcome.value if record.gate_outcome else '-'}"
        )
        if record.gate_reason:
            typer.echo(f"reason  : {record.gate_reason}")
        typer.echo(f"close   : {record.close_state.value}")
    typer.echo("")
    # The body — including the session's OWN next steps — always renders in full.
    # The profile never substitutes or suppresses a session's guidance (e.g. a
    # pending VERIFY escalation on a candidate-bearing status); it only trims the
    # informational header above (terse_output).
    typer.echo(record.body)


def _maybe_scope_hint(profile: Optional[Profile], record) -> None:
    """Under a profile, an empty-scope HOLD prints a helpful pointer — the profile
    never invents a scope (FR-5). No-op in default mode (FR-13)."""
    if profile is None:
        return
    if (record.gate_outcome is GateOutcome.hold and record.gate_reason
            and "scope" in record.gate_reason):
        typer.echo("")
        typer.echo(
            "hint: this profile never invents a scope. Pass --scope "
            "<path/module/host> to define the in-scope surface; an empty scope "
            "stays a HOLD (Constitution Article II)."
        )


def _root_default(profile: Optional[Profile], store: FileStore, project_id: str,
                  root: Optional[str]) -> Optional[str]:
    """Under a profile with ``default_root_from_local_path``, an UNSET ``--root``
    defaults to the project's ``local_path`` (FR-4). An explicit ``--root`` always
    wins (FR-17); ``scope.py`` containment (``resolve_within``) is unchanged, so
    every area escaping the root is still refused."""
    if root is not None:
        return root  # explicit flag always overrides
    if profile is None or not profile.default_root_from_local_path:
        return root
    proj = store.get_project(project_id)
    if proj is not None and proj.local_path:
        return proj.local_path
    return root


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
    profile: Optional[str] = _PROFILE_OPTION,
) -> None:
    """Register a project (NEW PROJECT session)."""
    prof = _resolve_profile_or_exit(profile)
    # The profile NEVER supplies a basis (FR-6) or a scope (FR-5): the session is
    # constructed from exactly what the operator passed.
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
    _maybe_scope_hint(prof, record)


@playbook_app.command("status")
def playbook_status(
    project: str = typer.Option(..., help="Project id to summarize."),
    state: Path = _STATE_OPTION,
    profile: Optional[str] = _PROFILE_OPTION,
) -> None:
    """Summarize state without changing it (STATUS session)."""
    prof = _resolve_profile_or_exit(profile)
    try:
        record = run_session(
            _store(state), HermesUltraCodeGate(), StatusSession(project)
        )
    except StoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)
    _echo_session(record, profile=prof, read_only=True)
    _maybe_scope_hint(prof, record)


@playbook_app.command("map")
def playbook_map(
    project: str = typer.Option(..., help="Project id to map."),
    root: Optional[str] = typer.Option(
        None, "--root", help="Local checkout to walk; defaults to the project's local_path."
    ),
    state: Path = _STATE_OPTION,
    profile: Optional[str] = _PROFILE_OPTION,
) -> None:
    """Record the in-scope attack surface, READ-ONLY (MAP session, feature 002).

    Walks only the project's in-scope areas and records Coverage. Executes no
    target code, transmits nothing, and never widens scope.
    """
    prof = _resolve_profile_or_exit(profile)
    store = _store(state)
    root = _root_default(prof, store, project, root)
    try:
        record = run_session(
            store, HermesUltraCodeGate(), MapSession(project, root=root)
        )
    except StoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)
    _echo_session(record, profile=prof, read_only=True)
    _maybe_scope_hint(prof, record)


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
    profile: Optional[str] = _PROFILE_OPTION,
) -> None:
    """Reason over code and SARIF for candidates, READ-ONLY (DISCOVER, feature 002).

    Dispatches one worker that reads any SARIF and writes candidate findings; the
    orchestrator ingests only the typed envelope. Executes no target code,
    transmits nothing, and never widens scope.
    """
    prof = _resolve_profile_or_exit(profile)
    store = _store(state)
    root = _root_default(prof, store, project, root)
    try:
        record = run_session(
            store,
            HermesUltraCodeGate(),
            DiscoverSession(project, sarif_path=sarif, root=root),
        )
    except StoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)
    _echo_session(record, profile=prof, read_only=True)
    _maybe_scope_hint(prof, record)


@playbook_app.command("sibling-hunt")
def playbook_sibling_hunt(
    project: str = typer.Option(..., help="Project id the verified finding belongs to."),
    finding: str = typer.Option(..., help="Verified finding id to hunt siblings of (F-NNNN)."),
    sibling: list[str] = typer.Option(
        [],
        "--sibling",
        help="A pre-registered sibling project id to also hunt. Repeatable.",
    ),
    sarif: Optional[str] = typer.Option(
        None, "--sarif", help="SARIF file to reason over for sibling instances."
    ),
    root: Optional[str] = typer.Option(
        None, "--root", help="Local checkout for code reasoning; defaults to local_path."
    ),
    state: Path = _STATE_OPTION,
    profile: Optional[str] = _PROFILE_OPTION,
) -> None:
    """Hunt read-only for same-class variants of a verified finding (SIBLING HUNT, 004).

    Derives a variant signature from the verified finding's typed fields, gates the
    source project AND each named sibling INDEPENDENTLY, and dispatches one worker
    per gated-proceed target that writes candidate variant findings; the
    orchestrator ingests only the typed envelope. Executes no target code,
    transmits nothing, never creates a project, and never widens scope. A named
    sibling that is not already registered (with its own authorization basis) is
    skipped, never created.
    """
    prof = _resolve_profile_or_exit(profile)
    store = _store(state)
    root = _root_default(prof, store, project, root)
    try:
        record = run_session(
            store,
            HermesUltraCodeGate(),
            SiblingHuntSession(
                project_id=project,
                finding_id=finding,
                sibling_project_ids=list(sibling),
                sarif_path=sarif,
                root=root,
            ),
        )
    except StoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)
    _echo_session(record, profile=prof, read_only=True)
    _maybe_scope_hint(prof, record)


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
    # Accepted for uniform env-activation, but DELIBERATELY not resolved before
    # the hard stop below and never used to alter execution posture: verify
    # constructs only a NoopSandbox dry-run under EVERY profile value (FR-8).
    profile: Optional[str] = _PROFILE_OPTION,
) -> None:
    """Verify a candidate finding in the sandbox (VERIFY session, feature 003).

    By default this NEVER executes untrusted target code. It constructs a
    ``VerifySession`` backed by a ``NoopSandbox`` — the injected sandbox seam that
    records the requested run and returns a canned result without running anything
    — and reports a dry-run that plainly says no execution happened while the
    sandbox sign-off is pending (Constitution Article III; Phase 0 §0.3).

    A real executing backend (``DockerSandbox``) now exists, but it is deliberately
    NOT wired into this CLI: executing target code is confined to the explicit,
    signed-off Tier-2 rediscovery harness, never exposed as a CLI flag against an
    arbitrary project. Passing ``--i-have-sandbox-signoff`` is the hard stop: this
    command exits with a clear message and runs nothing.
    """
    # --- the 003 HARD STOP -------------------------------------------------
    # The sign-off flag is the only path that would ever reach a real executing
    # backend. This CLI deliberately does not wire one (execution lives only in the
    # signed-off Tier-2 benchmark), so we refuse outright and execute nothing. This
    # command NEVER constructs a DockerSandbox with execution enabled, never calls
    # DockerSandbox.run(), and never spawns a subprocess.
    if i_have_sandbox_signoff:
        typer.echo(
            "verify refused: this CLI deliberately does not wire an executing "
            "sandbox backend. Executing untrusted target code is the hard stop; it "
            "runs only in the signed-off benchmark harness, and requires Mahdi's "
            "sign-off plus a valid project-scoped Signoff (Constitution Article III; "
            "Phase 0 §0.3). Nothing was executed.",
            err=True,
        )
        raise typer.Exit(code=2)

    # Non-signoff path: validate the profile NAME for parity with every other verb
    # (a typo'd --profile is still rejected), but AFTER the hard stop and WITHOUT
    # letting the result alter execution posture — verify is a NoopSandbox dry-run
    # under every profile value (FR-8, RT F2.2).
    _resolve_profile_or_exit(profile)

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


@playbook_app.command("disclose")
def playbook_disclose(
    project: str = typer.Option(..., help="Project id the finding belongs to."),
    finding: str = typer.Option(..., help="VERIFIED finding id to draft (F-NNNN)."),
    state: Path = _STATE_OPTION,
    profile: Optional[str] = _PROFILE_OPTION,
) -> None:
    """Draft disclosure artifacts for a verified finding (DISCLOSURE session, 005).

    DRAFT-ONLY (Constitution Article V). From a VERIFIED finding this drafts four
    LOCAL artifacts — an advisory (Markdown), a CVE JSON 5.1 draft, a CSAF 2.0
    advisory, and an OpenVEX statement — and writes them as session detail.

    It transmits NOTHING, never advances the finding to ``disclosed``, and never
    fabricates a CVE or advisory reference. Sending is a human action performed
    outside this tool; Deep Thought drafts only.
    """
    # Validate the profile for uniform env-activation, but NEVER apply terse or
    # auto-next-steps here: disclosure is not a read-only verb, so its full
    # human-gate teach-back and transmission notice always render (FR-7, FR-9).
    _resolve_profile_or_exit(profile)
    store = _store(state)
    # Refuse an unknown project or finding BEFORE entering the harness, so a typo
    # never persists a Session record at all. (The session ALSO refuses a missing
    # finding cleanly for the session-API path, but a CLI typo should write
    # nothing.) The project check additionally avoids an orphan Session that would
    # fail a later `check`.
    if store.get_project(project) is None:
        typer.echo(
            f"disclose refused: project {project!r} not found. Nothing was drafted.",
            err=True,
        )
        raise typer.Exit(code=2)
    if store.get_finding(finding) is None:
        typer.echo(
            f"disclose refused: finding {finding!r} not found. Nothing was drafted.",
            err=True,
        )
        raise typer.Exit(code=2)

    session = DisclosureSession(project_id=project, finding_id=finding)
    try:
        record = run_session(store, HermesUltraCodeGate(), session)
    except StoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)

    _echo_session(record)
    # Only assert the drafting human gate when drafts were actually produced. On a
    # gate hold/refuse or a non-verified refusal the session writes nothing, and
    # the teach-back above already states the reason — a success banner there would
    # misstate the disclosure state.
    if session.artifact_refs:
        typer.echo("")
        typer.echo(
            "HUMAN GATE: nothing was transmitted, no CVE was assigned, and the "
            "finding is unchanged (still verified). Coordinated disclosure requires "
            "a human to review the drafts and send. Deep Thought drafts local "
            "artifacts only."
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


# --- profiles ------------------------------------------------------------
@app.command("profiles")
def profiles() -> None:
    """List available low-friction profiles and the EXACT defaults each applies.

    Read-only introspection (Constitution Article VII): it lets an operator audit
    a profile — its finite loop budget, its root default, and its terse /
    auto-next-steps display flags — before trusting it, and changes no state. It
    also names the ceremony the profile deliberately does NOT streamline (scope,
    authorization basis, and output path are never defaulted).
    """
    profs = available_profiles()
    if not profs:
        typer.echo("no profiles registered")
        return
    for prof in profs:
        budget = prof.default_loop_budget
        bases = ", ".join(sorted(b.value for b in prof.low_ceremony_bases)) or "(none)"
        typer.echo(f"profile: {prof.name}")
        typer.echo(
            "  loop budget (flag-free default): "
            f"max_sessions={budget.max_sessions}, "
            f"max_wall_seconds={budget.max_wall_seconds}, "
            f"max_context_tokens={budget.max_context_tokens}"
        )
        typer.echo(f"  default_root_from_local_path: {prof.default_root_from_local_path}")
        typer.echo(f"  terse_output: {prof.terse_output}")
        typer.echo(f"  low_ceremony_bases (descriptive only): {bases}")
        typer.echo("  scope: NEVER auto-filled — pass --scope (empty stays a HOLD)")
        typer.echo("  authorization basis: NEVER defaulted or guessed")
        typer.echo("  output/state path: NEVER defaulted (no exfiltration knob)")
        typer.echo("  execution: no sandbox field; confers zero execution privilege")
        typer.echo(f"  fields: {', '.join(profile_fields(prof))}")
        typer.echo("")


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
# The finding record (OSV) is emitted for every finding. Disclosure formats are
# meaningful only once a finding is at least verified, so they are status-filtered.
_PUBLISH_FORMATS = ("osv", "csaf", "openvex", "cve-draft", "advisory")
_DISCLOSURE_STATUSES = frozenset(
    {FindingStatus.verified, FindingStatus.disclosed, FindingStatus.patched}
)


def _safe_stem(finding_id: str) -> str:
    """A filesystem-safe AND injective artifact filename stem for a finding id.

    A finding id can contain path separators or ``..`` (the model and check do not
    forbid it, and records can be hand-edited); using it raw in ``out/<fmt>/<stem>``
    could traverse out of the format directory. Percent-encoding every character
    outside ``[A-Za-z0-9._-]`` keeps the stem inside the directory AND injective
    (distinct ids -> distinct stems, so artifacts never silently overwrite), while
    leaving an ordinary id like ``x_F-0007`` unchanged. The stable ``x_`` prefix
    keeps the result from ever being ``.`` / ``..``.
    """
    return quote(osv_id_for(finding_id), safe="") or "artifact"


def _write_format(fmt: str, finding, dest: Path) -> Path:
    """Emit ONE finding in ONE format as a LOCAL artifact; return the path."""
    stem = _safe_stem(finding.id)
    if fmt == "advisory":
        path = dest / f"{stem}.md"
        path.write_text(finding_to_advisory(finding) + "\n", encoding="utf-8")
        return path
    builder = {
        "osv": finding_to_osv,
        "csaf": finding_to_csaf,
        "openvex": finding_to_openvex,
        "cve-draft": finding_to_cve_draft,
    }[fmt]
    path = dest / f"{stem}.json"
    path.write_text(
        json.dumps(builder(finding), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


@app.command("publish")
def publish(
    out: Path = typer.Option("out", "--out", help="Local artifact directory."),
    format: str = typer.Option(
        "osv",
        "--format",
        help="osv | csaf | openvex | cve-draft | advisory | all. Disclosure "
        "formats are DRAFT-ONLY and are emitted only for verified/disclosed/"
        "patched findings.",
    ),
    state: Path = _STATE_OPTION,
    profile: Optional[str] = _PROFILE_OPTION,
) -> None:
    """Emit prepared local artifacts. Asserts the human gate. Transmits nothing.

    ``osv`` (the default) writes the finding record to ``out/`` (unchanged). The
    disclosure formats (``csaf``/``openvex``/``cve-draft``/``advisory``) and
    ``all`` write each into an ``out/<format>/`` subdirectory. No format transmits;
    every write is a local artifact under the human gate (Constitution Article V).
    """
    # Validate the profile for uniform env-activation, but NEVER let it choose an
    # output path (FR-10) or trim the transmission notice (FR-7): the ``--out``
    # default and the human-gate banner are unchanged under every profile value.
    _resolve_profile_or_exit(profile)
    if format != "all" and format not in _PUBLISH_FORMATS:
        typer.echo(
            f"publish refused: unknown --format {format!r}. Choose one of: "
            f"{', '.join(_PUBLISH_FORMATS)}, all.",
            err=True,
        )
        raise typer.Exit(code=2)

    store = _store(state)

    # check is a required hard gate before publish (Constitution Article VII).
    report = run_check(store)
    if not report.ok:
        typer.echo("publish refused: check is not green. Run `deepthought check`.", err=True)
        raise typer.Exit(code=1)

    out.mkdir(parents=True, exist_ok=True)
    selected = list(_PUBLISH_FORMATS) if format == "all" else [format]
    findings = store.list_findings()

    written: list[Path] = []
    for fmt in selected:
        # OSV (the finding record) stays at out/ root for back-compat; disclosure
        # formats are namespaced so multiple JSON formats never collide on name.
        dest = out if fmt == "osv" else out / fmt
        dest.mkdir(parents=True, exist_ok=True)
        # OSV is emitted for every finding; disclosure formats only for findings
        # that are at least verified.
        targets = (
            findings
            if fmt == "osv"
            else [f for f in findings if f.status in _DISCLOSURE_STATUSES]
        )
        for finding in targets:
            written.append(_write_format(fmt, finding, dest))

    typer.echo(f"prepared {len(written)} artifact(s) under {out}/ (format: {format})")
    for path in written:
        typer.echo(f"  - {path}")
    typer.echo("")
    typer.echo("HUMAN GATE: nothing was transmitted. Coordinated disclosure requires")
    typer.echo("a human to review and send. Deep Thought emits local artifacts only.")


def _echo_loop_run(run) -> None:
    typer.echo(f"loop     : {run.id}")
    typer.echo(f"project  : {run.project}")
    typer.echo(f"sessions : {run.sessions_run}")
    typer.echo(f"stop     : {run.stop_reason.value}")
    typer.echo("trace    :")
    for step in run.trace:
        target = step.finding or step.area or ""
        where = step.session_id or "(escalation)"
        gate = step.gate_outcome.value if step.gate_outcome else "-"
        typer.echo(f"  - {step.kind.value:18s} {where:22s} {target:16s} gate={gate}")
    if run.outstanding_actions:
        typer.echo("outstanding (human sign-off):")
        for action in run.outstanding_actions:
            typer.echo(f"  - {action}")
    typer.echo("")
    typer.echo(run.body)


@app.command("loop")
def loop(
    project: str = typer.Option(..., help="Project id to drive (must be registered)."),
    max_sessions: Optional[int] = typer.Option(
        None, "--max-sessions", help="Max sessions the loop may run."
    ),
    max_seconds: Optional[float] = typer.Option(
        None, "--max-seconds", help="Max summed session wall-time."
    ),
    max_tokens: Optional[int] = typer.Option(
        None, "--max-tokens", help="Max summed session context tokens."
    ),
    state: Path = _STATE_OPTION,
    profile: Optional[str] = _PROFILE_OPTION,
) -> None:
    """Drive the safe, gated session chain autonomously under a budget (feature 006).

    Deterministic and bounded: runs STATUS/MAP/DISCOVER/SIBLING HUNT/DISCLOSURE
    behind the Gate, never expands scope, never executes target code, and never
    transmits — a candidate needing real reproduction, and a disclosure needing to
    be sent, are escalated to a human. Requires at least one budget limit; a
    governed stop (fixed point, budget, gate refusal) exits 0.
    """
    prof = _resolve_profile_or_exit(profile)
    no_flags = max_sessions is None and max_seconds is None and max_tokens is None
    used_profile_budget = False
    if no_flags and prof is not None:
        # Under a profile, a flag-free loop uses the profile's FINITE default
        # budget instead of exiting 2 (FR-3). It is a frozen LoopBudget with >=1
        # positive finite limit (validated at profile construction).
        budget = prof.default_loop_budget
        used_profile_budget = True
    elif no_flags:
        typer.echo(
            "error: the loop requires at least one budget limit "
            "(--max-sessions / --max-seconds / --max-tokens) — it is never unbounded"
        )
        raise typer.Exit(code=2)
    else:
        # An explicit flag ALWAYS overrides the profile default (FR-3, FR-17).
        try:
            budget = LoopBudget(
                max_sessions=max_sessions,
                max_wall_seconds=max_seconds,
                max_context_tokens=max_tokens,
            )
        except ValidationError:
            typer.echo("error: every budget limit must be a positive number")
            raise typer.Exit(code=2)
    try:
        run = run_loop(_store(state), HermesUltraCodeGate(), project, budget)
    except StoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)
    _echo_loop_run(run)
    if used_profile_budget:
        # Echo the effective budget so a flag-free run is never opaque (FR-3).
        typer.echo("")
        typer.echo(
            f"budget   : profile {prof.name!r} default — "
            f"max_sessions={budget.max_sessions}, "
            f"max_wall_seconds={budget.max_wall_seconds}, "
            f"max_context_tokens={budget.max_context_tokens}"
        )


if __name__ == "__main__":  # pragma: no cover
    app()
