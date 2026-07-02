# Tasks: Disclosure — draft-only advisory & VEX (005)

Test-first, gate-first. Each build task lands its failing tests before the code
that satisfies them. `[P]` marks tasks that can run in parallel (independent
files). The whole feature is DRAFT-ONLY: no task adds a transmit path or a
lifecycle transition.

## Setup

- **T001** Create `specs/005-disclosure/` docs (spec, plan, data-model,
  contracts, tasks). ✔ (this set)
- **T002** Bundle the authoritative schemas: `src/deepthought/export/csaf_schema.json`
  (OASIS CSAF 2.0) and `src/deepthought/export/cve_schema.json` (CVE Record 5.1),
  alongside the existing `osv_schema.json`. Confirm each loads via
  `importlib.resources` under an `@lru_cache` helper (mirror `_osv_schema`).

## Exporters (each: tests first, then implementation)

- **T003 [P]** Advisory: `tests/export/test_advisory.py` — `finding_to_advisory`
  renders the fixed section order, includes severity only when present, carries
  finding free-text inertly, and ends with the DRAFT status footer. Then
  `src/deepthought/export/advisory.py`.
- **T004 [P]** CSAF: `tests/export/test_csaf.py` — `validate_csaf(finding_to_csaf(f))
  == []`; field mapping (title/notes/scores/product_tree/references); no
  fabricated `cve` (uses `ids[]` when `cve` is `None`); `tracking.status == "draft"`;
  scores omitted when `severity is None`; injection-inertness. Then
  `src/deepthought/export/csaf.py` (+ `CSAF_VERSION`, `validate_csaf`).
- **T005 [P]** OpenVEX: `tests/export/test_openvex.py` — `validate_openvex(...)
  == []`; document + statement required fields; `status == "affected"` always
  carries `action_statement`; never asserts `not_affected`; `vulnerability.name`
  falls back to the finding id; injection-inertness. Then
  `src/deepthought/export/openvex.py` (+ `OPENVEX_CONTEXT`, programmatic
  `validate_openvex`).
- **T006 [P]** CVE draft: `tests/export/test_cve.py` — `validate_cve_draft(...)
  == []` (structural); CNA required members present; sentinel `cveId` and zeroed
  assigner UUID; `test_cve_placeholder_cveid_rejected_by_strict_validator` (the
  sentinel fails `^CVE-[0-9]{4}-[0-9]{4,19}$`); metrics omitted when `severity is
  None`; `problemTypes` omitted when no CWE; injection-inertness. Then
  `src/deepthought/export/cve.py` (+ `CVE_SCHEMA_DATAVERSION`,
  `validate_cve_draft`).

## Disclosure session

- **T007** `tests/sessions/test_disclosure.py` — refuse wrong project; refuse
  non-verified (candidate/disclosed/patched → refusal, nothing drafted); drafts
  all four artifacts (four `write_detail` refs; each blob passes its validator);
  `does_not_transition_to_disclosed` (status stays `verified`; the transition is
  never called); `transmits_nothing` (no network import/call; only `write_detail`);
  `does_not_set_cve_or_advisory_ref`; `next_steps_non_empty_and_names_human_gate`.
- **T008** `src/deepthought/sessions/disclosure.py` — `DisclosureSession`
  implementing `build_gate_context` + `run` per the contract (draft-only,
  detail-only, no lifecycle mutation).

## Check wiring

- **T009** `tests/test_check.py` additions — `_check_csaf`/`_check_openvex` fold
  validator errors into failures; a raising exporter degrades to a failed check
  (not a crash). Then register `_check_csaf` and `_check_openvex` in
  `check.py::run_check`. (The CVE draft is intentionally not checked.)

## CLI wiring

- **T010** `tests/test_cli.py` additions — `playbook disclose` runs the session
  and prints the teach-back; `publish --format csaf` writes `out/csaf/*.json`
  (validates); `--format all` writes every `out/<fmt>/`; default `--format osv`
  unchanged (back-compat); disclosure formats status-filtered to
  `verified`/`disclosed`/`patched`; `publish` still refused on a red `check`
  (`Exit(1)`); HUMAN GATE banner present; no network path exists. Then wire
  `playbook disclose` and `publish --format` in `cli.py`.

## Package exports

- **T011** `src/deepthought/export/__init__.py` re-exports the new builders /
  validators / constants; `src/deepthought/sessions/__init__.py` exports
  `DisclosureSession`; update the export docstring (CSAF/OpenVEX are no longer
  "deferred to feature 005").

## Validation and gate-before-done

- **T012** `scripts/smoke_005.sh` — the hermetic flow from `plan.md`
  (new-project → discover → verify → disclose → assert still `verified` → check
  green → `publish --format all` → negative red-check case → grep no-CVE /
  no-advisory-ref). Make it executable; follow `smoke_004.sh`'s shape.
- **T013** `pytest` green (all new tests + the existing suite); all five smokes
  pass (`smoke.sh`, `smoke_002.sh`, `smoke_003.sh`, `smoke_004.sh`,
  `smoke_005.sh`); `deepthought check` green on the produced state.
- **T014** Update `.claude/skills/deep-thought-protocol/SKILL.md` with a
  DISCLOSURE (draft-only) entry and the transmit/transition hard-stop note.
- **T015** Write `docs/build-log/005-disclosure.md` (status, what shipped, safety
  invariants, tests, review).

## Definition of done for 005

- All of T002–T015 complete; `pytest` + five smokes green; `check` green.
- Author every commit as `MahdiHedhli <16087011+MahdiHedhli@users.noreply.github.com>`;
  never credit Claude.
- Open PR; run the standing **dual-gate review** — codex (bot, or the local
  `codex review --base main` CLI when the bot lags) **and** agy (Antigravity /
  Gemini adversarial CLI) — both clean on the same HEAD. Silence / errors /
  quota limits count as an incomplete review, never a pass.
- **Merge-on-clean:** once both gates are clean and threads are resolved,
  squash-merge autonomously and continue. Only stop for Mahdi if the gates reach
  a genuine consensus conflict or a real design decision surfaces.
- **Hard stops remain (require Mahdi's sign-off, never autonomous):** any
  transmission/send/publish-externally of a disclosure, any auto-transition to
  `disclosed`, and any fabrication of a CVE or advisory reference. Each → URGENT
  NTFY to `Mahdi-Dev` + wait.
