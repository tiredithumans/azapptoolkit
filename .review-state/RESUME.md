# RESUME — comprehensive project review of azapptoolkit (checkpoint 2026-09-26 12:45 UTC; pushed as .review-state on branch claude/project-review-improvements-8m8rke, draft PR #280)

User request: "Do a comprehensive thorough scan of this project and let me know any improvements, enhancements,
features, or cleanup opportunities." Deliverable = a report (no code changes were asked for). Ultracode was on.

## Where things stand
- 26 finder slices ran (4 workflows), every finding adversarially verified, high bug/security items re-verified.
  Result: 439 findings, 438 surviving (321 confirmed, 117 partially, 1 refuted), 12 high-severity, all in
  `all-findings.json` (ids F001..F439) and `findings-index.md`. Per-section inputs in `buckets/*.json`.
- Toolchain baseline (salvaged logs): all shared-crate tests pass, web-rs host tests pass, wasm check passes
  (future-incompat warning from proc-macro-error2). Desktop crate cannot compile in this container (no WebKitGTK).
- Self-verified notes (unused deps, Exchange error-taxonomy drift, pedantic clippy hot spots): `self-verified-notes.md`.
- Completeness critic DONE (assessment + 6 gap slices; see `critic.json`). Its 6 gap FINDERS were still running
  when the checkpoint was taken (workflow wf_4f243e8f-296).
- Section writers workflow (wf_e624a4c2-684) COMPLETE at 13:12 UTC: `sections/1-bugs-security.md`, `2-cleanup-refactor-perf-deps.md`, `3-enhancements-features.md`, `4-docs-tests-tooling-a11y.md` written and completeness-checked (every id present once; duplicates merged). Writer summaries are in `journals/wf_e624a4c2-684.jsonl` (needed by the assembler).

## Workflow ids (transcripts under /root/.claude/projects/-home-user-azapptoolkit/12cb2860-e7bf-55f0-b15e-42e55e824c8b/subagents/workflows/)
| purpose | run id | script (workflows/scripts/) | status |
|---|---|---|---|
| backend-crates slices | wf_d88485ea-39b | review-slice-wf_d88485ea-39b.js | complete |
| backend-app slices | wf_e68e5b2b-501 | review-slice-wf_e68e5b2b-501.js | complete |
| frontend slices | wf_142c1a69-d8e | review-slice-wf_142c1a69-d8e.js | complete |
| cross-cutting slices | wf_005ba226-6d7 | review-slice-wf_d88485ea-39b.js (same script, different args) | complete |
| gap critic + gap finders | wf_4f243e8f-296 | review-gap-critic-wf_4f243e8f-296.js | critic done; finders in flight |
| section writers (buckets 1-4) | wf_e624a4c2-684 | review-section-writers-wf_e624a4c2-684.js | in flight |
Copies of every journal.jsonl are in `journals/<run id>.jsonl` (one `result` record per finished agent).

## How to resume
1. If the container survived: `python3 consolidate.py` (reads the journals in place; add the gap workflow's results
   automatically because wf_4f243e8f-296 is registered in `wf_labels`). Resume unfinished workflows with
   `Workflow({scriptPath: <script>, resumeFromRunId: <run id>, args: <same args>})` — finished agents replay from cache.
   The slice-workflow args (finder lists) are recorded in the task output files and in `slices.md`; the gap-critic
   and section-writer scripts take no args.
2. If the container was reclaimed: restore `.review-state/` from the branch `claude/project-review-improvements-8m8rke`
   into a scratch dir, point `BASE` in `consolidate.py` at `journals/` (rename files to `<run id>/journal.jsonl`), and
   re-launch only what is missing: the 6 gap finders (prompts in `critic.json`), the section writers, judges, assembler.
3. Remaining pipeline (plan in `plan-synthesis.md`, prompts in `synthesis-prompts.md`):
   a. gap finders → verify → recheck (wf_4f243e8f-296) → `python3 consolidate.py` → `buckets/5-gap-slices.json`.
   b. DONE for buckets 1-4; still needed: one writer for bucket 5 (gap findings) → `sections/5-gap-slices.md`.
   c. judge panel (2 lenses) → assembler writes `sections/0-head.md` (exec summary, scorecard, top-12, quick wins,
      strategic) and `sections/9-tail.md` (refuted, nits, coverage).
   d. `cat sections/0-head.md sections/1-*.md ... sections/9-tail.md > azapptoolkit-review-2026-09-26.md`; spot-check
      top items against the code (7 of 12 highs already spot-checked by the main session and agree); SendUserFile.
   e. Final chat summary: lead with the 12 high items and the top themes; offer an Artifact page in one line.

## The 12 high-severity, twice-verified items (all confirmed)
F036/F139 updater.rs:26 — documented auto-update opt-out (AZAPPTOOLKIT_AUTO_UPDATE / settings.auto_update) never read.
F039 backup.rs:675 — managed-identity backup pass not session-latched; per-MI read failures not recorded in `skipped`.
F054 exchange/mail_scopes.rs:108 — resolve_mail_scopes hardcodes Graph; EWS full_access_as_app never gets a verdict.
F070 sso/claims.rs:48 — claims codec mis-models transformation-sourced schema entries (TransformationID vs ID).
F105 auth/service/mod.rs:313 — domain-form tenant id accepted by config screen but can never sign in (tid GUID compare).
F151 core/scoping.rs:195 — mailbox advisory misses MailboxItem.*/MailboxFolder.*/Mail-Advanced.* families.
F178 graph/client/sharepoint.rs:105 — list_all_sites drops truncation signal; >5000-site sweep cached as complete.
F295 scripts/setup.sh:132 — `just setup` panics on a fresh clone (cargo check before any frontend dist).
F371 sso_tab.rs:543 — unreadable claims policy rendered as empty editor; Save detaches the real policy.
F394 exchange_scoping_section.rs:324 — toasts "Migrated" on a partial AAP report.
F424 dr.rs:502 — DR view claims re-run restore "recreates only what is missing"; backend creates unconditionally.

## Checkpoint hygiene
The repo's whole-history secrets scan (gitleaks private-key rule) fired on PEM armour text quoted in finding F008. The
committed copies under `.review-state/` are defanged by `checkpoint.sh` (`[PEM BEGIN …]`), and the two fingerprints from
the first checkpoint commit are listed in `/.gitleaksignore`; delete that file together with `.review-state/`.

## Progress 2026-09-26 16:55 UTC (resumed after the second usage-limit pause)
- Gap-critic finders all done: 52 gap findings (2 high, confirmed: F487 updater has no install-format gate for MSI/.deb;
  F488 Linux release leg builds on floating ubuntu-latest). Two gap verifiers + one recheck were re-run
  (wf_4f243e8f-296 resumed at 16:51); 26 gap findings were still `pending` at this checkpoint.
- Judge panel launched (wf_ae705326-921: judge:risk + judge:leverage, effort high). Its result feeds the assembler.
- Remaining: writer for `buckets/5-gap-slices.json` -> `sections/5-gap-slices.md`; assembler -> `sections/0-head.md` +
  `sections/9-tail.md`; cat into `azapptoolkit-review-2026-09-26.md`; spot-check; SendUserFile + chat summary.
