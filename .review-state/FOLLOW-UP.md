# Review follow-up — items not yet implemented

Remaining work from the 2026-09-26 review (`azapptoolkit-review-2026-09-26.md`) after #281 merged.

## Tier 3 — DONE on `chore/review-follow-up` (2026-10-02)
- F230 tokio feature trim → `fb53f42` (+ web-rs lockfile sync `6958df9`)
- F299 hand-mirrored tauri-cli version literal → `d5c0e12`
- F285 updater signing key scoped to the bundle step → `9f081ef`
- F300 intra-doc-link rustdoc gate → `4a29b5a`
- F216 six low-FP clippy lints + pedantic recipes → `0d8def0`
- F309 `just bump` recipe → `bbaf469`
- F232 reqwest HTTP/2 re-enabled (perf effect **unmeasured** — operator's call) → `910cb10`
- F094 permission tester lists/revokes the tested resource's Selected entries → `3103bc4`

## Module splits — DONE
- F016 `commands/permissions.rs` → directory module → `e2c67c7`
- F028 `commands/audit.rs` → directory module → `9ef935b`
- F076 `commands/sso/mod.rs` → directory module → `d482f56`

## Tier 4 — Enhancements & feature opportunities (not started)

The per-item set IS defined: the review doc's **"## Enhancements and feature
opportunities"** section (108 findings / 106 entries after the F042+F428 and
F264+F276 merges; 30 medium + 78 low; 58 S / 45 M / 5 L). The "8 enhancement
packages" label is the separate **"## Strategic projects"** list — those span
buckets (Idempotent DR restore pulls from Bugs; Run identity from gap slices),
so it is not the per-item enhancement set.

Already done from this bucket: **F094** → `3103bc4` (permission tester
lists/revokes Selected entries; its ship-together partner F073 — the dead
"(capped)" branch — remains open). **F309** → `bbaf469` (`just bump`).

Remaining 87 entries by area (read the section for each item's Problem +
Proposal; #### items are full entries, one-liners are bullets):

- **Audit & remediation (9)** — **all closed 2026-10-02.** F125 · F129 · F027
  (+ its UI Callout) · F034 · F035 · F127 + F402 (+ F393) verified already
  implemented on main (unconfinable-reach markers have their groups + posture
  counts; preparatory progress and unconditional caveat strips exist). F133
  shipped as the dedicated `AuditItem.app_owner_organization_id` column (SP rows
  keep `publisher: None`), not a publisher rewrite. F138 implemented:
  `issue::ORG_WIDE_FILES` advisory in Rule 12 (no remediation) + the
  `least_privilege_alternative_for` Files arm, so picker hint, audit
  recommendation and item wizard agree.
- **Scoping (Exchange/SharePoint) & resource access (9)** — closed 2026-10-02
  except **F174 · F263** (below). F060 · F406 · F407 · F439 verified already
  implemented on main (consolidated "Scoping is NOT effective" warning through a
  helper shared with `aap_migration`; `is_held_scopable` carries the resource,
  comment fixed; Grant write is Secondary with read Primary last; `do_probe`
  clears a stale result when the target changes). F069 step 1 (tester reads BOTH
  SP resources, labels SPO grants) shipped with F094; step 2 (converter strips
  the SPO copy + widened `is_scopable_sharepoint_resource_permission`) is
  **declined after review** — the design now deliberately keeps per-row Scope
  actions Graph-only because the conversion's grant and strip targets Microsoft
  Graph (F406 documents it; the picker hint agrees by omission). F436's
  display-name substitution verified implemented; its remaining tab reset landed
  with F197. F197 implemented: `enableRbacAuthorization` reaches
  `KeyVaultSweepResult.vaults_access_policy_mode`, so access-policy vaults are
  named in the sweep summary + export instead of reading as all-clear.
  **Open — F174:** the decommission teardown is a real gap (no
  `Remove-ManagementScope`/`Remove-ServicePrincipal` anywhere); it needs
  prove-zero-references + separately-confirmed design modelled on
  `delete_exchange_scope_group`'s live re-checks. **Blocked — F263:** parsing
  `RecipientAdministrativeUnitScope` requires the real wire key confirmed from a
  live role-assignment envelope before code exists; guessing the key is the
  failure mode the entry warns about.
- **Credentials & SSO (13)** — F075 · F385 · F382 · F381 · F374 · F373 · F338 ·
  F085 · F392 · F190 · F079 · F196 · F200
- **App-reg editing: auth / Expose an API / federation (5)** — F017 · F158 ·
  F162 · F342 · F350
- **Enterprise apps & managed identities (5)** — F377 · F378 · F391 · F389 ·
  F206
- **Operator tooling: search, DR, settings, readiness (18)** — F040 ·
  F042+F428 · F258 · F009 · F012 · F049 · F053 · F271 · F024 · F163 · F262 ·
  F157 · F153 · F149 · F369 · F390 · F432 · F434
- **Auth, sign-in & network resilience (9)** — F110 · F112 · F181 · F183 ·
  F427 · F114 · F113 · F354 · F018
- **Frontend consistency & polish (8)** — F341 · F357 · F355 · F322 · F321 ·
  F327 · F325 · F326
- **Graph API capabilities not yet adopted (9)** — F161 · F078 · F268 ·
  F264+F276 · F259 · F260 · F270 · F265 · F274
- **Product-gap proposals (11)** — F266 · F267 (#109 posture snapshot + drift
  report, effort L) · F278 · F269 · F272 · F273 · F275 · F277 · F279 · F280 ·
  F283
- **Docs, demo, packaging & release tooling (7)** — F247 · F413 · F420 · F222 ·
  F250 · F298 · F311

If picking items up, respect "Changes that must ship together": F027+F058 and
F127+F402+F393 shipped closed (see above — the paired flag/Callout and the
marker/group/posture trio landed in one change each); F075's `warnings` field
is dead weight until `sso_summary.rs` renders it. Before implementing a
remaining item, confirm it against current main — several entries describe
gaps that have since been closed.

## Wrap-up
- `just verify-full` is **green end to end** on this branch's final head (incl.
  the two `Cargo.lock` yoke-derive 0.8.3→0.8.4 fixes, needed because 0.8.3 was
  yanked and `[advisories] yanked = "deny"`).
- Correction to the earlier note: this box CAN run the browser GUI tests —
  wasm-pack downloads a matching chromedriver and `web-itest` ran here, all 4
  shards. The first run failed 3/48 in `gui_2`: the three F094
  `permission_tester` probe tests timed out because `mount_and_probe` typed the
  SharePoint URL without a tick after the tab click, so the URL input was not
  yet mounted and `set_input_value` no-oped. Fixed with flush ticks in
  `tests/gui/permission_tester.rs`; gui_2 is 48/48.
- Still unproven locally, CI-only: actionlint, shellcheck, secrets scan, CodeQL.
