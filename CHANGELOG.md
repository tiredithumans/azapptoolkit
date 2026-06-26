# Changelog

All notable changes to azapptoolkit are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **macOS and Linux release packages.** The release workflow now builds for all
  three platforms on their native runners: Windows (MSI + NSIS, unchanged), macOS
  (`.dmg` + auto-update payload, Apple Silicon), and Linux (`.AppImage` + `.deb`).
  The in-app auto-updater covers all three — `latest.json` now carries
  `darwin-aarch64` and `linux-x86_64` alongside `windows-x86_64`. macOS builds are
  unsigned for now (first launch needs a one-time Gatekeeper bypass — see the
  README); Apple notarization can be layered on later like the optional Windows
  Authenticode signing. New `just build-macos-updater` / `build-linux-updater`
  recipes; `bundle.targets` is now `"all"`.

- **Live web demo on GitHub Pages.** The full Leptos/Thaw UI now runs in a plain
  browser with curated sample data and no Tauri backend — try it at
  <https://tiredithumans.github.io/azapptoolkit/> with no install and no sign-in.
  The demo reuses the GUI test harness's mock IPC bridge (extracted to a shared
  `ipc_mock` module): a new `demo` Cargo feature pre-loads it with fixtures and
  signs into a demo tenant, and a banner marks it as read-only (mutations and
  exports are disabled). Built with `just web-build-pages` and published by a new
  `pages.yml` workflow; the desktop build is unaffected (the feature is off by
  default, so the mock and fixtures never enter the shipped bundle).

## [0.8.0] - 2026-06-26

### Added

- **Force re-authenticate in place when a session expires — no manual sign-out.**
  When the stored refresh token is expired or revoked, the **Refresh Token**
  button now falls back from the silent re-mint to one interactive browser
  round trip (pinned to the current account), restoring the session without
  signing out — so the cached lists and audit run survive. Additionally, any
  command that fails because the session is dead now surfaces an error toast
  with a **Re-authenticate** action, so recovery appears exactly when it's
  needed instead of leaving the user stuck. New `reauthenticate` command.

- **Interactive auto-update with a changelog splash.** When a new release is
  available, the app now shows a toast on launch ("Update available: vX.Y.Z —
  View changelog") that opens a splash listing the version's release notes with
  an **Update & restart** button (which downloads, installs, and relaunches,
  showing download progress) and a **Later** dismiss. A manual **Check for
  updates** button sits by the version in the nav. The release manifest
  (`latest.json`) now carries the `CHANGELOG.md` section as its `notes`, so the
  splash shows real changelog text.

### Changed

- **Updates are no longer installed silently in the background.** The former
  silent download-and-install on launch is replaced by the interactive prompt
  above, so the user sees what's changing and chooses when to restart.

## [0.7.0] - 2026-06-24

### Changed

- **Security Audit revamp — the audit is now the hero of the Security surface.**
  The Security sub-tabs are reframed: the audit is the default, full-width view,
  and the inventory lenses (Credential expiry, Delegated grants) move behind a
  subordinate "Detailed inventories" selector (all deep-links and keep-alive
  panes are preserved). The **App permissions** lens is removed — its data was
  redundant with the audit's findings. The audit's flat 14-item facet tab bar is
  replaced by **two combinable filters** — a primary risk-severity selector (All
  / Critical / High / Medium / Low) and a collapsible finding-type chip drawer
  (Expired, Unused, Over-privileged, High-risk delegated, Org-wide mailbox,
  Scoped mailbox, Org-wide SharePoint, Scoped sites, Unowned) — that
  **intersect** (e.g. "Critical apps with an expired credential"). The
  **Expired** finding matches only already-expired credentials (proactive
  "expiring soon" rotation lead-time stays in the Credential-expiry lens). The
  posture scorecard is regrouped into Risk and Findings rows; each card seeds its
  own dimension and composes with the other.
- **The Home dashboard's Security Posture card surfaces more drill-ins** —
  Critical / High / Medium / Expired / Over-privileged / Org-wide mailbox /
  Org-wide SharePoint / Unowned / Unused — each jumping to the audit pre-filtered
  to that subset.

### Added

- **Multi-select + context-aware inline bulk actions on the Security Audit table
  and App Registrations list.** Check rows to reveal an inline bar; on the audit
  it offers the remediation matching the active finding filter — **Remove expired
  credentials** (Expired), **Remove redundant permissions** (Over-privileged),
  **Scope mailbox access** to chosen groups (Org-wide mailbox), **Scope SharePoint
  access** to chosen sites (Org-wide SharePoint) — plus Delete, with live
  progress, cancel, typed confirmation for destructive actions, and a per-item
  result summary. The App Registrations list / Bulk Actions page keep the
  management set (Grant consent / Remove expired / Delete). The new bulk
  remediations (`bulk_remove_redundant_permissions`, `bulk_scope_mailbox_access`,
  `bulk_scope_sharepoint_access`) reuse the single-app remediation cores, so each
  app's live re-resolution, grant-before-strip safety, and cache invalidation
  match the one-click fixes. The audit table keeps its own selection set, separate
  from the App Registrations list's. The Enterprise Applications list is
  intentionally excluded (its rows are service principals, which the
  app-registration bulk commands can't target).

## [0.6.0] - 2026-06-24

### Added

- **Home dashboard metrics drill into a pre-filtered list.** Clicking a count on
  the Overview cards now jumps to the matching list/lens filtered to that subset,
  instead of just landing on an unfiltered list: Enterprise Applications'
  Disabled / Foreign and Managed Identities' System / User → their list's facet;
  Credential Health's Expired / ≤7d / ≤30d → the per-credential Credential-expiry
  lens (so the drilled count matches the clicked metric); Security Posture's
  Critical / High / Ownership / Unused → the audit view's matching facet. Zero
  counts stay muted and non-clickable (nothing to drill into). The facet of each
  drilled surface (enterprise / managed-identity / audit / credential-expiry) is
  lifted to the `Session` alongside the searches and reset on tenant switch so a
  metric click can seed it; drilling into the Enterprise list also auto-expands
  its filter drawer so the active chip is visible.
- **`just clean` reclaims disk.** A new task-runner recipe that runs `cargo
  clean` against both independent build trees — the root workspace and the
  web-rs frontend (excluded from the workspace, so the root clean never reaches
  it, and its `target/` is by far the larger). Frees disk when the cargo build
  caches grow unbounded.
- **Typed "DELETE" confirmation for the dangerous SP deletes.** Deleting a
  foreign-tenant or Microsoft first-party enterprise application's service
  principal (which can break tenant-wide sign-in) now requires typing `DELETE` to
  confirm, matching the bulk-delete guard; an ordinary in-tenant SP keeps the
  one-click confirm.
- **Detail panes now offer Retry when a load fails.** A transient 429 / network
  blip on an App Registration, Enterprise App, or Managed Identity detail load
  used to leave a static `error [code]: message` dead-end; it now shows the
  message with a Retry button (and a muted code), matching the list views. Shared
  `DetailLoadError` component across the three panes.
- **Empty tenants get an onboarding call-to-action.** An App Registrations /
  Enterprise Applications list with no items shows a "Create your first…" empty
  state with a primary create button, instead of the "adjust your search or
  filters" copy meant for a filtered-empty list.

### Changed

- **Permissions tab — clearer primary action.** "Grant access" (the wizard) is
  now the sole primary button; "Grant admin consent" (in-place consent of
  already-declared permissions) is demoted to a secondary action so the two are no
  longer competing primaries.
- **Grant-access wizard explains a disabled "Next".** Step 1 now shows a "Select
  at least one permission to continue." hint while the cart is empty, instead of a
  mutely-disabled button.
- **Consistent loading skeletons.** The Managed Identity detail pane's permission
  and Azure-role tables now show a skeleton placeholder while loading, matching
  the other detail surfaces (was a bare spinner).
- **Bulk delete / grant-consent now run with bounded concurrency and adaptive
  throttling.** Both ran fully serially with a fixed 50 ms pause between items —
  slow on the healthy path yet with no back-off under throttling. They now fan out
  through the shared bounded-concurrency dispatcher with an adaptive
  `ConcurrencyThrottle` (the in-flight cap halves on a Graph 429 and recovers when
  quiet), and report the live cap to the progress UI. The expired-credential sweep
  gains the same adaptive back-off (it had a fixed cap) and now projects only the
  fields it reads (`passwordCredentials`) instead of full app payloads.
- **Removed a dead, uncached `list_applications` command** that bypassed the
  cached app-list path and had no callers.
- **Workspace upgraded to Rust edition 2024** (from 2021), across both the native
  workspace and the excluded `web-rs` (WASM) frontend. `web-rs`'s declared MSRV
  rises 1.82 → 1.96 to clear the edition's 1.85 floor and match the root workspace;
  the pinned toolchain (`rust-toolchain.toml`, 1.96.0) and CI are unchanged. No
  source edits were required — `cargo fix --edition` surfaced only benign
  `tail_expr_drop_order` drop-order notes (HTTP-client and `JsValue` teardown),
  which are allow-by-default on edition 2024.
- **Tenant-wide reads are now cached, cutting redundant Graph traffic.** The
  service-principal sign-in activity report (a slow beta endpoint that paginates
  the whole tenant) is cached per tenant, so clicking through several apps' Activity
  tabs — and the security audit — share one fetch instead of re-scanning it each
  time. The Home dashboard's credential-expiry list is likewise read-through cached
  (it was re-scanning every app registration on each cold load, duplicating the
  apps list's own scan); it's busted whenever a credential or app changes, so a
  just-rotated credential is never shown as still-expiring. The discovered Graph
  activity workspace and ARM role-definition names are documented as read-only
  until their cache TTL / sign-out (cleared via "Clear all" in Cache diagnostics if
  ever re-pointed mid-session).

### Fixed

- **Stale service-principal cache no longer skews audit posture or detail panes.**
  Mutating an enterprise application's service principal — toggling sign-in /
  assignment-required, hiding it, changing SSO mode, or deleting it — now busts
  the per-app SP cache, so a re-run security audit reads the live `accountEnabled`
  (correct Rule-4 risk score) and the app-registration detail pane never shows a
  just-deleted paired SP. Previously these stayed cached for up to 60 minutes.
- **First permission grant on an unpaired app now appears immediately.** When a
  grant (single, admin-consent, or bulk) creates an app registration's first
  enterprise service principal, the App Registrations / Enterprise Apps lists and
  global search now refresh right away instead of waiting out the 60-minute cache
  TTL or a manual refresh.

## [0.5.0] - 2026-06-23

### Changed

- **The "Grant scoped access" wizard is now the unified "Grant access" flow,
  replacing the separate "Add permission" picker.** Each Permissions surface (app
  registration, enterprise app, managed identity) now has a single **Grant
  access** button. Step 1 is the full live permission catalog (every resource,
  Application + Delegated, searchable) as a **multi-select cart** — pick as many
  permissions as you want, then grant them in one pass. Step 2 auto-offers scoped
  targets (mailbox group or SharePoint sites) **only when the whole selection is
  one scopable mechanism** (all mailbox, or all SharePoint); mixed, non-scopable,
  or delegated selections grant org-wide, preserving "one mechanism per run". The
  per-row **Scope…** action still opens the wizard pre-seeded to that permission.
  The old inline single-grant picker (one permission per click, always org-wide)
  is retired; the catalog `PermissionPicker` is now a reusable multi-select
  component the wizard embeds.

## [0.4.0] - 2026-06-22

### Added

- **"Grant scoped access" wizard — one guided flow for confining permissions,
  across mechanisms.** A single always-available **Grant scoped access…** button
  on the Permissions tab (app registrations) and the Enterprise App / Managed
  Identity detail panes opens a three-step wizard — pick the permissions → choose
  the targets → review & grant — replacing the old "grant org-wide, then hunt for
  the scoping menu, then strip the grant" dance *and* the per-row inline scope
  nudge (now retired, along with `scope_panel.rs`). The wizard **dispatches on the
  scoping mechanism**: **Exchange RBAC** (Mail/Calendars/Contacts) confines to a
  mailbox group — declare-only, so no org-wide Entra grant is ever created (the
  `declare_app_permission` command) — and **SharePoint** (`Sites.*`) confines to
  specific sites via `Sites.Selected` (`convert_site_access_to_selected`). Picking
  a permission locks the run to its mechanism (scope the other separately); a held
  row's **Scope…** opens the wizard pre-selected to that permission. A de-emphasized
  **org-wide (no scoping)** option remains for the rare permission that needs
  tenant-wide reach. Built on the `ScopeKind` registry, so new mechanisms
  (Administrative Units, Azure RBAC, Teams resource-specific consent) drop in as a
  registry entry + a target panel + an apply arm. Managed-group mailboxes and the
  site list are managed inline via shared `ManagedScopeGroupPanel` /
  `SiteSelectionPanel` components.

### Internal

- **Scope-mechanism registry in `azapptoolkit-core::scoping`.** A single
  `scope_kind(value)` classifier + the `ScopeKind` enum (Exchange / SharePoint) +
  per-mechanism metadata (`target_noun` / `capability_key` / `admin_applicable`) —
  one source of truth for which mechanism, if any, scopes a Graph permission, and
  the dispatch key the scope wizard is built on. `admin_applicable()` is the seam
  for future owner-consented mechanisms (e.g. Teams resource-specific consent) that
  render guidance instead of an apply button.
- **GUI test coverage for the scope wizard.** Browser GUI tests (`just web-itest`)
  drive `ScopeWizard` end-to-end per mechanism: the Exchange scoped path declares
  each permission and assigns scoped roles with `removeUnscopedEntraGrants = true`
  (no org-wide grant); the org-wide option grants via `grant_single_permission`;
  SharePoint routes to `convert_site_access_to_selected` (`removeOrgwide = true`)
  and never touches Exchange RBAC; and a pre-seeded open jumps to the target step.
  The managed-identity picker test verifies the org-wide-direct grant after the
  inline scope nudge's retirement. Adds a `set_textarea_value` harness helper plus
  typed catalog / exchange / sharepoint fixture builders behind `test-support`.

## [0.3.2] - 2026-06-22

### Internal

- **Dependency refresh.** Both lockfiles — the root workspace and the
  workspace-excluded `web-rs` front-end — were updated to their latest
  semver-compatible versions: notably `rustls` 0.23.41, `quinn` 0.11.11, and
  `time` 0.3.51 (+ `time-macros`), alongside routine bumps to `bytes`,
  `camino`, `cc`, `getrandom`, `log`, `quote`, `web_atoms`, and the
  `wasm_split_*` helpers. Stale build-time transitives (`wit-bindgen` /
  `wasm-encoder` / `wasmparser` tooling) were pruned from the graph. No held
  major versions were touched (`rand` / `sha2` / `rsa` unchanged), and the
  RustSec advisory scan plus the cargo-deny license/source/bans gates remain
  green on both trees.

## [0.3.1] - 2026-06-22

### Added

- **Cancel button for Bulk Actions.** A long-running bulk grant / delete /
  remove-expired / create run can now be stopped from the UI — the backend bulk
  loops already polled the shared cancel flag, but the page had no control wired
  to it. A new `cancel_bulk` command drives it; the in-flight run still returns
  its partial result, tagged cancelled.
- **Retry on a failed list load.** When the App Registrations or Enterprise Apps
  list fails to load (e.g. a transient 429 or network blip), the error now offers
  an in-context **Retry** instead of a dead-end message — matching the dashboard
  cards.
- **Rate-limit back-off notice on the security audit.** When Microsoft Graph
  throttles a scan and the adaptive concurrency cap drops below its peak, the
  audit view now explains the slow-down (the same notice the DR backup shows), so
  a throttled scan reads as expected rather than stalled.

### Changed

- **Confirmation before revoking an enterprise application's permission.**
  Revoking a held app-role grant on an Enterprise App now prompts for
  confirmation, matching the Managed Identity pane — the identical action was
  previously a single un-guarded click that could break a live integration.
- **The App Registrations "Permissions" tab is now labelled "API permissions"**
  (the Entra portal's term) to distinguish the permissions an app *requests*
  (`requiredResourceAccess`) from the *held* grants shown on the Enterprise App /
  Managed Identity "Permissions" tabs. The routing value is unchanged, so
  deep-links still work.
- **Faster mailbox reverse-lookup.** The "who can reach this mailbox" probe now
  resolves every candidate's service-principal appId in one batched Graph read
  (`$batch`, ~20×) up front instead of one round trip per candidate.
- **Faster security audit on cold caches.** Each app's distinct resource indexes
  are now resolved concurrently rather than one serial round trip at a time.
- **Faster DR restore.** Principal resolution (users/groups by UPN / display
  name) is memoized for the run, so a principal reused across owners, assignees,
  and group memberships is searched once instead of per occurrence.

### Fixed

- **Actionable error guidance no longer collapses onto one line.** The recovery
  hints the backend attaches after a blank line (e.g. "You may need the Exchange
  Administrator role" on a 403) are now rendered with their line breaks intact
  instead of being flattened away.
- **The first-run configuration screen now shows a recovery hint** for each
  failure (invalid client/tenant ID, or a settings.json write error) instead of a
  raw `error [code]: message` dump — matching the sign-in screen.

### Internal

- **The WASM frontend (`web-rs`) is now linted under clippy** (`-D warnings`) in
  `just verify` and CI. Previously the largest, IPC-privileged tier escaped the
  lint gate entirely because it is excluded from the root workspace; the existing
  warnings are fixed.
- **The release workflow re-runs the RustSec advisory scan before building the
  installers**, so an advisory filed after the last main-branch CI run can't ride
  into a shipped build unscanned.
- **Internal cleanup (no behaviour change):** the 1,700-line
  `commands/applications.rs` was split into a `commands/applications/` module
  directory; the 13-site detail-pane cache-invalidation pairing was factored into
  one `invalidate_app_detail_state` helper; and the duplicated (and already
  drifting) premium-feature error mapper shared by the Activity and Conditional
  Access tabs was unified into one `graph_err::premium_feature_err`.
- **DR backup/restore now have automated coverage of their hardest invariants.**
  A mock-Graph (wiremock) test proves the backup degrades to per-object reads when
  a whole `$batch` fails and skips an individual failed object rather than aborting
  the run; a unit test pins `plan_restore`'s action counts and cloud/tenant-change
  flags. (The backup chunk helper now takes a progress callback instead of the
  Tauri `AppHandle`, so the test needs no webview/mock runtime; `wiremock` was
  added as a dev-dependency.)

## [0.3.0] - 2026-06-21

### Changed

- **Disaster-recovery backup is now batched and throttle-aware — far faster and
  no longer rate-limit-bound on large tenants.** The per-app/-SP/-MI reads that
  the backup fanned out as individual Graph calls (the bulk of a backup) now go
  out via Graph JSON batching (`$batch`, 20 sub-requests per round trip),
  collapsing the round-trip count roughly 20× and cutting wall-clock sharply. All
  three passes (app registrations, enterprise apps, managed identities) are
  batched, including the enterprise group-membership read (the advanced
  `memberOf` query now rides a per-sub-request `ConsistencyLevel` header in the
  batch). The managed-identity pass resolves each distinct resource service
  principal once via a batched prewarm. A whole-batch failure degrades to
  per-object reads for that chunk, and per-object failures still skip just that
  one object — a cancelled run remains an error, never a partial manifest.
- **Adaptive concurrency for the backup.** The backup now reuses the security
  audit's throttle tracker (promoted to a shared `ConcurrencyThrottle`): every
  Graph 429 halves the in-flight chunk cap, which then recovers after a quiet
  window — so a throttling tenant backs off gracefully instead of hammering at a
  fixed concurrency.
- **Legible DR progress.** The Disaster Recovery screen now shows a progress bar
  and the live concurrency for both backup and restore, plus a back-off notice
  while Graph is rate-limiting the backup (the adaptive cap has dropped below its
  peak) so a slow run reads as expected rather than stuck. `BulkProgress` gained
  an optional `in_flight_cap` field (additive; absent for the fixed-cap bulk
  flows).

## [0.2.0] - 2026-06-20

### Added

- **Exposed app roles management on enterprise applications.** A new **App roles**
  tab on the enterprise-app detail pane adds, edits, enables/disables, and deletes
  the app-role definitions an application publishes (the Entra "App roles" blade) —
  previously these were read-only in the Permissions tab. Edits target the role's
  canonical home: the **linked app registration** when one exists (Entra mirrors
  them onto the service principal), otherwise the **service principal** directly
  (gallery / foreign-tenant apps). The whole `appRoles` collection is re-read live
  and full-replaced on each change, preserving built-in roles (e.g. the SAML
  `msiam_access` default, surfaced read-only) byte-for-byte; deleting an enabled
  role disables it first (Graph rejects removing an enabled role). New backend
  commands `list_enterprise_app_roles`, `upsert_enterprise_app_role`, and
  `delete_enterprise_app_role` with typed frontend stubs.

## [0.1.4] - 2026-06-20

### Added

- **Enterprise Application management parity.** The enterprise-app detail pane
  gained the core lifecycle controls it was missing relative to the Microsoft
  Entra admin center:
  - **SSO tab** — a single sign-on **method selector** (SAML / OIDC / Disabled)
    that sets `preferredSingleSignOnMode`, so you can now enable or switch an
    existing app's SSO mode (previously the tab always showed the SAML editor for
    any non-OIDC value and could not turn SSO on). The SAML editor now accepts
    **multiple identifiers (Entity IDs) and reply URLs (ACS)**, and apps that
    aren't configured for SAML/OIDC (e.g. password-based) get a clear prompt
    instead of a misleading SAML form.
  - **Overview tab** — toggles for **"Enabled for sign-in"** (`accountEnabled`)
    and **"Assignment required"** (`appRoleAssignmentRequired`), plus an editable
    free-text **Notes** field.
  - **Owners tab** — **add/remove owners** (users only — groups can't own a
    service principal), replacing the previous read-only list.
  New backend commands (`set_sso_mode`, `set_enterprise_app_account_enabled`,
  `set_enterprise_app_assignment_required`, `set_enterprise_app_notes`,
  `add_enterprise_app_owner`, `remove_enterprise_app_owner`) with typed frontend
  stubs; `set_saml_urls` now takes lists of identifiers/reply URLs.

## [0.1.3] - 2026-06-19

### Added

- Browser-based **GUI functionality tests** for the front-end. Real Leptos views
  mount in a headless browser with the Tauri IPC bridge mocked (no tenant, no
  backend) and assert on rendered DOM + recorded commands. New `just web-itest`
  recipe (the CI `web` job runs it on headless Chrome); the harness lives behind
  a `test-support` cargo feature, so it never enters the shipped Trunk bundle.
  Coverage spans the App Registrations / Enterprise Applications / Managed
  Identities lists (load, filter, error, empty, and Refresh → invalidate-cache
  command paths), the readiness checklist, the App Registration detail pane, the
  Key Vault secret browser, the streamed-progress event plumbing, and mount-smoke
  for the bulk-actions, disaster-recovery, resource-access, and permission-tester
  views. `just setup` now installs `wasm-pack` and flags the browser + WebDriver
  prerequisite this gate needs.

### Fixed

- Directory and organization reads no longer fail to parse when Microsoft Graph
  returns an explicit `null` (or omits) `id` on a directory object or
  `verifiedDomains` on the organization — both now tolerate null/missing and
  fall back to a default instead of erroring the whole response.

### Changed

- **Front-end list-view maintainability refactor** (internal; no behavior change).
  The App Registration and Enterprise Application lists now share a `ListScaffold`
  component (header + search + filter drawer chrome) and a `use_filtered_list`
  hook (the layered search/facet filter memos, per-facet counts, and export
  snapshot), replacing two near-identical hand-rolled copies. A new `use_command`
  hook collapses the busy/error/tenant/spawn boilerplate that mutation handlers
  repeated. The 1.2k-line `audit_view` and 1k-line `managed_identities` views were
  each split into a module directory, and the IPC bindings' duplicated argument
  structs were centralized in `bindings/common.rs` alongside shared list constants
  in `constants.rs`.

- AAD token-endpoint failures now log the request **correlation ID** (the GUID
  Microsoft support needs to trace an issue) alongside the OAuth/AADSTS code,
  while still keeping the raw `error_description` — which can embed tenant/user
  GUIDs and client IPs — out of logs, the UI, and the audit log.

## [0.1.2] - 2026-06-17

### Added

- The app version is now shown beneath the **Sign Out** button in the
  navigation rail.

### Changed

- Moved **Cache** from the Tools group to the bottom of the navigation rail,
  directly above **Sign Out**.

### Documentation

- Clarified in the README that the in-app auto-updater manages only the NSIS
  (`-setup.exe`) per-user install. MSI/enterprise deployments must disable
  auto-update and update through their management tooling — installing one
  installer type and updating with the other leaves two conflicting Windows
  entries (and a stray Windows Installer "uninstall this product?" prompt).

## [0.1.1] - 2026-06-17

### Changed

- Input fields now show their full placeholder hint — it was being clipped in
  narrow boxes.
- Destructive actions (Delete / Remove / Revoke) are now styled red, and
  removing a mailbox from an Exchange scope group or revoking a managed-identity
  app-role assignment now asks for confirmation first.
- Updated to the `keyring` 4.1 architecture (the OS-native credential store is
  registered directly via `keyring-core`); on Linux, refresh tokens now use the
  Secret Service.

## [0.1.0] - 2026-06-17

Initial public release.
