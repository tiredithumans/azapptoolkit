# Changelog

All notable changes to azapptoolkit are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
