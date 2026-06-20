# Changelog

All notable changes to azapptoolkit are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
