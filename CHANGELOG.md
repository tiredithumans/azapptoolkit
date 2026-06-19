# Changelog

All notable changes to azapptoolkit are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  views.

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
