# Release pipeline, auto-update & the GitHub Pages demo

Deep-dive companion to the release/updater/demo gotchas in [AGENTS.md](../../AGENTS.md). Read this
before editing `release.yml`, `pages.yml`, `commands/updater.rs`, the `demo` feature, or the
crypto-dependency pins in `src-tauri/Cargo.toml`.

## Release: a 3-OS matrix → one aggregated `latest.json`

`release.yml` runs three stages:

1. **`guard`** — version/pubkey/audit checks, fails fast before any build minutes are spent.
2. **`build` matrix** — `windows-latest` runs `just build-windows-updater`; `macos-latest` runs
   `build-macos-updater` (native **aarch64** only); `ubuntu-latest` runs `build-linux-updater`
   (needs the GTK/WebKit + `patchelf` apt deps). Each leg uploads its `bundle/` tree as an
   artifact.
3. **`release`** — downloads all three artifacts and assembles ONE `latest.json` with
   `windows-x86_64` (NSIS `-setup.exe`) + `darwin-aarch64` (`.app.tar.gz`) + `linux-x86_64`
   (`.AppImage`) updater entries from each platform's `.sig`, plus SHA256SUMS, into a single
   draft release.

`bundle.targets` in `tauri.conf.json` is `"all"`; the mac/Linux recipes pin formats via
`--bundles` (`app,dmg` / `appimage,deb`). macOS ships **unsigned** (the Gatekeeper bypass is
documented in the README) — Authenticode (Windows) and notarization (macOS) are both optional,
secret-gated, and never blocking. Adding a platform/arch = a matrix leg + a `latest.json`
platform key + a justfile recipe.

## CHANGELOG header contract

Version headers are `## [X.Y.Z] - YYYY-MM-DD` — **no `v` prefix, ASCII hyphen**. The `release`
job's notes-extraction step (`release.yml`, the `^##\s+\[$version\]` match) pulls the lines
between this version's header and the next `## [` header to populate the updater manifest's
`notes`; a `[vX.Y.Z]` header silently matches nothing and the splash falls back to a generic
"see the release notes" line. Keep the format in lockstep with the existing CHANGELOG entries
and that regex.

## Auto-update is interactive, never silent

The front-end checks once on launch (`commands::updater::check_for_update`, swallowed silently
on failure and in dev). If an update waits, it toasts a notification whose action opens the
`UpdateSplash` (`web-rs/components/update_splash.rs`): changelog notes + an explicit
**Update & restart** button (`perform_update`: `download_and_install` → `app.restart()`, byte
progress on the `updater-progress` channel). A manual "Check for updates" button is a direct item
in the user block (`shell.rs`, alongside the version string shown beneath Sign Out).

The splash's changelog text is the updater manifest's `notes` (populated per the contract above),
so it only lights up for releases from **v0.8.0 onward** — v0.7.0's `latest.json` predates it.

**Do not reintroduce a silent background `download_and_install` in `lib.rs` setup** — it was
removed in favour of this flow and would race the prompt.

## GitHub Pages demo: the WASM frontend with the backend mocked

`just web-build-pages` builds `web-rs` with the `demo` feature; `.github/workflows/pages.yml`
deploys it (needs Settings → Pages → Source = "GitHub Actions"). The `demo` feature is off in
`web-build`/desktop builds, so the mock, fixtures, and banner never ship in releases.

- **The bridge** — the demo installs the shared `ipc_mock` bridge, the same
  `window.__TAURI_INTERNALS__` mock the GUI test harness uses. It lives in
  `web-rs/src/ipc_mock/` (not inside `test_support`), gated by the internal `mock-ipc` feature
  that both `test-support` and `demo` enable.
- **Boot** — fixtures are pre-loaded from `demo/mod.rs`; a demo tenant is seeded so the
  config/sign-in gates fall through to the shell (`lib.rs`); a read-only banner renders
  (`shell.rs`, `.demo-banner`).
- **Unregistered commands** (every mutation + any unfixtured read) degrade to a friendly
  `demo_unsupported` error via `ipc_mock::Unmocked::DemoFriendly`.
- **Args-aware detail fixtures** — `get_application_detail` / `get_enterprise_application_detail`
  / `get_mail_permission_scopes` are registered with `ipc_mock::mock_each` (the handler reads the
  call's camelCase args → returns a per-id fixture) so the detail pane switches per selection. A
  plain `mock_ok` returns one payload for every id — the wrong-detail bug to avoid. Ids are
  synthetic-but-realistic GUIDs from `fixtures::guid(seed)`.
- **Footgun: infallible invokes panic without a fixture.** The infallible `invoke()` reads
  (`get_cached_audit` / `cache_stats` / `export_audit_csv` / `get_auth_config`) and the
  `()`-returning ones (`invalidate_list_cache` — fired by every list Refresh — `clear_cache`,
  `cancel_*`, …) must be registered in `demo::register_fixtures`, or they **panic** on the
  rejected-promise fallback. Adding a new infallible `invoke()`/`invoke::<()>` reachable in the
  demo → register a fixture for it.
- **No SPA fallback needed** — nav is signal-based (no router), so there is no `404.html`; only
  the `--public-url` subpath base-href matters.

## Crypto dependencies: no `rsa`; deliberate `rand`/`sha2` pins

Self-signed cert generation (`src-tauri/src/cert.rs`) uses `rcgen` on the **`aws_lc_rs`** backend
(already in-tree via rustls) *specifically* to keep the `rsa` crate (RUSTSEC-2023-0071) out of
the dependency graph — **do not reintroduce `rsa`** (the `src-tauri/Cargo.toml` comment records
why).

The direct `rand = "0.8"` / `sha2 = "0.10"` pins in `src-tauri/Cargo.toml` (random bytes for
client secrets in `expose_api`/`app_roles`/`managed_identity`; the SHA-256 cert thumbprint) are
held to match what **`oauth2` 5 + Tauri 2** already resolve. Bumping to `rand` 0.10 / `sha2` 0.11
only stacks a **duplicate** major version (neither held version carries an advisory), so leave
them until oauth2/Tauri move first. Both lockfiles otherwise track the latest semver-compatible
versions — `cargo update` is a no-op.
