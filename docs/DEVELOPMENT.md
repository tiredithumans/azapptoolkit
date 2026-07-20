# Development

This document covers building azapptoolkit from source, running tests,
packaging a release MSI, and managing the updater signing keys.

For end-user installation and tenant configuration, see the
[project README](../README.md).

## Repository layout

```
azapptoolkit/
├── Cargo.toml                    # workspace root
├── crates/
│   ├── azapptoolkit-core/           # domain types, cache, audit/risk scoring
│   ├── azapptoolkit-auth/           # Entra ID OAuth2 PKCE + keyring
│   ├── azapptoolkit-graph/          # typed Microsoft Graph client
│   ├── azapptoolkit-exchange/       # Exchange Online Admin API client (RBAC for Applications)
│   ├── azapptoolkit-keyvault/       # Key Vault secrets client
│   ├── azapptoolkit-arm/            # Azure Resource Manager client (managed-identity Azure RBAC)
│   ├── azapptoolkit-permissions/    # bundled permissions catalog
│   └── azapptoolkit-dto/            # shared IPC DTO types
├── apps/
│   └── desktop/
│       ├── src-tauri/            # Tauri 2 commands, state, adapters
│       └── web-rs/               # Leptos 0.8 + Thaw frontend (WASM)
├── justfile                      # task runner — all build/dev/verify commands
└── .github/workflows/            # CI + release
```

## Prerequisites

The Rust-side tooling reduces to **two manual steps** — `just setup` provisions everything else:

1. **Rust**, via [rustup](https://rustup.rs). `rust-toolchain.toml` pins the channel (1.97), the
   `rustfmt` + `clippy` components, **and** the `wasm32-unknown-unknown` target, so rustup installs all
   of them automatically the first time you build in the repo — no `rustup target add` by hand.
2. **`just`**, the cross-platform task runner: `cargo install just` (or `brew install just` /
   `winget install Casey.Just`). This is the one bootstrap command; with `just` on your PATH,
   `just setup` installs Trunk (the WASM bundler) and the Tauri CLI if missing and runs a smoke build.

System dependencies that no `cargo`/`rustup` command can install — `just setup` detects and warns about
these, but you provide them via your OS package manager:

- A C toolchain: MSVC on Windows, Xcode CLT on macOS, gcc/clang on Linux
- On Linux: `libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `libssl-dev`
- On Windows, for MSI packaging: WiX Toolset 3.11+ (the NSIS target needs no manual prereq — Tauri
  downloads its toolchain on first build)

## Quick setup

With `just` installed, the `setup` recipe installs the Tauri CLI and trunk if missing, adds the wasm
target + rustfmt/clippy, checks OS build deps, and runs a compile + frontend-build smoke test. It is
idempotent (safe to rerun after pulling) and picks the right `[unix]`/`[windows]` variant automatically:

```bash
just setup
```

Run `just` (or `just --list`) at any time to see every available recipe.

## Running locally

```bash
# Point the app at the single-tenant Entra ID public client you control
export AZAPPTOOLKIT_CLIENT_ID=<your-client-guid>
export AZAPPTOOLKIT_TENANT_ID=<your-tenant-guid>

# Launch in dev mode. `just dev` runs `cargo tauri dev`, whose
# beforeDevCommand (`just web-serve`) builds and serves the Leptos
# frontend, then launches the Tauri shell against it.
just dev
```

See the README for the Entra app-registration requirements. Both
`AZAPPTOOLKIT_CLIENT_ID` and `AZAPPTOOLKIT_TENANT_ID` are required — without the
tenant id, sign-in is rejected.

### Baking the client/tenant IDs into a build

For team distribution it is usually easier to bake the GUIDs into the
binary so recipients don't have to set environment variables. Copy
`.env.example` at the repo root to `.env`, fill in the two values, and
build as normal:

```bash
cp .env.example .env       # then edit .env with your client/tenant GUIDs
just build-windows         # (or `cargo tauri build` for your host target)
```

The desktop crate's `build.rs` reads `.env` at the workspace root and
emits the values via `cargo:rustc-env=AZAPPTOOLKIT_BUILD_*`. At runtime
`state.rs` prefers a real `AZAPPTOOLKIT_*` env var, then the baked-in
value, then the placeholder — so a packaged build "just works" while
developers can still override locally with `export`. `.env` is
git-ignored; check in only `.env.example`.

## Testing

Run every CI gate in order with one command:

```bash
just verify        # fmt-check → clippy → test → web-fmt-check → web-test → web-build
```

Or run an individual gate:

```bash
just test          # cargo test --locked --workspace
just clippy        # cargo clippy --locked --workspace --all-targets -- -D warnings
just fmt-check     # cargo fmt --all -- --check
just web-build     # trunk build --locked of the Leptos/WASM frontend
```

Every new scoring rule added to `azapptoolkit-core::audit` must come with
a matching table-driven test that cites the PowerShell source
`file:line` it was ported from — this is how rule-for-rule parity with
the legacy module is maintained.

## Packaging installers

The release workflow builds packages for all three platforms — Windows
(MSI + NSIS), macOS (`.dmg` + `.app` updater payload), and Linux
(`.AppImage` + `.deb`) — each on its native GitHub-hosted runner. Locally
you can build for your own host with the per-platform recipes below.

### Windows

The build produces both an MSI and an NSIS installer in one pass.
WebView2 is provisioned via Tauri's `downloadBootstrapper` mode: it ships
with current Windows 10/11, so the installer uses what's already there; on
an older box that lacks it, the installer downloads it from Microsoft
during setup. (The heavier `offlineInstaller` mode — which embeds the full
~127 MB runtime — was dropped because its WiX/MSI custom action fails with
error 1722 "a program run as part of the setup did not finish as expected"
on machines that already have WebView2.)

```bash
# `just build-windows` runs `cargo tauri build --target x86_64-pc-windows-msvc`.
# Its beforeBuildCommand (`just web-build-release`) builds the Leptos frontend
# automatically before bundling.
just build-windows
```

Outputs:

| Path | Purpose |
|---|---|
| `target/x86_64-pc-windows-msvc/release/bundle/msi/azapptoolkit_<version>_x64_en-US.msi` | Classic per-machine installer (admin). Best for enterprise deployment / Group Policy. |
| `target/x86_64-pc-windows-msvc/release/bundle/nsis/azapptoolkit_<version>_x64-setup.exe` | Lightweight NSIS installer. Supports per-user install without admin — best for handing to a tester. |
| `target/x86_64-pc-windows-msvc/release/azapptoolkit.exe` | Raw binary. Needs the WebView2 runtime on the target machine; use only if you're bundling the app in a larger distribution container. |

`just build-windows` does **not** produce updater artifacts. The
release workflow uses `just build-windows-updater` (which adds
`--config updater-build.json`); with the
signing key in the environment, that variant writes `-setup.exe.sig`
next to the NSIS installer. (The override lives in
`apps/desktop/src-tauri/updater-build.json` rather than inline
`--config '{...}'`: PowerShell, the Windows recipe shell, strips the
JSON's inner double quotes when handing args to `cargo.exe`, so inline
JSON parses as invalid — a file path has no quoting to mangle.) `cargo tauri build` does not emit
`latest.json` — the workflow assembles it (see [CI](#ci) below). The
auto-update target is the **NSIS `-setup.exe`** (per-user, no admin);
the MSI is published for manual/enterprise download only.

### macOS

`just build-macos-updater` runs `cargo tauri build --target
aarch64-apple-darwin --config updater-build.json --bundles app,dmg` and
writes a `.dmg` (under `bundle/dmg/`) plus the `.app.tar.gz` updater
payload + `.sig` (under `bundle/macos/`). **Apple Silicon only** — a
universal binary is deliberately not built (it's the historically-flaky
bundling step on this stack; an Intel `macos-13` matrix leg can be added
later). The builds are **unsigned / not notarized**, so first launch hits
Gatekeeper — see the README's [Install → macOS](../README.md#install) note
for the one-time `xattr` / right-click-Open workaround. (Apple notarization
can be layered on later by adding the Developer-ID secrets + `APPLE_*` env
to the macOS leg, exactly as Authenticode is optional on Windows.)

### Linux

`just build-linux-updater` runs `cargo tauri build --target
x86_64-unknown-linux-gnu --config updater-build.json --bundles
appimage,deb` and writes a `.AppImage` (+ `.sig`, the updater payload) and
a `.deb`. The build host needs the GTK/WebKit dev libraries + `patchelf`
(`libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev
libssl-dev patchelf`); the release runner installs them. `rpm` is omitted
for now (add it to the recipe's `--bundles` when needed).

### Which installer to ship

For most "just run it" cases, use the **NSIS `-setup.exe`** — the
tester double-clicks it, it asks once about per-user vs per-machine,
and the app is on their Start menu within seconds. WebView2 is already
present on current Windows 10/11, so there's no prompt; setup only reaches
the internet to fetch WebView2 on an older machine that lacks it.

The **MSI** is the right choice when IT wants to roll the app out via
SCCM/Intune/Group Policy or needs the classic Windows Installer
properties for inventory.

### Building without a Windows machine

You don't need a local Windows box to produce installers. Tag a release
(`git tag v0.x.y && git push --tags`) and `.github/workflows/release.yml`
builds both the NSIS and MSI installers on a GitHub-hosted Windows runner
and attaches them to the GitHub release — this is the flow the README's
Releases-page distribution relies on. With the updater signing secrets
configured (see below), the workflow also generates the signed
`-setup.exe.sig` and the `latest.json` manifest; Authenticode signing of
the installers is layered on when those secrets are present too.

### Generating icons

`apps/desktop/src-tauri/icons/icon.svg` is the source. Regenerate every
bundled format with:

```bash
just icon
```

This replaces the placeholder PNGs checked into the repo with proper
32/128/256 raster assets plus `icon.ico` (Windows) and `icon.icns`
(macOS).

### Authenticode signing (Windows)

The release workflow signs both installers with `signtool.exe` when
`WINDOWS_CERTIFICATE` (base64-encoded PFX) and
`WINDOWS_CERTIFICATE_PASSWORD` are configured as GitHub Actions
secrets. A self-signed test certificate is fine for internal
distribution; an EV cert is recommended for external distribution.

## Updater keys

The auto-updater is **enabled** in
`apps/desktop/src-tauri/tauri.conf.json` (`plugins.updater.active =
true`) with this project's committed `pubkey`. The matching **private**
key is held in GitHub Actions secrets (plus the offline backup below), so
an official tagged build produces signed artifacts the installed app
will accept.

> **The private key is the single trust root for the whole install
> base — treat key loss and key leak as incidents.** GitHub Actions
> secrets are *write-only*: they cannot be read back out. If the secret
> is lost (org migration, accidental deletion, account loss) the
> installed base is **permanently cut off from auto-update**, because a
> build that rotates to a new pubkey must itself be signed with the
> *old* key to be accepted.
>
> - **Escrow (do this at generation time):** keep an offline, encrypted
>   backup of the private key file and its password — e.g. in a password
>   manager entry or an age/GPG-encrypted copy on storage that is not
>   this repo and not only the CI secret store. Verify the backup
>   restores before deleting any local copy.
> - **If the key leaks:** until clients install a new-pubkey build, every
>   installed app trusts the leaked key plus the floating
>   `releases/latest/download/latest.json` endpoint — anyone with the
>   leaked key *and* release-write access to this repo could push a
>   malicious "update". Respond immediately: (1) audit/revoke release
>   write access and rotate any exposed repo credentials; (2) generate a
>   new key pair; (3) ship a forward-fix release — **signed with the old
>   key** so existing installs accept it — whose only change is the new
>   `pubkey` in `tauri.conf.json` and a version bump; (4) replace the CI
>   secrets with the new key; (5) watch the Releases page for assets you
>   didn't publish until the install base has moved.

To cut a signed release you only need the two updater secrets below set
on the repo; the public key is already in the config. The release
workflow fails fast (the "Guard updater pubkey" step) if `active` is
true while the pubkey is still a placeholder.

**Forking / rotating the key.** If you maintain a fork or need to
rotate, generate your own key pair, swap in the new public key, and
re-set the secrets:

1. Generate a Tauri updater signing key pair (safe to run on any OS,
   no Windows toolchain needed):

   ```bash
   cargo tauri signer generate -w ~/.tauri/azapptoolkit-updater.key
   ```

2. Paste the emitted base64 **public** key into `tauri.conf.json`
   under `plugins.updater.pubkey`. Commit the edit. (Leave `active:
   true`; set it to `false` only to ship a build with no auto-update.)
3. Push the **private** key (the file's contents) + its password into
   GitHub Actions as secrets — see table below.
4. Tag the release; the workflow in `.github/workflows/release.yml`
   produces signed artifacts and a **draft** release. Review the
   generated notes (paste the matching `CHANGELOG.md` entry), then
   publish — nothing reaches the updater endpoint until you do.

Required GitHub Actions secrets for `release.yml`:

| Secret                                 | Purpose                                            |
|----------------------------------------|----------------------------------------------------|
| `TAURI_UPDATER_PRIVATE_KEY`            | Private key produced by `cargo tauri signer generate` |
| `TAURI_UPDATER_PRIVATE_KEY_PASSWORD`   | Password set during `signer generate`              |
| `WINDOWS_CERTIFICATE` (optional)       | Base64-encoded `.pfx` for Authenticode signing     |
| `WINDOWS_CERTIFICATE_PASSWORD` (opt.)  | Password for the above PFX                         |

The release workflow passes the private key through
`TAURI_SIGNING_PRIVATE_KEY` / `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
environment variables. With those set, `build-windows-updater` signs the
NSIS payload; the workflow then (re)signs the final binary — Authenticode
signing changes the bytes — and assembles the `latest.json` the installed
app pulls from the `endpoints` URL in `tauri.conf.json` (only when
`active: true`).

## Pulling a bad release

The updater only moves **forward** (it installs versions greater than the installed one), and the
endpoint is the floating `releases/latest/download/latest.json`, so a bad build is remediated by
shipping a *higher-versioned* fix — not by deleting the release:

1. **Stop the bleeding**: delete the bad GitHub release *and its tag*. `releases/latest` falls
   back to the previous release's `latest.json`; users who already installed the bad build stay on
   it (their version exceeds what `latest` now advertises), but nobody else picks it up.
2. **Forward-fix immediately**: branch from the last good commit (or revert the bad change on
   `main`), bump the version in `tauri.conf.json` + the workspace `Cargo.toml`, and tag — the
   normal release flow ships the fix, and every user (including those on the bad build) updates on
   next launch.
3. **Manual downgrade path** (users who can't wait): the MSI/NSIS installers from any previous
   release install over a newer build only if Windows allows the downgrade — document the specific
   release to grab in the incident notes. Users with auto-update disabled
   (`AZAPPTOOLKIT_AUTO_UPDATE=0` or the settings toggle) are unaffected throughout.

Never re-tag or re-upload different bytes under an existing version: the updater signature and
Authenticode timestamps make the history auditable — keep it that way.

## CI

`.github/workflows/ci.yml` runs on every push and pull request. Each job installs `just` and calls the
same recipes you run locally, so CI and local builds can't drift:

- Rust (`just fmt-check`, `just clippy`, `just test`) on Linux, Windows, and macOS
- Frontend (`just web-fmt-check`, `just web-test`, `just web-build`) of `apps/desktop/web-rs` (Leptos/WASM)
- Dependency policy: `just audit` + `just web-audit` (RustSec advisories — root workspace **and**
  the frontend's own lockfile) and `just deny` + `just web-deny` (license/source/bans for both trees)

`.github/workflows/release.yml` runs on `v*` tags and
`workflow_dispatch`:

- Builds both the MSI and the NSIS installer (NSIS with updater artifacts),
  with `--locked` enforcing the committed lockfiles end to end
- Optionally Authenticode-signs both installers
- Regenerates the NSIS updater signature over the final binary and
  generates the `latest.json` manifest (target `windows-x86_64` → NSIS)
- Publishes `SHA256SUMS` over every asset, so the (possibly unsigned) MSI
  can be integrity-pinned by enterprise deployment tooling
- Uploads the MSI, NSIS `-setup.exe`, its `.sig`, `latest.json`, and
  `SHA256SUMS` to a **draft** release — publishing is the deliberate
  human step (review notes, paste the CHANGELOG entry); the floating
  `releases/latest` endpoint never sees a half-assembled release

## Token & secret security model

Invariants every change must preserve (the audit/review baseline for auth-adjacent code):

- **No secret values to disk, ever.** Access tokens live in memory only and are zeroized on drop
  (`Zeroize` on `AccessToken` in `azapptoolkit-auth/src/token_cache.rs`); their `Debug` impl prints
  `<redacted>`. Refresh tokens go to the OS keyring — chunked across numbered entries because
  Windows Credential Manager caps a blob at 2560 UTF-16 bytes (don't collapse the chunking).
- **Build-time baking is for non-secrets only.** `src-tauri/build.rs` bakes `AZAPPTOOLKIT_CLIENT_ID`
  / `_TENANT_ID` (public-client identifiers). Never route a credential through `build.rs` or `.env`.
- **Errors are sanitized before they're shown or logged.** AAD errors are redacted to the AADSTS
  code (`azapptoolkit-auth/src/service.rs::redacted_aad_error`); Exchange response bodies are
  control-char-stripped and length-capped (`azapptoolkit-exchange/src/client.rs::sanitize_error_body`)
  — log the `ui_code`/request id, never a raw body that could carry token material.
- **Tokens stay scoped to their resource.** Write scopes are consented incrementally; optional
  admin scopes ride `ScopedTokenAdapter`, never the sign-in scope set. A missing consent surfaces
  as `consent_required` — it must not purge the refresh token (see AGENTS.md).

## Contributing

1. Run `just setup` once on a fresh clone (install `just` first — see Prerequisites).
2. `just fmt` before submitting.
3. `just verify` must pass — it runs the clippy, test, and frontend-build gates CI enforces.

Changes that port behavior from the legacy PowerShell module should
reference the source file and line range in the commit message or PR
description.
