# azapptoolkit task runner — the single source of truth for build/dev/verify
# commands. Cross-platform: `just` is one static binary on macOS, Linux, and
# Windows (cargo install just / brew install just / winget install Casey.Just),
# so the same recipes drive local dev, CI, and Tauri's before*Command hooks —
# no PowerShell required on macOS/Linux. Run `just` (or `just --list`) to see
# every recipe.

# Run recipe lines under PowerShell on Windows. `just` shells out to `sh -c` by
# default on every platform; Windows has no `sh` unless Git Bash is on PATH, so
# plain (non-shebang) recipes would fail with "could not find the shell 'sh'".
# Shebang recipes (e.g. `setup`) are unaffected — they run as their own script.
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# Show the recipe list when run with no arguments.
default:
    @just --list

# --- Daily dev ---------------------------------------------------------------

# Launch the Tauri shell (its beforeDevCommand runs `just web-serve`).
[working-directory('apps/desktop/src-tauri')]
dev:
    cargo tauri dev

# Frontend dev server — invoked by tauri.conf.json `beforeDevCommand`.
[working-directory('apps/desktop/web-rs')]
web-serve:
    trunk serve --port 5173 --no-autoreload

# Frontend release build — invoked by tauri.conf.json `beforeBuildCommand`.
# --locked: fail if web-rs/Cargo.lock is stale/tampered rather than silently
# re-resolving (same supply-chain pin enforcement as the workspace recipes).
[working-directory('apps/desktop/web-rs')]
web-build-release:
    trunk build --release --locked

# Frontend debug build — used by `verify` and the CI `web` job.
[working-directory('apps/desktop/web-rs')]
web-build:
    trunk build --locked

# --- Verify (CI gates, in the order CI runs them) ---------------------------

# Auto-format the whole workspace.
fmt:
    cargo fmt --all

# Check formatting (CI gate).
fmt-check:
    cargo fmt --all -- --check

# Tauri's `generate_context!` (src-tauri/src/lib.rs) validates at COMPILE time
# that the frontendDist dir (apps/desktop/web-rs/dist) exists, and panics
# otherwise. clippy/test compile the desktop crate but do NOT build the frontend,
# so on a fresh checkout (CI's rust job, or a clean clone) the dir is absent and
# the macro panics. Drop a minimal placeholder so the existence check passes;
# never clobber a real build's index.html (the web-build recipes overwrite dist
# with the real bundle). Hidden recipe (leading `_`).
[unix]
_stub-frontend-dist:
    mkdir -p apps/desktop/web-rs/dist
    [ -f apps/desktop/web-rs/dist/index.html ] || printf '<!doctype html><title>azapptoolkit</title>\n' > apps/desktop/web-rs/dist/index.html

[windows]
_stub-frontend-dist:
    New-Item -ItemType Directory -Force -Path apps/desktop/web-rs/dist | Out-Null
    if (-not (Test-Path apps/desktop/web-rs/dist/index.html)) { Set-Content -Path apps/desktop/web-rs/dist/index.html -Value '<!doctype html><title>azapptoolkit</title>' }

# Lint with warnings as errors (CI gate).
# --locked: fail if Cargo.lock is stale/tampered rather than silently re-resolving
# dependencies (supply-chain pin enforcement).
clippy: _stub-frontend-dist
    cargo clippy --locked --workspace --all-targets -- -D warnings

# Run the workspace test suite (CI gate). --locked enforces the committed Cargo.lock.
test: _stub-frontend-dist
    cargo test --locked --workspace

# Check frontend formatting (CI gate; web-rs is excluded from the root workspace).
[working-directory('apps/desktop/web-rs')]
web-fmt-check:
    cargo fmt -- --check

# Run the frontend unit tests on the host target (web-rs is excluded from the
# root workspace, so `just test` doesn't reach it). The pure-logic helpers have
# no runtime WASM dependency, so they compile and run natively. --locked enforces
# the committed web-rs Cargo.lock (this gate runs before web-build, so it pins the
# frontend lockfile that Trunk's build then reuses).
[working-directory('apps/desktop/web-rs')]
web-test:
    cargo test --locked

# Run every CI gate locally, in order. Run this before declaring a change done.
# Frontend tests run before the (slower) web build, matching the CI web job and
# failing fast on a logic regression.
verify: fmt-check clippy test web-fmt-check web-test web-build

# --- Dependency policy (CI audit/deny jobs) ---------------------------------

# RustSec advisory scan (config: .cargo/audit.toml; uses the RustSec DB).
audit:
    cargo audit

# RustSec scan of the frontend lockfile. web-rs is excluded from the root
# workspace and has its own Cargo.lock (incl. the git-pinned tauri-sys), so the
# root `audit` never sees it — and that WASM code runs inside the webview with
# IPC access, so it must be gated too.
web-audit:
    cargo audit -f apps/desktop/web-rs/Cargo.lock

# License + crate-source + bans policy (config: deny.toml).
deny:
    cargo deny check bans licenses sources

# Same policy for the frontend tree (web-rs is its own workspace; the root
# `deny` never reaches it). Reuses the root deny.toml so the two trees can't
# drift to different policies.
[working-directory('apps/desktop/web-rs')]
web-deny:
    cargo deny check --config ../../../deny.toml bans licenses sources

# --- Release / packaging ----------------------------------------------------

# Build the Windows MSI + NSIS installers (release; auto-builds the frontend).
# Args after `--` go to the underlying cargo build: --locked enforces the
# committed Cargo.lock on the one pipeline that produces shipped bytes (every
# verify gate pins it; the release build must not silently re-resolve).
[working-directory('apps/desktop/src-tauri')]
build-windows:
    cargo tauri build --target x86_64-pc-windows-msvc -- --locked

# Requires the updater signing key in TAURI_SIGNING_PRIVATE_KEY[_PASSWORD]
# (`tauri build` fails without it when createUpdaterArtifacts is on); kept
# separate from `build-windows` so local/test packaging needs no signing key.
# Windows installers WITH signed updater artifacts (.sig → latest.json in CI).
# The override comes from `updater-build.json`, not inline `--config '{...}'`:
# PowerShell (the Windows recipe shell) strips the JSON's inner double quotes
# when handing args to cargo.exe, so inline JSON parses as invalid ("key must be
# a string"). A file path has no quoting to mangle. It is NOT a `tauri.*.conf.json`
# name, so Tauri never auto-loads it — only this explicit `--config` does.
[working-directory('apps/desktop/src-tauri')]
build-windows-updater:
    cargo tauri build --target x86_64-pc-windows-msvc --config updater-build.json -- --locked

# Regenerate every bundled icon format from icons/icon.svg.
[working-directory('apps/desktop/src-tauri')]
icon:
    cargo tauri icon icons/icon.svg

# --- One-time developer setup (idempotent — safe to rerun) ------------------
# Ported from the former scripts/setup.sh and scripts/setup.ps1. Verifies the
# Rust toolchain, adds the wasm target + rustfmt/clippy, installs the Tauri CLI
# and trunk if missing, checks OS-specific build deps, then runs a compile +
# frontend-build smoke test. Run `cargo install just` (or your package manager)
# first, then `just setup`.

[unix]
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
    info() { printf "${BLUE}==>${NC} %s\n" "$*"; }
    ok()   { printf "${GREEN}[ OK ]${NC} %s\n" "$*"; }
    warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
    fail() { printf "${RED}[FAIL]${NC} %s\n" "$*" >&2; exit 1; }
    need_cmd() { command -v "$1" >/dev/null 2>&1; }

    info "Checking Rust toolchain"
    if ! need_cmd rustc; then
      fail "Rust not found. Install via https://rustup.rs, then rerun 'just setup'."
    fi
    ok "$(rustc --version)"

    if need_cmd rustup; then
      info "Ensuring rustfmt + clippy components are present"
      rustup component add rustfmt clippy >/dev/null 2>&1 || warn "Could not add rustfmt/clippy components automatically"
      ok "rustfmt + clippy ready"
      info "Ensuring the wasm32-unknown-unknown target"
      rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || warn "Could not add wasm32-unknown-unknown automatically"
      ok "wasm32-unknown-unknown ready"
    else
      warn "rustup not found — ensure rustfmt, clippy, and the wasm32-unknown-unknown target are installed some other way"
    fi

    if [[ "$(uname -s)" == "Linux" ]]; then
      info "Checking Linux system packages required by Tauri"
      LINUX_PKGS=(libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev)
      MISSING=()
      if need_cmd dpkg; then
        for p in "${LINUX_PKGS[@]}"; do
          if ! dpkg -s "$p" >/dev/null 2>&1; then MISSING+=("$p"); fi
        done
        if [[ ${#MISSING[@]} -gt 0 ]]; then
          warn "Missing apt packages: ${MISSING[*]}"
          warn "Install with: sudo apt-get update && sudo apt-get install -y ${MISSING[*]}"
        else
          ok "All required apt packages present"
        fi
      else
        warn "Non-Debian Linux detected — install equivalents of: ${LINUX_PKGS[*]}"
      fi
    fi

    info "Checking Tauri CLI"
    if need_cmd cargo-tauri; then
      ok "$(cargo tauri --version 2>/dev/null || echo 'tauri-cli present')"
    else
      warn "tauri-cli not installed — installing now (may take several minutes)"
      # Pin the CLI to the exact `tauri` runtime version (Cargo.lock) for
      # reproducible tooling. Bump both together. --locked pins the CLI's own deps.
      cargo install tauri-cli --locked --version "=2.11.2"
      ok "tauri-cli installed"
    fi

    info "Checking trunk (WASM bundler)"
    if need_cmd trunk; then
      ok "$(trunk --version)"
    else
      warn "trunk not installed — installing now (may take several minutes)"
      cargo install trunk --locked
      ok "trunk installed"
    fi

    info "cargo check --workspace"
    cargo check --workspace
    ok "Rust workspace compiles"

    info "Frontend build (apps/desktop/web-rs)"
    ( cd apps/desktop/web-rs && trunk build )
    ok "Frontend builds"

    cat <<'EOF'

    ==================================================================
    Setup complete.

    Before signing in to a real tenant, point the app at an Entra ID
    public-client app registration by exporting its client and tenant ids
    (both are required):

      export AZAPPTOOLKIT_CLIENT_ID=<your-public-client-guid>
      export AZAPPTOOLKIT_TENANT_ID=<your-tenant-guid>

    The app registration must be a single-tenant public client with a
    redirect URI of `http://127.0.0.1` and the following delegated
    permissions:

      - Directory.Read.All                        (required at sign-in)
      - Application.ReadWrite.All                 (on first write)
      - AppRoleAssignment.ReadWrite.All           (on first write)
      - DelegatedPermissionGrant.ReadWrite.All    (on first write)

    Optional features (Key Vault, Exchange scoping, audit logs, ...) need
    more scopes, consented on first use — see the permission table in
    README.md > First-run configuration for the full list.

    Run the app in dev mode:

      just dev

    For release builds, updater signing keys, and packaging, see
    docs/DEVELOPMENT.md.
    ==================================================================
    EOF

[windows]
setup:
    #!powershell.exe
    $ErrorActionPreference = 'Stop'
    function Write-Info   ($m) { Write-Host "==> $m"     -ForegroundColor Cyan }
    function Write-Ok     ($m) { Write-Host "[ OK ] $m"  -ForegroundColor Green }
    function Write-WarnMsg($m) { Write-Host "[WARN] $m"  -ForegroundColor Yellow }
    function Write-Fail   ($m) { Write-Host "[FAIL] $m"  -ForegroundColor Red; exit 1 }

    Write-Info "Checking Rust toolchain"
    if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) {
        Write-Fail "Rust not found. Install via https://rustup.rs, then rerun 'just setup'."
    }
    Write-Ok (rustc --version)

    if (Get-Command rustup -ErrorAction SilentlyContinue) {
        Write-Info "Ensuring rustfmt + clippy components are present"
        rustup component add rustfmt clippy *> $null
        Write-Ok "rustfmt + clippy ready"
        Write-Info "Ensuring the wasm32-unknown-unknown target"
        rustup target add wasm32-unknown-unknown *> $null
        Write-Ok "wasm32-unknown-unknown ready"
    } else {
        Write-WarnMsg "rustup not found — ensure rustfmt, clippy, and the wasm32-unknown-unknown target are installed some other way"
    }

    Write-Info "Checking Tauri CLI"
    if (Get-Command cargo-tauri -ErrorAction SilentlyContinue) {
        Write-Ok (cargo tauri --version 2>$null)
    } else {
        Write-WarnMsg "tauri-cli not installed — installing now (may take several minutes)"
        # Pin the CLI to the exact `tauri` runtime version (Cargo.lock) for
        # reproducible tooling. Bump both together. --locked pins the CLI's own deps.
        cargo install tauri-cli --locked --version "=2.11.2"
        Write-Ok "tauri-cli installed"
    }

    Write-Info "Checking WiX Toolset (required only for MSI packaging)"
    if (Get-Command candle -ErrorAction SilentlyContinue) {
        Write-Ok "WiX found"
    } else {
        Write-WarnMsg "WiX not found. Install WiX 3.11+ if you plan to build .msi installers."
        Write-WarnMsg "  https://wixtoolset.org/releases/"
    }

    Write-Info "Checking trunk (WASM bundler)"
    if (Get-Command trunk -ErrorAction SilentlyContinue) {
        Write-Ok (trunk --version)
    } else {
        Write-WarnMsg "trunk not installed — installing now (may take several minutes)"
        cargo install trunk --locked
        Write-Ok "trunk installed"
    }

    Write-Info "cargo check --workspace"
    cargo check --workspace
    Write-Ok "Rust workspace compiles"

    Write-Info "Frontend build (apps/desktop/web-rs)"
    Push-Location apps/desktop/web-rs
    try { trunk build } finally { Pop-Location }
    Write-Ok "Frontend builds"

    Write-Host ""
    Write-Host "==================================================================" -ForegroundColor Cyan
    Write-Host "Setup complete." -ForegroundColor Green
    Write-Host ""
    Write-Host "Before signing in to a real tenant, point the app at an Entra ID"
    Write-Host "public-client app registration by setting its client and tenant ids"
    Write-Host "(both are required):"
    Write-Host ""
    Write-Host "  [Environment]::SetEnvironmentVariable('AZAPPTOOLKIT_CLIENT_ID','<client-guid>','User')"
    Write-Host "  [Environment]::SetEnvironmentVariable('AZAPPTOOLKIT_TENANT_ID','<tenant-guid>','User')"
    Write-Host ""
    Write-Host "The app registration must be a single-tenant public client with a"
    Write-Host "redirect URI of http://127.0.0.1 and the following delegated scopes:"
    Write-Host ""
    Write-Host "  - Directory.Read.All                        (required at sign-in)"
    Write-Host "  - Application.ReadWrite.All                 (on first write)"
    Write-Host "  - AppRoleAssignment.ReadWrite.All           (on first write)"
    Write-Host "  - DelegatedPermissionGrant.ReadWrite.All    (on first write)"
    Write-Host ""
    Write-Host "Optional features (Key Vault, Exchange scoping, audit logs, ...) need"
    Write-Host "more scopes, consented on first use — see the permission table in"
    Write-Host "README.md > First-run configuration for the full list."
    Write-Host ""
    Write-Host "Run the app in dev mode:"
    Write-Host ""
    Write-Host "  just dev"
    Write-Host ""
    Write-Host "For release builds (MSI + NSIS installers), updater signing"
    Write-Host "keys, and packaging, see docs/DEVELOPMENT.md."
    Write-Host "==================================================================" -ForegroundColor Cyan
