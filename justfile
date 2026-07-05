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

# wasm-bindgen-test's headless runner gives a browser this many seconds to load
# the test module AND report results before it declares "Failed to detect test as
# having been run" (upstream default 20). The GUI tests are grouped into a few
# larger shard binaries (tests/gui_N.rs, ~45-52 MB each) that each run ~25 tests
# serially in one page, so the default is too tight a margin — 60 gives headroom
# without slowing green runs (they finish and exit early). `just`'s `export` puts
# it in every recipe's environment cross-platform; only wasm-pack's runner reads it.
export WASM_BINDGEN_TEST_TIMEOUT := "60"

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

# Frontend demo build for GitHub Pages. Release build + the `demo` feature (mock
# IPC bridge + curated sample data, so the full UI runs with no Tauri backend) +
# a subpath base-href so the hashed JS/WASM/CSS resolve under the Pages subpath
# (`https://<user>.github.io/<repo>/`). The desktop build keeps the default `/`;
# the `demo` feature is never enabled there. Default `BASE` matches the repo name;
# the Pages workflow passes it explicitly.
[working-directory('apps/desktop/web-rs')]
web-build-pages BASE="/azapptoolkit/":
    trunk build --release --locked --features demo --public-url {{BASE}}

# GUI functionality tests: mount real Leptos views in a headless browser with
# the Tauri IPC bridge mocked (no tenant, no backend), then assert on rendered
# DOM + recorded commands. Needs Chrome + a chromedriver. Pass the driver path
# via ARGS to pin it — CI passes the runner's `$CHROMEWEBDRIVER/chromedriver`,
# which GitHub keeps version-matched to the installed Chrome, so wasm-pack does
# not download a copy that mismatches it. With no ARGS, wasm-pack uses a
# `chromedriver` on `$PATH` or downloads one (swap `--chrome`/`--chromedriver`
# for `--firefox`/`--geckodriver` to use Firefox instead). Deliberately NOT in
# `verify`: that gate must run on any dev box, and this one needs a browser. The
# `test-support` feature compiles the harness (off in the shipped Trunk build).
[working-directory('apps/desktop/web-rs')]
web-itest *ARGS:
    wasm-pack test --headless --chrome {{ARGS}} -- --features test-support

# --- Housekeeping ------------------------------------------------------------

# Delete every cargo build artifact to reclaim disk. There are TWO independent
# build trees: the root workspace (`target/`) and the web-rs frontend, which is
# excluded from the workspace — so the root `cargo clean` never reaches it, and
# `web-rs/target/` is by far the larger of the two. `--manifest-path` cleans it
# without a chdir, keeping the recipe one plain `cargo` call per tree (works
# under both sh and PowerShell). The next build recompiles from scratch. The
# committed dist/ stub is left alone (verify recreates it via _stub-frontend-dist).
clean:
    cargo clean
    cargo clean --manifest-path apps/desktop/web-rs/Cargo.toml

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

# Lint the frontend with warnings as errors (CI gate). web-rs is excluded from
# the root workspace, so the root `clippy` recipe never reaches it — yet this is
# the largest, IPC-privileged tier. Lints the actual wasm build + the browser
# test harness; --features test-support so the integration-test targets (which
# use it) compile under --all-targets. --locked enforces the web-rs Cargo.lock.
[working-directory('apps/desktop/web-rs')]
web-clippy:
    cargo clippy --locked --target wasm32-unknown-unknown --all-targets --features test-support -- -D warnings

# Run the frontend unit tests on the host target (web-rs is excluded from the
# root workspace, so `just test` doesn't reach it). The pure-logic helpers have
# no runtime WASM dependency, so they compile and run natively. --locked enforces
# the committed web-rs Cargo.lock (this gate runs before web-build, so it pins the
# frontend lockfile that Trunk's build then reuses).
[working-directory('apps/desktop/web-rs')]
web-test:
    cargo test --locked

# Run the core CI gates locally, in order. Run this before declaring a change
# done. Frontend tests run before the (slower) web build, matching the CI web
# job and failing fast on a logic regression. NOT the whole of CI: the
# dependency audit/deny gates and the browser GUI tests are covered by
# `verify-full` below; actionlint stays CI-side unless installed locally.
verify: fmt-check clippy test web-fmt-check web-clippy web-test web-build

# Full CI parity: verify + both RustSec scans + both deny policies + the
# browser GUI tests. web-itest runs LAST because it needs a local browser +
# matching WebDriver (see its recipe) — the machine-independent gates fail
# first on a box without one.
verify-full: verify audit web-audit deny web-deny web-itest

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

# macOS bundles (.dmg download + .app.tar.gz updater payload) with signed updater
# artifacts. Native Apple Silicon (aarch64) — a universal binary is deliberately
# NOT built (it's the historically-flaky bundling step on this stack; an Intel
# leg can be added later). `--bundles app,dmg` keeps deb/rpm/etc. off the macOS
# leg. Same updater-key contract as `build-windows-updater`.
[working-directory('apps/desktop/src-tauri')]
build-macos-updater:
    cargo tauri build --target aarch64-apple-darwin --config updater-build.json --bundles app,dmg -- --locked

# Linux bundles (.AppImage download + updater payload, .deb for Debian/Ubuntu)
# with signed updater artifacts. Needs the GTK/WebKit/AppIndicator dev libs +
# patchelf on the build host (CI installs them). `--bundles appimage,deb` — rpm
# is omitted for now. Same updater-key contract as `build-windows-updater`.
[working-directory('apps/desktop/src-tauri')]
build-linux-updater:
    cargo tauri build --target x86_64-unknown-linux-gnu --config updater-build.json --bundles appimage,deb -- --locked

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

    info "Checking wasm-pack (frontend GUI test runner for 'just web-itest')"
    if need_cmd wasm-pack; then
      ok "$(wasm-pack --version)"
    else
      warn "wasm-pack not installed — installing now (may take several minutes)"
      cargo install wasm-pack --locked
      ok "wasm-pack installed"
    fi
    # `just web-itest` runs the Leptos views in a real headless browser, so it
    # needs a browser + a matching WebDriver on $PATH (CI uses Chrome). It is not
    # part of `just verify`, so this is a soft prerequisite — warn, don't fail.
    if need_cmd chromedriver || need_cmd geckodriver; then
      ok "WebDriver present (for 'just web-itest' browser GUI tests)"
    else
      warn "No chromedriver/geckodriver found — 'just web-itest' (browser GUI tests) needs one:"
      warn "  macOS:  brew install --cask google-chrome chromedriver   (versions must match)"
      warn "  Linux:  apt-get install chromium-driver   (or firefox + geckodriver)"
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

    Write-Info "Checking wasm-pack (frontend GUI test runner for 'just web-itest')"
    if (Get-Command wasm-pack -ErrorAction SilentlyContinue) {
        Write-Ok (wasm-pack --version)
    } else {
        Write-WarnMsg "wasm-pack not installed — installing now (may take several minutes)"
        cargo install wasm-pack --locked
        Write-Ok "wasm-pack installed"
    }
    # 'just web-itest' runs the Leptos views in a real headless browser, so it
    # needs a browser + a matching WebDriver on PATH (CI uses Chrome). Not part
    # of 'just verify', so this is a soft prerequisite — warn, don't fail.
    if (Get-Command chromedriver -ErrorAction SilentlyContinue) {
        Write-Ok "chromedriver present (for 'just web-itest' browser GUI tests)"
    } else {
        Write-WarnMsg "No chromedriver found — 'just web-itest' (browser GUI tests) needs Chrome + a matching chromedriver on PATH."
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
