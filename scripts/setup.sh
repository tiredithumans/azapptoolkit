#!/usr/bin/env bash
# Body of `just setup` (Unix). Run it through `just` from the repo root — the
# paths below are repo-relative. Idempotent; safe to rerun.
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
# needs BOTH a browser and a matching WebDriver. This is the only behavioural
# gate for ~46k lines of frontend, and it is the gate most likely to be
# missing locally — so install the driver rather than only naming it, and
# report the browser side precisely instead of assuming Chrome.
info "Checking the browser GUI test prerequisites ('just web-itest')"
BROWSER=""
for candidate in \
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  "/Applications/Chromium.app/Contents/MacOS/Chromium" \
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"; do
  if [[ -x "$candidate" ]]; then BROWSER="$candidate"; break; fi
done
if [[ -z "$BROWSER" ]]; then
  for candidate in google-chrome google-chrome-stable chromium chromium-browser brave-browser microsoft-edge; do
    if need_cmd "$candidate"; then BROWSER="$(command -v "$candidate")"; break; fi
  done
fi

if ! need_cmd chromedriver && ! need_cmd geckodriver; then
  # Small, safe, and useless to defer — unlike a browser, which is a large
  # unattended install this script will not perform on someone's behalf.
  if need_cmd brew; then
    warn "No WebDriver found — installing chromedriver via Homebrew"
    brew install chromedriver >/dev/null 2>&1 || warn "chromedriver install failed; install it manually"
  elif need_cmd apt-get; then
    warn "No WebDriver found — install with: sudo apt-get install -y chromium-driver"
  fi
fi

if need_cmd chromedriver || need_cmd geckodriver; then
  if [[ -n "$BROWSER" ]]; then
    ok "Browser GUI tests can run ($(basename "$BROWSER") + WebDriver)"
    case "$BROWSER" in
      *Chrome*|*chrome*) ;;
      *)
        # wasm-pack asks for Chrome by name; a Chromium-family sibling needs
        # its binary path handed to the driver. Without this the run fails
        # with an opaque 404 from a driver that started fine.
        warn "Only a non-Chrome Chromium browser was found. If 'just web-itest' fails to start one,"
        warn "  create apps/desktop/web-rs/webdriver.json with:"
        warn "  {\"goog:chromeOptions\": {\"binary\": \"$BROWSER\"}}"
        ;;
    esac
  else
    warn "A WebDriver is present but no browser was found — 'just web-itest' cannot run."
    warn "  macOS: brew install --cask google-chrome    Linux: apt-get install -y chromium"
  fi
else
  warn "No WebDriver — 'just web-itest' will LOUD-SKIP, leaving the frontend unproven locally."
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
