# Body of `just setup` (Windows). Run it through `just` from the repo root — the
# paths below are repo-relative. Idempotent; safe to rerun.
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

# rustc cannot link without the MSVC C++ build tools, and the cargo installs
# below are the first thing that needs them — so probe before them. Non-fatal,
# like the WiX check. link.exe is normally NOT on PATH (rustc finds it via
# vswhere, and Git ships an unrelated usr\bin\link.exe), so ask vswhere too.
# The -requires component is the x64 toolset; an ARM64-only install may warn
# falsely here, which is harmless.
Write-Info "Checking the MSVC C++ build tools (linker)"
$rustHost = ((rustc -vV) | Where-Object { $_ -like 'host:*' }) -replace '^host:\s*', ''
if ($rustHost -like '*-msvc') {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vc = $null
    if (Test-Path $vswhere) {
        $vc = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    }
    if ($vc) {
        Write-Ok "MSVC build tools found ($vc)"
    } elseif (Get-Command cl.exe -ErrorAction SilentlyContinue) {
        Write-Ok "cl.exe on PATH (Developer prompt)"
    } else {
        Write-WarnMsg "MSVC C++ build tools not found — Rust cannot link (error: linker 'link.exe' not found)."
        Write-WarnMsg "  Install Visual Studio Build Tools with the 'Desktop development with C++' workload:"
        Write-WarnMsg "  https://visualstudio.microsoft.com/visual-cpp-build-tools/"
    }
}

Write-Info "Checking Tauri CLI"
if (Get-Command cargo-tauri -ErrorAction SilentlyContinue) {
    Write-Ok (cargo tauri --version 2>$null)
} else {
    Write-WarnMsg "tauri-cli not installed — installing now (may take several minutes)"
    # Pin the CLI to the newest published `tauri-cli` at or below the locked
    # `tauri` runtime (Cargo.lock) for reproducible tooling — upstream does not
    # cut a CLI release for every runtime patch, so the two can differ in the
    # patch digit. Bump both together. --locked pins the CLI's own deps.
    cargo install tauri-cli --locked --version "=2.11.5"
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

# Smoke test through the same recipes CI and 'just verify' use, so the flags
# never drift. 'just check' first: it drops the placeholder web-rs/dist that
# Tauri's generate_context! needs on a fresh clone (dist/ is gitignored) and
# fails fast on a Rust error; 'just web-build' (trunk build --locked) then
# replaces the placeholder with the real bundle. A native command's non-zero
# exit does not throw under $ErrorActionPreference, so check $LASTEXITCODE.
Write-Info "Type-check both trees (just check)"
just check
if ($LASTEXITCODE -ne 0) { Write-Fail "just check failed" }
Write-Ok "Rust workspace + frontend type-check"

Write-Info "Frontend build (just web-build)"
just web-build
if ($LASTEXITCODE -ne 0) { Write-Fail "just web-build failed" }
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
