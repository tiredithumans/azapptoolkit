# Release step 2 in one command (SKILL.md steps 1-2 defer to `just bump`,
# which dispatches here on Windows; the changelog roll comes FIRST because
# the tail test compares against it). Mirrors scripts/bump.sh: rewrite the
# three guarded version literals (tauri.conf.json, root [workspace.package],
# web-rs [package]), resync BOTH lockfiles with `cargo update --workspace`
# (workspace members only, never --locked — the point is to rewrite the
# locks), then run the release-identity tests. Usage: just bump X.Y.Z
param([Parameter(Mandatory = $true)][string]$Version)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d+\.\d+\.\d+$') { Write-Error "bump: '$Version' is not X.Y.Z"; exit 1 }
Set-Location (Split-Path -Parent $PSScriptRoot)

function Rewrite-Block([string]$Path, [string]$BlockHeader) {
    # Scoped to the one block whose line starts `version = ...` — dependency
    # entries declare versions too and must not move.
    $inBlock = $false
    $out = Get-Content $Path | ForEach-Object {
        $line = $_
        if ($line -eq $BlockHeader) { $inBlock = $true; $line }
        elseif ($line -match '^\[') { $inBlock = $false; $line }
        elseif ($inBlock -and $line -match '^version = ') { 'version = "' + $Version + '"' }
        else { $line }
    }
    Set-Content $Path -Value $out
}

# tauri.conf.json carries exactly one "version" key — replace it anywhere.
$conf = 'apps/desktop/src-tauri/tauri.conf.json'
(Get-Content $conf -Raw) -replace '"version": *"[^"]*"', ('"version": "' + $Version + '"') | Set-Content $conf -NoNewline
Rewrite-Block 'Cargo.toml' '[workspace.package]'
Rewrite-Block 'apps/desktop/web-rs/Cargo.toml' '[package]'

# Fail loudly if any manifest did not end up stating the new version — a
# silently non-matching rewrite would ship a partial bump.
$checks = @(
    @($conf, ('"version": "' + $Version + '"')),
    @('Cargo.toml', ('version = "' + $Version + '"')),
    @('apps/desktop/web-rs/Cargo.toml', ('version = "' + $Version + '"'))
)
foreach ($c in $checks) {
    if ((Get-Content $c[0] -Raw) -notlike ('*' + $c[1] + '*')) {
        Write-Error "bump: $($c[0]) does not state $Version — the rewrite matched nothing"
        exit 1
    }
}

# Lockfile resync (SKILL.md §2): both trees, workspace-only update.
cargo update --workspace
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Push-Location apps/desktop/web-rs
cargo update --workspace
$webCode = $LASTEXITCODE
Pop-Location
if ($webCode -ne 0) { exit $webCode }

# Release-identity smoke: the release.rs invariant suite (three-manifest
# version parity, CHANGELOG header format, the verify-full gate list).
cargo test --locked -p desktop -- release
exit $LASTEXITCODE
