# azapptoolkit task runner — the single source of truth for build/dev/verify
# commands. Cross-platform: `just` is one static binary on macOS, Linux, and
# Windows (cargo install just / brew install just / winget install Casey.Just),
# so the same recipes drive local dev, CI, and Tauri's before*Command hooks —
# no PowerShell required on macOS/Linux. Run `just` (or `just --list`) to see
# every recipe.

# Run recipe lines under PowerShell on Windows. `just` shells out to `sh -c` by
# default on every platform; Windows has no `sh` unless Git Bash is on PATH, so
# plain (non-shebang) recipes would fail with "could not find the shell 'sh'".
# Shebang recipes (e.g. `web-itest-auto`) are unaffected — they run as their own script.
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# wasm-bindgen-test's headless runner gives a browser this many seconds to load
# the test module AND report results before it declares "Failed to detect test as
# having been run" (upstream default 20). This budget is PER BINARY, not per
# test: the runner polls the page until it prints `test result:`, so every test
# in a shard shares one 60s deadline.
#
# That is the reason the GUI tests stay sharded (tests/gui_N.rs) rather than
# merging into one binary — four independent 60s budgets, not one shared by
# every test. As of 2026-09-28: ~213 tests, 37-69 apiece, 12-28 MB per shard
# (`just web-itest-size` prints today's sizes). Merging was measured, when the
# suite was 72 tests, and was not a win anyway: a single binary was 29 MB vs
# 53 MB across four, but built *slower* (49-50s vs 46-47s) because cargo links
# the four in parallel and the merged one is a single serial link. `just`'s
# `export` puts it in every recipe's environment cross-platform; only wasm-pack's
# runner reads it.
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

# Frontend release build (Trunk, --locked) — tauri.conf.json beforeBuildCommand.
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

# GitHub Pages demo build: release + `demo` feature (mock IPC) under a subpath base-href.
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
# for `--firefox`/`--geckodriver` to use Firefox instead). Not a hard part of
# `verify` (that gate must run on any dev box); `verify` runs it via
# `web-itest-auto` when a browser is present. The `test-support` feature compiles
# the harness (off in the shipped Trunk build).

# Browser GUI tests: real Leptos views in headless Chrome, Tauri IPC mocked (needs chromedriver).
[working-directory('apps/desktop/web-rs')]
web-itest *ARGS:
    wasm-pack test --headless --chrome {{ARGS}} -- --features test-support

# `web-itest` when this box can actually run it; a LOUD skip when it cannot.
#
# The gap this closes: `verify` compiled the frontend but executed no frontend
# behavioural test, so the largest tier in the repo (web-rs/src, ~41k lines) had
# its ONLY behavioural gate living in CI. Renaming a CSS class, aria-label, or
# on-screen text a GUI test references passed `verify` and failed CI a full round
# trip later.
#
# Auto-detecting rather than mandatory, because the reason `web-itest` was kept
# out of `verify` still holds — that gate must run on a box with no browser. The
# skip is deliberately noisy so it can never be mistaken for a pass.

# web-itest when this box has wasm-pack + chromedriver; a LOUD skip otherwise.
[unix]
web-itest-auto:
    #!/usr/bin/env bash
    set -uo pipefail
    driver=""
    if [ -n "${CHROMEWEBDRIVER:-}" ] && [ -x "${CHROMEWEBDRIVER}/chromedriver" ]; then
      driver="--chromedriver ${CHROMEWEBDRIVER}/chromedriver"
    elif command -v chromedriver >/dev/null 2>&1; then
      driver="--chromedriver $(command -v chromedriver)"
    fi
    if ! command -v wasm-pack >/dev/null 2>&1 || [ -z "$driver" ]; then
      echo ""
      echo "  !! SKIPPED: web-itest — no wasm-pack and/or chromedriver on this box."
      echo "  !! The frontend's only behavioural gate did NOT run. A renamed CSS class,"
      echo "  !! aria-label, or on-screen text a GUI test references will fail in CI."
      echo "  !! Install chromedriver (matching your Chrome) to close this locally."
      echo ""
      exit 0
    fi
    just web-itest $driver

# On Windows the GUI tests stay a CI/Unix gate (matching web-itest-size), so
# `verify` still completes — loudly, never silently.
[windows]
web-itest-auto:
    @echo ""
    @echo "  !! SKIPPED: web-itest — Windows runs this gate in CI only."
    @echo "  !! Frontend behaviour is unproven locally until CI runs."
    @echo ""

# Enforce the per-shard wasm size ceiling the whole GUI-test strategy rests on.
#
# At opt-level 0 a merged test binary (~78 MB stripped) exceeded what headless
# Chrome will instantiate; `[profile.test] opt-level = 1` (web-rs/Cargo.toml)
# brought the merge to ~29 MB when the suite had 24 modules. The
# `tests/gui_N.rs` shards also exist for the per-binary 60s runner budget
# (`WASM_BINDGEN_TEST_TIMEOUT`, top of this file), and each must still stay
# under ~52 MB. That number lived ONLY in comments here and in Cargo.toml —
# nothing measured it. A shard drifting past the ceiling does not fail with "too
# big"; it fails as an opaque 60s `Failed to detect test as having been run`
# timeout, which reads like a flaky browser and sends you looking in the wrong
# place. Measured, it is one line of output naming the shard.
#
# Unix/CI only (bash shebang): this is a size gate on the Linux CI runner, not
# something a Windows dev box needs to reproduce. The `[windows]` twin below
# loud-skips it so `verify-full` still completes there.

# Enforce the per-shard wasm ceiling headless Chrome can instantiate (CI/Unix).
[unix]
[working-directory('apps/desktop/web-rs')]
web-itest-size:
    #!/usr/bin/env bash
    set -euo pipefail
    CEILING_MB=52
    DEPS=target/wasm32-unknown-unknown/debug/deps
    # Clear PRIOR shard artifacts first. cargo keeps every hash-suffixed build in
    # deps/, so a stale binary from an older profile or feature set sits beside
    # the current one — and those are enormous (a debug wasm with debuginfo is
    # ~2 GB, vs ~7-21 MB once `[profile.test] strip = "debuginfo"` applies).
    # Measuring the directory blind reports those as failures and buries the real
    # numbers. Objects stay cached, so this costs a relink, not a rebuild.
    shopt -s nullglob
    rm -f "$DEPS"/gui_*.wasm
    # Build the shard binaries without running them. Same profile + features as
    # `web-itest`, so these are the artifacts the browser would load.
    cargo test --locked --no-run --target wasm32-unknown-unknown --features test-support
    files=("$DEPS"/gui_*.wasm)
    if [ ${#files[@]} -eq 0 ]; then
      echo "no gui_*.wasm shards found — the build layout changed, so this gate is measuring nothing" >&2
      exit 1
    fi
    status=0
    for f in "${files[@]}"; do
      bytes=$(wc -c < "$f")
      mb=$(( bytes / 1024 / 1024 ))
      if [ "$mb" -gt "$CEILING_MB" ]; then
        printf '  FAIL %4d MB  %s (ceiling %d MB)\n' "$mb" "$(basename "$f")" "$CEILING_MB"
        status=1
      else
        printf '  ok   %4d MB  %s\n' "$mb" "$(basename "$f")"
      fi
    done
    if [ "$status" -ne 0 ]; then
      echo "" >&2
      echo "A shard exceeds the ceiling headless Chrome can instantiate. Split it:" >&2
      echo "move a '#[path] mod' out of that tests/gui_N.rs into another shard, grouping" >&2
      echo "modules by the view subtree they mount (co-locating modules that mount the" >&2
      echo "same pane costs barely more than one of them; splitting them duplicates it)." >&2
      exit 1
    fi

# On Windows the shard ceiling stays a CI/Unix gate (bash recipe), so
# `verify-full` still completes — loudly, never silently.
[windows]
web-itest-size:
    @echo ""
    @echo "  !! SKIPPED: web-itest-size — the shard-size ceiling runs in CI (Linux) only."
    @echo "  !! A GUI test shard grown past the ceiling will fail CI, not this run."
    @echo ""

# Size of the SHIPPED frontend bundle: raw and gzip bytes of the built
# `dist/*.wasm`, `*.js` and `*.css`, as a markdown table (so CI appends it
# verbatim to `$GITHUB_STEP_SUMMARY`). `web-itest-size` above only measures the
# debug GUI-test shards; nothing else put a number on what the webview loads at
# every launch, so a dependency bump or a view that doubled it landed unnoticed.
# It measures whatever `dist/` holds: run `just web-build-release` (or
# `web-build-pages`) first. Deliberately NOT in `verify-full`, which builds the
# frontend in debug and mirrors CI's debug-only `web` job; pages.yml and the
# release workflow's Linux leg, which already run the release Trunk build, call
# it instead. WASM_WARN_KB is a soft ceiling (~1.5x the release wasm recorded in
# docs/architecture/release-updater-demo.md): past it the recipe prints a WARN
# line and still exits 0. Unix/CI only (bash), with a loud Windows skip below.

# Report the built frontend bundle's raw + gzip sizes (run a release build first).
[unix]
[working-directory('apps/desktop/web-rs')]
web-size:
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    WASM_WARN_KB=7300
    files=(dist/*.wasm dist/*.js dist/*.css)
    if [ ${#files[@]} -eq 0 ]; then
      echo "no built bundle in dist/ — run \`just web-build-release\` (or web-build-pages) first" >&2
      exit 1
    fi
    total=0
    total_gz=0
    warn=""
    echo "| file | bytes | gzip -9 |"
    echo "|---|---:|---:|"
    for f in "${files[@]}"; do
      bytes=$(wc -c < "$f")
      gz=$(gzip -9 -c "$f" | wc -c)
      total=$(( total + bytes ))
      total_gz=$(( total_gz + gz ))
      printf '| %s | %d | %d |\n' "$(basename "$f")" "$bytes" "$gz"
      if [[ "$f" == *.wasm ]] && [ $(( bytes / 1024 )) -gt "$WASM_WARN_KB" ]; then
        warn="$(basename "$f") is $(( bytes / 1024 )) KB, past the ${WASM_WARN_KB} KB soft ceiling"
      fi
    done
    printf '| **total** | **%d** | **%d** |\n' "$total" "$total_gz"
    if [ -n "$warn" ]; then
      echo ""
      echo "WARN: $warn — check what grew before raising it (see release-updater-demo.md)."
    fi

# On Windows the bundle-size report stays a CI/Unix recipe (bash), so it
# completes — loudly, never silently.
[windows]
web-size:
    @echo ""
    @echo "  !! SKIPPED: web-size — the bundle-size report runs on Linux/macOS (and in CI) only."
    @echo ""

# --- Housekeeping ------------------------------------------------------------

# Delete every cargo build artifact to reclaim disk. There are TWO independent
# build trees: the root workspace (`target/`) and the web-rs frontend, which is
# excluded from the workspace — so the root `cargo clean` never reaches it, and
# `web-rs/target/` is by far the larger of the two. `--manifest-path` cleans it
# without a chdir, keeping the recipe one plain `cargo` call per tree (works
# under both sh and PowerShell). The next build recompiles from scratch. The
# dist/ placeholder (gitignored; `_stub-frontend-dist` recreates it) is left alone.

# cargo clean BOTH build trees (root workspace + the excluded web-rs).
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

# Placeholder web-rs/dist so generate_context! compiles without a frontend build.
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

# Lint the workspace, warnings as errors, --locked (CI gate).
clippy: _stub-frontend-dist
    cargo clippy --locked --workspace --all-targets -- -D warnings

# Run the workspace test suite (CI gate). --locked enforces the committed Cargo.lock.
test: _stub-frontend-dist
    cargo test --locked --workspace

# Build docs for every workspace crate, failing on broken/inaccessible
# intra-doc links (CI gate). `[workspace.lints.rustdoc]` denies
# `broken_intra_doc_links` + `private_intra_doc_links`, and clippy never runs
# rustdoc — this recipe is where that deny actually fires. The links carry
# real weight here (module docs are the subsystem record agents are told to
# read), so a rename that orphans one is a defect, not cosmetic noise.
# --no-deps: the gate is our prose; third-party link resolution is not ours.
# Needs the dist stub because documenting src-tauri runs `generate_context!`.
doc: _stub-frontend-dist
    cargo doc --locked --workspace --no-deps

# Same rustdoc gate for the frontend tree (wasm target — on the host, web-rs's
# components are cfg'd out, so host docs would prove nothing). web-rs is
# excluded from the workspace, so its `[lints.rustdoc]` is a hand-mirror of the
# root's, pinned by `web_rs_lint_block_matches_the_workspace_block`.
[working-directory('apps/desktop/web-rs')]
web-doc:
    cargo doc --locked --no-deps --target wasm32-unknown-unknown

# The inner loop while iterating: type-check BOTH trees (the root workspace incl.
# every test target, and the wasm frontend) with no codegen and no tests. Not a
# CI gate — `verify` is — but it catches the compile error `verify` would take
# minutes to reach, and it keeps skills off hand-typed `cargo`. The wasm tree is
# checked with `--all-targets --features test-support`, the configuration
# `web-clippy` gates, so src/test_support, src/ipc_mock and the gui_N shards are
# type-checked too. Trade-off (the same one `web-clippy` makes): the shipped
# feature set's `cfg(not(feature = "test-support"))` paths are not re-checked
# here; `web-build` in `verify` covers them.

# Type-check both trees (no codegen, no tests) — the fast inner loop.
check: _stub-frontend-dist
    cargo check --locked --workspace --all-targets
    cargo check --locked --manifest-path apps/desktop/web-rs/Cargo.toml --target wasm32-unknown-unknown --all-targets --features test-support

# Future-incompatibility report for BOTH trees: code the pinned toolchain still
# accepts but a later Rust will reject. Not a gate (nothing here is ours to fix
# in place, and the pinned toolchain keeps it a warning) — run it before bumping
# `rust-toolchain.toml` (docs/DEVELOPMENT.md, "Bumping the Rust toolchain"), so a
# listed crate is planned for instead of surfacing as a hard error in a
# transitive proc-macro on the bump PR. Same two invocations as `check`, plus
# `--future-incompat-report`, which names every affected crate even on a cached
# build ("0 dependencies" for a clean tree). For the detailed lint text, run
# `cargo report future-incompatibilities` inside that tree afterwards — it takes
# no `--manifest-path` and errors on a tree with no report, so it is not used here.
#
# Known today (web-rs only): proc-macro-error2 2.0.1, E0365 "extern crate
# `proc_macro` is private" (rust#127909). Four proc-macros depend on it (from
# `cargo tree -i proc-macro-error2 --target all` in web-rs):
#   - leptos_macro 0.8.17 directly (leptos's `view!`);
#   - syn_derive 0.2 <- rstml 0.12 <- leptos_macro / leptos_hot_reload;
#   - reactive_stores_macro 0.4.3 <- reactive_stores 0.4.3 <- tachys (leptos's own);
#   - reactive_stores_macro 0.2.6 <- reactive_stores 0.2.5 <- thaw_utils.
# No semver update removes it. The exits are a fixed proc-macro-error2 release,
# or leptos (leptos_macro, rstml, reactive_stores) AND thaw all dropping it —
# one upstream alone does not clear the warning. The fallback is a
# `[patch.crates-io]` of proc-macro-error2 to a fixed fork (plus a deny.toml
# `allow-git` entry), which covers all four paths at once.

# Future-incompat report for both trees (not a gate) — run before a toolchain bump.
future-incompat: _stub-frontend-dist
    cargo check --locked --workspace --all-targets --future-incompat-report
    cargo check --locked --manifest-path apps/desktop/web-rs/Cargo.toml --target wasm32-unknown-unknown --all-targets --features test-support --future-incompat-report

# One crate's tests, e.g. `just test-crate azapptoolkit-core` or
# `just test-crate desktop -- repo_invariants` (args after `--` go to cargo test).

# Run one crate's tests: `just test-crate <crate> [-- <filter>]`.
test-crate CRATE *ARGS: _stub-frontend-dist
    cargo test --locked -p {{CRATE}} {{ARGS}}

# Check frontend formatting (CI gate; web-rs is excluded from the root workspace).
[working-directory('apps/desktop/web-rs')]
web-fmt-check:
    cargo fmt -- --check

# Lint the frontend with warnings as errors (CI gate). web-rs is excluded from
# the root workspace, so the root `clippy` recipe never reaches it — yet this is
# the largest, IPC-privileged tier. Lints the actual wasm build + the browser
# test harness; --features test-support so the integration-test targets (which
# use it) compile under --all-targets. --locked enforces the web-rs Cargo.lock.

# Lint the frontend for the wasm target, warnings as errors (CI gate).
[working-directory('apps/desktop/web-rs')]
web-clippy:
    cargo clippy --locked --target wasm32-unknown-unknown --all-targets --features test-support -- -D warnings

# Run the frontend unit tests on the host target (web-rs is excluded from the
# root workspace, so `just test` doesn't reach it). The pure-logic helpers have
# no runtime WASM dependency, so they compile and run natively. --locked enforces
# the committed web-rs Cargo.lock (this gate runs before web-build, so it pins the
# frontend lockfile that Trunk's build then reuses).

# The second line runs the Pages demo's own consistency tests (`src/demo/`,
# compiled only under the `demo` feature). Nothing else builds that feature
# except pages.yml, so this is also the demo's only compile gate before deploy.

# Run the frontend unit tests on the host target (CI gate).
[working-directory('apps/desktop/web-rs')]
web-test:
    cargo test --locked
    cargo test --locked --features demo --lib demo::

# The machine-independent gates, shared by `verify` / `verify-ui` /
# `verify-full` so the browser suite is named exactly once per entry point and
# can never run twice in one invocation. Frontend tests run before the (slower)
# web build, matching the CI web job and failing fast on a logic regression.

# The machine-independent gates shared by every verify entry point.
_verify-core: fmt-check clippy test doc web-fmt-check web-clippy web-test web-build web-doc

# Run the core CI gates locally, in order. Run this before declaring a change
# done. The browser GUI tests run too WHEN this box can (see `web-itest-auto`)
# and announce loudly when they cannot. Still not the whole of CI: the
# dependency audit/deny gates and the per-shard wasm ceiling (`web-itest-size`,
# a full wasm test build when web-itest did not just run) are covered by
# `verify-full`; actionlint stays CI-side unless installed locally.

# The CI gates in CI order + the browser tests when this box can run them. Run before "done".
verify: _verify-core web-itest-auto
    @echo ""
    @echo "verify OK — NOT run: audit, web-audit, deny, web-deny (need network), machete (needs cargo-machete) and web-itest-size (shard-size ceiling)."
    @echo "  just verify-ui    = verify with the GUI tests REQUIRED (fails without a browser)"
    @echo "  just verify-full  = full CI parity (adds the audit/deny/machete gates + the shard-size ceiling)"
    @echo "If web-itest reported SKIPPED above, frontend behavior is still unproven:"
    @echo "renaming a CSS class, aria-label, or on-screen text a GUI test references"
    @echo "passes verify and fails CI."

# verify with the browser GUI tests MANDATORY rather than best-effort — use it
# when you have Chrome + a matching chromedriver and want the frontend actually
# proven, not skipped.

# verify with the browser GUI tests MANDATORY (fails without Chrome + chromedriver).
verify-ui: _verify-core web-itest

# Full CI parity: the core gates + both RustSec scans + both deny policies + the
# unused-dependency scan + the browser GUI tests + the per-shard wasm ceiling.
# web-itest runs LAST because it needs a local browser + matching WebDriver (see
# its recipe) — the machine-independent gates fail first on a box without one.
#
# `web-itest-size` is here because ci.yml runs it and this recipe claims CI
# parity. It was missing, so a shard that had grown past the ceiling passed
# `just verify-full` locally and failed in CI — the exact failure mode the
# recipe exists to prevent.

# Full CI parity: core gates + audit/deny for both trees + unused-dep scan + browser tests + shard ceiling.
verify-full: _verify-core audit web-audit deny web-deny machete web-itest web-itest-size

# --- Dependency policy (CI audit/deny jobs) ---------------------------------

# RustSec advisory scan (config: .cargo/audit.toml; uses the RustSec DB).
audit:
    cargo audit

# RustSec scan of the frontend lockfile. web-rs is excluded from the root
# workspace and has its own Cargo.lock (incl. the git-pinned tauri-sys), so the
# root `audit` never sees it — and that WASM code runs inside the webview with
# IPC access, so it must be gated too.

# RustSec advisory scan of the frontend lockfile (web-rs is outside the workspace).
web-audit:
    cargo audit -f apps/desktop/web-rs/Cargo.lock

# Advisory + license + crate-source + bans policy (config: deny.toml).
# `advisories` IS in this list: deny.toml carries a fully documented
# `[advisories]` block (yanked = "deny" plus three reviewed RUSTSEC ignores), and
# omitting the check meant that block was config nobody executed — `yanked` was
# never enforced by anything, and the ignores read as if they were load-bearing
# here when only `.cargo/audit.toml` was actually consulted.

# cargo-deny policy (advisories/bans/licenses/sources) for the root workspace.
deny:
    cargo deny check advisories bans licenses sources

# Same policy for the frontend tree (web-rs is its own workspace; the root
# `deny` never reaches it). Reuses the root deny.toml so the two trees can't
# drift to different policies. `--config` sits on the ROOT command: the
# cargo-deny 0.20 CLI refactor moved it off `check` (needs cargo-deny >= 0.20;
# CI pins the matching version in ci.yml).

# cargo-deny policy for the frontend tree, reusing the root deny.toml.
[working-directory('apps/desktop/web-rs')]
web-deny:
    cargo deny --config ../../../deny.toml check advisories bans licenses sources

# Unused-dependency scan over BOTH trees. cargo-machete walks directories, not the
# cargo workspace, so this one root run also covers the excluded apps/desktop/web-rs.
# It needs no build and no network. A dependency used only inside a macro expansion
# is invisible to it: list it under that crate's `[package.metadata.cargo-machete]
# ignored` with a comment saying why (today: `thiserror` in arm/graph/keyvault,
# named only by `core::http_error_enum!`). Plain mode, not `--with-metadata`: that
# shells out to `cargo metadata`, which may rewrite a lockfile, and every other
# gate here runs `--locked`. CI pins the matching version in ci.yml.

# Fail on a declared-but-unused dependency in either tree (cargo-machete).
machete:
    cargo machete --skip-target-dir

# --- Release / packaging ----------------------------------------------------
#
# The release pipeline per platform is a COMPILE step (`cargo tauri build
# --no-bundle`: frontend + Rust, no bundling, no signing) and a BUNDLE step
# (`cargo tauri bundle`: bundling + updater signatures). release.yml runs them
# as two steps and scopes TAURI_SIGNING_PRIVATE_KEY[_PASSWORD] to the bundle
# step only (review F285): a single `cargo tauri build` used to run every
# dependency build script with the updater's minisign key in its environment,
# although the CLI only needs the key during bundling. The `build-*-updater`
# recipes chain the pair so a local rehearsal is still one command, and
# `cargo tauri bundle` runs only `beforeBundleCommand` and expects the binary
# already built — so always chain or compile first.
# Args after `--` go to the underlying cargo build: --locked enforces the
# committed Cargo.lock on the one pipeline that produces shipped bytes (every
# verify gate pins it; the release build must not silently re-resolve).

# Windows MSI + NSIS installers, release, --locked (no updater signing key needed).
[working-directory('apps/desktop/src-tauri')]
build-windows:
    cargo tauri build --target x86_64-pc-windows-msvc -- --locked

# Requires the updater signing key in TAURI_SIGNING_PRIVATE_KEY[_PASSWORD]
# (`cargo tauri bundle` fails without it when createUpdaterArtifacts is on);
# kept separate from `build-windows` so local/test packaging needs no signing
# key. Windows installers WITH signed updater artifacts (.sig → latest.json in
# CI). The override comes from `updater-build.json`, not inline `--config
# '{...}'`: PowerShell (the Windows recipe shell) strips the JSON's inner double
# quotes when handing args to cargo.exe, so inline JSON parses as invalid ("key
# must be a string"). A file path has no quoting to mangle. It is NOT a
# `tauri.*.conf.json` name, so Tauri never auto-loads it — only this explicit
# `--config` (and the `bundle-*` recipes above) does.

# Windows compile step: frontend + Rust, no bundles, no signing env.
[working-directory('apps/desktop/src-tauri')]
compile-windows:
    cargo tauri build --no-bundle --target x86_64-pc-windows-msvc -- --locked

# Windows bundle step: MSI + NSIS + updater .sig (needs TAURI_SIGNING_PRIVATE_KEY).
# No `--bundles`: default `targets: "all"` is exactly msi + nsis on Windows.
[working-directory('apps/desktop/src-tauri')]
bundle-windows:
    cargo tauri bundle --target x86_64-pc-windows-msvc --config updater-build.json

# Windows installers WITH signed updater artifacts (needs TAURI_SIGNING_PRIVATE_KEY).
[working-directory('apps/desktop/src-tauri')]
build-windows-updater: compile-windows bundle-windows

# macOS bundles (.dmg download + .app.tar.gz updater payload) with signed updater
# artifacts. Native Apple Silicon (aarch64) — a universal binary is deliberately
# NOT built (it's the historically-flaky bundling step on this stack; an Intel
# leg can be added later). `--bundles app,dmg` keeps deb/rpm/etc. off the macOS
# leg. Same updater-key contract as `build-windows-updater`.

# macOS .app + .dmg for local use (Apple Silicon), no updater signing key needed.
[working-directory('apps/desktop/src-tauri')]
build-macos:
    cargo tauri build --target aarch64-apple-darwin --bundles app,dmg -- --locked

# macOS compile step: frontend + Rust, no bundles, no signing env.
[working-directory('apps/desktop/src-tauri')]
compile-macos:
    cargo tauri build --no-bundle --target aarch64-apple-darwin -- --locked

# macOS bundle step: .app + .dmg + .app.tar.gz updater payload (needs the key).
[working-directory('apps/desktop/src-tauri')]
bundle-macos:
    cargo tauri bundle --target aarch64-apple-darwin --config updater-build.json --bundles app,dmg

# macOS .dmg + .app.tar.gz with signed updater artifacts (Apple Silicon).
[working-directory('apps/desktop/src-tauri')]
build-macos-updater: compile-macos bundle-macos

# Linux bundles (.AppImage download + updater payload, .deb for Debian/Ubuntu)
# with signed updater artifacts. Needs the GTK/WebKit/AppIndicator dev libs +
# patchelf on the build host (CI installs them). `--bundles appimage,deb` — rpm
# is omitted for now. Same updater-key contract as `build-windows-updater`.

# Linux AppImage + .deb for local use, no updater signing key needed.
[working-directory('apps/desktop/src-tauri')]
build-linux:
    cargo tauri build --target x86_64-unknown-linux-gnu --bundles appimage,deb -- --locked

# Linux compile step: frontend + Rust, no bundles, no signing env.
[working-directory('apps/desktop/src-tauri')]
compile-linux:
    cargo tauri build --no-bundle --target x86_64-unknown-linux-gnu -- --locked

# Linux bundle step: .AppImage + .deb + updater payload (needs the key).
[working-directory('apps/desktop/src-tauri')]
bundle-linux:
    cargo tauri bundle --target x86_64-unknown-linux-gnu --config updater-build.json --bundles appimage,deb

# Linux AppImage + .deb with signed updater artifacts.
[working-directory('apps/desktop/src-tauri')]
build-linux-updater: compile-linux bundle-linux

# Regenerate every bundled icon format from icons/icon.svg.
[working-directory('apps/desktop/src-tauri')]
icon:
    cargo tauri icon icons/icon.svg

# --- One-time developer setup (idempotent — safe to rerun) ------------------
# The bodies live in scripts/setup.sh and scripts/setup.ps1 (they were inlined
# here once, which doubled this file and made `just --list` unreadable; `just
# setup` stays the single entry point). Each verifies the Rust toolchain, adds
# the wasm target + rustfmt/clippy, installs the Tauri CLI, trunk and wasm-pack
# if missing, checks OS-specific build deps (incl. a C toolchain) + the
# browser-test prerequisites, then runs `just check` + `just web-build` as a
# smoke test. Run `cargo install just` (or your package manager) first, then
# `just setup`.

# One-time, idempotent developer bootstrap (toolchain, targets, CLIs, browser test deps).
[unix]
setup:
    bash scripts/setup.sh

[windows]
setup:
    powershell.exe -NoLogo -ExecutionPolicy Bypass -File scripts/setup.ps1
