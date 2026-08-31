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

**Two parsers now depend on that header**, and they must agree: `release.yml` (above) and
`web-rs/build.rs`, which slices the *running* version's section the same way and bakes it into
the wasm bundle for the in-app "What's new" (below). `web-rs`'s
`the_running_versions_changelog_section_is_baked_in` test fails the build when the manifest
version has no finalized section — the same mistake that would otherwise ship blank in-app notes.

## Auto-update is interactive, never silent

The front-end checks once on launch (`commands::updater::check_for_update`, swallowed silently
on failure and in dev). If an update waits, it toasts a notification whose action opens the
`UpdateSplash` (`web-rs/components/update_splash.rs`): changelog notes + an explicit
**Update & restart** button (`perform_update`: `download_and_install` → `app.restart()`, byte
progress on the `updater-progress` channel). A manual "Check for updates" item lives in the
account menu that drops from the top-bar tenant pill (`shell.rs`, alongside the version string).

The splash's changelog text is the updater manifest's `notes` (populated per the contract above),
so it only lights up for releases from **v0.8.0 onward** — v0.7.0's `latest.json` predates it.

**Do not reintroduce a silent background `download_and_install` in `lib.rs` setup** — it was
removed in favour of this flow and would race the prompt.

### Release notes are rendered summary-first

`CHANGELOG.md` serves operators *and* contributors: every entry is a one-sentence lede followed
by paragraphs of rationale and implementation detail, plus whole `### Internal` sections about
tests and refactors. Rendered verbatim, an update splash answers "what does this change for me?"
with several screens of backend detail.

`components/changelog_notes.rs` therefore condenses by default — internal sections dropped, every
bullet cut to its first sentence, nested bullets (always elaboration) dropped — with a **Show
technical details** toggle that renders the section verbatim. The toggle only appears when the two
differ, and a release that condenses to nothing says so rather than rendering an empty box. Two
consequences worth knowing:

- **The transform is at render time, not in `release.yml`'s extraction.** The manifest keeps the
  full section, so the toggle has something to show and already-published releases summarise too.
- **The lede sentence is the whole user-facing summary.** `first_sentence` treats a `.`/`!`/`?` as
  a sentence end only when what follows can start one (uppercase, `**`, backtick, quote, `[`), so
  `e.g.`, `v0.22.4` and `1.2.1 → 1.2.2` survive. Writing an entry whose first sentence is *not* a
  self-contained statement of what changed is what makes these notes read badly — the renderer
  cannot recover it.

### "What's new" for the version already installed

The splash is a one-shot: once the update installs, the notes it showed are gone. `web-rs/build.rs`
bakes the running version's `CHANGELOG.md` section into the bundle at compile time and
`components/release_notes.rs` renders it — through the same `ChangelogNotes` component — in a
dialog opened from **What's new** on the version line of the account menu (`shell.rs`).

Compile-time, not an IPC call, deliberately: it works offline, on first launch, and in the Pages
demo, where an unfixtured infallible `invoke()` takes down the whole page. A version with no
CHANGELOG section bakes an empty string and the dialog degrades to its "Full changelog on GitHub"
link — but the web-rs test above fails first, so that state should never ship.

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

The direct `rand = "0.8"` pin in `src-tauri/Cargo.toml` (random bytes for the v4 GUIDs
`commands/guid.rs` mints, which `expose_api`/`app_roles`/`managed_identity` consume) and the
`sha2 0.10` line the tree resolves to are held to match what **`oauth2` 5 + Tauri 2** already
resolve. Note `sha2` is **not** a direct dependency: both certificate thumbprints digest on
`aws-lc-rs`, the same backend rcgen signs with (`src-tauri/Cargo.toml` says so at the
`aws-lc-rs` block). The only direct consumer of the 0.10 line is `p12-keystore`, pinned below
precisely to keep it there. As of a full `cargo update` on **2026-07-13**, `rand` is the only
direct dep in the entire codebase behind a major (web-rs is fully current). The re-eval trigger
below has **not** fired:

- **`rand` (0.8.7 → 0.10.2):** `oauth2` 5.0.0 — the latest oauth2 — still resolves `rand 0.8.7` /
  `rand_core 0.6.4`. Bumping our direct dep to 0.10 leaves oauth2's `rand 0.8` in the tree
  regardless (no dedup), and pulls `getrandom 0.3` alongside the in-tree 0.2.
- **`sha2` (0.10.9 → 0.11.0):** `sha2 0.10.9` is shared by oauth2 5, Tauri 2.11
  (`tauri-codegen` / `wry`) and `secret-service`, all unified on `digest 0.10`. We'd be the *only*
  crate on 0.11, so the bump **adds** a second `sha2` **and** a second `digest` major — net *more*
  duplication, not less.
- **Cost with no benefit:** `rand` needs a code edit (`commands/guid.rs`: `rand::thread_rng()` →
  `rng()`, renamed in 0.9+) and `cert.rs` uses `rand::rngs::OsRng` for the `.pfx` password — while
  `cargo audit` is clean on both held versions, so nothing forces the move.

**Re-evaluate only when `oauth2` (or Tauri) ships a release on `rand 0.9+` / `sha2 0.11`** — then a
bump dedups the tree instead of duplicating it. Both lockfiles otherwise track the latest
semver-compatible versions — a plain `cargo update` is a no-op.

### `p12-keystore` is pinned to 0.2.x — the same rule, applied to a new dep

The `.pfx` export (`cert.rs::build_pfx`) needs a PKCS#12 writer. `p12-keystore` **0.2.1** was
taken over the current **0.3.1** deliberately, and the pin is enforced in `dependabot.yml`.

0.3.x depends on `cms ^0.3.0-pre.1`, which requires `der 0.8.0-rc`, `spki 0.8.0-rc` and
`x509-cert 0.3.0-rc` as **non-optional** deps — four pre-release crates in the dependency graph
of a tool that handles tenant credentials. `deny.toml` sets `yanked = "deny"` as a required
check, and RustCrypto routinely retires superseded release candidates, so that combination lets
an upstream yank break CI with no change on our side. 0.3.x also rides the RustCrypto 0.11 hash
line, which would add a second `sha2` **and** `digest` major — exactly what the `rand`/`sha2`
reasoning above exists to avoid.

0.2.1 is all-stable and lands entirely on majors the lock file already carries — `sha2 0.10`,
`hmac 0.12`, `cbc 0.1`, `rand 0.10`, `x509-parser 0.18`, `base64 0.22`, `thiserror 2` — so
`cargo tree -d` gains **no new duplicate major at all**. The 16 crates it does add (`cms 0.2.3`,
`pkcs12 0.1`, `pkcs5 0.7`, `der 0.7`, `spki 0.7`, `x509-cert 0.2`, `const-oid 0.9`, `sha1 0.10`,
`pbkdf2`, `scrypt`, `salsa20`, `base64ct`, `pem-rfc7468`, `flagset`, `der_derive`) are all
stable releases under `Apache-2.0 OR MIT`.

The output is identical either way: **PBES2 / AES-256-CBC with an HMAC-SHA256 MAC** at 10 000
iterations is both versions' default, and `build_pfx` sets it explicitly regardless so a future
default change cannot silently downgrade a bundle.

`default-features = false` drops the crate's `pbes1` feature (RC2/DES) — those decrypt *legacy*
stores, and this app only ever writes its own.

**`rsa` stays out.** `cms` carries `rsa` as an optional dep, reachable only through its `builder`
feature, which nothing here enables — `cargo tree -i rsa` returns "did not match any packages".
That is a property to verify, not assume: `deny.toml`'s `[[bans.deny]] name = "rsa"` is what
actually holds the line.

**Drop this pin once `cms 0.3.0` ships final**, then take `p12-keystore` 0.3.x in one deliberate
commit (its `PrivateKeyChain::new` reverses to `(local_key_id, key, certs)` and takes a typed
`PrivateKey`, so the swap does not compile silently — but see
`the_generated_pfx_is_the_same_identity_as_the_revealed_pem`, which is what proves it either way).
