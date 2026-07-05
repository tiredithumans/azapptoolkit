# Agent Instructions — azapptoolkit

azapptoolkit is a **native Rust desktop app for managing Microsoft Entra ID app registrations** —
the replacement for ad-hoc PowerShell. Tauri 2 + Leptos 0.8 (WASM) workspace, edition 2024,
MSRV **1.96** (`rust-toolchain.toml`).

This file is an **invariant + pointer index**, not a manual: each gotcha is one rule plus a link
to the deep-dive. Keep it that way — deep detail belongs in `docs/architecture/`, and a size hook
warns past 28 000 bytes. **Read the linked doc before editing that subsystem.**

## Quick Reference

| Item | Detail |
|---|---|
| **Task runner** | `just` — recipes in `/justfile`; Tauri hooks call them too, so flags never drift. |
| **Setup / Dev** | `just setup` (OS-aware bootstrap) · `just dev` (`cargo tauri dev`) |
| **Verify** | `just verify` (fmt → clippy → test → web-fmt-check → web-clippy → web-test → web-build). `just verify-full` adds the CI-only gates (audit/deny both trees + web-itest). |
| **Workspace** | 9 crates (8 in `crates/` + `src-tauri`); frontend (`web-rs`) excluded, builds via Trunk. |

## Skills

| Skill | Trigger text | What it does |
|-------|-------------|--------------|
| **ship** | `"ship"`, `"land this"` | Commit → push → PR → wait on CI → merge → cleanup. |
| **feature** | `"feature X"`, `"add feature X"` | Scaffold a new branch, backend command stub, frontend binding, and verify. |
| **repo-review** | `"repo review"`, `"review this PR"` | Diff base → head, run verify gates, check conventional-commits & tenant-cache footguns. |
| **release** | `"release"`, `"bump version"` | Bump the 3 manifests, finalize CHANGELOG.md `[Unreleased]` → `[X.Y.Z]`, PR, tag, verify draft. |
| **debug** | `"debug X"` | Diagnose Tauri + Leptos WASM issues — walks backend, frontend, auth layers. |

Skills live in `.claude/skills/`; they activate on the trigger text above.

Key files/docs to read before editing:
- **Adding a command?** `src-tauri/src/lib.rs` (handler list) + `web-rs/src/bindings/`.
- **Auth / token / consent / re-auth?** [auth-and-consent.md](docs/architecture/auth-and-consent.md) → `src-tauri/src/state.rs` + `crates/azapptoolkit-auth/src/token_cache.rs`.
- **Caches, list commands, search, batch fan-out?** [caching-and-search.md](docs/architecture/caching-and-search.md).
- **Audit scoring, findings, remediations, Exchange/SharePoint scoping?** [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).
- **Frontend: session state, open-items workspace, UI primitives, Security workbench layout?** [frontend-workspace.md](docs/architecture/frontend-workspace.md).
- **Release matrix, auto-update, Pages demo, crypto pins?** [release-updater-demo.md](docs/architecture/release-updater-demo.md).
- **DR backup/restore?** [backup-and-restore.md](docs/architecture/backup-and-restore.md) → `crates/azapptoolkit-dto/src/backup.rs` + `src-tauri/src/commands/backup.rs`.
- **New dependency?** Check `Cargo.lock` for transitive conflicts.
- **WASM code?** `crates/azapptoolkit-core/src/lib.rs` for `#[cfg(not(target_arch = "wasm32"))]`.

## Repo map

```
crates/                              # shared Rust libraries
├── azapptoolkit-core/               # domain models, cache (LRU+TTL), audit/risk scoring
├── azapptoolkit-dto/                # serializable IPC boundary types (backend + frontend)
├── azapptoolkit-auth/               # Entra OAuth2 PKCE, token cache, OS keyring
├── azapptoolkit-graph/              # typed Microsoft Graph client (retry/backoff)
├── azapptoolkit-exchange/           # Exchange Online Admin API (RBAC for Applications)
├── azapptoolkit-keyvault/           # Azure Key Vault secrets client
├── azapptoolkit-arm/                # ARM + Azure Monitor Logs query (managed-identity)
└── azapptoolkit-permissions/        # bundled permissions catalog (data/) + Graph fallback

apps/desktop/
├── src-tauri/                       # backend (main process)
│   ├── lib.rs                       # Tauri builder, tracing, command registration
│   ├── state.rs                     # AppState: auth singleton, clients, cache, cancel flag
│   ├── commands/                    # #[tauri::command] handlers (domain files + applications/ sso/ subdirs)
│   ├── token_adapter.rs             # ScopedTokenAdapter (BearerProvider) for per-scope tokens
│   ├── build.rs                     # bakes AZAPPTOOLKIT_CLIENT_ID/_TENANT_ID from .env
│   ├── tauri.conf.json              # CSP, bundle, updater, before{Dev,Build}Command
│   └── capabilities/                # scoped capability definitions
└── web-rs/                          # WASM frontend — EXCLUDED from root workspace
    ├── main.rs                      # entry, theme detection, root component / routing
    ├── state.rs                     # context-provided Session (RwSignals)
    ├── views/                       # page/layout components
    ├── components/                  # reusable UI components
    ├── hooks/                       # Leptos Effect/Signal helpers (e.g. use_debounced)
    ├── bindings/                    # typed Tauri IPC stubs — mirror backend commands
    ├── ipc_mock/                    # shared mock Tauri IPC bridge + fixtures (test-support + demo)
    ├── demo/                        # GitHub Pages demo: mock IPC + curated sample data (feature `demo`)
    └── Trunk.toml                   # WASM build/serve (127.0.0.1:5173)

docs/DEVELOPMENT.md                  # build, test, package, release, updater keys
docs/architecture/                   # deep-dives: auth-consent · caching-search · scoping-audit · frontend-workspace · release-updater-demo · backup-restore
.github/workflows/                   # ci.yml · release.yml (Win MSI+NSIS · macOS dmg · Linux AppImage+deb, matrix) · codeql.yml · pages.yml (GitHub Pages demo)
```

## Common patterns

- **New Tauri command** — 3 steps (advisory hook `command-parity-check.sh` warns if you miss one):
  1. Implement `#[tauri::command] async fn` under `src-tauri/src/commands/` (a domain file or the `applications/` / `sso/` subdir).
  2. Add to `tauri::generate_handler![]` in `src-tauri/src/lib.rs`.
  3. Create a typed stub in `web-rs/src/bindings/` (calls `invoke_result`).

- **Workspace dependency** — add to `[workspace.dependencies]`, reference via `"name".workspace = true`. Check `Cargo.lock` for conflicts.

- **Audit scoring rule** — implement in `azapptoolkit-core::audit` with a table-driven test citing legacy PowerShell `file:line`.

- **Audit remediation (one-click "Fix")** — only for findings with a safe, existing mutation (additive like AddOwner or reversible like DisableSignIn also qualify); handler **re-resolves live state**. Scorer-attached via `build_remediations`, except `DisableSignIn` (runner post-pass) and `AddOwner` (no dedicated handler; the modal reuses `add_application_owner`). Full pattern: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **New external origin (CSP)** — only direct WASM frontend fetches need a `connect-src` change; backend reqwest calls don't.

## Canonical commands

All build/dev/verify commands live in `/justfile`. `just` searches upward, so recipes resolve from any subdirectory. Tauri's hooks call the same recipes; update them when you change build flags.

```bash
just setup          # one-time (idempotent OS-aware bootstrap)
just dev            # daily loop (= cargo tauri dev)

# CI gates:
just verify          # fmt-check → clippy → test → web-fmt-check → web-clippy → web-test → web-build
just verify-full     # verify + audit + web-audit + deny + web-deny + web-itest (full CI parity; web-itest needs a browser)
just fmt-check | clippy | test | web-fmt-check | web-clippy | web-test | web-build  # individual gates

# Frontend GUI tests (browser-gated, NOT in `verify` — only in `verify-full`/CI):
just web-itest       # real Leptos views in a headless browser, Tauri IPC mocked
                     # (no tenant/backend). Needs a browser + driver; CI uses Chrome.

# GitHub Pages demo build (deploy-only, NOT in `verify`):
just web-build-pages [BASE]   # release + `demo` feature (mock IPC + sample data,
                              # no backend) + subpath base-href; published by pages.yml.

# Dependency policy (required CI checks — run via verify-full):
just audit          # RustSec advisories (root workspace)
just web-audit      # RustSec (web-rs lockfile, separate from root)
just deny           # license + crate-source + bans (deny.toml)
just web-deny       # same policy, web-rs tree

# Release builds (per-host; the release.yml matrix runs the updater legs) + icons:
just build-windows-updater   # Windows MSI + NSIS installers + signed updater .sig (needs TAURI_SIGNING_PRIVATE_KEY)
just build-macos-updater     # macOS .dmg + .app updater payload (Apple Silicon)
just build-linux-updater     # Linux .AppImage + .deb + signed updater .sig
just build-windows           # keyless local packaging (MSI+NSIS, no updater .sig)
just icon                    # regenerate from icons/icon.svg

# Housekeeping:
just clean          # cargo clean BOTH build trees (root + excluded web-rs) to reclaim disk
```

Running locally needs `AZAPPTOOLKIT_CLIENT_ID` + `AZAPPTOOLKIT_TENANT_ID`. For team builds, bake via `.env` (see `build.rs`).

## Conventions & gotchas

- **Tauri commands:** `#[tauri::command] async fn` → `State<'_, AppState>` → `Result<T, UiError>`. Must be in `generate_handler![]` AND have a typed stub calling `invoke_result()`. Frontend args use `#[serde(rename_all = "camelCase")]`.

- **Tenant-scoped caches — cross-tenant leakage is the #1 footgun.** Cache keys are `{tenant_id}|{kind}`; never unscoped. On sign-out, `invalidate_prefix(kind, "{tenant_id}|")` for **every** kind. Details: [caching-and-search.md](docs/architecture/caching-and-search.md).

- **Invalidate caches only on `Ok`.** After success, bust the relevant list cache; on failure, leave fresh data alone. SP/app-registration mutation → `invalidate_app_lists(...)` (list keys + transitively detail + mailbox-scopes + audit). **Credential-only** mutations → `invalidate_app_credentials(cache, tenant, object_id)` (keeps the indexes). Details: [caching-and-search.md](docs/architecture/caching-and-search.md).

- **`CacheKind::ServicePrincipal` self-invalidates in the graph client, not the command aggregators.** Keyed by `appId` but SP mutators take an SP *object* id, so `delete`/`patch_service_principal` + `set_service_principal_tags` sweep the tenant prefix on `Ok`; `invalidate_app_lists` does **not** touch this kind. Details: [caching-and-search.md](docs/architecture/caching-and-search.md).

- **camelCase vs snake_case.** Graph domain models (`Application`, `ServicePrincipal`) are camel (no serde rename). DTOs/bindings are snake_case. A few core types (`Application`, `AuditItem`) cross IPC **as-is** — renaming is a wire-format change.

- **WASM gating.** `web-rs` compiles to `wasm32-unknown-unknown`. Server deps (tokio, reqwest, rustls) must be gated `#[cfg(not(target_arch = "wasm32"))]` in shared crates, or excluded from `web-rs`.

- **Auth: lazy, shared token refresh.** Token refreshes lazily (~60s before expiry) behind a shared mutex. Refresh tokens in OS keyring (chunked across numbered entries — Windows Credential Manager cap 2560 UTF-16 bytes). Write scopes consented **incrementally**. Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Extra-scope tokens (on-demand).** Admin-consent/premium scopes ride a `ScopedTokenAdapter` — never in the sign-in scope set. Every call must **degrade gracefully**. Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Silent grants can't *obtain* consent.** AADSTS65001/65004 → `AuthError::ConsentRequired` (distinct from `InvalidGrant`). Interactive consent via `EntraAuthService::consent_for_scopes`. Commands that need a "Grant consent" button must **pre-acquire** the token via `AppState::ensure_*` so `consent_required` survives `BearerProvider`. Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Force re-auth in place when the session is dead — don't sign the user out.** A dead refresh token (`InvalidGrant`/`RefreshTokenMissing` → code **`refresh_missing`**; `NotSignedIn` → **`not_signed_in`**) can't be re-minted silently; the `reauthenticate` command runs ONE interactive round trip and restores the session **without** dropping the tenant's data caches. Add a new re-auth-fatal code → extend BOTH `matches!` sets (`state.rs` + `shell.rs`). Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Role/scope catalog.** Three auth planes (Entra, Azure RBAC, Exchange) share one capabilities catalog. Adding a privileged feature → add a catalog entry instead of hardcoding role strings. Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Audit signals — structured, not text.** Facets/cards/finding groups key off `AuditItem` fields (`risk_level`, `credential_status`, `unused`, …), not `starts_with(...)` on free-text.

- **Shared `audit_cancel` flag.** Security-audit and Bulk-actions both poll `AppState.audit_cancel`. New long-running commands must `reset()` at the top. Resource Access lookups poll `AppState.sweep_cancel` (independent); DR backup/restore uses `AppState.dr_cancel`. Tested in `state.rs`.

- **Batched Graph fan-out + adaptive throttle.** Heavy per-object fan-outs (security audit, DR backup) use Graph JSON batching (`client.batch_get_json[_with_headers]`, 20 GETs/POST) + the shared `ConcurrencyThrottle` attached via `ThrottleGuard::attach`. Reuse both for any new heavy fan-out; don't hand-roll a second tracker or a raw per-item loop. Whole-batch failures must degrade to per-object reads. Details: [caching-and-search.md](docs/architecture/caching-and-search.md).

- **Scope-aware audit risk.** Mail permission risk depends on Exchange RBAC scoping: `score_application` reads `AppPermissions.mail_scopes` (empty map = org-wide). SharePoint scoping is name-based, no live call. Badges render in `web-rs/components/scope_badge.rs`. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Scoped grants reuse shared cores.** Exchange + SharePoint both grant scoped access *before* stripping org-wide, so a failure never strands the principal. Exchange scope source: `azapptoolkit_<app_id>` mail-enabled security group (`group_name_for`); membership changes **don't** invalidate caches. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Unified "Grant access" wizard.** One "Grant access" button per principal (`ScopeWizard`, `web-rs/components/scope_wizard.rs`) subsumes the old inline "Add permission" picker: select permissions (full-catalog cart) → choose access → grant. `mechanism` is `Some(kind)` only when the cart is non-empty *and* every item is an Application permission of the **same** `ScopeKind` (delegated/mixed/non-scopable ⇒ org-wide). Add a mechanism = a `ScopeKind` variant + a target panel + an apply arm; nothing else branches on the concrete mechanism. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Frontend reactivity is closure-based.** `{move || sig.get()}` for tracking; `.get()`/`.with()` to read. State is `RwSignal<T>` on a context-provided `Session`. CSS: plain global `styles.css` with BEM-ish names. Details: [frontend-workspace.md](docs/architecture/frontend-workspace.md).

- **One primitive per UI pattern (design-consistency invariant).** Page header = `components::ui::SectionHeader`; loading = skeletons (`SkeletonList`/`DetailSkeleton`), spinners only in-button/inline; load failure = `DetailLoadError`; notices/alerts = `components::ui::Callout`. Reuse the primitive; don't re-implement the markup. Details: [frontend-workspace.md](docs/architecture/frontend-workspace.md).

- **Open-items workspace = full-width lists + ONE shared cross-entity working set.** Opening a row calls `session.open_item(kind, entity_id, title)` into `Session.open_items` — there is no side detail pane; the dock + workspace mount **once in `shell.rs`**. **Footgun:** `open_items` + `shown_items` MUST reset in `set_active_tenant`, or a stale item leaks the prior tenant's data. No `selected_*_id` signals — global search, pairing, and deep-links all route through `open_item`/`close_item_by_entity`; don't reintroduce them. Details: [frontend-workspace.md](docs/architecture/frontend-workspace.md).

- **Per-list filter state lives on `Session.tenant_ui` (`TenantScopedUi`) and resets on tenant switch by structure.** Searches + drill-target facets + both bulk selections + shell dialog flags live there so outside surfaces (Global Search, Home metrics) can seed them. A new tenant-scoped signal goes INTO the substruct with a `reset()` line + an assertion in the `tenant_switch_resets_every_tenant_scoped_field` pinning test — never as a bare `Session` field with a hand-added reset. Details: [frontend-workspace.md](docs/architecture/frontend-workspace.md).

- **Security tab = findings-first workbench: one controller, read-only posture strip, keep-alive sub-tabs.** Filtering has exactly two homes — the Findings accordion + the All-apps `audit_severity` control; the strip is counts-only (don't reintroduce a severity TabBar / chip drawer / clickable scorecard as filters). `BulkActionBar` is the single home of bulk command-calling; **no Grant consent on audit surfaces**. **Load-bearing asymmetry:** `scoped_mailbox` matches `.contains(SCOPED_VIA_RBAC)` while sibling findings use `.starts_with` (pinned by `filter.rs` tests — a "normalize to starts_with" sweep empties it). Layout: [frontend-workspace.md](docs/architecture/frontend-workspace.md); finding semantics: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **The audit also scores SP-only principals (no local app registration) — and those rows are NOT bulk targets.** Phase 2 of `run_audit` scores foreign-tenant enterprise apps / MIs / orphaned SPs from their **granted** Graph app roles. `AuditItem.principal_kind` (`#[serde(default)]`, old cached runs read as `Application`) drives frontend routing; SP rows' Fixes call the SP-only cores, **never** the `remediate_scope_*` wrappers (they `get_application` first → 404). **SP rows render no checkbox and are excluded from select-all** — feeding an SP object id into an app-reg bulk core is the failure mode to guard. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Bulk remediations reuse the single-app cores, run sequentially.** `bulk_remove_redundant_permissions` / `bulk_scope_mailbox_access` / `bulk_scope_sharepoint_access` (`commands/bulk.rs`) loop the per-app remediation paths — **not** the `dispatch_capped` spawn fan-out (those cores take `State`, not `Send`). They `reset()` + poll `audit_cancel` and degrade to a per-app `error` rather than aborting. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Build-time config baking.** `build.rs` reads `.env`, emits `AZAPPTOOLKIT_BUILD_*`; runtime env vars override.

- **GitHub Pages demo = the WASM frontend with the Tauri backend mocked.** `just web-build-pages` builds `web-rs` with the `demo` feature (off in `web-build`/desktop, so the mock never ships); the shared `ipc_mock` bridge is pre-loaded with curated fixtures and deployed by `pages.yml`. **Footgun:** any infallible `invoke()`/`invoke::<()>` read reachable in the demo must be registered in `demo::register_fixtures`, or it **panics** on the rejected-promise fallback. Details: [release-updater-demo.md](docs/architecture/release-updater-demo.md).

- **Auto-update is interactive (not silent).** The front-end checks once on launch and toasts a notification whose action opens `UpdateSplash` (explicit **Update & restart**). **Don't reintroduce a silent background `download_and_install` in `lib.rs` setup** — it was removed in favour of this flow and would race the prompt. Details: [release-updater-demo.md](docs/architecture/release-updater-demo.md).

- **Release is a 3-OS matrix → one aggregated `latest.json`.** `release.yml`: `guard` (version/pubkey/audit) → `build` matrix (`build-windows-updater` · `build-macos-updater`, aarch64 only · `build-linux-updater`) → `release` assembles one draft; a human publishes. CHANGELOG version headers are `## [X.Y.Z] - YYYY-MM-DD` (**no `v` prefix, ASCII hyphen**) — the updater notes-extraction regex depends on it. Full flow: the `release` skill; matrix detail: [release-updater-demo.md](docs/architecture/release-updater-demo.md).

- **CSP governs the *webview*, not backend egress.** `connect-src` in `tauri.conf.json`; only WASM frontend fetches are restricted. Backend reqwest calls to new hosts don't need a CSP change.

- **Permissions catalog** is bundled at compile time from `azapptoolkit-permissions/data/`. Unknown resources fall back to `resolve_resource_sp()` Graph call.

- **Full-collection PATCH for `appRoles` / `oauth2PermissionScopes`.** Both are not-nullable arrays Graph **full-replaces** — re-read live state, mutate, write the whole array back (never merge against a cached payload). Deleting an enabled entry needs two PATCHes: disable first, then remove (`commands/expose_api.rs`, `commands/app_roles.rs`). Exposed **app roles** edit the **paired application** when one exists (else the SP directly) and round-trip roles as **raw JSON** so the `value: null` SAML default (`msiam_access`) survives byte-for-byte (a typed `AppRole` would rewrite it to `""`). Bust with `invalidate_app_details` only.

- **Crypto deps — no `rsa`; `rand`/`sha2` majors pinned on purpose.** Cert generation (`src-tauri/src/cert.rs`) uses `rcgen` on the `aws_lc_rs` backend specifically to keep `rsa` (RUSTSEC-2023-0071) out of the graph — **don't reintroduce `rsa`**. The `rand = "0.8"` / `sha2 = "0.10"` pins match what `oauth2` 5 + Tauri 2 resolve; bumping only stacks a duplicate major, so leave them until oauth2/Tauri move first. Details: [release-updater-demo.md](docs/architecture/release-updater-demo.md).

## Coding fundamentals

- Match the style, structure, and idioms of the file you're editing.
- Solve the task at hand; don't refactor unrelated code or expand scope.
- No abstraction, configuration, or generality for hypothetical futures (YAGNI).
- Comments explain *why*, not *what*.
- Dependencies are a cost; prefer std lib and existing workspace deps.
- Security first: no secrets to disk, tokens scoped per resource, don't log secrets.
- Test what you change; keep the suite green.

## Git & version control

- **Conventional Commits required:** `<type>[(scope)][!]: <description>`. The `conventional-commit-validator.sh` hook enforces this (types **and** the scope allowlist below).
  - Types: `feat fix docs chore refactor test build ci perf style revert deps`
  - Scopes (the canonical nine — this list is the single source; the hook mirrors it): `desktop`, `core`, `auth`, `graph`, `exchange`, `keyvault`, `permissions`, `ci`, `docs`. Omit the scope rather than invent one.
- Branch naming: `<type>/<short-slug>` (e.g. `feat/batch-approve`).
- Porting from legacy PowerShell → reference source `file:line` in the commit body.

## Verification playbook

Run the same gates CI runs before declaring a change done. `just verify` is the machine-independent core; `just verify-full` adds full CI parity. Use recipe flags from `/justfile`, don't hand-type raw `cargo` invocations.

1. **Format** — `just fmt-check`
2. **Lint** — `just clippy` (`-D warnings`)
3. **Test** — `just test` (workspace)
4. **Frontend** — `just web-fmt-check` + `web-clippy` (`-D warnings`, wasm target; web-rs is excluded from the root workspace so root `clippy` doesn't reach it) + `web-test` + `web-build`
5. **Frontend GUI tests** *(browser-gated; in `verify-full`/CI, not `verify`)* — `just web-itest`: real Leptos views in a headless browser with the Tauri IPC mocked. New view-behavior changes get a `tests/gui/<view>.rs` **module** + a `mod <view>;` line in `tests/gui.rs`; the harness lives in `web-rs/src/test_support/`. **All GUI tests compile into one binary (`tests/gui.rs`) so wasm-pack boots Chrome once** — never add a top-level `tests/*.rs` (cargo compiles each into its own binary, and per-binary `wasm-bindgen`+browser-boot overhead was ~97% of a ~13-min CI step). Tests share the one page's DOM; `test_support::reset()` (every test's first call) clears the body between them. That one binary monomorphizes every view, so its debug wasm is large — the recipe raises `WASM_BINDGEN_TEST_TIMEOUT` (120s) past the runner's 20s "detect test" default, which the single binary would otherwise blow. Renaming a CSS class / aria-label / on-screen text that a test references passes local `verify` but fails CI — the `web-test-strings-check.sh` hook warns at edit time.
6. **Dependency audit + deny** *(required CI checks)* — `just audit` + `web-audit` (RustSec) + `deny` + `web-deny`; all four are merge-blocking. `verify-full` runs them.
7. **actionlint** *(required CI check)* — lints the workflow YAML; runs CI-side (install locally to pre-check).
8. **CodeQL** *(GitHub-side)* — security queries, Rust build-mode `none`. Known limitation: CodeQL 2.25.6 doesn't expand macros for this codebase (~39% calls-with-call-target), expected and non-failing. Config: `.github/codeql/codeql-config.yml`.

For behavior changes not provable by unit test, run `just dev` and exercise the view.

## Keeping this file up to date

When editing these files, update the matching section here:
crate/dir changes → **Repo map**; workspace/toolchain/MSRV → **Quick Reference**;
`justfile` recipes / build commands → **Canonical commands, Verification playbook**;
new command/IPC/cache/CSP/cancel flag → **Conventions & gotchas** (one invariant + a doc pointer — deep detail goes in `docs/architecture/`);
CI gate or `tauri.conf.json` bundle/updater → **Verification playbook**.

The `staleness-check.sh` hook reminds you when a structural edit likely needs an AGENTS.md or doc update, and warns if this file passes its 28 000-byte budget. Always add an entry under `CHANGELOG.md` **[Unreleased]**.
