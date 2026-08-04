# Agent Instructions — azapptoolkit

azapptoolkit is a **native Rust desktop app for managing Microsoft Entra ID app registrations** —
the replacement for ad-hoc PowerShell. Tauri 2 + Leptos 0.8 (WASM) workspace, edition 2024,
MSRV **1.97** (`rust-toolchain.toml`).

This file is an **invariant + pointer index**, not a manual: each gotcha is one rule plus a link
to the deep-dive. Keep it that way — deep detail belongs in `docs/architecture/`, and a size hook
warns past 28 000 bytes. **Read the linked doc before editing that subsystem.**

## Quick Reference

| Item | Detail |
|---|---|
| **Task runner** | `just` — recipes in `/justfile`; Tauri hooks call them too, so flags never drift. |
| **Setup / Dev** | `just setup` (OS-aware bootstrap) · `just dev` (`cargo tauri dev`) |
| **Verify** | `just verify` (fmt → clippy → test → web-fmt-check → web-clippy → web-test → web-build → web-itest *if a browser*). `just verify-full` adds the CI-only gates (audit/deny both trees). |
| **Workspace** | 9 crates (8 in `crates/` + `src-tauri`); frontend (`web-rs`) excluded, builds via Trunk. |

## Skills

| Skill | Trigger text | What it does |
|-------|-------------|--------------|
| **ship** | `"ship"`, `"land this"` | Commit → push → PR → wait on CI → merge → cleanup. |
| **feature** | `"feature X"` | Scaffold branch, backend command stub, frontend binding, verify. |
| **repo-review** | `"repo review"`, `"review this PR"` | Diff base → head, run verify gates, check commits & tenant-cache footguns. |
| **release** | `"release"`, `"bump version"` | Bump the 3 manifests, finalize CHANGELOG `[Unreleased]` → `[X.Y.Z]`, PR, tag, verify draft. |
| **debug** | `"debug X"` | Diagnose Tauri + Leptos WASM issues — backend, frontend, auth layers. |

Skills live in `.claude/skills/`; they activate on the trigger text above.

Key files/docs to read before editing:
- **Adding a command?** `src-tauri/src/lib.rs` (handlers) + `web-rs/src/bindings/`.
- **Auth / token / consent / re-auth?** [auth-and-consent.md](docs/architecture/auth-and-consent.md) → `state.rs` + `auth/src/token_cache.rs`.
- **Caches, list commands, search, batch fan-out?** [caching-and-search.md](docs/architecture/caching-and-search.md).
- **Audit scoring, findings, remediations, Exchange/SharePoint scoping?** [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).
- **Frontend: session state, open-items workspace, UI primitives, Security workbench layout?** [frontend-workspace.md](docs/architecture/frontend-workspace.md).
- **Release matrix, auto-update, Pages demo, crypto pins?** [release-updater-demo.md](docs/architecture/release-updater-demo.md).
- **DR backup/restore?** [backup-and-restore.md](docs/architecture/backup-and-restore.md) → `dto/src/backup.rs` + `commands/backup.rs`.
- **New dependency?** Check `Cargo.lock` for conflicts.
- **WASM code?** See `#[cfg(not(target_arch = "wasm32"))]` in `azapptoolkit-core`.

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
│   ├── state.rs                     # AppState: auth singleton, clients, cache, cancel flags
│   ├── commands/                    # #[tauri::command] handlers (+ applications/ sso/ subdirs)
│   ├── token_adapter.rs             # ScopedTokenAdapter (BearerProvider), per-scope tokens
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
    ├── build.rs                     # bakes this version's CHANGELOG section (in-app "What's new")
    └── Trunk.toml                   # WASM build/serve (127.0.0.1:5173)

docs/DEVELOPMENT.md                  # build, test, package, release, updater keys
docs/architecture/                   # the six deep-dives linked throughout this file
docs/CHANGELOG-archive.md            # releases <= 0.19.2 (split out of CHANGELOG.md)
.github/workflows/                   # ci.yml · release.yml (3-OS matrix) · codeql.yml · pages.yml
```

## Common patterns

- **New Tauri command** — 3 steps (advisory hook `command-parity-check.sh` warns if you miss one):
  1. Implement `#[tauri::command] async fn` under `src-tauri/src/commands/` (a domain file or the `applications/` / `sso/` subdir).
  2. Add to `tauri::generate_handler![]` in `src-tauri/src/lib.rs`.
  3. Create a typed stub in `web-rs/src/bindings/` (calls `invoke_result`).

- **Workspace dependency** — add to `[workspace.dependencies]`, use `"name".workspace = true`. Check `Cargo.lock` for conflicts.

- **Audit scoring rule** — implement in `azapptoolkit-core::audit` with a table-driven test citing the legacy PowerShell `file:line`. A rule that shifts ranking needs a CHANGELOG note — operators watch these scores.

- **Audit remediation (one-click "Fix")** — only for findings with a safe, existing mutation (additive like AddOwner or reversible like DisableSignIn also qualify); handler **re-resolves live state**. Scorer-attached via `build_remediations`, except `DisableSignIn` (runner post-pass) and `AddOwner` (no dedicated handler; the modal reuses `add_application_owner`). Full pattern: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

## Canonical commands

All build/dev/verify commands live in `/justfile`. `just` searches upward, so recipes resolve from any subdirectory. Tauri's hooks call the same recipes; update them when you change build flags.

```bash
just setup          # one-time (idempotent OS-aware bootstrap)
just dev            # daily loop (= cargo tauri dev)

# CI gates:
just verify          # core gates, then web-itest via `web-itest-auto`: runs it given Chrome +
                     # chromedriver, LOUD skip when absent (never a silent pass)
just verify-ui       # same gates, web-itest MANDATORY (fails without a browser)
just verify-full     # core gates + audit + web-audit + deny + web-deny + web-itest (CI parity)
just fmt-check | clippy | test | web-fmt-check | web-clippy | web-test | web-build  # individual gates

# Browser-gated (best-effort in `verify`, mandatory in verify-ui/-full):
just web-itest       # real Leptos views in a headless browser, Tauri IPC mocked
just web-itest-size  # per-shard wasm ceiling the sharding strategy depends on

# GitHub Pages demo build (deploy-only): release + `demo` feature + subpath base-href.
just web-build-pages [BASE]

# Dependency policy (required CI checks — run via verify-full). web-rs has its
# OWN lockfile, so the root scans never reach it:
just audit · just web-audit   # RustSec advisories
just deny  · just web-deny    # advisories + licenses + sources + bans (deny.toml)

# Release builds (per-host; release.yml's matrix runs the updater legs). The
# *-updater recipes need TAURI_SIGNING_PRIVATE_KEY; `build-windows` is keyless.
just build-{windows,macos,linux}-updater · just build-windows · just icon

just clean          # cargo clean BOTH build trees (root + excluded web-rs)
```

Running locally needs `AZAPPTOOLKIT_CLIENT_ID` + `AZAPPTOOLKIT_TENANT_ID`. For team builds, bake via `.env` (see `build.rs`).

## Conventions & gotchas

- **Tauri commands:** `#[tauri::command] async fn` → `State<'_, AppState>` → `Result<T, UiError>`. Must be in `generate_handler![]` AND have a typed stub calling `invoke_result()`. Frontend args use `#[serde(rename_all = "camelCase")]`.

- **Tenant-scoped caches — cross-tenant leakage is the #1 footgun.** Keys are `{tenant_id}|{kind}`, never unscoped; sign-out calls `invalidate_prefix` for **every** kind. The two tenant-wide indexes (SP + app-registration) are *typed* and pinned — read via `sp_index_*`/`app_name_index_*`/`indexes_cached` (plain `get` = silent miss + rescan). Never pin a per-object key; bound bulk seeding by `Cache::capacity_for`. Details: [caching-and-search.md](docs/architecture/caching-and-search.md).

- **Invalidate caches only on `Ok`.** After success, bust the relevant list cache; on failure, leave fresh data alone. SP/app-registration mutation → `invalidate_app_lists(...)` (list keys + transitively detail + mailbox-scopes + audit). **Credential-only** mutations → `invalidate_app_credentials(cache, tenant, object_id)` (keeps the indexes). Details: [caching-and-search.md](docs/architecture/caching-and-search.md).

- **`CacheKind::ServicePrincipal` self-invalidates in the graph client, not the command aggregators.** Keyed by `appId` but SP mutators take an SP *object* id, so `delete`/`patch_service_principal` + `set_service_principal_tags` sweep the tenant prefix on `Ok`; `invalidate_app_lists` does **not** touch this kind. Details: [caching-and-search.md](docs/architecture/caching-and-search.md).

- **camelCase vs snake_case.** Graph domain models (`Application`, `ServicePrincipal`) are camel (no serde rename); DTOs/bindings are snake_case. `Application` + `AuditItem` cross IPC **as-is** — renaming a field is a wire-format change.

- **WASM gating.** `web-rs` compiles to `wasm32-unknown-unknown`. Server deps (tokio, reqwest, rustls) must be gated `#[cfg(not(target_arch = "wasm32"))]` in shared crates, or excluded from `web-rs`. `web-rs` is outside the workspace, so it declares its own `[lints.rust] unsafe_code = "deny"` — keep it in sync with the root block.

- **Auth: lazy, shared token refresh.** Token refreshes lazily (~60s before expiry) behind a shared mutex. Refresh tokens in OS keyring (chunked across numbered entries — Windows Credential Manager cap 2560 UTF-16 bytes). Write scopes consented **incrementally**. Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Extra-scope tokens (on-demand).** Admin-consent/premium scopes ride a `ScopedTokenAdapter`, never the sign-in scope set. Every call must **degrade gracefully**. Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Silent grants can't *obtain* consent.** AADSTS65001/65004 → `AuthError::ConsentRequired` (≠ `InvalidGrant`); interactive consent via `EntraAuthService::consent_for_scopes`. Commands needing a "Grant consent" button must **pre-acquire** the token via `AppState::ensure_*` so `consent_required` survives `BearerProvider`. Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Re-auth-fatal codes have ONE definition: `UiError::is_reauth_fatal()`** (`azapptoolkit-dto`, shared by both tiers). Adding a code = editing that fn. Long-running loops must stop on it (`run_bulk_seq` does) — a dead session makes every remaining item fail identically.

- **Force re-auth in place when the session is dead — don't sign the user out.** A dead refresh token (`InvalidGrant`/`RefreshTokenMissing` → **`refresh_missing`**; `NotSignedIn` → **`not_signed_in`**) can't be re-minted silently; `reauthenticate` runs ONE interactive round trip and restores the session **without** dropping data caches. A new re-auth-fatal code must extend BOTH `matches!` sets (`state.rs` + `shell.rs`). Every long-running fan-out must stop on it — pinned by `src-tauri/tests/repo_invariants.rs`, which also diffs web-rs's `[lints.rust]` against the workspace one. Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Role/scope catalog.** Three auth planes (Entra, Azure RBAC, Exchange) share one capabilities catalog. Adding a privileged feature → add a catalog entry instead of hardcoding role strings. Access Readiness enumerates the user's **direct** Azure role assignments for the Azure-RBAC plane (`core::azure_roles`, conservative supersets — control-plane roles don't grant KV data-plane — and never a false "Missing" since group-inherited roles aren't visible). Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Audit signals — structured, not text.** Facets/cards/finding groups key off `AuditItem` fields (`risk_level`, `credential_status`, `unused`, …), not free-text.

- **Shared `audit_cancel` flag.** Security-audit and Bulk-actions both poll `AppState.audit_cancel`; new long-running commands must `reset()` at the top. Resource Access polls `sweep_cancel`; DR backup/restore uses `dr_cancel`. Tested in `state.rs`.

- **Batched Graph fan-out + adaptive throttle.** Heavy fan-outs (audit, DR backup) use Graph JSON batching (`client.batch_get_json[_with_headers]`, 20 GETs/POST) + the shared `ConcurrencyThrottle` via `ThrottleGuard::attach`. Reuse both; never hand-roll a tracker or a per-item loop. Whole-batch failures degrade to per-object reads. `$count`/`$orderby` belong to `$search` alone — `$expand` + advanced query fails *silently* (caps at 20, no `nextLink`). Details: [caching-and-search.md](docs/architecture/caching-and-search.md).

- **Every paged read sends `$top`.** Paging is serial, so Graph's default of 100 is a 10× round-trip multiplier — paged reads (and `$batch` sub-URLs) send `client::MAX_PAGE_SIZE`, `/applications` sends `DEFAULT_APP_PAGE_SIZE`. Over-asking is clamped silently. Details: [caching-and-search.md](docs/architecture/caching-and-search.md).

- **Scope-aware audit risk.** `score_application` reads `AppPermissions.mail_scopes` (empty map = org-wide, so an unresolved probe never under-reports). SharePoint scoping is name-based, no live call. Badges: `web-rs/components/scope_badge.rs`.

- **Mailbox permissions live on TWO resources — carry the resource, never the bare value.** Graph and legacy **Office 365 Exchange Online** both expose `Mail.Read`/`Mail.Send`/`Contacts.*`; only Graph's are RBAC-confinable, and EWS `full_access_as_app` (all mailboxes) is legacy-only. Permissions travel as `audit::ResourcePermission { resource_app_id, value }`; `AppPermissions::is_scoped` gates on the row's **own** resource; mailbox membership comes from `scoping::is_mailbox_reaching_permission` (a `Mail.*` name test cannot see `full_access_as_app`); targets resolve via `graph_roles::mailbox_resource_roles`, never `graph_role_index`. Unscopable legacy grants get their own finding and **no** scope fix; a `ScopeMailboxAccess` fix is gated on the POSITIVE `is_scopable_exchange_resource_permission`, never the legacy test's negation. Target derivation is pure, in `azapptoolkit-exchange::targets`, incl. the shared fail-closed `require_scopable_targets`. Value-keyed shortcuts here have silently widened access. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **AAP migration is guarded, not mechanical.** `RestrictAccess` only (a `DenyAccess` blocklist inverts), one batch per **app**, and policies are deleted only once every grant they confined is re-scoped **and** both mailbox resources actually resolved — `mailbox_resource_roles` resolves Exchange Online best-effort, so an unverifiable empty target set must fail closed rather than read as "governs nothing". Roles assigned inside `assign_scoped_roles`' loop count as in place (several values map to one Exchange role). Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Scoped grants reuse shared cores.** Exchange + SharePoint grant scoped access *before* stripping org-wide, so a failure never strands the principal. The Exchange scope and its backing mail-group use two distinct per-tenant patterns (`scope_name_for`/`group_name_for`) covering **every** scoping path, resolved via `load_tenant_defaults`. Membership changes **don't** invalidate caches. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Unified "Grant access" wizard.** One button per principal (`ScopeWizard`): select permissions (full-catalog cart) → choose access → grant. `mechanism` is `Some(kind)` only when the cart is non-empty *and* every item is an Application permission of the **same** `ScopeKind` (delegated/mixed/non-scopable ⇒ org-wide). Add a mechanism = a `ScopeKind` variant + a target panel + an apply arm; nothing else branches on it. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Frontend reactivity is closure-based.** `{move || sig.get()}` for tracking; `.get()`/`.with()` to read. State is `RwSignal<T>` on a context-provided `Session`. CSS: plain global `styles.css` with BEM-ish names. Global keys live in `hooks::use_shortcuts`; a **bare-key** binding MUST no-op in a text field or it eats typing. Details: [frontend-workspace.md](docs/architecture/frontend-workspace.md).

- **One primitive per UI pattern (design-consistency invariant).** Page header = `components::ui::SectionHeader`; loading = skeletons (`SkeletonList`/`DetailSkeleton`), spinners only in-button/inline; load failure = `DetailLoadError`; notices/alerts = `components::ui::Callout`. Reuse the primitive; don't re-implement the markup. Details: [frontend-workspace.md](docs/architecture/frontend-workspace.md).

- **Open-items workspace = full-width lists + ONE shared cross-entity working set.** `session.open_item(kind, entity_id, title)` fills `Session.open_items`; there is no side detail pane, and the dock + workspace mount **once in `shell.rs`**. **Footgun:** `open_items` + `shown_items` MUST reset in `set_active_tenant`, or a stale item leaks the prior tenant's data. No `selected_*_id` signals — search, pairing and deep-links all route through `open_item`. Details: [frontend-workspace.md](docs/architecture/frontend-workspace.md).

- **Per-list filter state lives on `Session.tenant_ui` (`TenantScopedUi`) and resets on tenant switch by structure.** Searches, drill-target facets, both bulk selections and shell dialog flags live there so outside surfaces can seed them. A new tenant-scoped signal goes INTO the substruct with a `reset()` line + an assertion in the `tenant_switch_resets_every_tenant_scoped_field` pinning test — never a bare `Session` field with a hand-added reset. Details: [frontend-workspace.md](docs/architecture/frontend-workspace.md).

- **Security tab = findings-first workbench: one controller, read-only posture strip.** Filtering has exactly two homes — the Findings accordion + the All-apps `audit_severity` control; the strip is counts-only. `BulkActionBar` is the single home of bulk command-calling; **no Grant consent on audit surfaces**. **Load-bearing asymmetry:** `scoped_mailbox` matches `.contains(SCOPED_VIA_RBAC)` while siblings use `.starts_with` (pinned by `filter.rs` tests — a "normalize to starts_with" sweep empties it). Layout: [frontend-workspace.md](docs/architecture/frontend-workspace.md); semantics: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **The audit also scores SP-only principals (no local app registration) — and those rows are NOT bulk targets.** Phase 2 of `run_audit` scores foreign enterprise apps / MIs / orphaned SPs from their **granted** roles (both mailbox resources). `AuditItem.principal_kind` (`#[serde(default)]`) drives routing; SP rows' Fixes call the SP-only cores, **never** `remediate_scope_*` (they `get_application` first → 404). **SP rows render no checkbox and are excluded from select-all.** Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Bulk remediations reuse the single-app cores, sequentially** via `run_bulk_seq` — **not** `dispatch_capped` (those cores take `State`, not `Send`). They `reset()` + poll `audit_cancel`, degrade to a per-app structured `BulkError`, and stop on a re-auth-fatal code. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Build-time config baking.** `build.rs` reads `.env` → `AZAPPTOOLKIT_BUILD_*`; env vars override.

- **Per-tenant operator defaults live in `settings.json` too.** `UserSettings.tenant_defaults` holds default owners, SSO emails, the Exchange scope/group name patterns, and vault bindings; types in `azapptoolkit-core::defaults` (ungated — the frontend uses them as the IPC payload; `settings` persistence stays native-only). **Two writers** (`commands::config` + `commands::defaults`), both read-modify-write via `UserSettings::stored`. `apply_tenant_defaults` writes only operator-editable fields and **preserves `default_vault`/`app_vaults`** (owned by the rotation flow); it destructures `TenantDefaults` exhaustively, so a new field won't compile until it's decided there.

- **GitHub Pages demo = the WASM frontend with the Tauri backend mocked.** `just web-build-pages` builds `web-rs` with the `demo` feature (off in `web-build`/desktop, so the mock never ships); `pages.yml` deploys it. **Footgun:** any infallible `invoke()` must be in `demo::register_fixtures` or it **panics the whole page** — enforced by `web-rs/tests/demo_fixture_coverage.rs`. Details: [release-updater-demo.md](docs/architecture/release-updater-demo.md).

- **Auto-update is interactive (not silent).** The front-end checks once on launch and toasts a notification whose action opens `UpdateSplash` (explicit **Update & restart**). **Don't reintroduce a silent background `download_and_install` in `lib.rs` setup** — it would race the prompt. Details: [release-updater-demo.md](docs/architecture/release-updater-demo.md).

- **Release is a 3-OS matrix → one aggregated `latest.json`.** `release.yml`: `guard` → `build` matrix (windows · macos aarch64 · linux) → `release` assembles one draft; a human publishes. CHANGELOG headers are `## [X.Y.Z] - YYYY-MM-DD` (**no `v` prefix, ASCII hyphen**) — **two** parsers depend on it: `release.yml`'s notes extraction and `web-rs/build.rs`, which bakes the running version's section in for the in-app "What's new". Both read only `CHANGELOG.md` and only that version's section, so releases ≤ 0.19.2 sit in `docs/CHANGELOG-archive.md`. Flow: the `release` skill; matrix: [release-updater-demo.md](docs/architecture/release-updater-demo.md).

- **CSP governs the *webview*, not backend egress.** `connect-src` in `tauri.conf.json` restricts only WASM frontend fetches; backend reqwest calls to new hosts need no CSP change.

- **Permissions catalog** is bundled at compile time from `azapptoolkit-permissions/data/`; unknown resources fall back to `resolve_resource_sp()`.


- **Full-collection PATCH for `appRoles` / `oauth2PermissionScopes`.** Graph **full-replaces** these not-nullable arrays — re-read live state, mutate, write the whole array back (never merge a cached payload). Deleting an enabled entry needs two PATCHes: disable, then remove (`commands/expose_api.rs`, `commands/app_roles.rs`). Exposed **app roles** edit the **paired application** when one exists (else the SP) and round-trip as **raw JSON** so the `value: null` SAML default (`msiam_access`) survives byte-for-byte. Bust with `invalidate_app_details` only.

- **Crypto/encoding deps — no `rsa`; `rand`/`sha2`/`base64` majors pinned on purpose.** `cert.rs` uses `rcgen` on the `aws_lc_rs` backend specifically to keep `rsa` (RUSTSEC-2023-0071) out of the graph — **don't reintroduce it**. `rand = "0.8"` / `sha2 = "0.10"` / `base64 = "0.22"` match what `oauth2` 5 + Tauri 2 + the reqwest stack resolve; bumping a direct pin that nothing else follows only *adds* a duplicate major. Rationale + drop conditions live in `dependabot.yml`'s `ignore` blocks. Evidence: [release-updater-demo.md](docs/architecture/release-updater-demo.md).

## Coding fundamentals

- **Security-critical app:** never write secrets to disk or logs; scope tokens per resource. New dependency → check `Cargo.lock` for conflicts (deps are a cost — prefer std + existing workspace crates).

## Git & version control

- **Conventional Commits required:** `<type>[(scope)][!]: <description>`. The `conventional-commit-validator.sh` hook enforces this (types **and** the scope allowlist below).
  - Types: `feat fix docs chore refactor test build ci perf style revert deps`
  - Scopes (the canonical nine — this list is the single source; the hook mirrors it): `desktop`, `core`, `auth`, `graph`, `exchange`, `keyvault`, `permissions`, `ci`, `docs`. Omit the scope rather than invent one.
- Branch naming: `<type>/<short-slug>` (e.g. `feat/batch-approve`).
- Porting from legacy PowerShell → reference source `file:line` in the commit body.

## Verification playbook

Run the same gates CI runs before declaring a change done. `just verify` is the machine-independent core; `just verify-full` adds full CI parity. Use recipe flags from `/justfile`, don't hand-type raw `cargo` invocations.

Steps 1–4 are `just verify` (see **Canonical commands**); it also attempts web-itest. The CI-only additions below:

5. **Frontend GUI tests** *(browser-gated)* — `just web-itest`: real Leptos views in a headless browser, Tauri IPC mocked. Tests are `tests/gui/<view>.rs` **modules** grouped into shard binaries (`tests/gui_N.rs`) via `#[path] mod`; harness in `web-rs/src/test_support/`. Shards exist because one merged binary exceeds what headless Chrome will instantiate; `just web-itest-size` enforces the per-shard ceiling (CI runs it) and says how to split. Group modules by the **view subtree they mount**, not by count — the linker keeps only referenced views. `[profile.test] strip = "debuginfo"` + `opt-level = 1` are what make that ceiling reachable; never `strip = true` (kills the `name` section → anonymous panic traces). **Do NOT make `test_support::reset()` clear `document.body`** — the runner scrapes results from the page DOM, so wiping it makes the shard report nothing. Renaming a CSS class / aria-label / on-screen text a test references fails CI — `web-test-strings-check.sh` warns at edit time; `verify` catches it locally given a browser, `verify-ui` always.
6. **Dependency audit + deny** *(required CI checks)* — `audit`/`web-audit` (RustSec) + `deny`/`web-deny`; all four merge-blocking, all in `verify-full`.
7. **actionlint** *(required CI check)* — lints the workflow YAML; runs CI-side (install locally to pre-check).
8. **CodeQL** *(GitHub-side)* — security queries, build-mode `none`. Known limitation: CodeQL 2.25.6 doesn't expand macros here (~39% calls-with-call-target); expected, non-failing. Config: `.github/codeql/codeql-config.yml`.

For behavior changes not provable by unit test, run `just dev` and exercise the view.

## Keeping this file up to date

When editing these files, update the matching section here:
crate/dir changes → **Repo map**; workspace/toolchain/MSRV → **Quick Reference**;
`justfile` recipes / build commands → **Canonical commands, Verification playbook**;
new command/IPC/cache/CSP/cancel flag → **Conventions & gotchas** (one invariant + a doc pointer — deep detail goes in `docs/architecture/`);
CI gate or `tauri.conf.json` bundle/updater → **Verification playbook**.

The `staleness-check.sh` hook reminds you when a structural edit likely needs an AGENTS.md or doc update, and warns if this file passes its 28 000-byte budget. Always add an entry under `CHANGELOG.md` **[Unreleased]**.
