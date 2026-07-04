# Agent Instructions — azapptoolkit

azapptoolkit is a **native Rust desktop app for managing Microsoft Entra ID app registrations** —
the replacement for ad-hoc PowerShell. Tauri 2 + Leptos 0.8 (WASM) workspace, edition 2024,
MSRV **1.96** (`rust-toolchain.toml`).

Deep subsystem detail lives in `docs/architecture/` — this file keeps the invariant + a pointer.
**Read the linked doc before editing that subsystem.**

## Quick Reference

| Item | Detail |
|---|---|
| **Task runner** | `just` — recipes in `/justfile`; Tauri hooks call them too, so flags never drift. |
| **Setup / Dev** | `just setup` (OS-aware bootstrap) · `just dev` (`cargo tauri dev`) |
| **Verify** | `just verify` (fmt → clippy → test → web-fmt-check → web-clippy → web-test → web-build) |
| **Workspace** | 9 crates (8 in `crates/` + `src-tauri`); frontend (`web-rs`) excluded, builds via Trunk. |

## Skills

| Skill | Trigger text | What it does |
|-------|-------------|--------------|
| **ship** | `"ship"`, `"land this"` | Commit → push → PR → merge → cleanup (already present). |
| **feature** | `"feature X"`, `"add feature X"` | Scaffold a new branch, backend command stub, frontend binding, and verify. |
| **review** | `"review"`, `"approve this PR"` | Diff base → head, run verify gates, check conventional-commits & tenant-cache footguns. |
| **release** | `"release"`, `"bump version"` | Bump version, finalize CHANGELOG.md `[Unreleased]` → `[vX.Y.Z]`, tag and push. |
| **debug** | `"debug X"` | Diagnose Tauri + Leptos WASM issues — walks backend, frontend, auth layers. |

Skills live in `.claude/skills/`. Load a skill with `skill: <name>`.

Key files/docs to read before editing:
- **Adding a command?** `src-tauri/src/lib.rs` (handler list) + `web-rs/src/bindings/`.
- **Auth / token / consent?** [docs/architecture/auth-and-consent.md](docs/architecture/auth-and-consent.md) → `src-tauri/src/state.rs` + `crates/azapptoolkit-auth/src/token_cache.rs`.
- **Caches, list commands, search?** [docs/architecture/caching-and-search.md](docs/architecture/caching-and-search.md).
- **Audit scoring, remediations, Exchange/SharePoint?** [docs/architecture/scoping-and-audit.md](docs/architecture/scoping-and-audit.md).
- **DR backup/restore?** [docs/architecture/backup-and-restore.md](docs/architecture/backup-and-restore.md) → `crates/azapptoolkit-dto/src/backup.rs` + `src-tauri/src/commands/backup.rs`.
- **Debugging?** Use the `debug` skill — walks Rust backend, WASM frontend, and auth layers.
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
│   ├── commands/                    # #[tauri::command] handlers (one file per domain)
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
docs/architecture/                   # deep-dives: auth-consent, caching-search, scoping-audit
.github/workflows/                   # ci.yml · release.yml (Win MSI+NSIS · macOS dmg · Linux AppImage+deb, matrix) · codeql.yml · pages.yml (GitHub Pages demo)
```

## Common patterns

- **New Tauri command** — 3 steps (advisory hook `command-parity-check.sh` warns if you miss one):
  1. Implement `#[tauri::command] async fn` under `src-tauri/src/commands/`.
  2. Add to `tauri::generate_handler![]` in `src-tauri/src/lib.rs`.
  3. Create a typed stub in `web-rs/src/bindings/` (calls `invoke_result`).

- **Workspace dependency** — add to `[workspace.dependencies]`, reference via `"name".workspace = true`. Check `Cargo.lock` for conflicts.

- **Audit scoring rule** — implement in `azapptoolkit-core::audit` with a table-driven test citing legacy PowerShell `file:line`.

- **Audit remediation (one-click "Fix")** — only for findings with a safe, existing mutation (additive like AddOwner or reversible like DisableSignIn also qualify); handler **re-resolves live state**. Scorer-attached via `build_remediations`, except `DisableSignIn` (runner post-pass — `unused` is set there) and `AddOwner` (no dedicated handler; the modal reuses `add_application_owner`). Full pattern: [docs/architecture/scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **New external origin (CSP)** — only direct WASM frontend fetches need a `connect-src` change; backend reqwest calls don't.

## Canonical commands

All build/dev/verify commands live in `/justfile`. `just` searches upward, so recipes resolve from any subdirectory. Tauri's hooks call the same recipes; update them when you change build flags.

```bash
just setup          # one-time (idempotent OS-aware bootstrap)
just dev            # daily loop (= cargo tauri dev)

# CI gates:
just verify          # fmt-check → clippy → test → web-fmt-check → web-clippy → web-test → web-build
just fmt-check | clippy | test | web-fmt-check | web-clippy | web-test | web-build  # individual gates

# Frontend GUI tests (browser-gated, NOT in `verify`):
just web-itest       # real Leptos views in a headless browser, Tauri IPC mocked
                     # (no tenant/backend). Needs a browser + driver; CI uses Chrome.

# GitHub Pages demo build (deploy-only, NOT in `verify`):
just web-build-pages [BASE]   # release + `demo` feature (mock IPC + sample data,
                              # no backend) + subpath base-href; published by pages.yml.

# Dependency policy (CI also runs these):
just audit          # RustSec advisories (root workspace)
just web-audit      # RustSec (web-rs lockfile, separate from root)
just deny           # license + crate-source + bans (deny.toml)
just web-deny       # same policy, web-rs tree

# Release builds (per-host; the release.yml matrix runs all three) + icons:
just build-windows           # Windows MSI + NSIS installers
just build-macos-updater     # macOS .dmg + .app updater payload (Apple Silicon)
just build-linux-updater     # Linux .AppImage + .deb
just icon                    # regenerate from icons/icon.svg

# Housekeeping:
just clean          # cargo clean BOTH build trees (root + excluded web-rs) to reclaim disk
```

Running locally needs `AZAPPTOOLKIT_CLIENT_ID` + `AZAPPTOOLKIT_TENANT_ID`. For team builds, bake via `.env` (see `build.rs`).

## Conventions & gotchas

- **Tauri commands:** `#[tauri::command] async fn` → `State<'_, AppState>` → `Result<T, UiError>`. Must be in `generate_handler![]` AND have a typed stub calling `invoke_result()`. Frontend args use `#[serde(rename_all = "camelCase")]`.

- **Tenant-scoped caches — cross-tenant leakage is the #1 footgun.** Cache keys are `{tenant_id}|{kind}`; never unscoped. On sign-out, `invalidate_prefix(kind, "{tenant_id}|")` for **every** kind. Details: [caching-and-search.md](docs/architecture/caching-and-search.md).

- **Invalidate caches only on `Ok`.** After success, bust the relevant list cache. On failure, leave fresh data alone. Mutation of SP/app registration → `invalidate_app_lists(...)` (drops apps-pairing, enterprise, indexes, transitively detail + mailbox-scopes + audit run). **Credential-only** mutations → `invalidate_app_credentials(cache, tenant, object_id)` (faster: keeps indexes).

- **`CacheKind::ServicePrincipal` (per-app SP, keyed by `appId`) self-invalidates in the graph client, not via the command aggregators.** It's keyed by `appId` but the SP mutators take an SP *object* id, so `delete_service_principal` / `patch_service_principal` / `set_service_principal_tags` call a private tenant-prefix sweep (`invalidate_sp_cache`) on `Ok` — the can't-miss option (a targeted single-key bust isn't possible). `set_service_principal_app_roles` rides this via `patch_service_principal`. `invalidate_app_lists` does **not** touch this kind, so don't rely on it for SP-field freshness. `ensure_service_principal` returns `(ServicePrincipal, bool)` where the bool is **created**; first-grant paths (`grant_single_permission`, `grant_admin_consent[_core]`, bulk grant) call `invalidate_app_lists` only when an SP was newly created (else the cheaper detail+audit bust).

- **camelCase vs snake_case.** Graph domain models (`Application`, `ServicePrincipal`) are camel (no serde rename). DTOs/bindings are snake_case. A few core types (`Application`, `AuditItem`) cross IPC **as-is** — renaming is a wire-format change.

- **WASM gating.** `web-rs` compiles to `wasm32-unknown-unknown`. Server deps (tokio, reqwest, rustls) must be gated `#[cfg(not(target_arch = "wasm32"))]` in shared crates, or excluded from `web-rs`.

- **Auth: lazy, shared token refresh.** Token refreshes lazily (~60s before expiry) behind a shared mutex. Refresh tokens in OS keyring (chunked across numbered entries — Windows Credential Manager cap 2560 UTF-16 bytes). Write scopes consented **incrementally**. Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Extra-scope tokens (on-demand).** Admin-consent/premium scopes ride a `ScopedTokenAdapter` — never in the sign-in scope set. Every call must **degrade gracefully**. Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Silent grants can't *obtain* consent.** AADSTS65001/65004 → `AuthError::ConsentRequired` (distinct from `InvalidGrant`). Interactive consent via `EntraAuthService::consent_for_scopes`. Commands that need a "Grant consent" button must **pre-acquire** the token via `AppState::ensure_*` so `consent_required` survives `BearerProvider`.

- **Force re-auth in place when the session is dead — don't make the user sign out.** A dead refresh token (`InvalidGrant`/`RefreshTokenMissing`, both → `UiError` code **`refresh_missing`**; `NotSignedIn` → **`not_signed_in`**) can't be re-minted silently. `reauthenticate` command → `EntraAuthService::reauthenticate(&TenantContext)` runs ONE interactive browser round trip (`prompt=login`, `login_hint` = current account) and validates the returned `tid`+`oid` match (cache-safety, mirrors `consent_for_scopes`; a different account errors) — restoring the session **without** dropping the tenant's data caches (sign-out would). Takes the full `TenantContext` (not a bare id) because `InvalidGrant` purges `known_tenants`; the front-end still holds it in `active_tenant`. Front-end: the nav **Refresh Token** button (`shell.rs`) tries silent `refresh_session` first, then falls back to `reauthenticate` on those two codes; and `Session::report_command_error(&UiError)` (the central error sink — `use_command::run_toast_err` routes through it) shows a **Re-authenticate** toast action keyed on the same two codes, else a plain error toast. Add a new re-auth-fatal code → extend BOTH `matches!` sets (`state.rs` + `shell.rs`).

- **Role/scope catalog.** Three auth planes (Entra, Azure RBAC, Exchange) share one capabilities catalog. Adding a privileged feature → add a catalog entry instead of hardcoding role strings. Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Audit signals — structured, not text.** Facets/cards key off `AuditItem` fields (`risk_level`, `credential_status`), not `starts_with(...)` on free-text.

- **Shared `audit_cancel` flag.** Security-audit and Bulk-actions both poll `AppState.audit_cancel`. New long-running commands must `reset()` at the top. Resource Access lookups poll `AppState.sweep_cancel` (independent). DR backup/restore uses `AppState.dr_cancel`. Tested in `state.rs`.

- **Batched Graph fan-out + adaptive throttle.** Large per-object fan-outs (security audit, DR backup) use Graph JSON batching — `client.batch_get_json[_with_headers]` (`graph/src/client/batch.rs`, 20 GETs/POST, results in input order, inner-429 re-batch) — plus a shared `ConcurrencyThrottle` (`commands/throttle.rs`) wired as the client's `ThrottleObserver` and fed to `dispatch_capped` as `|| throttle.current_limit()` so the in-flight cap halves on 429 and recovers when quiet. Reuse these for any new heavy fan-out; don't hand-roll a second tracker or a raw per-item loop. Advanced queries in a batch (e.g. `memberOf` `$count`) need the **per-sub-request** header form — the outer POST's headers don't reach sub-requests. Whole-batch failures must degrade to per-object reads, never fail the run. Attach/detach the observer with the shared `ThrottleGuard::attach(client, tracker)` RAII (`commands/throttle.rs`) so an early `?` can't leave a stale observer halving the shared per-tenant client's cap (used by the audit and the bulk fan-outs). Backup and the bulk write flows (delete / grant / remove-expired) emit the live cap in `BulkProgress.in_flight_cap` (additive `Option`; the DR view shows it + a back-off notice). The write fan-outs can't `$batch` (Graph batches GETs), so the win there is bounded concurrency + adaptive 429 backoff, not round-trip collapse.

- **Scope-aware audit risk.** Mail permission risk depends on Exchange RBAC scoping: `score_application` reads `AppPermissions.mail_scopes`; empty map = org-wide. SharePoint scoping is name-based, no live call needed. Badges render in `web-rs/components/scope_badge.rs`. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Scoped grants reuse shared cores.** Exchange + SharePoint both grant scoped access *before* stripping org-wide, so a failure never strands the principal. Exchange scope source: `azapptoolkit_<app_id>` mail-enabled security group (`group_name_for`); membership changes **don't** invalidate caches. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Unified "Grant access" wizard + scope registry + per-mechanism strategy.** Scoping is a family of *independent* authorities, unified behind one classifier — `core::scoping::scope_kind(value) -> Option<ScopeKind>` (Exchange / SharePoint; `admin_applicable()` is the seam for future not-admin-scopable mechanisms like Teams RSC). The `ScopeWizard` (`web-rs/components/scope_wizard.rs`) is the **single "Grant access" button** on every principal's Permissions surface — it **subsumes the old "Add permission" picker** (there is no separate inline single-grant picker). Uniform shell — **select permissions → choose access → review & grant**. **Step 1 is the full live catalog** (the reusable multi-select `PermissionPicker`, every resource + Application/Delegated, **`ApplicationOnly` for a bare SP** since its org-wide grant is app-role-only) as a cart; the wizard owns `selected: Vec<PickerSelection>` and the picker emits toggles. **`mechanism`** is `Some(kind)` only when the cart is non-empty *and* every item is an Application permission mapping to the **same** `ScopeKind` (delegated/mixed/non-scopable ⇒ `None` ⇒ org-wide only). **Step 2 dispatches the target panel + apply by `ScopeKind`**: **Exchange RBAC** is declare-only (it `declare_app_permission`s each permission using the cart's id — manifest only, **no** runtime grant — then assigns the scoped role, since RBAC for Applications authorizes independently of the Entra grant; reach = union, so leaving the Entra grant defeats scoping), **SharePoint** swaps to `Sites.Selected` via `convert_site_access_to_selected`. One mechanism per run; a held row's "Scope…" opens it pre-seeded with the full `PickerSelection`. Org-wide falls back to `grant_single_permission` per item (app reg) / `grant_managed_identity_permission` grouped by resource (bare SP). Targets are managed via shared `ManagedScopeGroupPanel` (mailboxes) / `SiteSelectionPanel` (sites). Add a mechanism = a `ScopeKind` variant + a target panel + an apply arm; nothing else branches on the concrete mechanism.

- **Frontend reactivity is closure-based.** `{move || sig.get()}` for tracking; `.get()`/`.with()` to read. State is `RwSignal<T>` on a context-provided `Session`. CSS: plain global `styles.css` with BEM-ish names.

- **One primitive per UI pattern (design-consistency invariant).** Page header = `components::ui::SectionHeader` (uppercase category crumb + title) app-wide — there is no `.view-header`; the two list views own their `SectionHeader` above a titleless `ListScaffold` (which no longer takes `title`/`actions` — the card starts at its search box). Loading = skeletons for content regions (`SkeletonList`/`DetailSkeleton`), spinners **only** for in-button/inline busy. Load failure = `DetailLoadError` (the universal "message + Retry" block: detail panes, all three list views, dashboard cards — pass `on_retry: Callback<()>` + a context `class`). Notices/alerts = `components::ui::Callout` (`info`/`ok`/`warn`/`danger`, reuses the `.alert` classes) — migrate `<div class="alert alert--…">` sites onto it.

- **Open-items workspace = full-width lists + ONE shared cross-entity "working set".** The three list views (App Reg / Enterprise / Managed Identities) render full-width; opening a row no longer renders a side detail pane — instead it `session.open_item(kind, entity_id, title)`s into the shared working set. `Session.open_items: RwSignal<Vec<OpenItem>>` (+ `open_seq` monotonic id source, + `shown_items: Vec<u64>` = the 1–2 displayed) is modeled on the toast stack (`Vec` + seq + cap `MAX_OPEN_ITEMS=8` + drain-oldest); helpers `open_item` (dedupes by `(kind, entity_id)`, re-focuses), `focus_item(id, split)` (split caps `shown` at 2, drop-oldest), `close_item`/`close_item_by_entity`, `set_open_item_title`, `is_open`. **Same cross-tenant footgun as the lifted searches/facets: `open_items` + `shown_items` MUST reset in `set_active_tenant`** (a stale open item leaks the prior tenant's data). The `OpenItemsDock` (chip strip) + `OpenItemsWorkspace` (overlay, 1-up or `--two` side-by-side) are mounted **once in `shell.rs`** so the set is shared, cross-entity, and survives nav — **not** per-view (keep-alive would duplicate them). The workspace mounts ALL open windows (keyed `<For>` over `open_items`) and toggles `display` by `shown` (keep-alive across chip switches); collapse is `style:display:none`, not unmount. App-reg + enterprise detail panes are self-contained and reused directly; the **MI detail is split** into `ManagedIdentityDetailWindow` (owns the resources/signals/ConfirmDialog, keyed off one `mi_id`) feeding the pure-presenter `ManagedIdentityDetailPane`. Each pane takes an optional `on_title` callback so opens that lacked a real name (pairing jumps, `open_*_on_tab` deep-links — they pass the id as a placeholder) self-correct the chip label once the detail loads. Row "open" highlight reuses `app-list__row--selected` (so `pairing.rs` scroll-settle still matches) but keys off `is_open`, not a single selection. The old `selected_app_object_id`/`selected_enterprise_app_id`/`selected_managed_identity_id` signals are **gone** — global search, pairing, and deep-links all route through `open_item`/`close_item_by_entity`.

- **Per-list filter state the Home dashboard drills into lives on `Session.tenant_ui` (`TenantScopedUi`) — and resets on tenant switch structurally.** Searches (`apps_search`/`enterprise_search`/`mi_search`) and the facet of each *drill target* (`enterprise_facet`, `mi_facet`, `credentials_facet`, the audit's `audit_severity`, and the Findings pane's `audit_expanded_group`) are `RwSignal`s on the `TenantScopedUi` substruct so an outside surface can seed them: Global Search seeds the search; the Home dashboard's clickable metrics seed the facet via `open_enterprise_with_facet` / `open_managed_identities_with_facet` / `open_posture_with_facet` / `open_credentials_with_facet` before navigating. `open_posture_with_facet` routes severity keys (`critical|high|medium|low`) to the All-apps pane's `audit_severity` and every finding key to `audit_expanded_group` + the Findings pane. The view binds its chip signal *to* the session field (`let ent_filter = session.tenant_ui.enterprise_facet;`). This is the front-end mirror of the backend cross-tenant-leakage footgun, and the reset is now **by structure, not vigilance**: `set_active_tenant` calls `TenantScopedUi::reset()`, whose body sits directly under the field declarations — a new tenant-scoped signal goes INTO `TenantScopedUi` with a `reset()` line (and an assertion in the `tenant_switch_resets_every_tenant_scoped_field` pinning test), never as a bare `Session` field with a hand-added reset. Also in the substruct: both bulk selections, the pending deep-link tabs, and the shell dialog flags (`cache_open`/`create_open`/`sso_wizard_open`). The **App Registrations credential facet stays local** (no metric drills into it). Drilling into the Enterprise list also trips a one-shot `pending_open_filters` so the list expands its collapsed filter drawer to reveal the active chip.

- **Security tab = findings-first workbench: one controller, one strip, four panes.** `SecurityView` constructs ONE `audit_view::AuditController` (run/cancel/export/progress/consent + the cached-run hydration with its tenant-race guard) and provides it via context; the posture strip renders **read-only** severity counts (never filter controls — the old severity-TabBar + finding-chip-drawer + clickable-scorecard triple-control is retired, as is `SavedViews view_key="audit"`). Sub-tabs (`security_tab`: `"findings" | "apps" | "credentials" | "grants"`, keep-alive): **Findings** (default) renders `groups::group_findings` — the `GROUP_CATALOG` keyed by the same finding keys `filter::matches_finding` understands (classification delegates to it, so the marker predicates live once), Actionable groups ranked by impact (Σ `risk_score`), Healthy positives (`scoped_mailbox`/`scoped_sites`) demoted to a collapsed disclosure; accordion expansion = `Session.tenant_ui.audit_expanded_group`. **All apps** keeps the ranked table with ONE severity control (`audit_severity`) + search (`filter_indices(items, severity, "all", query)`). The `expired` finding matches **only** `CredentialStatus::Expired` (expiring-soon lives in the Credential-expiry lens). **`scoped_mailbox` uses `.contains(SCOPED_VIA_RBAC)` while every sibling finding uses `.starts_with`** — a load-bearing asymmetry (the marker is mid-issue), pinned by the `filter.rs` tests; a "normalize to starts_with" sweep silently empties that finding. Shared counts live in `audit_view/posture.rs::posture_counts` — the Home posture card consumes the same function, so the numbers can't disagree. One shared multi-select `tenant_ui.selected_audit_ids` (distinct from `tenant_ui.selected_app_ids`; both live in `TenantScopedUi`, so the tenant-switch reset is structural), cleared on group-expansion change and on findings↔apps tab switch. **`components/bulk_action_bar.rs::BulkActionBar` is the single home of the selection-driven bulk command-calling logic** — mounted per expanded Findings group with `groups::group_bulk_actions(key)` (each fix paired with the rule it actually fixes: Expired→RemoveExpired, Org-wide mailbox/SharePoint→Scope, Redundant→RemoveRedundant, Ownership→AddOwner, Unused→DisableSignIn+Delete; advisory groups get none — the old Over-privileged→RemoveRedundant cross-rule mapping is retired), on the All-apps pane (`[RemoveExpired, Delete]`), the App Registrations list, and the Bulk Actions page; **no Grant consent on audit surfaces**. "Fix all N" just seeds `selected_audit_ids` with the group's *eligible* (Application-kind) ids — the bar's typed-confirm / target forms still gate execution.

- **The audit also scores SP-only principals (no local app registration) — and those rows are NOT bulk targets.** Phase 2 of `run_audit` scores foreign-tenant enterprise apps / MIs / orphaned SPs from their **granted** Graph app roles (`score_service_principal`; candidates = no paired application + ≥1 Graph application grant — the noise filter). One additive wire field `AuditItem.principal_kind` (`#[serde(default)]`, old cached runs read as `Application`) drives everything frontend: the `no_local_app` finding group, Open routing (enterprise/MI detail), and `ScopeFixTarget` — SP rows' mailbox/SharePoint Fixes call the SP-only cores (`grant_managed_identity_scoped_exchange_access` / `convert_site_access_to_selected`), NEVER the `remediate_scope_*` wrappers (they `get_application` first → 404). **SP rows render no checkbox and are excluded from select-all** — feeding an SP object id into the app-reg bulk cores is the failure mode to guard. `grant_managed_identity_permission` busts the audit cache on grant (its old "audit scans only app registrations" no-bust rationale is dead). Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Bulk remediations reuse the single-app cores, run sequentially.** `bulk_remove_redundant_permissions` / `bulk_scope_mailbox_access` / `bulk_scope_sharepoint_access` (`commands/bulk.rs`) loop the per-app remediation paths (`remediation::remediate_remove_redundant_permissions`, `exchange::grant_exchange_mailbox_access` with `permissions: None` = all, `remediation::remediate_scope_sharepoint_access`) — **not** the `dispatch_capped` spawn fan-out, because those cores take `State` (not `Send` into a spawn) and the selection is a small admin-chosen set. They `reset()` + poll `audit_cancel`, emit `bulk-progress` (no `in_flight_cap`), and degrade to a per-app `error` rather than aborting; each per-app core busts its own cache. The scope targets (mailbox groups / site URLs + role) are **uniform across the selection**.

- **Build-time config baking.** `build.rs` reads `.env`, emits `AZAPPTOOLKIT_BUILD_*`; runtime env vars override.

- **GitHub Pages demo = the WASM frontend with the Tauri backend mocked.** `just web-build-pages` builds `web-rs` with the `demo` feature, deployed by `.github/workflows/pages.yml` (needs Settings → Pages → Source = "GitHub Actions"). It installs the shared `ipc_mock` bridge — the same `window.__TAURI_INTERNALS__` mock the GUI test harness uses, **extracted out of `test_support` into `web-rs/src/ipc_mock/`** (gated by the internal `mock-ipc` feature that both `test-support` and `demo` enable) — pre-loaded with curated fixtures (`demo/mod.rs`), seeds a demo tenant so the config/sign-in gates fall through to the shell (`lib.rs`), and shows a read-only banner (`shell.rs`, `.demo-banner`). Unregistered commands (every mutation + any unfixtured read) degrade to a friendly `demo_unsupported` error via `ipc_mock::Unmocked::DemoFriendly`. Detail commands (`get_application_detail` / `get_enterprise_application_detail` / `get_mail_permission_scopes`) are registered **args-aware** with `ipc_mock::mock_each` (handler reads the call's camelCase args → returns a per-id fixture) so the detail pane switches per selection; a plain `mock_ok` returns one payload for every id (the bug the user hit). Ids are synthetic-but-realistic GUIDs from `fixtures::guid(seed)`. **Footgun:** the infallible `invoke()` reads (`get_cached_audit`/`cache_stats`/`export_audit_csv`/`get_auth_config`) and the `()`-returning ones (`invalidate_list_cache` — fired by every list Refresh — `clear_cache`, `cancel_*`, …) must be registered in `demo::register_fixtures`, or they **panic** on the rejected-promise fallback. Adding a new infallible `invoke()`/`invoke::<()>` reachable in the demo → register a fixture for it. The `demo` feature is off in `web-build`/desktop, so the mock + fixtures + banner never ship in releases. Nav is signal-based (no router), so no `404.html` SPA fallback is needed — only the `--public-url` subpath base-href.

- **Auto-update is interactive (not silent).** The front-end checks once on launch (`commands::updater::check_for_update`, swallowed silently on failure / in dev) and, if an update waits, toasts a notification whose action opens the `UpdateSplash` (`web-rs/components/update_splash.rs`) — changelog notes + **Update & restart** (`perform_update`: download_and_install → `app.restart()`, byte progress on the `updater-progress` channel). There's also a manual "Check for updates" button by the nav version. The changelog text is the updater manifest's `notes`, which `release.yml` populates from the `CHANGELOG.md` section for the tag, so it only lights up for releases from **v0.8.0 onward** (v0.7.0's `latest.json` predates it). Don't reintroduce a silent background `download_and_install` in `lib.rs` setup — it was removed in favour of this flow and would race the prompt.

- **Release is a 3-OS matrix → one aggregated `latest.json`.** `release.yml` runs `guard` (version/pubkey/audit, fails fast) → `build` matrix (`windows-latest` `just build-windows-updater` · `macos-latest` `build-macos-updater`, native **aarch64** only · `ubuntu-latest` `build-linux-updater`, needs the GTK/WebKit + `patchelf` apt deps), each uploading its `bundle/` tree as an artifact → `release` job downloads all and assembles ONE `latest.json` with `windows-x86_64` (NSIS `-setup.exe`) + `darwin-aarch64` (`.app.tar.gz`) + `linux-x86_64` (`.AppImage`) updater entries from each platform's `.sig`, plus SHA256SUMS, into a single draft. `bundle.targets` is `"all"`; the mac/Linux recipes pin formats via `--bundles` (`app,dmg` / `appimage,deb`). macOS ships **unsigned** (Gatekeeper bypass documented in README) — Authenticode (Windows) and notarization (macOS) are both optional, secret-gated, never blocking. Adding a platform/arch = a matrix leg + a `latest.json` platform key + a justfile recipe.

- **CSP governs the *webview*, not backend egress.** `connect-src` in `tauri.conf.json`; only WASM frontend fetches are restricted. Backend reqwest calls to new hosts don't need a CSP change.

- **Permissions catalog** is bundled at compile time from `azapptoolkit-permissions/data/`. Unknown resources fall back to `resolve_resource_sp()` Graph call.

- **Full-collection PATCH for `appRoles` / `oauth2PermissionScopes`.** Both are not-nullable arrays Graph **full-replaces** — re-read live state, mutate, write the whole array back (never merge against a cached payload). Deleting an enabled entry needs two PATCHes: disable first, then remove (`commands/expose_api.rs`, `commands/app_roles.rs`). Exposed **app roles** (`commands/app_roles.rs`) edit the **paired application** when one exists (Entra mirrors onto the SP) else the SP directly, and round-trip roles as **raw JSON** so the `value: null` SAML default (`msiam_access`) survives byte-for-byte (a typed `AppRole` would rewrite it to `""`). Bust with `invalidate_app_details` only — these aren't on any list/audit payload.

- **Crypto deps — no `rsa` crate; `rand`/`sha2` majors are pinned on purpose.** Self-signed cert generation (`src-tauri/src/cert.rs`) uses `rcgen` on the **`aws_lc_rs`** backend (already in-tree via rustls) *specifically* to keep the `rsa` crate (RUSTSEC-2023-0071) out of the dependency graph — **don't reintroduce `rsa`** (the `src-tauri/Cargo.toml` comment records why). The direct `rand = "0.8"` / `sha2 = "0.10"` pins in `src-tauri/Cargo.toml` (random bytes for client secrets in `expose_api`/`app_roles`/`managed_identity`; SHA-256 cert thumbprint) are held to match what **`oauth2` 5 + Tauri 2** already resolve; bumping to `rand` 0.10 / `sha2` 0.11 only stacks a **duplicate** version (neither held version carries an advisory), so leave them until oauth2/Tauri move first. Both lockfiles otherwise track the latest semver-compatible versions — `cargo update` is a no-op.

## Coding fundamentals

- Match the style, structure, and idioms of the file you're editing.
- Solve the task at hand; don't refactor unrelated code or expand scope.
- No abstraction, configuration, or generality for hypothetical futures (YAGNI).
- Comments explain *why*, not *what*.
- Dependencies are a cost; prefer std lib and existing workspace deps.
- Security first: no secrets to disk, tokens scoped per resource, don't log secrets.
- Test what you change; keep the suite green.

## Git & version control

- **Conventional Commits required:** `<type>[(scope)][!]: <description>`.
  - Types: `feat fix docs chore refactor test build ci perf style revert deps`
  - Scopes: `desktop`, `core`, `auth`, `graph`, `exchange`, `keyvault`, `permissions`, `ci`, `docs`.
- Porting from legacy PowerShell → reference source `file:line` in commit body.

## Verification playbook

Run the same gates CI runs before declaring a change done. `just verify` is the single command; each gate is also callable independently. Use recipe flags from `/justfile`, don't hand-type raw `cargo` invocations.

1. **Format** — `just fmt-check`
2. **Lint** — `just clippy` (`-D warnings`)
3. **Test** — `just test` (workspace)
4. **Frontend** — `just web-fmt-check` + `web-clippy` (`-D warnings`, wasm target; web-rs is excluded from the root workspace so root `clippy` doesn't reach it) + `web-test` + `web-build`
5. **Frontend GUI tests** *(browser-gated, not in `verify`)* — `just web-itest`: real Leptos views in a headless browser with the Tauri IPC mocked (no tenant/backend). New view-behavior changes get a `tests/<view>.rs` case; the harness (mock IPC + `mount_view` + DOM helpers + fixtures) lives in `web-rs/src/test_support/` behind the `test-support` feature.
6. **Dependency audit** *(optional locally)* — `just audit` + `web-audit` (RustSec) + `deny` + `web-deny`
6. **CodeQL** *(GitHub-side)* — security queries, Rust build-mode `none`. Known limitation: CodeQL 2.25.6 doesn't expand macros for this codebase (~39% calls-with-call-target), which is expected and non-failing. Config: `.github/codeql/codeql-config.yml`.

For behavior changes not provable by unit test, run `just dev` and exercise the view.

## Keeping this file up to date

When editing these files, update the matching section in AGENTS.md:
crate/dir changes → **Repo map**; workspace/toolchain/MSRV → **Quick Reference + What this repo is**;
`justfile` recipes / build commands → **Canonical commands, Verification playbook**;
new command/IPC/cache/CSP/cancel flag → **Conventions & gotchas**;
CI gate or `tauri.conf.json` bundle/updater → **Verification playbook**.

The staleness hook (`agents-md-staleness-check.sh`) reminds you if you forget. Always add an entry under `CHANGELOG.md` **[Unreleased]**.
