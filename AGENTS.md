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
    └── Trunk.toml                   # WASM build/serve (127.0.0.1:5173)

docs/DEVELOPMENT.md                  # build, test, package, release, updater keys
docs/architecture/                   # deep-dives: auth-consent, caching-search, scoping-audit
.github/workflows/                   # ci.yml · release.yml (Windows MSI+NSIS) · codeql.yml
```

## Common patterns

- **New Tauri command** — 3 steps (advisory hook `command-parity-check.sh` warns if you miss one):
  1. Implement `#[tauri::command] async fn` under `src-tauri/src/commands/`.
  2. Add to `tauri::generate_handler![]` in `src-tauri/src/lib.rs`.
  3. Create a typed stub in `web-rs/src/bindings/` (calls `invoke_result`).

- **Workspace dependency** — add to `[workspace.dependencies]`, reference via `"name".workspace = true`. Check `Cargo.lock` for conflicts.

- **Audit scoring rule** — implement in `azapptoolkit-core::audit` with a table-driven test citing legacy PowerShell `file:line`.

- **Audit remediation (one-click "Fix")** — only for findings with a safe, existing mutation; handler **re-resolves live state**. Full pattern: [docs/architecture/scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

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

# Dependency policy (CI also runs these):
just audit          # RustSec advisories (root workspace)
just web-audit      # RustSec (web-rs lockfile, separate from root)
just deny           # license + crate-source + bans (deny.toml)
just web-deny       # same policy, web-rs tree

# Release (Windows) + icons:
just build-windows  # MSI + NSIS installers
just icon           # regenerate from icons/icon.svg

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

- **Role/scope catalog.** Three auth planes (Entra, Azure RBAC, Exchange) share one capabilities catalog. Adding a privileged feature → add a catalog entry instead of hardcoding role strings. Details: [auth-and-consent.md](docs/architecture/auth-and-consent.md).

- **Audit signals — structured, not text.** Facets/cards key off `AuditItem` fields (`risk_level`, `credential_status`), not `starts_with(...)` on free-text.

- **Shared `audit_cancel` flag.** Security-audit and Bulk-actions both poll `AppState.audit_cancel`. New long-running commands must `reset()` at the top. Resource Access lookups poll `AppState.sweep_cancel` (independent). DR backup/restore uses `AppState.dr_cancel`. Tested in `state.rs`.

- **Batched Graph fan-out + adaptive throttle.** Large per-object fan-outs (security audit, DR backup) use Graph JSON batching — `client.batch_get_json[_with_headers]` (`graph/src/client/batch.rs`, 20 GETs/POST, results in input order, inner-429 re-batch) — plus a shared `ConcurrencyThrottle` (`commands/throttle.rs`) wired as the client's `ThrottleObserver` and fed to `dispatch_capped` as `|| throttle.current_limit()` so the in-flight cap halves on 429 and recovers when quiet. Reuse these for any new heavy fan-out; don't hand-roll a second tracker or a raw per-item loop. Advanced queries in a batch (e.g. `memberOf` `$count`) need the **per-sub-request** header form — the outer POST's headers don't reach sub-requests. Whole-batch failures must degrade to per-object reads, never fail the run. Attach/detach the observer with the shared `ThrottleGuard::attach(client, tracker)` RAII (`commands/throttle.rs`) so an early `?` can't leave a stale observer halving the shared per-tenant client's cap (used by the audit and the bulk fan-outs). Backup and the bulk write flows (delete / grant / remove-expired) emit the live cap in `BulkProgress.in_flight_cap` (additive `Option`; the DR view shows it + a back-off notice). The write fan-outs can't `$batch` (Graph batches GETs), so the win there is bounded concurrency + adaptive 429 backoff, not round-trip collapse.

- **Scope-aware audit risk.** Mail permission risk depends on Exchange RBAC scoping: `score_application` reads `AppPermissions.mail_scopes`; empty map = org-wide. SharePoint scoping is name-based, no live call needed. Badges render in `web-rs/components/scope_badge.rs`. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Scoped grants reuse shared cores.** Exchange + SharePoint both grant scoped access *before* stripping org-wide, so a failure never strands the principal. Exchange scope source: `azapptoolkit_<app_id>` mail-enabled security group (`group_name_for`); membership changes **don't** invalidate caches. Details: [scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Unified "Grant access" wizard + scope registry + per-mechanism strategy.** Scoping is a family of *independent* authorities, unified behind one classifier — `core::scoping::scope_kind(value) -> Option<ScopeKind>` (Exchange / SharePoint; `admin_applicable()` is the seam for future not-admin-scopable mechanisms like Teams RSC). The `ScopeWizard` (`web-rs/components/scope_wizard.rs`) is the **single "Grant access" button** on every principal's Permissions surface — it **subsumes the old "Add permission" picker** (there is no separate inline single-grant picker). Uniform shell — **select permissions → choose access → review & grant**. **Step 1 is the full live catalog** (the reusable multi-select `PermissionPicker`, every resource + Application/Delegated, **`ApplicationOnly` for a bare SP** since its org-wide grant is app-role-only) as a cart; the wizard owns `selected: Vec<PickerSelection>` and the picker emits toggles. **`mechanism`** is `Some(kind)` only when the cart is non-empty *and* every item is an Application permission mapping to the **same** `ScopeKind` (delegated/mixed/non-scopable ⇒ `None` ⇒ org-wide only). **Step 2 dispatches the target panel + apply by `ScopeKind`**: **Exchange RBAC** is declare-only (it `declare_app_permission`s each permission using the cart's id — manifest only, **no** runtime grant — then assigns the scoped role, since RBAC for Applications authorizes independently of the Entra grant; reach = union, so leaving the Entra grant defeats scoping), **SharePoint** swaps to `Sites.Selected` via `convert_site_access_to_selected`. One mechanism per run; a held row's "Scope…" opens it pre-seeded with the full `PickerSelection`. Org-wide falls back to `grant_single_permission` per item (app reg) / `grant_managed_identity_permission` grouped by resource (bare SP). Targets are managed via shared `ManagedScopeGroupPanel` (mailboxes) / `SiteSelectionPanel` (sites). Add a mechanism = a `ScopeKind` variant + a target panel + an apply arm; nothing else branches on the concrete mechanism.

- **Frontend reactivity is closure-based.** `{move || sig.get()}` for tracking; `.get()`/`.with()` to read. State is `RwSignal<T>` on a context-provided `Session`. CSS: plain global `styles.css` with BEM-ish names.

- **Per-list filter state the Home dashboard drills into lives on `Session` — and resets on tenant switch.** Searches (`apps_search`/`enterprise_search`/`mi_search`) and the facet of each *drill target* (`enterprise_facet`, `mi_facet`, `audit_facet`, `credentials_facet`) are `RwSignal`s on `Session` so an outside surface can seed them: Global Search seeds the search; the Home dashboard's clickable metrics seed the facet via `open_enterprise_with_facet` / `open_managed_identities_with_facet` / `open_posture_with_facet` / `open_credentials_with_facet` before navigating. The view binds its chip signal *to* the session field (`let ent_filter = session.enterprise_facet;`). This is the front-end mirror of the backend cross-tenant-leakage footgun: every lifted search/facet field **must** be reset in `set_active_tenant` to its "show all" sentinel (`"all"`), or a previous tenant's filter silently narrows the next tenant's list. The **App Registrations credential facet stays local** (no metric drills into it). Drilling into the Enterprise list also trips a one-shot `pending_open_filters` so the list expands its collapsed filter drawer to reveal the active chip.

- **Build-time config baking.** `build.rs` reads `.env`, emits `AZAPPTOOLKIT_BUILD_*`; runtime env vars override.

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
