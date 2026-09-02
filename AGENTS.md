# Agent Instructions — azapptoolkit

azapptoolkit is a **native Rust desktop app for managing Microsoft Entra ID app registrations** —
the replacement for ad-hoc PowerShell. Tauri 2 + Leptos 0.8 (WASM) workspace, edition 2024,
MSRV **1.98** (`rust-toolchain.toml`).

This file is an **invariant + pointer index**, not a manual: one sentence per rule plus a link to
the deep-dive that explains it. Keep it that way — detail belongs in `docs/architecture/` (read by
every agent) and in the path-scoped `.claude/rules/` files (Claude Code only; each loads when a
matching file is touched). A hook and a test hold this file under **20 000 bytes**. **Read the
linked doc before editing that subsystem.**

## Quick reference

| Item | Detail |
|---|---|
| **Task runner** | `just` — recipes in `/justfile`, `just --list` describes each; Tauri's hooks call them too, so flags never drift. |
| **Setup / Dev** | `just setup` (idempotent OS-aware bootstrap; bodies in `scripts/`) · `just dev` (`cargo tauri dev`) |
| **Inner loop** | `just check` (type-check both trees, no codegen) · `just test-crate <crate> [-- <filter>]` |
| **Verify** | `just verify` = the CI gates in CI order, plus the browser GUI tests when Chrome + chromedriver are present (LOUD skip otherwise). `just verify-ui` makes them mandatory; `just verify-full` adds the audit/deny gates (network). |
| **Workspace** | 9 crates (8 in `crates/` + `src-tauri`); the frontend (`web-rs`) is excluded, builds via Trunk, own lockfile. |

Deep-dives in `docs/architecture/` — read the one for the subsystem you touch:

- Auth, tokens, consent, re-auth, capability catalog, SAML certs → [auth-and-consent.md](docs/architecture/auth-and-consent.md)
- Caches, list commands, search, batch fan-out, cancellation → [caching-and-search.md](docs/architecture/caching-and-search.md)
- Exchange mailbox scoping, scope groups, AAP migration → [exchange-scoping.md](docs/architecture/exchange-scoping.md)
- SharePoint `Sites.Selected` and sub-site Selected scopes → [sharepoint-selected.md](docs/architecture/sharepoint-selected.md)
- Audit scoring, findings, remediations, bulk, the grant wizard → [audit-findings-and-remediation.md](docs/architecture/audit-findings-and-remediation.md)
- Resource Access reverse lookups, permission tester → [resource-access-and-permission-tester.md](docs/architecture/resource-access-and-permission-tester.md)
- Session state, open-items workspace, UI primitives, Security layout, GUI-test sharding → [frontend-workspace.md](docs/architecture/frontend-workspace.md)
- Release matrix, auto-update, Pages demo, crypto pins → [release-updater-demo.md](docs/architecture/release-updater-demo.md)
- DR backup/restore → [backup-and-restore.md](docs/architecture/backup-and-restore.md)

Skills in `.claude/skills/` are self-describing: **ship** · **feature** · **repo-review** · **release** · **debug**.

## Repo map

```
crates/                              # shared Rust libraries
├── azapptoolkit-core/               # models, cache (LRU+TTL), audit scoring, scoping, http_error/_retry
├── azapptoolkit-dto/                # serializable IPC boundary types (backend + frontend)
├── azapptoolkit-auth/               # Entra OAuth2 PKCE, token cache, OS keyring
├── azapptoolkit-graph/              # typed Microsoft Graph client (retry/backoff)
├── azapptoolkit-exchange/           # Exchange Admin API; `verdict.rs` = pure mailbox-scope decisions
├── azapptoolkit-keyvault/           # Azure Key Vault secrets client
├── azapptoolkit-arm/                # ARM + Azure Monitor Logs query (managed-identity)
└── azapptoolkit-permissions/        # bundled permissions catalog (data/) + Graph fallback

apps/desktop/
├── src-tauri/                       # backend (main process)
│   ├── src/lib.rs                   # Tauri builder, tracing, `generate_handler![]`
│   ├── src/state.rs                 # AppState: auth singleton, clients, cache, cancel flags
│   ├── src/commands/                # #[tauri::command] handlers (+ applications/ exchange/ sso/ subdirs)
│   ├── src/token_adapter.rs         # ScopedTokenAdapter (BearerProvider), per-scope tokens
│   ├── tests/repo_invariants/       # source-scanning tests that pin the rules below
│   ├── build.rs                     # bakes AZAPPTOOLKIT_CLIENT_ID/_TENANT_ID from .env
│   └── tauri.conf.json              # CSP, bundle, updater, before{Dev,Build}Command
└── web-rs/                          # WASM frontend — EXCLUDED from the root workspace
    ├── src/main.rs · state/         # entry + routing · context-provided Session (RwSignals)
    ├── src/views/ · components/     # pages/layouts · reusable UI (components/ui = the primitives)
    ├── src/bindings/                # typed Tauri IPC stubs — mirror backend commands
    ├── src/ipc_mock/ · demo/        # mock IPC bridge + fixtures (tests) · GitHub Pages demo
    ├── tests/gui_N.rs               # sharded browser GUI tests (real views, IPC mocked)
    └── build.rs                     # bakes this version's CHANGELOG section ("What's new")

scripts/                             # bodies of `just setup` (setup.sh / setup.ps1)
docs/DEVELOPMENT.md                  # build, test, package, release, updater keys
docs/architecture/                   # the deep-dives linked above
docs/CHANGELOG-archive.md            # releases <= 0.26.3 (split out of CHANGELOG.md)
.github/workflows/                   # ci.yml · release.yml (3-OS matrix) · codeql.yml · pages.yml
.claude/{hooks,skills,rules}/        # advisory hooks · workflows · path-scoped detail for Claude
```

## Common patterns

- **New Tauri command** — three steps; the advisory `command-parity-check.sh` hook names a missing one:
  1. `#[tauri::command] async fn` under `src-tauri/src/commands/` (a domain file or subdir).
  2. Add it to `tauri::generate_handler![]` in `src-tauri/src/lib.rs`.
  3. A typed stub in `web-rs/src/bindings/` that calls `invoke_result`.
- **Workspace dependency** — add to `[workspace.dependencies]`, use `"name".workspace = true`, check `Cargo.lock` for a duplicate major first. Dependencies are a cost: prefer std + existing crates.
- **Audit scoring rule** — in `azapptoolkit-core::audit` with a table-driven test citing the legacy PowerShell `file:line`; a rule that shifts ranking needs a CHANGELOG note.
- **Audit remediation (one-click "Fix")** — only for a safe, existing mutation; re-resolves live state. → [audit-findings-and-remediation.md](docs/architecture/audit-findings-and-remediation.md)

## Canonical commands

Every build/dev/verify command is a `just` recipe (`just --list` describes each; never hand-type `cargo`). Day to day:
`just check` · `just test-crate <crate>` · `just verify` (before declaring a change done) ·
`just verify-full` (CI parity) · `just clean` (both build trees). Browser-gated: `just web-itest`,
`just web-itest-size`. Pages demo: `just web-build-pages [BASE]`. Release builds are per-host
(`just build-{windows,macos,linux}-updater` need `TAURI_SIGNING_PRIVATE_KEY`; `build-windows` is
keyless). Running locally needs `AZAPPTOOLKIT_CLIENT_ID` + `AZAPPTOOLKIT_TENANT_ID` (team builds
bake them via `.env`).

## Conventions & gotchas

### Backend, commands, caches

- **Tauri commands:** `#[tauri::command] async fn` → `State<'_, AppState>` → `Result<T, UiError>`; frontend args use `#[serde(rename_all = "camelCase")]`.
- **Tenant-scoped caches — cross-tenant leakage is the #1 footgun.** Keys are `{tenant_id}|{kind}`, sign-out sweeps every kind, the two tenant-wide indexes are read only through their typed accessors, and a cache-only command must prove the session. → [caching-and-search.md](docs/architecture/caching-and-search.md)
- **Invalidate caches only on `Ok`** (`invalidate_app_lists` / `invalidate_app_credentials` / `invalidate_app_details`); a pinned index takes `generation_for` before the fetch and stores via `*_if_current`. Pinned in `repo_invariants/cache.rs`. → [caching-and-search.md](docs/architecture/caching-and-search.md)
- **`CacheKind::ServicePrincipal` self-invalidates in the graph client**, never in the command aggregators.
- **Long-running writes stop on Cancel AND on a dead session:** `claim()` a `CancelToken` before the first await, latch `dispatch::SessionDead`, flag the result incomplete; fan-outs never return a partial result. Pinned per call site in `repo_invariants/{cancel,fanout}.rs`. → [caching-and-search.md](docs/architecture/caching-and-search.md)
- **Batched Graph fan-out + adaptive throttle** (`$batch` + `ConcurrencyThrottle` via `ThrottleGuard::attach`, degrading to per-object reads); never a hand-rolled loop; `$expand` + advanced query fails silently. → [caching-and-search.md](docs/architecture/caching-and-search.md)
- **Every paged read sends `$top`** (`client::MAX_PAGE_SIZE`; `/applications` sends `DEFAULT_APP_PAGE_SIZE`) — paging is serial.
- **Full-collection PATCH for `appRoles` / `oauth2PermissionScopes`:** re-read live, mutate, write the whole array back; disable then remove; exposed app roles edit the paired application as raw JSON; bust with `invalidate_app_details` only.
- **camelCase vs snake_case:** Graph domain models are camel (no serde rename), DTOs/bindings snake; `Application` + `AuditItem` cross IPC as-is, so a rename is a wire-format change.
- **One definition per policy:** HTTP error taxonomy from `core::http_error_enum!`, retry budget from `core::http_retry` (incl. `$batch`), re-auth-fatal codes only in `core::reauth::REAUTH_FATAL_CODES`.
- **The `BearerProvider` boundary carries the auth classification** as `core::token::TokenError { code, message }` — never a bare `String` — with `token_adapter::token_error` as the sole mapping.
- **Per-tenant operator defaults live in `settings.json`** (`UserSettings.tenant_defaults`); two writers read-modify-write via `UserSettings::stored`; `apply_tenant_defaults` destructures exhaustively and preserves the rotation-owned vault fields.
- **Build-time config baking:** `build.rs` reads `.env` → `AZAPPTOOLKIT_BUILD_*`; env vars override. **CSP governs the webview only** — backend reqwest egress needs no `connect-src` change.
- **Permissions catalog** is bundled at compile time from `azapptoolkit-permissions/data/`; unknown resources fall back to `resolve_resource_sp()`.

### Auth

- **Lazy, shared token refresh** ~60 s before expiry behind one mutex; refresh tokens in the OS keyring, chunked for Windows; write scopes consented incrementally. → [auth-and-consent.md](docs/architecture/auth-and-consent.md)
- **Extra-scope tokens ride `ScopedTokenAdapter`**, never the sign-in scope set, and every call degrades gracefully. → [auth-and-consent.md](docs/architecture/auth-and-consent.md)
- **Silent grants can't obtain consent:** AADSTS65001/65004 → `AuthError::ConsentRequired` (≠ `InvalidGrant`); a "Grant consent" button needs `AppState::ensure_*` pre-acquisition. → [auth-and-consent.md](docs/architecture/auth-and-consent.md)
- **A dead session forces re-auth in place** (`refresh_missing` / `not_signed_in` → `reauthenticate`, one interactive round trip, data caches kept) — never sign the user out. → [auth-and-consent.md](docs/architecture/auth-and-consent.md)
- **Role/scope catalog:** three auth planes share one capabilities catalog — add an entry instead of a hardcoded role string; splice its remediation into 403s via `graph_err::forbidden_remediation`. → [auth-and-consent.md](docs/architecture/auth-and-consent.md)
- **SAML signing-cert rollover derives its phase from live SP state**; a thumbprint is SHA-1 and `core::thumbprint::canonical` is its one converter. → [auth-and-consent.md](docs/architecture/auth-and-consent.md)
- **Auth trusts are validated wherever minted** (`core::federation` on every path; bounded SAML cert lifetimes). Pinned by `repo_invariants/trust.rs`.

### Scoping & audit

- **Scope-aware audit risk:** `score_application` reads `AppPermissions.mail_scopes` (empty map = org-wide); a legacy AAP verdict is its own finding, never the healthy one. → [audit-findings-and-remediation.md](docs/architecture/audit-findings-and-remediation.md)
- **Mailbox AND SharePoint permissions live on TWO resources each — carry the resource, never the bare value** (`audit::ResourcePermission`, the positive `is_scopable_*_resource_permission` / `scope_kind_for` gates; value-only forms are pinned out). → [exchange-scoping.md](docs/architecture/exchange-scoping.md)
- **`Sites.Selected` reach is knowable only from the site side:** one tenant index shared by the sweep and the per-app panel, `AppSiteAccessDto::from_sweep` the single projection, empty = "no grants" only when `is_complete()`. → [sharepoint-selected.md](docs/architecture/sharepoint-selected.md)
- **Sub-site Selected scopes are a SECOND, non-enumerable mechanism** (`ScopeKind::SharePointItem`, `grantedToV2` body, URL resolved then checked with `selected_scope_accepts`, appRole declared before assigned, own capability `sharepoint_selected_items`). → [sharepoint-selected.md](docs/architecture/sharepoint-selected.md)
- **AAP migration is guarded, not mechanical:** `RestrictAccess` only, one batch per app, fail closed; planner `azapptoolkit-exchange::aap`. → [exchange-scoping.md](docs/architecture/exchange-scoping.md)
- **Scoped grants reuse shared cores** and grant scoped access before stripping org-wide; scope + group names come from the two per-tenant patterns via `load_tenant_defaults`; membership changes don't invalidate caches. → [exchange-scoping.md](docs/architecture/exchange-scoping.md)
- **Repointing a management scope is explicit and fail-closed:** `ensure_management_scope` is create-only, `set_management_scope_filter` the sole filter mutator, only for a proven `MemberOfGroup` OR-chain. → [exchange-scoping.md](docs/architecture/exchange-scoping.md)
- **Unified "Grant access" wizard** (`ScopeWizard`): `mechanism` is `Some(kind)` only when every cart item is an Application permission of one `ScopeKind`; adding a mechanism touches exactly three places. → [audit-findings-and-remediation.md](docs/architecture/audit-findings-and-remediation.md)
- **Audit signals are structured, not text:** facets/cards/groups key off `AuditItem` fields; a cancelled/truncated/degraded run is never cached nor shown as all-clear; a backup records what it missed. → [audit-findings-and-remediation.md](docs/architecture/audit-findings-and-remediation.md)
- **SP-only principals are scored but are NOT bulk targets:** `AuditItem.principal_kind` routes to the SP-only cores, never `remediate_scope_*`. → [audit-findings-and-remediation.md](docs/architecture/audit-findings-and-remediation.md)
- **Bulk remediations run the single-app cores sequentially** via `run_bulk_seq` (not `dispatch_capped`), claim a `CancelToken`, degrade to `BulkError`, stop on a re-auth-fatal code. → [audit-findings-and-remediation.md](docs/architecture/audit-findings-and-remediation.md)

### Frontend

- **Reactivity is closure-based** (`{move || sig.get()}`); state is `RwSignal<T>` on a context-provided `Session`; CSS is global BEM-ish; a bare-key shortcut must no-op in a text field. → [frontend-workspace.md](docs/architecture/frontend-workspace.md)
- **One primitive per UI pattern** (`SectionHeader`, skeletons, `DetailLoadError`, `Callout`, `ShowMore`) — reuse, never re-implement. → [frontend-workspace.md](docs/architecture/frontend-workspace.md)
- **Open-items workspace:** `session.open_item(...)` fills ONE shared `Session.open_items`; dock + workspace mount once in `shell.rs`; `open_items` + `shown_items` reset in `set_active_tenant`; no `selected_*_id` signals. → [frontend-workspace.md](docs/architecture/frontend-workspace.md)
- **Per-list filter state lives on `Session.tenant_ui`** and resets by structure — a new field goes in the substruct with a `reset()` line + the pinning test. → [frontend-workspace.md](docs/architecture/frontend-workspace.md)
- **Security tab is a findings-first workbench:** filtering has exactly two homes, `BulkActionBar` is the only bulk caller, no Grant consent on audit surfaces. → [frontend-workspace.md](docs/architecture/frontend-workspace.md)
- **WASM gating:** server deps are `#[cfg(not(target_arch = "wasm32"))]` in shared crates; `web-rs` restates `unsafe_code = "deny"` (pinned by test).
- **The Pages demo mocks the backend:** any infallible `invoke()` must be in `demo::register_fixtures` or the page panics (enforced by `demo_fixture_coverage.rs`). → [release-updater-demo.md](docs/architecture/release-updater-demo.md)
- **Auto-update is interactive:** launch check → toast → `UpdateSplash`; never reintroduce a silent `download_and_install`. → [release-updater-demo.md](docs/architecture/release-updater-demo.md)

### Release & dependencies

- **Release is a 3-OS matrix → one aggregated `latest.json`**, a draft a human publishes; CHANGELOG headers are `## [X.Y.Z] - YYYY-MM-DD` exactly (two parsers, pinned by test). → [release-updater-demo.md](docs/architecture/release-updater-demo.md)
- **Crypto/encoding pins on purpose:** no `rsa` (`rcgen` on `aws_lc_rs`); `rand`/`sha2`/`base64` majors and `p12-keystore` 0.2.x held — rationale in `dependabot.yml`. → [release-updater-demo.md](docs/architecture/release-updater-demo.md)
- **web-rs has its own lockfile**, so the root audit/deny never reach it — `web-audit` / `web-deny` do.

## Coding fundamentals

- **Security-critical app:** never write secrets to disk or logs; scope tokens per resource.

## Git & version control

- **Conventional Commits required:** `<type>[(scope)][!]: <description>`; the `conventional-commit-validator.sh` hook enforces the types **and** the scope allowlist.
  - Types: `feat fix docs chore refactor test build ci perf style revert deps`
  - Scopes (the canonical nine — the hook mirrors this line and `repo_invariants/release.rs` pins the two to each other): `desktop`, `core`, `auth`, `graph`, `exchange`, `keyvault`, `permissions`, `ci`, `docs`. Omit the scope rather than invent one.
- Branch naming: `<type>/<short-slug>` (e.g. `feat/batch-approve`).
- **CHANGELOG:** every **user-visible** change gets an entry under `[Unreleased]`; internal, docs, CI and tooling changes need none.
- Porting from legacy PowerShell → reference source `file:line` in the commit body.

## Verification playbook

Run the gates CI runs before declaring a change done, via the `just` recipes:

1. `just verify` — fmt → clippy → test → web-fmt → web-clippy → web-test → web-build, then the browser GUI tests when this box can run them (`just verify-ui` to require them).
2. `just verify-full` — adds `audit`/`web-audit`/`deny`/`web-deny` (required CI checks) and the shard-size ceiling.
3. CI-side only: actionlint, shellcheck of `.claude/hooks/` + a whole-history secrets scan (never gated on the change detector), CodeQL (build-mode `none`; macro expansion is a known gap).

The browser GUI tests (`just web-itest`) are the frontend's only behavioural gate: renaming a CSS class, aria-label, or on-screen text a test references fails CI. Sharding + footguns: [frontend-workspace.md](docs/architecture/frontend-workspace.md). For behaviour no test can prove, run `just dev` and exercise the view.

## Keeping this file up to date

Crate/dir changes → **Repo map**; toolchain/MSRV → **Quick reference**; `justfile` recipes → **Canonical commands**; a new command/IPC/cache/CSP/cancel invariant → one sentence under **Conventions & gotchas** plus its detail in `docs/architecture/` (and, for Claude, the matching `.claude/rules/` file); a CI gate → **Verification playbook**. The `staleness-check.sh` hook reminds you (once per session) when a structural edit likely needs this file, and warns past the 20 000-byte budget.
