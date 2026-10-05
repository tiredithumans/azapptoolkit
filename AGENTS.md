# Agent Instructions — azapptoolkit

azapptoolkit is a native Rust desktop app for managing Microsoft Entra ID app registrations — the
replacement for ad-hoc PowerShell. Tauri 2 + Leptos 0.8 (WASM) workspace, edition 2024, MSRV 1.98
(`rust-toolchain.toml`).

This file is an invariant + pointer index, not a manual: one sentence per rule. Detail lives in
`docs/architecture/` (every agent) and the path-scoped `.claude/rules/` (Claude Code; each loads when
a matching file is touched) — read a subsection's deep-dive before editing that subsystem. Most rules
are pinned by `apps/desktop/src-tauri/tests/repo_invariants/<area>.rs`; a failing assertion names its rule.

## Quick reference

| Item | Detail |
|---|---|
| Task runner | `just` — every build/dev/verify command is a recipe in `/justfile` (never hand-type `cargo`); `just --list` describes each. |
| Setup / Dev | `just setup` (idempotent OS-aware bootstrap; bodies in `scripts/`) · `just dev` (`cargo tauri dev`) |
| Inner loop | `just check` (type-check both trees, no codegen) · `just test-crate <crate> [-- <filter>]` |
| Gates | `just verify` (before declaring a change done) · `just verify-full` (CI parity) · `just clean` (both build trees) |
| Browser / demo | `just web-itest` · `just web-itest-size` (browser-gated) · `just web-build-pages [BASE]` (Pages demo) |
| Release builds | per-host; `just build-{windows,macos,linux}-updater` need `TAURI_SIGNING_PRIVATE_KEY`, `build-windows` is keyless |
| Run locally | needs `AZAPPTOOLKIT_CLIENT_ID` + `AZAPPTOOLKIT_TENANT_ID` (team builds bake them via `.env`) |

Deep-dives in `docs/architecture/`:

- Auth, tokens, consent, re-auth, capability catalog, SAML certs → [auth-and-consent.md](docs/architecture/auth-and-consent.md)
- Caches, list commands, search, batch fan-out, cancellation → [caching-and-search.md](docs/architecture/caching-and-search.md)
- Exchange mailbox scoping, scope groups, AAP migration → [exchange-scoping.md](docs/architecture/exchange-scoping.md)
- SharePoint `Sites.Selected` and sub-site Selected scopes → [sharepoint-selected.md](docs/architecture/sharepoint-selected.md)
- Audit scoring, findings, remediations, bulk, the grant wizard → [audit-findings-and-remediation.md](docs/architecture/audit-findings-and-remediation.md)
- Resource Access reverse lookups, permission tester → [resource-access-and-permission-tester.md](docs/architecture/resource-access-and-permission-tester.md)
- Session state, open-items workspace, UI primitives, Security layout, GUI-test sharding → [frontend-workspace.md](docs/architecture/frontend-workspace.md)
- Release matrix, auto-update, Pages demo, crypto pins → [release-updater-demo.md](docs/architecture/release-updater-demo.md)
- DR backup/restore → [backup-and-restore.md](docs/architecture/backup-and-restore.md)

## Repo map

```
crates/azapptoolkit-<name>/ — shared Rust libraries:
  core — models, cache (LRU+TTL), audit scoring, scoping, http_error/_retry
  dto — serializable IPC boundary types (backend + frontend)
  auth — Entra OAuth2 PKCE, token cache, OS keyring
  graph — typed Microsoft Graph client (retry/backoff)
  exchange — Exchange Admin API; verdict.rs = pure mailbox-scope decisions
  keyvault — Azure Key Vault secrets client
  arm — ARM + Azure Monitor Logs query (managed-identity)
  permissions — resource directory (data/); permissions resolve live
apps/desktop/src-tauri/ — backend (main process)
  src/lib.rs — Tauri builder, tracing, generate_handler![]
  src/state.rs — AppState: auth singleton, clients, cache, cancel flags
  src/commands/ — #[tauri::command] handlers (+ applications/ audit/ exchange/ permissions/ sso/ subdirs)
  src/token_adapter.rs — ScopedTokenAdapter (BearerProvider), per-scope tokens
  tests/repo_invariants/ — source-scanning tests that pin the rules below
  build.rs — bakes AZAPPTOOLKIT_CLIENT_ID/_TENANT_ID from .env
  tauri.conf.json — CSP, bundle, updater, before{Dev,Build}Command
apps/desktop/web-rs/ — WASM frontend (Trunk), EXCLUDED from the root workspace, own lockfile
  src/main.rs · state/ — entry + routing · context-provided Session (RwSignals)
  src/views/ · components/ — pages/layouts · reusable UI (components/ui = the primitives)
  src/bindings/ — typed Tauri IPC stubs, mirror backend commands
  src/ipc_mock/ · demo/ — mock IPC bridge + fixtures (tests) · GitHub Pages demo
  tests/gui_N.rs — sharded browser GUI tests (real views, IPC mocked)
  build.rs — bakes this version's CHANGELOG section ("What's new")
docs/DEVELOPMENT.md — build, test, package, release, updater keys
docs/CHANGELOG-archive.md — releases <= 0.26.3
.github/workflows/ — ci.yml · release.yml (3-OS matrix) · codeql.yml · pages.yml
.claude/ — hooks/ (advisory) · rules/ (path-scoped detail) · skills/ (ship, feature, repo-review, release, debug)
```

## Common patterns

- **New Tauri command** — three steps; the advisory `command-parity-check.sh` hook names a missing one:
  1. `#[tauri::command] async fn` under `src-tauri/src/commands/` (a domain file or subdir).
  2. Add it to `tauri::generate_handler![]` in `src-tauri/src/lib.rs`.
  3. A typed stub in `web-rs/src/bindings/` that calls `invoke_result`.
- **Workspace dependency** — add to `[workspace.dependencies]`, use `"name".workspace = true`, check `Cargo.lock` for a duplicate major first. Dependencies are a cost: prefer std + existing crates.
- **Audit scoring rule** — in `azapptoolkit-core::audit` with a table-driven test citing the legacy PowerShell `file:line`; a rule that shifts ranking needs a CHANGELOG note.
- **Audit remediation (one-click "Fix")** — only for a safe, existing mutation; re-resolves live state.

## Conventions & gotchas

### Backend, commands, caches

Deep-dive: caching-and-search.md

- **Security-critical app:** never write secrets to disk or logs; scope tokens per resource.
- **Tauri commands:** `#[tauri::command] async fn` → `State<'_, AppState>` → `Result<T, UiError>`; frontend args use `#[serde(rename_all = "camelCase")]`.
- **Tenant-scoped caches — cross-tenant leakage is the #1 footgun.** Keys are `{tenant_id}|{kind}`, sign-out and `sign_in` sweep every kind (never `reauthenticate`), the two tenant-wide indexes are read only through their typed accessors, and a cache-only command must prove the session.
- **Invalidate caches only on `Ok`** (tiers: `invalidate_app_lists` / `_credentials` / `_detail_state` / `_details`); a pinned index or a long scan's result takes `generation_for` before the fetch and stores via `*_if_current`.
- **`CacheKind::ServicePrincipal` self-invalidates in the graph client**, never in the command aggregators.
- **Long-running writes stop on Cancel AND on a dead session:** `claim()` a `CancelToken` before the first await, latch `dispatch::SessionDead`, flag the result incomplete; fan-outs never return a partial result.
- **Batched Graph fan-out + adaptive throttle** (`$batch` + `ConcurrencyThrottle` via `ThrottleGuard::attach`, degrading to per-object reads); never a hand-rolled loop; `$expand` + advanced query fails silently.
- **Every paged read sends `$top`** (`client::MAX_PAGE_SIZE`; `/applications` sends `DEFAULT_APP_PAGE_SIZE`) — paging is serial.
- **Full-collection PATCH for `appRoles` / `oauth2PermissionScopes`:** re-read live, mutate, write the whole array back; disable then remove; exposed app roles edit the paired application as raw JSON; bust with `invalidate_app_details` only.
- **camelCase vs snake_case:** Graph domain models are camel (no serde rename), DTOs/bindings snake; `Application` + `AuditItem` cross IPC as-is, so a rename is a wire-format change.
- **One definition per policy:** HTTP errors from `core::http_error_enum!` (Exchange: hand-rolled, conformance-tested), retries from `core::http_retry` (incl. `$batch`), re-auth-fatal codes only in `core::reauth::REAUTH_FATAL_CODES`.
- **The `BearerProvider` boundary carries the auth classification** as `core::token::TokenError { code, message }` — never a bare `String` — with `token_adapter::token_error` as the sole mapping.
- **Per-tenant operator defaults live in `settings.json`** (`UserSettings.tenant_defaults`); writers use only `UserSettings::mutate` (fails closed); `apply_tenant_defaults` destructures exhaustively and preserves the rotation-owned vault fields.
- **Build-time config baking:** `build.rs` reads `.env` → `AZAPPTOOLKIT_BUILD_*`; env vars override. **CSP governs the webview only** — backend reqwest egress needs no `connect-src` change.
- **Permission definitions resolve live** via `resolve_resource_sp()`; `azapptoolkit-permissions/data/` bundles only the picker's resource directory.

### Auth

Deep-dive: auth-and-consent.md

- **Lazy, shared token refresh** ~60 s before expiry behind one mutex; refresh tokens in the OS keyring, chunked for Windows; write scopes consented incrementally.
- **Extra-scope tokens ride `ScopedTokenAdapter`**, never the sign-in scope set, and every call degrades gracefully.
- **Silent grants can't obtain consent:** AADSTS65001/65004 → `AuthError::ConsentRequired` (≠ `InvalidGrant`); a "Grant consent" button needs `AppState::ensure_*` pre-acquisition.
- **A dead session forces re-auth in place** (`refresh_missing` / `not_signed_in` → `reauthenticate`, one interactive round trip, data caches kept) — never sign the user out.
- **Role/scope catalog:** three auth planes share one capabilities catalog — add an entry instead of a hardcoded role string; splice its remediation into 403s via `graph_err::forbidden_remediation`.
- **SAML signing-cert rollover derives its phase from live SP state**; a thumbprint is SHA-1 and `core::thumbprint::canonical` is its one converter.
- **Auth trusts are validated wherever minted** (`core::federation` on every path; bounded SAML cert lifetimes).

### Exchange & SharePoint scoping

Deep-dives: exchange-scoping.md · sharepoint-selected.md

- **Mailbox AND SharePoint permissions live on TWO resources each — carry the resource, never the bare value** (`audit::ResourcePermission`, the positive `is_scopable_*_resource_permission` / `scope_kind_for` gates; value-only forms are pinned out).
- **`Sites.Selected` reach is knowable only from the site side:** one tenant index shared by the sweep and the per-app panel, `AppSiteAccessDto::from_sweep` the single projection, empty = "no grants" only when `is_complete()`.
- **Sub-site Selected scopes are a SECOND, non-enumerable mechanism** (`ScopeKind::SharePointItem`, `grantedToV2` body, URL resolved then checked with `selected_scope_accepts`, appRole declared before assigned, own capability `sharepoint_selected_items`).
- **AAP migration is guarded, not mechanical:** `RestrictAccess` only, one batch per app, fail closed; planner `azapptoolkit-exchange::aap`.
- **Scoped grants reuse shared cores** and grant scoped access before stripping org-wide; scope + group names come from the two per-tenant patterns via `load_tenant_defaults`; membership changes don't invalidate caches.
- **Repointing a management scope is explicit and fail-closed:** `ensure_management_scope` is create-only, `set_management_scope_filter` the sole filter mutator, only for a proven `MemberOfGroup` OR-chain.

### Audit & remediation

Deep-dive: audit-findings-and-remediation.md

- **Scope-aware audit risk:** `score_application` reads `AppPermissions.mail_scopes` (empty map = org-wide); a legacy AAP verdict is its own finding, never the healthy one.
- **Unified "Grant access" wizard** (`ScopeWizard`): `mechanism` is `Some(kind)` only when every cart item is an Application permission of one `ScopeKind`; a new mechanism's touch points are listed in the deep-dive.
- **Audit signals are structured, not text:** facets/cards/groups key off `AuditItem` fields; a cancelled/truncated/degraded run is never cached nor shown as all-clear, and its export says so; a backup records what it missed.
- **SP-only principals are scored but are NOT bulk targets:** `AuditItem.principal_kind` routes to the SP-only cores, never `remediate_scope_*`.
- **Bulk remediations run the single-app cores sequentially** via `run_bulk_seq` (not `dispatch_capped`), claim a `CancelToken`, degrade to `BulkError`, stop on a re-auth-fatal code.

### Frontend

Deep-dive: frontend-workspace.md

- **Reactivity is closure-based** (`{move || sig.get()}`); state is `RwSignal<T>` on a context-provided `Session`; CSS is global BEM-ish; a bare-key shortcut must no-op in a text field.
- **One primitive per UI pattern** (`SectionHeader`, skeletons, `DetailLoadError`, `Callout`, `ShowMore`) — reuse, never re-implement.
- **Open-items workspace:** `session.open_item(...)` fills ONE shared `Session.open_items`; dock + workspace mount once in `shell.rs`; `open_items` + `shown_items` reset in `set_active_tenant`; no `selected_*_id` signals.
- **Per-list filter state lives on `Session.tenant_ui`** and resets by structure — a new field goes in the substruct with a `reset()` line + the pinning test.
- **Security tab is a findings-first workbench:** filtering has exactly two homes, `BulkActionBar` is the only bulk caller, no Grant consent on audit surfaces.
- **WASM gating:** server deps are `#[cfg(not(target_arch = "wasm32"))]` in shared crates; `web-rs` restates `unsafe_code = "deny"`.

### Release, updater & dependencies

Deep-dive: release-updater-demo.md

- **Release is a 3-OS matrix → one aggregated `latest.json`**, a draft a human publishes; CHANGELOG headers are `## [X.Y.Z] - YYYY-MM-DD` exactly (two parsers read them).
- **Auto-update is interactive:** launch check → toast → `UpdateSplash`; never reintroduce a silent `download_and_install`.
- **The Pages demo mocks the backend:** any infallible `invoke()` must be in `demo::register_fixtures` or the page panics (`demo_fixture_coverage.rs`).
- **Crypto/encoding pins on purpose:** no `rsa` (`rcgen` on `aws_lc_rs`); `sha2` + `p12-keystore` 0.2.x held — re-derive a hold from the graph, don't restate it; see `dependabot.yml`.
- **web-rs has its own lockfile**, so the root audit/deny never reach it — `web-audit` / `web-deny` do.

## Git & version control

- **Conventional Commits required:** `<type>[(scope)][!]: <description>`; the `conventional-commit-validator.sh` hook enforces the types and the scope allowlist.
  - Types: `feat fix docs chore refactor test build ci perf style revert deps`
  - Scopes (the canonical nine; the hook mirrors this line and `repo_invariants/release.rs` pins them equal): `desktop`, `core`, `auth`, `graph`, `exchange`, `keyvault`, `permissions`, `ci`, `docs`. Omit the scope rather than invent one.
- Branch naming: `<type>/<short-slug>` (e.g. `feat/batch-approve`).
- **CHANGELOG:** every user-visible change gets an entry under `[Unreleased]`; internal, docs, CI and tooling changes need none.
- Porting from legacy PowerShell → reference source `file:line` in the commit body.

## Verification playbook

1. `just verify` — fmt → clippy → test → doc → web-fmt → web-clippy → web-test → web-build → web-doc, then the browser GUI tests when this box can run them (`just verify-ui` requires them). `doc`/`web-doc` are the only gates that run rustdoc, so the only ones that fail on a broken intra-doc link (`[workspace.lints.rustdoc]` deny).
2. `just verify-full` — adds `audit`/`web-audit`/`deny`/`web-deny`/`machete` (required CI checks) + the shard ceiling.
3. CI-only: actionlint, shellcheck of `.claude/hooks/`, a whole-history secrets scan (never gated on the change detector), CodeQL (build-mode `none`; macro expansion is a known gap).

The browser GUI tests are the frontend's only behavioural gate: renaming a CSS class, aria-label, or on-screen text a test references fails CI (sharding + footguns: frontend-workspace.md). For behaviour no test can prove, run `just dev` and exercise the view.

## Keeping this file up to date

Crate/dir changes → Repo map; toolchain/MSRV or `justfile` recipes → Quick reference; a new command/IPC/cache/CSP/cancel invariant → one sentence in its Conventions subsection (no per-bullet doc link) plus its detail in `docs/architecture/` (and, for Claude, the matching `.claude/rules/` file); a CI gate → Verification playbook. The `staleness-check.sh` hook reminds you (once per session) when a structural edit likely needs this file. The hook and `repo_invariants/release.rs` hold this file under 18 000 bytes — past it, move detail out rather than raise the budget.
