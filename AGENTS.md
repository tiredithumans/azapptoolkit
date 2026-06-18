# Agent Instructions — azapptoolkit

This file is the single source of truth for **every** AI assistant that contributes to this repo —
Claude Code, Codex, Cursor, Aider, Copilot, Gemini, and any other. `CLAUDE.md` imports it via `@AGENTS.md`;
other tools should read it directly. If something here conflicts with a tool's generic defaults, this
file wins. Keep it accurate — see [Keeping this file up to date](#keeping-this-file-up-to-date).

Deep subsystem detail lives in `docs/architecture/` — this file keeps the invariant + a pointer.
**Read the linked doc before editing that subsystem.**

## Quick Reference

| Item | Detail |
|---|---|
| **Task runner** | [`just`](https://github.com/casey/just) — one cross-platform binary; recipes in `/justfile` are the single source of truth for every build/dev/verify command (used by humans, CI, **and** Tauri's `before*Command` hooks, so flags never drift). Run `just` to list them. |
| **First-time setup** | `just setup` (idempotent OS-aware bootstrap; needs `just` installed first — `cargo install just`, `brew install just`, or `winget install Casey.Just`) |
| **Daily dev loop** | `just dev` (= `cargo tauri dev`: builds + serves Leptos frontend, launches shell) |
| **Rust / Tauri** | MSRV 1.96 via `rust-toolchain.toml`; Tauri v2.11.x |
| **Workspace members** | 9 crates (8 in `crates/` + `src-tauri`); excludes `apps/desktop/web-rs` (WASM) |
| **Verify before done** | `just verify` (fmt-check → clippy → test → web-fmt-check → web-test → web-build, the CI gates in order) |

Key files/docs to read before editing:
- **Adding a command?** Read `src-tauri/src/lib.rs` (handler list) + `web-rs/src/bindings/` for the stub pattern.
- **Changing auth/token/consent behavior?** Read [docs/architecture/auth-and-consent.md](docs/architecture/auth-and-consent.md), then `src-tauri/src/state.rs` (AppState) + `crates/azapptoolkit-auth/src/token_cache.rs`.
- **Touching caches, list commands, or search?** Read [docs/architecture/caching-and-search.md](docs/architecture/caching-and-search.md).
- **Touching audit scoring, remediations, or Exchange/SharePoint scoping?** Read [docs/architecture/scoping-and-audit.md](docs/architecture/scoping-and-audit.md).
- **Touching DR backup/restore (tenant export/import)?** Read [docs/architecture/backup-and-restore.md](docs/architecture/backup-and-restore.md), then `crates/azapptoolkit-dto/src/backup.rs` + `src-tauri/src/commands/backup.rs`.
- **Adding a new dependency?** Check `Cargo.lock` for transitive conflicts.
- **Updating WASM code?** Read `crates/azapptoolkit-core/src/lib.rs` for `#[cfg(not(target_arch = "wasm32"))]` examples.

## What this repo is

azapptoolkit is a **native desktop app for managing Microsoft Entra ID app registrations** — the
replacement for ad-hoc PowerShell. It signs in to Entra ID directly from the user's workstation via
OAuth2 PKCE (as a public client, single-tenant) and talks to Microsoft Graph, Exchange Online, and
Azure Key Vault with the signed-in user's delegated permissions. It ships **no** service principal of
its own and stores no tokens the user can't audit: refresh tokens live in the OS keyring, access
tokens stay in memory and are zeroized on drop.

The stack is **pure Rust**: a [Tauri 2](https://tauri.app) shell with a Rust backend and a
[Leptos 0.8](https://leptos.dev) + [Thaw UI](https://github.com/thaw-ui/thaw) frontend compiled to
WebAssembly. Workspace edition is 2021, MSRV/pinned toolchain is **1.96** (`rust-toolchain.toml`).

## Repo map

Cargo workspace. Note the frontend crate (`apps/desktop/web-rs`) is **excluded** from the root
workspace — it builds for `wasm32-unknown-unknown` via Trunk, separately.

```
crates/                              # shared Rust libraries
├── azapptoolkit-core/               # domain models, cache (LRU+TTL), audit/risk scoring, constants
├── azapptoolkit-dto/                # serializable IPC boundary types (shared by backend + frontend)
├── azapptoolkit-auth/               # Entra OAuth2 PKCE sign-in, token cache, OS keyring persistence
├── azapptoolkit-graph/              # typed Microsoft Graph client (retry/backoff, deserialization)
├── azapptoolkit-exchange/           # Exchange Online Admin API client (RBAC for Applications)
├── azapptoolkit-keyvault/           # Azure Key Vault secrets client
├── azapptoolkit-arm/                # Azure Resource Manager client (managed-identity Azure RBAC) + Azure Monitor Logs query
└── azapptoolkit-permissions/        # bundled permissions catalog (data/) + live Graph fallback

apps/desktop/
├── src-tauri/                       # backend (main process)
│   ├── src/lib.rs                   #   Tauri builder, tracing setup, command registration
│   ├── src/state.rs                 #   AppState: auth singleton, per-tenant clients, cache, cancel flag
│   ├── src/commands/                #   #[tauri::command] handlers, one file per domain
│   ├── src/token_adapter.rs         #   ScopedTokenAdapter (BearerProvider) for per-scope tokens
│   ├── build.rs                     #   bakes AZAPPTOOLKIT_CLIENT_ID/_TENANT_ID from .env at compile time
│   ├── tauri.conf.json              #   shell config: before{Dev,Build}Command, CSP, bundle, updater
│   └── capabilities/                #   Tauri 2 scoped capability definitions
└── web-rs/                          # frontend (WASM) — EXCLUDED from root workspace
    ├── src/main.rs                  #   WASM entry, theme detection, root component / routing
    ├── src/state.rs                 #   context-provided Session (RwSignals)
    ├── src/views/                   #   page/layout components
    ├── src/components/              #   reusable UI components
    ├── src/hooks/                   #   Leptos Effect/Signal helpers (e.g. use_debounced)
    ├── src/bindings/                #   typed Tauri IPC stubs — MIRROR the backend commands
    └── Trunk.toml                   #   WASM build/serve config (127.0.0.1:5173)

docs/DEVELOPMENT.md                  # build, test, package, release, updater keys, CI
docs/architecture/                   # agent/developer deep-dives (auth-consent, caching-search, scoping-audit)
.github/workflows/                   # ci.yml (fmt/clippy/test/web/audit/deny), release.yml (Windows MSI+NSIS), codeql.yml (CodeQL advanced setup, Rust build-mode none); config in .github/codeql/
```

## Common patterns

- **Adding a new Tauri command** — 3 steps (an advisory hook, `command-parity-check.sh`, reminds you
  when one half is missing):
  1. Implement `#[tauri::command] async fn` in a file under `src-tauri/src/commands/`
  2. Add to the `tauri::generate_handler![]` list in `src-tauri/src/lib.rs`
  3. Create a typed stub in `web-rs/src/bindings/` that calls `invoke_result(...)`

- **Adding a workspace dependency** — add to `[workspace.dependencies]` in root `Cargo.toml`,
  then reference via `"name".workspace = true` in member crates. Check `Cargo.lock` for
  transitive conflicts before committing.

- **Adding an audit scoring rule** — implement in `azapptoolkit-core::audit` with a
  table-driven test that cites the legacy PowerShell `file:line` it was ported from.

- **Adding an audit remediation (one-click "Fix")** — only for findings whose fix maps to a
  **safe, existing** mutation; the handler **re-resolves live state** before acting (the audit
  snapshot is advisory). Full pattern: [docs/architecture/scoping-and-audit.md](docs/architecture/scoping-and-audit.md).

- **Adding a new external origin** — only a direct fetch from the WASM frontend needs a CSP change
  (widen `connect-src` in `src-tauri/tauri.conf.json`); backend reqwest calls don't (see the CSP
  gotcha below).

## Canonical commands

Every build/dev/verify command lives in `/justfile` as a `just` recipe — there are no standalone
shell/PowerShell scripts. `just` searches upward for the justfile, so recipes resolve from any
subdirectory; web recipes set `[working-directory(...)]` so they're shell-agnostic. Tauri's hooks are
wired to recipes too: `beforeDevCommand` → `just web-serve`, `beforeBuildCommand` →
`just web-build-release`. When you add or change a build command anywhere, update the matching recipe
so CI, Tauri, and humans stay in sync. Run `just` (or `just --list`) to see them all.

```bash
just setup          # First-time setup (idempotent — rerun after pulling)
just dev            # Daily dev loop (= cargo tauri dev)

# Verify — all CI gates in order (fmt-check → clippy → test → web-fmt-check → web-test → web-build):
just verify
# …or one gate: just fmt-check | clippy | test | web-fmt-check | web-test | web-build

# Dependency policy (CI also runs these). The web-* variants gate the frontend's
# own Cargo.lock, which the root scans never reach (web-rs is workspace-excluded):
just audit          # RustSec advisories (root workspace)
just web-audit      # RustSec advisories (web-rs lockfile)
just deny           # license + crate-source + bans policy (deny.toml)
just web-deny       # same policy over the web-rs tree (reuses deny.toml)

# Release (Windows) + icons:
just build-windows  # MSI + NSIS installers
just icon           # regenerate bundled icons from icons/icon.svg
```

Running locally needs `AZAPPTOOLKIT_CLIENT_ID` + `AZAPPTOOLKIT_TENANT_ID` (a single-tenant public-client
registration you control). Both are required; sign-in is rejected without the tenant id. For team
builds, bake them via `.env` (see `build.rs` and docs/DEVELOPMENT.md). `.env` is git-ignored — only
`.env.example` is checked in.

## Project conventions & gotchas

- **Tauri command pattern.** Backend commands are `#[tauri::command] async fn` taking
  `State<'_, AppState>` as the first param and returning `Result<T, UiError>`. Every new command **must**
  be added to the `tauri::generate_handler![]` list in `src-tauri/src/lib.rs`, **and** get a typed stub in
  `web-rs/src/bindings/` that calls `invoke_result(...)`. Arg structs on the frontend use
  `#[serde(rename_all = "camelCase")]` (Tauri's JS-side convention). Forgetting either half = a command
  the UI can't reach.
- **Tenant-scoped caches — cross-tenant leakage is the #1 footgun.** Cache keys are tenant-prefixed via
  helpers (`apps_pairing_key(tenant_id)` → `"{tenant_id}|apps_pairing"`); never use an unscoped key. On
  sign-out, `cache.invalidate_prefix(kind, "{tenant_id}|")` for **every** kind (Lists, Audit,
  ServicePrincipal, Permissions). Lists load once as lean pre-classified row
  DTOs and all filtering/search runs in frontend memos; `global_search` filters the cached `sp_index` +
  `app_name_index` in memory. Details: [docs/architecture/caching-and-search.md](docs/architecture/caching-and-search.md).
- **Invalidate caches only on `Ok`.** After a successful mutation, bust the relevant list cache
  (`invalidate_app_lists(...)` drops apps-pairing, enterprise, `sp_index`, **and** `app_name_index`
  together, **plus — transitively — the per-app detail cache, the cached mailbox-scope verdicts
  (`{tenant}|mail_scopes|…`), and the cached audit run**, so a scope grant or credential change
  never leaves a stale posture tile or Scope badge); never on the error path, so a
  failed write doesn't clear fresh data. Any mutation that can
  add/remove/rename an SP or app registration must call it. **Credential-only** mutations
  (add/remove secret or cert, generate-self-signed, remove-expired) instead call the tiered
  `invalidate_app_credentials(cache, tenant, object_id)`: a credential change can't touch the SP
  pairing or name indexes, so it keeps both (avoiding a full-tenant `/servicePrincipals` +
  `/applications` re-scan) and drops only apps-pairing, the one app's detail, and the audit run.
- **camelCase vs snake_case.** Graph domain models (`Application`, `ServicePrincipal`, …) are **camelCase**
  to match Graph JSON directly. IPC boundary/DTO types are **snake_case**; the `bindings/` layer bridges
  via serde rename. Don't double-rename. Third case: a few core domain types (`Application`,
  `AuditItem` + its remediation/scope subtree) cross IPC **as-is** — both sides share the Rust
  definitions, so renaming a field there is a wire-format change (see `AuditItem`'s rustdoc).
- **WASM gating.** `web-rs` compiles only to `wasm32-unknown-unknown`. Server-side deps (tokio, reqwest,
  rustls, …) must be gated with `#[cfg(not(target_arch = "wasm32"))]` in shared crates, or kept
  out of `web-rs`'s dependency graph entirely.
- **Auth: lazy, shared token refresh.** Access tokens refresh lazily (~60s before expiry) behind a shared
  mutex; refresh tokens persist in the OS keyring, access tokens never touch disk. Write scopes are
  consented **incrementally** on first write. Refresh tokens are **chunked** across numbered keyring
  entries in `token_cache.rs` (Windows Credential Manager caps a blob at 2560 UTF-16 bytes) — don't
  collapse them to a single `set_password`, or Windows sign-in breaks.
  Details: [docs/architecture/auth-and-consent.md](docs/architecture/auth-and-consent.md).
- **Optional on-demand extra-scope tokens.** Admin-consent/premium scopes (SCIM, AuditLog, Policy,
  SharePoint, group membership, ARM) are **never** added to the sign-in scope set — they ride a lazily-acquired
  `ScopedTokenAdapter`, and every call must **degrade gracefully** (missing scope/license/consent →
  "unavailable" message, never a hard failure of the surrounding view). Scope→feature table + helper
  inventory: [docs/architecture/auth-and-consent.md](docs/architecture/auth-and-consent.md).
- **Silent grants can't *obtain* consent — only use it.** AADSTS65001/65004 maps to
  `AuthError::ConsentRequired`, **distinct from `InvalidGrant`** — the refresh token is still valid, so
  `access_token_for_scopes` must NOT purge it. Interactive consent goes through
  `EntraAuthService::consent_for_scopes` (UI: `request_scope_consent`). A command that wants the UI to
  show a "Grant consent" button must **pre-acquire the token with a typed `AppState::ensure_*` call** so
  `consent_required` survives the `BearerProvider` boundary (which flattens errors to `String`).
  Full flow + examples: [docs/architecture/auth-and-consent.md](docs/architecture/auth-and-consent.md).
- **Role/scope feedback rides one capability catalog.** The app spans **three independent auth planes**
  (Entra directory, Azure RBAC, Exchange Online RBAC). `azapptoolkit-core::capabilities` maps each
  privileged feature → plane, roles, scopes, remediation; three surfaces read it (reactive 403 hints,
  `RequiresRole` labels, the readiness checklist). When adding a privileged feature, add a catalog entry
  instead of hardcoding a role string. Details: [docs/architecture/auth-and-consent.md](docs/architecture/auth-and-consent.md).
- **Structured audit signals over issue-text parsing.** Audit facets/cards key off structured `AuditItem`
  fields (`risk_level`, `credential_status`, `unused`, …), never `starts_with(...)` on free-text issues.
  When adding a facet/card, prefer a structured flag on `AuditItem`.
- **Shared `audit_cancel` flag.** Both the Security-audit and Bulk-actions loops poll the single
  `AppState.audit_cancel` (a `CancelFlag` — `reset()`/`cancel()`/`is_cancelled()`, encapsulating the
  memory ordering) for early exit, so one Cancel button covers both. Any new long-running command
  must `reset()` this flag at the top — or add its own `CancelFlag` — or it will be cancelled by an
  unrelated operation (and vice versa). The Resource Access lookups (site sweep + mailbox probe) do
  the latter: both poll `AppState.sweep_cancel`, so cancelling them can't abort a concurrent
  audit/bulk run. The DR backup/restore fan-out does the same with `AppState.dr_cancel` (flipped by
  `cancel_dr`). The flag semantics (reset/cancel/independence) are unit-tested in `state.rs`.
- **Scope-aware audit risk.** A mail permission's effective risk depends on Exchange RBAC scoping:
  `score_application` reads `AppPermissions.mail_scopes`; an **empty** map (the default) scores
  everything org-wide — byte-for-byte PowerShell parity. The bulk audit swallows resolver errors (never
  under-reports); the per-app detail propagates only a *genuine* 403/consent failure and resolves
  missing-principal → `OrgWide` (unless a legacy `RestrictAccess` AAP confines it). SharePoint scoping is
  name-based (`Sites.Selected` vs every other `Sites.*`) and needs no live call. Badges render in one
  place: `web-rs/components/scope_badge.rs`.
  Full semantics: [docs/architecture/scoping-and-audit.md](docs/architecture/scoping-and-audit.md).
- **Scoped grants reuse shared cores.** Exchange: `commands::exchange::apply_exchange_mailbox_scope`
  (both the app-reg and managed-identity callers). SharePoint:
  `commands::sharepoint::convert_site_access_to_selected`. Both grant the scoped access **before**
  stripping the org-wide grant, so a failure never strands the principal with no access. The same cores
  back the per-permission "Scope…" (restrict-after-the-fact) actions. The recommended Exchange scope
  source is the **toolkit-managed mail-enabled security group** `azapptoolkit_<app_id>`
  (`group_name_for`): `list/add/remove_exchange_scope_group_members` create it
  (`New-DistributionGroup -Type Security`) and manage membership via new typed cmdlet wrappers on
  `ExchangeClient`. The grant flow is unchanged — the UI just passes the managed group's identifier
  in `groups`; because its DN is stable, scoping is adjusted by editing *membership*, not the
  (immutable) management-scope filter. Membership mutations **don't** invalidate caches (the verdict
  keys off scope name / clause count, the member list is fetched live, and a distribution group isn't
  in the app/SP indexes) — so don't add an `invalidate_app_lists` there.
  Details: [docs/architecture/scoping-and-audit.md](docs/architecture/scoping-and-audit.md).
- **Frontend reactivity is closure-based.** Leptos tracks signals read inside a reactive closure:
  `{move || sig.get()}`. Capture with `move ||` and read with `.get()`/`.with()` — a signal read outside a
  tracking scope won't update the UI. State is plain `RwSignal<T>` on a context-provided `Session`
  (no Redux/Zustand). CSS is plain global `styles.css` with BEM-ish class names (`apps-view__body`).
- **Build-time config baking.** `src-tauri/build.rs` reads `.env` at the workspace root and emits
  `AZAPPTOOLKIT_BUILD_*` via `cargo:rustc-env`. Runtime env vars override the baked-in values.
- **CSP governs the *webview*, not backend egress.** `tauri.conf.json`'s `connect-src` allowlists Graph,
  `login.microsoftonline.com`, Key Vault, and ARM (+ sovereign-cloud hosts, switched by
  `AZAPPTOOLKIT_CLOUD`). In practice every Graph/Key Vault/ARM/Exchange/SharePoint call is made from the
  **native Rust backend via reqwest**, which the CSP does not restrict — a new *backend* host needs no
  CSP change; only a direct fetch from the WASM frontend does.
- **Permissions catalog is bundled at compile time** from `azapptoolkit-permissions/data/`. Unknown
  resources fall back to a live `resolve_resource_sp()` Graph call.

## Coding fundamentals

- **Respect the codebase** — match the style, structure, and idioms of the file you're editing.
- **Minimal, focused changes** — solve the task at hand; don't refactor unrelated code or expand scope.
- **Simplicity / YAGNI** — no abstraction, configuration, or generality for hypothetical futures.
- **Comments explain *why*, not *what*** — a comment earns its place by explaining a non-obvious
  reason, constraint, or gotcha.
- **Dependencies are a cost** — prefer std lib and existing workspace deps; a new crate widens the
  audit surface, raises WASM-gating concerns, and can break `deny.toml` license policy.
- **Security first** — no secret values to disk, ever; keep tokens scoped to their resource; don't log
  secrets; preserve the incremental-consent and keyring boundaries.
- **Test what you change** — add or update tests alongside behavior changes; keep the suite green.

## Common LLM anti-patterns

- **Don't reintroduce the `rsa` crate** — it was dropped because every release (through 0.10.0-rc) carries the
  RUSTSEC-2023-0071 Marvin timing side-channel. Self-signed cert keys are generated by `rcgen` on its
  `aws_lc_rs` backend (`src-tauri/src/cert.rs`); aws-lc-rs is already in the tree via rustls. If you ever need
  RSA elsewhere, use aws-lc-rs, not the `rsa` crate.
- **Don't pin `time` back to 0.3.47.** `time` 0.3.48 (only that release) tripped E0119 against
  `cookie` 0.18.1's blanket `From` impl; 0.3.49 fixed it and is the current floor (verified by full CI
  on all three OSes with cookie still at 0.18.1). `time` is a *transitive* dep — no
  `[workspace.dependencies]` entry, no dependabot `ignore` — so let dependabot advance it; CI gates the
  cookie compatibility. (`rand` ≥ 0.9 and `sha2` ≥ 0.11 are different: those stay `ignore`d in
  `.github/dependabot.yml` because of the rsa 0.9 rand_core/digest chain.)
- **Don't double-rename camelCase ↔ snake_case.** Graph domain models use camel (no serde rename). DTOs and
  IPC bindings use snake with `rename_all`. A command can end up serializing twice.
- **Don't put WASM server deps in `web-rs`.** Server-only crates (tokio, reqwest, rustls) must be
  gated with `#[cfg(not(target_arch = "wasm32"))]` in shared crates, or kept out of `web-rs`'s
  dependency graph entirely (the OS-native keyring stores take the latter route, via
  `[target.'cfg(...)']` deps in `azapptoolkit-auth`). Check `crates/azapptoolkit-core/src/lib.rs` for examples.
- **Don't invalidate caches on the error path.** `invalidate_app_lists(...)` drops apps-pairing,
  enterprise, and `sp_index` keys — a failed write must not clear fresh data. Only call it on `Ok`.
- **Don't forget to reset `audit_cancel`** in new long-running commands. Both Security-audit and
  Bulk-actions poll a single `AppState.audit_cancel` atomic, so one Cancel button covers both.
- **Don't `cargo check` `web-rs` from the workspace root** — it's excluded from the workspace; use
  `just web-build` / `just web-test` (host-target) instead.

## Git & version control

- **Conventional Commits are required.** Format: `<type>[(scope)][!]: <description>`.
  - **types:** `feat fix docs chore refactor test build ci perf style revert deps`
  - **scopes seen in this repo:** `desktop`, `core`, `auth`, `graph`, `exchange`, `keyvault`,
    `permissions`, `ci`, `docs`.
- **Changes that port behavior from the legacy PowerShell module** should reference the source `file:line`
  range in the commit body.
- Keep history clean and changes scoped to one logical unit.
- **Shipping flow** — branch off `main` → conventional commits → push → PR → merge (merge commit) →
  delete branch + `git fetch --prune`. Claude Code users: the `/ship` skill
  (`.claude/skills/ship/SKILL.md`) runs the whole sequence.

## Verification playbook

Run the same gates CI runs, before declaring a change done. `just verify` runs steps 1–4 in order;
each is also a standalone recipe. The recipe definitions in `/justfile` are the source of truth for the
exact flags — don't hand-type raw `cargo` invocations that could drift from them.

1. **Format** — `just fmt-check` (`cargo fmt --all -- --check`)
2. **Lint** — `just clippy` (clippy with `-D warnings`; warnings are errors)
3. **Test** — `just test` (workspace test suite)
4. **Frontend** — `just web-fmt-check` + `just web-test` + `just web-build` (the excluded WASM crate;
   CI runs these in the `web` job since the workspace gates don't reach it)
5. **Dependency audit** *(optional locally; CI runs it on every PR + weekly)* — `just audit` +
   `just web-audit` (RustSec, both lockfiles) + `just deny` + `just web-deny` (license/source/bans
   policy for both trees, config in `deny.toml`).
6. **CodeQL** *(GitHub-side, not a local `just` gate)* — `.github/workflows/codeql.yml` runs the CodeQL
   advanced setup on every push/PR to `main` + weekly, for its **security queries**. Rust is
   **build-mode `none`** only. **Known limitation — don't re-chase it:** CodeQL 2.25.6's Rust extractor
   does not expand macros (proc *or* builtin) for this codebase regardless of config, so the "Low Rust
   analysis quality" annotation (~39% calls-with-call-target) is expected and unfixable today
   (github/codeql#20643, #20659). It's a non-failing annotation, not a scan failure, and CodeQL isn't one
   of the required checks. The env prep (toolchain, wasm32, dist stub, `cargo fetch`) is hygiene/future-
   proofing, NOT a quality lever — proven inert by forcing sysroot/proc-macro-server to real paths.
   Re-apply branch `ci/codeql-proc-macro-expansion` once a newer bundle ships working expansion. Config:
   `.github/codeql/codeql-config.yml` (web-rs **included**). Default setup is `not-configured`, no conflict.

For a behavior change you can't prove with a unit test, run `just dev` and exercise the affected view.

## Where the docs live

- **`README.md`** — end-user facing: features, install, updates, requirements, first-run Entra
  configuration, logs, data/privacy, security.
- **`docs/DEVELOPMENT.md`** — the single build/dev doc: build from source, prerequisites, testing,
  packaging the Windows installer, icon generation, signing keys, CI/release workflows.
- **`docs/architecture/`** — agent/developer deep-dives referenced throughout this file:
  [auth-and-consent.md](docs/architecture/auth-and-consent.md),
  [caching-and-search.md](docs/architecture/caching-and-search.md),
  [scoping-and-audit.md](docs/architecture/scoping-and-audit.md),
  [backup-and-restore.md](docs/architecture/backup-and-restore.md).
- **`docs/operator-rbac/OPERATOR-ROLES.md`** — operator/deployment guide: least-privilege Entra
  directory role, Azure custom role, and Exchange role a human operator needs.

## Keeping this file up to date

When you change a surface below, update the matching section **in the same commit (or at minimum
the same PR — docs must land before merge)**: crate/dir changes →
**Repo map**; workspace/member/toolchain/MSRV → **Repo map**, **What this repo is**; any `justfile`
recipe / build command → **Quick Reference**, **Canonical commands**, **Verification playbook**;
new command/IPC/cache/CSP/cancel flag → **Project conventions & gotchas**; CI gate or
`tauri.conf.json` bundle/updater setting → **Verification playbook**; any user-facing feature,
fix, or behavior change → an entry under `CHANGELOG.md` **[Unreleased]** (no hook watches the
changelog — it goes stale silently unless every shipping PR carries its entry).

Keep this file lean: a gotcha here is the **invariant + pointer**; mechanism detail belongs in the
matching `docs/architecture/` doc (update it in the same commit too). Advisory hooks
(`agents-md-staleness-check.sh`, `docs-staleness-check.sh`, `command-parity-check.sh`) remind you
but **never block**.
