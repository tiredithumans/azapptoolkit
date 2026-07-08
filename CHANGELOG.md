# Changelog

All notable changes to azapptoolkit are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.19.1] - 2026-07-07

### Fixed

- **Security-tab export no longer freezes the app.** Exporting an audit (CSV,
  JSON, or HTML) from the Security workbench blanked and locked up the whole
  window on Windows, requiring a force-quit. The Export control was a Thaw `Menu`
  overlay, and opening the native "Save file" dialog from inside that teleported
  overlay raced its teardown and wedged the webview. It's now a plain-DOM
  disclosure dropdown that closes before the dialog opens.

### Changed

- **Consistent "Export ▾" dropdown across every list.** The App Registrations,
  Enterprise Applications, and Managed Identities tabs replaced their inline
  "Export CSV" / "Export JSON" buttons with the same compact "Export ▾" disclosure
  the Security tab now uses (a shared `ExportMenu` component). No behaviour change
  beyond the surface — the same plain-DOM control on every tab.

## [0.19.0] - 2026-07-07

### Added

- **Create enterprise applications from the Microsoft Entra gallery.** The
  renamed **New application** button (Enterprise Applications header + the Home
  Overview card) now opens a chooser — **Browse the Entra gallery** or **Create
  your own** — mirroring the Azure portal. "Browse the gallery" searches the
  `applicationTemplates` catalog and instantiates the picked app (e.g. Salesforce,
  ServiceNow) into a paired app + service principal; single sign-on is then
  finished on the app's SSO tab. "Create your own" opens the existing custom
  SAML/OIDC SSO wizard. New backend: `search_application_templates` +
  `create_gallery_application`.

### Changed

- **Renamed "New SSO application" → "New application".** Matches the Azure portal
  and the app's "New app registration" convention; it now covers both the gallery
  and custom creation paths (see Added).

- **Home Overview — card action buttons align to a common baseline.** Every card's
  action(s) now sit in a consistent row pinned to the card bottom, so the buttons
  line up across the row instead of floating at content-dependent heights.
- **Left nav slimmed to navigation; account actions moved to the tenant pill.**
  The signed-in tenant pill (top right) is now an account menu: clicking it drops
  Access Readiness, Settings, Cache diagnostics, Check for updates, Sign Out, and
  the app version — the cluster that used to sit at the foot of the left rail. The
  rail is now purely Inventory / Security / Operations, and the account actions
  stay reachable from the always-visible pill even when the rail collapses. The
  Refresh-token control stays beside the pill.
- **Access Readiness — removed the standalone "Re-check" button.** Refreshing your
  token (the top-right control) now re-runs the readiness check in place, since a
  refresh is exactly when your active roles change — one action instead of
  refresh-then-re-check.

- **Global search is now a records-only finder.** The command palette (nav/tool
  actions that appeared as a "Commands" group in the results) was removed now that
  the nav rail and account menu cover navigation — so searching for an app is no
  longer buried under command rows. Records (App Registrations / Enterprise
  Applications / Managed Identities) stay keyboard-navigable, and Cmd/Ctrl-K still
  focuses the bar.

### Fixed

- **Global search hint no longer shows a Mac-only shortcut or truncates.** The
  placeholder dropped the `⌘K` reference (the focus hotkey still works with
  Ctrl/Cmd on every platform) and is now a short "Search apps by name or GUID…"
  tip that fits the field.

## [0.18.1] - 2026-07-07

### Changed

- **Settings — organized into three tabs.** The per-tenant operator defaults are
  now grouped under **App Registration Defaults** (default owners), **Enterprise
  Application Defaults** (default owners + SSO notification emails), and **Naming
  Defaults** (Key Vault secret, management scope, and mail-enabled security group
  name patterns), replacing the single long scroll. One **Save defaults** button
  still persists every tab at once.
- **Left nav — removed the "More" dropdown.** Cache diagnostics and Check for
  updates are now direct items in the account block (one click instead of two);
  the app version shows as a line beneath Sign Out.

## [0.18.0] - 2026-07-07

### Changed

- **Exchange scoping — configurable scope + group naming, applied to all scoping.**
  Two per-tenant naming patterns on the **Settings** page now drive the names the
  toolkit creates when it scopes an app's mailbox access via Exchange RBAC:
  - **Management scope naming** (default `app_scope_{appId}`) — previously wired
    only into the legacy-AAP migration, this pattern now governs the management
    scope name for **every** Exchange scoping path, including fresh scoped-mailbox
    grants from the Grant-access wizard. The old migration-only "Exchange
    migration" settings section is replaced by this clearer one.
  - **Mail-enabled security group naming** (new, default `app_scope_group_{appId}`)
    — the toolkit-managed scope group whose membership defines which mailboxes an
    app can reach is now configurable too. **Note:** the built-in default changed
    from `azapptoolkit_{appId}`; a scope group already created under the old name
    won't be auto-discovered unless you set the group pattern to
    `azapptoolkit_{appId}`.
- **Scope wizard — clearer managed-group status.** Step 2's mailbox panel now
  badges whether the scope group already **exists** (with its live member count)
  or **will be created** on first add — the previous heading implied the group
  existed even when it didn't — and lists the group's current members so it's
  clear exactly which mailboxes the scoping covers.

## [0.17.0] - 2026-07-06

### Added

- **App registration — editable Internal notes.** The Overview tab now shows an
  **Internal notes** field (Microsoft Graph `application.notes`, the same
  free-text property the Entra portal surfaces under *Branding & properties*).
  It reads in the overview and is editable in the same **Edit → Save** form as
  display name / sign-in audience / description; clearing the box removes the
  note. Saving reuses the existing `update_application` path, so the cached
  detail is refreshed automatically.

## [0.16.0] - 2026-07-06

### Added

- **Settings page — per-tenant operator defaults.** A new **Settings** entry in
  the account section of the nav configures defaults that are stored locally
  (per tenant, in `settings.json`) and reused so you don't re-enter them each
  time:
  - **Default owners** for app registrations and enterprise applications.
    Each Owners tab gains an **"Add Default Owners"** button that adds them in
    one click — additive (it skips owners already present and never removes).
    Enterprise-app owners are users only, matching Entra's rules.
  - A **default SSO notification-email list** that seeds the notification field
    when creating a new SAML SSO configuration (only when the field is empty, so
    it never clobbers an edit).
  - A **management-scope-name pattern** (with an `{appId}` placeholder) that
    becomes the default name when migrating a legacy Application Access Policy —
    still overridable per migration; blank falls back to `app_scope_<AppId>`.
  - A **Key Vault secret-name pattern** (with an `{appId}` placeholder) that
    names the vault secret on rotation; defaults to `secret-<AppId GUID>`. (KV
    secret names allow only letters, digits, and dashes — no underscores — so the
    prefix is `secret-`.) A per-app remembered name still wins.
  - A **distribution-list search** on the SSO notification-email default: search
    mail-enabled groups / distribution lists and add a team address (e.g.
    `sso-alerts@contoso.com`) without typing it. (Owners stay users-only — Graph
    rejects groups as service-principal owners.)

- **Key Vault vault picker with discovery + per-app memory.** The rotation
  dialog and the Key Vault browser show the vaults you can access (discovered via
  Azure Resource Manager) in a **searchable, filter-as-you-type list** beside the
  vault field — type to filter the full set (with a match count), or enter any
  name directly. When you rotate an app registration's secret into a vault, that
  vault (and secret name) is **remembered per app**, so the next rotation
  pre-selects it; a tenant-level default vault fills in for apps with no history
  yet. Only names are stored, never secrets.

### Changed

- **Access Readiness now checks Azure RBAC accurately instead of always "?".**
  It enumerates your **direct** Azure role assignments across your subscriptions
  and reports **✓ Have** when a matching assignment is found (with conservative
  supersets — e.g. Owner/Contributor satisfy "Reader", but control-plane roles do
  **not** stand in for Key Vault data-plane access). Because group-inherited roles
  aren't visible to the per-user lookup, it never downgrades to a false "Missing":
  without a confirmed direct assignment it stays "?" with guidance. Falls back to
  the previous "?" + nudge when Azure (ARM) access hasn't been consented.

### Fixed

- **Access Readiness now reports Exchange Online RBAC accurately instead of
  always "? Unknown".** The `exchange_rbac` capability was tagged as an
  unimplemented "Exchange probe" whose role verdict was hardcoded to Unknown, so
  an operator with an **active** Exchange Administrator role still saw "?".
  Exchange Online RBAC is activated through the Entra *Exchange Administrator*
  directory role (roleTemplateId `29232cdf-…`), which `/me` already returns — so
  the capability is now detected like every other directory-role capability
  (matched by template id, with Global Administrator as a superset). An active
  Exchange/Global Admin now reads **✓ Have**; PIM-eligible-but-inactive reads
  **✗ Missing**. The unused `RoleDetect::ExchangeProbe` path was removed. Azure
  RBAC remains "?" (it's genuinely per-subscription/-vault and not enumerable
  from the directory), but its detail text now explains that and points to
  Resource Access rather than reading like a failure.

### Changed

- **The "Readiness" tab moved next to Sign Out and is renamed "Access
  Readiness".** It reports the *signed-in operator's own* permissions, not the
  org's apps, so it now lives in the account block at the bottom of the nav rail
  (directly above Sign Out) instead of the Security group. The page heading, tab,
  and top-bar crumb all read "Access Readiness" consistently (the crumb group is
  now "Account").

- **Legacy Application Access Policy migration: the management-scope name now
  defaults to `app_scope_<AppId GUID>` and is customizable.** Previously the scope
  reused the mail-group's `azapptoolkit_<AppId>` name; it's now named separately
  (`app_scope_<AppId>`) so a scope and its backing group never collide, and the
  migration UI exposes an optional "Management scope name" field (blank ⇒ the
  default). The override applies to single-app migrations; a whole-tenant run
  always derives the per-app default so scopes can't clash.

## [0.15.1] - 2026-07-05

### Fixed

- **CI: the GitHub Pages demo deploy no longer flakes red on a transient backend
  error.** `actions/deploy-pages` intermittently reports "Deployment failed, try
  again later" on its first status poll (~1 run in 30) even when the build and
  uploaded artifact are fine; a manual re-run always cleared it. `pages.yml` now
  retries the deploy step once (after a short pause) via `continue-on-error` + a
  conditional second attempt, so the transient self-heals. A genuinely persistent
  failure still fails the job (the retry has no `continue-on-error`).

### Changed

- **Perf: the security audit no longer fetches every service principal twice.**
  `run_audit` already enumerates the whole tenant's service principals once (the
  `sp_index` scan that drives the SP-only scoring phase), and that projection
  (`id,appId,accountEnabled,…`) is a superset of the two fields per-app scoring
  reads. The run previously *also* issued a batched lean-SP prewarm — roughly one
  `$batch` POST per 20 app registrations (~250 extra POSTs on a 5 000-app tenant)
  — re-fetching the same directory objects. It now seeds the audit's lean SP
  cache from the index in memory (new `GraphClient::seed_lean_sps_from_index`),
  cutting those POSTs to zero and reducing 429 pressure on large tenants. App
  registrations absent from the index are left cold, so a per-app lean lookup
  still resolves them (an SP-less app caches `None`; a truncated index falls back
  to a real GET) — identical to the prior failed-batch degradation. Removed the
  now-unused `GraphClient::prewarm_service_principals_lean`.

- **Docs: trimmed `AGENTS.md` over-prompting.** Removed the generic "Coding
  fundamentals" bullets that restated Claude's default behaviour (style-matching,
  scope discipline, comments-explain-why, keep-the-suite-green), keeping only the
  security-critical + dependency-cost invariants that are specific to this repo;
  deleted the duplicate CSP rule from **Common patterns** (it survives in
  **Conventions & gotchas**); and collapsed Verification-playbook steps 1–4 into a
  single pointer to `just verify` so the section leads with the CI-only detail that
  isn't obvious. No behavioural rules changed — pure dead-weight removal.

- **CI: the browser GUI tests (`just web-itest`) run far faster** via two changes
  to `apps/desktop/web-rs`:
  - **Strip debuginfo from the test wasm** — `[profile.test] strip = "debuginfo"`.
    Each integration-test wasm was ~1.9 GB, ~96% of it DWARF debuginfo that
    wasm-bindgen-test-runner had to decode before every run (~24s/binary). Stripping
    it cuts each binary to ~8–52 MB so the decode is near-free. The runner already
    strips debuginfo from the served module, so in-browser behaviour and panic
    messages are unchanged (only already-unusable wasm stack frames lose line info);
    scoped to the `test` profile, so `just dev` / `web-build` keep their debuginfo.
  - **Group the 21 one-file-per-binary tests into 3 shard binaries**
    (`tests/gui_N.rs` pulling `tests/gui/<view>.rs` modules), so Chrome is booted 3×
    instead of 21×. A *single* merged binary was tried first but its ~78 MB served
    wasm exceeds what headless Chrome will instantiate (timed out even at 120s); each
    shard is kept under ~52 MB. Tests in a shard share one page and rely on Leptos
    disposing each mounted view on unmount for isolation (the runner scrapes results
    from the DOM, so `reset()` must NOT clear the body). `WASM_BINDGEN_TEST_TIMEOUT=60`
    (justfile) gives the larger shards load headroom over the runner's 20s default.

## [0.15.0] - 2026-07-04

### Added

- **Key Vault reverse lookup** — a third tab in Resource Access sweeps every reachable Key Vault's
  direct Azure RBAC role assignments and shows which principals (apps, managed identities, users)
  hold which role on which vault. Filter by principal to see the vaults an app can reach, or by
  vault to see who can touch it; broadly-privileged roles (Owner, Key Vault Administrator, …) are
  flagged. Progress-streamed, cancellable, and backend-cached like the Sites sweep; reads use the
  signed-in user's Azure Reader rights (ARM scope, consented on demand). Complements the existing
  per-managed-identity Azure-roles view (the forward direction).

### Changed

- **Release/CI hardening:** the `release.yml` `guard` job now runs `cargo audit` against the
  workspace-excluded `web-rs` lockfile too (via `just web-audit`), so a fresh advisory in the
  IPC-privileged frontend tree fails fast before the build matrix spends minutes.
- **Developer tooling:** new `just verify-full` recipe runs full CI parity locally — `just verify`
  plus both RustSec scans, both `cargo deny` policies, and the browser GUI tests (`web-itest`). The
  agent instructions (`AGENTS.md`) were put on an invariant-plus-pointer diet with deep detail moved
  into `docs/architecture/` (new `frontend-workspace.md`, `release-updater-demo.md`), and the
  contributor hooks/skills were realigned to the actual release, verify, and branch-protection flow.
  No application behavior change.

## [0.14.0] - 2026-07-04

### Changed

- **CSS token housekeeping** (internal hygiene, no visual change): finished the
  design-token migration in `styles.css` — dropped the dead compatibility aliases
  (`--shadow-sm`→`--shadow-2`, `--shadow-md`→`--shadow-4`, `--surface-elevated`→
  `--surface-raised`) after repointing their uses, and swept hardcoded 4px-grid
  spacing and 12px font-sizes onto the existing `--space-*` / `--text-*` tokens
  where a token exactly equals the value. Pixel-identical output.
- **Design polish — iconography pass, posture-card hierarchy, labeled compare panes**
  (visual only, no behavior change). Chrome buttons now draw from the shared `Icon`
  catalog so one action reads the same everywhere: the dock chip close (`×`) and
  workspace pane close (`✕`) — two different glyphs for the same "close" — collapse
  onto one `Close` icon; the pane "⤢ Full" control becomes a `Maximize` icon (new
  catalog entry); "Export ▾" becomes **Export** + a `ChevronDown`; and the "+ New
  app" / "+ New SSO application" / "New app registration" primary buttons lead with a
  `Plus` icon (label kept, `+` prefix dropped). The Home **Security Posture** card is
  reworked from a flat 9-metric grid into a hierarchy — a large **Critical / High /
  Medium** severity row above a ranked **Top findings** list (tone dot · title · count
  · chevron) that reuses the Security workbench's impact ordering (`GROUP_CATALOG`) and
  the shared `posture_counts`, so it rhymes with the pane it opens (same drill targets).
  Workspace compare panes get a real title bar — the dock chip's kind glyph + the item's
  live name — so a 2-up side-by-side labels which pane is which, and the overlay panes
  lift onto a deeper `--shadow-16` layer. A button-ladder note is added to `styles.css`.
- **Shell refresh — the top bar earns its keep and the nav rail regroups** (muscle-memory
  reorg, no feature change): the previously-empty top-bar thirds now carry the
  persistent app-level anchor — the left shows the active view's nav-group crumb +
  title (mirrors the page `SectionHeader` so identity survives content scroll) and the
  right adds a signed-in **tenant chip** (org name + primary verified domain, previously
  buried in the nav user block) plus the **Refresh token** affordance (silent
  `refresh_session` → interactive `reauthenticate` fallback, unchanged behavior). The
  left navigation is regrouped into three labeled sections — **Inventory** (Home / App
  Registrations / Enterprise Applications / Managed Identities), **Security** (Security /
  Permission Tester / Resource Access / **Readiness**, promoted up out of the user block
  since it's a real page), **Operations** (Bulk Actions / Disaster Recovery / Key Vault).
  The signed-in user block slims to identity + Sign Out with an overflow "…" popover
  (closes on outside-click / Escape) holding the low-frequency utilities — cache
  diagnostics, check-for-updates, and the version string.
- **UI consistency pass — one page-header, one loading, one failure grammar** (design
  unification; visuals ≈ unchanged): every page now uses the single `SectionHeader`
  (uppercase category eyebrow + title) — the App Registrations and Enterprise
  Applications views moved off the old `.view-header`, and `ListScaffold` lost its
  `title`/`actions` props so the list card starts at its search box instead of
  re-rendering the page title a second time (the `.view-header*` and
  `.app-list__header` CSS is deleted). Loading fallbacks follow one rule — skeletons
  for content regions, spinners only for in-button busy: the Home dashboard cards and
  the detail tabs (Authentication / Expose an API / Conditional Access / Activity /
  Federated credentials) now fall back to a `DetailSkeleton`/`SkeletonList` matching
  the region instead of a centered spinner. Failure states collapse onto two
  primitives: `DetailLoadError` is now the universal "section failed → message +
  Retry" block (detail panes, all three list views, and the dashboard cards route
  through it), and a new `Callout` (info/ok/warn/danger) is the single home for the
  scattered `.alert` boxes, adopted at the consent prompts and audit notices.
- **Frontend view code split for maintainability** (no behavior or DOM change): the
  enterprise-application detail pane finished its module-directory split (Overview /
  Owners / Credentials / the small Provisioning-Activity-CA panels moved out of
  `mod.rs`); `resource_access_view.rs` became a `resource_access/` directory (Sites
  and Mailboxes panels in their own files); the lazily-loading Usage panel moved out
  of `permissions_tab.rs`; the three list views' identical export snapshot + double-
  submit guard + toast logic collapsed into one `use_list_export` hook and the
  Managed Identities list now renders through the shared `ListScaffold` like the
  other two; and the duplicated `ls_get`/`ls_set` localStorage helpers plus the
  recurring two-field IPC arg shapes were single-sourced (`util.rs`,
  `bindings/common.rs`). The dialog-dense `credentials_tab`/`expose_api_tab` splits
  were deliberately left for later — extracting their dialogs would thread 10+
  signals through props and touch the Suspend-reset footgun for no real gain.
- **The desktop backend's largest command modules were decomposed** (no behavior,
  wire, or cancel/progress change): `run_audit`'s ~380-line orchestrator split its
  best-effort tenant-wide prefetch blocks into named `async fn`s and bundled
  `score_one`'s ~10 parameters into one `Arc<ScoreCtx>` (each scoring task now clones
  one `Arc`, not a dozen values); the six sequential bulk commands share one
  `run_bulk_seq` scaffold (the AGENTS.md-pinned "per-app cores take `State`, so these
  stay sequential" invariant kept — plus the leftover fixed 50 ms create-loop pause
  removed); `commands/sso.rs` split into `sso/mod.rs` + a self-contained `sso/claims.rs`
  claims-policy codec, and `get_sso_config`'s previously untested service-principal
  field spelunking became a tested `extract_sp_sso_fields`; the seven
  `AppState::ensure_*_token` probes collapse onto one private `ensure_scoped_token`
  core (centralizing the hand-maintained CAE/adapter pairing); and the five SharePoint
  pre-acquire blocks share a `sharepoint_client_checked` helper mirroring
  `exchange_client_checked`.
- **Internal: the audit engine is now a module directory** (`azapptoolkit-core::audit`
  split into `permissions` / `types` / `scoring` / `credentials` submodules with a
  re-exporting `mod.rs`) — no behavior or wire-format change; every public path and
  all 124 characterization tests are unchanged.
- **The capabilities catalog pairs each directory-role name with its immutable
  `roleTemplateId` in one entry** (previously two index-aligned slices whose
  alignment only a test enforced — the shape the v0.12.1 "Role missing" fix worked
  around). Misaligned name/id pairs are now unrepresentable; display consumers use
  the new `Capability::role_names()`. Also removed two dead public helpers
  (`capabilities_for_plane`, `ScopeKind::target_noun`) and derived the cache's
  per-kind bucket array size from `CacheKind::ALL` instead of a hand-synced literal.
- **Graph client restructured for maintainability** (no behavior change): the
  transport/retry core, pagination helpers, and request/patch body types moved out
  of the 1,150-line `client.rs` into `client/transport.rs` and their domain modules
  (all import paths preserved via re-exports); the 2,700-line test monolith split
  into per-domain files. The two near-identical service-principal batch-prewarm
  functions now share one core, and the dead `GraphError::Url` variant was removed.
- **The auth service is now a module directory** (`service/{wire,loopback,scopes}.rs` +
  a ~900-line core): the AAD wire protocol (error classification/redaction, claims
  decoding), the loopback redirect listener, and the per-feature scope catalog each
  live in their own file. Pure code motion plus one shared `ensure_same_identity`
  helper for the tid+oid cache-safety check `consent_for_scopes` and `reauthenticate`
  previously duplicated. `AccessToken` also dropped its never-used serde derives, so
  the memory-only token contract is now compiler-enforced.
- **Exchange client restructured the same way** (no behavior change): the 1,136-line
  `client.rs` split into `client/transport.rs` (envelope POST + retry loop with the
  bodyless-403 diagnostics capture), `client/rbac.rs` (service principals, scopes,
  role assignments, legacy AAP, verification), `client/groups.rs` (recipient groups
  + the managed scope group + the OPATH filter builder), and `client/tests.rs`; the
  four optional `Get-*` lookups now share one `first_optional_as` projection, and an
  empty single-object cmdlet result is reported honestly as a protocol error instead
  of a fabricated HTTP-200 API error. Key Vault dropped a dead transport parameter
  and its unused `SecretProperties` alias, and both the ARM and Key Vault paging
  loops gained a defensive page cap against self-referencing `nextLink`s.
- **The frontend's tenant-scoped UI state resets structurally on tenant switch.**
  Every lifted search, facet, bulk selection, pending deep-link tab, and shell
  dialog flag now lives in one `TenantScopedUi` substruct on `Session` whose
  `reset()` sits directly under its field declarations, and `set_active_tenant`
  resets the whole group in one call — previously each of ~18 fields had to be
  remembered individually there, and two dialog flags had already been missed
  (fixed in the prior release wave). A pinning test asserts every field returns
  to its sentinel. No behavior change beyond that structural guarantee.

### Fixed

- **Interactive sign-in no longer hangs when the browser opens a speculative
  connection to the loopback listener.** The redirect listener previously accepted
  exactly one connection and read one TCP segment; a browser preconnect or a stray
  `/favicon.ico` probe could consume that slot and the real OAuth redirect was lost
  until the 300s timeout. It now loops — non-redirect requests get a 404 — and reads
  to the end of the request head instead of assuming a single segment.
- **Azure Resource Manager paging now refuses off-origin `nextLink`s** before the
  bearer token is attached — the same guard the Graph and Key Vault clients already
  had. The origin check (including its embedded-credentials rejection, which the Key
  Vault copy had missed) is now single-sourced in `azapptoolkit-core::net` so the
  three clients can't drift again.
- **Throttled one-shot scoped Graph calls (sync jobs, directory audits, sign-in
  activity, claims-policy writes) now surface as `throttled`/retryable** instead of a
  generic Graph error, so the UI's retry affordance and backoff messaging apply. The
  one-shot transport still deliberately skips the retry loop.
- **Key Vault secret reads can no longer leak the secret via `{:?}` debug
  formatting** — `SecretValue` got the same redacted `Debug` its write-side twin
  gained in v0.12.0.
- **Interactive sign-in / consent / re-authenticate no longer block an async worker
  on the OS-keyring write** (the silent-refresh path already ran it off-thread); the
  four flows now share one post-token-exchange persistence helper.
- **A dead session during DR backup/restore now offers the Re-authenticate toast
  action** instead of a dead-end error banner (the DR view's hand-rolled handlers
  bypassed the central error sink).
- **Switching tenants closes the create-app dialog and SSO wizard** — previously a
  tenant switch mid-dialog left the stale form floating over the new tenant's Home.

## [0.13.0] - 2026-07-03

### Changed

- **The Security tab is now a findings-first workbench.** The old audit pane had three
  competing controls for the same two filter signals — a severity tab bar, an 11-chip
  finding drawer, and an 11-card clickable scorecard — with remediation buried per-row
  in one big table. The redesign gives one clear path: a read-only posture strip
  (severity counts + Run/Cancel/Export/progress/consent) above four sub-tabs.
  **Findings** (the new default) is a ranked, grouped list of finding categories —
  worst-impact first, healthy/scoped configurations demoted to a collapsed section —
  where expanding a group shows the affected principals with per-row Open/Fix, a
  multi-select, and a bulk bar offering exactly the fix that pairs with that group's
  rule ("Fix all N" pre-selects every eligible app; typed confirmations and target
  forms still gate execution). This also retires the old mismatch where the
  Over-privileged filter offered the Remove-redundant bulk fix (a different rule) —
  Redundant permissions now has its own group, and new group fixes cover ownership
  (Add owner) and unused apps (Disable sign-in / Delete). **All apps** keeps the
  ranked score table with a single severity filter + search for triage. Credential
  expiry and Delegated grants stay as sibling tabs. Home's Security Posture card keeps
  its metrics but now shares the workbench's count code (the numbers can never
  disagree), and its drills route severity clicks to All apps and finding clicks to
  the matching expanded group. Saved views for the audit were removed along with the
  filter drawer (any stored `audit` saved views are simply ignored).

### Added

- **Two new one-click audit remediations: "Add owner" and "Disable sign-in".** The
  ownership finding (no owners / single owner) now carries an **Add owner** Fix — a
  guided directory-search modal that adds the picked user via the existing owner
  mutation (purely additive, so it can't break a working sign-in). Apps flagged
  **Unused** carry a **Disable sign-in** Fix that sets `accountEnabled: false` on the
  app's service principal — reversible any time from the enterprise app's Overview
  toggle, which is why a plain confirm suffices. Both follow the audit's safe-fix
  contract: the backend re-resolves live state before acting (disable-sign-in resolves
  the SP fresh from the application; an app with no SP reports not-found), and both
  clear the row's Fix button on success. Previously the ownership and unused findings
  were advisory-only — 12 of ~18 finding types had no remediation path at all; this
  starts closing that gap ahead of the findings-first Security tab revamp.

- **An inline callout points at scoping when an identity holds org-wide access.** On the
  Enterprise Application and Managed Identity Permissions tabs — the surfaces where a
  foreign-tenant (no local app registration) principal gets scoped — a warning callout
  now names the held org-wide mail/SharePoint permissions up front and its "Scope…"
  button opens the Grant-access wizard pre-seeded, the same contract as a held row's
  "Scope…". Previously the Exchange/SharePoint scoping sections rendered further down
  the tab and mail had no per-row scope entry, so the path was easy to miss.

- **The Security Audit now covers principals without a local app registration** —
  foreign-tenant (OIDC/multi-tenant) enterprise applications, managed identities, and
  orphaned service principals. Previously the audit enumerated only `/applications`, so
  a foreign app holding org-wide `Mail.*` or `Sites.*` produced no finding at all. Such
  principals are scored from their *granted* Graph application roles (plus
  admin-consented delegated scopes): permission risk, admin consent, disabled-SP,
  org-wide mailbox/SharePoint advisories, and the unused-app signal apply; credential
  and manifest rules don't (those live on the application in its home tenant). The
  noise filter — only SPs holding at least one Graph application grant — keeps the
  hundreds of grantless first-party Microsoft SPs out. Rows carry a new additive
  `principal_kind` field and a "No app registration" finding chip; their Open
  deep-links to the Enterprise Application / Managed Identity detail, and their
  one-click mailbox/SharePoint Fixes route to the SP-only scoping commands (the
  app-registration remediation wrappers would 404). SP rows are excluded from the bulk
  selection — bulk actions target app registrations. The extra coverage costs no new
  per-item Graph traffic: it reuses the tenant-wide grants and app-role reads the run
  already made. CSV export gains a trailing `PrincipalKind` column, and granting a
  permission to a bare SP now invalidates the cached audit run.

## [0.12.1] - 2026-07-02

### Fixed

- **Readiness no longer reports an active role as missing in tenants with legacy role
  names.** The checklist matched directory roles by display name, but the `directoryRole`
  objects in long-lived tenants carry legacy names — Graph names the SharePoint
  Administrator role "SharePoint Service Administrator" (documented), Global
  Administrator historically "Company Administrator" — so an **active** role could show
  "Role missing" no matter how often the token was refreshed. Roles are now matched by
  their immutable `roleTemplateId` (with a display-name fallback), so the SharePoint
  site access row — and every other directory-role check — recognizes the activated
  role regardless of what the tenant calls it.
- **Global search finds anything by any of its GUIDs.** Pasting a full GUID into the
  top-bar search only probed two of the four identities (app registration by appId,
  service principal by object id) — so an Enterprise Application was unfindable by its
  Application ID (and an app registration by its object id), returning nothing at all
  for a gallery/third-party app with no local registration. The GUID branch now probes
  all four in parallel: app registration by appId *and* object id, service principal by
  object id *and* appId.
- **The copy confirmation now covers every copy button.** v0.12.0's "Copied" badge only
  landed on `CopyableId` (MI detail fields, DR view, credential-table ID cells) — the
  detail-pane header's app-id copy button and the SSO summary fields still gave no
  feedback. The badge behavior is extracted into a shared `CopyIconButton` and all
  icon-button copy affordances render it.

### Changed

- **The compare gesture hint is visible in the dock itself.** Once a second item is
  open, the dock shows an inline "Ctrl/Cmd-click a chip to compare" hint (hidden while
  a side-by-side compare is active) — the hover tooltip alone required knowing to hover.
- **Dependency refresh.** tauri 2.11.3 → 2.11.5, leptos 0.8.19 → 0.8.20,
  anyhow 1.0.103, time 0.3.53 (Dependabot), and the `taiki-e/install-action` CI pin
  → 2.82.7. Two fresh `quick-xml` advisories (RUSTSEC-2026-0194/0195 — DoS-class
  parser issues, transitive via `plist` → `tauri`, which parses only the app's own
  bundle metadata) are triaged as documented ignores until `plist` ships on
  quick-xml 0.41+.

## [0.12.0] - 2026-07-01

### Fixed

- **Failed loads offer an in-context Retry.** The tenant-wide audit dashboards
  (Credential expiry, Consent grants, Application permissions) and the Managed
  Identities list now show a Retry button with a "Failed to load: …" message instead
  of a dead-end error, matching the App Registrations and Enterprise Applications
  lists — so a transient 429/network failure recovers in place.
- **An invalid SAML certificate subject fails before the app is created.** SAML setup
  now rejects a certificate subject that doesn't start with `CN=` up front (a typed
  validation error, like the reply-URL check) instead of failing at the
  certificate step — after the app and service principal already exist — and leaving a
  half-configured app. The rotate-certificate command gets the same friendly rejection.

### Security

- **Rotated client secrets are zeroized in backend memory.** The rotate-into-Key-Vault
  flow holds the freshly minted secret in exactly one buffer and wipes it on drop
  (`SecretSetRequest` now zeroizes its value — covering manual `kv_set_secret` writes
  too — and redacts it from `Debug` output), matching the existing access-token and
  generated-certificate handling.

### Changed

- **Copy buttons confirm the copy.** `CopyableId` (the copy-to-clipboard GUID fields in
  detail panes and table cells) shows a brief "Copied" badge after a click, instead of
  no feedback at all.
- **The open-items compare gesture is discoverable.** Dock chips' tooltip now reads
  "click to focus · Ctrl/Cmd-click to compare side-by-side" — the 2-up compare was
  previously invisible unless you already knew the shortcut.
- **Admin-consent grants resolve resource service principals in one batched read.**
  "Grant admin consent" (single, bulk, and DR-restore paths) pre-resolves every declared
  resource's service principal via Graph `$batch` and the shared Permissions cache instead
  of one sequential lookup per resource — on a cold cache an app with N resources costs
  1 POST, not N GETs. A batch failure degrades to the existing per-resource lookups;
  per-resource failure reporting is unchanged.

## [0.11.0] - 2026-06-30

### Added

- **Grant a custom app registration's app role to a managed identity (or another app) from
  the UI.** The "Grant access" wizard's resource picker now lists the tenant's own app
  registrations that expose application app roles — a new **"Tenant app registrations"**
  group below the bundled Microsoft APIs — so a managed identity (or an app registration)
  can be granted a custom API's app role without hand-crafting the assignment. The backend
  grant path already accepted any resource; this surfaces those resources in the picker
  (`list_app_role_resources`, owner-scoped to the tenant).

### Fixed

- **The in-app update changelog renders as formatted text, not raw Markdown.** The
  "Update available" splash showed the release notes as a raw `**…**` / `- ` / `###`
  Markdown dump in a monospace block. A small renderer (`components/changelog_notes.rs`)
  now formats the subset our changelog uses — headings, bullet lists (nested +
  wrapped), bold, inline code, and links — so the notes read like the GitHub release.

### Changed

- **Trimmed redundant CI work.** CodeQL no longer runs on pull requests — it's not
  a required check and the current extractor doesn't expand Rust macros, so PR-level
  alerts add little; it still runs on `main` (Security tab) and the weekly re-scan.
  The weekly `ci.yml` cron now runs only the dependency-advisory jobs (`cargo-audit`
  / `cargo-deny`) instead of re-running the full 3-OS build matrix. Every job now has
  a `timeout-minutes` backstop so a hung runner is killed in minutes, not hours.
- **Docs-only changes skip the build matrix.** A new change-detection job classifies
  each PR/push; when only docs change (Markdown, `docs/`, `LICENSE`, `.claude/`), the
  compile/test/lint jobs skip their work while still reporting their required status
  checks as green — so a docs-only PR goes green in seconds instead of ~12 minutes
  without being blocked by pending required checks. CodeQL also skips docs-only pushes.

## [0.10.0] - 2026-06-29

### Added

- **Open-items workspace — full-width lists + a shared "working set" dock.** The
  App Registrations, Enterprise Applications, and Managed Identities lists are now
  full-width; selecting a row opens it in a workspace overlay on top, rather than
  a cramped side detail pane. A persistent **Open** dock (a strip of chips,
  shared across all three entity types) holds everything you've opened — your
  working set — so you can switch between items without re-finding them, and pin
  **two side-by-side to compare**. Chip click shows an item full-width;
  `Cmd`/`Ctrl`-click (or a second pin) opens it alongside the first; `Esc` — or
  navigating to another view from the nav rail — collapses the workspace back to
  the list; the chip × closes an item and a **Close all** button clears the whole
  working set. The dock persists across navigation (Home, Security, …) and resets
  on tenant switch.

### Fixed

- **Detail-pane tabs are reachable on narrow panes.** Thaw's `<TabList>` (the App
  Registration / Enterprise / Managed Identity detail tabs) doesn't scroll, so
  when the tab row was wider than the pane — a narrow screen, or the many-tab App
  Registration detail — the overflowing tabs were clipped by the pane's
  `overflow-x: hidden` and couldn't be reached. The tab strip now scrolls
  horizontally (`.thaw-tab-list { overflow-x: auto }`).

### Changed

- **Mobile-friendly responsive layout.** The web UI (and the GitHub Pages demo)
  now reads well on a phone: fixed a page-level horizontal-scroll bug where a
  wide child (data table, long id) could stretch the main column past the
  viewport (`.shell__main` now pins `min-width: 0`); the list/detail split stacks
  with the detail given the larger share instead of an even 50/50; dashboard
  cards drop to a single overflow-proof column; and a new ≤560px breakpoint
  narrows the icon rail, tightens padding, near-full-bleeds dialogs, and wraps or
  stacks dense headers, action clusters, and editor grids.

- **CI: bump SHA-pinned GitHub Actions to their latest releases.**
  `Swatinem/rust-cache` (`v2` → `v2.9.1`) and `taiki-e/install-action`
  (`v2.82.3` → `v2.82.5`) across `ci.yml`, `codeql.yml`, `pages.yml`, and
  `release.yml`. All other actions were already at their latest release SHA;
  `dtolnay/rust-toolchain` stays pinned to the MSRV `1.96.0` and
  `github/codeql-action` to `codeql-bundle-v2.25.6` (both intentional pins).

## [0.9.0] - 2026-06-26

### Added

- **macOS and Linux release packages.** The release workflow now builds for all
  three platforms on their native runners: Windows (MSI + NSIS, unchanged), macOS
  (`.dmg` + auto-update payload, Apple Silicon), and Linux (`.AppImage` + `.deb`).
  The in-app auto-updater covers all three — `latest.json` now carries
  `darwin-aarch64` and `linux-x86_64` alongside `windows-x86_64`. macOS builds are
  unsigned for now (first launch needs a one-time Gatekeeper bypass — see the
  README); Apple notarization can be layered on later like the optional Windows
  Authenticode signing. New `just build-macos-updater` / `build-linux-updater`
  recipes; `bundle.targets` is now `"all"`. The GitHub release page groups the
  downloads by OS (Windows / macOS / Linux) in its notes.

- **Live web demo on GitHub Pages.** The full Leptos/Thaw UI now runs in a plain
  browser with curated sample data and no Tauri backend — try it at
  <https://tiredithumans.github.io/azapptoolkit/> with no install and no sign-in.
  The demo reuses the GUI test harness's mock IPC bridge (extracted to a shared
  `ipc_mock` module): a new `demo` Cargo feature pre-loads it with fixtures and
  signs into a demo tenant, and a banner marks it as read-only (mutations and
  exports are disabled). Built with `just web-build-pages` and published by a new
  `pages.yml` workflow; the desktop build is unaffected (the feature is off by
  default, so the mock and fixtures never enter the shipped bundle).

## [0.8.0] - 2026-06-26

### Added

- **Force re-authenticate in place when a session expires — no manual sign-out.**
  When the stored refresh token is expired or revoked, the **Refresh Token**
  button now falls back from the silent re-mint to one interactive browser
  round trip (pinned to the current account), restoring the session without
  signing out — so the cached lists and audit run survive. Additionally, any
  command that fails because the session is dead now surfaces an error toast
  with a **Re-authenticate** action, so recovery appears exactly when it's
  needed instead of leaving the user stuck. New `reauthenticate` command.

- **Interactive auto-update with a changelog splash.** When a new release is
  available, the app now shows a toast on launch ("Update available: vX.Y.Z —
  View changelog") that opens a splash listing the version's release notes with
  an **Update & restart** button (which downloads, installs, and relaunches,
  showing download progress) and a **Later** dismiss. A manual **Check for
  updates** button sits by the version in the nav. The release manifest
  (`latest.json`) now carries the `CHANGELOG.md` section as its `notes`, so the
  splash shows real changelog text.

### Changed

- **Updates are no longer installed silently in the background.** The former
  silent download-and-install on launch is replaced by the interactive prompt
  above, so the user sees what's changing and chooses when to restart.

## [0.7.0] - 2026-06-24

### Changed

- **Security Audit revamp — the audit is now the hero of the Security surface.**
  The Security sub-tabs are reframed: the audit is the default, full-width view,
  and the inventory lenses (Credential expiry, Delegated grants) move behind a
  subordinate "Detailed inventories" selector (all deep-links and keep-alive
  panes are preserved). The **App permissions** lens is removed — its data was
  redundant with the audit's findings. The audit's flat 14-item facet tab bar is
  replaced by **two combinable filters** — a primary risk-severity selector (All
  / Critical / High / Medium / Low) and a collapsible finding-type chip drawer
  (Expired, Unused, Over-privileged, High-risk delegated, Org-wide mailbox,
  Scoped mailbox, Org-wide SharePoint, Scoped sites, Unowned) — that
  **intersect** (e.g. "Critical apps with an expired credential"). The
  **Expired** finding matches only already-expired credentials (proactive
  "expiring soon" rotation lead-time stays in the Credential-expiry lens). The
  posture scorecard is regrouped into Risk and Findings rows; each card seeds its
  own dimension and composes with the other.
- **The Home dashboard's Security Posture card surfaces more drill-ins** —
  Critical / High / Medium / Expired / Over-privileged / Org-wide mailbox /
  Org-wide SharePoint / Unowned / Unused — each jumping to the audit pre-filtered
  to that subset.

### Added

- **Multi-select + context-aware inline bulk actions on the Security Audit table
  and App Registrations list.** Check rows to reveal an inline bar; on the audit
  it offers the remediation matching the active finding filter — **Remove expired
  credentials** (Expired), **Remove redundant permissions** (Over-privileged),
  **Scope mailbox access** to chosen groups (Org-wide mailbox), **Scope SharePoint
  access** to chosen sites (Org-wide SharePoint) — plus Delete, with live
  progress, cancel, typed confirmation for destructive actions, and a per-item
  result summary. The App Registrations list / Bulk Actions page keep the
  management set (Grant consent / Remove expired / Delete). The new bulk
  remediations (`bulk_remove_redundant_permissions`, `bulk_scope_mailbox_access`,
  `bulk_scope_sharepoint_access`) reuse the single-app remediation cores, so each
  app's live re-resolution, grant-before-strip safety, and cache invalidation
  match the one-click fixes. The audit table keeps its own selection set, separate
  from the App Registrations list's. The Enterprise Applications list is
  intentionally excluded (its rows are service principals, which the
  app-registration bulk commands can't target).

## [0.6.0] - 2026-06-24

### Added

- **Home dashboard metrics drill into a pre-filtered list.** Clicking a count on
  the Overview cards now jumps to the matching list/lens filtered to that subset,
  instead of just landing on an unfiltered list: Enterprise Applications'
  Disabled / Foreign and Managed Identities' System / User → their list's facet;
  Credential Health's Expired / ≤7d / ≤30d → the per-credential Credential-expiry
  lens (so the drilled count matches the clicked metric); Security Posture's
  Critical / High / Ownership / Unused → the audit view's matching facet. Zero
  counts stay muted and non-clickable (nothing to drill into). The facet of each
  drilled surface (enterprise / managed-identity / audit / credential-expiry) is
  lifted to the `Session` alongside the searches and reset on tenant switch so a
  metric click can seed it; drilling into the Enterprise list also auto-expands
  its filter drawer so the active chip is visible.
- **`just clean` reclaims disk.** A new task-runner recipe that runs `cargo
  clean` against both independent build trees — the root workspace and the
  web-rs frontend (excluded from the workspace, so the root clean never reaches
  it, and its `target/` is by far the larger). Frees disk when the cargo build
  caches grow unbounded.
- **Typed "DELETE" confirmation for the dangerous SP deletes.** Deleting a
  foreign-tenant or Microsoft first-party enterprise application's service
  principal (which can break tenant-wide sign-in) now requires typing `DELETE` to
  confirm, matching the bulk-delete guard; an ordinary in-tenant SP keeps the
  one-click confirm.
- **Detail panes now offer Retry when a load fails.** A transient 429 / network
  blip on an App Registration, Enterprise App, or Managed Identity detail load
  used to leave a static `error [code]: message` dead-end; it now shows the
  message with a Retry button (and a muted code), matching the list views. Shared
  `DetailLoadError` component across the three panes.
- **Empty tenants get an onboarding call-to-action.** An App Registrations /
  Enterprise Applications list with no items shows a "Create your first…" empty
  state with a primary create button, instead of the "adjust your search or
  filters" copy meant for a filtered-empty list.

### Changed

- **Permissions tab — clearer primary action.** "Grant access" (the wizard) is
  now the sole primary button; "Grant admin consent" (in-place consent of
  already-declared permissions) is demoted to a secondary action so the two are no
  longer competing primaries.
- **Grant-access wizard explains a disabled "Next".** Step 1 now shows a "Select
  at least one permission to continue." hint while the cart is empty, instead of a
  mutely-disabled button.
- **Consistent loading skeletons.** The Managed Identity detail pane's permission
  and Azure-role tables now show a skeleton placeholder while loading, matching
  the other detail surfaces (was a bare spinner).
- **Bulk delete / grant-consent now run with bounded concurrency and adaptive
  throttling.** Both ran fully serially with a fixed 50 ms pause between items —
  slow on the healthy path yet with no back-off under throttling. They now fan out
  through the shared bounded-concurrency dispatcher with an adaptive
  `ConcurrencyThrottle` (the in-flight cap halves on a Graph 429 and recovers when
  quiet), and report the live cap to the progress UI. The expired-credential sweep
  gains the same adaptive back-off (it had a fixed cap) and now projects only the
  fields it reads (`passwordCredentials`) instead of full app payloads.
- **Removed a dead, uncached `list_applications` command** that bypassed the
  cached app-list path and had no callers.
- **Workspace upgraded to Rust edition 2024** (from 2021), across both the native
  workspace and the excluded `web-rs` (WASM) frontend. `web-rs`'s declared MSRV
  rises 1.82 → 1.96 to clear the edition's 1.85 floor and match the root workspace;
  the pinned toolchain (`rust-toolchain.toml`, 1.96.0) and CI are unchanged. No
  source edits were required — `cargo fix --edition` surfaced only benign
  `tail_expr_drop_order` drop-order notes (HTTP-client and `JsValue` teardown),
  which are allow-by-default on edition 2024.
- **Tenant-wide reads are now cached, cutting redundant Graph traffic.** The
  service-principal sign-in activity report (a slow beta endpoint that paginates
  the whole tenant) is cached per tenant, so clicking through several apps' Activity
  tabs — and the security audit — share one fetch instead of re-scanning it each
  time. The Home dashboard's credential-expiry list is likewise read-through cached
  (it was re-scanning every app registration on each cold load, duplicating the
  apps list's own scan); it's busted whenever a credential or app changes, so a
  just-rotated credential is never shown as still-expiring. The discovered Graph
  activity workspace and ARM role-definition names are documented as read-only
  until their cache TTL / sign-out (cleared via "Clear all" in Cache diagnostics if
  ever re-pointed mid-session).

### Fixed

- **Stale service-principal cache no longer skews audit posture or detail panes.**
  Mutating an enterprise application's service principal — toggling sign-in /
  assignment-required, hiding it, changing SSO mode, or deleting it — now busts
  the per-app SP cache, so a re-run security audit reads the live `accountEnabled`
  (correct Rule-4 risk score) and the app-registration detail pane never shows a
  just-deleted paired SP. Previously these stayed cached for up to 60 minutes.
- **First permission grant on an unpaired app now appears immediately.** When a
  grant (single, admin-consent, or bulk) creates an app registration's first
  enterprise service principal, the App Registrations / Enterprise Apps lists and
  global search now refresh right away instead of waiting out the 60-minute cache
  TTL or a manual refresh.

## [0.5.0] - 2026-06-23

### Changed

- **The "Grant scoped access" wizard is now the unified "Grant access" flow,
  replacing the separate "Add permission" picker.** Each Permissions surface (app
  registration, enterprise app, managed identity) now has a single **Grant
  access** button. Step 1 is the full live permission catalog (every resource,
  Application + Delegated, searchable) as a **multi-select cart** — pick as many
  permissions as you want, then grant them in one pass. Step 2 auto-offers scoped
  targets (mailbox group or SharePoint sites) **only when the whole selection is
  one scopable mechanism** (all mailbox, or all SharePoint); mixed, non-scopable,
  or delegated selections grant org-wide, preserving "one mechanism per run". The
  per-row **Scope…** action still opens the wizard pre-seeded to that permission.
  The old inline single-grant picker (one permission per click, always org-wide)
  is retired; the catalog `PermissionPicker` is now a reusable multi-select
  component the wizard embeds.

## [0.4.0] - 2026-06-22

### Added

- **"Grant scoped access" wizard — one guided flow for confining permissions,
  across mechanisms.** A single always-available **Grant scoped access…** button
  on the Permissions tab (app registrations) and the Enterprise App / Managed
  Identity detail panes opens a three-step wizard — pick the permissions → choose
  the targets → review & grant — replacing the old "grant org-wide, then hunt for
  the scoping menu, then strip the grant" dance *and* the per-row inline scope
  nudge (now retired, along with `scope_panel.rs`). The wizard **dispatches on the
  scoping mechanism**: **Exchange RBAC** (Mail/Calendars/Contacts) confines to a
  mailbox group — declare-only, so no org-wide Entra grant is ever created (the
  `declare_app_permission` command) — and **SharePoint** (`Sites.*`) confines to
  specific sites via `Sites.Selected` (`convert_site_access_to_selected`). Picking
  a permission locks the run to its mechanism (scope the other separately); a held
  row's **Scope…** opens the wizard pre-selected to that permission. A de-emphasized
  **org-wide (no scoping)** option remains for the rare permission that needs
  tenant-wide reach. Built on the `ScopeKind` registry, so new mechanisms
  (Administrative Units, Azure RBAC, Teams resource-specific consent) drop in as a
  registry entry + a target panel + an apply arm. Managed-group mailboxes and the
  site list are managed inline via shared `ManagedScopeGroupPanel` /
  `SiteSelectionPanel` components.

### Internal

- **Scope-mechanism registry in `azapptoolkit-core::scoping`.** A single
  `scope_kind(value)` classifier + the `ScopeKind` enum (Exchange / SharePoint) +
  per-mechanism metadata (`target_noun` / `capability_key` / `admin_applicable`) —
  one source of truth for which mechanism, if any, scopes a Graph permission, and
  the dispatch key the scope wizard is built on. `admin_applicable()` is the seam
  for future owner-consented mechanisms (e.g. Teams resource-specific consent) that
  render guidance instead of an apply button.
- **GUI test coverage for the scope wizard.** Browser GUI tests (`just web-itest`)
  drive `ScopeWizard` end-to-end per mechanism: the Exchange scoped path declares
  each permission and assigns scoped roles with `removeUnscopedEntraGrants = true`
  (no org-wide grant); the org-wide option grants via `grant_single_permission`;
  SharePoint routes to `convert_site_access_to_selected` (`removeOrgwide = true`)
  and never touches Exchange RBAC; and a pre-seeded open jumps to the target step.
  The managed-identity picker test verifies the org-wide-direct grant after the
  inline scope nudge's retirement. Adds a `set_textarea_value` harness helper plus
  typed catalog / exchange / sharepoint fixture builders behind `test-support`.

## [0.3.2] - 2026-06-22

### Internal

- **Dependency refresh.** Both lockfiles — the root workspace and the
  workspace-excluded `web-rs` front-end — were updated to their latest
  semver-compatible versions: notably `rustls` 0.23.41, `quinn` 0.11.11, and
  `time` 0.3.51 (+ `time-macros`), alongside routine bumps to `bytes`,
  `camino`, `cc`, `getrandom`, `log`, `quote`, `web_atoms`, and the
  `wasm_split_*` helpers. Stale build-time transitives (`wit-bindgen` /
  `wasm-encoder` / `wasmparser` tooling) were pruned from the graph. No held
  major versions were touched (`rand` / `sha2` / `rsa` unchanged), and the
  RustSec advisory scan plus the cargo-deny license/source/bans gates remain
  green on both trees.

## [0.3.1] - 2026-06-22

### Added

- **Cancel button for Bulk Actions.** A long-running bulk grant / delete /
  remove-expired / create run can now be stopped from the UI — the backend bulk
  loops already polled the shared cancel flag, but the page had no control wired
  to it. A new `cancel_bulk` command drives it; the in-flight run still returns
  its partial result, tagged cancelled.
- **Retry on a failed list load.** When the App Registrations or Enterprise Apps
  list fails to load (e.g. a transient 429 or network blip), the error now offers
  an in-context **Retry** instead of a dead-end message — matching the dashboard
  cards.
- **Rate-limit back-off notice on the security audit.** When Microsoft Graph
  throttles a scan and the adaptive concurrency cap drops below its peak, the
  audit view now explains the slow-down (the same notice the DR backup shows), so
  a throttled scan reads as expected rather than stalled.

### Changed

- **Confirmation before revoking an enterprise application's permission.**
  Revoking a held app-role grant on an Enterprise App now prompts for
  confirmation, matching the Managed Identity pane — the identical action was
  previously a single un-guarded click that could break a live integration.
- **The App Registrations "Permissions" tab is now labelled "API permissions"**
  (the Entra portal's term) to distinguish the permissions an app *requests*
  (`requiredResourceAccess`) from the *held* grants shown on the Enterprise App /
  Managed Identity "Permissions" tabs. The routing value is unchanged, so
  deep-links still work.
- **Faster mailbox reverse-lookup.** The "who can reach this mailbox" probe now
  resolves every candidate's service-principal appId in one batched Graph read
  (`$batch`, ~20×) up front instead of one round trip per candidate.
- **Faster security audit on cold caches.** Each app's distinct resource indexes
  are now resolved concurrently rather than one serial round trip at a time.
- **Faster DR restore.** Principal resolution (users/groups by UPN / display
  name) is memoized for the run, so a principal reused across owners, assignees,
  and group memberships is searched once instead of per occurrence.

### Fixed

- **Actionable error guidance no longer collapses onto one line.** The recovery
  hints the backend attaches after a blank line (e.g. "You may need the Exchange
  Administrator role" on a 403) are now rendered with their line breaks intact
  instead of being flattened away.
- **The first-run configuration screen now shows a recovery hint** for each
  failure (invalid client/tenant ID, or a settings.json write error) instead of a
  raw `error [code]: message` dump — matching the sign-in screen.

### Internal

- **The WASM frontend (`web-rs`) is now linted under clippy** (`-D warnings`) in
  `just verify` and CI. Previously the largest, IPC-privileged tier escaped the
  lint gate entirely because it is excluded from the root workspace; the existing
  warnings are fixed.
- **The release workflow re-runs the RustSec advisory scan before building the
  installers**, so an advisory filed after the last main-branch CI run can't ride
  into a shipped build unscanned.
- **Internal cleanup (no behaviour change):** the 1,700-line
  `commands/applications.rs` was split into a `commands/applications/` module
  directory; the 13-site detail-pane cache-invalidation pairing was factored into
  one `invalidate_app_detail_state` helper; and the duplicated (and already
  drifting) premium-feature error mapper shared by the Activity and Conditional
  Access tabs was unified into one `graph_err::premium_feature_err`.
- **DR backup/restore now have automated coverage of their hardest invariants.**
  A mock-Graph (wiremock) test proves the backup degrades to per-object reads when
  a whole `$batch` fails and skips an individual failed object rather than aborting
  the run; a unit test pins `plan_restore`'s action counts and cloud/tenant-change
  flags. (The backup chunk helper now takes a progress callback instead of the
  Tauri `AppHandle`, so the test needs no webview/mock runtime; `wiremock` was
  added as a dev-dependency.)

## [0.3.0] - 2026-06-21

### Changed

- **Disaster-recovery backup is now batched and throttle-aware — far faster and
  no longer rate-limit-bound on large tenants.** The per-app/-SP/-MI reads that
  the backup fanned out as individual Graph calls (the bulk of a backup) now go
  out via Graph JSON batching (`$batch`, 20 sub-requests per round trip),
  collapsing the round-trip count roughly 20× and cutting wall-clock sharply. All
  three passes (app registrations, enterprise apps, managed identities) are
  batched, including the enterprise group-membership read (the advanced
  `memberOf` query now rides a per-sub-request `ConsistencyLevel` header in the
  batch). The managed-identity pass resolves each distinct resource service
  principal once via a batched prewarm. A whole-batch failure degrades to
  per-object reads for that chunk, and per-object failures still skip just that
  one object — a cancelled run remains an error, never a partial manifest.
- **Adaptive concurrency for the backup.** The backup now reuses the security
  audit's throttle tracker (promoted to a shared `ConcurrencyThrottle`): every
  Graph 429 halves the in-flight chunk cap, which then recovers after a quiet
  window — so a throttling tenant backs off gracefully instead of hammering at a
  fixed concurrency.
- **Legible DR progress.** The Disaster Recovery screen now shows a progress bar
  and the live concurrency for both backup and restore, plus a back-off notice
  while Graph is rate-limiting the backup (the adaptive cap has dropped below its
  peak) so a slow run reads as expected rather than stuck. `BulkProgress` gained
  an optional `in_flight_cap` field (additive; absent for the fixed-cap bulk
  flows).

## [0.2.0] - 2026-06-20

### Added

- **Exposed app roles management on enterprise applications.** A new **App roles**
  tab on the enterprise-app detail pane adds, edits, enables/disables, and deletes
  the app-role definitions an application publishes (the Entra "App roles" blade) —
  previously these were read-only in the Permissions tab. Edits target the role's
  canonical home: the **linked app registration** when one exists (Entra mirrors
  them onto the service principal), otherwise the **service principal** directly
  (gallery / foreign-tenant apps). The whole `appRoles` collection is re-read live
  and full-replaced on each change, preserving built-in roles (e.g. the SAML
  `msiam_access` default, surfaced read-only) byte-for-byte; deleting an enabled
  role disables it first (Graph rejects removing an enabled role). New backend
  commands `list_enterprise_app_roles`, `upsert_enterprise_app_role`, and
  `delete_enterprise_app_role` with typed frontend stubs.

## [0.1.4] - 2026-06-20

### Added

- **Enterprise Application management parity.** The enterprise-app detail pane
  gained the core lifecycle controls it was missing relative to the Microsoft
  Entra admin center:
  - **SSO tab** — a single sign-on **method selector** (SAML / OIDC / Disabled)
    that sets `preferredSingleSignOnMode`, so you can now enable or switch an
    existing app's SSO mode (previously the tab always showed the SAML editor for
    any non-OIDC value and could not turn SSO on). The SAML editor now accepts
    **multiple identifiers (Entity IDs) and reply URLs (ACS)**, and apps that
    aren't configured for SAML/OIDC (e.g. password-based) get a clear prompt
    instead of a misleading SAML form.
  - **Overview tab** — toggles for **"Enabled for sign-in"** (`accountEnabled`)
    and **"Assignment required"** (`appRoleAssignmentRequired`), plus an editable
    free-text **Notes** field.
  - **Owners tab** — **add/remove owners** (users only — groups can't own a
    service principal), replacing the previous read-only list.
  New backend commands (`set_sso_mode`, `set_enterprise_app_account_enabled`,
  `set_enterprise_app_assignment_required`, `set_enterprise_app_notes`,
  `add_enterprise_app_owner`, `remove_enterprise_app_owner`) with typed frontend
  stubs; `set_saml_urls` now takes lists of identifiers/reply URLs.

## [0.1.3] - 2026-06-19

### Added

- Browser-based **GUI functionality tests** for the front-end. Real Leptos views
  mount in a headless browser with the Tauri IPC bridge mocked (no tenant, no
  backend) and assert on rendered DOM + recorded commands. New `just web-itest`
  recipe (the CI `web` job runs it on headless Chrome); the harness lives behind
  a `test-support` cargo feature, so it never enters the shipped Trunk bundle.
  Coverage spans the App Registrations / Enterprise Applications / Managed
  Identities lists (load, filter, error, empty, and Refresh → invalidate-cache
  command paths), the readiness checklist, the App Registration detail pane, the
  Key Vault secret browser, the streamed-progress event plumbing, and mount-smoke
  for the bulk-actions, disaster-recovery, resource-access, and permission-tester
  views. `just setup` now installs `wasm-pack` and flags the browser + WebDriver
  prerequisite this gate needs.

### Fixed

- Directory and organization reads no longer fail to parse when Microsoft Graph
  returns an explicit `null` (or omits) `id` on a directory object or
  `verifiedDomains` on the organization — both now tolerate null/missing and
  fall back to a default instead of erroring the whole response.

### Changed

- **Front-end list-view maintainability refactor** (internal; no behavior change).
  The App Registration and Enterprise Application lists now share a `ListScaffold`
  component (header + search + filter drawer chrome) and a `use_filtered_list`
  hook (the layered search/facet filter memos, per-facet counts, and export
  snapshot), replacing two near-identical hand-rolled copies. A new `use_command`
  hook collapses the busy/error/tenant/spawn boilerplate that mutation handlers
  repeated. The 1.2k-line `audit_view` and 1k-line `managed_identities` views were
  each split into a module directory, and the IPC bindings' duplicated argument
  structs were centralized in `bindings/common.rs` alongside shared list constants
  in `constants.rs`.

- AAD token-endpoint failures now log the request **correlation ID** (the GUID
  Microsoft support needs to trace an issue) alongside the OAuth/AADSTS code,
  while still keeping the raw `error_description` — which can embed tenant/user
  GUIDs and client IPs — out of logs, the UI, and the audit log.

## [0.1.2] - 2026-06-17

### Added

- The app version is now shown beneath the **Sign Out** button in the
  navigation rail.

### Changed

- Moved **Cache** from the Tools group to the bottom of the navigation rail,
  directly above **Sign Out**.

### Documentation

- Clarified in the README that the in-app auto-updater manages only the NSIS
  (`-setup.exe`) per-user install. MSI/enterprise deployments must disable
  auto-update and update through their management tooling — installing one
  installer type and updating with the other leaves two conflicting Windows
  entries (and a stray Windows Installer "uninstall this product?" prompt).

## [0.1.1] - 2026-06-17

### Changed

- Input fields now show their full placeholder hint — it was being clipped in
  narrow boxes.
- Destructive actions (Delete / Remove / Revoke) are now styled red, and
  removing a mailbox from an Exchange scope group or revoking a managed-identity
  app-role assignment now asks for confirmation first.
- Updated to the `keyring` 4.1 architecture (the OS-native credential store is
  registered directly via `keyring-core`); on Linux, refresh tokens now use the
  Secret Service.

## [0.1.0] - 2026-06-17

Initial public release.
