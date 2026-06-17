# Changelog

All notable changes to azapptoolkit are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **In-app first-run configuration** — a freshly-downloaded release now prompts
  for its Entra **Application (client) ID** and **Tenant ID** on first launch and
  saves them to your per-user `settings.json`, so it no longer requires setting
  environment variables before starting. Resolution order is environment variable
  → saved `settings.json` → build-time bake → unset.

- **Toolkit-managed Exchange scope group** — when scoping an app, enterprise app,
  or managed identity's mailbox access (Exchange RBAC for Applications), the
  Exchange scoping section now creates and manages a mail-enabled security group
  named `azapptoolkit_<AppId>` for you: add mailboxes inline, see the current
  members, and remove them — no round trip to the Exchange admin center. The
  scoped grant points its management scope at this group, so afterward you adjust
  who's in scope just by editing membership (the management-scope filter never
  changes). Only direct members are in scope (nested groups don't count), and
  Exchange can take 30 min–2 h to apply RBAC changes.

- **Browse applications** — virtualized list of every app registration in the
  tenant with 300 ms debounced search and a master-detail layout (Overview /
  Credentials / Owners / Permissions tabs).
- **Create, edit, delete** app registrations — display name, sign-in audience,
  description, owners (add / remove / replace-all), and required resource access.
- **Credentials** — add / remove client secrets, upload PEM or base64-DER
  certificates, generate a self-signed certificate (RSA-2048, validity 1–1095
  days), and bulk-sweep expired secrets across every app in the tenant.
- **API permissions and admin consent** — bundled permissions catalog with
  Microsoft Graph fallback for unknown resources; delegated and application
  permission picker; diff preview; one-click admin consent with per-permission
  outcome reporting.
- **Security audit** — risk-scored dashboard with per-rule findings, CSV export
  to a user-chosen path, adaptive concurrency on 429 responses, and cancellable
  scans.
- **Disaster-recovery backup** — a new "Disaster Recovery" page exports a
  portable JSON manifest of the tenant's app estate: every app registration in
  full configuration (manifest, redirect URIs, declared permissions,
  Expose-an-API, federated credentials, owners, credential metadata) plus an
  inventory of enterprise applications and managed identities. Secret and
  certificate *values* are never captured (they are unrecoverable by Graph
  design — a restore regenerates them); the backup records only metadata.
  Read-only and cancellable.
- **Disaster-recovery restore** — load a backup file and replay its app
  registrations into the current tenant: a dry-run plan (with a cross-cloud
  blocker), then create-each-app → remap declared permissions / identifier URIs
  / owners by stable key → re-grant admin consent → regenerate client secrets in
  bulk. Produces a redistribution report carrying the **show-once** new secret
  values, unresolved owners, and certificates needing manual re-upload. Object
  IDs change in a new tenant, so first-party permissions survive verbatim while
  custom-API references and owners are remapped by name. Cancellable.
- **Disaster-recovery restore — enterprise applications** — for an enterprise app
  whose paired app registration is restored, the restore also re-applies its
  access: settings (tags, assignment-required), app-role assignments (users /
  groups remapped by name, roles by value), and security-group memberships.
  Foreign/gallery enterprise apps and unmatched custom roles are listed in the
  report as a manual runbook (re-consent / re-instantiate). The backup now
  captures enterprise-app assignment and group-membership detail.
- **Disaster-recovery restore — managed identities** — the backup captures each
  managed identity's held Microsoft Graph app-roles. On restore, a managed
  identity already recreated in the destination (matched by name) has those
  app-roles re-bound to its new principal automatically; managed identities not
  yet recreated, and their Azure RBAC role assignments (whose source scopes
  don't transfer), are listed as a manual runbook.
- **Exchange mailbox scoping (RBAC for Applications)** — grant an app's mailbox
  access through Exchange Online RBAC scoped to specific groups, and migrate an
  existing Application Access Policy to RBAC with a dry-run preview.
- **SharePoint per-site permissions** — grant or revoke per-site application
  permissions under the `Sites.Selected` model.
- **Key Vault integration** — store newly minted client secrets into any Key
  Vault you have RBAC on, and browse existing secret values on demand.
- **Cache diagnostics** — runtime-mutable per-kind TTLs, hit/miss counters,
  individual-cache clear, full disable for debugging.
- **Expose an API** tab — full portal parity for the app's own API surface:
  Application ID URI, OAuth2 scopes the app exposes (add / edit /
  disable-then-delete), and pre-authorized client applications.
- **Authentication tab** — redirect URIs per platform, public-client flow and
  implicit-grant settings, matching the portal's Authentication blade.
- **Credentials tab portal parity** — client-secret expiry presets and custom
  dates with a Secret ID column, certificate **file upload** with thumbprint and
  key-id columns, and a federated-credential **scenario picker** with in-place
  edit.
- **Per-app sign-in activity** and a tenant-wide **inventory export**
  (CSV/JSON) of every app registration.
- **Readiness checklist** — a live page showing which directory / Azure /
  Exchange roles and delegated consents the signed-in operator holds versus
  what each feature needs, backed by a capability catalog that also drives
  in-context "requires role X" labels and actionable 403 hints.
- **Resource Access reverse lookups** — pick a resource and see which apps can
  reach it: a tenant-wide SharePoint **site sweep** (site ⇄ app `Sites.Selected`
  grants) and a **mailbox check** that probes every mail-capable app — including
  RBAC-only principals — against one mailbox via Exchange's authoritative
  authorization test.
- **Observed Graph activity** — granted-versus-used permission analysis from
  `MicrosoftGraphActivityLogs` via Azure Monitor Log Analytics (on-demand
  Log Analytics scope; needs Entra diagnostic settings exporting to a
  workspace).
- **Least-privilege audit upgrades** — detection and one-click removal of
  **redundant application permissions** (a narrower permission implied by a
  broader one already held), and **downgrade suggestions** that swap a broad
  permission for a sufficient narrower one after admin review.
- **Service-principal group memberships** — list, add, and remove security-group
  memberships for any service principal (the access model for group-gated APIs
  like Power BI / Fabric admin settings), with an on-demand
  `GroupMember.ReadWrite.All` consent.
- **Permission tester** — a Tools page that answers "can this identity reach
  that resource", testing whether any service principal (app registration,
  enterprise app, or managed identity) actually reaches a specific Exchange
  mailbox or SharePoint site.
- **Conditional Access visibility** — see which Conditional Access policies
  target an app (on-demand `Policy.Read.All`).
- **Activity log** — recent directory activity / change log for an app from the
  Entra audit logs (on-demand `AuditLog.Read.All`).
- **SAML single sign-on wizard** — configure SAML SSO, edit the notification
  email addresses, and customize the attribute & claim mapping — including a
  transformation builder — via claims-mapping policies.
- **Managed identities** — discover system- and user-assigned identities, grant
  Graph application permissions (with optional resource scoping at grant time),
  and view their Azure RBAC role assignments via Azure Resource Manager.
- **Federated identity credentials** — list, add, and remove workload-identity
  federation (GitHub Actions, Kubernetes, …) per app registration.
- **Audit remediation** — one-click "Fix" actions for findings whose remedy maps
  to a safe existing mutation (e.g. remove expired credentials), re-resolving
  live state before acting.
- **Credential-expiry dashboard**, **consent & application-permission audits**,
  and a **home dashboard / command palette** with saved filter views.
- **Global substring search** across app registrations, enterprise apps, and
  managed identities (contains-anywhere on name / appId / object id), feeding
  per-list search with filter chips, counts, and saved views.
- After-the-fact **"Scope…"** actions to restrict an already-granted org-wide
  Exchange or SharePoint permission to specific mailboxes / sites.
- **Sovereign / national cloud support** — `AZAPPTOOLKIT_CLOUD` switches the
  Entra, Graph, Exchange, Key Vault, and ARM endpoints to US Gov (GCC High),
  US Gov DoD, or Azure China (21Vianet).

### Changed

- The App Registration and Enterprise Application lists now filter creation date
  by an inclusive **range** — *Created before* **and** *Created after* — using
  native date inputs (the previous component-library picker crashed the view when
  its calendar opened). Each bound has a clear button to turn it off, and an
  inverted range (after later than before) is flagged.
- The list filters (saved views, created-on range, and facet chips) now live in a
  **collapsible drawer** on the App Registration and Enterprise Application lists,
  collapsed by default to reclaim list space, with an active-filter count badge so
  a hidden filter stays discoverable. Search stays outside it, always visible.
- The security-audit table renders in pages (a "Show more" control) and filters
  by row index instead of cloning the full result set per keystroke, so very
  large tenants no longer stall the view on every search/facet change.
- Unused-app detection (the audit's Unused tab) now uses `AuditLog.Read.All` —
  the least-privileged scope for the service-principal sign-in-activity report —
  instead of `Reports.Read.All`.
- The Exchange and SharePoint access tabs are folded into the **Permissions**
  tab as conditional sections, so an app's full effective access reads in one
  place.
- The per-row **"Scope…"** action on **mail/calendar/contacts** permissions is
  removed from the App Registration Permissions tab, the Enterprise Application
  permissions pane, and the Managed Identity detail. Exchange RBAC scoping is
  **app-wide** — one management scope binds the whole principal's mail roles — so
  confining mailbox access is now driven solely by the **"Exchange scoping"**
  section (the Managed Identity detail gains that section to match the other two
  surfaces, so an already-held mail permission stays scopable). Mail **scope
  badges**, the per-row **"Scope…"** for org-wide SharePoint `Sites.*` (convert to
  `Sites.Selected`), and the scope-first prompt shown right after granting a new
  mail permission are unchanged.
- The **permission tester** verdict is rebuilt as the union of the Entra grant
  layer and the Exchange RBAC layer (honoring `InScope`), so a scoped app that
  still holds an un-stripped org-wide Entra grant reports the access it really
  has.
- Graph traffic is leaner and more resilient: requests use `$select`
  projections and `$batch` where it pays, honor `Retry-After` on 429s, and the
  audit's per-app API fan-out is cut sharply; large scans adapt their
  concurrency to throttling and remain cancellable.
- The **permission picker** filter is now debounced like every other list
  search, so typing no longer rebuilds the entire permission list (hundreds of
  rows for Microsoft Graph, each with risk/scope hints) on every keystroke.
- The **Resource Access** Sites sweep filters against a prebuilt lowercased
  search index instead of re-lowercasing all four fields of every row (up to
  ~5k) on each keystroke, keeping search responsive on large tenants.
- The SAML/OIDC **claims editor** renders its claim, transformation, and
  input/parameter/output rows with stable keys, so adding or removing one row
  patches just that row instead of rebuilding the whole editor.
- The **"Exchange scoping"** section now reads correctly for the principal it's
  shown on: a managed identity sees *"this managed identity's mailbox access… the
  Mail/Calendars/Contacts permissions it holds"* rather than app-registration
  wording (its roles come from held grants, not a manifest), and the legacy
  **Application Access Policy migration** block — a registered-app concern — is
  hidden on the managed-identity surface.

### Fixed

- On a tenant with more than 10,000 service principals, the Enterprise
  Applications list, the App Registrations pairing arrows, and global search no
  longer fail outright — the service-principal scan now returns the first
  10,000 (logging that coverage is partial) instead of erroring past an
  internal page limit.
- The Resource Access site sweep refreshes immediately after a per-site
  permission is granted or removed, instead of showing the pre-mutation grants
  for up to an hour.
- Backend panics are captured into the log file with a backtrace, so a crash
  no longer leaves the log directory empty ("it just closed").
- Rolling log files are pruned to the most recent 14 days; previously they
  accumulated one file per day indefinitely.
- Exchange mailbox scoping requests the classic `Exchange.Manage` delegated
  scope (not the preview `Exchange.ManageV2`), fixing bodyless-403 rejections
  from the admin API; scope-verdict probes tolerate the `"Not Run"` `InScope`
  value and are cached per app with an honest "Resolving…" state.
- Long-running fan-out scans no longer drop completed results once the
  concurrency cap is reached.
- The audit cache is tenant-prefixed and sign-out sweeps every cache kind, so
  switching tenants can never surface another tenant's data.
- The MSI installer provisions WebView2 via `downloadBootstrapper`, fixing
  install error 1722 on machines without the runtime.
- Newly created client secrets show a reveal dialog reliably; default secret
  expiry is 365 days.

- Exchange scoped-mailbox grants no longer strip an app's org-wide Entra grant
  when the scoped role assignment failed to land, which could leave the principal
  with no mailbox access; only permissions whose scoped role is in place are
  stripped (mirrors the SharePoint grant-before-strip guard).
- `rotate_app_credential` and bulk admin-consent now invalidate the list / detail
  / audit caches on success, so credential and permission changes are reflected
  immediately instead of after the cache TTL.

### Internal

- Internal workspace crates are marked `publish = false`; `cargo deny` is green
  again (wildcard path-deps allowed for private crates).
- CI hardening: GitHub Actions are pinned to commit SHAs, `--locked` enforces
  the committed lockfiles in every gate, an `actionlint` job gates workflow
  syntax, and the dependency-policy jobs now also scan the frontend's own
  lockfile (`just web-audit` / `just web-deny`).
- The unused `tauri-plugin-shell` plugin and its `shell:allow-open` capability
  are removed from the webview's grant set.
- Release-pipeline hardening: releases are created as **drafts** (publishing is
  the human step), every asset ships in a `SHA256SUMS` manifest, `--locked` is
  enforced on the release build itself, the tag guard also checks the Cargo
  workspace version, and release runs are serialized. The dead Tauri v1
  `"dialog"` updater key is removed and the Windows install mode pinned to
  `passive`; the README now describes the updater's real (automatic) behavior.

### Security

- Entra ID sign-in uses OAuth 2.0 with PKCE and a state CSRF parameter, on a
  loopback redirect bound to `127.0.0.1`.
- Refresh tokens live only in the OS keyring (Windows Credential Manager / macOS
  Keychain / libsecret); access tokens stay in memory and are zeroized on drop.
  Private-key PEMs are zeroized on drop and redacted from `Debug` formatting.
- Write scopes are consented incrementally — a session that only reads never
  holds tokens that can mutate.
- Bearer tokens are scoped per resource (Graph / Key Vault / Exchange) and never
  sent to a `nextLink` that points at a different origin.
- AAD error responses are redacted before reaching the UI — only the canonical
  OAuth code and `AADSTSnnnnn` number are surfaced; the full description (which
  may carry tenant / user GUIDs) is logged via `tracing` for operators.
- `cargo-audit` runs on every PR and on a weekly schedule.
- Dropped the `rsa` crate entirely. Self-signed certificate keys are now
  generated by `rcgen` on its `aws_lc_rs` backend (already in the tree via
  rustls), removing the `rsa` Marvin timing side-channel advisory
  (RUSTSEC-2023-0071) from the dependency graph rather than suppressing it. No
  fixed `rsa` release exists, so this also retires the audit/deny ignore for it.

[Unreleased]: https://github.com/tiredithumans/azapptoolkit/commits/main
