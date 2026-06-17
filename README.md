# azapptoolkit

> Native desktop app for managing Microsoft Entra ID applications — no
> PowerShell modules, no scripting, no service principal of its own.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#install)
[![Rust](https://img.shields.io/badge/rust-1.96-orange.svg)](./rust-toolchain.toml)
[![Status: pre-release](https://img.shields.io/badge/status-pre--release-yellow.svg)](./CHANGELOG.md)

azapptoolkit signs in to Entra ID directly from your workstation and
talks to Microsoft Graph with your delegated permissions. The only
thing you install on the machine is the installer itself — no Az
PowerShell, no Microsoft Graph PowerShell SDK, no Azure CLI, and no
toolkit-owned service principal storing tokens you cannot audit.

## Table of contents

- [Features](#features)
- [Quick start](#quick-start)
- [Install](#install)
- [Updates](#updates)
- [Requirements](#requirements)
- [First-run configuration](#first-run-configuration)
- [Logs](#logs)
- [Data and privacy](#data-and-privacy)
- [Security](#security)
- [Built with](#built-with)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Browse** every app registration in the tenant in a virtualized
  list with debounced search.
- **Create, edit, delete** app registrations — sign-in audience,
  description, owners, and required permissions.
- **Authentication settings** — redirect URIs per platform,
  public-client flows, and implicit-grant toggles, mirroring the
  portal's Authentication blade.
- **Expose an API** — manage the Application ID URI, the OAuth2 scopes
  an app exposes (add / edit / disable-then-delete), and its
  pre-authorized client applications.
- **Rotate credentials** — add or remove client secrets, upload
  certificate credentials (drag-drop PEM or paste base64), and
  bulk-sweep every expired secret across the tenant in one pass.
- **Credential-expiry dashboard** — a tenant-wide view of every app
  registration's client secrets and certificates sorted soonest-to-expire,
  with status filters, an expiring-soon banner, CSV export, and a one-click
  jump into each app's credentials to rotate.
- **Federated identity credentials** — manage workload identity federation
  (GitHub Actions, Kubernetes, …) per app registration: list, add (with
  issuer/subject templates), and remove the OIDC trust relationships that let an
  external workload authenticate as the app with no client secret.
- **API permissions and admin consent** — pick delegated and
  application permissions from a bundled catalog (with Graph fallback
  for unknown resources) and grant admin consent in one click, with a
  diff view before writing.
- **Security audit** — risk-scored dashboard of every app
  registration with per-rule findings (high-risk app/delegated permissions,
  ownerless/single-owner apps, unused apps via sign-in activity, expiring
  credentials, and more), one-click **fixes** for safely remediable findings
  (remove expired credentials, scope mailbox/SharePoint access, remove
  redundant permissions), **scope-aware risk** (a mail permission confined via
  Exchange RBAC scores below an org-wide one), facet filters, CSV/JSON/HTML
  export, adaptive throttling on 429s, and cancellable scans.
- **Consent & application-permission audits** — tenant-wide views of every
  delegated (OAuth2) consent grant and every application permission apps hold
  on Microsoft Graph / Exchange / SharePoint, with high-risk highlighting,
  filters, CSV export, and a jump to the granting app.
- **Observed Graph activity** — compare an app's *granted* permissions with the
  Graph calls it *actually makes* (`MicrosoftGraphActivityLogs` via Azure
  Monitor Log Analytics) to spot grants that nothing uses.
- **Per-app sign-in activity** and a tenant-wide **inventory export** (CSV /
  JSON) of every app registration.
- **Enterprise applications** — inspect any service principal (credentials,
  exposed roles & scopes, owners, SAML signing-cert health), see **who has
  access**, grant/revoke access for users and groups, view SCIM **provisioning**
  status, and toggle **My Apps** visibility.
- **Group memberships** — list, add, and remove a service principal's
  security-group memberships (the access model for group-gated APIs such as
  Power BI / Fabric admin settings).
- **Managed identities** — discover system- and user-assigned identities, grant
  Graph application permissions, see over-privilege at a glance, and view their
  **Azure RBAC** role assignments across subscriptions (via Azure Resource
  Manager).
- **Permission tester** — answer "can this identity reach that resource": pick
  any service principal (app registration, enterprise app, or managed identity)
  and test whether it actually reaches a specific Exchange mailbox or SharePoint
  site, exercising the same live primitives the grant flows use.
- **Resource Access reverse lookups** — pick a resource and see which
  applications can reach it: a tenant-wide **site sweep** indexes every
  per-site `Sites.Selected` grant (filter by app for "which sites can this app
  reach?" — the lookup Graph doesn't offer), and a **mailbox check** probes
  every mail-capable app against one mailbox via Exchange's authoritative
  authorization test. Coverage is reported honestly — a partial scan says so.
- **Conditional Access visibility** — see which Conditional Access policies
  target an application (on-demand, via `Policy.Read.All`).
- **Activity log** — recent directory activity / change log for an app, from the
  Entra audit logs (on-demand, via `AuditLog.Read.All`).
- **SAML single sign-on** — a guided wizard to configure SAML-based SSO and
  customize the attribute & claim mapping (claims-mapping policies).
- **SharePoint site access (`Sites.Selected`)** — list, grant, and revoke a
  site's per-app permissions, and convert an org-wide `Sites.*` grant to
  site-scoped access.
- **Command bar & home dashboard** — the top-bar search bar jumps to any app or
  GUID and runs any tool (Cmd/Ctrl-K focuses it); a sign-in landing page
  summarizing credential health and security posture. Saved filter views pin
  your favorite facet+search combinations.
- **Exchange mailbox scoping (RBAC for Applications)** — restrict an
  app's mailbox access to specific groups via Exchange Online's RBAC
  for Applications (the supported replacement for the deprecated
  Application Access Policies), and migrate an existing policy to
  RBAC in one click with a dry-run preview.
- **Key Vault integration** — store a newly minted client secret
  directly into any Azure Key Vault you have RBAC on, and browse
  existing secret values on demand.
- **Readiness checklist** — a live page showing which directory / Azure /
  Exchange roles and delegated consents the signed-in operator holds versus
  what each feature needs, with in-context "requires role" labels and
  actionable 403 hints throughout the app.
- **Cache diagnostics** — inspect hit/miss counters per cache, clear
  individual caches, or disable caching entirely for debugging.

## Quick start

1. Download the latest Windows installer from the
   [Releases page](https://github.com/tiredithumans/azapptoolkit/releases).
   Most users want the **NSIS `-setup.exe`** — see [Install](#install) for
   when to choose the MSI instead.
2. Create a single-tenant app registration in your directory. On first
   launch azapptoolkit prompts for its **Application (client) ID** and
   **Tenant ID** and saves them locally (or set `AZAPPTOOLKIT_CLIENT_ID` +
   `AZAPPTOOLKIT_TENANT_ID` as user environment variables instead). See
   [First-run configuration](#first-run-configuration) for the exact
   permissions to consent.
3. Launch azapptoolkit. The first run opens your browser for the
   Entra sign-in once; after that, the OS keyring stores your refresh
   token and the app reconnects silently.

## Install

Download the latest installer from the
[Releases page](https://github.com/tiredithumans/azapptoolkit/releases).
Two formats are published, for two different audiences. **Pick one and
stick with it** — installing one type and later updating with the other
leaves two conflicting entries in Windows (see [Updates](#updates)):

- **`azapptoolkit_<version>_x64-setup.exe`** — lightweight NSIS
  installer. Per-user install, no admin rights, and **auto-updates
  silently in place**. The right choice for individual users and
  testers — pick this one unless you specifically need the MSI.
- **`azapptoolkit_<version>_x64_en-US.msi`** — classic Windows Installer
  for **enterprise rollout** via SCCM, Intune, or Group Policy. The
  in-app auto-updater does **not** manage MSI installs (it ships only the
  NSIS payload); deploy new versions through your management tooling and
  **disable auto-update** on these installs (see [Opting out](#opting-out)).

The Edge WebView2 runtime is the only external dependency, and it ships
with current Windows 10/11 — so on those machines installation and first
launch need no internet. On an older machine that lacks it, the installer
downloads WebView2 from Microsoft during setup. After install, the only
runtime azapptoolkit depends on is Windows itself plus that WebView2
runtime.

## Updates

The in-app auto-updater targets the **NSIS (`-setup.exe`) per-user
install**. On launch, azapptoolkit checks the configured release endpoint
for a newer signed build. If one is available, it is downloaded and
applied **automatically** — there is no prompt; a brief Windows installer
progress window may appear, and the new version runs the next time the
app starts. Update payloads are verified against a public key baked
into the build at release time — a payload that fails signature
verification is rejected before any bytes touch disk. A failed update
check or install never blocks the app; it is logged (see
[Logs](#logs)) and retried on a later launch.

> **MSI installs:** the updater only ever ships the NSIS payload, so
> letting it run against an MSI install creates a second, conflicting
> installation. If you deployed the `.msi`, **disable auto-update** (see
> [Opting out](#opting-out)) and push new versions through your management
> tooling instead.

### Opting out

Auto-update is on by default. There are two ways to turn it off:

- **Environment variable** — set `AZAPPTOOLKIT_AUTO_UPDATE=0` (also
  accepts `false` / `off` / `no`) in the user or machine environment
  before launching the app. Useful for CI runners and for MDM/Group
  Policy deployments that wrap the launcher.
- **Settings file** — drop a JSON file at the platform's app-data
  folder:
  - Windows: `%APPDATA%\azapptoolkit\settings.json`
  - macOS: `~/Library/Application Support/azapptoolkit/settings.json`
  - Linux: `~/.local/share/azapptoolkit/settings.json`

  ```json
  { "auto_update": false }
  ```

The env var takes precedence over the settings file when both are
present. With auto-update disabled the app makes no network calls to
the updater endpoint at any point in the session.

## Requirements

- Windows 10 or newer (primary target). macOS and Linux builds are
  supported for development but not currently published — see
  [docs/DEVELOPMENT.md](./docs/DEVELOPMENT.md).
- A Microsoft Entra ID account with at least the
  `Application Administrator` role, or the equivalent delegated
  consent for the permissions listed below.
- Outbound network access (at runtime) to
  `login.microsoftonline.com`, `graph.microsoft.com`, and — only when
  you use those features — `*.vault.azure.net` for Key Vault,
  `outlook.office365.com` for Exchange mailbox scoping,
  `management.azure.com` for a managed identity's Azure RBAC roles, and
  `api.loganalytics.azure.com` for observed Graph activity (usage
  analysis).

## First-run configuration

azapptoolkit talks to Microsoft Graph as a **public client** scoped
to **one Entra tenant**. It needs a single-tenant app registration in
your own directory to drive the PKCE sign-in; sign-in attempts from
accounts outside that tenant are rejected at the Entra endpoint. Your
tenant's Entra admin creates the registration once and every
workstation reuses the same client id and tenant id.

1. In the Azure portal, create a new App Registration:
   - Supported account types: **Accounts in this organizational directory only (Single tenant)**.
   - Redirect URI: **Public client / native** → `http://127.0.0.1`.
     (The app binds a loopback listener on `127.0.0.1` with an
     OS-assigned port; Entra matches the loopback host and ignores
     the port.)
2. On the Authentication blade, set **Allow public client flows** to
   **Yes**.
3. Under **API permissions → Add a permission**, add the delegated permissions
   in the table below, then have an admin click **Grant admin consent** for the
   tenant. Only `Directory.Read.All` is requested at sign-in; every other scope
   is consented **incrementally** the first time you use the feature that needs
   it. So a browse-only session never carries write or premium scopes, and a
   tenant that hasn't consented to an optional permission can still sign in and
   use everything else — that feature just shows an "unavailable" notice with a
   one-click **Grant consent** prompt.

   | Permission | What it unlocks | Required? |
   |---|---|---|
   | Graph · `Directory.Read.All` | Every read in the app — app registrations, enterprise apps, managed identities, owners, app-role & OAuth2 grants, org info, user/group search (the only read-only Graph scope that can read `/oauth2PermissionGrants`) | **Required** — at sign-in |
   | Graph · `Application.ReadWrite.All` | Create / edit / delete app registrations & service principals; manage credentials and owners | **Required for edits** — on first write |
   | Graph · `AppRoleAssignment.ReadWrite.All` | Grant / revoke application permissions and user/group access assignments | **Required for edits** — on first write |
   | Graph · `DelegatedPermissionGrant.ReadWrite.All` | Grant / revoke delegated (OAuth2) permission grants | **Required for edits** — on first write |
   | Graph · `AuditLog.Read.All` | **Activity** tab (directory change log) and **unused-app** detection in the security audit (the sign-in report also needs Entra ID **P1/P2**) | Optional |
   | Graph · `Policy.Read.All` | **Conditional Access** tab — which CA policies target an app (an Entra ID **P1/P2** feature) | Optional |
   | Graph · `Policy.ReadWrite.ApplicationConfiguration` | **Claims-mapping** policies — SAML attribute & claim customization in the SSO wizard | Optional |
   | Graph · `GroupMember.ReadWrite.All` | **Group memberships** — add/remove a service principal in security groups (the access model for group-gated APIs like Power BI / Fabric) | Optional |
   | Graph · `Synchronization.Read.All` | SCIM **provisioning** job status on enterprise apps (needs Entra ID **P1/P2**) | Optional |
   | Graph · `Sites.FullControl.All` | SharePoint **Sites.Selected** — list / grant / revoke a site's per-app permissions (SharePoint site access section on the Permissions tab) | Optional |
   | Office 365 Exchange Online · `Exchange.Manage` | **Exchange mailbox scoping** (RBAC for Applications) — confine an app's mailbox access to specific groups | Optional |
   | Azure Key Vault · `user_impersonation` | Store a new client secret into, or browse secrets from, an Azure **Key Vault** | Optional |
   | Azure Service Management · `user_impersonation` | View a managed identity's **Azure RBAC** role assignments across subscriptions | Optional |
   | Log Analytics API · `Data.Read` | **Observed Graph activity** — granted-vs-used analysis from `MicrosoftGraphActivityLogs` (also needs Entra diagnostic settings exporting to a Log Analytics workspace, and Log Analytics Reader on it) | Optional |

   Everything marked *Optional* needs **admin consent** but is acquired only on
   first use, never at sign-in. The Key Vault, Azure Service Management, and
   Log Analytics tokens are requested at runtime as `…/.default` (whatever
   delegated permission you've consented to for that resource) — you still add
   `user_impersonation` / `Data.Read` under *API permissions*.

   The sign-in flow also requests the OpenID Connect protocol scopes
   `openid`, `profile`, and `offline_access` (for the ID token and a
   refresh token). These are built-in v2.0 endpoint scopes, not
   resource permissions — you do **not** need to add them under
   *API permissions*, and there's no corresponding configuration on
   the Enterprise Application side. The admin-consent click on the
   Graph permissions above covers them automatically.

   **A few features also need the signed-in *user* to hold a role** — their own
   rights, separate from the app-registration permissions above:
   - **Key Vault** — `Key Vault Secrets User` or `Key Vault Secrets Officer` RBAC
     on the target vaults (the vaults must be in RBAC permission mode).
   - **Exchange mailbox scoping** — an Exchange Online **Role Management** RBAC
     role (held by the **Organization Management** role group; the Entra
     **Exchange Administrator** role grants it, but only once **active** — not
     merely PIM-*eligible* — and after it propagates to Exchange). A
     not-yet-effective role shows as a *"forbidden (403)"* banner or a Scope
     column stuck on **Unknown**; see the troubleshooting note in
     [`docs/operator-rbac/OPERATOR-ROLES.md`](docs/operator-rbac/OPERATOR-ROLES.md#3-exchange-online--built-in-exchange-administrator).
   - **Managed-identity Azure RBAC** — at least one readable Azure subscription
     to *view* role assignments; *assigning* a role to a managed identity
     additionally needs a higher Azure role such as **User Access Administrator**.
4. From the registration's Overview page, copy the **Application
   (client) ID**. From Azure → Microsoft Entra ID → Overview, copy
   the **Tenant ID**. Then give them to azapptoolkit one of three ways:

   - **In-app (simplest — recommended for a downloaded release).** Launch
     azapptoolkit. On first run, before any sign-in, it shows a **Configure
     your tenant** screen: paste the two IDs and select **Save & restart**.
     They're stored in your per-user `settings.json` (see [Logs](#logs) for the
     folder) and reused on every later launch — no environment variables
     needed.
   - **Environment variables.** Set both before launching (useful for MDM /
     automation; these override the saved values):

     ```powershell
     [Environment]::SetEnvironmentVariable('AZAPPTOOLKIT_CLIENT_ID','<client-guid>','User')
     [Environment]::SetEnvironmentVariable('AZAPPTOOLKIT_TENANT_ID','<tenant-guid>','User')
     ```
   - **Baked into a team build.** If you're an admin packaging a build for a
     whole team, copy `.env.example` to `.env` at the repo root, fill in the
     two GUIDs, and run `cargo tauri build`. The values are baked into the
     installer at compile time (see `apps/desktop/src-tauri/build.rs`), so
     recipients install and launch with no per-workstation configuration (the
     setup screen is skipped). See [docs/DEVELOPMENT.md](./docs/DEVELOPMENT.md).

   The resolution order is **environment variable → in-app `settings.json` →
   baked-in value → unset**; while unset, sign-in can't succeed and the
   configuration screen is shown.

   **Sovereign / national clouds.** The app targets the commercial cloud by
   default. To use a tenant in US Gov (GCC High), US Gov DoD, or Azure China
   (21Vianet), set `AZAPPTOOLKIT_CLOUD` to `usgov`, `usgovdod`, or `china`
   respectively (unset or `commercial` for the global cloud). This switches the
   Entra login, Microsoft Graph, Exchange Online, Key Vault, and ARM endpoints to
   that cloud's hosts. The app registration must be created in the matching
   national-cloud admin center.

On first launch, azapptoolkit opens a loopback listener, pops your
default browser for the Entra sign-in, and persists the resulting
refresh token in the OS keyring (Windows Credential Manager / macOS
Keychain / libsecret). Access tokens are refreshed lazily and never
written to disk.

## Logs

Rolling daily log files are written to the platform's app-data folder:

- Windows: `%APPDATA%\azapptoolkit\logs\azapptoolkit.log*`
- macOS: `~/Library/Application Support/azapptoolkit/logs/`
- Linux: `~/.local/share/azapptoolkit/logs/`

Increase verbosity with `RUST_LOG=debug` (or the narrower `EnvFilter`
syntax — for example `azapptoolkit_graph=trace`).

## Data and privacy

- No secret value is ever written to disk by azapptoolkit. Newly
  created client secrets are shown once, copyable to clipboard, and
  optionally pushed to Key Vault over TLS.
- Refresh tokens live in the OS keyring only; access tokens stay in
  memory and are zeroized on drop.
- Telemetry: **none**. azapptoolkit makes no network calls beyond
  Entra ID, Microsoft Graph, Azure Key Vault, Exchange Online, Azure
  Resource Manager, Azure Monitor Log Analytics, and the configured
  updater endpoint (the sovereign-cloud equivalents of those hosts
  when `AZAPPTOOLKIT_CLOUD` is set).

## Security

If you find a vulnerability, please **do not** open a public issue.
Instead, email the maintainer or use GitHub's
[private security advisory](https://github.com/tiredithumans/azapptoolkit/security/advisories/new)
flow so a fix can ship before the issue is disclosed.

Defensive choices worth knowing:

- OAuth uses PKCE plus a state CSRF parameter, on a loopback redirect
  bound to `127.0.0.1`.
- Bearer tokens are scoped to the resource (Graph / Key Vault /
  Exchange) and never sent to a `nextLink` that points at a different
  origin.
- Write scopes are consented incrementally — a session that only
  reads never holds tokens that can mutate.
- `cargo-audit` runs on every PR and on a weekly schedule.

## Built with

- [Rust](https://www.rust-lang.org/) (workspace, MSRV 1.96)
- [Tauri 2](https://tauri.app) for the desktop shell
- [Leptos](https://leptos.dev) + [Thaw UI](https://github.com/thaw-ui/thaw)
  for the WASM frontend
- [reqwest](https://github.com/seanmonstar/reqwest) /
  [rustls](https://github.com/rustls/rustls) for HTTPS
- [oauth2](https://github.com/ramosbugs/oauth2-rs) and the OS keyring
  via [`keyring`](https://github.com/hwchen/keyring-rs)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to get set up, the
working agreements, and the pre-PR checklist; build, testing, packaging,
and release-signing details are in
[docs/DEVELOPMENT.md](./docs/DEVELOPMENT.md). Issues and pull requests
are welcome — please open an issue first to discuss non-trivial changes.
By participating you agree to the
[Code of Conduct](./CODE_OF_CONDUCT.md).

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](./LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license
  ([LICENSE-MIT](./LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

© TiredITHumans
