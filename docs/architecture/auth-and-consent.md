# Auth, consent & role feedback

Deep-dive companion to the auth/consent gotchas in [AGENTS.md](../../AGENTS.md). Read this before
editing `azapptoolkit-auth`, `AppState` token plumbing, consent flows, or anything touching the
capability catalog / readiness checklist.

## Token lifecycle

Access tokens are refreshed lazily (~60s before expiry) behind a shared mutex; refresh tokens
persist in the OS keyring, access tokens never touch disk (in-memory, zeroized on drop). Write
scopes are consented **incrementally** on first write — a browse-only session holds no
mutate-capable token. Error codes distinguish failure modes (`not_signed_in`, `keyring`,
`token_exchange`, `network`, `authorization`, `consent_required`).

**Keyring chunking (Windows footgun).** Refresh tokens are chunked across numbered keyring entries
(`{tenant}:{oid}`, `{tenant}:{oid}#1`, …) in `token_cache.rs` because Windows Credential Manager
caps a blob at 2560 UTF-16 bytes and Entra tokens exceed that — don't collapse them back to a
single `set_password`, or Windows sign-in breaks.

## Optional on-demand extra-scope tokens

Some features need admin-consent/premium scopes beyond the sign-in bundle:

| Scope | Feature |
|---|---|
| `Synchronization.Read.All` | SCIM provisioning |
| `AuditLog.Read.All` | Directory activity / change log (the Activity tab) **and** the service-principal sign-in-activity report behind the audit's unused-app detection. The `reports/servicePrincipalSignInActivities` report's least-privileged scope is `AuditLog.Read.All`, **not** `Reports.Read.All`. |
| `Policy.Read.All` | Conditional Access visibility (the Conditional Access tab) |
| `Policy.ReadWrite.ApplicationConfiguration` | Claims-mapping policies — SAML attribute & claim customization in the SSO wizard / detail "SSO" tab |
| `Sites.FullControl.All` | SharePoint `Sites.Selected` — list/grant/revoke a site's per-app permissions in the Permissions tab's SharePoint site access section. The site-permission endpoints require it even for **reads**, since the verb-selected read token only holds `Directory.Read.All`. |
| `GroupMember.ReadWrite.All` | Group-membership add/remove for a service principal (the enterprise-app Access tab's "Group memberships" section) — the access model for group-gated APIs like Power BI / Fabric tenant settings. Deliberately the membership-only scope, not `Group.ReadWrite.All` (the app never creates/deletes groups). Membership **reads** ride the sign-in `Directory.Read.All`; only the `$ref` writes need this. |
| ARM `management.azure.com/.default` | Managed-identity Azure RBAC |
| Log Analytics `api.loganalytics.azure.com/.default` | Observed Graph activity (granted-vs-used) — queries `MicrosoftGraphActivityLogs` from a Log Analytics workspace (its own data-plane host + audience, distinct from ARM; sovereign variants via `CloudEnvironment::log_analytics_resource`). Also needs the Log Analytics Reader Azure RBAC role on the workspace and Entra diagnostic settings exporting the table. |

These are **never** added to the sign-in scope set (that could block sign-in for un-consented
tenants). Instead they ride a `ScopedTokenAdapter` acquired lazily:
`GraphClient.sync_token`/`audit_log_token`/`policy_token`/`policy_write_token`/`sharepoint_token`/
`group_member_token` (via `with_sync_token`/`with_audit_log_token`/`with_policy_token`/
`with_policy_write_token`/`with_sharepoint_token`/`with_group_member_token`; reads go through
`GraphClient::scoped_get`, claims/site/membership writes through the scoped POST/PATCH/DELETE
helpers), `AppState::arm_for` for the ARM client, and `AppState::log_analytics_for` for the Azure
Monitor Logs query client.

Any call must **degrade gracefully** — a missing scope/license/consent surfaces as an "unavailable"
message, never a hard failure of the surrounding view. New optional-scope features must follow this
pattern (and add the origin to the CSP only if the *frontend* fetches it directly — see the CSP
gotcha in AGENTS.md).

## Silent grants can't *obtain* consent — only use it

A `refresh_token` grant for a not-yet-consented scope returns AADSTS65001/65004, which
`service.rs::classify_token_error` maps to `AuthError::ConsentRequired` (code `consent_required`),
**distinct from `InvalidGrant`** — the refresh token is still valid, so `access_token_for_scopes`
must NOT purge it (purging here = signing the user out over a missing optional scope; that was the
bug).

To actually acquire consent, call `EntraAuthService::consent_for_scopes` — an interactive
`/authorize` round trip with `prompt=consent`, pinned to the signed-in account via `login_hint`,
that seeds the token cache so the next silent acquisition succeeds. The UI reaches it through the
`request_scope_consent(tenant_id, feature)` command (feature → scopes via
`AppState::consent_scopes_for`).

**Pre-acquire typed tokens so `consent_required` survives to the UI.** The `BearerProvider`
boundary flattens errors to `String`, so a command that wants the UI to show a "Grant consent"
button must pre-acquire the token with a typed call (e.g. `AppState::ensure_arm_token`,
`ensure_policy_write_token`, `ensure_sharepoint_token`, `ensure_audit_log_token`,
`ensure_exchange_token`, `ensure_group_member_token`, or `ensure_log_analytics_token`). Examples:

- `list_managed_identity_azure_roles` (ARM)
- `commands::sso::create_saml_sso_application` / `set_claims_mapping` (policy write)
- the `commands::sharepoint` site-permission commands — the SharePoint site access section shows the button on
  `consent_required` and retries the listing after consent
- `add_sp_to_group` / `remove_sp_from_group` — the Access tab's "Group memberships" section stashes
  the attempted change and offers "Grant consent & retry", replaying it after the grant
- the `commands::exchange` commands — they build their client via `exchange_client_checked` →
  `ensure_exchange_token`, so the Exchange/Permissions tabs can offer "Grant consent & retry"
- `run_audit` — pre-acquires the `AuditLog.Read.All` token so the Security-audit view can offer a
  "Grant consent & re-run" button that enables the **Unused** tab. The sign-in activity report
  behind it is gated on that scope + Entra ID P1/P2;
  `AuditRunResult.sign_in_report_available`/`sign_in_consent_required` drive the banner/empty state.

## Force re-auth in place — never make the user sign out

A dead refresh token can't be re-minted silently: `InvalidGrant` / `RefreshTokenMissing` both map
to `UiError` code **`refresh_missing`** (`NotSignedIn` → **`not_signed_in`**). The recovery is the
`reauthenticate` command → `EntraAuthService::reauthenticate(&TenantContext)`: ONE interactive
browser round trip (`prompt=login`, `login_hint` = the current account) that validates the
returned `tid` + `oid` match the session (cache safety, mirroring `consent_for_scopes`; a
different account errors) — restoring the session **without** dropping the tenant's data caches,
which a sign-out/sign-in cycle would.

- It takes the full `TenantContext`, not a bare tenant id, because `InvalidGrant` purges
  `known_tenants` — the front-end still holds the context in `active_tenant`.
- Front-end wiring: the top-bar **Refresh Token** button (`shell.rs`, next to the tenant chip)
  tries silent `refresh_session` first, then falls back to `reauthenticate` on those two codes.
  `Session::report_command_error(&UiError)` — the central error sink;
  `use_command::run_toast_err` routes through it — shows a **Re-authenticate** toast action keyed
  on the same two codes, else a plain error toast.
- **Adding a new re-auth-fatal code → extend BOTH `matches!` sets** (`state.rs` + `shell.rs`);
  they must stay in lockstep or the button and the toast disagree.

## Capability catalog — role/scope feedback rides one source of truth

There is no single role that unlocks the app — it runs with the signed-in user's delegated rights
across **three independent auth planes** (Entra directory, Azure RBAC, Exchange Online RBAC), each
with its own PIM ([docs/operator-rbac/OPERATOR-ROLES.md](../operator-rbac/OPERATOR-ROLES.md)).

`azapptoolkit-core::capabilities` is the single source of truth mapping each privileged feature →
its `plane`, required role(s) (`directory_roles_any`, **any one** satisfies — encodes built-in
alternatives), delegated `scopes`, and a `remediation` string. When adding a privileged feature,
add a catalog entry instead of hardcoding a role string.

Three surfaces read it so the guidance never drifts:

1. **Reactive 403 hints** — `ArmError`/`KeyVaultError::ui_hint()` (appended in the dto `From<…>`
   impls, like Exchange) and command-level `forbidden` overrides (`permissions.rs`
   `grant_failure_message`, `managed_identity.rs`, `sharepoint.rs` `sharepoint_err`) pull
   `remediation`. There is deliberately no blanket `GraphError::ui_hint` — a Graph 403 is too
   ambiguous to name a role.
2. **Proactive `RequiresRole` label** (`web-rs/components/requires_role.rs`, on the privileged
   tabs/actions).
3. **Live readiness checklist** (`commands::readiness::check_readiness` → `ActiveView::Readiness`,
   shell nav above Refresh Token). The checklist reports **two halves per capability** (role +
   scope — "Two halves, both required"):
   - role half via `GraphClient::me_active_directory_roles`
     (`/me/transitiveMemberOf/...directoryRole`, **active-only by design** so a
     PIM-eligible-but-inactive role reads as missing — the nudge to activate);
   - scope half via a **silent token probe** per audience (`access_token_for_scopes[_cae]`:
     `Ok`=Have, `consent_required`=Missing, else Unknown).

   `check_readiness` is **never cached** (freshness after a PIM activation is the point); the Azure
   and Exchange *role* halves are deliberately `Unknown` (not per-user enumerable — verify in PIM /
   use the scoping action).

## SAML signing-certificate rollover — staged, resumable, revertible

A SAML signing certificate is the trust the *application* validates assertions against, so replacing
it is a two-sided change. Entra can hold several certificates on the service principal at once and
nominates one via `preferredTokenSigningKeyThumbprint`; downtime comes entirely from promoting a key
the application has never seen. Commands live in `commands/sso/mod.rs`.

**Phase is derived, never stored.** `build_rollover` projects `RolloverPhase` from live SP state
(`keyCredentials` + `preferredTokenSigningKeyThumbprint` + `now`) on every read. Nothing about an
in-flight rollover is persisted, so one abandoned half way — app closed, tenant switched, handed to a
colleague — resumes exactly where it was, and two operators can't hold different ideas about it.
Phases: `Steady` · `Staged` (a valid newer cert is not yet preferred) · `PendingRetire` (the newest
is live, the previous one still present as the rollback) · `Unconfigured`.

**Three Graph behaviours are load-bearing:**

1. **One certificate is two `keyCredentials` entries** — a `Sign` and a `Verify` half sharing one
   `customKeyIdentifier`. Dedupe by thumbprint or every certificate lists twice and a
   one-certificate app reads as mid-rollover. `remove_service_principal_key_credential` drops *both*
   halves for the same reason — removing one strands the other.
2. **`customKeyIdentifier` is uppercase** while `preferredTokenSigningKeyThumbprint` can differ in
   case. Every comparison is `eq_ignore_ascii_case`; a case-sensitive match shows no active
   certificate and reads as a broken app.
3. **Entra auto-promotes.** Once the active certificate expires with a valid inactive one present,
   Entra signs with the inactive one whether or not anyone activated it. So a staged certificate
   turns the active cert's expiry into an *activation deadline* (`auto_promote_deadline`), and an
   expired-but-still-nominated certificate means the promotion already happened.

**Expired-ness is decided once, by timestamp.** `CertStatus::Expired` comes from `end <= now`, and
`days_to_expiry` is **floored** (`div_euclid`), not truncated — a certificate expired 12 hours ago is
`-1`, never a `0` indistinguishable from "expires today". The board's `sso_cert_status` additionally
reads Expired off `CertStatus` rather than re-deriving it from the day count, so the board and the
SSO tab can't disagree about the same certificate during the first 24 hours after expiry.

**Guards.** `activate` and `revert` share one PATCH (`set_preferred_signing_key`) that re-resolves
live state and refuses a thumbprint that is missing or expired; activating the already-active
certificate is a no-op, not an error. `retire` refuses the active certificate (breaks sign-in — or,
when it's expired-but-still-nominated, would leave the nomination dangling; the message says which)
and the staged one (that's a pending rollover, not a leftover) — and because the superseded
certificate *is* the rollback, retiring is what ends the ability to revert, so it stays an explicit
action. An **expired, non-nominated** certificate passes both guards and gets a per-row **Remove**
button in the rollover table (the portal's "Delete certificate" on inactive certs); the superseded
one deliberately does not — its removal stays on the explicit "Retire previous certificate" action.

**Deliberately not a guard:** activation is not gated on `probe_federation_metadata` having run. The
probe reads the public metadata endpoint (a backend `reqwest` call — `connect-src` governs the
webview only) and can fail for reasons unrelated to the rollover; blocking on it would strand an
operator mid-window. It is an unchecked precondition in the UI instead, and a failed probe renders as
"couldn't check", never as "not published" — a false negative there talks an operator out of a safe
activation. The probe compares base64 DER bodies rather than thumbprints: deriving a thumbprint means
SHA-1, which `cert.rs` deliberately keeps out of the tree.

**Bulk.** Staging is additive, reversible, and changes nothing for users, so it is the only phase safe
to fan out (via `run_bulk_seq`, like the other bulk remediations). Activation stays per-app and gated.

### The tenant-wide expiry board

`list_sso_certificate_expirations` (Security → **SSO certificates**) is what makes rotation
schedulable instead of reactive. The audit's credential rules read an *application's*
`keyCredentials`, so a signing certificate — which lives on the service principal — was invisible
in-app entirely.

- **One filtered scan, not a fan-out.** `preferredSingleSignOnMode` supports `$filter eq` on the
  default query surface (no `ConsistencyLevel`, no `$count`), and only SAML apps have a signing
  certificate, so `list_saml_sso_service_principals` returns exactly the rows that matter in one
  paged GET. The `SP_INDEX_MAX` cap applies to that filtered subset, which no real tenant reaches.
- **Coverage caveat (documented Graph behaviour).** Microsoft's docs note `preferredSingleSignOnMode`
  "might be null for older SAML apps" — the filtered scan cannot see those, so an app with signing
  certificates can be missing from the board entirely. The board carries a hint saying so; don't
  present it as tenant-wide proof, and don't "fix" this by scanning every SP (that's the fan-out the
  filter exists to avoid).
- **Same projection as the SSO tab.** Rows are built by `build_rollover`, so the board and the
  per-app panel can never disagree about whether a replacement is staged.
- **Not a risk-score input.** An expiring certificate is an *availability* risk; `risk_score` ranks
  exposure. Points here would move apps up a ranking operators read as "most over-permissioned"
  because they are due for maintenance. It reuses `CredentialStatus` and `EXPIRY_WARNING_DAYS` so
  "Expiring Soon" means the same thing on both expiry boards, and an unreadable expiry is `Unknown`,
  never `Active`.
- **Cache busting is wider than it looks.** The board caches on `CacheKind::Lists`, and
  `invalidate_sso_cert_board` fires on `Ok` from every certificate mutation **plus**
  `set_notification_emails` (it flips the "nobody is warned" column) and `set_sso_mode` (it decides
  whether the app is on the board at all). Missing either of those last two leaves the board
  contradicting the SSO tab for up to the TTL.

### Bulk staging

`bulk_stage_sso_certificates` is the only rollover phase offered across a selection. Staging is
additive and inactive, so a bulk run changes nothing for users; activation flips
`preferredTokenSigningKeyThumbprint` and is a coordinated switch, which is why it stays per-app.

- Runs through `run_bulk_seq` like the other bulk remediations — sequential (the per-app core takes
  `State`, so it is not `Send`), claiming `audit_cancel` before any suspension point, degrading to a
  per-app `BulkError`, and halting on a re-auth-fatal code rather than failing every remaining app
  identically.
- **Idempotent by design.** `stage_if_not_already` re-resolves live state and skips an app that
  already has a valid replacement staged. The board's work-queue filter lists an app until its
  rollover is *finished*, not until it is started, so without this an operator who stages on Monday
  and returns on Wednesday mints a second spare on every app they already prepared.
- The outcome distinguishes `thumbprint: Some(..)` (staged) from `skipped: true` (already prepared);
  the summary reports them separately, because folding skips into "staged" claims work that did not
  happen.
- Takes **service-principal** ids. `Session.tenant_ui.selected_sso_cert_ids` is deliberately a third
  selection set alongside `selected_app_ids`/`selected_audit_ids`, which hold app-registration object
  ids — feeding SP ids to an app-registration bulk command would target the wrong objects entirely.
