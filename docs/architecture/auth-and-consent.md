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
