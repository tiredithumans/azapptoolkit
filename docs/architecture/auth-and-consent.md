# Auth, consent & role feedback

Deep-dive companion to the auth/consent gotchas in [AGENTS.md](../../AGENTS.md). Read this before
editing `azapptoolkit-auth`, `AppState` token plumbing, consent flows, or anything touching the
capability catalog / readiness checklist.

## Token lifecycle

Access tokens are refreshed lazily (~60s before expiry) behind a shared mutex; refresh tokens
persist in the OS keyring, access tokens never touch disk (in-memory, zeroized on drop). Write
scopes are consented **incrementally** on first write — a browse-only session holds no
mutate-capable token. Error codes distinguish failure modes (`not_signed_in`, `keyring`,
`keyring_unavailable`, `token_exchange`, `network`, `authorization`, `consent_required`,
`interaction_required`, `cancelled`). `keyring_unavailable` is a credential store that could not be
registered at all (on Linux: no Secret Service provider on the session bus) — memoised for the
process, so its sign-in hint says to start one and restart, never to "unlock" it.

**The cache keys on CAE-ness.** Access tokens are cached per `(tenant, scope_key, cae)`. Every Graph
adapter is `ScopedTokenAdapter::new_cae` (tokens minted with the `cp1` client capability, revoked
promptly on a password reset, disabled user or risky sign-in), while ARM / Exchange / Key Vault /
Log Analytics stay non-CAE. With CAE-ness outside the key, whichever flow seeded a slot first decided
for both; now a mismatch costs one extra silent refresh, never a wrong token. The flows that seed a
Graph slot mint CAE to match: `sign_in` and `reauthenticate` (the `claims` parameter rides both the
`/authorize` URL and the code redemption), `refresh_session` / `restore_session`
(`access_token_for_scopes_cae`), and consent / step-up when `EntraAuthService::is_graph_scope_set`
says the requested set is a Graph one. The per-scope refresh lock stays keyed on
`(tenant, scope_key)` only.

**The `/token` POST rides the shared retry budget** (`core::http_retry::with_retries`): a 429
(honouring `Retry-After`) or a 5xx / network failure is retried; any other rejection is terminal and
classified as before. The class comes from the grant (`retry_class_for`): a `refresh_token` grant is
idempotent, an `authorization_code` is single-use, so only a 429 replays it. A timeout is terminal,
and so is a `Retry-After` above `TOKEN_RETRY_AFTER_MAX_SECS` (30 s), because the refresh holds its
per-scope lock across the backoff (intended for a short wait — same-key waiters get the retried
result instead of re-POSTing into the same throttle — but not for the minutes the shared policy
honours for Graph / ARM writes).

**An abandoned browser round trip is `cancelled`.** The redirect wait (`REDIRECT_WAIT`, 300 s)
timing out, or Entra redirecting `access_denied` with `error_subcode=cancel` or with no AADSTS code
in its description, is `AuthError::Cancelled`. A coded `access_denied` (AADSTS65004, a declined
consent) stays `authorization`.

**Only the pending `state` ends the redirect wait.** The loopback port is reachable by any local
process and by a blind cross-origin request from any page in the browser, so a request whose `state`
is missing or foreign (a bare `error=` included) is answered 400, logged at warn (which parameters
were present, never their values) and ignored; a non-`GET` (a CORS/PNA preflight) gets a 404. The
trade-off is deliberate: a genuinely mismatched redirect now waits out `REDIRECT_WAIT` and surfaces as
`cancelled` rather than failing fast as `StateMismatch`. A matching `error=` redirect keeps its
OAuth code (gated to `[a-z_]`) and the AADSTS code from `error_description`, redacted by the same
`wire::redact_aad_error` as a `/token` error, so the sign-in card's AADSTS hint fires.

**Launch restore.** The keyring entry is keyed `{tenant}:{oid}`, and the oid used to live only in
memory — so nothing could read the refresh token back at startup, and every launch showed the
sign-in card and a `prompt=select_account` browser bounce. `UserSettings.last_account` now persists
that pointer (object ids + UPN — identifiers, never the token), and the `restore_session` command
redeems it for the sign-in read scopes through the ordinary silent-refresh path. It is guarded on
the *configured* tenant: an account remembered under a different directory is refused rather than
used to address someone else's keyring entry. Every empty case — nothing stored, signed out, tenant
repointed, token revoked, keyring locked — returns `Ok(None)`, not an error, and lands on the normal
sign-in card; a failed attempt removes the context again so it can never leave a half-live session.
The one restore failure returned as an error is an unreachable token endpoint (`network`: offline, a
captive portal, a proxy down) — the refresh token is untouched (only `InvalidGrant` purges it), so
the launch screen shows a warning Callout with a Retry of the silent restore
(`views::sign_in::attempt_restore`, shared by `Root`'s launch attempt and the button) instead of
sending the operator to a browser that can't load Entra ID either.

**A browser that won't launch offers its link in the app.** When `open_system_browser` fails (no
default handler, a confined `xdg-open`, a policy blocking the handler), `run_auth_code_flow` hands
the authorize URL to the hook installed with `EntraAuthService::set_browser_fallback` —
`Some(url)`, then `None` when the browser leg ends however it ends (a `ManualLinkOffer` guard). The
desktop emits it as the `auth-browser-fallback` event (`commands::auth::offer_sign_in_link_in_the_webview`,
wired in `lib.rs` setup), and `BrowserFallbackNotice`, mounted once in `Root` above every screen,
shows it through `CopyBlock` — so sign-in, consent, step-up and re-auth are all covered. The URL is
single-use (PKCE + `state`) and redeemable only through this process's loopback listener; it is
shown to the operator, never logged.

**Keyring chunking (Windows footgun).** Refresh tokens are chunked across numbered keyring entries
(`{tenant}:{oid}`, `{tenant}:{oid}#1`, …) in `token_cache.rs` because Windows Credential Manager
caps a blob at 2560 UTF-16 bytes and Entra tokens exceed that — don't collapse them back to a
single `set_password`, or Windows sign-in breaks.

## Optional on-demand extra-scope tokens

Some features need admin-consent/premium scopes beyond the sign-in bundle:

| Scope | Feature |
|---|---|
| `Synchronization.Read.All` | SCIM provisioning |
| `AuditLog.Read.All` | Directory activity / change log (the Activity tab), **and** the two sign-in reports: the service-principal sign-in-activity report behind the audit's unused-app detection, **and** the beta `reports/appCredentialSignInActivities` behind the unused-credential advisory and the Credentials tab's Last-used column (that one is **Global cloud only** — a sovereign cloud reads it as unavailable and the feature stays off). Both reports' least-privileged scope is `AuditLog.Read.All`, **not** `Reports.Read.All`. |
| `Policy.Read.All` | Conditional Access visibility (the Conditional Access tab) **and** the app-management-policy reads (tenant default + per-app overrides) behind the Credentials tab's lifetime markers, the add-secret pre-warning, the audit's lifetime advisory and the Home posture line. Both ride the ONE `policy` consent feature / `policy_token` — the CA tab's "Grant consent" covers the policy reads too (v1.0 endpoints, no P1/P2 needed for the lifetime half, unlike CA). |
| `Policy.ReadWrite.ApplicationConfiguration` + `Application.ReadWrite.All` (one token) | Claims-mapping policies — SAML attribute & claim customization in the SSO wizard / detail "SSO" tab. The policy object itself needs only the Policy scope, but the service-principal `$ref` assign/list/remove need both in the same token, so one bundle (and one consent) covers reading and saving. A failed claims read sets `SsoConfigDto.claims_read_failed`; the SSO tab then turns Save off and offers "Load claims" (consent + reload) rather than saving over claims it never loaded. |
| `Sites.FullControl.All` | SharePoint `Sites.Selected` — list/grant/revoke a site's per-app permissions in the Permissions tab's SharePoint site access section. The site-permission endpoints require it even for **reads**, since the verb-selected read token only holds `Directory.Read.All`. |
| `GroupMember.ReadWrite.All` + `Application.ReadWrite.All` (one token) | Group-membership add/remove for a service principal (the enterprise-app Access tab's "Group memberships" section) — the access model for group-gated APIs like Power BI / Fabric tenant settings. Learn's "Add members" table documents the pair for a `servicePrincipal` member (Graph must also write the SP); `Application.ReadWrite.All` is already in the write bundle, so this widens nothing. Deliberately the membership-only group scope, not `Group.ReadWrite.All` (the app never creates/deletes groups). Membership **reads** ride the sign-in `Directory.Read.All`; only the `$ref` writes need this. |
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
`azapptoolkit_auth::service::wire::classify_token_error` maps to `AuthError::ConsentRequired` (code `consent_required`),
**distinct from `InvalidGrant`** — the refresh token is still valid, so `access_token_for_scopes`
must NOT purge it (purging here = signing the user out over a missing optional scope; that was the
bug).

To actually acquire consent, call `EntraAuthService::consent_for_scopes` — an interactive
`/authorize` round trip with `prompt=consent`, pinned to the signed-in account via `login_hint`,
that seeds the token cache so the next silent acquisition succeeds. The UI reaches it through the
`request_scope_consent(tenant_id, feature)` command (feature → scopes via
`AppState::consent_scopes_for`).

**The front-end has one shared fallback.** `Session::report_consent_required` is the consent twin of
`report_if_session_dead`: any command failing `consent_required` raises a toast offering the grant,
so a missing consent is recoverable even where no bespoke button exists — from the toast path
(`run_toast_err`) and the inline-error path (`run`, which keeps its inline text too) alike, both via
`Session::report_recovery_action`. `CommandState` carries the
scope set to offer as `consent_feature`, defaulting to `"write"` — the Graph write scopes, which are
consented lazily on first write and which, before this, had no grant path anywhere in the UI. A
component whose mutations ride an on-demand feature scope overrides it
(`use_command().with_consent_feature("exchange")`); offering the wrong set is a real bug this repo
has shipped, when the scope wizard offered the Exchange scopes for a failed org-wide Graph grant.

**`consent_required` crosses the `BearerProvider` boundary; pre-acquire anyway where it matters.**
`token_adapter::token_error` carries the classification as `TokenError { code }`, and every client's
`Token` arm passes it through (`core::reauth::passthrough_code` — the re-auth-fatal codes plus the
non-fatal `PASSTHROUGH_NON_FATAL_CODES`: `consent_required`, and `network_error` for a refresh that
couldn't reach the token endpoint, which so stays retryable). So the shared toast fallback fires for
any command whose scoped call hits a missing consent. Pre-acquire the token with a typed call anyway
when the command has side effects before the scoped call (a grant must not half-land before it
discovers the gap) or needs a specific feature's button (e.g. `AppState::ensure_arm_token`,
`ensure_policy_write_token`, `ensure_sharepoint_token`, `ensure_audit_log_token`,
`ensure_exchange_token`, `ensure_group_member_token`, `ensure_sync_token`, or
`ensure_log_analytics_token`). Each wrapper is a one-liner over `AppState::ensure_feature_token`,
which reads the scope set from the `ConsentFeature` table (`AppState::feature_scopes` — the same
table `consent_scopes_for` serves) and derives CAE-ness from it via `is_graph_scope_set`, so no
caller picks the CAE slot by hand. Examples:

- `list_managed_identity_azure_roles` (ARM)
- `commands::sso::create_saml_sso_application` / `set_claims_mapping` (policy write)
- the `commands::sharepoint` site-permission commands — the SharePoint site access section shows the button on
  `consent_required` and retries the listing after consent
- `add_sp_to_group` / `remove_sp_from_group` — the Access tab's "Group memberships" section stashes
  the attempted change and offers "Grant consent & retry", replaying it after the grant
- the `commands::exchange` commands — they build their client via `exchange_client_checked` →
  `ensure_exchange_token`, so the Exchange/Permissions tabs can offer "Grant consent & retry"
- `get_enterprise_app_provisioning` (`ensure_sync_token`) — the Provisioning tab turns
  `consent_required` into "Grant consent & retry" for the `sync` feature and reloads; a 403 keeps
  a role/license message instead
- `run_audit` — pre-acquires the `AuditLog.Read.All` token so the Security-audit view can offer a
  "Grant consent & re-run" button that enables the **Unused** tab. The sign-in activity report
  behind it is gated on that scope + Entra ID P1/P2;
  `AuditRunResult.sign_in_report_available`/`sign_in_consent_required` drive the banner/empty state.

## A step-up is not a dead session

A Conditional Access policy can demand an interactive step — MFA, registration, an external
challenge — for **one resource** (a "Require MFA for Azure management" or authentication-strength
policy). The silent grant for that audience then fails `interaction_required` / `login_required`,
or `invalid_grant` carrying AADSTS50074/50076/50079/50158. `classify_token_error` maps all of these
to `AuthError::InteractionRequired` (code **`interaction_required`**) — after the consent check, so a
consent gap still wins — and `access_token_inner` does **not** purge on it: the refresh token is
still valid for every other audience (MSAL keeps the account on `InteractionRequiredAuthError`).
Classifying it as `InvalidGrant` used to delete the keyring token and forget the tenant, so an
ARM-only MFA policy signed the operator out of Graph browsing, and re-authenticating on the Graph
read scopes never met the ARM policy, so the purge repeated.

- `interaction_required` is a `core::reauth::PASSTHROUGH_NON_FATAL_CODES` entry: it survives every
  client's `Token` arm, never halts a fan-out, and is not retryable. It must never join
  `REAUTH_FATAL_CODES`.
- Recovery: `request_scope_step_up(tenant_id, feature)` →
  `EntraAuthService::step_up_where_required` → `step_up_for_scopes` — one `prompt=login` round trip
  (the shared core with `consent_for_scopes`, identity-checked the same way), which seeds the token
  cache so the retried command is silent. Nothing in the error names the audience, so the caller
  names the feature, and `step_up_where_required` aims it:
  - **every Graph feature steps up on the sign-in read scopes** — a policy targets the resource,
    not individual scopes, and the read set is the one always consented; stepping up on the
    `"write"` default would show an operator who never consented the write bundle a consent screen
    instead of the MFA prompt. It runs unconditionally, because a cached read token masks the need;
  - **a non-Graph feature** (ARM, Exchange, Key Vault, Log Analytics) is first acquired silently and
    opens the browser only when that still fails `interaction_required`; any other failure (a
    missing consent) comes back as-is. So a surface can name every audience its command acquires.
- Two front-end levers call it, both one per pattern: the toast sink
  (`Session::report_interaction_required`, **Verify identity**, with the caller's
  `consent_feature` — ARM / Exchange writes declare theirs) and, for a surface that renders its own
  error, the inline `components::verify_identity_button::VerifyIdentityButton` (**Verify identity &
  retry**, which re-runs the surface). The inline one sits beside each hand-rolled "Grant consent &
  retry": the managed-identity Azure RBAC tab (`arm`; its Assign form routes through
  `report_recovery_action(.., "arm")`), the Key Vault RBAC sweep (`arm`), Observed Graph activity
  (`log_analytics` then `arm` — the query acquires both) and the mailbox-scoping banner
  (`exchange`).
- A step-up on the Graph read scopes (tenant-wide MFA, sign-in frequency) comes back from
  `refresh_session` as `interaction_required`; **Refresh token** falls back to `reauthenticate`
  for it, which is exactly that step-up.

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
- The `InvalidGrant` purge is conditional (`token_cache::delete_refresh_token_if_current`): it
  deletes only if the keyring still holds the token that just failed, compared and deleted under
  the chunk-set lock. Refresh locks are per scope set, so a slow refresh can fail with the old token
  after `reauthenticate` stored a new one; that newer session is kept and the call returns
  `RefreshTokenMissing` without dropping the tenant, so the silent `refresh_session` retry recovers.
  A narrow window remains: a `reauthenticate` landing between the delete and the in-memory cleanup
  loses its cached tokens and registration (its keyring token survives for launch restore).
- `sign_out` deletes the keyring token (the one fallible step) first, and clears the token cache and
  `known_tenants` only after it succeeds, so a failure never leaves a refresh token for the next
  launch to restore. For a multi-chunk (Windows) token, a failure after the first chunk is gone keeps
  the in-memory session but leaves the stored token unloadable. Every keyring call in the service
  runs on the blocking pool (pinned by a source scan in `service/mod.rs`).
- The configured tenant id is canonicalised (`core::identity::canonical_tenant_id`: trimmed,
  lowercase) wherever it enters (`EntraAuthService::new`, `AppState` resolution, `set_auth_config`),
  because Entra issues `tid` lowercase and the tid check, cache keys and launch restore compare
  verbatim.
- Front-end wiring: `Session::spawn_refresh_token` tries silent `refresh_session` first, then
  falls back to `reauthenticate` on those two codes (and on `interaction_required`, the Graph
  read-scope step-up). It is the one entry for the top-bar **Refresh
  token** button (`shell.rs`, next to the tenant chip) and the 401 toast below, and its in-flight
  guard (`Session.token_refreshing` / `token_reauthing`) lives on the session, so neither trigger
  can race a second refresh or a second browser flow.
  `Session::report_recovery_action` is the one ordering of the recovery toasts — dead session
  (**Re-authenticate**) → rejected token (**Refresh token**) → missing consent (**Grant consent**)
  → Conditional Access step-up (**Verify identity**) —
  used by both `report_command_error_for` (the central sink behind `run_toast_err`; anything else
  is a plain error toast) and `CommandState::run` (inline-error surfaces, which keep their inline
  text as well). Surfaces with their own consent / step-up button (the Permission Tester, the
  Resource Access Sites and Key Vault sweeps) call only `report_if_session_dead` first and show
  their inline text when it returns false; ones without (the mailbox probe, the Key Vault browser)
  take the whole `report_recovery_action` ladder; global search points its status row at the toast.
  A recovery toast dedupes by lever + feature (`Session::push_recovery_toast`: `reauth`,
  `refresh-token:{text}`, `consent:{feature}`, `step-up:{feature}`), so a burst of failures raises
  one lever, and the stack cap (`MAX_TOASTS`) drops transient toasts before any sticky one
  (`Toast::is_sticky`: an error with an action). Only `CommandState::run_toast_err` adds **Retry**
  (`report_command_error_with_retry`), for a failure the backend marks `retryable` (throttled,
  5xx, network) and no recovery lever outranks; the Retry is pinned to the tenant the call ran for,
  because toasts survive a tenant switch, and bounded by the owning component: a sticky toast
  outlives its detail pane, so a Retry whose `CommandState.busy` is disposed (or still busy) says
  why instead of re-running an op that would read disposed signals and panic. Direct `report_command_error` callers hold no op to
  re-run and keep a plain toast.
- `unauthorized` (a client 401 — a revoked token, or a CAE claims challenge the silent re-mint
  couldn't satisfy) gets the **Refresh token** action but is deliberately NOT re-auth-fatal: one
  401 doesn't prove the session dead, so a fan-out keeps going. The Exchange/Key Vault/ARM 401
  hints and `premium_feature_err` point at the same control, never at signing out. The toast shows
  that curated text (`UiError::unauthorized_guidance`, everything past the shared
  `core::reauth::UNAUTHORIZED_STATUS` line) and falls back to a generic lead only for a bare 401,
  because the hint's "if it persists" advice is all that separates a persistent 401 from a
  refresh loop.
- **Adding a new re-auth-fatal code → add it to `core::reauth::REAUTH_FATAL_CODES`, nothing
  else**; every predicate and client pass-through reads that slice.

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
   `grant_failure_message`, `managed_identity.rs`, `sharepoint.rs` `sharepoint_err`,
   `enterprise_application.rs` `group_membership_err` / `provisioning_err` → `provisioning_read`,
   `sso::set_claims_mapping`'s `claims_policy_err` → `sso_claims_mapping`) pull `remediation`. There is deliberately no blanket `GraphError::ui_hint` — a Graph 403 is too
   ambiguous to name a role.
2. **Proactive `RequiresRole` label** (`web-rs/components/requires_role.rs`, on the privileged
   tabs/actions).
3. **Live readiness checklist** (`commands::readiness::check_readiness` → `ActiveView::Readiness`,
   shell nav above Refresh Token). The checklist reports **two halves per capability** (role +
   scope — "Two halves, both required"):
   - role half via `GraphClient::me_active_directory_roles`
     (`/me/transitiveMemberOf/...directoryRole`, **active-only by design** so a
     PIM-eligible-but-inactive role reads as missing — the nudge to activate). A Missing row says
     "activate if eligible, otherwise request an assignment" and links the cloud-correct PIM
     "My roles" page (`ReadinessReport.pim_activation_url` from
     `CloudEnvironment::pim_my_roles_url`). Telling eligible from unassigned would need
     `RoleEligibilitySchedule.Read.Directory`, deliberately not requested;
   - scope half via a **silent token probe** per audience (`AppState::ensure_feature_token` over
     `ConsentFeature` — the same scope-set + CAE derivation the `ensure_*` wrappers use, so a probe
     can never seed a token in a different CAE slot from the adapter that reuses it; `Ok`=Have,
     `consent_required`=Missing, else Unknown).
   - a Missing scope is named through `Capability::display_scopes(cloud)`: the catalog writes a
     resource audience as a `{keyvault}` / `{arm}` / `{log_analytics}` / `{exchange}` placeholder
     (never a literal host, pinned by `no_catalog_scope_hardcodes_a_cloud_host`), expanded to the
     configured cloud's origin — the same audience the probe asks for (pinned by
     `displayed_resource_scopes_are_the_probed_ones` in `readiness.rs`).

   Every `ConsentFeature` has a catalog row and every catalog `scope_feature` is a
   `ConsentFeature` (pinned by `every_consent_feature_has_a_catalog_row` /
   `every_catalog_scope_feature_is_a_consent_feature` in `state.rs`), so each on-demand scope the
   app can request shows up on the checklist.

   `check_readiness` is **never cached** (freshness after a PIM activation is the point); the Azure
   and Exchange *role* halves are deliberately `Unknown` (not per-user enumerable — verify in PIM /
   use the scoping action).

## Signed-AuthnRequest visibility — read-only, never-flag-on-unknown

`requestSignatureVerification` on the paired **application** (`isSignedRequestRequired` +
`allowedWeakAlgorithms`) is the tenant-side gate for whether Entra verifies signed SAML
authentication requests. `get_application_sso_fields` selects it (no new scope — it rides the
already-consented default token on a round trip that already happens), and
`extract_request_signature_verification` projects it onto `SsoConfigDto` as
`signed_requests_required` + `allowed_weak_signature_algorithms`.

**Two invariants.** (1) A missing or malformed block is **unknown** and renders *nothing* — the
tab must never imply unsigned requests are acceptable just because Graph omitted a field
(the never-flag-on-unknown contract, shared with the credential-lifetime advisory). A
`"none"`/empty `allowedWeakAlgorithms` normalises to `None`: present means a real allowance.
(2) **There is deliberately no write path.** The v1.0 `application-update` property list (checked
2026-10-03) does not list the property as updatable, so the SSO tab shows the state and points to
the Entra admin center instead of PATCHing an undocumented field on an auth-trust control; a
toggle may only be added with evidence the PATCH lands. The tab also does not score it —
adding a rule would need a per-app SSO read inside the audit fan-out and is CHANGELOG-gated as a
ranking change.

## SAML signing-certificate rollover — staged, resumable, revertible

A SAML signing certificate is the trust the *application* validates assertions against, so replacing
it is a two-sided change. Entra can hold several certificates on the service principal at once and
nominates one via `preferredTokenSigningKeyThumbprint`; downtime comes entirely from promoting a key
the application has never seen. Commands live in `commands/sso/mod.rs`.

**Phase is derived, never stored.** `build_rollover` projects `RolloverPhase` from live SP state
(`keyCredentials` + `preferredTokenSigningKeyThumbprint` + `now`) on every read. Nothing about an
in-flight rollover is persisted, so one abandoned half way — app closed, tenant switched, handed to a
colleague — resumes exactly where it was, and two operators can't hold different ideas about it.
`get_sso_config` carries the SSO tab's initial `SigningCertRolloverDto` and the app-owner
`SsoSummary`, both projected from its single service-principal read; the panel calls
`get_signing_cert_rollover` only to re-read after its own actions.
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
activation. The probe compares base64 DER bodies rather than thumbprints: the bodies are what the metadata
document actually publishes, so the comparison needs no digest at all.

**Bulk.** Staging is additive, reversible, and changes nothing for users, so it is the only phase safe
to fan out (via `run_bulk_seq`, like the other bulk remediations). Activation stays per-app and gated.

### Thumbprints — one algorithm, one converter

A certificate thumbprint in Entra is the **SHA-1** digest of the certificate DER. That is not a
choice we make; it is what Entra derives, and it is the value the portal's Thumbprint column shows,
the value a JWT client assertion carries as `x5t`, and the only value an operator can look up. Any
other digest displayed as "the thumbprint" sends them hunting for a string that exists nowhere.

It reaches us written **three ways**, and mixing them up has broken this codebase twice:

| Where | Encoding | Example |
|---|---|---|
| `keyCredentials[].customKeyIdentifier` | `Edm.Binary` → base64 of the 20 SHA-1 bytes | `2iD8ppbE+D6Kmu1ZvjM2jtQh88E=` |
| `preferredTokenSigningKeyThumbprint` | String → hex of the same 20 bytes | `DA20FCA696C4F83E8A9AED59BE33368ED421F3C1` |
| a hand-uploaded `customKeyIdentifier` | already hex, case not guaranteed | `da20fca6…` |

`azapptoolkit-core::thumbprint::canonical` is the **single** converter: it normalises all three to
uppercase hex, and every display and every comparison in both trees goes through it — the backend
(`commands::sso::canonical_thumbprint`) and the WASM frontend (`util::thumbprint_hex`) are thin
delegates. The nomination is canonicalised too — `active_thumbprint` (the expiry board's Thumbprint
column) and `signing_cert_thumbprint` go through `preferred_thumbprint`, which upper-cases a hex
value and keeps an unparseable nomination raw rather than re-decoding it as base64 into a thumbprint
that exists nowhere. Two failures are pinned by its tests:

- **Comparing base64 to hex raw** matched nothing, so no certificate ever read as active: every app
  showed "Staged", every expiry "Unknown", the work-queue filter matched nothing, and bulk staging
  silently skipped every app. Nothing errored.
- **Blindly base64-decoding an already-hex identifier.** A 40-character hex string is *also* valid
  base64 (length divisible by 4, every character in the alphabet), so the decode succeeds, yields 30
  meaningless bytes, and renders 60 plausible-looking hex characters. `canonical` checks for the hex
  form first and passes it through.

**Generation follows the same rule.** `cert.rs::generate_self_signed` digests SHA-1 over the DER it
just produced — via `aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY`, the same aws-lc-rs backend rcgen
signs with, so no crate enters the graph and no `sha2` dependency is declared. SHA-1 is used **only**
as this identifier, never as a security primitive. A SHA-256 thumbprint is returned alongside it for
operators who verify or pin on the stronger digest, and wherever both are shown they are **labelled
by algorithm**; the reveal modal previously showed only the SHA-256 value under the bare label
"Thumbprint", which never matched the Credentials tab row for the same certificate.

### The generated `.pfx` — same certificate, second encoding

The reveal hands back the private key as PKCS#8 PEM **and** as a password-protected PKCS#12
bundle. Both are the *same key*: `build_pfx` takes the PKCS#8 DER `rcgen` already holds
(`KeyPair::serialized_der()`), never a second key pair, so the one public half now sitting on the
app registration authenticates whichever the operator installs. rcgen's `KeyPair` is held in
`Zeroizing` (rcgen's `zeroize` feature), so its PKCS#8 copy is wiped on every path; the copy
p12-keystore takes into its `KeyStore` is not reachable and is not wiped.

Why both. PEM is what Linux and macOS hosts, the Python/Node MSAL libraries, the Azure SDK's
`certificate_path` and a Key Vault import consume. Windows consumes neither of those: an operator
running `Connect-MgGraph -CertificateThumbprint` needs the certificate **with its private key** in
`Cert:\CurrentUser\My`, and the only supported route in is `Import-PfxCertificate`. Before the
bundle existed, that meant pasting a one-time private key into an `openssl pkcs12 -export`
invocation — which also made the system clipboard the private key's only export channel.

**The bundle's `localKeyId` is the certificate's SHA-1 digest**, so the same-string rule above
holds inward too. This is not cosmetic: Windows' PKCS#12 reader binds the key bag to the
certificate bag through that attribute. A mismatch imports *successfully*, with
`HasPrivateKey = False` — a silent failure the operator meets much later, as a client assertion
that will not sign. `the_pfx_local_key_id_is_the_certificate_thumbprint` pins it.

The profile is **PBES2 / AES-256-CBC with an HMAC-SHA256 MAC**, set explicitly rather than
inherited from the writer's defaults. One consequence worth knowing: **Windows Server 2016 and
older cannot read an AES-256 `.pfx`** (Server 2019 / Windows 10 and newer can). The reveal says
so, and points at the PEM for those hosts.

The password is generated by the app — 24 bytes of `OsRng` as unpadded base64url, ~192 bits — not
typed by the operator. The alphabet (`A-Za-z0-9-_`) is load-bearing: the string is pasted into a
PowerShell `ConvertTo-SecureString` and an `openssl -passin pass:` argument, and a PKCS#12
password is encoded as a BMPString, so it stays free of shell metacharacters and stays ASCII.
It is shown once beside the bundle and never persisted; `GeneratedCert` zeroizes both on drop and
redacts both from `Debug`, exactly as it already did for the PEM key.

The file itself goes through `private_file::write_owner_only` like every other artifact this app
writes — `0600`, temp-sibling then atomic rename. The crate pin behind all this
(`p12-keystore` 0.2.x, and why not 0.3) is in
[release-updater-demo.md](release-updater-demo.md#crypto-dependencies-no-rsa-deliberate-randsha2-pins).

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
  `State`, so it is not `Send`), claiming `bulk_cancel` before any suspension point, degrading to a
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
