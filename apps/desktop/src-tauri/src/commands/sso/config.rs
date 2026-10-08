//! The enterprise-app "SSO" tab: reading the current config (and the
//! app-owner summary), plus the in-place writers — mode, SAML URLs, claims
//! mapping, notification emails, redirect URIs.

use tauri::State;

use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_graph::client::{ApplicationSpaPatch, ApplicationSsoPatch, ApplicationWebPatch};
use azapptoolkit_graph::{GraphClient, GraphError};

use crate::commands::applications::invalidate_app_details;
use crate::dto::UiError;
use crate::dto::sso::{
    ClaimsPolicyDto, OidcSsoSummary, SamlSsoSummary, SsoConfigDto, SsoMode, SsoSummary,
};
use crate::state::AppState;

use super::board::invalidate_sso_cert_board;
use super::claims::{build_claims_definition, parse_claims_definition};
use super::rollover::{build_rollover, is_preferred_key, preferred_thumbprint};
use super::{
    ClaimsWrite, apply_claims_policy, claims_policy_err, discard_unassigned_claims_policy,
    invalid_logout_url, invalid_redirect_uri, oidc_summary_urls, plan_claims_write,
    saml_summary_urls, sanitize_notification_emails,
};

/// Reads the current SSO configuration of an existing enterprise app to drive
/// the detail-pane "SSO" tab. The claims read degrades gracefully — it never
/// forces a consent prompt (that only happens via an explicit edit). A failed
/// claims read sets `claims_read_failed`, so the tab can tell "no policy" from
/// "couldn't read it" and refuse to save over claims it never loaded.
///
/// One read fills the whole tab: the app-owner [`SsoSummary`] and (for SAML)
/// the rollover panel's initial [`SigningCertRolloverDto`] are projected from
/// the same service-principal read, so opening the tab reads the SP once.
/// Whether this cloud offers the admin center's custom claims policy read. The
/// beta `servicePrincipals/{id}/claimsPolicy` is documented for the global
/// service only (not US Government L4/L5 or China).
pub(crate) fn portal_claims_readable(cloud: CloudEnvironment) -> bool {
    cloud == CloudEnvironment::Commercial
}

#[tauri::command]
pub async fn get_sso_config(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
) -> Result<SsoConfigDto, UiError> {
    get_sso_config_core(&state, &tenant_id, service_principal_id).await
}

/// [`get_sso_config`] without the Tauri `State` wrapper, so a handler test can
/// drive it against a mock Graph.
pub(crate) async fn get_sso_config_core(
    state: &AppState,
    tenant_id: &str,
    service_principal_id: String,
) -> Result<SsoConfigDto, UiError> {
    let cloud = state.auth.cloud();
    let client = state.graph_for(tenant_id);

    // The SP SSO fields and the assigned claims-mapping policy both key off the
    // input service_principal_id and are independent of each other (and of the
    // SP→app→app-SSO chain below), so read them concurrently — folding the
    // claims round trip into the first wave instead of trailing the whole chain.
    // The admin center's own claims live in the (beta) custom claims policy, a
    // third independent read of the same first wave. It exists in the global
    // cloud only: elsewhere it is not asked for (`Ok(None)` = "can't be read
    // here"), so a national-cloud tenant keeps its claims editing instead of
    // tripping the unreadable-claims guard on a call that can never succeed.
    let portal_read = async {
        if portal_claims_readable(cloud) {
            client
                .get_custom_claims_policy(&service_principal_id)
                .await
                .map(Some)
        } else {
            Ok(None)
        }
    };
    let (sp, claims_result, portal_result) = tokio::join!(
        client.get_service_principal_sso_fields(&service_principal_id),
        client.list_assigned_claims_mapping_policies(&service_principal_id),
        portal_read,
    );

    let sp =
        sp?.ok_or_else(|| UiError::not_found("service_principal", "Service principal not found."))?;
    let (app_id, sso_mode, signing_thumbprint, signing_expiry, notification_emails) =
        extract_sp_sso_fields(&sp);
    // The rollover panel's initial state: the same pure projection
    // `get_signing_cert_rollover` runs, over this same live read — so the
    // phase still derives from live SP state and nothing is stored.
    let rollover = (SsoMode::from_graph(sso_mode.as_deref()) == SsoMode::Saml).then(|| {
        build_rollover(
            &sp,
            &service_principal_id,
            tenant_id,
            cloud,
            chrono::Utc::now(),
        )
    });

    // Resolve the paired application object id, then read its SSO web fields.
    // Web `redirectUris` double as the SAML reply URLs and the OIDC redirect
    // URIs on a custom app, so they populate both fields.
    let (
        object_id,
        identifier_uris,
        web_redirects,
        logout_url,
        spa_redirect_uris,
        signed_requests_required,
        allowed_weak_signature_algorithms,
        group_claims,
    ) = match client.find_application_by_app_id(&app_id).await? {
        Some(app) => {
            let app_sso = client.get_application_sso_fields(&app.id).await?;
            let (ids, redirects, logout, spa) = app_sso
                .as_ref()
                .map(extract_app_sso_fields)
                .unwrap_or_default();
            let (signed, weak) = app_sso
                .as_ref()
                .map(extract_request_signature_verification)
                .unwrap_or_default();
            let group_claims = app_sso
                .as_ref()
                .and_then(|a| a.get("groupMembershipClaims"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            (
                app.id,
                ids,
                redirects,
                logout,
                spa,
                signed,
                weak,
                group_claims,
            )
        }
        None => (
            String::new(),
            Vec::new(),
            Vec::new(),
            None,
            Vec::new(),
            None,
            None,
            None,
        ),
    };
    // `entity_id` keeps the first identifier for the app-owner summary; the
    // editor uses the full `identifier_uris` list.
    let entity_id = identifier_uris.first().cloned();
    let reply_urls = web_redirects.clone();
    let redirect_uris = web_redirects;

    // Claims: best-effort (read concurrently in the first wave above). A missing
    // scope/consent leaves the policy unset AND flags the read as failed, so the
    // tab never offers a save over a policy it couldn't see.
    let (claims_policy, claims_policy_id, claims_policy_name, claims_read_failed) =
        match claims_result {
            Ok(policies) => match policies.into_iter().next() {
                Some(policy) => {
                    let parsed = policy
                        .definition
                        .first()
                        .map(|d| parse_claims_definition(d))
                        .unwrap_or_default();
                    (Some(parsed), Some(policy.id), policy.display_name, false)
                }
                None => (None, None, None, false),
            },
            Err(err) => {
                tracing::debug!(
                    ?err,
                    "claims policy unreadable; SSO tab will block claims edits"
                );
                (None, None, None, true)
            }
        };
    // The admin-center view needs BOTH policies: a mapping policy overrides the
    // admin center's, and showing either alone could name the wrong claims. An
    // unreadable admin-center policy also blocks claims edits, since the
    // editor's warning about overriding it would be a guess.
    let (claims_view, claims_read_failed) = match (&portal_result, claims_read_failed) {
        (Ok(portal), false) => {
            let mut view = super::claims_view::claims_view(
                claims_policy
                    .as_ref()
                    .map(|policy| super::claims_view::AssignedMappingPolicy {
                        policy,
                        name: claims_policy_name.as_deref(),
                    }),
                portal.as_ref().and_then(Option::as_ref),
                group_claims.as_deref(),
            );
            view.portal_policy_unreadable = portal.is_none();
            (Some(view), false)
        }
        (Err(err), _) => {
            tracing::debug!(?err, "custom claims policy unreadable; no claims view");
            (None, true)
        }
        (Ok(_), true) => (None, true),
    };

    let mut dto = SsoConfigDto {
        object_id,
        service_principal_id,
        app_id,
        sso_mode,
        entity_id,
        identifier_uris,
        reply_urls,
        logout_url,
        redirect_uris,
        spa_redirect_uris,
        signing_cert_thumbprint: signing_thumbprint,
        signing_cert_expiry: signing_expiry,
        notification_emails,
        claims_policy,
        claims_policy_id,
        claims_read_failed,
        claims_view,
        signed_requests_required,
        allowed_weak_signature_algorithms,
        summary: None,
        rollover,
    };
    dto.summary = build_sso_summary(cloud, tenant_id, &dto);
    Ok(dto)
}

/// The app-owner output summary ("Details for the application owner") for the
/// saved mode, projected from an already-read [`SsoConfigDto`] plus the cloud's
/// static URL formulas. SAML omits the signing cert base64 (only available at
/// creation/rotation time); OIDC omits the show-once secret. `None` when SSO is
/// not SAML or OIDC. Pure, so the URL formulas are table-testable.
pub(crate) fn build_sso_summary(
    cloud: CloudEnvironment,
    tenant_id: &str,
    cfg: &SsoConfigDto,
) -> Option<SsoSummary> {
    match SsoMode::from_graph(cfg.sso_mode.as_deref()) {
        SsoMode::Oidc => {
            let (authority, discovery_url) = oidc_summary_urls(cloud, tenant_id);
            Some(SsoSummary::Oidc(OidcSsoSummary {
                object_id: cfg.object_id.clone(),
                service_principal_id: cfg.service_principal_id.clone(),
                client_id: cfg.app_id.clone(),
                tenant_id: tenant_id.to_string(),
                authority,
                discovery_url,
                redirect_uris: cfg.redirect_uris.clone(),
                spa_redirect_uris: cfg.spa_redirect_uris.clone(),
                client_secret: None,
                client_secret_expiry: None,
            }))
        }
        SsoMode::Saml => {
            let (issuer, login_url, logout_url, federation_metadata_url) =
                saml_summary_urls(cloud, tenant_id, &cfg.app_id);
            Some(SsoSummary::Saml(SamlSsoSummary {
                object_id: cfg.object_id.clone(),
                service_principal_id: cfg.service_principal_id.clone(),
                app_id: cfg.app_id.clone(),
                entity_id_issuer: issuer,
                login_url,
                logout_url,
                federation_metadata_url,
                sp_entity_id: cfg.entity_id.clone().unwrap_or_default(),
                reply_url: cfg.reply_urls.first().cloned().unwrap_or_default(),
                signing_cert_base64: None,
                signing_cert_thumbprint: cfg.signing_cert_thumbprint.clone(),
                signing_cert_expiry: cfg.signing_cert_expiry.clone(),
                claims_policy_id: cfg.claims_policy_id.clone(),
                warnings: Vec::new(),
            }))
        }
        SsoMode::Disabled => None,
    }
}

/// Pulls the SSO-relevant fields out of a service principal's raw JSON:
/// `(app_id, sso_mode, signing_cert_thumbprint, signing_cert_expiry,
/// notification_emails)`. The expiry is the `endDateTime` of the `keyCredentials`
/// entry whose `customKeyIdentifier` denotes the preferred signing key. The two
/// fields are in DIFFERENT ENCODINGS — base64 bytes vs hex — so the match runs
/// through [`is_preferred_key`]; comparing them raw never matches and silently
/// yields no expiry. Pure (no Graph / State), mirroring [`extract_app_sso_fields`].
pub(crate) fn extract_sp_sso_fields(
    sp: &serde_json::Value,
) -> (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<String>,
) {
    let app_id = sp
        .get("appId")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let sso_mode = sp
        .get("preferredSingleSignOnMode")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let signing_thumbprint = preferred_thumbprint(sp);
    let signing_expiry = signing_thumbprint.as_deref().and_then(|tp| {
        sp.get("keyCredentials")
            .and_then(|v| v.as_array())
            .and_then(|creds| {
                creds.iter().find(|c| {
                    c.get("customKeyIdentifier")
                        .and_then(|v| v.as_str())
                        .is_some_and(|id| is_preferred_key(id, tp))
                })
            })
            .and_then(|c| c.get("endDateTime"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    });
    let notification_emails = sp
        .get("notificationEmailAddresses")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    (
        app_id,
        sso_mode,
        signing_thumbprint,
        signing_expiry,
        notification_emails,
    )
}

/// Pulls `identifierUris` / `web.redirectUris` / `web.logoutUrl` /
/// `spa.redirectUris` out of the raw application JSON. Returns
/// `(identifier_uris, web_redirect_uris, logout_url, spa_redirect_uris)` — all
/// identifiers and reply URLs, so the SSO tab can edit several of each.
pub(crate) fn extract_app_sso_fields(
    app: &serde_json::Value,
) -> (Vec<String>, Vec<String>, Option<String>, Vec<String>) {
    let str_vec = |v: Option<&serde_json::Value>| -> Vec<String> {
        v.and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let identifier_uris = str_vec(app.get("identifierUris"));
    let web_redirects = str_vec(app.get("web").and_then(|w| w.get("redirectUris")));
    let logout_url = app
        .get("web")
        .and_then(|w| w.get("logoutUrl"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let spa_redirect_uris = str_vec(app.get("spa").and_then(|s| s.get("redirectUris")));
    (
        identifier_uris,
        web_redirects,
        logout_url,
        spa_redirect_uris,
    )
}

/// Pulls `requestSignatureVerification` out of the raw application JSON:
/// `(isSignedRequestRequired, allowedWeakAlgorithms)`. Both halves are `None`
/// when the block is absent or malformed — **unknown**, not "verification off":
/// the tab renders nothing rather than implying an unsigned AuthnRequest is
/// accepted (the same never-flag-on-unknown contract as the credential-lifetime
/// advisory). `"none"` normalises to `None`: it means no weak algorithm is
/// allowed, so a present value is always a real allowance worth flagging.
/// Read-only on purpose — the v1.0 `application-update` property list omits
/// `requestSignatureVerification`, so there is no documented PATCH for it and
/// the tab shows this state, it can't set it.
pub(crate) fn extract_request_signature_verification(
    app: &serde_json::Value,
) -> (Option<bool>, Option<String>) {
    let block = app.get("requestSignatureVerification");
    let required = block
        .and_then(|b| b.get("isSignedRequestRequired"))
        .and_then(|v| v.as_bool());
    let weak = block
        .and_then(|b| b.get("allowedWeakAlgorithms"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("none"))
        .map(str::to_string);
    (required, weak)
}

/// Sets a service principal's `preferredSingleSignOnMode`. `mode` is a typed
/// [`SsoMode`]: an unknown or mis-cased value fails IPC deserialisation before
/// any PATCH is sent, and [`SsoMode::Disabled`] clears the preference to `null`
/// (SSO disabled). Password-based and linked SSO aren't settable here — they
/// require portal-only configuration — so the UI only offers SAML/OIDC/off.
/// Busts only the SSO-certificate expiry board (`invalidate_sso_cert_board`):
/// the mode decides whether the app is on the board at all. The SSO tab reads
/// the mode live and no other cached payload carries it.
#[tauri::command]
pub async fn set_sso_mode(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    mode: SsoMode,
) -> Result<(), UiError> {
    let value = mode.graph_value().map_or(serde_json::Value::Null, |m| {
        serde_json::Value::String(m.into())
    });
    let client = state.graph_for(&tenant_id);
    let body = serde_json::json!({ "preferredSingleSignOnMode": value });
    client
        .patch_service_principal(&service_principal_id, &body)
        .await?;
    // Whether this app is a SAML app at all decides whether it appears on the
    // expiry board.
    invalidate_sso_cert_board(&state, &tenant_id);
    Ok(())
}

/// Updates the SAML identifiers (Entity IDs), reply URLs (ACS), and logout URL on
/// an existing app. Supports multiple identifiers and reply URLs (the portal's
/// "Basic SAML Configuration" allows several of each). Every reply URL is
/// validated (no wildcards / insecure schemes), and so is a non-empty logout
/// URL (the same rules, https or loopback http only); at least one identifier
/// and one reply URL are required.
#[tauri::command]
pub async fn set_saml_urls(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    identifier_uris: Vec<String>,
    reply_urls: Vec<String>,
    logout_url: Option<String>,
) -> Result<(), UiError> {
    set_saml_urls_core(
        &state,
        &tenant_id,
        &object_id,
        identifier_uris,
        reply_urls,
        logout_url,
    )
    .await
}

/// The handler body, taking `&AppState` so a test can drive it against a mock
/// Graph — the seam [`set_oidc_redirect_uris_core`] uses.
pub(crate) async fn set_saml_urls_core(
    state: &AppState,
    tenant_id: &str,
    object_id: &str,
    identifier_uris: Vec<String>,
    reply_urls: Vec<String>,
    logout_url: Option<String>,
) -> Result<(), UiError> {
    let identifiers: Vec<String> = identifier_uris
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let replies: Vec<String> = reply_urls
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if identifiers.is_empty() {
        return Err(UiError::validation(
            "invalid_saml_config",
            "Enter at least one identifier (Entity ID).",
        ));
    }
    if replies.is_empty() {
        return Err(UiError::validation(
            "invalid_saml_config",
            "Enter at least one reply URL (ACS).",
        ));
    }
    azapptoolkit_core::redirect::validate_redirect_uris(&replies).map_err(invalid_redirect_uri)?;
    // Entra loads the logout URL in a hidden iframe at sign-out, so it is held
    // to the logout rules (https only), not just the reply-URL ones.
    let logout_url = logout_url
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(url) = logout_url.as_deref() {
        azapptoolkit_core::redirect::validate_logout_url(url).map_err(invalid_logout_url)?;
    }
    let client = state.graph_for(tenant_id);
    let body = ApplicationSsoPatch {
        identifier_uris: Some(identifiers),
        web: Some(ApplicationWebPatch {
            redirect_uris: Some(replies),
            logout_url,
            implicit_grant_settings: None,
        }),
        spa: None,
    };
    client.patch_application_web(object_id, &body).await?;
    // An in-place PATCH of one app's identifier/reply URLs adds, removes or
    // renames nothing, so nothing in the list tier (`sp_index`,
    // `app_name_index`, the enterprise list, the search corpus) changes; the SSO
    // tab reads live. The detail sweep is the can't-miss cheap tier (same as
    // the Expose-an-API and App roles PATCHes of this resource).
    invalidate_app_details(&state.cache, tenant_id);
    Ok(())
}

/// Saves the claims-mapping policy of an existing app. When this SP is the
/// policy's only subject the definition is PATCHed in place (no unassign window,
/// no new object); when the policy is shared with other apps, this app gets a
/// private copy and the shared policy is left as it was for everyone else. An
/// empty `policy` (Entra's defaults) unassigns the policy and deletes it once
/// nothing else uses it. A failure to read the current assignment is returned
/// and nothing is written.
#[tauri::command]
pub async fn set_claims_mapping(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    display_name: String,
    policy: ClaimsPolicyDto,
) -> Result<Option<String>, UiError> {
    // Pre-acquire so a missing consent surfaces typed (the UI's "Grant consent").
    // Stays in the command, not the core: silent grants can't obtain consent.
    state
        .ensure_policy_write_token(&tenant_id)
        .await
        .map_err(UiError::from)?;
    set_claims_mapping_core(
        &state,
        &tenant_id,
        &service_principal_id,
        &display_name,
        &policy,
    )
    .await
    .map_err(claims_policy_err)
}

/// The handler body, taking `&AppState` so a test can drive it against a mock
/// Graph — the seam [`set_oidc_redirect_uris_core`] uses. Reads the live
/// assignment and the policy's `appliesTo` first, plans with
/// [`plan_claims_write`], then writes.
pub(crate) async fn set_claims_mapping_core(
    state: &AppState,
    tenant_id: &str,
    service_principal_id: &str,
    display_name: &str,
    policy: &ClaimsPolicyDto,
) -> Result<Option<String>, UiError> {
    let client = state.graph_for(tenant_id);

    // A listing failure propagates: guessing "nothing assigned" would assign a
    // second policy (Graph rejects it) or skip the ownership proof.
    let assigned: Vec<String> = client
        .list_assigned_claims_mapping_policies(service_principal_id)
        .await?
        .into_iter()
        .map(|p| p.id)
        .collect();
    let subjects = match assigned.as_slice() {
        [id] => Some(client.list_claims_mapping_policy_subjects(id).await?),
        _ => None,
    };
    let plan = plan_claims_write(
        service_principal_id,
        &assigned,
        subjects.as_deref(),
        policy.is_empty(),
    )?;

    let result = match plan {
        ClaimsWrite::Nothing => None,
        ClaimsWrite::Create => {
            Some(apply_claims_policy(&client, service_principal_id, display_name, policy).await?)
        }
        ClaimsWrite::PatchInPlace(id) => {
            client
                .update_claims_mapping_policy(&id, &build_claims_definition(policy))
                .await?;
            Some(id)
        }
        ClaimsWrite::Fork { detach } => Some(
            fork_claims_policy(&client, service_principal_id, display_name, policy, &detach)
                .await?,
        ),
        ClaimsWrite::Detach { policy_id, delete } => {
            client
                .remove_claims_mapping_policy(service_principal_id, &policy_id)
                .await?;
            if delete {
                // The operator's intent (no custom claims) is already live, and
                // a retry would find nothing assigned — so an orphan is logged,
                // not surfaced as a failed save.
                if let Err(err) = client.delete_claims_mapping_policy(&policy_id).await {
                    tracing::warn!(?err, policy = %policy_id, "failed to delete the detached claims policy");
                }
            }
            None
        }
    };
    // Saving one SP's claims-mapping policy adds, removes or renames no app or
    // SP, so the list tier is untouched; the SSO tab reads the policy live.
    // Detail tier only (see `set_saml_urls`).
    invalidate_app_details(&state.cache, tenant_id);
    Ok(result)
}

/// Gives `service_principal_id` its own copy of a SHARED claims policy: the new
/// policy is created first (a failure there changes nothing), then the shared
/// one is unassigned from this SP only, then the copy is assigned. A failed
/// assign re-assigns the shared policy (best effort) and deletes the copy, so
/// the app is left as it started. The shared policy's other subjects are never
/// touched. Create-first (rather than unassign then [`apply_claims_policy`])
/// keeps the window with no policy assigned to one round trip.
async fn fork_claims_policy(
    client: &GraphClient,
    service_principal_id: &str,
    display_name: &str,
    policy: &ClaimsPolicyDto,
    shared_id: &str,
) -> Result<String, GraphError> {
    let created = client
        .create_claims_mapping_policy(&build_claims_definition(policy), display_name)
        .await?;
    if let Err(err) = client
        .remove_claims_mapping_policy(service_principal_id, shared_id)
        .await
    {
        discard_unassigned_claims_policy(client, &created.id).await;
        return Err(err);
    }
    if let Err(err) = client
        .assign_claims_mapping_policy(service_principal_id, &created.id)
        .await
    {
        if let Err(rollback) = client
            .assign_claims_mapping_policy(service_principal_id, shared_id)
            .await
        {
            tracing::warn!(?rollback, policy = %shared_id, "failed to re-assign the shared claims policy");
        }
        discard_unassigned_claims_policy(client, &created.id).await;
        return Err(err);
    }
    Ok(created.id)
}

/// Sets the SAML signing-certificate expiry notification recipients
/// (`notificationEmailAddresses`) on a service principal. Entra notifies these
/// addresses 60/30/7 days before the active signing cert expires. An empty list
/// clears the addresses. A normal SP write — rides the standard incremental
/// write scope (no extra consent).
#[tauri::command]
pub async fn set_notification_emails(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    emails: Vec<String>,
) -> Result<(), UiError> {
    let cleaned = sanitize_notification_emails(&emails);
    // Entra caps the list at five addresses (incl. the admin who added the app).
    if cleaned.len() > 5 {
        return Err(UiError::validation(
            "invalid_notification_emails",
            "Entra allows at most 5 notification email addresses.",
        ));
    }
    if let Some(bad) = cleaned.iter().find(|e| !e.contains('@')) {
        return Err(UiError::validation(
            "invalid_notification_emails",
            format!("\"{bad}\" is not a valid email address."),
        ));
    }
    let client = state.graph_for(&tenant_id);
    let body = serde_json::json!({ "notificationEmailAddresses": cleaned });
    client
        .patch_service_principal(&service_principal_id, &body)
        .await?;
    // The SSO tab reads this live, but the expiry board caches it as the
    // "nobody is warned" column, so that one entry does need busting.
    invalidate_sso_cert_board(&state, &tenant_id);
    Ok(())
}

/// Sets the OIDC redirect URIs (web + SPA) on an existing app. Full replacement.
#[tauri::command]
pub async fn set_oidc_redirect_uris(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    redirect_uris: Vec<String>,
    spa_redirect_uris: Vec<String>,
) -> Result<(), UiError> {
    set_oidc_redirect_uris_core(
        &state,
        &tenant_id,
        &object_id,
        redirect_uris,
        spa_redirect_uris,
    )
    .await
}

/// The handler body, taking `&AppState` so a test can drive it against a mock
/// Graph (`tauri::State` is only constructible by the runtime — the same seam
/// `applications::credentials::add_password_core` uses, and for the same
/// reason: the rules that live here, invalidate only on `Ok` and only the
/// detail tier, had never been exercised by a test).
pub(crate) async fn set_oidc_redirect_uris_core(
    state: &AppState,
    tenant_id: &str,
    object_id: &str,
    redirect_uris: Vec<String>,
    spa_redirect_uris: Vec<String>,
) -> Result<(), UiError> {
    azapptoolkit_core::redirect::validate_redirect_uris(&redirect_uris)
        .and_then(|()| azapptoolkit_core::redirect::validate_redirect_uris(&spa_redirect_uris))
        .map_err(invalid_redirect_uri)?;
    let client = state.graph_for(tenant_id);
    let body = ApplicationSsoPatch {
        identifier_uris: None,
        web: Some(ApplicationWebPatch {
            redirect_uris: Some(redirect_uris),
            logout_url: None,
            implicit_grant_settings: None,
        }),
        spa: Some(ApplicationSpaPatch {
            redirect_uris: Some(spa_redirect_uris),
        }),
    };
    client.patch_application_web(object_id, &body).await?;
    // An in-place PATCH of one app's redirect URIs adds, removes or renames
    // nothing, so the list tier (`sp_index`, `app_name_index`, the enterprise
    // list, the search corpus) is untouched and the tens-of-seconds tenant
    // re-scan dropping it costs is avoided; the SSO tab reads live. Detail tier
    // only (see `set_saml_urls`).
    invalidate_app_details(&state.cache, tenant_id);
    Ok(())
}
