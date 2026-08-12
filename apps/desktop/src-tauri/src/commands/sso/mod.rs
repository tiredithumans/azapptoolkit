//! Single-sign-on (SAML / OIDC) setup commands.
//!
//! Stands up an Entra **Enterprise Application** configured for SSO and produces
//! the app-owner output summary (Entity ID/Issuer, login/logout URLs, federation
//! metadata, signing certificate for SAML; client id, authority, discovery URL,
//! redirect URIs + show-once secret for OIDC). Two entry points share this code:
//! the "New SSO application" wizard (create) and the enterprise-app detail "SSO"
//! tab (edit existing).
//!
//! Both protocols instantiate the generic custom application template
//! ([`CUSTOM_TEMPLATE_ID`]) so a paired service principal (the Enterprise App)
//! always appears in the list. The multi-step Graph flow races against directory
//! replication, so the PATCH steps right after instantiate are wrapped in
//! [`with_replication_retry`] (retries `NotFound` only).

use std::future::Future;
use std::time::Duration;

use tauri::State;

use azapptoolkit_graph::client::{
    ApplicationSpaPatch, ApplicationSsoPatch, ApplicationWebPatch, ServicePrincipalSigningKeyPatch,
    ServicePrincipalSsoModePatch,
};
use azapptoolkit_graph::{GraphClient, GraphError};

mod claims;
use claims::{build_claims_definition, parse_claims_definition};

use crate::commands::applications::invalidate_app_lists;
use crate::dto::UiError;
use crate::dto::sso::{
    ClaimsPolicyDto, MetadataProbeDto, OidcSsoConfigInput, OidcSsoSummary, SamlSsoConfigInput,
    SamlSsoSummary, SigningCertRolloverDto, SsoConfigDto,
};
use crate::state::AppState;

/// The Microsoft Entra generic **custom** (non-gallery) application template.
/// Instantiating it creates a blank app + service principal we then configure.
const CUSTOM_TEMPLATE_ID: &str = "8adf8e6e-67b2-4cf2-a259-e3dc5476c621";

/// Login authority host used to build the app-owner output URLs.
const LOGIN_HOST: &str = "https://login.microsoftonline.com";

// ---------------- helpers ----------------

/// Retries `op` while it returns `GraphError::NotFound` — the only error worth
/// retrying right after `instantiate`, where the freshly created app/SP may not
/// have replicated yet. Backs off 500ms → 1s → 2s → 4s (5 attempts total). Any
/// other error returns immediately.
async fn with_replication_retry<F, Fut, T>(mut op: F) -> Result<T, GraphError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, GraphError>>,
{
    let mut delay_ms = 500u64;
    for attempt in 0..5u32 {
        match op().await {
            Err(GraphError::NotFound(_)) if attempt < 4 => {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                delay_ms *= 2;
            }
            other => return other,
        }
    }
    // The loop always returns: on attempt 4 the `attempt < 4` guard is false, so
    // even a NotFound falls through to the `other => return` arm. Make that
    // explicit so a future edit to the bound fails loudly here instead of
    // silently firing one extra request.
    unreachable!("with_replication_retry exhausted its loop without returning")
}

/// Trims, drops blanks, and dedupes (case-insensitive, order-preserving) a list
/// of notification email addresses.
fn sanitize_notification_emails(input: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    input
        .iter()
        .map(|e| e.trim())
        .filter(|e| !e.is_empty())
        .filter(|e| seen.insert(e.to_ascii_lowercase()))
        .map(str::to_string)
        .collect()
}

/// Static SAML output URLs that the app owner needs, derived from the tenant id.
fn saml_summary_urls(tenant_id: &str, app_id: &str) -> (String, String, String, String) {
    let issuer = format!("https://sts.windows.net/{tenant_id}/");
    let login = format!("{LOGIN_HOST}/{tenant_id}/saml2");
    let logout = login.clone();
    let metadata = format!(
        "{LOGIN_HOST}/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml?appid={app_id}"
    );
    (issuer, login, logout, metadata)
}

/// Static OIDC output URLs (authority + discovery document) for the tenant.
fn oidc_summary_urls(tenant_id: &str) -> (String, String) {
    let authority = format!("{LOGIN_HOST}/{tenant_id}/v2.0");
    let discovery = format!("{authority}/.well-known/openid-configuration");
    (authority, discovery)
}

/// Creates and assigns a claims-mapping policy for `policy`, returning the new
/// policy id. The caller must have pre-acquired the policy-write token (so a
/// missing consent surfaces as the typed `consent_required`).
async fn apply_claims_policy(
    client: &GraphClient,
    service_principal_id: &str,
    display_name: &str,
    policy: &ClaimsPolicyDto,
) -> Result<String, GraphError> {
    let definition = build_claims_definition(policy);
    let created = client
        .create_claims_mapping_policy(&definition, display_name)
        .await?;
    client
        .assign_claims_mapping_policy(service_principal_id, &created.id)
        .await?;
    Ok(created.id)
}

// ---------------- create ----------------

/// Creates a SAML SSO enterprise application end to end and returns the
/// app-owner summary. Steps 1–5 use the standard write scope; the optional
/// claims step (6) needs `Policy.ReadWrite.ApplicationConfiguration` and is
/// skipped entirely when no custom claims are requested.
#[tauri::command]
pub async fn create_saml_sso_application(
    state: State<'_, AppState>,
    tenant_id: String,
    input: SamlSsoConfigInput,
) -> Result<SamlSsoSummary, UiError> {
    // Reject wildcard / insecure reply URLs before creating anything (MS
    // app-registration security best practices).
    azapptoolkit_core::redirect::validate_redirect_uri(&input.reply_url)
        .map_err(invalid_redirect_uri)?;

    // Likewise reject a certificate subject Graph would refuse at step 4 —
    // by then the app + SP already exist, so the failure would leave a
    // half-configured app.
    if let Some(s) = input.cert_subject.as_deref().filter(|s| !s.is_empty()) {
        validate_cert_subject(s)?;
    }
    // Same reason, same step: the certificate's lifetime is also only used at
    // step 4, so it is bounded here rather than after the app exists.
    // `configure_saml` resolves it again to get the value — it is a pure
    // function of the input, and this call is the gate.
    resolve_cert_lifetime_days(input.cert_lifetime_days)?;

    // Pre-acquire the claims-write token up front (only when needed) so a
    // missing-consent rejection surfaces as `consent_required` and the UI can
    // offer a "Grant consent" button — before we create anything.
    if input.claims_policy.as_ref().is_some_and(|p| !p.is_empty()) {
        state
            .ensure_policy_write_token(&tenant_id)
            .await
            .map_err(UiError::from)?;
    }

    let client = state.graph_for(&tenant_id);

    // 1. Instantiate the generic custom template → app + SP.
    let pair = client
        .instantiate_application_template(CUSTOM_TEMPLATE_ID, &input.display_name)
        .await?;
    let object_id = pair.application.id.clone();
    let app_id = pair.application.app_id.clone();
    let sp_id = pair.service_principal.id.clone();

    // From here a failure leaves a half-configured app the user can finish in
    // the SSO tab; we never auto-delete. Bust caches on any early return that
    // got past instantiate so the new (paired) SP shows up in the lists.
    let result = configure_saml(&client, &object_id, &sp_id, &tenant_id, &app_id, &input).await;
    invalidate_app_lists(&state.cache, &tenant_id);
    result.map_err(|e| augment_with_object_id(e, &object_id))
}

/// Steps 2–6 of the SAML flow, factored out so the caller can always invalidate
/// caches once instantiate succeeded.
async fn configure_saml(
    client: &GraphClient,
    object_id: &str,
    sp_id: &str,
    tenant_id: &str,
    app_id: &str,
    input: &SamlSsoConfigInput,
) -> Result<SamlSsoSummary, UiError> {
    // 2. SSO mode = saml.
    let sso_mode_body = ServicePrincipalSsoModePatch {
        preferred_single_sign_on_mode: "saml".to_string(),
    };
    with_replication_retry(|| client.patch_service_principal(sp_id, &sso_mode_body)).await?;

    // 3. Entity ID + reply (ACS) URL + optional logout URL on the app.
    let app_body = ApplicationSsoPatch {
        identifier_uris: Some(vec![input.entity_id.clone()]),
        web: Some(ApplicationWebPatch {
            redirect_uris: Some(vec![input.reply_url.clone()]),
            logout_url: input
                .logout_url
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            implicit_grant_settings: None,
        }),
        spa: None,
    };
    with_replication_retry(|| client.patch_application_web(object_id, &app_body)).await?;

    // 4. Generate the token-signing certificate.
    let subject = input
        .cert_subject
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("CN={}", input.display_name));
    let days = resolve_cert_lifetime_days(input.cert_lifetime_days)?;
    let end = chrono::Utc::now() + chrono::Duration::days(days as i64);
    let cert = client
        .add_token_signing_certificate(sp_id, &subject, end)
        .await?;

    // 5. Activate it as the preferred signing key.
    client
        .patch_service_principal(
            sp_id,
            &ServicePrincipalSigningKeyPatch {
                preferred_token_signing_key_thumbprint: cert.thumbprint.clone(),
            },
        )
        .await?;

    // 5b. Optional SAML cert-expiry notification recipients. Best-effort —
    // Entra already seeds the creating admin, so a failure here isn't fatal.
    let emails = sanitize_notification_emails(&input.notification_emails);
    if !emails.is_empty() {
        let body = serde_json::json!({ "notificationEmailAddresses": emails });
        if let Err(err) =
            with_replication_retry(|| client.patch_service_principal(sp_id, &body)).await
        {
            tracing::warn!(?err, "failed to set notification emails on new SSO app");
        }
    }

    // 6. Optional custom claims. A failure here is non-fatal: the SSO app is
    // already usable, so we degrade to "no custom claims" rather than failing
    // the whole create.
    let claims_policy_id = match &input.claims_policy {
        Some(policy) if !policy.is_empty() => {
            match apply_claims_policy(
                client,
                sp_id,
                &format!("{} claims", input.display_name),
                policy,
            )
            .await
            {
                Ok(id) => Some(id),
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        "claims-mapping policy failed; SSO app created without it"
                    );
                    None
                }
            }
        }
        _ => None,
    };

    let (issuer, login_url, logout_url, federation_metadata_url) =
        saml_summary_urls(tenant_id, app_id);
    Ok(SamlSsoSummary {
        object_id: object_id.to_string(),
        service_principal_id: sp_id.to_string(),
        app_id: app_id.to_string(),
        entity_id_issuer: issuer,
        login_url,
        logout_url,
        federation_metadata_url,
        sp_entity_id: input.entity_id.clone(),
        reply_url: input.reply_url.clone(),
        signing_cert_base64: cert.key.clone(),
        signing_cert_thumbprint: Some(cert.thumbprint.clone()),
        signing_cert_expiry: cert.end_date_time.map(|d| d.to_rfc3339()),
        claims_policy_id,
    })
}

/// Creates an OIDC SSO enterprise application: instantiate, set redirect URIs,
/// optionally mint a client secret. Returns the app-owner summary.
#[tauri::command]
pub async fn create_oidc_sso_application(
    state: State<'_, AppState>,
    tenant_id: String,
    input: OidcSsoConfigInput,
) -> Result<OidcSsoSummary, UiError> {
    // Reject wildcard / insecure redirect URIs (web + SPA) before creating
    // anything (MS app-registration security best practices).
    for uri in input
        .redirect_uris
        .iter()
        .chain(input.spa_redirect_uris.iter())
    {
        azapptoolkit_core::redirect::validate_redirect_uri(uri).map_err(invalid_redirect_uri)?;
    }

    let client = state.graph_for(&tenant_id);

    let pair = client
        .instantiate_application_template(CUSTOM_TEMPLATE_ID, &input.display_name)
        .await?;
    let object_id = pair.application.id.clone();
    let app_id = pair.application.app_id.clone();
    let sp_id = pair.service_principal.id.clone();

    let result = configure_oidc(&client, &object_id, &app_id, &sp_id, &tenant_id, &input).await;
    invalidate_app_lists(&state.cache, &tenant_id);
    result.map_err(|e| augment_with_object_id(e, &object_id))
}

async fn configure_oidc(
    client: &GraphClient,
    object_id: &str,
    app_id: &str,
    sp_id: &str,
    tenant_id: &str,
    input: &OidcSsoConfigInput,
) -> Result<OidcSsoSummary, UiError> {
    // Redirect URIs (web and/or SPA). Only include the keys actually provided.
    let web = (!input.redirect_uris.is_empty()).then(|| ApplicationWebPatch {
        redirect_uris: Some(input.redirect_uris.clone()),
        logout_url: None,
        implicit_grant_settings: None,
    });
    let spa = (!input.spa_redirect_uris.is_empty()).then(|| ApplicationSpaPatch {
        redirect_uris: Some(input.spa_redirect_uris.clone()),
    });
    if web.is_some() || spa.is_some() {
        let body = ApplicationSsoPatch {
            identifier_uris: None,
            web,
            spa,
        };
        with_replication_retry(|| client.patch_application_web(object_id, &body)).await?;
    }

    // Optional client secret (show-once).
    let (client_secret, client_secret_expiry) = if let Some(name) = input
        .secret_display_name
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        let days = input.secret_lifetime_days.unwrap_or(180);
        let lifetime = Duration::from_secs(days as u64 * 86_400);
        let secret =
            with_replication_retry(|| client.add_password(object_id, name, lifetime)).await?;
        (
            secret.secret_text.clone(),
            secret.end_date_time.map(|d| d.to_rfc3339()),
        )
    } else {
        (None, None)
    };

    let (authority, discovery_url) = oidc_summary_urls(tenant_id);
    Ok(OidcSsoSummary {
        object_id: object_id.to_string(),
        service_principal_id: sp_id.to_string(),
        client_id: app_id.to_string(),
        tenant_id: tenant_id.to_string(),
        authority,
        discovery_url,
        redirect_uris: input.redirect_uris.clone(),
        spa_redirect_uris: input.spa_redirect_uris.clone(),
        client_secret,
        client_secret_expiry,
    })
}

/// Maps a redirect-URI validation rejection (wildcard / insecure scheme) to a
/// non-retryable `invalid_redirect_uri` UI error.
fn invalid_redirect_uri(message: String) -> UiError {
    UiError::validation("invalid_redirect_uri", message)
}

/// Rejects a certificate subject Graph's `addTokenSigningCertificate` would
/// refuse (its `displayName` must start with `CN=`) — validated *before* any
/// mutation so a bad value can't leave a half-configured app.
fn validate_cert_subject(subject: &str) -> Result<(), UiError> {
    if subject.to_ascii_uppercase().starts_with("CN=") {
        Ok(())
    } else {
        Err(UiError::validation(
            "invalid_cert_subject",
            "certificate subject must start with 'CN=' (e.g. CN=Contoso SSO)",
        ))
    }
}

/// Graph's ceiling on a token-signing certificate: `endDateTime` "can be up to
/// 3 years from the date the certificate is created". 1095 days is three years
/// even across a leap day.
const MAX_CERT_LIFETIME_DAYS: u32 = 1095;

/// Default when the caller supplies none — matches Graph's own default (and the
/// portal's) of three years.
const DEFAULT_CERT_LIFETIME_DAYS: u32 = 365;

/// Bounds a caller-supplied signing-certificate lifetime.
///
/// This certificate is what proves a SAML assertion came from Entra, so its
/// lifetime is the window in which a stolen key stays useful — an unbounded
/// value is a trust that never has to be re-established. Graph refuses past
/// three years anyway; checking here turns a raw 400 into a typed rejection
/// *before* any mutation, and keeps an absurd value out of
/// `chrono::Duration::days`, which panics rather than saturating.
fn resolve_cert_lifetime_days(days: Option<u32>) -> Result<u32, UiError> {
    let days = days.unwrap_or(DEFAULT_CERT_LIFETIME_DAYS);
    if days == 0 || days > MAX_CERT_LIFETIME_DAYS {
        return Err(UiError::validation(
            "invalid_cert_lifetime",
            format!(
                "certificate lifetime must be between 1 and {MAX_CERT_LIFETIME_DAYS} days                  (3 years, Entra's maximum); got {days}"
            ),
        ));
    }
    Ok(days)
}

/// Annotates an error message with the created object id so a partial failure
/// after instantiate tells the user which half-configured app to finish/clean up.
fn augment_with_object_id(mut err: UiError, object_id: &str) -> UiError {
    err.message = format!(
        "{} (the application was created — object id {object_id}; you can finish or delete it from the list).",
        err.message
    );
    err
}

// ---------------- read / edit (detail tab) ----------------

/// Reads the current SSO configuration of an existing enterprise app to drive
/// the detail-pane "SSO" tab. The claims read degrades gracefully — it never
/// forces a consent prompt (that only happens via an explicit edit).
#[tauri::command]
pub async fn get_sso_config(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
) -> Result<SsoConfigDto, UiError> {
    let client = state.graph_for(&tenant_id);

    // The SP SSO fields and the assigned claims-mapping policy both key off the
    // input service_principal_id and are independent of each other (and of the
    // SP→app→app-SSO chain below), so read them concurrently — folding the
    // claims round trip into the first wave instead of trailing the whole chain.
    let (sp, claims_result) = tokio::join!(
        client.get_service_principal_sso_fields(&service_principal_id),
        client.list_assigned_claims_mapping_policies(&service_principal_id),
    );

    let sp = sp?.ok_or_else(|| UiError::validation("not_found", "Service principal not found."))?;
    let (app_id, sso_mode, signing_thumbprint, signing_expiry, notification_emails) =
        extract_sp_sso_fields(&sp);

    // Resolve the paired application object id, then read its SSO web fields.
    // Web `redirectUris` double as the SAML reply URLs and the OIDC redirect
    // URIs on a custom app, so they populate both fields.
    let (object_id, identifier_uris, web_redirects, logout_url, spa_redirect_uris) =
        match client.find_application_by_app_id(&app_id).await? {
            Some(app) => {
                let app_sso = client.get_application_sso_fields(&app.id).await?;
                let (ids, redirects, logout, spa) = app_sso
                    .as_ref()
                    .map(extract_app_sso_fields)
                    .unwrap_or_default();
                (app.id, ids, redirects, logout, spa)
            }
            None => (String::new(), Vec::new(), Vec::new(), None, Vec::new()),
        };
    // `entity_id` keeps the first identifier for the app-owner summary; the
    // editor uses the full `identifier_uris` list.
    let entity_id = identifier_uris.first().cloned();
    let reply_urls = web_redirects.clone();
    let redirect_uris = web_redirects;

    // Claims: best-effort (read concurrently in the first wave above). A missing
    // scope/consent leaves the policy unset.
    let (claims_policy, claims_policy_id) = match claims_result {
        Ok(policies) => match policies.into_iter().next() {
            Some(policy) => {
                let parsed = policy
                    .definition
                    .first()
                    .map(|d| parse_claims_definition(d))
                    .unwrap_or_default();
                (Some(parsed), Some(policy.id))
            }
            None => (None, None),
        },
        Err(err) => {
            tracing::debug!(?err, "claims policy read skipped (scope/consent)");
            (None, None)
        }
    };

    Ok(SsoConfigDto {
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
    })
}

/// Pulls the SSO-relevant fields out of a service principal's raw JSON:
/// `(app_id, sso_mode, signing_cert_thumbprint, signing_cert_expiry,
/// notification_emails)`. The expiry is the `endDateTime` of the `keyCredentials`
/// entry whose `customKeyIdentifier` matches the preferred signing thumbprint
/// (case-insensitive) — Graph stores the thumbprint uppercase in
/// `customKeyIdentifier` but the preferred-key field can differ in case, so the
/// match is the load-bearing bit (unit-tested below). Pure (no Graph / State),
/// mirroring [`extract_app_sso_fields`].
fn extract_sp_sso_fields(
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
    let signing_thumbprint = sp
        .get("preferredTokenSigningKeyThumbprint")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let signing_expiry = signing_thumbprint.as_deref().and_then(|tp| {
        sp.get("keyCredentials")
            .and_then(|v| v.as_array())
            .and_then(|creds| {
                creds.iter().find(|c| {
                    c.get("customKeyIdentifier")
                        .and_then(|v| v.as_str())
                        .map(|id| id.eq_ignore_ascii_case(tp))
                        .unwrap_or(false)
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
fn extract_app_sso_fields(
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

/// Sets a service principal's `preferredSingleSignOnMode`. `mode` is `"saml"` or
/// `"oidc"`; any other value (e.g. `""`, `"disabled"`, `"none"`) clears it to
/// `null` (SSO disabled). Password-based and linked SSO aren't settable here —
/// they require portal-only configuration — so the UI only offers SAML/OIDC/off.
/// No cache bust: the mode is read live on the (uncached) SSO tab and is on no
/// cached list/audit payload.
#[tauri::command]
pub async fn set_sso_mode(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    mode: String,
) -> Result<(), UiError> {
    let value = match mode.as_str() {
        "saml" => serde_json::Value::String("saml".into()),
        "oidc" => serde_json::Value::String("oidc".into()),
        // Anything else disables SSO (clears the preference).
        _ => serde_json::Value::Null,
    };
    let client = state.graph_for(&tenant_id);
    let body = serde_json::json!({ "preferredSingleSignOnMode": value });
    client
        .patch_service_principal(&service_principal_id, &body)
        .await?;
    Ok(())
}

/// Updates the SAML identifiers (Entity IDs), reply URLs (ACS), and logout URL on
/// an existing app. Supports multiple identifiers and reply URLs (the portal's
/// "Basic SAML Configuration" allows several of each). Every reply URL is
/// validated (no wildcards / insecure schemes); at least one identifier and one
/// reply URL are required.
#[tauri::command]
pub async fn set_saml_urls(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
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
    let client = state.graph_for(&tenant_id);
    let body = ApplicationSsoPatch {
        identifier_uris: Some(identifiers),
        web: Some(ApplicationWebPatch {
            redirect_uris: Some(replies),
            logout_url: logout_url.filter(|s| !s.is_empty()),
            implicit_grant_settings: None,
        }),
        spa: None,
    };
    client.patch_application_web(&object_id, &body).await?;
    invalidate_app_lists(&state.cache, &tenant_id);
    Ok(())
}

/// Generates a fresh SAML token-signing certificate and activates it immediately
/// — a **big-bang rotation**. Every new assertion is signed by the new key the
/// moment this returns, so any app holding a single static certificate stops
/// accepting sign-ins until its copy is replaced.
///
/// Kept for the app that genuinely can only hold one certificate, where a
/// maintenance window is the plan. Everything else should use the staged flow
/// ([`stage_saml_signing_certificate`] → [`probe_federation_metadata`] →
/// [`activate_saml_signing_certificate`]), which keeps the old certificate
/// available as an instant rollback.
#[tauri::command]
pub async fn rotate_saml_signing_certificate(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    subject: String,
    lifetime_days: Option<u32>,
) -> Result<SsoCertResult, UiError> {
    let cert = mint_signing_certificate(
        &state,
        &tenant_id,
        &service_principal_id,
        &subject,
        lifetime_days,
    )
    .await?;
    state
        .graph_for(&tenant_id)
        .patch_service_principal(
            &service_principal_id,
            &ServicePrincipalSigningKeyPatch {
                preferred_token_signing_key_thumbprint: cert.thumbprint.clone(),
            },
        )
        .await?;
    invalidate_app_lists(&state.cache, &tenant_id);
    Ok(cert)
}

/// Result of [`rotate_saml_signing_certificate`] and
/// [`stage_saml_signing_certificate`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SsoCertResult {
    pub thumbprint: String,
    pub base64: Option<String>,
    pub expiry: Option<String>,
}

// ---------------- staged rollover ----------------

/// Reads the staged-rollover state of a SAML app's signing certificates.
///
/// Live read (the SSO tab is uncached anyway). The phase is a **pure projection
/// of live Graph state** — nothing about a rollover is persisted, so one
/// abandoned halfway is always resumable and two operators can't hold different
/// ideas about where it is.
#[tauri::command]
pub async fn get_signing_cert_rollover(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
) -> Result<SigningCertRolloverDto, UiError> {
    let client = state.graph_for(&tenant_id);
    let sp = client
        .get_service_principal_sso_fields(&service_principal_id)
        .await?
        .ok_or_else(|| UiError::validation("not_found", "Service principal not found."))?;
    Ok(build_rollover(
        &sp,
        &service_principal_id,
        &tenant_id,
        chrono::Utc::now(),
    ))
}

/// **Phase 1 of a staged rollover** — mints a new signing certificate and stops.
///
/// Deliberately does *not* touch `preferredTokenSigningKeyThumbprint`: the new
/// certificate lands inactive, Entra starts publishing it in the app's
/// federation metadata, and an app that polls metadata can pick it up before it
/// ever signs an assertion. Additive and reversible, so this is the half that is
/// safe to run across many apps at once; activation stays per-app and gated.
#[tauri::command]
pub async fn stage_saml_signing_certificate(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    subject: String,
    lifetime_days: Option<u32>,
) -> Result<SsoCertResult, UiError> {
    let cert = mint_signing_certificate(
        &state,
        &tenant_id,
        &service_principal_id,
        &subject,
        lifetime_days,
    )
    .await?;
    // `add_token_signing_certificate` self-invalidates the SP cache; the app
    // lists carry no signing-cert field, so nothing else to bust.
    Ok(cert)
}

/// **Phase 2** — fetches the app's federation metadata and reports the signing
/// certificates Entra publishes for it.
///
/// Unauthenticated GET to the public metadata endpoint (a backend `reqwest`
/// call, so no CSP change — `connect-src` governs the webview only). A transport
/// or parse failure is returned as a populated [`MetadataProbeDto`] with
/// `http_status: None`, never as a command error: "we couldn't check" and "Entra
/// isn't publishing it" must not look the same to the operator.
#[tauri::command]
pub async fn probe_federation_metadata(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
) -> Result<MetadataProbeDto, UiError> {
    // Prove the session before reaching out: this command takes no token, so
    // without it a signed-out window could still drive tenant-shaped requests.
    state.auth.tenant_context(&tenant_id).ok_or_else(|| {
        UiError::validation(
            "not_signed_in",
            format!("not signed in to tenant {tenant_id}"),
        )
    })?;
    let (_, _, _, metadata_url) = saml_summary_urls(&tenant_id, &app_id);
    let fetched_at = chrono::Utc::now().to_rfc3339();

    let response = metadata_http_client().get(&metadata_url).send().await;
    let (status, body) = match response {
        Ok(resp) => {
            let status = resp.status().as_u16();
            match resp.text().await {
                Ok(body) => (status, Some(body)),
                Err(err) => {
                    return Ok(MetadataProbeDto {
                        fetched_at,
                        error: Some(format!("Could not read the metadata response: {err}")),
                        ..Default::default()
                    });
                }
            }
        }
        Err(err) => {
            return Ok(MetadataProbeDto {
                fetched_at,
                error: Some(format!("Could not reach the metadata endpoint: {err}")),
                ..Default::default()
            });
        }
    };

    let certs = body.as_deref().map(parse_signing_certs).unwrap_or_default();
    let error = (!(200..300).contains(&status))
        .then(|| format!("The metadata endpoint returned HTTP {status}."));
    Ok(MetadataProbeDto {
        fetched_at,
        signing_key_count: certs.len(),
        published_certs: certs,
        http_status: Some(status),
        error,
    })
}

/// **Phase 3** — promotes a staged certificate to
/// `preferredTokenSigningKeyThumbprint`. The moment this lands, every new SAML
/// assertion is signed by it.
///
/// Re-resolves live state first and refuses anything unsafe: a thumbprint that
/// is no longer on the service principal, or one that has already expired.
/// Activating the certificate that is already active is a no-op, not an error,
/// so a double-click can't produce a scary failure.
///
/// Deliberately **not** gated on a metadata probe having run — a probe can fail
/// for reasons that have nothing to do with the rollover (offline, proxy), and
/// blocking on it would strand an operator mid-window. The UI surfaces it as an
/// unchecked precondition instead.
#[tauri::command]
pub async fn activate_saml_signing_certificate(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    thumbprint: String,
) -> Result<SigningCertRolloverDto, UiError> {
    set_preferred_signing_key(state, tenant_id, service_principal_id, thumbprint).await
}

/// **Phase 3b** — the rollback. Re-points `preferredTokenSigningKeyThumbprint`
/// back at the superseded certificate, which is still in `keyCredentials` and
/// therefore takes effect immediately for new assertions.
///
/// Same PATCH as [`activate_saml_signing_certificate`], kept as its own command
/// so the UI can offer it as a distinct, obviously-safe action and so a revert
/// reads as a revert in the logs rather than as another activation.
#[tauri::command]
pub async fn revert_saml_signing_certificate(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    thumbprint: String,
) -> Result<SigningCertRolloverDto, UiError> {
    set_preferred_signing_key(state, tenant_id, service_principal_id, thumbprint).await
}

/// **Phase 4** — removes a retired certificate, ending the rollover.
///
/// Refuses to remove the active certificate or the last usable one (either would
/// break sign-in outright), and refuses to remove the sole remaining fallback
/// while a rollover is still in flight — retiring the superseded certificate is
/// what *ends* the ability to roll back, so it can't happen by accident before
/// the new one is confirmed good.
#[tauri::command]
pub async fn retire_saml_signing_certificate(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    key_id: String,
) -> Result<SigningCertRolloverDto, UiError> {
    let client = state.graph_for(&tenant_id);
    let before = get_signing_cert_rollover(
        state.clone(),
        tenant_id.clone(),
        service_principal_id.clone(),
    )
    .await?;

    let target = before
        .certs
        .iter()
        .find(|c| c.key_id == key_id)
        .ok_or_else(|| {
            UiError::validation(
                "cert_not_found",
                "That certificate is no longer on the service principal.",
            )
        })?;
    if target.is_active {
        return Err(UiError::validation(
            "cert_is_active",
            "That certificate is signing assertions right now. Activate its replacement first.",
        ));
    }
    if matches!(target.status, azapptoolkit_dto::sso::CertStatus::Staged) {
        return Err(UiError::validation(
            "cert_is_staged",
            "That certificate is staged for the next rollover, not retired. Activate it or let it expire.",
        ));
    }

    client
        .remove_service_principal_key_credential(&service_principal_id, &key_id)
        .await?;
    get_signing_cert_rollover(state, tenant_id, service_principal_id).await
}

/// Mints a signing certificate on the service principal. Shared by the create
/// flow, the one-shot rotate, and [`stage_saml_signing_certificate`], so the
/// subject/lifetime rules can't drift between them.
async fn mint_signing_certificate(
    state: &State<'_, AppState>,
    tenant_id: &str,
    service_principal_id: &str,
    subject: &str,
    lifetime_days: Option<u32>,
) -> Result<SsoCertResult, UiError> {
    let days = resolve_cert_lifetime_days(lifetime_days)?;
    let subject = if subject.is_empty() {
        "CN=SSO"
    } else {
        subject
    };
    // Typed rejection instead of a raw Graph 400 (consistent with create).
    validate_cert_subject(subject)?;
    let end = chrono::Utc::now() + chrono::Duration::days(days as i64);
    let cert = state
        .graph_for(tenant_id)
        .add_token_signing_certificate(service_principal_id, subject, end)
        .await?;
    Ok(SsoCertResult {
        thumbprint: cert.thumbprint.clone(),
        base64: cert.key.clone(),
        expiry: cert.end_date_time.map(|d| d.to_rfc3339()),
    })
}

/// The one PATCH that changes which certificate signs assertions, shared by
/// activate and revert so the guards can't diverge between the forward and the
/// backward move. Re-resolves live state before writing.
async fn set_preferred_signing_key(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    thumbprint: String,
) -> Result<SigningCertRolloverDto, UiError> {
    let before = get_signing_cert_rollover(
        state.clone(),
        tenant_id.clone(),
        service_principal_id.clone(),
    )
    .await?;

    let target = before
        .certs
        .iter()
        .find(|c| c.thumbprint.eq_ignore_ascii_case(&thumbprint))
        .ok_or_else(|| {
            UiError::validation(
                "cert_not_staged",
                "That certificate is no longer on the service principal — stage a new one.",
            )
        })?;
    if matches!(target.status, azapptoolkit_dto::sso::CertStatus::Expired) {
        return Err(UiError::validation(
            "cert_expired",
            "That certificate has expired. Entra won't sign with it — stage a new one instead.",
        ));
    }
    // Idempotent: a double-click shouldn't read as a failure.
    if target.is_active {
        return Ok(before);
    }

    state
        .graph_for(&tenant_id)
        .patch_service_principal(
            &service_principal_id,
            &ServicePrincipalSigningKeyPatch {
                preferred_token_signing_key_thumbprint: target.thumbprint.clone(),
            },
        )
        .await?;
    get_signing_cert_rollover(state, tenant_id, service_principal_id).await
}

/// Shared `reqwest` client for federation-metadata probes. The endpoint is
/// public and unauthenticated, so this never carries a token — it exists only so
/// repeated probes reuse one connection pool.
fn metadata_http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap_or_default()
    })
}

/// Extracts the base64 DER bodies of the `<KeyDescriptor use="signing">`
/// certificates from a federation metadata document, deduped and whitespace
/// stripped.
///
/// Scans for the elements directly rather than pulling in an XML parser: the
/// document is a fixed-shape Microsoft-generated file, and the only thing read
/// out of it is a count and a set of opaque base64 bodies. A malformed document
/// yields an empty list, which the caller reports as "0 published" alongside the
/// HTTP status — it never fabricates a match.
///
/// A `KeyDescriptor` with no `use` attribute is signing-capable per the SAML
/// metadata spec, so those count too; an explicit `use="encryption"` does not.
fn parse_signing_certs(xml: &str) -> Vec<String> {
    const DESCRIPTOR: &str = "<KeyDescriptor";
    const CERT_OPEN: &str = "<X509Certificate>";
    const CERT_CLOSE: &str = "</X509Certificate>";

    let mut out: Vec<String> = Vec::new();
    for block in xml.split(DESCRIPTOR).skip(1) {
        // The attributes run up to the element's own `>`; anything after that
        // belongs to the children.
        let attrs = block.split('>').next().unwrap_or_default();
        if attrs.contains("use=\"encryption\"") || attrs.contains("use='encryption'") {
            continue;
        }
        // Stop at the next descriptor's content — `split` already did that.
        let mut rest = block;
        while let Some(start) = rest.find(CERT_OPEN) {
            let after = &rest[start + CERT_OPEN.len()..];
            let Some(end) = after.find(CERT_CLOSE) else {
                break;
            };
            let body: String = after[..end]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if !body.is_empty() && !out.iter().any(|existing| existing == &body) {
                out.push(body);
            }
            rest = &after[end + CERT_CLOSE.len()..];
        }
    }
    out
}

/// Projects a service principal's raw JSON into the rollover view.
///
/// Pure (no Graph, no `State`) so the phase machine is table-testable — mirrors
/// [`extract_sp_sso_fields`]. Two Graph behaviours are load-bearing here:
///
/// - a signing certificate is **two** `keyCredentials` entries (a `Sign` and a
///   `Verify` half sharing one `customKeyIdentifier`), so entries are deduped by
///   thumbprint or the list shows every certificate twice;
/// - `customKeyIdentifier` is reported uppercase while
///   `preferredTokenSigningKeyThumbprint` can differ in case, so every
///   comparison is case-insensitive.
fn build_rollover(
    sp: &serde_json::Value,
    service_principal_id: &str,
    tenant_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> SigningCertRolloverDto {
    use azapptoolkit_dto::sso::{CertStatus, RolloverPhase, SigningCertDto};

    let app_id = sp
        .get("appId")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let preferred = sp
        .get("preferredTokenSigningKeyThumbprint")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let parse_time = |v: Option<&serde_json::Value>| -> Option<chrono::DateTime<chrono::Utc>> {
        v.and_then(|x| x.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc))
    };

    // Dedupe the Sign/Verify pair down to one row per certificate.
    let mut certs: Vec<(SigningCertDto, Option<chrono::DateTime<chrono::Utc>>)> = Vec::new();
    for cred in sp
        .get("keyCredentials")
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let thumbprint = cred
            .get("customKeyIdentifier")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if thumbprint.is_empty()
            || certs
                .iter()
                .any(|(c, _)| c.thumbprint.eq_ignore_ascii_case(&thumbprint))
        {
            continue;
        }
        let end = parse_time(cred.get("endDateTime"));
        let is_active = preferred
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case(&thumbprint));
        certs.push((
            SigningCertDto {
                key_id: cred
                    .get("keyId")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                thumbprint,
                display_name: cred
                    .get("displayName")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                start_date_time: cred
                    .get("startDateTime")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                end_date_time: cred
                    .get("endDateTime")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                is_active,
                days_to_expiry: end.map(|e| (e - now).num_days()),
                // Provisional; the pass below needs the active cert's expiry.
                status: CertStatus::Expired,
            },
            end,
        ));
    }

    // The active certificate's expiry is the pivot: a valid non-active cert that
    // outlives it is the rollover candidate, one that doesn't is the fallback.
    let active_end = certs
        .iter()
        .find(|(c, _)| c.is_active)
        .and_then(|(_, end)| *end);
    let active_expired = active_end.is_some_and(|e| e <= now);

    for (cert, end) in &mut certs {
        let expired = end.is_some_and(|e| e <= now);
        cert.status = if expired {
            CertStatus::Expired
        } else if cert.is_active {
            CertStatus::Active
        } else if active_expired || active_end.is_none_or(|a| end.is_some_and(|e| e > a)) {
            // Newer than the active one — or the active one can no longer sign,
            // in which case every valid certificate is a candidate.
            CertStatus::Staged
        } else {
            CertStatus::Superseded
        };
    }

    // Newest first; undated entries sort last.
    certs.sort_by(|(_, a), (_, b)| match (a, b) {
        (Some(a), Some(b)) => b.cmp(a),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    let certs: Vec<SigningCertDto> = certs.into_iter().map(|(c, _)| c).collect();

    let staged_thumbprint = certs
        .iter()
        .find(|c| matches!(c.status, CertStatus::Staged))
        .map(|c| c.thumbprint.clone());
    let has_superseded = certs
        .iter()
        .any(|c| matches!(c.status, CertStatus::Superseded));
    let has_active = certs.iter().any(|c| matches!(c.status, CertStatus::Active));

    let phase = if preferred.is_none() || certs.is_empty() {
        RolloverPhase::Unconfigured
    } else if staged_thumbprint.is_some() {
        RolloverPhase::Staged
    } else if !has_active {
        // A preferred key that is expired (or missing from keyCredentials) with
        // nothing valid to promote — sign-in is broken, not merely mid-rollover.
        RolloverPhase::Unconfigured
    } else if has_superseded {
        RolloverPhase::PendingRetire
    } else {
        RolloverPhase::Steady
    };

    let auto_promote_deadline = matches!(phase, RolloverPhase::Staged)
        .then(|| {
            certs
                .iter()
                .find(|c| c.is_active)
                .and_then(|c| c.end_date_time.clone())
        })
        .flatten();

    let (_, _, _, federation_metadata_url) = saml_summary_urls(tenant_id, &app_id);
    SigningCertRolloverDto {
        service_principal_id: service_principal_id.to_string(),
        app_id,
        federation_metadata_url,
        certs,
        active_thumbprint: preferred,
        staged_thumbprint,
        phase,
        auto_promote_deadline,
    }
}

/// Replaces the claims-mapping policy on an existing app. Removes any existing
/// assignment first (claims-mapping definitions are effectively replace-only),
/// then creates + assigns a fresh policy. Passing an empty `policy` (no schema
/// entries and no transformations) just removes the current policy.
#[tauri::command]
pub async fn set_claims_mapping(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    display_name: String,
    policy: ClaimsPolicyDto,
) -> Result<Option<String>, UiError> {
    // Pre-acquire so a missing consent surfaces typed (the UI's "Grant consent").
    state
        .ensure_policy_write_token(&tenant_id)
        .await
        .map_err(UiError::from)?;
    let client = state.graph_for(&tenant_id);

    // Remove existing assignment(s) so the new policy fully replaces them.
    if let Ok(existing) = client
        .list_assigned_claims_mapping_policies(&service_principal_id)
        .await
    {
        for assigned in existing {
            if let Err(err) = client
                .remove_claims_mapping_policy(&service_principal_id, &assigned.id)
                .await
            {
                tracing::warn!(?err, policy = %assigned.id, "failed to detach old claims policy");
            }
        }
    }

    let policy_id = if policy.is_empty() {
        None
    } else {
        Some(apply_claims_policy(&client, &service_principal_id, &display_name, &policy).await?)
    };
    invalidate_app_lists(&state.cache, &tenant_id);
    Ok(policy_id)
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
    // No cache bust: notificationEmailAddresses is SSO-tab state read live and is
    // on no cached list/detail/audit payload.
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
    azapptoolkit_core::redirect::validate_redirect_uris(&redirect_uris)
        .and_then(|()| azapptoolkit_core::redirect::validate_redirect_uris(&spa_redirect_uris))
        .map_err(invalid_redirect_uri)?;
    let client = state.graph_for(&tenant_id);
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
    client.patch_application_web(&object_id, &body).await?;
    invalidate_app_lists(&state.cache, &tenant_id);
    Ok(())
}

/// Recomputes the app-owner output summary for an existing enterprise app.
/// `protocol` is `"saml"` or `"oidc"`. SAML returns a [`SamlSsoSummary`]
/// (without the signing cert base64 — that's only available at creation/rotation
/// time); OIDC returns an [`OidcSsoSummary`] without the show-once secret. The
/// two are returned as untagged JSON; the front-end branches on `protocol`.
#[tauri::command]
pub async fn get_sso_summary(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    protocol: String,
) -> Result<serde_json::Value, UiError> {
    let config = get_sso_config(state, tenant_id.clone(), service_principal_id).await?;
    if protocol == "oidc" {
        let (authority, discovery_url) = oidc_summary_urls(&tenant_id);
        let summary = OidcSsoSummary {
            object_id: config.object_id,
            service_principal_id: config.service_principal_id,
            client_id: config.app_id,
            tenant_id,
            authority,
            discovery_url,
            redirect_uris: config.redirect_uris,
            spa_redirect_uris: config.spa_redirect_uris,
            client_secret: None,
            client_secret_expiry: None,
        };
        serde_json::to_value(summary).map_err(|e| UiError::serde(e.to_string()))
    } else {
        let (issuer, login_url, logout_url, federation_metadata_url) =
            saml_summary_urls(&tenant_id, &config.app_id);
        let summary = SamlSsoSummary {
            object_id: config.object_id,
            service_principal_id: config.service_principal_id,
            app_id: config.app_id,
            entity_id_issuer: issuer,
            login_url,
            logout_url,
            federation_metadata_url,
            sp_entity_id: config.entity_id.unwrap_or_default(),
            reply_url: config.reply_urls.into_iter().next().unwrap_or_default(),
            signing_cert_base64: None,
            signing_cert_thumbprint: config.signing_cert_thumbprint,
            signing_cert_expiry: config.signing_cert_expiry,
            claims_policy_id: config.claims_policy_id,
        };
        serde_json::to_value(summary).map_err(|e| UiError::serde(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signing_certificate_lifetime_is_bounded_by_entras_three_year_ceiling() {
        // Default when none is supplied.
        assert_eq!(resolve_cert_lifetime_days(None).unwrap(), 365);
        assert_eq!(resolve_cert_lifetime_days(Some(1)).unwrap(), 1);
        assert_eq!(
            resolve_cert_lifetime_days(Some(MAX_CERT_LIFETIME_DAYS)).unwrap(),
            MAX_CERT_LIFETIME_DAYS
        );
        // A certificate that never practically expires is a trust that never
        // has to be re-established — and Graph refuses past three years anyway.
        let err = resolve_cert_lifetime_days(Some(MAX_CERT_LIFETIME_DAYS + 1)).unwrap_err();
        assert_eq!(err.code, "invalid_cert_lifetime");
        // Zero would mint an already-expired certificate.
        assert!(resolve_cert_lifetime_days(Some(0)).is_err());
        // And an absurd value never reaches `chrono::Duration::days`, which
        // panics rather than saturating.
        assert!(resolve_cert_lifetime_days(Some(u32::MAX)).is_err());
    }

    #[test]
    fn cert_subject_requires_cn_prefix() {
        // Graph's addTokenSigningCertificate rejects a displayName that
        // doesn't start with CN= — pin the fail-fast mirror of that rule.
        assert!(validate_cert_subject("CN=Contoso SSO").is_ok());
        assert!(validate_cert_subject("cn=lowercase").is_ok());
        for bad in ["Contoso", "O=Contoso", " ", "CN"] {
            let err = validate_cert_subject(bad).unwrap_err();
            assert_eq!(err.code, "invalid_cert_subject", "input: {bad:?}");
        }
    }

    #[test]
    fn sanitize_notification_emails_trims_and_dedupes() {
        let out = sanitize_notification_emails(&[
            " a@x.com ".into(),
            "A@X.com".into(), // case-insensitive dupe of the first
            String::new(),
            "b@y.com".into(),
        ]);
        assert_eq!(out, vec!["a@x.com".to_string(), "b@y.com".to_string()]);
    }

    #[test]
    fn saml_urls_match_spec() {
        let (issuer, login, logout, metadata) = saml_summary_urls("tid", "aid");
        assert_eq!(issuer, "https://sts.windows.net/tid/");
        assert_eq!(login, "https://login.microsoftonline.com/tid/saml2");
        assert_eq!(logout, login);
        assert_eq!(
            metadata,
            "https://login.microsoftonline.com/tid/federationmetadata/2007-06/federationmetadata.xml?appid=aid"
        );
    }

    #[test]
    fn oidc_urls_match_spec() {
        let (authority, discovery) = oidc_summary_urls("tid");
        assert_eq!(authority, "https://login.microsoftonline.com/tid/v2.0");
        assert_eq!(
            discovery,
            "https://login.microsoftonline.com/tid/v2.0/.well-known/openid-configuration"
        );
    }

    #[test]
    fn extract_app_sso_fields_reads_uris() {
        let app = serde_json::json!({
            "identifierUris": ["https://app/saml", "https://app/saml2"],
            "web": { "redirectUris": ["https://app/acs", "https://app/acs2"], "logoutUrl": "https://app/logout" },
            "spa": { "redirectUris": ["https://app/spa"] }
        });
        let (identifiers, web_redirects, logout, spa) = extract_app_sso_fields(&app);
        // All identifiers and reply URLs are returned (multi-value support).
        assert_eq!(
            identifiers,
            vec![
                "https://app/saml".to_string(),
                "https://app/saml2".to_string()
            ]
        );
        assert_eq!(
            web_redirects,
            vec![
                "https://app/acs".to_string(),
                "https://app/acs2".to_string()
            ]
        );
        assert_eq!(logout.as_deref(), Some("https://app/logout"));
        assert_eq!(spa, vec!["https://app/spa".to_string()]);
    }

    #[test]
    fn extract_sp_sso_fields_matches_expiry_by_thumbprint_case_insensitively() {
        // The signing-cert expiry is the keyCredentials entry whose
        // customKeyIdentifier matches the preferred thumbprint — and the match is
        // case-insensitive (Graph stores customKeyIdentifier uppercase). A
        // non-matching credential's endDateTime must be ignored.
        let sp = serde_json::json!({
            "appId": "app-123",
            "preferredSingleSignOnMode": "saml",
            "preferredTokenSigningKeyThumbprint": "abc123def",
            "keyCredentials": [
                { "customKeyIdentifier": "OTHER", "endDateTime": "2000-01-01T00:00:00Z" },
                { "customKeyIdentifier": "ABC123DEF", "endDateTime": "2030-06-01T00:00:00Z" }
            ],
            "notificationEmailAddresses": ["a@x.com", "b@y.com"]
        });
        let (app_id, sso_mode, thumbprint, expiry, emails) = extract_sp_sso_fields(&sp);
        assert_eq!(app_id, "app-123");
        assert_eq!(sso_mode.as_deref(), Some("saml"));
        assert_eq!(thumbprint.as_deref(), Some("abc123def"));
        // Picked the matching (upper-cased) credential, not the first one.
        assert_eq!(expiry.as_deref(), Some("2030-06-01T00:00:00Z"));
        assert_eq!(emails, vec!["a@x.com".to_string(), "b@y.com".to_string()]);
    }

    // ---------------- staged rollover ----------------

    use azapptoolkit_dto::sso::{CertStatus, RolloverPhase};

    /// `now` for the rollover tables below. Fixed so "expired" and "valid" are
    /// properties of the fixture, not of the day the suite runs.
    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    /// One `keyCredentials` entry. Graph emits a `Sign`/`Verify` pair per
    /// certificate, so the helper takes the usage explicitly.
    fn cred(key_id: &str, thumbprint: &str, end: &str, usage: &str) -> serde_json::Value {
        serde_json::json!({
            "keyId": key_id,
            "customKeyIdentifier": thumbprint,
            "displayName": "CN=Contoso",
            "endDateTime": end,
            "usage": usage,
            "type": "AsymmetricX509Cert",
        })
    }

    fn sp_with(preferred: Option<&str>, creds: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({
            "appId": "app-1",
            "preferredSingleSignOnMode": "saml",
            "preferredTokenSigningKeyThumbprint": preferred,
            "keyCredentials": creds,
        })
    }

    #[test]
    fn rollover_phase_reads_the_four_states_off_live_sp_state() {
        // Steady: one valid certificate, and it's the preferred one.
        let roll = build_rollover(
            &sp_with(
                Some("AAA"),
                vec![cred("k1", "AAA", "2027-01-01T00:00:00Z", "Verify")],
            ),
            "sp-1",
            "tid",
            now(),
        );
        assert_eq!(roll.phase, RolloverPhase::Steady);
        assert_eq!(roll.staged_thumbprint, None);
        // Nothing staged ⇒ no deadline to show.
        assert_eq!(roll.auto_promote_deadline, None);

        // Staged: a newer valid certificate exists but isn't preferred yet.
        let roll = build_rollover(
            &sp_with(
                Some("AAA"),
                vec![
                    cred("k1", "AAA", "2026-06-01T00:00:00Z", "Verify"),
                    cred("k2", "BBB", "2029-01-01T00:00:00Z", "Verify"),
                ],
            ),
            "sp-1",
            "tid",
            now(),
        );
        assert_eq!(roll.phase, RolloverPhase::Staged);
        assert_eq!(roll.staged_thumbprint.as_deref(), Some("BBB"));
        // The ACTIVE certificate's expiry is the activation deadline: once it
        // passes, Entra promotes the staged certificate on its own.
        assert_eq!(
            roll.auto_promote_deadline.as_deref(),
            Some("2026-06-01T00:00:00Z")
        );

        // PendingRetire: the newest certificate is active, the older one is the
        // rollback target and still present.
        let roll = build_rollover(
            &sp_with(
                Some("BBB"),
                vec![
                    cred("k1", "AAA", "2026-06-01T00:00:00Z", "Verify"),
                    cred("k2", "BBB", "2029-01-01T00:00:00Z", "Verify"),
                ],
            ),
            "sp-1",
            "tid",
            now(),
        );
        assert_eq!(roll.phase, RolloverPhase::PendingRetire);
        assert_eq!(
            roll.certs
                .iter()
                .find(|c| c.thumbprint == "AAA")
                .map(|c| c.status),
            Some(CertStatus::Superseded)
        );

        // Unconfigured: no preferred key at all.
        let roll = build_rollover(
            &sp_with(
                None,
                vec![cred("k1", "AAA", "2027-01-01T00:00:00Z", "Verify")],
            ),
            "sp-1",
            "tid",
            now(),
        );
        assert_eq!(roll.phase, RolloverPhase::Unconfigured);
    }

    #[test]
    fn an_expired_active_certificate_means_entra_already_promoted_the_staged_one() {
        // The trap from Microsoft's own docs: with an expired active certificate
        // and a valid inactive one, Entra signs with the inactive one — so the
        // deadline is in the PAST and the UI must not call this "steady".
        let roll = build_rollover(
            &sp_with(
                Some("AAA"),
                vec![
                    cred("k1", "AAA", "2025-06-01T00:00:00Z", "Verify"),
                    cred("k2", "BBB", "2029-01-01T00:00:00Z", "Verify"),
                ],
            ),
            "sp-1",
            "tid",
            now(),
        );
        assert_eq!(roll.phase, RolloverPhase::Staged);
        assert_eq!(roll.staged_thumbprint.as_deref(), Some("BBB"));
        let active = roll.certs.iter().find(|c| c.is_active).unwrap();
        // Still the nominated key, but it can't sign — both facts are visible.
        assert!(active.is_active);
        assert_eq!(active.status, CertStatus::Expired);
        assert!(active.days_to_expiry.is_some_and(|d| d < 0));
        assert_eq!(
            roll.auto_promote_deadline.as_deref(),
            Some("2025-06-01T00:00:00Z")
        );
    }

    #[test]
    fn the_sign_verify_pair_graph_returns_is_one_certificate_not_two() {
        // `addTokenSigningCertificate` writes TWO keyCredentials entries sharing
        // one customKeyIdentifier. Listing both would show every certificate
        // twice and make a one-certificate app look mid-rollover.
        let roll = build_rollover(
            &sp_with(
                Some("AAA"),
                vec![
                    cred("k1", "AAA", "2027-01-01T00:00:00Z", "Sign"),
                    cred("k2", "AAA", "2027-01-01T00:00:00Z", "Verify"),
                ],
            ),
            "sp-1",
            "tid",
            now(),
        );
        assert_eq!(roll.certs.len(), 1);
        assert_eq!(roll.phase, RolloverPhase::Steady);
    }

    #[test]
    fn rollover_matches_the_preferred_thumbprint_case_insensitively_and_sorts_newest_first() {
        // Graph reports customKeyIdentifier uppercase; the preferred field can
        // differ in case. A case-sensitive match would show NO active
        // certificate and read as a broken app.
        let roll = build_rollover(
            &sp_with(
                Some("bbb"),
                vec![
                    cred("k1", "AAA", "2026-06-01T00:00:00Z", "Verify"),
                    cred("k2", "BBB", "2029-01-01T00:00:00Z", "Verify"),
                ],
            ),
            "sp-1",
            "tid",
            now(),
        );
        assert_eq!(roll.certs[0].thumbprint, "BBB", "newest first");
        assert!(roll.certs[0].is_active);
        assert_eq!(roll.certs[0].status, CertStatus::Active);
        // The metadata URL is the app's own, so the panel can link it directly.
        assert!(roll.federation_metadata_url.ends_with("appid=app-1"));
    }

    #[test]
    fn parse_signing_certs_reads_signing_keys_and_skips_encryption_ones() {
        let xml = r#"
            <EntityDescriptor>
              <IDPSSODescriptor>
                <KeyDescriptor use="signing">
                  <KeyInfo><X509Data><X509Certificate>MIIC
                  AAAA</X509Certificate></X509Data></KeyInfo>
                </KeyDescriptor>
                <KeyDescriptor use="encryption">
                  <KeyInfo><X509Data><X509Certificate>SHOULDNOTAPPEAR</X509Certificate></X509Data></KeyInfo>
                </KeyDescriptor>
                <KeyDescriptor use="signing">
                  <KeyInfo><X509Data><X509Certificate>MIICBBBB</X509Certificate></X509Data></KeyInfo>
                </KeyDescriptor>
              </IDPSSODescriptor>
            </EntityDescriptor>"#;
        let certs = parse_signing_certs(xml);
        // Whitespace inside the base64 body is stripped, encryption keys skipped.
        assert_eq!(certs, vec!["MIICAAAA".to_string(), "MIICBBBB".to_string()]);
        // Two published signing keys is the precondition for an app that polls
        // metadata to discover a staged certificate before it goes live.
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn parse_signing_certs_counts_a_use_less_descriptor_and_dedupes() {
        // Per the SAML metadata spec a KeyDescriptor with no `use` is valid for
        // signing, so it counts. The same body repeated is still one key.
        let xml = "<KeyDescriptor><X509Certificate>DUP</X509Certificate></KeyDescriptor>\
                   <KeyDescriptor use=\"signing\"><X509Certificate>DUP</X509Certificate></KeyDescriptor>";
        assert_eq!(parse_signing_certs(xml), vec!["DUP".to_string()]);
    }

    #[test]
    fn parse_signing_certs_never_fabricates_a_match_from_junk() {
        // A malformed or empty document yields nothing — the probe reports "0
        // published" next to the HTTP status rather than inventing a key.
        assert!(parse_signing_certs("").is_empty());
        assert!(parse_signing_certs("<html>404</html>").is_empty());
        // An unterminated element is not a certificate.
        assert!(parse_signing_certs("<KeyDescriptor><X509Certificate>oops").is_empty());
    }

    #[test]
    fn extract_sp_sso_fields_absent_fields_default_empty() {
        // A minimal SP (no SSO mode / thumbprint / creds / emails) yields all
        // `None`/empty — no expiry probe fires without a thumbprint.
        let sp = serde_json::json!({ "appId": "app-only" });
        let (app_id, sso_mode, thumbprint, expiry, emails) = extract_sp_sso_fields(&sp);
        assert_eq!(app_id, "app-only");
        assert_eq!(sso_mode, None);
        assert_eq!(thumbprint, None);
        assert_eq!(expiry, None);
        assert!(emails.is_empty());
    }
}
