//! The create flows: the "New SSO application" wizard's two end-to-end setups
//! (SAML and OIDC) and their per-step configure helpers.

use std::time::Duration;

use tauri::State;

use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_graph::GraphClient;
use azapptoolkit_graph::client::{
    ApplicationSpaPatch, ApplicationSsoPatch, ApplicationWebPatch, ServicePrincipalSigningKeyPatch,
    ServicePrincipalSsoModePatch,
};

use crate::commands::applications::{augment_with_object_id, invalidate_app_lists};
use crate::dto::UiError;
use crate::dto::sso::{OidcSsoConfigInput, OidcSsoSummary, SamlSsoConfigInput, SamlSsoSummary};
use crate::state::AppState;

use super::{
    apply_claims_policy, claims_policy_err, invalid_logout_url, invalid_redirect_uri,
    oidc_summary_urls, resolve_cert_lifetime_days, resolve_secret_lifetime_days, saml_summary_urls,
    sanitize_notification_emails, validate_cert_subject, with_replication_retry,
};

/// Creates a SAML SSO enterprise application end to end and returns the
/// app-owner summary. Steps 1–5 use the standard write scope; the optional
/// claims step (6) needs the claims-mapping policy token
/// (`Policy.ReadWrite.ApplicationConfiguration` + `Application.ReadWrite.All`) and is
/// skipped entirely when no custom claims are requested.
#[tauri::command]
pub async fn create_saml_sso_application(
    state: State<'_, AppState>,
    tenant_id: String,
    input: SamlSsoConfigInput,
) -> Result<SamlSsoSummary, UiError> {
    create_saml_sso_application_core(&state, &tenant_id, input).await
}

/// Body of [`create_saml_sso_application`], taking `&AppState` so the
/// before-instantiate gates are testable against a mock Graph.
pub(crate) async fn create_saml_sso_application_core(
    state: &AppState,
    tenant_id: &str,
    mut input: SamlSsoConfigInput,
) -> Result<SamlSsoSummary, UiError> {
    // Reject wildcard / insecure reply URLs before creating anything (MS
    // app-registration security best practices).
    azapptoolkit_core::redirect::validate_redirect_uri(&input.reply_url)
        .map_err(invalid_redirect_uri)?;
    // The logout URL too, and by the stricter logout rules (https only — Entra
    // loads it in a hidden iframe at sign-out). Trimmed here so `configure_saml`
    // writes exactly the value that was checked.
    input.logout_url = input
        .logout_url
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(url) = input.logout_url.as_deref() {
        azapptoolkit_core::redirect::validate_logout_url(url).map_err(invalid_logout_url)?;
    }

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
            .ensure_policy_write_token(tenant_id)
            .await
            .map_err(UiError::from)?;
    }

    let client = state.graph_for(tenant_id);
    let cloud = state.auth.cloud();

    // 1. Instantiate the cloud's generic custom template → app + SP.
    let pair = client
        .instantiate_application_template(cloud.custom_app_template_id(), &input.display_name)
        .await?;
    let object_id = pair.application.id.clone();
    let app_id = pair.application.app_id.clone();
    let sp_id = pair.service_principal.id.clone();

    // From here a failure leaves a half-configured app the user can finish in
    // the SSO tab; we never auto-delete. Bust caches on any early return that
    // got past instantiate so the new (paired) SP shows up in the lists.
    let result = configure_saml(
        &client, cloud, &object_id, &sp_id, tenant_id, &app_id, &input,
    )
    .await;
    invalidate_app_lists(&state.cache, tenant_id);
    result.map_err(|e| augment_with_object_id(e, &object_id))
}

/// Steps 2–6 of the SAML flow, factored out so the caller can always invalidate
/// caches once instantiate succeeded. Steps 5b (notification emails) and 6
/// (custom claims) are best-effort: non-fatal, reported in `warnings` so the
/// summary never reads as a clean success when one of them did not land.
pub(crate) async fn configure_saml(
    client: &GraphClient,
    cloud: CloudEnvironment,
    object_id: &str,
    sp_id: &str,
    tenant_id: &str,
    app_id: &str,
    input: &SamlSsoConfigInput,
) -> Result<SamlSsoSummary, UiError> {
    let mut warnings: Vec<String> = Vec::new();

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
    // Retrying the POST on NotFound is safe: NotFound means nothing was minted.
    let cert =
        with_replication_retry(|| client.add_token_signing_certificate(sp_id, &subject, end))
            .await?;

    // 5. Activate it as the preferred signing key.
    let signing_key_body = ServicePrincipalSigningKeyPatch {
        preferred_token_signing_key_thumbprint: cert.thumbprint.clone(),
    };
    with_replication_retry(|| client.patch_service_principal(sp_id, &signing_key_body)).await?;

    // 5b. Optional SAML cert-expiry notification recipients. Best-effort —
    // Entra already seeds the creating admin — so a failure is non-fatal,
    // reported in `warnings`.
    let emails = sanitize_notification_emails(&input.notification_emails);
    if !emails.is_empty() {
        let body = serde_json::json!({ "notificationEmailAddresses": emails });
        if let Err(err) =
            with_replication_retry(|| client.patch_service_principal(sp_id, &body)).await
        {
            tracing::warn!(?err, "failed to set notification emails on new SSO app");
            warnings.push(format!(
                "Certificate-expiry notification emails were not saved: {} Add them on the \
                 app's SSO tab (Save notification emails).",
                UiError::from(err).message
            ));
        }
    }

    // 6. Optional custom claims. Non-fatal, reported in `warnings`: the SSO
    // app is already usable, so we degrade to "no custom claims" rather than
    // failing the whole create.
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
                    warnings.push(format!(
                        "Custom claims were not applied: {} Open the app's SSO tab and \
                         select Save claims to retry.",
                        claims_policy_err(UiError::from(err)).message
                    ));
                    None
                }
            }
        }
        _ => None,
    };

    let (issuer, login_url, logout_url, federation_metadata_url) =
        saml_summary_urls(cloud, tenant_id, app_id);
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
        warnings,
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
    create_oidc_sso_application_core(&state, &tenant_id, input).await
}

/// Body of [`create_oidc_sso_application`], taking `&AppState` so the
/// before-instantiate gates are testable against a mock Graph.
pub(crate) async fn create_oidc_sso_application_core(
    state: &AppState,
    tenant_id: &str,
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
    // Same reason as the SAML certificate lifetime: the secret is only minted
    // after instantiate, so an out-of-range lifetime is rejected here rather
    // than after the app + SP exist. `configure_oidc` resolves it again to get
    // the value — it is a pure function of the input, and this call is the gate.
    if input
        .secret_display_name
        .as_deref()
        .is_some_and(|s| !s.is_empty())
    {
        resolve_secret_lifetime_days(input.secret_lifetime_days)?;
    }

    let client = state.graph_for(tenant_id);
    let cloud = state.auth.cloud();

    let pair = client
        .instantiate_application_template(cloud.custom_app_template_id(), &input.display_name)
        .await?;
    let object_id = pair.application.id.clone();
    let app_id = pair.application.app_id.clone();
    let sp_id = pair.service_principal.id.clone();

    let result = configure_oidc(
        &client, cloud, &object_id, &app_id, &sp_id, tenant_id, &input,
    )
    .await;
    invalidate_app_lists(&state.cache, tenant_id);
    result.map_err(|e| augment_with_object_id(e, &object_id))
}

pub(crate) async fn configure_oidc(
    client: &GraphClient,
    cloud: CloudEnvironment,
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
        let days = resolve_secret_lifetime_days(input.secret_lifetime_days)?;
        let lifetime = Duration::from_secs(u64::from(days) * 86_400);
        let secret =
            with_replication_retry(|| client.add_password(object_id, name, lifetime)).await?;
        (
            secret.secret_text.clone(),
            secret.end_date_time.map(|d| d.to_rfc3339()),
        )
    } else {
        (None, None)
    };

    let (authority, discovery_url) = oidc_summary_urls(cloud, tenant_id);
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
