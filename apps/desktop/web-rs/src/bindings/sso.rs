//! Single-sign-on (SAML / OIDC) setup IPC bindings.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::sso::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSamlArgs<'a> {
    tenant_id: &'a str,
    input: &'a SamlSsoConfigInput,
}

pub async fn create_saml_sso_application(
    tenant_id: &str,
    input: &SamlSsoConfigInput,
) -> Result<SamlSsoSummary, UiError> {
    invoke_result(
        "create_saml_sso_application",
        CreateSamlArgs { tenant_id, input },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateOidcArgs<'a> {
    tenant_id: &'a str,
    input: &'a OidcSsoConfigInput,
}

pub async fn create_oidc_sso_application(
    tenant_id: &str,
    input: &OidcSsoConfigInput,
) -> Result<OidcSsoSummary, UiError> {
    invoke_result(
        "create_oidc_sso_application",
        CreateOidcArgs { tenant_id, input },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
}

pub async fn get_sso_config(
    tenant_id: &str,
    service_principal_id: &str,
) -> Result<SsoConfigDto, UiError> {
    invoke_result(
        "get_sso_config",
        SpArgs {
            tenant_id,
            service_principal_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetSsoModeArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    mode: &'a str,
}

/// Sets `preferredSingleSignOnMode`: `"saml"`, `"oidc"`, or anything else
/// (e.g. `""`) to disable SSO.
pub async fn set_sso_mode(
    tenant_id: &str,
    service_principal_id: &str,
    mode: &str,
) -> Result<(), UiError> {
    invoke_result(
        "set_sso_mode",
        SetSsoModeArgs {
            tenant_id,
            service_principal_id,
            mode,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetSamlUrlsArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    identifier_uris: &'a [String],
    reply_urls: &'a [String],
    logout_url: Option<&'a str>,
}

pub async fn set_saml_urls(
    tenant_id: &str,
    object_id: &str,
    identifier_uris: &[String],
    reply_urls: &[String],
    logout_url: Option<&str>,
) -> Result<(), UiError> {
    invoke_result(
        "set_saml_urls",
        SetSamlUrlsArgs {
            tenant_id,
            object_id,
            identifier_uris,
            reply_urls,
            logout_url,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotateCertArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    subject: &'a str,
    lifetime_days: Option<u32>,
}

/// Result of `rotate_saml_signing_certificate` (mirrors the backend struct).
#[derive(Clone, Debug, serde::Deserialize)]
pub struct SsoCertResult {
    pub thumbprint: String,
    pub base64: Option<String>,
    pub expiry: Option<String>,
}

pub async fn rotate_saml_signing_certificate(
    tenant_id: &str,
    service_principal_id: &str,
    subject: &str,
    lifetime_days: Option<u32>,
) -> Result<SsoCertResult, UiError> {
    invoke_result(
        "rotate_saml_signing_certificate",
        RotateCertArgs {
            tenant_id,
            service_principal_id,
            subject,
            lifetime_days,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetClaimsArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    display_name: &'a str,
    policy: &'a ClaimsPolicyDto,
}

pub async fn set_claims_mapping(
    tenant_id: &str,
    service_principal_id: &str,
    display_name: &str,
    policy: &ClaimsPolicyDto,
) -> Result<Option<String>, UiError> {
    invoke_result(
        "set_claims_mapping",
        SetClaimsArgs {
            tenant_id,
            service_principal_id,
            display_name,
            policy,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetNotificationEmailsArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    emails: &'a [String],
}

/// Sets the SAML cert-expiry notification recipients on the service principal.
pub async fn set_notification_emails(
    tenant_id: &str,
    service_principal_id: &str,
    emails: &[String],
) -> Result<(), UiError> {
    invoke_result(
        "set_notification_emails",
        SetNotificationEmailsArgs {
            tenant_id,
            service_principal_id,
            emails,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetOidcUrisArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    redirect_uris: &'a [String],
    spa_redirect_uris: &'a [String],
}

pub async fn set_oidc_redirect_uris(
    tenant_id: &str,
    object_id: &str,
    redirect_uris: &[String],
    spa_redirect_uris: &[String],
) -> Result<(), UiError> {
    invoke_result(
        "set_oidc_redirect_uris",
        SetOidcUrisArgs {
            tenant_id,
            object_id,
            redirect_uris,
            spa_redirect_uris,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SummaryArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    protocol: &'a str,
}

/// Recomputes the app-owner summary for an existing app. The backend returns an
/// untagged JSON object; callers deserialize into [`SamlSsoSummary`] or
/// [`OidcSsoSummary`] based on `protocol`.
pub async fn get_sso_summary(
    tenant_id: &str,
    service_principal_id: &str,
    protocol: &str,
) -> Result<serde_json::Value, UiError> {
    invoke_result(
        "get_sso_summary",
        SummaryArgs {
            tenant_id,
            service_principal_id,
            protocol,
        },
    )
    .await
}
