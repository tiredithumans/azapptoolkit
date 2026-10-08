//! Single-sign-on (SAML / OIDC) setup commands.
//!
//! Stands up an Entra **Enterprise Application** configured for SSO and produces
//! the app-owner output summary (Entity ID/Issuer, login/logout URLs, federation
//! metadata, signing certificate for SAML; client id, authority, discovery URL,
//! redirect URIs + show-once secret for OIDC). Two entry points share this code:
//! the "New SSO application" wizard (create) and the enterprise-app detail "SSO"
//! tab (edit existing).
//!
//! Both protocols instantiate the configured cloud's generic custom application
//! template ([`CloudEnvironment::custom_app_template_id`]) so a paired service
//! principal (the Enterprise App)
//! always appears in the list. The multi-step Graph flow races against directory
//! replication, so every write against the freshly created app/SP (steps 2–5b,
//! and the OIDC redirect/secret writes) is wrapped in
//! [`with_replication_retry`] (retries `NotFound` only).
//!
//! Split by concern: `create` (the wizard's SAML/OIDC create flows), `config`
//! (the SSO tab's read + in-place writers), `rollover` (the signing-certificate
//! lifecycle and its pure projection/guard helpers), `metadata` (the
//! federation-metadata probe + XML scanners), `board` (the tenant-wide
//! cert-expiry board and its cache plumbing), `claims` (the claims-definition
//! codec). The replication retry, the URL/email helpers and the lifetime guards
//! are used by several of those files, so they live here.

mod board;
mod claims;
mod claims_view;
mod config;
mod create;
mod metadata;
mod rollover;

// Glob re-exports keep every item reachable at `crate::commands::sso::*`
// (the pre-split path) — crucially including the hidden `__cmd__<name>` items
// that `#[tauri::command]` generates, which `generate_handler!` resolves at
// `commands::sso::<fn>` alongside the function itself.
pub use board::*;
pub use config::*;
pub use create::*;
pub use metadata::*;
pub use rollover::*;

// The two bulk-remediation entry points, reached as `commands::sso::*`.
pub(crate) use board::invalidate_sso_cert_board_by_cache;
pub(crate) use rollover::stage_if_not_already;

use std::future::Future;
use std::time::Duration;

use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_graph::GraphClient;
use azapptoolkit_graph::GraphError;

use crate::commands::applications::MAX_SECRET_LIFETIME_DAYS;
use crate::commands::graph_err::forbidden_remediation;
use crate::dto::UiError;
use crate::dto::sso::ClaimsPolicyDto;

use claims::build_claims_definition;

// ---------------- Shared plumbing ----------------

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

/// Static SAML output URLs that the app owner needs, derived from the tenant id
/// and `cloud` (issuer root and login host differ per sovereign cloud).
fn saml_summary_urls(
    cloud: CloudEnvironment,
    tenant_id: &str,
    app_id: &str,
) -> (String, String, String, String) {
    let login_root = cloud.login_authority_root();
    let issuer = format!("{}/{tenant_id}/", cloud.saml_issuer_root());
    let login = format!("{login_root}/{tenant_id}/saml2");
    let logout = login.clone();
    let metadata = format!(
        "{login_root}/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml?appid={app_id}"
    );
    (issuer, login, logout, metadata)
}

/// Static OIDC output URLs (authority + discovery document) for the tenant in
/// `cloud`.
fn oidc_summary_urls(cloud: CloudEnvironment, tenant_id: &str) -> (String, String) {
    let authority = format!("{}/{tenant_id}/v2.0", cloud.login_authority_root());
    let discovery = format!("{authority}/.well-known/openid-configuration");
    (authority, discovery)
}

/// Creates and assigns a claims-mapping policy for `policy`, returning the new
/// policy id. The caller must have pre-acquired the policy-write token (so a
/// missing consent surfaces as the typed `consent_required`).
///
/// A failed assign deletes the policy just minted (best effort — it has no
/// subjects, so no ownership check is needed) instead of leaving an orphan in
/// the tenant; the original assign error is returned either way.
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
    if let Err(err) = client
        .assign_claims_mapping_policy(service_principal_id, &created.id)
        .await
    {
        discard_unassigned_claims_policy(client, &created.id).await;
        return Err(err);
    }
    Ok(created.id)
}

/// Best-effort delete of a claims-mapping policy this call just created and
/// never managed to assign — it has no subjects, so deleting it touches no app.
/// A failure only leaves the orphan the delete was trying to avoid, so it is
/// logged, never surfaced over the error that got us here.
async fn discard_unassigned_claims_policy(client: &GraphClient, policy_id: &str) {
    if let Err(err) = client.delete_claims_mapping_policy(policy_id).await {
        tracing::warn!(?err, policy = %policy_id, "failed to delete an unassigned claims policy");
    }
}

/// What saving the claims editor does to Graph, decided from live state before
/// any write (see [`plan_claims_write`]).
#[derive(Debug, PartialEq, Eq)]
enum ClaimsWrite {
    /// No policy assigned and none wanted.
    Nothing,
    /// No policy assigned: create one and assign it.
    Create,
    /// This SP is the policy's only subject: replace its definition in place.
    PatchInPlace(String),
    /// The assigned policy is shared with other subjects: give this SP its own
    /// copy (create, unassign `detach`, assign the copy) and leave the shared
    /// policy untouched for everyone else.
    Fork { detach: String },
    /// An empty editor: unassign the policy, and delete it too when this SP was
    /// its only subject (nothing else would ever use it again).
    Detach { policy_id: String, delete: bool },
}

/// Decides how to save a claims policy. `assigned` is the ids of the policies
/// assigned to `sp_id`; `subjects` is the `appliesTo` ids of the one assigned
/// policy (`None` when none is assigned). Any subject other than `sp_id` — a
/// second SP, or an application object — makes the policy shared, and a shared
/// policy is never edited in place or deleted; so is an empty or missing
/// `appliesTo`, which proves nothing about who else uses it. More than one assigned policy
/// should be impossible (Graph allows one per SP); it fails closed, no writes.
fn plan_claims_write(
    sp_id: &str,
    assigned: &[String],
    subjects: Option<&[String]>,
    empty: bool,
) -> Result<ClaimsWrite, UiError> {
    // Sole ownership needs positive proof: `appliesTo` lists this SP and
    // nothing else. An empty list (replication lag, an odd response) is not
    // proof — the assignment listing just said this SP has the policy — and
    // `all()` over nothing would be vacuously true.
    let sole = subjects.is_some_and(|subs| !subs.is_empty() && subs.iter().all(|s| s == sp_id));
    match assigned {
        [] if empty => Ok(ClaimsWrite::Nothing),
        [] => Ok(ClaimsWrite::Create),
        [id] if empty => Ok(ClaimsWrite::Detach {
            policy_id: id.clone(),
            delete: sole,
        }),
        [id] if sole => Ok(ClaimsWrite::PatchInPlace(id.clone())),
        [id] => Ok(ClaimsWrite::Fork { detach: id.clone() }),
        _ => Err(UiError::validation(
            "multiple_claims_policies",
            "This application has more than one claims-mapping policy assigned. Resolve it in the \
             Entra admin center before editing claims here.",
        )),
    }
}

/// Maps a redirect-URI validation rejection (wildcard / insecure scheme) to a
/// non-retryable `invalid_redirect_uri` UI error.
fn invalid_redirect_uri(message: String) -> UiError {
    UiError::validation("invalid_redirect_uri", message)
}

/// [`invalid_redirect_uri`] for the logout URL, naming the field: the SSO
/// editor re-sends the stored logout URL on every save, so a rejection that
/// read like a reply-URL error would send the operator to the wrong field.
fn invalid_logout_url(message: String) -> UiError {
    invalid_redirect_uri(format!("Logout URL: {message}"))
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

/// Default when the caller supplies none.
///
/// Deliberately ONE year, not the three that Graph and the portal default to: a
/// signing certificate's lifetime is the window a stolen key stays useful, and
/// the staged rollover makes renewing cheap enough that three years of exposure
/// isn't worth the saved effort. (An earlier version of this comment claimed it
/// matched Graph's three-year default, which invited "correcting" the value
/// upward.)
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
                "certificate lifetime must be between 1 and {MAX_CERT_LIFETIME_DAYS} days \
                 (3 years, Entra's maximum); got {days}"
            ),
        ));
    }
    Ok(days)
}

/// Default OIDC client-secret lifetime when the caller supplies none — the
/// portal's recommended preset.
const DEFAULT_SECRET_LIFETIME_DAYS: u32 = 180;

/// Bounds a caller-supplied OIDC client-secret lifetime to
/// `1..=`[`MAX_SECRET_LIFETIME_DAYS`] (the portal's 24-month cap, the same
/// bound the Credentials tab applies).
///
/// `0` would mint a secret that has already expired when the summary shows
/// it; a large value reaches Graph only after `instantiate_application_template`
/// has created the app and service principal, leaving a half-configured app —
/// and `u32::MAX` days overflows `chrono` inside `GraphClient::add_password`.
/// Checking here turns all of that into a typed rejection *before* any mutation.
fn resolve_secret_lifetime_days(days: Option<u32>) -> Result<u32, UiError> {
    let days = days.unwrap_or(DEFAULT_SECRET_LIFETIME_DAYS);
    if days == 0 || i64::from(days) > MAX_SECRET_LIFETIME_DAYS {
        return Err(UiError::validation(
            "invalid_secret_lifetime",
            format!(
                "client secret lifetime must be between 1 and {MAX_SECRET_LIFETIME_DAYS} days \
                 (24 months, Entra's maximum); got {days}"
            ),
        ));
    }
    Ok(days)
}

/// Appends the `sso_claims_mapping` catalog remediation to a 403 from a claims
/// save — which role can manage application policies. Spliced at the command,
/// not in the core: the core's error stays the plain Graph classification its
/// tests assert on.
fn claims_policy_err(mut err: UiError) -> UiError {
    if let Some(remediation) = forbidden_remediation(&err, "sso_claims_mapping") {
        err.message = format!("{} {remediation}", err.message);
    }
    err
}

#[cfg(test)]
mod handler_tests;
#[cfg(test)]
mod tests;
