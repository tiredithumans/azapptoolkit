//! The tenant-wide certificate-expiry board: the list command, its CSV export,
//! the row classifier, and the cache key/invalidation pair the rest of the SSO
//! layer (and bulk remediation) uses to keep it fresh.

use tauri::State;

use azapptoolkit_core::cache::CacheKind;

use crate::dto::UiError;
use crate::dto::sso::SsoCertificateRowDto;
use crate::state::AppState;

use super::rollover::build_rollover;

/// Tenant-wide SAML signing-certificate expiry board.
///
/// The audit's credential rules read an *application's* `keyCredentials`, so a
/// SAML signing certificate — which lives on the service principal — was
/// invisible in-app: the first anyone heard of an expiry was Entra's 60-day
/// email, which goes to `notificationEmailAddresses` that may be nobody's
/// mailbox any more. This is the list that makes rotation schedulable.
///
/// One server-side filtered scan (`preferredSingleSignOnMode eq 'saml'`), then
/// the **same** [`build_rollover`] projection the SSO tab uses — so a row here
/// and the panel there can never disagree about whether a replacement is
/// staged. Soonest-to-expire first.
///
/// Cached per tenant on `CacheKind::Lists`; every rollover mutation busts it.
#[tauri::command]
pub async fn list_sso_certificate_expirations(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<SsoCertificateRowDto>, UiError> {
    // The cache-HIT path below returns before any client is built, so the
    // `graph_for` on the miss path is not a session proof for it.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    let cache_key = sso_certificate_expirations_key(&tenant_id);
    if let Some(cached) = state
        .cache
        .get::<Vec<SsoCertificateRowDto>>(CacheKind::Lists, &cache_key)
    {
        return Ok(cached);
    }
    // Before the scan: a rollover that lands while it pages busts this key,
    // and the store below must not re-cache the pre-rollover board.
    let watch = state.cache.generation_for(CacheKind::Lists, &cache_key);

    let client = state.graph_for(&tenant_id);
    // `truncated` is logged by the client. The cap is SP_INDEX_MAX (10 000)
    // applied to SAML apps *only*, so unlike the unfiltered index scans this is
    // not a bound a real tenant reaches — a directory with more than ten
    // thousand SAML SSO applications does not exist in practice.
    let (sps, _truncated) = client.list_saml_sso_service_principals().await?;
    let now = chrono::Utc::now();
    let cloud = state.auth.cloud();

    let mut rows: Vec<SsoCertificateRowDto> = sps
        .iter()
        .map(|sp| {
            let sp_id = sp
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let roll = build_rollover(sp, &sp_id, &tenant_id, cloud, now);
            // The row is about the certificate that signs *today* — the active
            // one. `build_rollover` keeps it flagged `is_active` even once
            // expired, which is exactly the row worth showing loudest.
            let active = roll.certs.iter().find(|c| c.is_active);
            SsoCertificateRowDto {
                service_principal_id: sp_id,
                app_id: roll.app_id,
                display_name: sp
                    .get("displayName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("—")
                    .to_string(),
                thumbprint: roll.active_thumbprint,
                end_date_time: active.and_then(|c| c.end_date_time.clone()),
                days_to_expiry: active.and_then(|c| c.days_to_expiry),
                status: sso_cert_status(active),
                has_staged_replacement: roll.staged_thumbprint.is_some(),
                phase: roll.phase,
                notification_emails_configured: sp
                    .get("notificationEmailAddresses")
                    .and_then(|v| v.as_array())
                    .is_some_and(|a| a.iter().any(|e| e.as_str().is_some_and(|s| !s.is_empty()))),
            }
        })
        .collect();

    // Soonest first; an app with no resolvable expiry sorts last rather than
    // masquerading as urgent.
    rows.sort_by_key(|r| r.days_to_expiry.unwrap_or(i64::MAX));
    state.cache.put_if_current(watch, &rows);
    Ok(rows)
}

/// Exports the expiry board as CSV through the OS save dialog — same shape as
/// the credential-expiry export, so both boards produce comparable files.
#[tauri::command]
pub async fn save_sso_certificates_to_file(
    app_handle: tauri::AppHandle,
    rows: Vec<SsoCertificateRowDto>,
    format: String,
) -> Result<Option<String>, UiError> {
    crate::commands::export::save_csv_via_dialog(app_handle, "sso-certificates", &format, || {
        sso_certificates_to_csv(&rows)
    })
    .await
}

/// Serializes the board as CSV. Display names are tenant-controllable, so every
/// field goes through `csv_field` (formula-injection guard + delimiter quoting),
/// reused from the audit export.
pub(crate) fn sso_certificates_to_csv(rows: &[SsoCertificateRowDto]) -> String {
    use crate::commands::export::csv_field;
    let mut out = String::new();
    out.push_str(
        "Application,AppId,ServicePrincipalId,Thumbprint,Expires,DaysToExpiry,Status,\
         ReplacementStaged,NotificationEmailsConfigured\n",
    );
    for r in rows {
        let row = [
            csv_field(&r.display_name),
            csv_field(&r.app_id),
            csv_field(&r.service_principal_id),
            csv_field(r.thumbprint.as_deref().unwrap_or_default()),
            csv_field(r.end_date_time.as_deref().unwrap_or_default()),
            r.days_to_expiry.map(|d| d.to_string()).unwrap_or_default(),
            csv_field(r.status.as_str()),
            csv_field(if r.has_staged_replacement {
                "yes"
            } else {
                "no"
            }),
            csv_field(if r.notification_emails_configured {
                "yes"
            } else {
                "no"
            }),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

/// Classifies the active signing certificate for the expiry board, by the same
/// day thresholds the audit's credential rules use — so "Expiring Soon" means
/// the same number of days on both boards. No resolvable certificate (or no
/// resolvable expiry on it) is `Unknown`, never `Active`: an unreadable date is
/// not evidence of health.
///
/// Expired-ness is taken from the cert's [`CertStatus`] — the timestamp
/// comparison `build_rollover` already made — not re-derived from the day
/// count, so the board and the SSO tab can never disagree about whether the
/// same certificate is expired.
pub(crate) fn sso_cert_status(
    active: Option<&azapptoolkit_dto::sso::SigningCertDto>,
) -> azapptoolkit_core::audit::CredentialStatus {
    use azapptoolkit_core::audit::CredentialStatus;
    use azapptoolkit_dto::sso::CertStatus;
    let Some(cert) = active else {
        return CredentialStatus::Unknown;
    };
    if matches!(cert.status, CertStatus::Expired) {
        return CredentialStatus::Expired;
    }
    // The audit's own day bucketing, not a copy of it.
    CredentialStatus::from_days_to_expiry(cert.days_to_expiry)
}

/// Cache key for [`list_sso_certificate_expirations`]. Tenant-scoped like every
/// other Lists key — an unscoped key here would leak one tenant's SSO inventory
/// into another's board.
pub(crate) fn sso_certificate_expirations_key(tenant_id: &str) -> String {
    format!("{tenant_id}|sso_certificate_expirations")
}

/// Busts the expiry board. Called on `Ok` by every mutation that can change a
/// row: the certificate ones, plus `set_notification_emails` (it flips the
/// "nobody is warned" column) and `set_sso_mode` (it decides whether the app is
/// on the board at all). Missing either of those last two leaves the board
/// contradicting the SSO tab for up to the cache TTL.
pub(crate) fn invalidate_sso_cert_board(state: &State<'_, AppState>, tenant_id: &str) {
    invalidate_sso_cert_board_by_cache(&state.cache, tenant_id);
}

/// Cache-only variant of [`invalidate_sso_cert_board`] for callers that hold a
/// `&Cache` rather than the `State` (the bulk driver's post-run sweep).
pub(crate) fn invalidate_sso_cert_board_by_cache(
    cache: &azapptoolkit_core::cache::Cache,
    tenant_id: &str,
) {
    cache.invalidate(
        CacheKind::Lists,
        &sso_certificate_expirations_key(tenant_id),
    );
}
