//! Tenant-wide credential-expiry reporting.
//!
//! Enumerates every app registration in the tenant and flattens its client
//! secrets + certificates into one expiry-sorted list, reusing the audit
//! module's [`summarize_credentials`] so the dashboard's expiry semantics match
//! the security audit's. CSV export goes through the OS save dialog, mirroring
//! `save_audit_to_file`.
//!
//! Read-through cached under `CacheKind::Lists` (`{tenant}|credential_expirations`).
//! It scans the same `/applications` collection the Home dashboard's
//! `list_applications_with_pairing` already caches, so an uncached scan here was a
//! second full-tenant scan on every cold load. The cache is busted by
//! `invalidate_app_credentials` (a rotate/remove shifts an expiry) and
//! `invalidate_app_lists` (a create/delete changes the app set), so a
//! just-rotated/removed credential is never shown as still-expiring — the same
//! freshness contract `apps_pairing` accepts.

use tauri::{AppHandle, State};

use azapptoolkit_core::audit::summarize_credentials;
use azapptoolkit_core::cache::CacheKind;
use azapptoolkit_graph::client::AppListQuery;

use crate::commands::audit::csv_field;
use crate::dto::credentials::CredentialRowDto;
use crate::dto::UiError;
use crate::state::AppState;

/// Page size — Graph caps `$top` at 100 on `/applications`.
const PAGE_SIZE: u32 = 100;
/// Safety cap on total apps scanned, mirroring the audit run.
const MAX_APPS: usize = 10_000;

/// Lists every app-registration credential (client secret + certificate) in the
/// tenant, sorted soonest-to-expire first (credentials with no expiry sort
/// last).
#[tauri::command]
pub async fn list_credential_expirations(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<CredentialRowDto>, UiError> {
    let cache_key = crate::commands::applications::credential_expirations_key(&tenant_id);
    if let Some(cached) = state
        .cache
        .get::<Vec<CredentialRowDto>>(CacheKind::Lists, &cache_key)
    {
        return Ok(cached);
    }
    let client = state.graph_for(&tenant_id);
    // Project only what `summarize_credentials` + the row build read. The
    // default projection drags in `requiredResourceAccess`, `verifiedPublisher`,
    // etc. — unused here and, for permission-heavy apps, the bulk of the
    // payload, multiplied across a full-tenant scan on every visit to this view.
    let apps = client
        .list_applications_all(
            AppListQuery::default()
                .with_top(PAGE_SIZE)
                .with_select(vec![
                    "id",
                    "appId",
                    "displayName",
                    "passwordCredentials",
                    "keyCredentials",
                ]),
            Some(MAX_APPS),
        )
        .await?;
    let now = chrono::Utc::now();

    let mut rows: Vec<CredentialRowDto> = Vec::new();
    for app in &apps {
        let (secrets, certs) = summarize_credentials(app, now);
        for c in secrets.into_iter().chain(certs) {
            rows.push(CredentialRowDto {
                app_object_id: app.id.clone(),
                app_id: app.app_id.clone(),
                app_display_name: app.display_name.clone(),
                credential_name: c.name,
                kind: c.kind,
                start_date_time: c.start_date_time,
                end_date_time: c.end_date_time,
                days_to_expiry: c.days_to_expiry,
                status: c.status,
            });
        }
    }

    rows.sort_by_key(|r| sort_key(r.days_to_expiry));
    state.cache.put(CacheKind::Lists, cache_key, &rows);
    Ok(rows)
}

/// Sort by days-to-expiry ascending; `None` (no expiry) sorts last.
fn sort_key(days: Option<i64>) -> (u8, i64) {
    match days {
        Some(d) => (0, d),
        None => (1, 0),
    }
}

/// Writes the credential list as CSV via the OS save dialog. Returns the chosen
/// path, or `None` if the user cancelled. Mirrors `save_audit_to_file`.
#[tauri::command]
pub async fn save_credentials_to_file(
    app_handle: AppHandle,
    rows: Vec<CredentialRowDto>,
    format: String,
) -> Result<Option<String>, UiError> {
    if format != "csv" {
        return Err(UiError::validation(
            "unsupported_format",
            format!("unsupported export format: {format}"),
        ));
    }
    let content = credentials_to_csv(&rows);
    let default_name = format!(
        "credentials-{}.csv",
        chrono::Utc::now().format("%Y%m%dT%H%M%S")
    );
    super::audit::write_via_dialog(app_handle, "CSV", "csv", default_name, content).await
}

/// Serializes credential rows as CSV. Display names are app-controllable, so
/// every field is routed through `csv_field` (formula-injection guard +
/// delimiter quoting), reused from the audit export.
fn credentials_to_csv(rows: &[CredentialRowDto]) -> String {
    let mut out = String::new();
    out.push_str("Application,AppId,ObjectId,Credential,Kind,Expires,DaysToExpiry,Status\n");
    for r in rows {
        let row = [
            csv_field(&r.app_display_name),
            csv_field(&r.app_id),
            csv_field(&r.app_object_id),
            csv_field(&r.credential_name),
            csv_field(r.kind.as_str()),
            csv_field(&r.end_date_time.map(|d| d.to_rfc3339()).unwrap_or_default()),
            r.days_to_expiry.map(|d| d.to_string()).unwrap_or_default(),
            csv_field(r.status.as_str()),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::audit::{CredentialKind, CredentialStatus};

    fn row(name: &str, days: Option<i64>) -> CredentialRowDto {
        CredentialRowDto {
            app_object_id: "obj-1".into(),
            app_id: "app-1".into(),
            app_display_name: name.into(),
            credential_name: "secret-1".into(),
            kind: CredentialKind::Secret,
            start_date_time: None,
            end_date_time: None,
            days_to_expiry: days,
            status: CredentialStatus::Active,
        }
    }

    #[test]
    fn sort_key_orders_expiry_first_and_no_expiry_last() {
        let mut v = vec![None, Some(30), Some(-3), Some(7)];
        v.sort_by_key(|d| sort_key(*d));
        assert_eq!(v, vec![Some(-3), Some(7), Some(30), None]);
    }

    #[test]
    fn csv_has_header_and_one_row_per_credential() {
        let csv = credentials_to_csv(&[row("App A", Some(10)), row("App B", None)]);
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[0].starts_with("Application,AppId,ObjectId,Credential"));
        assert_eq!(lines.len(), 3); // header + 2 rows
        assert!(lines[1].starts_with("App A,"));
    }

    #[test]
    fn csv_neutralizes_formula_injection_in_app_name() {
        // CWE-1236: an app display name beginning with '=' must be defused so a
        // spreadsheet treats the cell as text, not a formula.
        let csv = credentials_to_csv(&[row("=cmd|'/c calc',A1", Some(1))]);
        assert!(csv.contains("\"'=cmd|'/c calc',A1\""));
        assert!(!csv.lines().skip(1).any(|l| l.starts_with('=')));
    }
}
