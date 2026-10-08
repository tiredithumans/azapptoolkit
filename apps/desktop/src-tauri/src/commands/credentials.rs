//! Tenant-wide credential-expiry reporting.
//!
//! Enumerates every app registration in the tenant and flattens its client
//! secrets + certificates into one expiry-sorted list, reusing the audit
//! module's [`summarize_credentials`] so the dashboard's expiry semantics match
//! the security audit's. CSV export goes through the OS save dialog, mirroring
//! `save_audit_to_file`.
//!
//! The roll-up has no scan of its own: it is derived from the App
//! Registrations scan (`applications::scan_app_list`), whose `$select` is a
//! superset of what it reads, and stored pinned and guarded under
//! `CacheKind::Lists` (`{tenant}|credential_expirations`) with a watch captured
//! before that scan. It used to page the whole `/applications` collection
//! itself, a second (with the Enterprise Apps name index, third) full-tenant
//! scan on every cold Home load. The cache is busted by
//! `invalidate_app_credentials` (a rotate/remove shifts an expiry) and
//! `invalidate_app_lists` (a create/delete changes the app set), so a
//! just-rotated/removed credential is never shown as still-expiring — the same
//! freshness contract `apps_pairing` accepts.

use std::collections::HashMap;

use tauri::{AppHandle, State};

use azapptoolkit_core::audit::{enforced_secret_max_days, summarize_credentials};
use azapptoolkit_core::models::{AppManagementPolicy, Application, TenantAppManagementPolicy};
use chrono::{DateTime, Utc};

use crate::commands::export::csv_field;
use crate::dto::UiError;
use crate::dto::credentials::{
    AppCredentialPolicyDto, CredentialRowDto, CredentialUsageDto, CredentialUsageRow,
};
use crate::state::AppState;

/// Lists every app-registration credential (client secret + certificate) in the
/// tenant, sorted soonest-to-expire first (credentials with no expiry sort
/// last).
#[tauri::command]
pub async fn list_credential_expirations(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<std::sync::Arc<Vec<CredentialRowDto>>, UiError> {
    // The cache-HIT path returns before any client is built, so it needs its
    // own session proof.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    Ok(crate::commands::applications::credential_expirations_cached(&state, &tenant_id).await?)
}

/// Tenant-wide per-credential last-used map for the Credentials tab, read from
/// the beta `appCredentialSignInActivities` report. Same fold as the audit's
/// prefetch (per credential: newest date wins; a present row with no date is
/// "tracked but never used"), so the tab's column and the audit's
/// unused-credential advisory can never disagree — but this degrades to
/// `available: false` instead of failing, because the tab renders "—" for
/// unknown, it must not error.
///
/// **Global cloud only**: on a sovereign cloud the host rejects the beta path
/// and this always answers "not available" — the same graceful-degradation
/// contract the unused-app report's sovereign limit follows.
#[tauri::command]
pub async fn list_credential_usage(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<CredentialUsageDto, UiError> {
    // The tab calls this on every mount; prove the session before the
    // (possibly cache-hit) report read, matching `list_credential_expirations`.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    let client = state.graph_for(&tenant_id);
    // Read-through cached in the Graph client (60-min Permissions TTL): a
    // re-opened tab or a fresh app detail costs no second walk of a slow,
    // rate-limited beta report.
    let report = match state.ensure_audit_log_token(&tenant_id).await {
        Ok(()) => client.list_app_credential_sign_in_activities().await.ok(),
        Err(err) => {
            tracing::info!(
                code = %UiError::from(err).code,
                "credential usage: AuditLog.Read.All token unavailable; Last-used column degrades to unknown"
            );
            None
        }
    };
    let Some(rows) = report else {
        return Ok(CredentialUsageDto {
            available: false,
            rows: Vec::new(),
        });
    };
    let mut merged: HashMap<(String, String), Option<DateTime<Utc>>> = HashMap::new();
    for r in &rows {
        let (Some(app_id), Some(key_id)) = (r.app_id.as_deref(), r.key_id.as_deref()) else {
            continue;
        };
        if app_id.is_empty() || key_id.is_empty() {
            continue;
        }
        // Any dated row makes the credential "used as of" that date; absence
        // of a row entirely is handled client-side as Unknown (no key here).
        let entry = merged
            .entry((app_id.to_string(), key_id.to_string()))
            .or_insert(None);
        if let Some(dt) = r
            .sign_in_activity
            .as_ref()
            .and_then(|s| s.last_sign_in_date_time)
        {
            *entry = Some(match *entry {
                Some(prev) if prev >= dt => prev,
                _ => dt,
            });
        }
    }
    let mut out: Vec<CredentialUsageRow> = merged
        .into_iter()
        .map(|((app_id, key_id), last_used)| CredentialUsageRow {
            app_id,
            key_id,
            last_used,
        })
        .collect();
    // Deterministic order — the map iteration order would otherwise make two
    // identical reports serialize differently.
    out.sort_by(|a, b| (&a.app_id, &a.key_id).cmp(&(&b.app_id, &b.key_id)));
    Ok(CredentialUsageDto {
        available: true,
        rows: out,
    })
}

/// The effective secret-lifetime cap for one application, from its policy pair.
/// Kept out of the command so the precedence table is testable without a
/// client. ≥2 overrides on one principal is a combination Graph does not
/// document ("only one policy is typically assigned") — the combination is
/// unknowable, so it reads as NO cap, matching `ScoreCtx::secret_cap_for`:
/// the tab and the audit can never disagree about one app's cap.
fn effective_cap_days(
    default: Option<&TenantAppManagementPolicy>,
    assigned: &[AppManagementPolicy],
    created: Option<DateTime<Utc>>,
) -> Option<i64> {
    if assigned.len() >= 2 {
        return None;
    }
    enforced_secret_max_days(assigned.first(), default, created)
}

/// Per-app credential-policy context for the Credentials tab (the per-app
/// sibling of the audit's lifetime advisory). Three reads — the application
/// (for its creation date, the policy date gate's input), the tenant default
/// policy, and the per-app override nav — all read-through cached in the
/// client; any failure degrades the whole DTO to `available: false` rather
/// than erroring, because the tab's contract is "show nothing when the policy
/// is unknown", never "claim no cap".
#[tauri::command]
pub async fn get_app_credential_policy(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<AppCredentialPolicyDto, UiError> {
    // Mount-time read like the Last-used column: prove the session before the
    // (possibly cache-hit) reads.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    let client = state.graph_for(&tenant_id);
    let (app, default_policy, assigned) = tokio::join!(
        client.get_application(&object_id),
        client.get_default_app_management_policy(),
        client.list_app_management_policies_for_app(&object_id),
    );
    let (Ok(app), Ok(default_policy), Ok(assigned)) = (app, default_policy, assigned) else {
        tracing::info!(
            tenant_id,
            object_id,
            "credential policy: app or policy reads failed; tab shows no cap"
        );
        return Ok(AppCredentialPolicyDto::default());
    };
    let effective_cap_days =
        effective_cap_days(default_policy.as_ref(), &assigned, app.created_date_time);
    let custom_policy_names = assigned
        .iter()
        .map(|p| {
            if p.display_name.is_empty() {
                p.id.clone()
            } else {
                p.display_name.clone()
            }
        })
        .collect();
    Ok(AppCredentialPolicyDto {
        available: true,
        effective_cap_days,
        custom_policy_names,
    })
}

/// Flattens every app's client secrets + certificates into one expiry-sorted
/// list, reusing the audit's [`summarize_credentials`] so the roll-up's expiry
/// semantics match the security audit's.
pub(crate) fn credential_rows(apps: &[Application], now: DateTime<Utc>) -> Vec<CredentialRowDto> {
    let mut rows: Vec<CredentialRowDto> = Vec::new();
    for app in apps {
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
    sort_credential_rows(&mut rows);
    rows
}

/// The roll-up's one order: soonest expiry first, no expiry last. Stable, so
/// a patched roll-up (`applications::record_created_apps`) keeps its other
/// rows where the scan put them.
pub(crate) fn sort_credential_rows(rows: &mut [CredentialRowDto]) {
    rows.sort_by_key(|r| sort_key(r.days_to_expiry));
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
    super::export::save_csv_via_dialog(app_handle, "credentials", &format, || {
        credentials_to_csv(&rows)
    })
    .await
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

    /// The roll-up is flattened across apps and sorted by expiry, whatever the
    /// order the scan returned the apps and credentials in, and every row
    /// carries the identity of the app it came from.
    #[test]
    fn credential_rows_flattens_and_sorts_across_apps() {
        use azapptoolkit_core::models::{KeyCredential, PasswordCredential};
        let now = Utc::now();
        let a = Application {
            id: "obj-a".into(),
            app_id: "app-a".into(),
            display_name: "App A".into(),
            password_credentials: vec![PasswordCredential {
                key_id: "k1".into(),
                display_name: Some("later".into()),
                end_date_time: Some(now + chrono::Duration::days(90)),
                ..Default::default()
            }],
            key_credentials: vec![KeyCredential {
                key_id: "k2".into(),
                display_name: Some("no-end".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let b = Application {
            id: "obj-b".into(),
            app_id: "app-b".into(),
            display_name: "App B".into(),
            password_credentials: vec![PasswordCredential {
                key_id: "k3".into(),
                display_name: Some("expired".into()),
                end_date_time: Some(now - chrono::Duration::days(5)),
                ..Default::default()
            }],
            ..Default::default()
        };

        let rows = credential_rows(&[a, b], now);

        let names: Vec<&str> = rows.iter().map(|r| r.credential_name.as_str()).collect();
        assert_eq!(names, ["expired", "later", "no-end"]);
        assert_eq!(rows[0].app_object_id, "obj-b");
        assert_eq!(rows[0].app_id, "app-b");
        assert_eq!(rows[0].app_display_name, "App B");
        assert_eq!(rows[0].kind, CredentialKind::Secret);
        assert_eq!(rows[1].app_object_id, "obj-a");
        assert_eq!(rows[2].app_id, "app-a");
        assert_eq!(rows[2].app_display_name, "App A");
        assert_eq!(rows[2].kind, CredentialKind::Certificate);
        assert_eq!(rows[2].days_to_expiry, None);
    }

    #[test]
    fn effective_cap_days_follows_the_audit_precedence_table() {
        use azapptoolkit_core::models::{
            AppManagementConfiguration, CredentialRestrictionConfiguration,
        };
        let life = |max: &str| CredentialRestrictionConfiguration {
            restriction_type: Some("passwordLifetime".into()),
            state: Some("enabled".into()),
            max_lifetime: Some(max.into()),
            restrict_for_apps_created_after_date_time: None,
        };
        let policy = |caps: Vec<&str>| AppManagementConfiguration {
            password_credentials: caps.iter().map(|c| life(c)).collect(),
            ..Default::default()
        };
        let tenant = |caps: Vec<&str>| TenantAppManagementPolicy {
            is_enabled: true,
            application_restrictions: Some(policy(caps)),
            ..Default::default()
        };
        let custom = |name: &str, caps: Vec<&str>| AppManagementPolicy {
            id: name.into(),
            display_name: name.into(),
            is_enabled: true,
            restrictions: Some(policy(caps)),
            applies_to: vec![],
        };
        let old = Some(Utc::now() - chrono::Duration::days(400));

        // No policy at all ⇒ no cap — and, crucially, an UNREAD policy never
        // reaches here: the command degrades before this runs.
        assert_eq!(effective_cap_days(None, &[], old), None);
        // Tenant default applies to an un-overridden app…
        assert_eq!(
            effective_cap_days(Some(&tenant(vec!["P90D"])), &[], old),
            Some(90)
        );
        // …but an assigned override REPLACES it, even one with no lifetime
        // rule of its own.
        assert_eq!(
            effective_cap_days(Some(&tenant(vec!["P90D"])), &[custom("bare", vec![])], old),
            None
        );
        // An enabled override's own cap is the effective one…
        assert_eq!(
            effective_cap_days(
                Some(&tenant(vec!["P90D"])),
                &[custom("strict", vec!["P30D"])],
                old
            ),
            Some(30)
        );
        // …and ≥2 overrides is an unknowable combination ⇒ no verdict, never
        // a guessed minimum.
        assert_eq!(
            effective_cap_days(
                Some(&tenant(vec!["P90D"])),
                &[custom("a", vec![]), custom("b", vec!["P30D"])],
                old
            ),
            None
        );
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
