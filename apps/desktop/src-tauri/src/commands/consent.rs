//! Tenant-wide OAuth2 (delegated) consent-grant audit.
//!
//! Enumerates every `oauth2PermissionGrant` in the tenant, resolves the client
//! and resource service-principal names from the shared SP index, splits the
//! granted scopes, and flags high-risk ones (via
//! [`azapptoolkit_core::audit::is_risky_delegated_scope`]). Surfaces broad /
//! admin-consented delegated access an attacker could abuse. CSV export mirrors
//! the audit/credentials exports.
//!
//! No read-through cache (always fresh, like the credential dashboard) — but it
//! reuses the cached per-tenant SP index for name resolution.

use std::cmp::Reverse;
use std::collections::HashMap;

use tauri::{AppHandle, State};

use azapptoolkit_core::audit::{
    HIGH_RISK_APP_PERMISSIONS, MEDIUM_RISK_APP_PERMISSIONS, is_risky_delegated_scope,
};

use crate::commands::applications::sp_index_cached;
use crate::commands::export::csv_field;
use crate::dto::UiError;
use crate::dto::consent::{AppPermissionGrantDto, OAuth2GrantDto};
use crate::state::AppState;

/// High-value first-party resource APIs scanned for application-permission
/// grants. Microsoft Graph dominates, but Exchange Online and SharePoint also
/// expose powerful app-only permissions.
const SCANNED_RESOURCE_APP_IDS: &[&str] = &[
    "00000003-0000-0000-c000-000000000000", // Microsoft Graph
    "00000002-0000-0ff1-ce00-000000000000", // Office 365 Exchange Online
    "00000003-0000-0ff1-ce00-000000000000", // Office 365 SharePoint Online
];

/// Classifies a resolved application-permission value as `high` / `medium` /
/// `low` using the audit's risk lists.
fn permission_risk(value: &str) -> &'static str {
    if HIGH_RISK_APP_PERMISSIONS.contains(&value) {
        "high"
    } else if MEDIUM_RISK_APP_PERMISSIONS.contains(&value) {
        "medium"
    } else {
        "low"
    }
}

fn risk_rank(risk: &str) -> u8 {
    match risk {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    }
}

/// Lists every delegated permission grant in the tenant, client/resource names
/// resolved and scopes risk-classified, sorted risky-first.
#[tauri::command]
pub async fn list_oauth2_grants_audit(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<OAuth2GrantDto>, UiError> {
    let client = state.graph_for(&tenant_id);

    // Reuse the shared per-tenant SP index for name resolution (same cache the
    // App Registrations / Enterprise Apps lists use).
    let sps = sp_index_cached(&state, &client, &tenant_id).await?;
    let by_id: HashMap<String, (String, String)> = sps
        .into_iter()
        .map(|sp| (sp.id, (sp.display_name, sp.app_id)))
        .collect();

    let grants = client.list_all_oauth2_grants().await?;

    let mut rows: Vec<OAuth2GrantDto> = grants
        .into_iter()
        .map(|g| {
            let (client_display_name, client_app_id) = match by_id.get(&g.client_id) {
                Some((name, app_id)) => (name.clone(), Some(app_id.clone())),
                None => (format!("(unknown SP {})", g.client_id), None),
            };
            let resource_display_name = by_id
                .get(&g.resource_id)
                .map(|(name, _)| name.clone())
                .unwrap_or_else(|| format!("(unknown SP {})", g.resource_id));
            let scopes: Vec<String> = g.scope.split_whitespace().map(str::to_string).collect();
            let risky_scopes: Vec<String> = scopes
                .iter()
                .filter(|s| is_risky_delegated_scope(s))
                .cloned()
                .collect();
            OAuth2GrantDto {
                grant_id: g.id,
                client_sp_id: g.client_id,
                client_display_name,
                client_app_id,
                resource_display_name,
                consent_type: g.consent_type,
                scopes,
                risky_scopes,
            }
        })
        .collect();

    // Risky grants first, then admin-consent (AllPrincipals), then by client.
    rows.sort_by(|a, b| {
        let key = |r: &OAuth2GrantDto| {
            (
                Reverse(!r.risky_scopes.is_empty()),
                Reverse(r.consent_type == "AllPrincipals"),
                r.client_display_name.to_lowercase(),
            )
        };
        key(a).cmp(&key(b))
    });

    Ok(rows)
}

/// Writes the grant list as CSV via the OS save dialog. Mirrors
/// `save_audit_to_file` / `save_credentials_to_file`.
#[tauri::command]
pub async fn save_oauth2_grants_to_file(
    app_handle: AppHandle,
    rows: Vec<OAuth2GrantDto>,
    format: String,
) -> Result<Option<String>, UiError> {
    if format != "csv" {
        return Err(UiError::validation(
            "unsupported_format",
            format!("unsupported export format: {format}"),
        ));
    }
    let content = grants_to_csv(&rows);
    let default_name = format!(
        "oauth2-grants-{}.csv",
        chrono::Utc::now().format("%Y%m%dT%H%M%S")
    );
    super::export::write_via_dialog(app_handle, "CSV", "csv", default_name, content).await
}

fn grants_to_csv(rows: &[OAuth2GrantDto]) -> String {
    let mut out = String::new();
    out.push_str("Client,ClientAppId,Resource,ConsentType,Scopes,RiskyScopes\n");
    for r in rows {
        let row = [
            csv_field(&r.client_display_name),
            csv_field(r.client_app_id.as_deref().unwrap_or("")),
            csv_field(&r.resource_display_name),
            csv_field(&r.consent_type),
            csv_field(&r.scopes.join(" ")),
            csv_field(&r.risky_scopes.join(" ")),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

/// Lists every **application** permission held tenant-wide on the high-value
/// resource APIs ([`SCANNED_RESOURCE_APP_IDS`]) — i.e. the app-only access apps
/// have been granted. Queries each resource's `appRoleAssignedTo` (one paged
/// call per resource, not per-app), resolves the permission value from the
/// resource's `appRoles`, and risk-classifies it. Sorted high-risk first.
#[tauri::command]
pub async fn list_app_permission_grants(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<AppPermissionGrantDto>, UiError> {
    let client = state.graph_for(&tenant_id);

    // Scan the resources concurrently — one appRoleAssignedTo call each. A
    // resource absent from the tenant (or a failed call) yields no rows, never
    // a hard error.
    let per_resource = futures::future::join_all(SCANNED_RESOURCE_APP_IDS.iter().map(
        |&resource_app_id| {
            let client = client.clone();
            async move {
                let resource = match client.resolve_resource_sp(resource_app_id).await {
                    Ok(Some(sp)) => sp,
                    Ok(None) => return Vec::new(),
                    Err(err) => {
                        tracing::warn!(?err, resource = %resource_app_id, "app-permission scan: resource resolve failed; skipping");
                        return Vec::new();
                    }
                };
                let role_map: HashMap<String, String> = resource
                    .app_roles
                    .iter()
                    .map(|r| (r.id.clone(), r.value.clone()))
                    .collect();
                let resource_display_name = resource.display_name.clone();
                let assignments = match client.list_app_role_assigned_to(&resource.id).await {
                    Ok(a) => a,
                    Err(err) => {
                        tracing::warn!(?err, resource = %resource_app_id, "app-permission scan: appRoleAssignedTo failed; skipping");
                        return Vec::new();
                    }
                };
                assignments
                    .into_iter()
                    .map(|a| {
                        let permission = role_map
                            .get(&a.app_role_id)
                            .cloned()
                            .unwrap_or_else(|| a.app_role_id.clone());
                        let risk = permission_risk(&permission).to_string();
                        let pid = a.principal_id;
                        let name = a.principal_display_name.unwrap_or_else(|| pid.clone());
                        AppPermissionGrantDto {
                            client_sp_id: pid,
                            client_display_name: name,
                            permission,
                            resource_display_name: resource_display_name.clone(),
                            risk,
                        }
                    })
                    .collect::<Vec<_>>()
            }
        },
    ))
    .await;

    let mut rows: Vec<AppPermissionGrantDto> = per_resource.into_iter().flatten().collect();
    rows.sort_by(|a, b| {
        (risk_rank(&a.risk), a.client_display_name.to_lowercase())
            .cmp(&(risk_rank(&b.risk), b.client_display_name.to_lowercase()))
    });
    Ok(rows)
}

/// Writes the application-permission grant list as CSV via the OS save dialog.
#[tauri::command]
pub async fn save_app_permission_grants_to_file(
    app_handle: AppHandle,
    rows: Vec<AppPermissionGrantDto>,
    format: String,
) -> Result<Option<String>, UiError> {
    if format != "csv" {
        return Err(UiError::validation(
            "unsupported_format",
            format!("unsupported export format: {format}"),
        ));
    }
    let content = app_permissions_to_csv(&rows);
    let default_name = format!(
        "app-permissions-{}.csv",
        chrono::Utc::now().format("%Y%m%dT%H%M%S")
    );
    super::export::write_via_dialog(app_handle, "CSV", "csv", default_name, content).await
}

fn app_permissions_to_csv(rows: &[AppPermissionGrantDto]) -> String {
    let mut out = String::new();
    out.push_str("Application,Permission,Resource,Risk\n");
    for r in rows {
        let row = [
            csv_field(&r.client_display_name),
            csv_field(&r.permission),
            csv_field(&r.resource_display_name),
            csv_field(&r.risk),
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

    fn row(client: &str, risky: &[&str]) -> OAuth2GrantDto {
        OAuth2GrantDto {
            grant_id: Some("g1".into()),
            client_sp_id: "sp1".into(),
            client_display_name: client.into(),
            client_app_id: Some("app1".into()),
            resource_display_name: "Microsoft Graph".into(),
            consent_type: "AllPrincipals".into(),
            scopes: vec!["User.Read".into()],
            risky_scopes: risky.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn csv_has_header_and_row_per_grant() {
        let csv = grants_to_csv(&[row("App A", &["Mail.Read"]), row("App B", &[])]);
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[0].starts_with("Client,ClientAppId,Resource"));
        assert_eq!(lines.len(), 3);
        assert!(lines[1].starts_with("App A,"));
    }

    #[test]
    fn csv_neutralizes_formula_injection_in_client_name() {
        let csv = grants_to_csv(&[row("=cmd|'/c calc',A1", &[])]);
        assert!(csv.contains("\"'=cmd|'/c calc',A1\""));
        assert!(!csv.lines().skip(1).any(|l| l.starts_with('=')));
    }

    #[test]
    fn permission_risk_classifies_against_audit_lists() {
        assert_eq!(permission_risk("Directory.ReadWrite.All"), "high");
        assert_eq!(permission_risk("Mail.Send"), "high");
        assert_eq!(permission_risk("User.Read.All"), "medium");
        assert_eq!(permission_risk("Calendar.ReadWrite"), "medium");
        // Anything not on either list is low (including an unresolved role id).
        assert_eq!(permission_risk("User.Read"), "low");
        assert_eq!(
            permission_risk("00000000-0000-0000-0000-000000000000"),
            "low"
        );
    }

    #[test]
    fn risk_rank_orders_high_before_medium_before_low() {
        assert!(risk_rank("high") < risk_rank("medium"));
        assert!(risk_rank("medium") < risk_rank("low"));
        // Unknown labels sort last, alongside low.
        assert_eq!(risk_rank("unknown"), risk_rank("low"));
    }
}
