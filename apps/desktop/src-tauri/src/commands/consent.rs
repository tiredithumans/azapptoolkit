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
//! reuses the cached per-tenant SP index for name resolution. The consent
//! posture pair (F274) follows the same always-fresh stance: both surfaces read
//! it once at mount, never in a fan-out.

use std::cmp::Reverse;
use std::collections::HashMap;

use tauri::{AppHandle, State};

use azapptoolkit_core::audit::{
    HIGH_RISK_APP_PERMISSIONS, MEDIUM_RISK_APP_PERMISSIONS, is_risky_delegated_scope,
};
use azapptoolkit_core::models::AdminConsentRequestPolicy;
use azapptoolkit_core::scoping::{
    MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID, OFFICE365_SHAREPOINT_ONLINE_APP_ID,
};

use crate::commands::applications::sp_index_cached;
use crate::commands::export::csv_field;
use crate::dto::UiError;
use crate::dto::consent::{AppPermissionGrantDto, OAuth2GrantDto, TenantConsentPostureDto};
use crate::state::AppState;

/// High-value first-party resource APIs scanned for application-permission
/// grants. Microsoft Graph dominates, but Exchange Online and SharePoint also
/// expose powerful app-only permissions.
const SCANNED_RESOURCE_APP_IDS: &[&str] = &[
    MICROSOFT_GRAPH_APP_ID,
    OFFICE365_EXCHANGE_ONLINE_APP_ID,
    OFFICE365_SHAREPOINT_ONLINE_APP_ID,
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
    // The SP index below can answer from cache; `graph_for` only builds token
    // adapters, so it is not a session proof.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    let client = state.graph_for(&tenant_id);

    // Reuse the shared per-tenant SP index for name resolution (same cache the
    // App Registrations / Enterprise Apps lists use). The grant read is
    // independent of it — the index only resolves ids to names AFTER both land —
    // so on a cold tenant these two full page-walks overlap instead of running
    // back to back.
    let (sps, grants) = futures::future::try_join(
        sp_index_cached(&state, &client, &tenant_id),
        client.list_all_oauth2_grants(),
    )
    .await?;
    let by_id: HashMap<&str, (&str, &str)> = sps
        .iter()
        .map(|sp| {
            (
                sp.id.as_str(),
                (sp.display_name.as_str(), sp.app_id.as_str()),
            )
        })
        .collect();

    let mut rows: Vec<OAuth2GrantDto> = grants
        .into_iter()
        .map(|g| {
            let (client_display_name, client_app_id) = match by_id.get(g.client_id.as_str()) {
                Some((name, app_id)) => ((*name).to_string(), Some((*app_id).to_string())),
                None => (format!("(unknown SP {})", g.client_id), None),
            };
            let resource_display_name = by_id
                .get(g.resource_id.as_str())
                .map(|(name, _)| (*name).to_string())
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
    super::export::save_csv_via_dialog(app_handle, "oauth2-grants", &format, || {
        grants_to_csv(&rows)
    })
    .await
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
                let assignments = match client.list_app_role_assigned_to_cached(&resource.id).await {
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
    super::export::save_csv_via_dialog(app_handle, "app-permissions", &format, || {
        app_permissions_to_csv(&rows)
    })
    .await
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

/// Reads the tenant consent-setting posture (F274): the `authorizationPolicy`
/// + `adminConsentRequestPolicy` pair that *produces* the delegated grants the
/// audit above inventories. Both reads ride the `Policy.Read.All` token.
///
/// Best-effort by contract: this always answers `Ok`, because the posture is
/// mount-time context for the Home posture card and the grants header, not
/// audit data — a failed pair must render nothing, never a degraded run or an
/// error toast. `default()` is the all-unknown state (no session, either read
/// failed). No session proof failure even reaches the reads.
#[tauri::command]
pub async fn get_tenant_consent_posture(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<TenantConsentPostureDto, UiError> {
    Ok(read_consent_posture(&state, &tenant_id).await)
}

async fn read_consent_posture(state: &AppState, tenant_id: &str) -> TenantConsentPostureDto {
    // Without a live session both scoped reads fail at token acquisition
    // anyway; proving first skips the adapter build and the doomed round
    // trips. This is not the cache-only proof duty (nothing here is cached) —
    // it is the "never attempt a doomed read" shortcut.
    if crate::commands::session::prove_tenant_session(state, tenant_id).is_err() {
        tracing::info!(tenant = %tenant_id, "consent posture: no live session; unknown");
        return TenantConsentPostureDto::default();
    }
    let client = state.graph_for(tenant_id);
    let (authz, acw) = tokio::join!(
        client.get_authorization_policy(),
        client.get_admin_consent_request_policy()
    );
    // All-or-nothing: a partial policy picture is deliberately no picture
    // (whole-DTO contract in `dto::consent`).
    match (authz, acw) {
        (Ok(authz), Ok(acw)) => consent_posture_from(&authz, acw),
        (authz, acw) => {
            tracing::info!(?authz, ?acw, tenant = %tenant_id, "consent posture: policy pair incomplete; unknown");
            TenantConsentPostureDto::default()
        }
    }
}

/// Normalises the raw policy payloads into the DTO. Never flags on unknown:
/// `allowUserConsentForRiskyApps` arrives `null` on real tenants (the docs say
/// default-false, the example response says `null`), and a
/// `permissionGrantPoliciesAssigned` array with anything non-string in it is
/// treated as unreadable rather than half-parsed.
fn consent_posture_from(
    authz: &serde_json::Value,
    acw: Option<AdminConsentRequestPolicy>,
) -> TenantConsentPostureDto {
    let risky = authz
        .get("allowUserConsentForRiskyApps")
        .and_then(serde_json::Value::as_bool);
    let policies = authz
        .get("defaultUserRolePermissions")
        .and_then(|d| d.get("permissionGrantPoliciesAssigned"))
        .and_then(serde_json::Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .map(|v| v.as_str().map(str::to_string))
                .collect::<Option<Vec<String>>>()
        });
    TenantConsentPostureDto {
        available: true,
        risky_app_user_consent: risky,
        default_user_role_consent_policies: policies,
        // An absent policy object really is "not enabled": the workflow needs
        // the object created (same reading as an absent default
        // app-management policy).
        admin_consent_workflow_enabled: Some(acw.is_some_and(|p| p.is_enabled)),
    }
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
        assert_eq!(permission_risk("Calendars.ReadWrite"), "medium");
        // The singular form is not a Graph permission and must NOT classify.
        assert_eq!(permission_risk("Calendar.ReadWrite"), "low");
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

    fn posture_from(authz: serde_json::Value, acw: Option<bool>) -> TenantConsentPostureDto {
        consent_posture_from(
            &authz,
            acw.map(|e| AdminConsentRequestPolicy { is_enabled: e }),
        )
    }

    #[test]
    fn posture_flags_user_self_consent_only_from_a_non_empty_policy_list() {
        // The Learn example response ships a legacy policy id in the array:
        // users CAN self-consent, and that is the warn case.
        let p = posture_from(
            serde_json::json!({"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned":
                ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}}),
            None,
        );
        assert!(p.available);
        assert_eq!(
            p.default_user_role_consent_policies.as_deref(),
            Some(&["ManagePermissionGrantsForSelf.microsoft-user-default-legacy".to_string()][..])
        );
        // An empty array is decidable the other way: confirmed NO self-consent.
        let p = posture_from(
            serde_json::json!({"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": []}}),
            None,
        );
        assert_eq!(
            p.default_user_role_consent_policies.as_deref(),
            Some(&[][..])
        );
        // Absent or malformed is UNKNOWN — never rendered as either verdict.
        let p = posture_from(serde_json::json!({"id": "authorizationPolicy"}), None);
        assert_eq!(p.default_user_role_consent_policies, None);
        let p = posture_from(
            serde_json::json!({"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": null}}),
            None,
        );
        assert_eq!(p.default_user_role_consent_policies, None);
        // A non-string member makes the whole array unreadable, not half-parsed.
        let p = posture_from(
            serde_json::json!({"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned":
                ["ok.policy", {"id": "weird"}]}}),
            None,
        );
        assert_eq!(p.default_user_role_consent_policies, None);
    }

    #[test]
    fn posture_reads_risky_app_consent_as_tri_state() {
        // Real tenants emit `null` here even though docs claim a false default;
        // only Some(true) is actionable, and Some(false) must not render as
        // unknown (it IS the restricted answer).
        let p = posture_from(
            serde_json::json!({"allowUserConsentForRiskyApps": null}),
            None,
        );
        assert_eq!(p.risky_app_user_consent, None);
        let p = posture_from(
            serde_json::json!({"allowUserConsentForRiskyApps": false}),
            None,
        );
        assert_eq!(p.risky_app_user_consent, Some(false));
        let p = posture_from(
            serde_json::json!({"allowUserConsentForRiskyApps": true}),
            None,
        );
        assert_eq!(p.risky_app_user_consent, Some(true));
    }

    #[test]
    fn absent_admin_consent_policy_is_decidedly_disabled() {
        // `None` (404) = the workflow object was never created = not enabled —
        // decidable, unlike the unknowns above.
        let p = posture_from(serde_json::json!({}), None);
        assert_eq!(p.admin_consent_workflow_enabled, Some(false));
        let p = posture_from(serde_json::json!({}), Some(false));
        assert_eq!(p.admin_consent_workflow_enabled, Some(false));
        let p = posture_from(serde_json::json!({}), Some(true));
        assert_eq!(p.admin_consent_workflow_enabled, Some(true));
        // A fully-empty authz payload still yields `available`: the pair was
        // read; every field just stayed unknown.
        assert!(p.available);
    }
}
