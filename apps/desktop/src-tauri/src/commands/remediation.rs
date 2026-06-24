//! Audit remediation commands — one-click fixes for findings whose remedy maps
//! to a safe, existing mutation. Each re-resolves the live state before acting,
//! so a stale audit snapshot can never drive a destructive change against the
//! wrong (e.g. since-rotated) credential.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use tauri::State;

use azapptoolkit_core::audit::{is_expired, subsuming_app_permissions};
use azapptoolkit_core::models::{Application, RequiredResourceAccess};

use crate::commands::applications::invalidate_app_credentials;
use crate::commands::exchange::grant_exchange_mailbox_access;
use crate::commands::permissions::remove_declared_access;
use crate::commands::sharepoint::convert_site_access_to_selected;
use crate::dto::UiError;
use crate::dto::exchange::ExchangeAccessResult;
use crate::dto::remediation::{RedundantPermissionsOutcome, RemediationOutcome};
use crate::dto::sharepoint::SiteScopeResult;
use crate::state::AppState;

/// keyIds of the app's expired secrets. Uses the shared whole-day rule
/// (`azapptoolkit_core::audit::is_expired`) so the command removes *exactly*
/// the set the audit flagged and previewed, never more.
fn expired_secret_key_ids(app: &Application, now: DateTime<Utc>) -> Vec<String> {
    app.password_credentials
        .iter()
        .filter(|c| is_expired(c.end_date_time, now))
        .map(|c| c.key_id.clone())
        .collect()
}

/// Distinct keyIds of the app's expired certificates. A certificate can appear
/// as paired Sign/Verify entries sharing one keyId; `remove_key_credential`
/// drops every entry with that keyId, so we dedup to avoid a redundant second
/// PATCH (and an inflated removal count).
fn expired_cert_key_ids(app: &Application, now: DateTime<Utc>) -> Vec<String> {
    let mut ids: Vec<String> = app
        .key_credentials
        .iter()
        .filter(|c| is_expired(c.end_date_time, now))
        .map(|c| c.key_id.clone())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Removes every *currently-expired* secret and certificate from an app
/// registration. The expired set is recomputed from a fresh fetch (end date in
/// the past) — never the audit snapshot — so a credential rotated since the
/// audit ran is left untouched. Safe by construction: an expired credential
/// can't authenticate, so removing it can't break a working sign-in.
#[tauri::command]
pub async fn remediate_remove_expired_credentials(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<RemediationOutcome, UiError> {
    let client = state.graph_for(&tenant_id);
    // Fail before any mutation if we can't read the live app — nothing changed,
    // so no cache bust is needed on this path.
    let app = client.get_application(&object_id).await?;
    let now = Utc::now();

    let expired_secrets = expired_secret_key_ids(&app, now);
    let expired_certs = expired_cert_key_ids(&app, now);

    let mut outcome = RemediationOutcome::default();
    let mut error: Option<UiError> = None;

    for key_id in &expired_secrets {
        if let Err(e) = client.remove_password(&object_id, key_id).await {
            error = Some(e.into());
            break;
        }
        outcome.removed_secrets += 1;
    }
    if error.is_none() {
        for key_id in &expired_certs {
            if let Err(e) = client.remove_key_credential(&object_id, key_id).await {
                error = Some(e.into());
                break;
            }
            outcome.removed_certificates += 1;
        }
    }

    // Any successful removal mutated this app's credentials, so its detail, the
    // apps list row, and the audit are stale and must refetch — but a credential
    // change can't touch the SP/name indexes, so use the tiered invalidation
    // (keeps them, avoiding a full-tenant re-scan). Deliberate exception to
    // "invalidate only on Ok": a *partial* success here is still a real write,
    // so we bust caches even when a later removal failed (but never when nothing
    // was removed).
    if outcome.total() > 0 {
        invalidate_app_credentials(&state.cache, &tenant_id, &object_id);
    }
    if let Some(e) = error {
        return Err(e);
    }
    Ok(outcome)
}

/// Confines an app's org-wide mailbox permissions (audit Rule 11) to specific
/// groups via Exchange RBAC for Applications. Delegates to the shared scoping
/// core (`grant_exchange_mailbox_access`), which re-resolves the live manifest,
/// assigns the scoped Exchange roles, and strips the org-wide Entra grants
/// **only for permissions whose scoped replacement landed** (grant-before-strip,
/// so the app is never left with no mailbox access) — and busts caches on Ok.
/// `permissions` is the specific mail values to scope (the audit's finding set);
/// `groups` are the admin-chosen mailbox groups. Degrades to a `UiError` (e.g.
/// not an Exchange admin) which the modal surfaces.
#[tauri::command]
pub async fn remediate_scope_mailbox_access(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    permissions: Vec<String>,
    groups: Vec<String>,
) -> Result<ExchangeAccessResult, UiError> {
    grant_exchange_mailbox_access(state, tenant_id, object_id, Some(permissions), groups, true)
        .await
}

/// Converts an app's org-wide `Sites.*` access (audit Rule 12) to the
/// `Sites.Selected` model on admin-supplied site URLs. Resolves the service
/// principal from the live app, then delegates to the shared
/// `convert_site_access_to_selected` core, which grants per-site access before
/// stripping the broad grant (only if ≥1 site landed) and pre-acquires the
/// SharePoint token so a missing-consent rejection surfaces as `consent_required`
/// for the "Grant consent & retry" affordance.
#[tauri::command]
pub async fn remediate_scope_sharepoint_access(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    site_urls: Vec<String>,
    role: String,
) -> Result<SiteScopeResult, UiError> {
    let graph = state.graph_for(&tenant_id);
    let app = graph.get_application(&object_id).await?;
    let sp = graph
        .get_service_principal_by_app_id(&app.app_id)
        .await?
        .ok_or_else(|| {
            UiError::not_found("sp", "no service principal exists for this application")
        })?;
    convert_site_access_to_selected(
        state,
        tenant_id,
        sp.id,
        app.app_id,
        app.display_name,
        site_urls,
        role,
        true,
    )
    .await
}

/// One planned removal for the redundant-permissions fix: a narrower declared
/// permission whose coverage by a broader sibling on the *same resource* was
/// re-verified against live state. `assignment_id` is the narrower permission's
/// live appRoleAssignment, when granted.
struct RedundantRemoval {
    resource_app_id: String,
    value: String,
    permission_id: String,
    assignment_id: Option<String>,
}

/// Plans which declared permissions the redundant-permissions fix may remove.
/// Pure so the safety rules are unit-testable without a Graph client.
///
/// Inputs are keyed by the manifest's `resource_app_id`: `role_indexes` maps
/// each resolvable resource's appRole id → permission value, `granted` maps the
/// app SP's live appRoleAssignments on that resource (appRole id → assignment
/// id). A resource missing from `role_indexes` is skipped — its values can't be
/// classified.
///
/// Safety rules (stricter than audit Rule 18, which flattens across resources):
/// - The broader covering permission must be declared on the **same** resource
///   (`Mail.Read` on Exchange Online is not covered by Graph's `Mail.ReadWrite`).
/// - A **granted** narrower permission is removable only while a covering
///   broader permission is also granted — a declared-but-ungranted broader
///   doesn't authorize anything, so removing the narrower grant would break the
///   app. Such values land in `skipped` (second return).
/// - An **ungranted** narrower declaration is removable whenever the broader is
///   declared: declarations authorize nothing, so nothing live can break.
fn plan_redundant_removals(
    required: &[RequiredResourceAccess],
    role_indexes: &HashMap<String, HashMap<String, String>>,
    granted: &HashMap<String, HashMap<String, String>>,
) -> (Vec<RedundantRemoval>, Vec<String>) {
    let empty = HashMap::new();
    let mut removals = Vec::new();
    let mut skipped = Vec::new();
    for resource in required {
        let Some(index) = role_indexes.get(&resource.resource_app_id) else {
            continue;
        };
        let grants = granted.get(&resource.resource_app_id).unwrap_or(&empty);
        let declared: Vec<(&str, &str)> = resource
            .resource_access
            .iter()
            .filter(|a| a.r#type == "Role")
            .filter_map(|a| index.get(&a.id).map(|v| (a.id.as_str(), v.as_str())))
            .collect();
        let value_to_id: HashMap<&str, &str> = declared.iter().map(|(id, v)| (*v, *id)).collect();
        for (id, value) in &declared {
            let broaders: Vec<&str> = subsuming_app_permissions(value)
                .iter()
                .copied()
                .filter(|b| value_to_id.contains_key(*b))
                .collect();
            if broaders.is_empty() {
                continue;
            }
            let assignment_id = grants.get(*id).cloned();
            if assignment_id.is_some()
                && !broaders.iter().any(|b| grants.contains_key(value_to_id[b]))
            {
                skipped.push((*value).to_string());
                continue;
            }
            removals.push(RedundantRemoval {
                resource_app_id: resource.resource_app_id.clone(),
                value: (*value).to_string(),
                permission_id: (*id).to_string(),
                assignment_id,
            });
        }
    }
    (removals, skipped)
}

/// Removes an app's *redundant* application permissions (audit Rule 18) —
/// narrower permissions whose access a broader permission on the same resource
/// already fully covers (e.g. `Mail.Read` alongside `Mail.ReadWrite`). The
/// removable set is re-planned from a fresh manifest + live appRoleAssignments
/// (see [`plan_redundant_removals`]) — never the audit snapshot — so a grant
/// revoked or scoped since the audit ran flips the affected value to `skipped`
/// instead of being removed. Safe by construction: a narrower grant is revoked
/// only while a covering broader grant is live, and Graph authorizes app-only
/// calls by the union of granted roles, so every call the narrower permission
/// authorized still succeeds.
///
/// Per narrower permission: revoke the appRoleAssignment (when granted), then
/// drop the declaration from `requiredResourceAccess` in one trailing patch.
/// Grant-revocation errors stop further revocations, but declarations whose
/// grants were already revoked are still patched out — a revoked grant with a
/// lingering declaration is the inconsistent state to avoid. Idempotent: a
/// re-run finds nothing left to remove.
#[tauri::command]
pub async fn remediate_remove_redundant_permissions(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<RedundantPermissionsOutcome, UiError> {
    let client = state.graph_for(&tenant_id);
    // Fail before any mutation if the live app can't be read.
    let app = client.get_application(&object_id).await?;

    // Resolve each declared resource's appRole id → value index (+ the resource
    // SP object id, which is what appRoleAssignments key their resource by). A
    // resource that can't be resolved is skipped by the planner.
    let mut role_indexes: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut resource_sp_ids: HashMap<String, String> = HashMap::new();
    for resource in &app.required_resource_access {
        if role_indexes.contains_key(&resource.resource_app_id) {
            continue;
        }
        if let Ok(Some(sp)) = client.resolve_resource_sp(&resource.resource_app_id).await {
            role_indexes.insert(
                resource.resource_app_id.clone(),
                sp.app_roles
                    .iter()
                    .map(|r| (r.id.clone(), r.value.clone()))
                    .collect(),
            );
            resource_sp_ids.insert(resource.resource_app_id.clone(), sp.id);
        }
    }

    // The app SP's live grants. Must not be swallowed: with the granted set
    // unknown, the planner would misread a granted narrower permission as a
    // declaration-only one. No SP at all ⇒ genuinely nothing granted.
    let sp = client.get_service_principal_by_app_id(&app.app_id).await?;
    let mut granted: HashMap<String, HashMap<String, String>> = HashMap::new();
    let sp_id = match sp {
        Some(sp) => {
            let assignments = client.list_app_role_assignments(&sp.id).await?;
            for (resource_app_id, resource_sp_id) in &resource_sp_ids {
                granted.insert(
                    resource_app_id.clone(),
                    assignments
                        .iter()
                        .filter(|a| a.resource_id == *resource_sp_id)
                        .map(|a| (a.app_role_id.clone(), a.id.clone()))
                        .collect(),
                );
            }
            Some(sp.id)
        }
        None => None,
    };

    let (plan, skipped) =
        plan_redundant_removals(&app.required_resource_access, &role_indexes, &granted);

    let mut outcome = RedundantPermissionsOutcome {
        removed: Vec::new(),
        skipped,
    };
    let mut error: Option<UiError> = None;
    let mut declarations_to_drop: Vec<&RedundantRemoval> = Vec::new();
    let mut grants_revoked = false;

    for removal in &plan {
        match (&removal.assignment_id, &sp_id) {
            (Some(assignment_id), Some(sp_id)) => {
                match client
                    .remove_app_role_assignment(sp_id, assignment_id)
                    .await
                {
                    Ok(()) => {
                        grants_revoked = true;
                        declarations_to_drop.push(removal);
                    }
                    Err(e) => {
                        error = Some(e.into());
                        break;
                    }
                }
            }
            _ => declarations_to_drop.push(removal),
        }
    }

    // One trailing manifest patch for every narrower permission whose grant is
    // gone (just revoked, or never granted).
    let mut next = app.required_resource_access.clone();
    let mut any_declared_removed = false;
    for removal in &declarations_to_drop {
        any_declared_removed |= remove_declared_access(
            &mut next,
            &removal.resource_app_id,
            &removal.permission_id,
            Some("Role"),
        );
    }
    let mut manifest_patched = false;
    if any_declared_removed {
        let patch = azapptoolkit_graph::client::AppPatch {
            required_resource_access: Some(next),
            ..Default::default()
        };
        match client.update_application(&object_id, &patch).await {
            Ok(_) => {
                manifest_patched = true;
                outcome.removed = declarations_to_drop
                    .iter()
                    .map(|r| r.value.clone())
                    .collect();
            }
            Err(e) => {
                if error.is_none() {
                    error = Some(e.into());
                }
            }
        }
    }

    // Same deliberate exception as remove-expired-credentials: a partial success
    // still mutated live state, so bust caches even on the error path (but never
    // when nothing changed).
    if grants_revoked || manifest_patched {
        super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    }
    if let Some(e) = error {
        return Err(e);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::models::{KeyCredential, PasswordCredential};
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn secret(key_id: &str, end: Option<DateTime<Utc>>) -> PasswordCredential {
        PasswordCredential {
            key_id: key_id.into(),
            end_date_time: end,
            ..Default::default()
        }
    }

    fn cert(key_id: &str, end: Option<DateTime<Utc>>) -> KeyCredential {
        KeyCredential {
            key_id: key_id.into(),
            end_date_time: end,
            ..Default::default()
        }
    }

    #[test]
    fn picks_only_expired_secrets() {
        let app = Application {
            password_credentials: vec![
                secret("expired", Some(now() - Duration::days(1))),
                secret("active", Some(now() + Duration::days(30))),
                secret("no-expiry", None), // never expires / unknown → left alone
            ],
            ..Default::default()
        };
        assert_eq!(expired_secret_key_ids(&app, now()), vec!["expired"]);
    }

    #[test]
    fn sub_day_lapsed_credential_matches_audit_and_is_left_alone() {
        // Lapsed 12h ago: num_days() truncates to 0, so the audit calls this
        // "expiring soon" (no Fix offered). The command must agree and NOT
        // remove it — it only crosses into "expired" after a full day.
        let app = Application {
            password_credentials: vec![
                secret("just-lapsed", Some(now() - Duration::hours(12))),
                secret("day-old", Some(now() - Duration::days(1))),
            ],
            ..Default::default()
        };
        assert_eq!(expired_secret_key_ids(&app, now()), vec!["day-old"]);
    }

    #[test]
    fn dedups_paired_certificate_entries() {
        // A cert with Sign + Verify entries shares one keyId; expired once → one id.
        let app = Application {
            key_credentials: vec![
                cert("cert-a", Some(now() - Duration::days(5))),
                cert("cert-a", Some(now() - Duration::days(5))),
                cert("cert-b", Some(now() + Duration::days(5))), // still valid
            ],
            ..Default::default()
        };
        assert_eq!(expired_cert_key_ids(&app, now()), vec!["cert-a"]);
    }

    // ---------------- redundant-permissions planner ----------------

    use azapptoolkit_core::models::ResourceAccess;

    const GRAPH: &str = "00000003-0000-0000-c000-000000000000";

    /// Manifest with Role entries on one resource; ids derive from values.
    fn declared(resource: &str, values: &[&str]) -> RequiredResourceAccess {
        RequiredResourceAccess {
            resource_app_id: resource.into(),
            resource_access: values
                .iter()
                .map(|v| ResourceAccess {
                    id: format!("id-{v}"),
                    r#type: "Role".into(),
                })
                .collect(),
        }
    }

    /// Role index for `resource` matching `declared`'s id scheme.
    fn index(resource: &str, values: &[&str]) -> HashMap<String, HashMap<String, String>> {
        let mut m = HashMap::new();
        m.insert(
            resource.to_string(),
            values
                .iter()
                .map(|v| (format!("id-{v}"), v.to_string()))
                .collect(),
        );
        m
    }

    /// Live grants on `resource` for the given values (assignment id = `a-{value}`).
    fn grants(resource: &str, values: &[&str]) -> HashMap<String, HashMap<String, String>> {
        let mut m = HashMap::new();
        m.insert(
            resource.to_string(),
            values
                .iter()
                .map(|v| (format!("id-{v}"), format!("a-{v}")))
                .collect(),
        );
        m
    }

    #[test]
    fn plan_removes_granted_narrower_when_broader_grant_is_live() {
        let required = vec![declared(GRAPH, &["Mail.ReadWrite", "Mail.Read"])];
        let idx = index(GRAPH, &["Mail.ReadWrite", "Mail.Read"]);
        let granted = grants(GRAPH, &["Mail.ReadWrite", "Mail.Read"]);
        let (plan, skipped) = plan_redundant_removals(&required, &idx, &granted);
        assert!(skipped.is_empty());
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].value, "Mail.Read");
        assert_eq!(plan[0].permission_id, "id-Mail.Read");
        assert_eq!(plan[0].assignment_id.as_deref(), Some("a-Mail.Read"));
    }

    #[test]
    fn plan_skips_granted_narrower_when_broader_is_declared_only() {
        // The broader permission lost its grant (e.g. scoped via Exchange RBAC,
        // which strips the org-wide Entra grant): the narrower grant is now
        // load-bearing and must be kept.
        let required = vec![declared(GRAPH, &["Mail.ReadWrite", "Mail.Read"])];
        let idx = index(GRAPH, &["Mail.ReadWrite", "Mail.Read"]);
        let granted = grants(GRAPH, &["Mail.Read"]);
        let (plan, skipped) = plan_redundant_removals(&required, &idx, &granted);
        assert!(plan.is_empty());
        assert_eq!(skipped, vec!["Mail.Read".to_string()]);
    }

    #[test]
    fn plan_removes_ungranted_narrower_declaration() {
        // Neither permission granted: a declaration authorizes nothing, so the
        // redundant narrower one is removable with no assignment to revoke.
        let required = vec![declared(GRAPH, &["Mail.ReadWrite", "Mail.Read"])];
        let idx = index(GRAPH, &["Mail.ReadWrite", "Mail.Read"]);
        let (plan, skipped) = plan_redundant_removals(&required, &idx, &HashMap::new());
        assert!(skipped.is_empty());
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].value, "Mail.Read");
        assert!(plan[0].assignment_id.is_none());
    }

    #[test]
    fn plan_requires_broader_on_the_same_resource() {
        // Graph's Mail.ReadWrite does not cover Exchange Online's Mail.Read —
        // subsumption never pairs across resources.
        let exo = "00000002-0000-0ff1-ce00-000000000000";
        let required = vec![
            declared(GRAPH, &["Mail.ReadWrite"]),
            declared(exo, &["Mail.Read"]),
        ];
        let mut idx = index(GRAPH, &["Mail.ReadWrite"]);
        idx.extend(index(exo, &["Mail.Read"]));
        let (plan, skipped) = plan_redundant_removals(&required, &idx, &HashMap::new());
        assert!(
            plan.is_empty(),
            "cross-resource pair must not plan a removal"
        );
        assert!(skipped.is_empty());
    }

    #[test]
    fn plan_skips_unresolvable_resources_and_non_subsumed_values() {
        // No role index for the resource → values can't be classified → skip.
        let required = vec![declared(GRAPH, &["Mail.ReadWrite", "Mail.Read"])];
        let (plan, skipped) = plan_redundant_removals(&required, &HashMap::new(), &HashMap::new());
        assert!(plan.is_empty());
        assert!(skipped.is_empty());

        // Sites.Selected is never planned for removal, even under FullControl.
        let required = vec![declared(
            GRAPH,
            &["Sites.FullControl.All", "Sites.Selected"],
        )];
        let idx = index(GRAPH, &["Sites.FullControl.All", "Sites.Selected"]);
        let granted = grants(GRAPH, &["Sites.FullControl.All", "Sites.Selected"]);
        let (plan, _) = plan_redundant_removals(&required, &idx, &granted);
        assert!(plan.is_empty());
    }
}
