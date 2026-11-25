//! The network lock (B2): create, read, turn on and remove the app's one
//! toolkit-owned Conditional Access policy.
//!
//! Every command re-resolves live state: the app (its sign-in audience decides
//! eligibility), its service principal, and the tenant's policies. Turn on and
//! remove act only on [`toolkit_lock_for`]'s policy — our name prefix, exactly
//! this service principal, the exact lock shape — so a foreign or
//! portal-edited policy is never changed. A lock is always created
//! report-only; new named locations are created untrusted.

use std::collections::HashSet;

use jiff::{SignedDuration, Timestamp};
use tauri::State;

use azapptoolkit_core::conditional_access::{
    CidrError, LockIneligible, NetworkLock, lock_display_name, lock_ineligibility_for_app,
    lock_policy_body, network_lock_for, parse_cidr, toolkit_lock_for,
};
use azapptoolkit_core::models::{ConditionalAccessPolicy, NamedLocation, SignIn};
use azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;
use azapptoolkit_graph::{GraphClient, GraphError};

use crate::commands::applications::invalidate_app_detail_state;
use crate::commands::graph_err::forbidden_remediation;
use crate::commands::guid::require_app_id;
use crate::commands::session::prove_tenant_session;
use crate::dto::UiError;
use crate::dto::conditional_access::{
    CreatedLock, NamedLocationDto, NetworkLockStatus, NewLocationArgs, ReportOnlyReadout,
    ToolkitLockDto,
};
use crate::state::{AppState, ConsentFeature};

/// How far back the report-only readout looks.
pub(crate) const READOUT_WINDOW_DAYS: u32 = 7;

/// The app's live state the lock depends on.
struct LiveApp {
    display_name: String,
    sp_id: Option<String>,
    ineligible: Option<LockIneligible>,
}

async fn live_app(client: &GraphClient, app_id: &str) -> Result<LiveApp, UiError> {
    let app = client
        .find_application_by_app_id(app_id)
        .await
        .map_err(UiError::from)?
        .ok_or_else(|| UiError::not_found("application", "No app registration has this app id"))?;
    let sp = client
        .get_service_principal_by_app_id(app_id)
        .await
        .map_err(UiError::from)?;
    let ineligible = lock_ineligibility_for_app(app.sign_in_audience.as_deref(), sp.is_some());
    Ok(LiveApp {
        display_name: app.display_name,
        sp_id: sp.map(|s| s.id),
        ineligible,
    })
}

async fn live_policies(client: &GraphClient) -> Result<Vec<ConditionalAccessPolicy>, UiError> {
    client
        .list_conditional_access_policies()
        .await
        .map_err(map_lock_write_err)
}

fn location_dto(l: &NamedLocation) -> Option<NamedLocationDto> {
    Some(NamedLocationDto {
        id: l.id.clone()?,
        display_name: l.display_name.clone().unwrap_or_default(),
        is_trusted: l.is_trusted.unwrap_or(false),
        range_count: u32::try_from(l.ip_ranges.len()).unwrap_or(u32::MAX),
    })
}

/// What a report-only lock would have blocked: sign-ins where this policy's
/// applied result is `reportOnlyFailure`, plus up to five distinct addresses.
pub(crate) fn readout_from(sign_ins: &[SignIn], policy_id: &str) -> ReportOnlyReadout {
    let mut would_block = 0u32;
    let mut ips: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for s in sign_ins {
        let hit = s.applied_conditional_access_policies.iter().any(|p| {
            p.id.as_deref() == Some(policy_id) && p.result.as_deref() == Some("reportOnlyFailure")
        });
        if !hit {
            continue;
        }
        would_block = would_block.saturating_add(1);
        if let Some(ip) = &s.ip_address
            && ips.len() < 5
            && seen.insert(ip.clone())
        {
            ips.push(ip.clone());
        }
    }
    ReportOnlyReadout {
        would_block,
        sample_ips: ips,
        window_days: READOUT_WINDOW_DAYS,
    }
}

/// Maps a lock read/write failure. A refusal that names workload identities
/// is the missing Workload ID Premium licence (Graph doesn't document the
/// exact error, so the body is matched on its text); any other 403 carries the
/// catalog's remediation.
pub(crate) fn map_lock_write_err(err: GraphError) -> UiError {
    let body = match &err {
        GraphError::Forbidden(b) => Some(b.as_str()),
        GraphError::Api { body, .. } => Some(body.as_str()),
        _ => None,
    };
    if body.is_some_and(|b| b.to_ascii_lowercase().contains("workload identit")) {
        return UiError::validation(
            "workload_identity_license_required",
            "Creating or changing a Conditional Access policy for an app needs a Microsoft \
             Entra Workload ID Premium licence.",
        );
    }
    let mut ui = UiError::from(err);
    if let Some(remediation) = forbidden_remediation(&ui, "conditional_access_lock") {
        ui.message = format!("{} {remediation}", ui.message);
    }
    ui
}

/// Validates a create request against the live IP named locations: at least
/// one location, every id a GUID that names a live IP location, and every new
/// CIDR valid (blank lines skipped, `/0` refused). Returns the parsed CIDRs.
pub(crate) fn validate_create(
    named_location_ids: &[String],
    new_location: Option<&NewLocationArgs>,
    live: &[NamedLocation],
) -> Result<Vec<(bool, String)>, UiError> {
    if named_location_ids.is_empty() && new_location.is_none() {
        return Err(UiError::validation(
            "no_locations",
            "Choose at least one named location, or add a new one.",
        ));
    }
    for id in named_location_ids {
        if !azapptoolkit_core::guid::is_guid(id) {
            return Err(UiError::validation(
                "invalid_location_id",
                "A named location id is not a valid id.",
            ));
        }
        if !live
            .iter()
            .any(|l| l.is_ip() && l.id.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(id)))
        {
            return Err(UiError::validation(
                "unknown_location",
                "A chosen named location no longer exists, or isn't an IP location. Reload and choose again.",
            ));
        }
    }
    let Some(new) = new_location else {
        return Ok(Vec::new());
    };
    let name = new.name.trim();
    if name.is_empty() || name.chars().count() > 256 {
        return Err(UiError::validation(
            "invalid_location_name",
            "Give the new named location a name (up to 256 characters).",
        ));
    }
    let mut cidrs = Vec::new();
    for line in new.cidrs.iter().map(|c| c.trim()).filter(|c| !c.is_empty()) {
        match parse_cidr(line) {
            Ok(parsed) => cidrs.push(parsed),
            Err(CidrError::PrefixZero) => {
                return Err(UiError::validation(
                    "invalid_cidr",
                    format!("{line} covers every address, which would make the lock meaningless."),
                ));
            }
            Err(CidrError::Malformed) => {
                return Err(UiError::validation(
                    "invalid_cidr",
                    format!("{line} isn't an IPv4 or IPv6 range like 203.0.113.0/24."),
                ));
            }
        }
    }
    if cidrs.is_empty() {
        return Err(UiError::validation(
            "invalid_cidr",
            "Add at least one IP range for the new named location.",
        ));
    }
    Ok(cidrs)
}

/// The Network lock section's state: eligibility, the toolkit's own lock (any
/// state) with its locations, every other policy's verdict, and — for a
/// report-only lock — what it would have blocked in the last week.
#[tauri::command]
pub async fn get_network_lock(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
) -> Result<NetworkLockStatus, UiError> {
    require_app_id(&app_id)?;
    prove_tenant_session(&state, &tenant_id)?;
    state
        .ensure_feature_token(&tenant_id, ConsentFeature::Policy)
        .await
        .map_err(UiError::from)?;
    let client = state.graph_for(&tenant_id);
    let app = live_app(&client, &app_id).await?;
    let (Some(sp_id), None) = (app.sp_id.as_deref(), app.ineligible) else {
        let reason = app.ineligible.unwrap_or(LockIneligible::NoServicePrincipal);
        return Ok(NetworkLockStatus {
            ineligible: Some(reason),
            toolkit_lock: None,
            other: NetworkLock::NotPossible { reason },
            other_policy_name: None,
            readout: None,
        });
    };
    let policies = live_policies(&client).await?;
    let ours = toolkit_lock_for(&policies, sp_id).cloned();
    let ours_id = ours.as_ref().and_then(|p| p.id.clone());
    let others: Vec<ConditionalAccessPolicy> = policies
        .into_iter()
        .filter(|p| p.id.is_none() || p.id != ours_id)
        .collect();
    let other = network_lock_for(&others, sp_id, MICROSOFT_GRAPH_APP_ID);
    let other_policy_name = match &other {
        NetworkLock::Enforced { policy_ids } => others
            .iter()
            .find(|p| p.id.as_ref().is_some_and(|id| policy_ids.contains(id)))
            .and_then(|p| p.display_name.clone()),
        _ => None,
    };
    let mut toolkit_lock = None;
    let mut readout = None;
    if let Some(p) = ours {
        let locations = client.list_named_locations().await.unwrap_or_default();
        let excluded = p
            .conditions
            .as_ref()
            .and_then(|c| c.locations.as_ref())
            .map(|l| l.exclude_locations.clone())
            .unwrap_or_default();
        let excluded_locations = excluded
            .iter()
            .map(|id| {
                locations
                    .iter()
                    .find(|l| l.id.as_deref() == Some(id.as_str()))
                    .and_then(location_dto)
                    .unwrap_or(NamedLocationDto {
                        id: id.clone(),
                        display_name: id.clone(),
                        is_trusted: false,
                        range_count: 0,
                    })
            })
            .collect();
        let policy_id = p.id.clone().unwrap_or_default();
        let lock_state = p.state.clone().unwrap_or_else(|| "unknown".into());
        if lock_state == "enabledForReportingButNotEnforced"
            && state
                .ensure_feature_token(&tenant_id, ConsentFeature::AuditLog)
                .await
                .is_ok()
        {
            let since =
                Timestamp::now() - SignedDuration::from_hours(24 * i64::from(READOUT_WINDOW_DAYS));
            readout = client
                .list_service_principal_sign_ins(&app_id, since)
                .await
                .ok()
                .map(|rows| readout_from(&rows, &policy_id));
        }
        toolkit_lock = Some(ToolkitLockDto {
            policy_id,
            state: lock_state,
            excluded_locations,
        });
    }
    Ok(NetworkLockStatus {
        ineligible: None,
        toolkit_lock,
        other,
        other_policy_name,
        readout,
    })
}

/// The tenant's IP named locations, for the lock picker.
#[tauri::command]
pub async fn list_named_locations(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<NamedLocationDto>, UiError> {
    prove_tenant_session(&state, &tenant_id)?;
    state
        .ensure_feature_token(&tenant_id, ConsentFeature::Policy)
        .await
        .map_err(UiError::from)?;
    let locations = state
        .graph_for(&tenant_id)
        .list_named_locations()
        .await
        .map_err(map_lock_write_err)?;
    Ok(locations
        .iter()
        .filter(|l| l.is_ip())
        .filter_map(location_dto)
        .collect())
}

/// Creates the app's lock, report-only: an optional new untrusted IP named
/// location first, then the policy excluding every chosen location.
#[tauri::command]
pub async fn create_network_lock(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    named_location_ids: Vec<String>,
    new_location: Option<NewLocationArgs>,
) -> Result<CreatedLock, UiError> {
    require_app_id(&app_id)?;
    prove_tenant_session(&state, &tenant_id)?;
    for feature in [
        ConsentFeature::Policy,
        ConsentFeature::ConditionalAccessWrite,
    ] {
        state
            .ensure_feature_token(&tenant_id, feature)
            .await
            .map_err(UiError::from)?;
    }
    let client = state.graph_for(&tenant_id);
    let app = live_app(&client, &app_id).await?;
    let sp_id = match (app.sp_id, app.ineligible) {
        (Some(sp), None) => sp,
        _ => {
            return Err(UiError::validation(
                "lock_not_possible",
                "Conditional Access can't target this app: only single-tenant app registrations \
                 with a service principal can be locked.",
            ));
        }
    };
    let policies = live_policies(&client).await?;
    if toolkit_lock_for(&policies, &sp_id).is_some() {
        return Err(UiError::validation(
            "lock_exists",
            "This app already has a network lock. Reload to see it.",
        ));
    }
    let live_locations = client
        .list_named_locations()
        .await
        .map_err(map_lock_write_err)?;
    let cidrs = validate_create(&named_location_ids, new_location.as_ref(), &live_locations)?;
    let mut excluded = named_location_ids.clone();
    let mut created_location_id = None;
    let mut created_location_name = None;
    if let Some(new) = &new_location {
        let created = client
            .create_ip_named_location(new.name.trim(), &cidrs)
            .await
            .map_err(map_lock_write_err)?;
        let id = created.id.ok_or_else(|| {
            UiError::new(
                "protocol",
                "Graph returned a named location without an id",
                false,
            )
        })?;
        excluded.push(id.clone());
        created_location_id = Some(id);
        created_location_name = Some(new.name.trim().to_string());
    }
    let body = lock_policy_body(&lock_display_name(&app.display_name), &sp_id, &excluded);
    let created = match client.create_ca_policy(&body).await {
        Ok(p) => p,
        Err(err) => {
            let mut ui = map_lock_write_err(err);
            if let Some(name) = &created_location_name {
                ui.message = format!(
                    "{} The named location \"{name}\" was created and is kept — choose it next time.",
                    ui.message
                );
                invalidate_app_detail_state(&state.cache, &tenant_id);
            }
            return Err(ui);
        }
    };
    invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(CreatedLock {
        policy_id: created.id.unwrap_or_default(),
        created_location_id,
    })
}

/// The toolkit lock's id for this app, verified live; refuses anything else.
async fn verified_toolkit_lock(
    state: &AppState,
    tenant_id: &str,
    app_id: &str,
    policy_id: &str,
) -> Result<std::sync::Arc<GraphClient>, UiError> {
    for feature in [
        ConsentFeature::Policy,
        ConsentFeature::ConditionalAccessWrite,
    ] {
        state
            .ensure_feature_token(tenant_id, feature)
            .await
            .map_err(UiError::from)?;
    }
    let client = state.graph_for(tenant_id);
    let app = live_app(&client, app_id).await?;
    let not_ours = || {
        UiError::validation(
            "not_a_toolkit_lock",
            "That policy isn't this app's toolkit network lock (it may have been changed in the \
             portal). Reload to see the current state.",
        )
    };
    let sp_id = app.sp_id.ok_or_else(not_ours)?;
    let policies = live_policies(&client).await?;
    match toolkit_lock_for(&policies, &sp_id) {
        Some(p) if p.id.as_deref() == Some(policy_id) => Ok(client),
        _ => Err(not_ours()),
    }
}

/// Turns the app's toolkit lock on (`enabled`), after verifying it live.
#[tauri::command]
pub async fn enable_network_lock(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    policy_id: String,
) -> Result<(), UiError> {
    require_app_id(&app_id)?;
    prove_tenant_session(&state, &tenant_id)?;
    let client = verified_toolkit_lock(&state, &tenant_id, &app_id, &policy_id).await?;
    client
        .set_ca_policy_state(&policy_id, "enabled")
        .await
        .map_err(map_lock_write_err)?;
    invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(())
}

/// Deletes the app's toolkit lock, after verifying it live. Named locations
/// stay (they may be shared).
#[tauri::command]
pub async fn remove_network_lock(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    policy_id: String,
) -> Result<(), UiError> {
    require_app_id(&app_id)?;
    prove_tenant_session(&state, &tenant_id)?;
    let client = verified_toolkit_lock(&state, &tenant_id, &app_id, &policy_id).await?;
    // A replayed DELETE whose first attempt committed answers 404: gone is
    // gone. An outcome Graph never reported may have landed too, so the audit
    // is swept for it while the error is still returned.
    match client.delete_ca_policy(&policy_id).await {
        Ok(()) | Err(GraphError::NotFound(_)) => {
            invalidate_app_detail_state(&state.cache, &tenant_id);
            Ok(())
        }
        Err(err) => {
            if err.may_have_committed() {
                invalidate_app_detail_state(&state.cache, &tenant_id);
            }
            Err(map_lock_write_err(err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::models::{AppliedConditionalAccessPolicy, NamedLocation, SignIn};

    fn sign_in(ip: &str, results: &[(&str, &str)]) -> SignIn {
        SignIn {
            created_date_time: None,
            ip_address: Some(ip.into()),
            applied_conditional_access_policies: results
                .iter()
                .map(|(id, r)| AppliedConditionalAccessPolicy {
                    id: Some((*id).into()),
                    display_name: None,
                    result: Some((*r).into()),
                })
                .collect(),
        }
    }

    #[test]
    fn readout_counts_report_only_failures_for_this_policy() {
        let rows = vec![
            sign_in("203.0.113.1", &[("pol-1", "reportOnlyFailure")]),
            sign_in("203.0.113.1", &[("pol-1", "reportOnlyFailure")]),
            sign_in("203.0.113.2", &[("pol-1", "reportOnlySuccess")]),
            sign_in("203.0.113.3", &[("other", "reportOnlyFailure")]),
            sign_in("203.0.113.4", &[("pol-1", "reportOnlyFailure")]),
        ];
        let r = readout_from(&rows, "pol-1");
        assert_eq!(r.would_block, 3);
        assert_eq!(r.sample_ips, vec!["203.0.113.1", "203.0.113.4"]);
        assert_eq!(r.window_days, READOUT_WINDOW_DAYS);
        let many: Vec<SignIn> = (0..9)
            .map(|i| {
                sign_in(
                    &format!("198.51.100.{i}"),
                    &[("pol-1", "reportOnlyFailure")],
                )
            })
            .collect();
        assert_eq!(readout_from(&many, "pol-1").sample_ips.len(), 5);
    }

    #[test]
    fn lock_write_licence_error_is_typed() {
        let licence = azapptoolkit_graph::GraphError::Forbidden(
            r#"{"error":{"code":"Authorization_RequestDenied","message":"Workload Identities Premium licenses are required to create or modify Conditional Access policies scoped to service principals."}}"#.into(),
        );
        assert_eq!(
            map_lock_write_err(licence).code,
            "workload_identity_license_required"
        );
        let bad_request = azapptoolkit_graph::GraphError::Api {
            status: 400,
            body: "Creating a policy for workload identities requires a Workload Identity Premium license".into(),
        };
        assert_eq!(
            map_lock_write_err(bad_request).code,
            "workload_identity_license_required"
        );
        let role = azapptoolkit_graph::GraphError::Forbidden(
            r#"{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}"#.into(),
        );
        let ui = map_lock_write_err(role);
        assert_eq!(ui.code, "forbidden");
        assert!(ui.message.contains("Conditional Access"), "{}", ui.message);
    }

    fn ip_location(id: &str) -> NamedLocation {
        NamedLocation {
            id: Some(id.into()),
            display_name: Some("Office".into()),
            odata_type: Some("#microsoft.graph.ipNamedLocation".into()),
            is_trusted: Some(true),
            ip_ranges: Vec::new(),
        }
    }

    #[test]
    fn create_validation_refuses_bad_input() {
        const LOC: &str = "aaaaaaaa-0000-0000-0000-000000000001";
        let live = vec![ip_location(LOC)];
        let code = |ids: &[&str], new: Option<NewLocationArgs>| {
            let ids: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
            validate_create(&ids, new.as_ref(), &live)
                .err()
                .map(|e| e.code)
        };
        assert_eq!(code(&[], None), Some("no_locations".into()));
        assert_eq!(
            code(&["not-a-guid"], None),
            Some("invalid_location_id".into())
        );
        assert_eq!(
            code(&["bbbbbbbb-0000-0000-0000-000000000002"], None),
            Some("unknown_location".into())
        );
        let everything = NewLocationArgs {
            name: "All".into(),
            cidrs: vec!["0.0.0.0/0".into()],
        };
        assert_eq!(code(&[], Some(everything)), Some("invalid_cidr".into()));
        let unnamed = NewLocationArgs {
            name: "  ".into(),
            cidrs: vec!["10.0.0.0/8".into()],
        };
        assert_eq!(
            code(&[], Some(unnamed)),
            Some("invalid_location_name".into())
        );
        let ok = NewLocationArgs {
            name: "Payroll egress".into(),
            cidrs: vec!["10.0.0.0/8".into(), "".into(), " 2001:db8::/32".into()],
        };
        let parsed = {
            let ids = vec![LOC.to_string()];
            validate_create(&ids, Some(&ok), &live).unwrap()
        };
        assert_eq!(
            parsed,
            vec![
                (false, "10.0.0.0/8".to_string()),
                (true, "2001:db8::/32".to_string())
            ]
        );
    }
}
