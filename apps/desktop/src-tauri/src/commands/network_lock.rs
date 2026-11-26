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

/// The tenant's policies; `map` is the read's error mapping (the tab's
/// graceful `map_ca_err` for the status read, the lock's for a write's verify).
async fn live_policies(
    client: &GraphClient,
    map: fn(GraphError) -> UiError,
) -> Result<Vec<ConditionalAccessPolicy>, UiError> {
    client.list_conditional_access_policies().await.map_err(map)
}

fn location_dto(l: &NamedLocation) -> Option<NamedLocationDto> {
    Some(NamedLocationDto {
        id: l.id.clone()?,
        display_name: l.display_name.clone().unwrap_or_default(),
        is_trusted: l.is_trusted.unwrap_or(false),
        range_count: u32::try_from(l.ip_ranges.len()).unwrap_or(u32::MAX),
    })
}

/// What a report-only lock would have blocked: of the sign-ins this policy
/// produced any result for (`evaluated` — zero before the app signs in after
/// the lock was created), those whose result is `reportOnlyFailure`, plus up
/// to five distinct addresses. `truncated` = the read hit its cap.
pub(crate) fn readout_from(
    sign_ins: &[SignIn],
    policy_id: &str,
    truncated: bool,
) -> ReportOnlyReadout {
    let mut evaluated = 0u32;
    let mut would_block = 0u32;
    let mut ips: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for s in sign_ins {
        let ours = s
            .applied_conditional_access_policies
            .iter()
            .find(|p| p.id.as_deref() == Some(policy_id));
        let Some(ours) = ours else {
            continue;
        };
        evaluated = evaluated.saturating_add(1);
        if ours.result.as_deref() != Some("reportOnlyFailure") {
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
        evaluated,
        would_block,
        truncated,
        sample_ips: ips,
        window_days: READOUT_WINDOW_DAYS,
    }
}

/// Maps a lock WRITE failure (reads use the tab's graceful `map_ca_err`). A
/// refusal about a workload-identity LICENCE is the missing Workload ID
/// Premium licence (Graph doesn't document the exact error, so the body is
/// matched on its text: it must name workload identities AND a licence /
/// premium); any other 403 carries the catalog's remediation.
pub(crate) fn map_lock_write_err(err: GraphError) -> UiError {
    let body = match &err {
        GraphError::Forbidden(b) => Some(b.as_str()),
        GraphError::Api { body, .. } => Some(body.as_str()),
        _ => None,
    };
    let is_licence = body.is_some_and(|b| {
        let b = b.to_ascii_lowercase();
        (b.contains("workload identit") || b.contains("workload id"))
            && (b.contains("licen") || b.contains("premium"))
    });
    if is_licence {
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

/// A new named location's id when a live IP location already has this name
/// (trimmed, case-insensitive) AND exactly these ranges — a retried create
/// reuses it instead of leaking a duplicate. Same name, other ranges →
/// `location_name_taken`.
pub(crate) fn reusable_location(
    live: &[NamedLocation],
    name: &str,
    cidrs: &[(bool, String)],
) -> Result<Option<String>, UiError> {
    let name = name.trim();
    let Some(same_name) = live.iter().find(|l| {
        l.is_ip()
            && l.display_name
                .as_deref()
                .is_some_and(|n| n.trim().eq_ignore_ascii_case(name))
    }) else {
        return Ok(None);
    };
    // Both sides canonical: Graph may store a range in another spelling. A
    // live range that doesn't parse drops out, so the sets differ (refused).
    let mut have: Vec<String> = same_name
        .ip_ranges
        .iter()
        .filter_map(|r| r.cidr_address.as_deref())
        .filter_map(|c| parse_cidr(c).ok().map(|(_, c)| c))
        .collect();
    let mut want: Vec<String> = cidrs.iter().map(|(_, c)| c.clone()).collect();
    have.sort();
    want.sort();
    if have == want {
        Ok(same_name.id.clone())
    } else {
        Err(UiError::validation(
            "location_name_taken",
            format!(
                "A named location called \"{name}\" already exists with other ranges. Choose it from the list, or use another name."
            ),
        ))
    }
}

/// How long the report-only readout (the sign-in log read) may take before
/// the section gives up on it: the section renders only once it returns, and
/// the read can retry for minutes. 15 s matches readiness's Azure plane.
pub(crate) const READOUT_BUDGET: std::time::Duration = std::time::Duration::from_secs(15);

/// `read` bounded by `budget`: past it, the readout is unknown (`None`), which
/// the section already words honestly.
pub(crate) async fn readout_within<T>(
    budget: std::time::Duration,
    read: impl std::future::Future<Output = Option<T>>,
) -> Option<T> {
    match tokio::time::timeout(budget, read).await {
        Ok(readout) => readout,
        Err(_) => {
            tracing::warn!(
                budget_secs = budget.as_secs(),
                "network lock: sign-in readout timed out"
            );
            None
        }
    }
}

/// A failed policy create's error, and whether the POST may have committed
/// anyway (a 5xx, a dropped connection, an unreadable 2xx): then the cached
/// audit, which shows each grant's lock, is swept and the message says so.
pub(crate) fn create_policy_failed(
    err: GraphError,
    created_location: Option<&str>,
) -> (UiError, bool) {
    let may_have_committed = err.may_have_committed();
    let mut ui = map_lock_write_err(err);
    ui.message = create_failed_message(&ui.message, created_location);
    if may_have_committed {
        ui.message
            .push_str(" The lock may have been created anyway; reload before trying again.");
    }
    (ui, may_have_committed)
}

/// A failed policy create's message: when the named location landed first,
/// say so — it is kept and can be chosen next time.
pub(crate) fn create_failed_message(base: &str, created_location: Option<&str>) -> String {
    match created_location {
        Some(name) => format!(
            "{base} The named location \"{name}\" was created and is kept — choose it next time."
        ),
        None => base.to_string(),
    }
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
    let ineligible = |reason, toolkit_lock| NetworkLockStatus {
        ineligible: Some(reason),
        toolkit_lock,
        other: NetworkLock::NotPossible { reason },
        other_policy_name: None,
        readout: None,
    };
    let Some(sp_id) = app.sp_id.as_deref() else {
        return Ok(ineligible(LockIneligible::NoServicePrincipal, None));
    };
    if let Some(reason) = app.ineligible {
        // Conditional Access doesn't apply to this app now, but a lock the
        // toolkit made earlier is still in the tenant (and back in force if
        // the app becomes eligible again): offer its removal. An unreadable
        // policy list keeps the plain "not possible".
        let ours = match live_policies(&client, crate::commands::conditional_access::map_ca_err)
            .await
        {
            Ok(policies) => toolkit_lock_for(&policies, sp_id).cloned(),
            Err(err) => {
                tracing::info!(code = %err.code, "network lock: policies unreadable for an ineligible app");
                None
            }
        };
        let lock = match ours {
            Some(p) => Some(toolkit_lock_dto(&client, &p).await),
            None => None,
        };
        return Ok(ineligible(reason, lock));
    }
    let policies = live_policies(&client, crate::commands::conditional_access::map_ca_err).await?;
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
        let lock = toolkit_lock_dto(&client, &p).await;
        if lock.state == "enabledForReportingButNotEnforced"
            && state
                .ensure_feature_token(&tenant_id, ConsentFeature::AuditLog)
                .await
                .is_ok()
        {
            let since =
                Timestamp::now() - SignedDuration::from_hours(24 * i64::from(READOUT_WINDOW_DAYS));
            readout = readout_within(READOUT_BUDGET, async {
                match client.list_service_principal_sign_ins(&app_id, since).await {
                    Ok((rows, truncated)) => Some(readout_from(&rows, &lock.policy_id, truncated)),
                    Err(err) => {
                        tracing::warn!(
                            code = err.ui_code(),
                            "network lock: sign-in readout failed"
                        );
                        None
                    }
                }
            })
            .await;
        }
        toolkit_lock = Some(lock);
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
        .map_err(crate::commands::conditional_access::map_ca_err)?;
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
    let policies = live_policies(&client, map_lock_write_err).await?;
    if toolkit_lock_for(&policies, &sp_id).is_some() {
        return Err(UiError::validation(
            "lock_exists",
            "This app already has a network lock.",
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
        // A retried create (the policy failed last time) reuses the location
        // it already made instead of leaking a duplicate.
        if let Some(id) = reusable_location(&live_locations, &new.name, &cidrs)? {
            excluded.push(id);
        } else {
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
    }
    let body = lock_policy_body(&lock_display_name(&app.display_name), &sp_id, &excluded);
    let created = match client.create_ca_policy(&body).await {
        Ok(p) => p,
        Err(err) => {
            let (ui, may_have_landed) = create_policy_failed(err, created_location_name.as_deref());
            // The "only on Ok" exception for a write that may have landed.
            if may_have_landed {
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

/// The toolkit lock's DTO: its state and the named locations it excludes
/// (an unreadable location list shows ids).
async fn toolkit_lock_dto(client: &GraphClient, p: &ConditionalAccessPolicy) -> ToolkitLockDto {
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
    ToolkitLockDto {
        policy_id,
        state: lock_state,
        excluded_locations,
    }
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
            "That policy isn't this app's toolkit network lock any more (it may have been \
             changed in the portal).",
        )
    };
    let sp_id = app.sp_id.ok_or_else(not_ours)?;
    let policies = live_policies(&client, map_lock_write_err).await?;
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
        let r = readout_from(&rows, "pol-1", false);
        assert_eq!(r.would_block, 3);
        assert_eq!(
            r.evaluated, 4,
            "every result for this policy, success included"
        );
        assert!(!r.truncated);
        assert_eq!(r.sample_ips, vec!["203.0.113.1", "203.0.113.4"]);
        assert_eq!(r.window_days, READOUT_WINDOW_DAYS);
        // Sign-ins from before the lock existed carry no result for it.
        let before = vec![sign_in("203.0.113.9", &[("other", "success")])];
        let r = readout_from(&before, "pol-1", true);
        assert_eq!((r.evaluated, r.would_block, r.truncated), (0, 0, true));
        let many: Vec<SignIn> = (0..9)
            .map(|i| {
                sign_in(
                    &format!("198.51.100.{i}"),
                    &[("pol-1", "reportOnlyFailure")],
                )
            })
            .collect();
        assert_eq!(readout_from(&many, "pol-1", false).sample_ips.len(), 5);
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
        // Mentioning workload identities isn't enough: it must be about a licence.
        let shape = azapptoolkit_graph::GraphError::Api {
            status: 400,
            body: "clientApplications is invalid for workload identity policies".into(),
        };
        assert_ne!(
            map_lock_write_err(shape).code,
            "workload_identity_license_required"
        );
        let id_premium = azapptoolkit_graph::GraphError::Forbidden(
            "This tenant needs Workload ID Premium for this policy".into(),
        );
        assert_eq!(
            map_lock_write_err(id_premium).code,
            "workload_identity_license_required"
        );
    }

    #[test]
    fn a_retried_create_reuses_its_named_location_or_refuses_a_clash() {
        let mut existing = ip_location("aaaaaaaa-0000-0000-0000-000000000009");
        existing.display_name = Some("Payroll egress".into());
        existing.ip_ranges = vec![azapptoolkit_core::models::IpRange {
            cidr_address: Some("10.0.0.0/8".into()),
        }];
        let live = vec![existing];
        let same = vec![(false, "10.0.0.0/8".to_string())];
        assert_eq!(
            reusable_location(&live, " payroll EGRESS ", &same).unwrap(),
            Some("aaaaaaaa-0000-0000-0000-000000000009".to_string())
        );
        let other = vec![(false, "192.0.2.0/24".to_string())];
        assert_eq!(
            reusable_location(&live, "Payroll egress", &other)
                .err()
                .map(|e| e.code),
            Some("location_name_taken".into())
        );
        assert_eq!(reusable_location(&live, "New place", &same).unwrap(), None);
    }

    /// Review Focus 5: the location landed, the policy didn't.
    #[test]
    fn a_failed_policy_create_names_the_location_that_landed() {
        let msg = create_failed_message("Graph refused.", Some("Payroll egress"));
        assert!(msg.starts_with("Graph refused."), "{msg}");
        assert!(msg.contains("\"Payroll egress\""), "{msg}");
        assert_eq!(
            create_failed_message("Graph refused.", None),
            "Graph refused."
        );
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

    /// A retried create matches the live location whatever spelling either
    /// side used (B2b).
    #[test]
    fn reusable_location_compares_canonical_ranges() {
        let mut live = ip_location("loc-1");
        live.ip_ranges = vec![azapptoolkit_core::models::IpRange {
            cidr_address: Some("2001:DB8::/32".into()),
        }];
        let got = reusable_location(&[live], "office", &[(true, "2001:db8::/32".into())]);
        assert_eq!(got.unwrap(), Some("loc-1".to_string()));
    }

    /// The sign-in readout can't hold the section's skeleton for minutes
    /// (B2a).
    #[tokio::test(start_paused = true)]
    async fn readout_gives_up_at_its_budget() {
        let started = tokio::time::Instant::now();
        let none: Option<u32> = readout_within(READOUT_BUDGET, std::future::pending()).await;
        assert_eq!(none, None);
        assert!(started.elapsed() >= READOUT_BUDGET);
        let some = readout_within(READOUT_BUDGET, async { Some(7_u32) }).await;
        assert_eq!(some, Some(7));
    }

    /// A policy POST that may have committed sweeps the cached audit and
    /// says the lock may exist (B2g).
    #[test]
    fn a_policy_create_that_may_have_landed_sweeps() {
        let (ui, sweep) = create_policy_failed(
            GraphError::Server {
                status: 502,
                body: String::new(),
            },
            None,
        );
        assert!(sweep);
        assert!(
            ui.message.contains("may have been created"),
            "{}",
            ui.message
        );
        let (ui, sweep) = create_policy_failed(GraphError::Forbidden("no".into()), None);
        assert!(!sweep);
        assert!(
            !ui.message.contains("may have been created"),
            "{}",
            ui.message
        );
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
