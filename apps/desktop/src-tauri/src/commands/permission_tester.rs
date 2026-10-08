//! Permission-tester commands.
//!
//! "App → resource" effective-access checks: given an app and a specific
//! Exchange mailbox or SharePoint site, report whether the app actually has
//! access and how (org-wide vs scoped). Every check degrades gracefully: a
//! missing admin right/scope surfaces as an `unknown` verdict, never a hard
//! error of the page.
//!
//! A mailbox has **two independent access authorities**, and actual access is
//! their **union** (per Microsoft's RBAC-for-Applications guidance — neither
//! authority can restrict the other):
//!
//! 1. **Entra layer** ([`EntraReach`]) — an org-wide Graph application
//!    permission (`Mail.Read`, …) reaches every mailbox, constrained only by a
//!    legacy Application Access Policy, evaluated live via
//!    `Test-ApplicationAccessPolicy`.
//! 2. **Exchange RBAC layer** ([`RbacReach`]) — management role assignments,
//!    evaluated via `Test-ServicePrincipalAuthorization -Resource`, honoring
//!    the per-row `InScope` flag: `false` means the permission is held but
//!    does **not** cover the tested mailbox. This cmdlet deliberately excludes
//!    Entra grants, which is why layer 1 exists.
//!
//! SharePoint unions the org-wide `Sites.*` grant with the per-site
//! permission list.

use std::collections::HashMap;
use std::sync::Arc;

use tauri::{AppHandle, State};
use tokio::sync::Mutex;

use azapptoolkit_core::audit::{AuditPrincipalKind, MailPermissionScope, ResourcePermission};
use azapptoolkit_core::models::{
    AppRoleAssignment, ResolvedSharePointResource, SelectedPermission,
};
use azapptoolkit_core::scoping::{
    OFFICE365_SHAREPOINT_ONLINE_APP_ID, SP_FILES_SELECTED, SP_LIST_ITEMS_SELECTED,
    SP_LISTS_SELECTED, SP_SITES_SELECTED, SelectedScopeLevel, is_aap_confinable_permission,
    is_scopable_exchange_resource_permission, is_sharepoint_orgwide_permission,
    selected_scope_accepts, selected_scope_level_for,
};
use azapptoolkit_exchange::ExchangeClient;
use azapptoolkit_exchange::models::{
    ExoApplicationAccessPolicy, ExoAuthorizationResult, ExoServicePrincipal,
};
use azapptoolkit_graph::GraphClient;

use crate::commands::dispatch::{SessionDead, dispatch_capped};
use azapptoolkit_exchange::verdict::{aap_verdict_for, is_org_wide_auth_row};

use crate::commands::exchange::exchange_client;
use crate::commands::export::{coverage_comment_block, coverage_json, csv_field};
use crate::commands::graph_roles::{
    ResourceRoles, mailbox_resource_roles, resolve_grant, sharepoint_resource_roles,
};
use crate::commands::progress::emit_progress;
use crate::commands::sharepoint::{sharepoint_client_checked, sharepoint_item_err};
use crate::dto::UiError;
use crate::dto::permission_tester::{
    AccessVerdict, MailboxProbeProgress, MailboxReacherRow, MailboxReachersResult,
    PermissionTestResult,
};
use crate::state::AppState;

/// The Entra layer's input: the mail-scopable Graph application permissions
/// the SP holds as **org-wide Entra app-role grants**. These reach *every*
/// mailbox directly through Graph with no Exchange RBAC involvement —
/// `Test-ServicePrincipalAuthorization` deliberately excludes them — and only
/// a legacy Application Access Policy can constrain them. Returns the matching
/// permission values; empty when the SP holds no such grant, or when the app has
/// no service principal in this tenant at all (it then holds nothing).
///
/// `Err` when the SP lookup, the mailbox role index or the assignment list
/// couldn't be read. That is never "holds none": the caller reports it as
/// [`EntraReach::Unreadable`] (an `unknown` verdict). Folding the error into an
/// empty list let a transient Graph failure answer a definite "No access" for
/// an app holding `Mail.Read` tenant-wide. Mirrors path 1 of
/// [`test_site_access`] (org-wide `Sites.*`).
async fn orgwide_mailbox_grant(
    client: &GraphClient,
    app_id: &str,
) -> Result<Vec<ResourcePermission>, UiError> {
    let Some(sp) = client.get_service_principal_by_app_id(app_id).await? else {
        return Ok(Vec::new());
    };
    // Across BOTH mailbox-bearing resources, resource-aware — the shared
    // pipeline the Exchange scoping reconciliation reads, so the two can't drift.
    // The resource stays attached: the legacy-policy gate in [`entra_reach`]
    // asks a resource-aware question of each grant.
    let mut perms =
        crate::commands::exchange::try_held_orgwide_mail_permissions(client, &sp.id).await?;
    sort_permissions(&mut perms);
    Ok(perms)
}

/// Sorts by value (then resource) and drops exact duplicates, so the reported
/// permission lists are stable across Graph's response order.
fn sort_permissions(perms: &mut Vec<ResourcePermission>) {
    perms.sort_by(|a, b| {
        (a.value.as_str(), a.resource_app_id.as_deref())
            .cmp(&(b.value.as_str(), b.resource_app_id.as_deref()))
    });
    perms.dedup();
}

/// The bare values of `perms`, for display.
fn permission_values(perms: &[ResourcePermission]) -> Vec<String> {
    perms.iter().map(|p| p.value.clone()).collect()
}

/// Exchange-RBAC-layer outcome for one (principal, mailbox) pair, derived
/// from `Test-ServicePrincipalAuthorization -Resource` rows with `InScope`
/// honored. The cmdlet returns one row per role assignment *whether or not*
/// the tested mailbox is covered — only `InScope = true` rows grant access.
enum RbacReach {
    /// An in-scope assignment is organization-wide. Carries the role names.
    OrgWide(Vec<String>),
    /// At least one management scope includes the mailbox (`InScope = true`).
    Scoped(Vec<String>),
    /// No assignment covers the mailbox. `had_assignments` distinguishes
    /// "scoped to other mailboxes" (rows present, all `InScope = false`) from
    /// "not registered for RBAC at all" — the explanations differ.
    None { had_assignments: bool },
    /// The cmdlet failed (403/network), or returned rows without the
    /// `InScope` boolean despite a `-Resource`; nothing can be concluded.
    Indeterminate,
}

fn rbac_reach_from_rows(rows: &[ExoAuthorizationResult]) -> RbacReach {
    let in_scope: Vec<&ExoAuthorizationResult> =
        rows.iter().filter(|r| r.in_scope == Some(true)).collect();
    if !in_scope.is_empty() {
        let mut roles: Vec<String> = in_scope
            .iter()
            .filter_map(|r| r.role_name.clone())
            .collect();
        roles.sort();
        roles.dedup();
        return if in_scope.iter().any(|r| is_org_wide_auth_row(r)) {
            RbacReach::OrgWide(roles)
        } else {
            RbacReach::Scoped(roles)
        };
    }
    if rows.iter().any(|r| r.in_scope.is_none()) {
        // A `-Resource` was supplied, so every row should carry a real
        // boolean; a missing one means the scope-membership check didn't run.
        return RbacReach::Indeterminate;
    }
    RbacReach::None {
        had_assignments: !rows.is_empty(),
    }
}

/// Probes Exchange RBAC for whether `app_id` reaches `mailbox`, mapping the
/// outcome to an [`RbacReach`]. A missing-object error means the principal isn't
/// in Exchange's SP store (the managed-identity case) ⇒ *definitely* no RBAC
/// layer, distinct from an indeterminate probe failure (a 403/transient error,
/// which must never be read as "no access"). `log_context` tags the info log
/// emitted when Exchange can't answer. Shared by `test_mailbox_access` and the
/// mailbox reverse-lookup `probe_candidate`.
async fn rbac_reach_for(
    exo: &ExchangeClient,
    app_id: &str,
    mailbox: &str,
    log_context: &str,
) -> RbacReach {
    match exo
        .test_service_principal_authorization(app_id, Some(mailbox))
        .await
    {
        Ok(rows) => rbac_reach_from_rows(&rows),
        Err(err) => {
            // Log a concise code, not the raw body — an Exchange 403 can return
            // a NUL-padded blob that otherwise floods the log.
            tracing::info!(%app_id, code = err.ui_code(), "{log_context}");
            if err.is_missing_object() {
                // Not in Exchange's SP store (the managed-identity case) ⇒
                // definitely no RBAC layer, not an indeterminate probe.
                RbacReach::None {
                    had_assignments: false,
                }
            } else {
                RbacReach::Indeterminate
            }
        }
    }
}

/// Entra-layer outcome: the org-wide Graph mailbox grants, gated by the
/// legacy Application Access Policy — the only mechanism that constrains
/// Entra grants (Exchange RBAC scoping never does; see the module docs).
enum EntraReach {
    /// Org-wide grants held and no AAP names this app — reaches every mailbox.
    OrgWide(Vec<String>),
    /// Grants held, confined by a `RestrictAccess` AAP whose group includes
    /// the tested mailbox.
    ScopedByAap {
        perms: Vec<String>,
        scope_name: Option<String>,
    },
    /// Grants held but the live AAP evaluation denied this mailbox.
    DeniedByAap,
    /// Grants held; the AAP gate couldn't be evaluated. Reported as org-wide
    /// reach with a caveat — never under-reported.
    Unverified(Vec<String>),
    /// No org-wide Graph mailbox grant in Entra ID.
    NotHeld,
    /// The SP's app-role assignments couldn't be read — whether an org-wide
    /// grant is held is unknown (never `NotHeld`).
    Unreadable,
}

/// Evaluates the Entra layer for `perms` (already-confirmed org-wide grants).
/// `policies` is the pre-fetched AAP list (`None` = couldn't be read). The
/// live `Test-ApplicationAccessPolicy` call is made only when a policy
/// actually names this app, so the common no-AAP case costs no extra cmdlet.
///
/// A policy answers only for what it governs ([`is_aap_confinable_permission`],
/// on each grant's own resource). A held RBAC-only grant (`MailboxItem.*`,
/// `Mail-Advanced.*`, …) is org-wide whatever any policy says, so it is
/// reported as [`EntraReach::OrgWide`] before the policy is consulted —
/// letting the live AAP test answer for it reported an org-wide grant as
/// confined (or denied) for this mailbox.
async fn entra_reach(
    exo: &ExchangeClient,
    app_id: &str,
    mailbox: &str,
    perms: Vec<ResourcePermission>,
    policies: Option<&[ExoApplicationAccessPolicy]>,
) -> EntraReach {
    let ungoverned: Vec<String> = perms
        .iter()
        .filter(|p| {
            !p.resource_app_id
                .as_deref()
                .is_some_and(|r| is_aap_confinable_permission(r, &p.value))
        })
        .map(|p| p.value.clone())
        .collect();
    if !ungoverned.is_empty() {
        return EntraReach::OrgWide(ungoverned);
    }
    let perms = permission_values(&perms);
    let Some(policies) = policies else {
        return EntraReach::Unverified(perms);
    };
    // Casefolded for the reason `verdict::aap_verdict_for` documents: Exchange
    // stores the AppId in whatever case it was given, and a case-sensitive
    // compare reported a confined app as reaching every mailbox.
    if !policies.iter().any(|p| {
        p.app_id
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(app_id))
    }) {
        return EntraReach::OrgWide(perms);
    }
    match exo.test_application_access_policy(app_id, mailbox).await {
        Ok(result) => match result.granted {
            // Granted *through* a RestrictAccess policy means the mailbox is
            // in the policy group (scoped); granted with only DenyAccess
            // policies means the mailbox just isn't on the blocklist — that
            // is still effectively org-wide reach.
            Some(true) => match aap_verdict_for(policies, app_id) {
                Some(MailPermissionScope::Scoped { scope_name, .. }) => {
                    EntraReach::ScopedByAap { perms, scope_name }
                }
                _ => EntraReach::OrgWide(perms),
            },
            Some(false) => EntraReach::DeniedByAap,
            None => EntraReach::Unverified(perms),
        },
        Err(err) => {
            tracing::info!(%app_id, code = err.ui_code(), "AAP access test unavailable");
            EntraReach::Unverified(perms)
        }
    }
}

/// Folds the two layers into one verdict. Reach precedence: org-wide >
/// scoped > unknown > no access — a definite grant on either layer wins (the
/// authorities union), and an indeterminate layer only degrades the verdict
/// to `unknown` when nothing else grants access.
fn synthesize(mailbox: &str, entra: &EntraReach, rbac: &RbacReach) -> PermissionTestResult {
    // 0 = no access, 1 = unknown, 2 = scoped, 3 = org-wide.
    let entra_level = match entra {
        EntraReach::OrgWide(_) | EntraReach::Unverified(_) => 3,
        EntraReach::ScopedByAap { .. } => 2,
        EntraReach::Unreadable => 1,
        EntraReach::DeniedByAap | EntraReach::NotHeld => 0,
    };
    let rbac_level = match rbac {
        RbacReach::OrgWide(_) => 3,
        RbacReach::Scoped(_) => 2,
        RbacReach::Indeterminate => 1,
        RbacReach::None { .. } => 0,
    };
    let level = entra_level.max(rbac_level);

    let mut roles: Vec<String> = Vec::new();
    if entra_level >= 2 {
        match entra {
            EntraReach::OrgWide(perms)
            | EntraReach::Unverified(perms)
            | EntraReach::ScopedByAap { perms, .. } => roles.extend(perms.iter().cloned()),
            _ => {}
        }
    }
    match rbac {
        RbacReach::OrgWide(r) | RbacReach::Scoped(r) => roles.extend(r.iter().cloned()),
        _ => {}
    }
    roles.sort();
    roles.dedup();

    let mut parts: Vec<String> = Vec::new();
    match entra {
        EntraReach::OrgWide(perms) => parts.push(format!(
            "Holds organization-wide Graph mailbox permission(s) ({}) in Entra ID with no legacy Application Access Policy restricting them — this grant alone reaches “{mailbox}” and every other mailbox.",
            perms.join(", ")
        )),
        EntraReach::ScopedByAap { perms, scope_name } => {
            let scope = scope_name
                .as_deref()
                .map(|n| format!(" (scope “{n}”)"))
                .unwrap_or_default();
            parts.push(format!(
                "Entra-granted permission(s) ({}) are confined by a legacy Application Access Policy{scope} whose group includes “{mailbox}”.",
                perms.join(", ")
            ));
        }
        EntraReach::DeniedByAap => parts.push(format!(
            "The organization-wide Entra grant is blocked for “{mailbox}” by a legacy Application Access Policy."
        )),
        EntraReach::Unverified(perms) => parts.push(format!(
            "Holds organization-wide Graph mailbox permission(s) ({}) that reach “{mailbox}” (and every mailbox) directly via Graph, unless a legacy Application Access Policy confines them — that couldn't be verified.",
            perms.join(", ")
        )),
        EntraReach::NotHeld => parts.push(
            "No organization-wide Graph mailbox permission is granted in Entra ID.".into(),
        ),
        EntraReach::Unreadable => parts.push(
            "The app's Entra ID app-role assignments couldn't be read, so whether it holds an organization-wide Graph mailbox permission is unknown."
                .into(),
        ),
    }
    match rbac {
        RbacReach::OrgWide(_) => parts.push(
            "Exchange RBAC for Applications grants organization-wide access.".into(),
        ),
        RbacReach::Scoped(_) => parts.push(format!(
            "An Exchange RBAC management scope includes “{mailbox}” (InScope = true)."
        )),
        RbacReach::None {
            had_assignments: true,
        } => parts.push(format!(
            "Exchange RBAC role assignments exist, but none of their scopes include “{mailbox}” (InScope = false)."
        )),
        RbacReach::None {
            had_assignments: false,
        } => parts.push("No Exchange RBAC for Applications assignments.".into()),
        RbacReach::Indeterminate => parts.push(
            "The Exchange RBAC authorization check couldn't be completed (Exchange administrator rights may be required)."
                .into(),
        ),
    }
    // The finding behind "why does my scoped app still reach everything":
    // RBAC scoping is only effective once the org-wide Entra grant is removed.
    if matches!(entra, EntraReach::OrgWide(_))
        && matches!(
            rbac,
            RbacReach::Scoped(_)
                | RbacReach::None {
                    had_assignments: true
                }
        )
    {
        parts.push(
            "The Exchange RBAC scoping is ineffective while the organization-wide Entra grant remains — the two union, so remove the Entra application permission to make the scope effective."
                .into(),
        );
    }

    let verdict = match level {
        3 => AccessVerdict::OrgWide,
        2 => AccessVerdict::Scoped,
        1 => AccessVerdict::Unknown,
        _ => AccessVerdict::NoAccess,
    };
    PermissionTestResult {
        has_access: verdict.reaches(),
        verdict,
        roles,
        detail: Some(parts.join(" ")),
        resource_label: mailbox.to_string(),
    }
}

/// Tests whether `app_id` (a service principal's appId) can access the
/// Exchange `mailbox` — the union of the Entra layer (org-wide Graph grants
/// gated by `Test-ApplicationAccessPolicy`) and the Exchange RBAC layer
/// (`Test-ServicePrincipalAuthorization -Resource`, which bypasses the RBAC
/// propagation cache; `InScope` honored). A principal the RBAC cmdlet can't
/// resolve (a managed identity isn't in Exchange's SP store) has no RBAC
/// layer at all; any other failure leaves that layer indeterminate. Never a
/// thrown error.
#[tauri::command]
pub async fn test_mailbox_access(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    mailbox: String,
) -> Result<PermissionTestResult, UiError> {
    let mailbox = mailbox.trim().to_string();
    let graph = state.graph_for(&tenant_id);
    let exo = match exchange_client(&state, &tenant_id) {
        Ok(exo) => exo,
        Err(err) => {
            // No Exchange client at all: an org-wide Entra grant still answers
            // on its own (with the AAP caveat); otherwise nothing can be said.
            return match orgwide_mailbox_grant(&graph, &app_id).await {
                Ok(perms) if !perms.is_empty() => Ok(synthesize(
                    &mailbox,
                    &EntraReach::Unverified(permission_values(&perms)),
                    &RbacReach::Indeterminate,
                )),
                // A dead session re-authenticates in place rather than
                // reading as an inconclusive test.
                Err(graph_err) if graph_err.is_reauth_fatal() => Err(graph_err),
                _ => Ok(PermissionTestResult::unknown(
                    &mailbox,
                    format!(
                        "Couldn't reach Exchange to test access ({}). Exchange administrator rights are required.",
                        err.code
                    ),
                )),
            };
        }
    };

    let rbac = rbac_reach_for(
        &exo,
        &app_id,
        &mailbox,
        "mailbox RBAC access test unavailable",
    )
    .await;

    let entra = match orgwide_mailbox_grant(&graph, &app_id).await {
        Ok(perms) if !perms.is_empty() => {
            // The AAP list is read only when an Entra grant exists for it to
            // constrain.
            let policies = exo.get_application_access_policies().await.ok();
            entra_reach(&exo, &app_id, &mailbox, perms, policies.as_deref()).await
        }
        Ok(_) => EntraReach::NotHeld,
        // A dead session re-authenticates in place (never an "unknown" verdict
        // indistinguishable from a genuine one).
        Err(err) if err.is_reauth_fatal() => return Err(err),
        Err(err) => {
            tracing::info!(code = %err.code, "mailbox test: Entra grants unreadable");
            EntraReach::Unreadable
        }
    };

    Ok(synthesize(&mailbox, &entra, &rbac))
}

/// In-flight cap for the per-candidate Exchange probes — the admin-API cmdlet
/// is heavyweight, so this stays well below the Graph loops' caps.
const PROBE_CONCURRENCY: usize = 4;

/// The mailbox reverse lookup: which applications can reach `mailbox`?
///
/// Candidates come from two sources, merged by SP object id: the paged
/// `appRoleAssignedTo` on each mailbox-bearing resource SP (Microsoft Graph,
/// and Office 365 Exchange Online for the EWS `full_access_as_app` scope) —
/// together the whole tenant's principal → mailbox-app-role matrix — filtered
/// to principals holding a mail-scopable application permission
/// ([`mailbox_candidates`]); plus the Exchange SP store
/// (`Get-ServicePrincipal`), which is the only place a principal granted
/// access *solely* through Exchange RBAC (no Entra grant) is visible. Each
/// candidate is then evaluated with the same two-layer union
/// [`test_mailbox_access`] uses: the held Entra grants gated by the legacy AAP
/// (the AAP list is fetched once for the whole run), unioned with the Exchange
/// RBAC layer via `Test-ServicePrincipalAuthorization -Resource` (`InScope`
/// honored).
///
/// Degradation, never under-reporting (audit Rule-11 posture): when Exchange
/// is unavailable, a candidate's held org-wide Graph mail grant reaches every
/// mailbox via Graph anyway, so it reads `org_wide` with the legacy-AAP
/// caveat; it never silently drops to "no access". The Exchange-only
/// candidate source is necessarily absent in that degraded mode — including
/// when the Exchange.Manage token can't be acquired — and the UI's
/// `exchange_available = false` summary flags the partial coverage;
/// `exchange_sp_store_read = false` flags the same gap when Exchange answered
/// but its SP store couldn't be listed.
///
/// Long-running: emits `mailbox-probe-progress` and polls its own
/// `AppState.mailbox_probe_cancel` token, stopped only by
/// [`cancel_mailbox_probe`] and by sign-out (`AppState::forget_tenant`). The
/// probe has its own flag because the Resource
/// Access panels stay mounted and can run at the same time as the site and
/// Key Vault sweeps: a shared flag let one panel's Cancel abort the others.
#[tauri::command]
pub async fn find_mailbox_reachers(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    mailbox: String,
) -> Result<MailboxReachersResult, UiError> {
    // The app-registration index below can answer from cache, and the Exchange
    // token error is swallowed when non-fatal, so neither it nor `graph_for`
    // proves the session. Sync, so the claim still precedes every await.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    // Claimed before the first await: the Graph role index and the tenant-wide
    // app-role-assignment read below run before the dispatch, and a token
    // claimed after them discards a cancel issued during them. Pinned by
    // `repo_invariants::cancel`.
    let cancel = state.mailbox_probe_cancel.claim();
    let mailbox = mailbox.trim().to_string();
    if mailbox.is_empty() {
        return Err(UiError::validation(
            "missing_mailbox",
            "enter a mailbox address to check",
        ));
    }

    let client = state.graph_for(&tenant_id);
    // BOTH mailbox-bearing resources: Microsoft Graph is required, Office 365
    // Exchange Online is omitted when the tenant has no such SP (an ordinary
    // empty set). Reading Graph alone missed an app whose only mailbox grant is
    // the EWS `full_access_as_app` scope — the strongest one there is.
    let resources = mailbox_resource_roles(&client).await?;
    let mut assigned = Vec::new();
    for resource in &resources {
        assigned.extend(
            client
                .list_app_role_assigned_to(&resource.sp_object_id)
                .await?,
        );
    }
    // principal id → (display name, held mail-scopable values).
    let mut candidates = mailbox_candidates(&resources, assigned);

    // Best-effort Exchange client; without it every verdict derives from the
    // Entra grants (org-wide reach — never under-reported). `exchange_client`
    // only checks the session and the UPN, so without this pre-acquire a
    // missing Exchange.Manage consent still read as `exchange_available`.
    let exo = match state.ensure_exchange_token(&tenant_id).await {
        Ok(()) => exchange_client(&state, &tenant_id).ok(),
        Err(err) => {
            let ui = UiError::from(err);
            if ui.is_reauth_fatal() {
                return Err(ui);
            }
            tracing::info!(code = %ui.code, "mailbox probe: Exchange token unavailable");
            None
        }
    };
    let exchange_available = exo.is_some();
    // One AAP read serves every candidate's Entra-layer gate; best-effort
    // (`None` = unverifiable, those candidates keep the caveated org-wide
    // reading instead of a fabricated verdict).
    let policies: Option<Arc<Vec<ExoApplicationAccessPolicy>>> = match exo.as_deref() {
        Some(exo) => exo
            .get_application_access_policies()
            .await
            .ok()
            .map(Arc::new),
        None => None,
    };
    // Second candidate source: principals registered in Exchange's SP store.
    // An app granted access *only* through Exchange RBAC holds no Graph
    // app-role assignment, so the appRoleAssignedTo sweep above can't see it —
    // these probe with empty held permissions (Entra layer = not held).
    // Best-effort: an unreadable list leaves the Graph-derived candidates, and
    // `exchange_sp_store_read` tells the summary those principals are missing.
    let mut exchange_sp_store_read = false;
    if let Some(exo) = exo.as_deref() {
        match exo.list_service_principals().await {
            Ok(sps) => {
                exchange_sp_store_read = true;
                merge_exchange_candidates(&mut candidates, sps);
            }
            Err(err) => {
                tracing::info!(
                    code = err.ui_code(),
                    "mailbox probe: Exchange SP list unavailable"
                );
            }
        }
    }

    // Prewarm the SP object-id → (appId, servicePrincipalType) map in one batched
    // read instead of one Graph GET per candidate inside the probe loop. The
    // Exchange cmdlets and UI deep links want the appId, not the SP object id the
    // assignment row carries; the servicePrincipalType tags managed identities so
    // a row's "Open" routes to the MI pane. Resolving that per candidate is an
    // N-round-trip fan-out, while the batch helper collapses it to ~N/20 (results
    // in input order, 20 per `$batch`). A prewarm miss (or whole-batch failure)
    // just falls through to the probe's own per-candidate resolve, so this never
    // changes a verdict.
    let candidate_ids: Vec<String> = candidates.keys().cloned().collect();
    let sp_meta_by_principal: Arc<HashMap<String, (String, Option<String>)>> = Arc::new(
        match client.batch_get_service_principals(&candidate_ids).await {
            Ok(results) => candidate_ids
                .iter()
                .cloned()
                .zip(results)
                .filter_map(|(id, r)| match r {
                    Ok(Some(sp)) => Some((id, (sp.app_id, sp.service_principal_type))),
                    _ => None,
                })
                .collect(),
            Err(err) => {
                tracing::info!(
                    ?err,
                    "mailbox probe: SP prewarm batch failed; resolving per-candidate"
                );
                HashMap::new()
            }
        },
    );
    // appId → application object id for every registration homed in THIS tenant.
    // A hit means the reacher is a local app registration, so its "Open" routes to
    // the App Registration pane by the application object id; a miss (managed
    // identity, foreign enterprise app, or orphaned SP) routes to the enterprise /
    // MI pane by the SP object id. Best-effort — an unreadable list just routes
    // every row by SP object id, never changing a verdict. Reads the SHARED
    // per-tenant app-registration index (the same entry global search and the
    // Enterprise Apps join use) rather than running a `/applications` scan of
    // its own on every probe.
    let app_reg_index: Arc<HashMap<String, String>> = Arc::new(
        match crate::commands::applications::app_name_index_cached(&state, &client, &tenant_id)
            .await
        {
            Ok(apps) => apps
                .iter()
                .map(|a| (a.app_id.clone(), a.id.clone()))
                .collect(),
            Err(err) => {
                tracing::info!(
                    ?err,
                    "mailbox probe: application index unavailable; routing every row by SP object id"
                );
                HashMap::new()
            }
        },
    );

    let total = candidates.len();
    emit_progress(
        &app_handle,
        "mailbox-probe-progress",
        MailboxProbeProgress {
            done: 0,
            total,
            current_app: None,
            cancelled: false,
        },
    );

    let done = Arc::new(Mutex::new(0usize));
    let mailbox_shared = Arc::new(mailbox.clone());

    let mut rows: Vec<MailboxReacherRow> = Vec::new();
    let session = SessionDead::new();
    let mut cancelled = dispatch_capped(
        candidates,
        || PROBE_CONCURRENCY,
        |(principal_id, (display_name, held))| {
            // A dead session fails every remaining candidate identically —
            // stop dispatching rather than report a sweep that only looks
            // complete. In-flight probes still drain into `collect`.
            if cancel.is_cancelled() || session.is_dead() {
                return None;
            }
            let client = client.clone();
            let exo = exo.clone();
            let policies = policies.clone();
            let app_handle = app_handle.clone();
            let done = done.clone();
            let cancel_for_task = cancel.clone();
            let mailbox = mailbox_shared.clone();
            let prewarmed = sp_meta_by_principal.get(&principal_id).cloned();
            let app_reg_index = app_reg_index.clone();
            Some(tokio::spawn(async move {
                let ctx = ProbeContext {
                    client: &client,
                    exo: exo.as_deref(),
                    policies: policies.as_deref().map(Vec::as_slice),
                    mailbox: &mailbox,
                    app_reg_index: &app_reg_index,
                };
                let candidate = ProbeCandidate {
                    principal_id,
                    display_name,
                    held_permissions: held,
                    prewarmed,
                };
                let outcome = probe_candidate(&ctx, candidate).await;
                let mut guard = done.lock().await;
                *guard += 1;
                let progress = MailboxProbeProgress {
                    done: *guard,
                    total,
                    current_app: outcome.row.display_name.clone(),
                    cancelled: cancel_for_task.is_cancelled(),
                };
                drop(guard);
                emit_progress(&app_handle, "mailbox-probe-progress", progress);
                outcome
            }))
        },
        |joined| match joined {
            Ok(outcome) => {
                session.note_fatal(outcome.session_dead);
                rows.push(outcome.row);
            }
            Err(err) => tracing::warn!(?err, "mailbox probe: join error"),
        },
    )
    .await;
    if session.is_dead() {
        return Err(session.err("the mailbox reach sweep"));
    }
    cancelled = cancelled || cancel.is_cancelled();

    // Highest-reach first (`AccessVerdict::reach_rank`); names break ties so
    // the order is stable across runs.
    rows.sort_by(|a, b| {
        a.verdict
            .reach_rank()
            .cmp(&b.verdict.reach_rank())
            .then_with(|| a.display_name.cmp(&b.display_name))
    });

    Ok(MailboxReachersResult {
        tenant_id,
        mailbox,
        total_candidates: total,
        rows,
        exchange_available,
        exchange_sp_store_read,
        cancelled,
    })
}

/// Signals an in-progress [`find_mailbox_reachers`] probe to stop at the next
/// dispatch boundary.
#[tauri::command]
pub fn cancel_mailbox_probe(state: State<'_, AppState>) {
    state.mailbox_probe_cancel.cancel();
}

/// The reverse lookup's Entra-derived candidates: every service principal holding
/// a mail-scopable application permission on either mailbox resource, keyed by
/// SP object id → (display name, held values, sorted and deduped). `assigned`
/// is the `appRoleAssignedTo` rows of every resource in `resources`.
///
/// Each grant is resolved against the resource it was made on and gated with
/// the resource-carrying test, so Microsoft Graph's mail family and the EWS
/// `full_access_as_app` scope count while Office 365 Exchange Online's retired
/// Outlook REST `Mail.*` roles (which nothing can scope) do not.
fn mailbox_candidates(
    resources: &[ResourceRoles],
    assigned: Vec<AppRoleAssignment>,
) -> HashMap<String, (Option<String>, Vec<ResourcePermission>)> {
    let mut candidates: HashMap<String, (Option<String>, Vec<ResourcePermission>)> = HashMap::new();
    for a in assigned {
        if a.principal_type.as_deref() != Some("ServicePrincipal") {
            continue;
        }
        let Some((resource, _, value)) = resolve_grant(resources, &a.resource_id, &a.app_role_id)
        else {
            continue;
        };
        if !is_scopable_exchange_resource_permission(Some(resource), value) {
            continue;
        }
        // The resource stays attached for the legacy-policy gate.
        let held = ResourcePermission {
            resource_app_id: Some(resource.to_string()),
            value: value.to_string(),
        };
        candidates
            .entry(a.principal_id)
            .or_insert_with(|| (a.principal_display_name, Vec::new()))
            .1
            .push(held);
    }
    for (_, held) in candidates.values_mut() {
        sort_permissions(held);
    }
    candidates
}

/// Folds the Exchange-registered service principals into the candidate map
/// (keyed by SP object id). A principal already present — it holds an Entra
/// grant — keeps its richer entry; a new one enters with empty held
/// permissions, so its verdict can only come from the Exchange RBAC layer.
fn merge_exchange_candidates(
    candidates: &mut HashMap<String, (Option<String>, Vec<ResourcePermission>)>,
    exchange_sps: Vec<ExoServicePrincipal>,
) {
    for sp in exchange_sps {
        let Some(object_id) = sp.object_id else {
            continue;
        };
        candidates
            .entry(object_id)
            .or_insert((sp.display_name, Vec::new()));
    }
}

/// One candidate's row, plus whether the failure that produced it was
/// re-auth-fatal. The flag rides back on the value because the probe runs in a
/// spawned task: the error type itself doesn't survive that boundary, and a
/// dead session must stop the sweep rather than fill it with "unknown"
/// verdicts indistinguishable from genuine ones.
struct ProbeOutcome {
    row: MailboxReacherRow,
    session_dead: bool,
}

/// What stays the same for every candidate in one mailbox-reach sweep, grouped
/// so each [`probe_candidate`] call names only the candidate — the same
/// transposition reasoning as `exchange::ApplyExchangeMailboxScopeParams`.
struct ProbeContext<'a> {
    client: &'a GraphClient,
    exo: Option<&'a ExchangeClient>,
    /// The tenant's AAP list, pre-fetched once for the sweep.
    policies: Option<&'a [ExoApplicationAccessPolicy]>,
    mailbox: &'a str,
    /// appId -> app registration object id, for the row's Open routing.
    app_reg_index: &'a HashMap<String, String>,
}

/// The one principal a [`probe_candidate`] call is about.
struct ProbeCandidate {
    principal_id: String,
    display_name: Option<String>,
    /// The candidate's held Entra grants, already known from the index, each
    /// with its resource.
    held_permissions: Vec<ResourcePermission>,
    /// The batch-prewarmed `(appId, servicePrincipalType)`, when the prewarm
    /// covered this principal.
    prewarmed: Option<(String, Option<String>)>,
}

/// Probes one candidate principal against the mailbox — the same two-layer
/// union as [`test_mailbox_access`], with the candidate's held Entra grants
/// already known and the AAP list pre-fetched. Infallible by design — every
/// failure path lands in a verdict (`unknown` at worst) so one bad candidate
/// can't abort the whole probe.
async fn probe_candidate(ctx: &ProbeContext<'_>, candidate: ProbeCandidate) -> ProbeOutcome {
    let ProbeContext {
        client,
        exo,
        policies,
        mailbox,
        app_reg_index,
    } = *ctx;
    let ProbeCandidate {
        principal_id,
        display_name,
        held_permissions,
        prewarmed,
    } = candidate;
    // The Exchange cmdlets and the UI's deep links want the appId (and the
    // servicePrincipalType drives the row's Open routing), not the SP object id
    // the assignment row carries. Use the batch-prewarmed pair when we have it;
    // only fall back to a per-candidate Graph read when the prewarm missed this
    // principal (or its whole batch failed).
    let (app_id, service_principal_type) = match prewarmed {
        Some(meta) => meta,
        None => match client
            .get_service_principal_by_object_id(&principal_id)
            .await
        {
            Ok(Some(sp)) => (sp.app_id, sp.service_principal_type),
            other => {
                // A dead session fails every remaining candidate identically,
                // so the verdict "unknown" would be indistinguishable from a
                // genuine one. Report it up so the sweep stops.
                let session_dead = match other {
                    Err(err) => {
                        let ui = UiError::from(err);
                        tracing::info!(%principal_id, code = %ui.code, "mailbox probe: SP resolve failed");
                        ui.is_reauth_fatal()
                    }
                    // `Ok(None)`: the SP genuinely isn't there.
                    Ok(_) => false,
                };
                return ProbeOutcome {
                    session_dead,
                    row: MailboxReacherRow {
                        app_id: String::new(),
                        display_name,
                        held_permissions: permission_values(&held_permissions),
                        verdict: AccessVerdict::Unknown,
                        roles: Vec::new(),
                        detail: Some("Couldn't resolve the service principal.".into()),
                        // Can't confirm a local registration; route Open to the
                        // enterprise pane by SP object id (the reliable fallback).
                        principal_kind: AuditPrincipalKind::ServicePrincipal,
                        object_id: principal_id.clone(),
                        principal_id,
                    },
                };
            }
        },
    };

    let (principal_kind, object_id) = classify_reacher(
        &app_id,
        &principal_id,
        service_principal_type.as_deref(),
        app_reg_index,
    );

    let result = match exo {
        None => {
            let entra = if held_permissions.is_empty() {
                EntraReach::NotHeld
            } else {
                EntraReach::Unverified(permission_values(&held_permissions))
            };
            synthesize(mailbox, &entra, &RbacReach::Indeterminate)
        }
        Some(exo) => {
            let rbac = rbac_reach_for(
                exo,
                &app_id,
                mailbox,
                "mailbox probe: Exchange couldn't answer",
            )
            .await;
            // An Exchange-registration-only candidate has no Entra grant for
            // the AAP gate to constrain.
            let entra = if held_permissions.is_empty() {
                EntraReach::NotHeld
            } else {
                entra_reach(exo, &app_id, mailbox, held_permissions.clone(), policies).await
            };
            synthesize(mailbox, &entra, &rbac)
        }
    };
    ProbeOutcome {
        session_dead: false,
        row: MailboxReacherRow {
            app_id,
            principal_id,
            display_name,
            held_permissions: permission_values(&held_permissions),
            verdict: result.verdict,
            roles: result.roles,
            detail: result.detail,
            principal_kind,
            object_id,
        },
    }
}

/// Routes a reacher row to the right detail pane, mirroring the audit view's
/// `principal_kind` routing: a managed identity opens the MI pane; an appId that
/// resolves to a local application registration opens the App Registration pane
/// (by the *application* object id); everything else — a foreign-tenant
/// enterprise app or an orphaned SP — opens the enterprise pane by the SP object
/// id. Returns `(kind, object_id)` for the Open affordance.
fn classify_reacher(
    app_id: &str,
    principal_id: &str,
    service_principal_type: Option<&str>,
    app_reg_index: &HashMap<String, String>,
) -> (AuditPrincipalKind, String) {
    if service_principal_type == Some("ManagedIdentity") {
        (
            AuditPrincipalKind::ManagedIdentity,
            principal_id.to_string(),
        )
    } else if let Some(object_id) = app_reg_index.get(app_id) {
        (AuditPrincipalKind::Application, object_id.clone())
    } else {
        (
            AuditPrincipalKind::ServicePrincipal,
            principal_id.to_string(),
        )
    }
}

/// The SharePoint grants a principal holds on Microsoft Graph, read once.
///
/// Both halves matter: an org-wide `Sites.*` reaches every resource on its own,
/// while a Selected scope grants nothing by itself — it only lets a *permission
/// entry* on a resource take effect. An `Err` from [`sharepoint_grants_held`]
/// means the assignments couldn't be read, which is never the same as "holds
/// none" — [`site_verdict`] takes it as `None` and answers `unknown`. The
/// `Default` (nothing held) is what an app with no service principal gets.
#[derive(Default)]
struct HeldSharePointGrants {
    /// Org-wide `Sites.*` values (everything but `Sites.Selected`).
    orgwide: Vec<String>,
    /// Held Selected scope values, paired with the level each grants at.
    selected: Vec<(String, SelectedScopeLevel)>,
}

impl HeldSharePointGrants {
    /// Whether a permission entry found at `level` is actually backed by a scope
    /// in this principal's token. Reuses the grant path's own fail-closed level
    /// check, so the tester and the granter agree on which scope reaches what —
    /// including the one asymmetry (`ListItems.*` covers a file, `Files.*` does
    /// not cover a plain-list item).
    fn scope_for_level(&self, level: SelectedScopeLevel) -> Option<&str> {
        self.selected
            .iter()
            .find(|(_, held)| selected_scope_accepts(*held, level))
            .map(|(value, _)| value.as_str())
    }
}

/// Reads `app_id`'s granted app-roles on BOTH SharePoint-bearing resources
/// (Microsoft Graph and Office 365 SharePoint Online) and classifies the
/// SharePoint ones. An org-wide `Sites.*` on SharePoint Online (REST/CSOM)
/// reaches every site just as the Graph one does, so reading Graph alone let
/// such an app read as `no_access`; it is labelled with its resource so the
/// verdict names which API carries the reach. Selected scopes stay Graph-only
/// ([`selected_scope_level_for`]). An app with no service principal in the
/// tenant holds nothing (`Ok` of the empty default). `Err` when the SP lookup,
/// the Graph role index or the assignment list can't be read — the caller must
/// then report `unknown` rather than "no access".
async fn sharepoint_grants_held(
    client: &GraphClient,
    app_id: &str,
) -> Result<HeldSharePointGrants, UiError> {
    let Some(sp) = client.get_service_principal_by_app_id(app_id).await? else {
        return Ok(HeldSharePointGrants::default());
    };
    let resources = sharepoint_resource_roles(client).await?;
    let assignments = client.list_app_role_assignments(&sp.id).await?;

    let mut orgwide = Vec::new();
    let mut selected = Vec::new();
    for a in &assignments {
        let Some((resource, _, value)) = resolve_grant(&resources, &a.resource_id, &a.app_role_id)
        else {
            continue;
        };
        if is_sharepoint_orgwide_permission(Some(resource), value) {
            orgwide.push(if resource == OFFICE365_SHAREPOINT_ONLINE_APP_ID {
                format!("{value} (SharePoint Online)")
            } else {
                value.to_string()
            });
        } else if let Some(level) = selected_scope_level_for(Some(resource), value) {
            selected.push((value.to_string(), level));
        }
    }
    orgwide.sort();
    orgwide.dedup();
    Ok(HeldSharePointGrants { orgwide, selected })
}

/// One permission entry naming the tested app, and the securable it sits on.
struct EntryHit {
    level: SelectedScopeLevel,
    /// Human label for the securable the entry is on — the same securable when
    /// the entry is on the target, an ancestor when it was inherited.
    where_label: String,
    roles: Vec<String>,
}

/// The roles `app_id` is granted by `perms`, or `None` when no entry names it.
fn roles_for_app(perms: &[SelectedPermission], app_id: &str) -> Option<Vec<String>> {
    let mut roles: Vec<String> = perms
        .iter()
        .filter(|p| p.app_id().is_some_and(|id| id.eq_ignore_ascii_case(app_id)))
        .flat_map(|p| p.roles.clone())
        .collect();
    if roles.is_empty() {
        return None;
    }
    roles.sort();
    roles.dedup();
    Some(roles)
}

/// Walks the securable chain from `resolved` up to its site collection, looking
/// for a permission entry naming `app_id`. Nearest match wins.
///
/// Walking upward is not an optimization — it is how SharePoint answers the
/// question. Microsoft's access calculation finds the application record "on the
/// resource **or a securable hierarchical parent**", so a file with no entry of
/// its own is still reachable through the library's or the site collection's.
/// Reading only the exact URL would report "no access" for access that exists.
async fn find_entry_in_chain(
    client: &azapptoolkit_graph::GraphClient,
    resolved: &ResolvedSharePointResource,
    app_id: &str,
) -> Result<Option<EntryHit>, UiError> {
    let site_label = resolved
        .site_name
        .clone()
        .or_else(|| resolved.site_url.clone())
        .unwrap_or_else(|| resolved.site_id.clone());

    // 1. The item itself (a folder or a file).
    if let (Some(list_id), Some(item_id)) =
        (resolved.list_id.as_deref(), resolved.item_id.as_deref())
    {
        let perms = client
            .list_list_item_permissions(&resolved.site_id, list_id, item_id)
            .await
            .map_err(sharepoint_item_err)?;
        if let Some(roles) = roles_for_app(&perms, app_id) {
            return Ok(Some(EntryHit {
                level: resolved.level,
                where_label: resolved.display_path.clone(),
                roles,
            }));
        }
    }

    // 2. The list / document library holding it.
    if let Some(list_id) = resolved.list_id.as_deref() {
        let perms = client
            .list_list_permissions(&resolved.site_id, list_id)
            .await
            .map_err(sharepoint_item_err)?;
        if let Some(roles) = roles_for_app(&perms, app_id) {
            return Ok(Some(EntryHit {
                level: SelectedScopeLevel::List,
                where_label: resolved
                    .list_name
                    .clone()
                    .unwrap_or_else(|| "the list".to_string()),
                roles,
            }));
        }
    }

    // 3. The site collection — the root of inheritance.
    let perms = client
        .list_site_permissions(&resolved.site_id)
        .await
        .map_err(sharepoint_item_err)?;
    let mut roles: Vec<String> = perms
        .into_iter()
        .filter(|p| {
            p.granted_to_identities.iter().any(|s| {
                s.application
                    .as_ref()
                    .and_then(|a| a.id.as_deref())
                    .map(|id| id.eq_ignore_ascii_case(app_id))
                    .unwrap_or(false)
            })
        })
        .flat_map(|p| p.roles)
        .collect();
    roles.sort();
    roles.dedup();
    if roles.is_empty() {
        return Ok(None);
    }
    Ok(Some(EntryHit {
        level: SelectedScopeLevel::Site,
        where_label: site_label,
        roles,
    }))
}

/// Tests whether `app_id` can access the SharePoint resource at `site_url` — a
/// site collection, a list or document library, a folder, or a single file.
///
/// Three access paths, in the order SharePoint itself resolves them:
///
/// 1. An org-wide `Sites.*` (≠ `Sites.Selected`) app-role grant reaches every
///    resource regardless of per-resource permissions.
/// 2. A permission entry naming the app, on the target **or any securable
///    parent** ([`find_entry_in_chain`]).
/// 3. …which only takes effect if the app also holds a Selected scope reaching
///    that level. Microsoft's model needs all three of consent, entry, and token
///    scope; miss one and the app has no access. An entry without the scope is
///    the most common half-finished state, so it is reported as `no_access` with
///    the missing half named, never as access the app doesn't have.
///
/// Pre-acquires `Sites.FullControl.All` so a missing-consent rejection surfaces
/// as `consent_required` (the page shows a "Grant consent" button) — the
/// permission endpoints require it even for reads, at every level.
#[tauri::command]
pub async fn test_site_access(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    site_url: String,
) -> Result<PermissionTestResult, UiError> {
    let client = sharepoint_client_checked(&state, &tenant_id).await?;

    // Read the principal's grants once — both paths below need them, and a
    // failure here must not be read as "holds nothing".
    let held = match sharepoint_grants_held(&client, &app_id).await {
        Ok(h) => Some(h),
        // A dead session re-authenticates in place rather than reading as an
        // inconclusive test.
        Err(e) if e.is_reauth_fatal() => return Err(e),
        Err(e) => {
            tracing::info!(code = %e.code, "site test: app-role assignments unreadable");
            None
        }
    };

    let resolved = client
        .resolve_sharepoint_resource(&site_url)
        .await
        .map_err(sharepoint_item_err)?;
    let label = resolved.display_path.clone();

    // Path 1 (org-wide) needs no entry at all, so the chain walk is skipped.
    let hit = if held.as_ref().is_some_and(|h| !h.orgwide.is_empty()) {
        None
    } else {
        find_entry_in_chain(&client, &resolved, &app_id).await?
    };
    Ok(site_verdict(held.as_ref(), hit, label))
}

/// Folds the three SharePoint access paths into one verdict. `held` is `None`
/// when the app's app-role assignments couldn't be read — that is never "holds
/// none", so every branch that would lean on it answers `unknown`. `hit` is the
/// nearest permission entry naming the app on the target or an ancestor.
///
/// | held                | hit    | verdict                                  |
/// |---------------------|--------|------------------------------------------|
/// | org-wide `Sites.*`  | any    | `org_wide`                               |
/// | unreadable          | none   | `unknown`                                |
/// | readable            | none   | `no_access`                              |
/// | unreadable          | entry  | `unknown`                                |
/// | matching scope      | entry  | `scoped`                                 |
/// | no matching scope   | entry  | `no_access`, naming the scope it needs   |
fn site_verdict(
    held: Option<&HeldSharePointGrants>,
    hit: Option<EntryHit>,
    label: String,
) -> PermissionTestResult {
    // Path 1: org-wide, which needs no entry at all.
    if let Some(h) = held
        && !h.orgwide.is_empty()
    {
        return PermissionTestResult {
            has_access: true,
            verdict: AccessVerdict::OrgWide,
            roles: h.orgwide.clone(),
            detail: Some(format!(
                "The app holds an organization-wide SharePoint permission and can access “{label}” (and every other site, library and file in the tenant)."
            )),
            resource_label: label,
        };
    }

    // Path 2: a permission entry on the target or an ancestor.
    let Some(hit) = hit else {
        return match held {
            None => PermissionTestResult {
                has_access: false,
                verdict: AccessVerdict::Unknown,
                roles: Vec::new(),
                detail: Some(format!(
                    "No permission entry names this app on “{label}” or anything above it, but its app-role assignments couldn't be read, so whether it holds an organization-wide SharePoint grant is unknown."
                )),
                resource_label: label,
            },
            Some(_) => PermissionTestResult {
                has_access: false,
                verdict: AccessVerdict::NoAccess,
                roles: Vec::new(),
                detail: Some(format!(
                    "No permission entry names this app on “{label}” or anything above it, and it holds no organization-wide SharePoint grant."
                )),
                resource_label: label,
            },
        };
    };

    let inherited = hit.where_label != label;
    let via = if inherited {
        format!(" (inherited from “{}”)", hit.where_label)
    } else {
        String::new()
    };

    // Path 3: the entry only bites if the token can carry a scope for its level.
    let Some(held) = held else {
        return PermissionTestResult {
            has_access: false,
            verdict: AccessVerdict::Unknown,
            roles: hit.roles,
            detail: Some(format!(
                "“{label}” grants this app access{via}, but its app-role assignments couldn't be read, so whether it holds the matching Selected scope is unknown."
            )),
            resource_label: label,
        };
    };

    match held.scope_for_level(hit.level) {
        Some(scope) => PermissionTestResult {
            has_access: true,
            verdict: AccessVerdict::Scoped,
            roles: hit.roles,
            detail: Some(format!(
                "The app is granted access to “{label}” specifically{via}, and holds {scope} — the Selected model's grant and scope halves are both in place."
            )),
            resource_label: label,
        },
        None => PermissionTestResult {
            has_access: false,
            verdict: AccessVerdict::NoAccess,
            roles: hit.roles,
            detail: Some(format!(
                "“{label}” grants this app access{via}, but the app doesn't hold a Selected permission reaching {}. A permission entry alone grants nothing until the matching scope is in the app's token — grant {} as well.",
                level_noun(hit.level),
                required_scope_for(hit.level),
            )),
            resource_label: label,
        },
    }
}

/// The securable a level names, for the "doesn't reach …" sentence.
fn level_noun(level: SelectedScopeLevel) -> &'static str {
    match level {
        SelectedScopeLevel::Site => "a site collection",
        SelectedScopeLevel::List => "a list or document library",
        SelectedScopeLevel::ListItem => "a list item or folder",
        SelectedScopeLevel::File => "a file",
    }
}

/// The Selected scope an entry at `level` needs in the token to take effect.
fn required_scope_for(level: SelectedScopeLevel) -> &'static str {
    match level {
        SelectedScopeLevel::Site => SP_SITES_SELECTED,
        SelectedScopeLevel::List => SP_LISTS_SELECTED,
        SelectedScopeLevel::ListItem => SP_LIST_ITEMS_SELECTED,
        SelectedScopeLevel::File => SP_FILES_SELECTED,
    }
}

/// Exports the (frontend-filtered) mailbox-reacher rows to CSV/JSON via the OS
/// save dialog. Returns the path, or `None` if the user cancelled.
///
/// "Which apps can read this mailbox?" is the answer an operator is asked to put
/// in writing after an incident, and until this existed the only way out of the
/// app was a screenshot. The rows come from the frontend because the view's
/// filter does — confirmed "No access" rows are hidden by default, and the
/// export follows what is on screen.
///
/// `summary` is that panel's own coverage sentence, and here it is the whole
/// point: an `unknown` verdict means an Exchange RBAC check could not be
/// evaluated, and when Exchange is unavailable altogether the verdicts derive
/// from the Entra grants alone. Both caveats are stated on screen and both must
/// travel with the file, or a partial probe reads as an audited all-clear.
#[tauri::command]
pub async fn save_mailbox_reachers_to_file(
    app_handle: AppHandle,
    rows: Vec<MailboxReacherRow>,
    summary: String,
    format: String,
) -> Result<Option<String>, UiError> {
    crate::commands::export::save_export_via_dialog(
        &app_handle,
        "mailbox-reachers",
        &format,
        || mailbox_reachers_to_csv(&rows, &summary),
        || coverage_json(&summary, &rows),
    )
    .await
}

/// Serializes mailbox-reacher rows as CSV under the shared coverage comment
/// block. Display names and Exchange-supplied detail are directory data, so
/// every field is routed through `csv_field` (formula-injection guard +
/// delimiter quoting).
fn mailbox_reachers_to_csv(rows: &[MailboxReacherRow], summary: &str) -> String {
    let mut out = coverage_comment_block(
        "azapptoolkit — mailbox reachers (Entra grant ∪ Exchange RBAC)",
        summary,
    );
    out.push_str(
        "Application,AppId,Verdict,HeldPermissions,ExchangeRoles,Detail,PrincipalKind,ObjectId\n",
    );
    for r in rows {
        let row = [
            csv_field(r.display_name.as_deref().unwrap_or("")),
            csv_field(&r.app_id),
            csv_field(r.verdict.as_str()),
            // Semicolon-joined into one cell each: a comma would split the row.
            csv_field(&r.held_permissions.join("; ")),
            csv_field(&r.roles.join("; ")),
            csv_field(r.detail.as_deref().unwrap_or("")),
            csv_field(r.principal_kind.as_str()),
            csv_field(&r.object_id),
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
    use crate::commands::export::csv_columns;
    use azapptoolkit_core::cache::Cache;
    use azapptoolkit_core::models::{SiteIdentity, SiteIdentitySet};
    use azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;
    use azapptoolkit_core::scoping::{EWS_FULL_ACCESS_AS_APP, OFFICE365_EXCHANGE_ONLINE_APP_ID};
    use azapptoolkit_core::token::{BearerProvider, StaticTokenProvider};

    fn reacher(name: &str, verdict: AccessVerdict) -> MailboxReacherRow {
        MailboxReacherRow {
            app_id: "11111111-1111-1111-1111-111111111111".into(),
            principal_id: "22222222-2222-2222-2222-222222222222".into(),
            display_name: Some(name.into()),
            held_permissions: vec!["Mail.Read".into(), "Mail.Send".into()],
            verdict,
            roles: vec!["Application Mail.Read".into()],
            detail: Some("Org-wide Graph grant, unconstrained by any policy".into()),
            principal_kind: AuditPrincipalKind::Application,
            object_id: "33333333-3333-3333-3333-333333333333".into(),
        }
    }

    #[test]
    fn reacher_csv_leads_with_the_coverage_line_then_a_header_and_one_row_each() {
        let csv = mailbox_reachers_to_csv(
            &[
                reacher("Contoso API", AccessVerdict::OrgWide),
                reacher("Fabrikam Web", AccessVerdict::Unknown),
            ],
            "1 of 12 candidate apps can reach “shared@contoso.com” · 1 couldn’t be confirmed (need Exchange admin rights)",
        );
        let lines: Vec<&str> = csv.lines().collect();
        // An unconfirmed verdict is possible access, not noise — the caveat has
        // to reach whoever reads the file, not just whoever ran the probe.
        assert!(lines[1].contains("couldn’t be confirmed"));
        let header = lines
            .iter()
            .position(|l| l.starts_with("Application,"))
            .unwrap();
        assert_eq!(lines.len() - header, 3); // header + 2 rows
        assert!(lines[header + 1].starts_with("Contoso API,"));
    }

    #[test]
    fn reacher_csv_keeps_held_permissions_in_one_cell() {
        // Comma-joining them would silently shift every column right of them —
        // as would the Exchange-supplied `detail` prose, which routinely
        // contains commas of its own, so the count is quote-aware.
        let csv = mailbox_reachers_to_csv(
            &[reacher("Contoso API", AccessVerdict::OrgWide)],
            "complete",
        );
        assert!(csv.contains("Mail.Read; Mail.Send"));
        let header = csv
            .lines()
            .position(|l| l.starts_with("Application,"))
            .unwrap();
        let columns = csv_columns(csv.lines().nth(header).unwrap());
        assert_eq!(csv_columns(csv.lines().nth(header + 1).unwrap()), columns);
    }

    #[test]
    fn reacher_csv_neutralizes_formula_injection_in_a_display_name() {
        // CWE-1236: app display names are attacker-controllable directory data.
        // The comma in the payload is the point: neutralization has to compose
        // with quoting.
        let csv = mailbox_reachers_to_csv(
            &[reacher("=cmd|'/c calc',A1", AccessVerdict::OrgWide)],
            "complete",
        );
        assert!(csv.contains("\"'=cmd|'/c calc',A1\""));
    }

    // The Open affordance's routing: an SP-only reacher must never resolve to an
    // app-registration object id (opening one would `get_application` → 404), and
    // a local app registration must open by its *application* object id, not the
    // SP object id.
    #[test]
    fn classify_reacher_routes_by_kind() {
        let mut index = HashMap::new();
        index.insert("local-app".to_string(), "app-object-1".to_string());

        // A managed identity always routes to the MI pane by its SP object id.
        assert_eq!(
            classify_reacher("mi-app", "sp-mi", Some("ManagedIdentity"), &index),
            (AuditPrincipalKind::ManagedIdentity, "sp-mi".to_string())
        );
        // A local app registration routes to the App Registration pane by the
        // application object id (not the SP object id).
        assert_eq!(
            classify_reacher("local-app", "sp-local", Some("Application"), &index),
            (AuditPrincipalKind::Application, "app-object-1".to_string())
        );
        // A foreign enterprise app (no local registration) routes to the
        // enterprise pane by SP object id — the security-relevant boundary.
        assert_eq!(
            classify_reacher("foreign-app", "sp-foreign", Some("Application"), &index),
            (
                AuditPrincipalKind::ServicePrincipal,
                "sp-foreign".to_string()
            )
        );
        // An Exchange-only candidate (no servicePrincipalType, no local reg) also
        // falls back to the SP object id.
        assert_eq!(
            classify_reacher("x", "sp-x", None, &index),
            (AuditPrincipalKind::ServicePrincipal, "sp-x".to_string())
        );
    }

    fn row(
        role: &str,
        scope_type: &str,
        allowed: &str,
        in_scope: Option<bool>,
    ) -> ExoAuthorizationResult {
        ExoAuthorizationResult {
            role_name: Some(role.into()),
            granted_permissions: None,
            allowed_resource_scope: Some(allowed.into()),
            scope_type: Some(scope_type.into()),
            in_scope,
        }
    }

    fn scoped_row(in_scope: Option<bool>) -> ExoAuthorizationResult {
        row(
            "Application Mail.Read",
            "CustomRecipientScope",
            "azapptoolkit_app-1",
            in_scope,
        )
    }

    // The bug behind "Has access — scoped" for an out-of-scope mailbox: the
    // cmdlet returns a row per assignment regardless of coverage, and only
    // `InScope = true` rows grant access.
    #[test]
    fn out_of_scope_rows_grant_nothing() {
        let reach = rbac_reach_from_rows(&[scoped_row(Some(false))]);
        assert!(matches!(
            reach,
            RbacReach::None {
                had_assignments: true
            }
        ));
        let result = synthesize("a@x.com", &EntraReach::NotHeld, &reach);
        assert!(!result.has_access);
        assert_eq!(result.verdict, AccessVerdict::NoAccess);
        assert!(result.detail.unwrap().contains("InScope = false"));
    }

    #[test]
    fn in_scope_scoped_row_grants_scoped_access() {
        let reach = rbac_reach_from_rows(&[scoped_row(Some(true)), scoped_row(Some(false))]);
        assert!(matches!(reach, RbacReach::Scoped(_)));
        let result = synthesize("a@x.com", &EntraReach::NotHeld, &reach);
        assert!(result.has_access);
        assert_eq!(result.verdict, AccessVerdict::Scoped);
        assert_eq!(result.roles, vec!["Application Mail.Read".to_string()]);
    }

    #[test]
    fn in_scope_org_row_is_org_wide() {
        let reach = rbac_reach_from_rows(&[row(
            "Application Mail.Read",
            "Organization",
            "Organization",
            Some(true),
        )]);
        assert!(matches!(reach, RbacReach::OrgWide(_)));
        assert_eq!(
            synthesize("a@x.com", &EntraReach::NotHeld, &reach).verdict,
            AccessVerdict::OrgWide
        );
    }

    #[test]
    fn missing_in_scope_boolean_is_indeterminate_not_access() {
        // A `-Resource` was supplied, so a row without the boolean means the
        // membership check didn't run — never read it as a grant.
        let reach = rbac_reach_from_rows(&[scoped_row(None)]);
        assert!(matches!(reach, RbacReach::Indeterminate));
        let result = synthesize("a@x.com", &EntraReach::NotHeld, &reach);
        assert!(!result.has_access);
        assert_eq!(result.verdict, AccessVerdict::Unknown);
    }

    #[test]
    fn empty_rows_are_no_access_without_assignments() {
        assert!(matches!(
            rbac_reach_from_rows(&[]),
            RbacReach::None {
                had_assignments: false
            }
        ));
    }

    // Microsoft's union semantics: an un-stripped org-wide Entra grant defeats
    // the Exchange RBAC scope, so the out-of-scope mailbox IS reachable — and
    // the detail must say why and how to fix it.
    #[test]
    fn unstripped_entra_grant_overrides_rbac_scope() {
        let result = synthesize(
            "a@x.com",
            &EntraReach::OrgWide(vec!["Mail.Read".into()]),
            &RbacReach::None {
                had_assignments: true,
            },
        );
        assert!(result.has_access);
        assert_eq!(result.verdict, AccessVerdict::OrgWide);
        let detail = result.detail.unwrap();
        assert!(detail.contains("ineffective"));
        assert!(detail.contains("remove the Entra application permission"));
    }

    #[test]
    fn aap_denied_with_no_rbac_is_no_access() {
        let result = synthesize(
            "a@x.com",
            &EntraReach::DeniedByAap,
            &RbacReach::None {
                had_assignments: false,
            },
        );
        assert!(!result.has_access);
        assert_eq!(result.verdict, AccessVerdict::NoAccess);
        assert!(
            result
                .detail
                .unwrap()
                .contains("blocked for “a@x.com” by a legacy Application Access Policy")
        );
    }

    #[test]
    fn aap_restrict_membership_is_scoped() {
        let result = synthesize(
            "a@x.com",
            &EntraReach::ScopedByAap {
                perms: vec!["Mail.Read".into()],
                scope_name: Some("Sales".into()),
            },
            &RbacReach::None {
                had_assignments: false,
            },
        );
        assert!(result.has_access);
        assert_eq!(result.verdict, AccessVerdict::Scoped);
        assert!(result.detail.unwrap().contains("Sales"));
    }

    // Exchange fully unreachable but an org-wide Entra grant held: org-wide
    // with the AAP caveat (the never-under-report posture), not "unknown".
    #[test]
    fn unverified_aap_reports_org_wide_with_caveat() {
        let result = synthesize(
            "a@x.com",
            &EntraReach::Unverified(vec!["Mail.Read".into()]),
            &RbacReach::Indeterminate,
        );
        assert!(result.has_access);
        assert_eq!(result.verdict, AccessVerdict::OrgWide);
        assert!(result.detail.unwrap().contains("couldn't be verified"));
    }

    // An RBAC grant is definite even when the Entra path is blocked by an AAP.
    #[test]
    fn rbac_scope_survives_aap_denial() {
        let result = synthesize(
            "a@x.com",
            &EntraReach::DeniedByAap,
            &RbacReach::Scoped(vec!["Application Mail.Read".into()]),
        );
        assert!(result.has_access);
        assert_eq!(result.verdict, AccessVerdict::Scoped);
    }

    fn exo_sp(object_id: Option<&str>, name: &str) -> ExoServicePrincipal {
        ExoServicePrincipal {
            object_id: object_id.map(Into::into),
            app_id: Some("app-x".into()),
            display_name: Some(name.into()),
            identity: None,
        }
    }

    // RBAC-only principals (no Graph app-role assignment) enter as candidates
    // with empty held permissions; Graph-derived entries are never clobbered.
    #[test]
    fn merge_exchange_candidates_adds_new_and_keeps_graph_entries() {
        let mut candidates: HashMap<String, (Option<String>, Vec<ResourcePermission>)> =
            HashMap::from([
                (
                    "obj-1".to_string(),
                    (
                        Some("From Graph".to_string()),
                        vec![ResourcePermission::graph("Mail.Read")],
                    ),
                ),
                // An EWS-only holder found on the Office 365 Exchange Online SP.
                (
                    "obj-ews".to_string(),
                    (
                        Some("EWS app".to_string()),
                        vec![ResourcePermission::exchange_online(EWS_FULL_ACCESS_AS_APP)],
                    ),
                ),
            ]);
        merge_exchange_candidates(
            &mut candidates,
            vec![
                exo_sp(Some("obj-1"), "From Exchange"),
                exo_sp(Some("obj-2"), "RBAC only"),
                exo_sp(Some("obj-ews"), "EWS app (Exchange)"),
                exo_sp(None, "No object id"),
            ],
        );
        assert_eq!(candidates.len(), 3);
        let kept = &candidates["obj-1"];
        assert_eq!(kept.0.as_deref(), Some("From Graph"));
        assert_eq!(permission_values(&kept.1), vec!["Mail.Read".to_string()]);
        // The EWS grant survives the merge — an Exchange-store duplicate must
        // not reset it to "holds nothing" (which would probe as `no_access`).
        let ews = &candidates["obj-ews"];
        assert_eq!(ews.0.as_deref(), Some("EWS app"));
        assert_eq!(
            permission_values(&ews.1),
            vec![EWS_FULL_ACCESS_AS_APP.to_string()]
        );
        let added = &candidates["obj-2"];
        assert_eq!(added.0.as_deref(), Some("RBAC only"));
        assert!(added.1.is_empty());
    }

    // ── Candidate discovery across BOTH mailbox resources ─────────────────

    fn mailbox_resources() -> Vec<ResourceRoles> {
        vec![
            ResourceRoles {
                app_id: MICROSOFT_GRAPH_APP_ID,
                sp_object_id: "graph-sp".to_string(),
                role_value_by_id: [
                    ("role-mail-read".to_string(), "Mail.Read".to_string()),
                    ("role-user".to_string(), "User.Read.All".to_string()),
                ]
                .into(),
            },
            ResourceRoles {
                app_id: OFFICE365_EXCHANGE_ONLINE_APP_ID,
                sp_object_id: "exo-sp".to_string(),
                role_value_by_id: [
                    ("role-ews".to_string(), EWS_FULL_ACCESS_AS_APP.to_string()),
                    // The retired Outlook REST role, which nothing can scope.
                    ("role-exo-mail".to_string(), "Mail.Read".to_string()),
                ]
                .into(),
            },
        ]
    }

    fn assigned(principal: &str, kind: &str, resource: &str, role: &str) -> AppRoleAssignment {
        AppRoleAssignment {
            id: format!("{principal}-{role}"),
            principal_id: principal.into(),
            resource_id: resource.into(),
            app_role_id: role.into(),
            principal_display_name: Some(format!("{principal} name")),
            principal_type: Some(kind.into()),
            ..Default::default()
        }
    }

    // An app whose only mailbox grant is `full_access_as_app` reaches every
    // mailbox over EWS; the Graph-only sweep never listed it.
    #[test]
    fn mailbox_candidates_include_an_ews_only_holder() {
        let sp = "ServicePrincipal";
        let candidates = mailbox_candidates(
            &mailbox_resources(),
            vec![
                assigned("sp-1", sp, "graph-sp", "role-mail-read"),
                assigned("sp-2", sp, "exo-sp", "role-ews"),
                assigned("sp-3", sp, "exo-sp", "role-exo-mail"),
                assigned("sp-4", sp, "graph-sp", "role-user"),
                assigned("user-1", "User", "graph-sp", "role-mail-read"),
                assigned("sp-5", sp, "exo-sp", "role-ews"),
                assigned("sp-5", sp, "graph-sp", "role-mail-read"),
                assigned("sp-5", sp, "exo-sp", "role-ews"),
            ],
        );
        assert_eq!(
            candidates["sp-1"].1,
            vec![ResourcePermission::graph("Mail.Read")]
        );
        assert_eq!(candidates["sp-1"].0.as_deref(), Some("sp-1 name"));
        assert_eq!(
            candidates["sp-2"].1,
            vec![ResourcePermission::exchange_online(EWS_FULL_ACCESS_AS_APP)]
        );
        // Sorted and deduped across both resources, each keeping its resource.
        assert_eq!(
            candidates["sp-5"].1,
            vec![
                ResourcePermission::graph("Mail.Read"),
                ResourcePermission::exchange_online(EWS_FULL_ACCESS_AS_APP)
            ]
        );
        // The retired Outlook REST role, a non-mail role and a user are out.
        assert!(!candidates.contains_key("sp-3"));
        assert!(!candidates.contains_key("sp-4"));
        assert!(!candidates.contains_key("user-1"));
        assert_eq!(candidates.len(), 3);
    }

    // ── A legacy policy answers only for what it governs ─────────────────

    /// `MailboxItem.ReadWrite.All` is RBAC-scopable but no Application Access
    /// Policy ever confined it, so a policy naming the app must not answer for
    /// it: the grant reaches every mailbox. Decided before any Exchange call —
    /// the client points nowhere, so reaching it would fail the test.
    #[tokio::test]
    async fn a_policy_does_not_answer_for_an_rbac_only_grant() {
        use azapptoolkit_core::token::StaticTokenProvider;
        let exo = ExchangeClient::with_base_url(
            StaticTokenProvider::new("t"),
            "tenant-1",
            "admin@contoso.com",
            "http://127.0.0.1:9".to_string(),
        );
        let policies: Vec<ExoApplicationAccessPolicy> = serde_json::from_value(serde_json::json!([
            { "Identity": "p", "AppId": "app-1", "ScopeName": "Sales", "AccessRight": "RestrictAccess" }
        ]))
        .unwrap();
        let held = vec![
            ResourcePermission::graph("Mail.Read"),
            ResourcePermission::graph("MailboxItem.ReadWrite.All"),
        ];
        match entra_reach(&exo, "app-1", "a@x.com", held, Some(&policies)).await {
            EntraReach::OrgWide(perms) => {
                assert_eq!(perms, vec!["MailboxItem.ReadWrite.All".to_string()]);
            }
            _ => panic!("an ungoverned grant must read org-wide"),
        }
        // A grant with no resolved resource is never governed either.
        let unresolved = vec![ResourcePermission {
            resource_app_id: None,
            value: "Mail.Read".into(),
        }];
        assert!(matches!(
            entra_reach(&exo, "app-1", "a@x.com", unresolved, Some(&policies)).await,
            EntraReach::OrgWide(_)
        ));
    }

    // ── A failed Entra read is `unknown`, never "No access" ───────────────

    #[test]
    fn an_unreadable_entra_grant_is_unknown_not_no_access() {
        let result = synthesize(
            "a@x.com",
            &EntraReach::Unreadable,
            &RbacReach::None {
                had_assignments: false,
            },
        );
        assert_eq!(result.verdict, AccessVerdict::Unknown);
        assert!(!result.has_access);
        let detail = result.detail.unwrap();
        assert!(detail.contains("couldn't be read"));
        assert!(!detail.contains("No organization-wide Graph mailbox permission is granted"));
    }

    #[test]
    fn an_rbac_scope_still_decides_when_entra_is_unreadable() {
        let scoped = synthesize(
            "a@x.com",
            &EntraReach::Unreadable,
            &RbacReach::Scoped(vec!["Application Mail.Read".into()]),
        );
        assert_eq!(scoped.verdict, AccessVerdict::Scoped);
        assert!(scoped.has_access);
        let org = synthesize(
            "a@x.com",
            &EntraReach::Unreadable,
            &RbacReach::OrgWide(vec!["Application Mail.Read".into()]),
        );
        assert_eq!(org.verdict, AccessVerdict::OrgWide);
    }

    fn graph_over(server: &wiremock::MockServer) -> GraphClient {
        let token: Arc<dyn BearerProvider> = StaticTokenProvider::new("tok");
        GraphClient::with_base_url(
            "tenant-test",
            token.clone(),
            token,
            Cache::new(),
            server.uri(),
        )
    }

    async fn mock_sp_lookup(server: &wiremock::MockServer, response: wiremock::ResponseTemplate) {
        use wiremock::matchers::{method, path, query_param};
        wiremock::Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .and(query_param("$filter", "appId eq 'app-1'"))
            .respond_with(response)
            .mount(server)
            .await;
    }

    // The fixture the tri-state exists for: a Graph read error must come back
    // as an error (→ `EntraReach::Unreadable`), not as an empty grant list.
    #[tokio::test]
    async fn a_failed_sp_lookup_is_an_unreadable_mailbox_grant() {
        let server = wiremock::MockServer::start().await;
        // `Retry-After: 0` keeps the retry budget from sleeping out its backoff.
        mock_sp_lookup(
            &server,
            wiremock::ResponseTemplate::new(503).insert_header("Retry-After", "0"),
        )
        .await;
        let client = graph_over(&server);
        assert!(orgwide_mailbox_grant(&client, "app-1").await.is_err());
        assert!(sharepoint_grants_held(&client, "app-1").await.is_err());
    }

    // An app with no service principal in the tenant genuinely holds nothing.
    #[tokio::test]
    async fn an_absent_sp_holds_no_grant() {
        let server = wiremock::MockServer::start().await;
        mock_sp_lookup(
            &server,
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})),
        )
        .await;
        let client = graph_over(&server);
        assert_eq!(
            orgwide_mailbox_grant(&client, "app-1").await.unwrap(),
            Vec::<ResourcePermission>::new()
        );
        let held = sharepoint_grants_held(&client, "app-1").await.unwrap();
        assert!(held.orgwide.is_empty() && held.selected.is_empty());
    }

    // An org-wide `Sites.*` on Office 365 SharePoint Online (REST/CSOM) reaches
    // every site as surely as the Graph one; reading Graph alone let such an app
    // read as `no_access`. The same value on each resource is kept apart.
    #[tokio::test]
    async fn an_orgwide_sites_grant_on_sharepoint_online_is_held() {
        use wiremock::matchers::{method, path, query_param};
        let server = wiremock::MockServer::start().await;
        let sp_by_app_id = |app_id: &str, body: serde_json::Value| {
            wiremock::Mock::given(method("GET"))
                .and(path("/servicePrincipals"))
                .and(query_param("$filter", format!("appId eq '{app_id}'")))
                .respond_with(
                    wiremock::ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "value": [body] })),
                )
        };
        sp_by_app_id(
            "app-1",
            serde_json::json!({"id": "sp-app", "appId": "app-1"}),
        )
        .mount(&server)
        .await;
        sp_by_app_id(
            MICROSOFT_GRAPH_APP_ID,
            serde_json::json!({"id": "sp-graph", "appId": MICROSOFT_GRAPH_APP_ID,
                "appRoles": [{"id": "r-graph-sel", "value": "Sites.Selected"}]}),
        )
        .mount(&server)
        .await;
        sp_by_app_id(
            OFFICE365_SHAREPOINT_ONLINE_APP_ID,
            serde_json::json!({"id": "sp-spo", "appId": OFFICE365_SHAREPOINT_ONLINE_APP_ID,
                "appRoles": [{"id": "r-spo-full", "value": "Sites.FullControl.All"}]}),
        )
        .mount(&server)
        .await;
        wiremock::Mock::given(method("GET"))
            .and(path("/servicePrincipals/sp-app/appRoleAssignments"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"value": [
                    {"id": "a1", "principalId": "sp-app", "resourceId": "sp-spo", "appRoleId": "r-spo-full"},
                    {"id": "a2", "principalId": "sp-app", "resourceId": "sp-graph", "appRoleId": "r-graph-sel"}
                ]}),
            ))
            .mount(&server)
            .await;
        let held = sharepoint_grants_held(&graph_over(&server), "app-1")
            .await
            .unwrap();
        assert_eq!(
            held.orgwide,
            vec!["Sites.FullControl.All (SharePoint Online)"]
        );
        assert_eq!(
            held.selected,
            vec![("Sites.Selected".to_string(), SelectedScopeLevel::Site)]
        );
    }

    // ── The SharePoint verdict table ──────────────────────────────────────

    fn held(orgwide: &[&str], selected: &[(&str, SelectedScopeLevel)]) -> HeldSharePointGrants {
        HeldSharePointGrants {
            orgwide: orgwide.iter().map(|s| s.to_string()).collect(),
            selected: selected.iter().map(|(v, l)| (v.to_string(), *l)).collect(),
        }
    }

    fn hit(level: SelectedScopeLevel, where_label: &str) -> EntryHit {
        EntryHit {
            level,
            where_label: where_label.into(),
            roles: vec!["read".into()],
        }
    }

    const LABEL: &str = "Contoso / Docs / plan.docx";

    #[test]
    fn site_verdict_org_wide_wins_over_any_entry() {
        let h = held(&["Sites.Read.All"], &[]);
        let r = site_verdict(
            Some(&h),
            Some(hit(SelectedScopeLevel::Site, "Contoso")),
            LABEL.into(),
        );
        assert_eq!(r.verdict, AccessVerdict::OrgWide);
        assert!(r.has_access);
        assert_eq!(r.roles, vec!["Sites.Read.All".to_string()]);
    }

    // The F055 regression: no entry and unreadable grants is NOT "no access".
    #[test]
    fn site_verdict_no_entry_and_unreadable_grants_is_unknown() {
        let r = site_verdict(None, None, LABEL.into());
        assert_eq!(r.verdict, AccessVerdict::Unknown);
        assert!(!r.has_access);
        let detail = r.detail.unwrap();
        assert!(detail.contains("couldn't be read"));
        assert!(!detail.contains("holds no organization-wide SharePoint grant"));
    }

    // Also what an app with no service principal gets (the empty default).
    #[test]
    fn site_verdict_no_entry_and_no_grants_is_no_access() {
        let r = site_verdict(Some(&HeldSharePointGrants::default()), None, LABEL.into());
        assert_eq!(r.verdict, AccessVerdict::NoAccess);
        assert!(!r.has_access);
        assert!(
            r.detail
                .unwrap()
                .contains("holds no organization-wide SharePoint grant")
        );
    }

    #[test]
    fn site_verdict_entry_with_unreadable_grants_is_unknown() {
        let r = site_verdict(
            None,
            Some(hit(SelectedScopeLevel::File, LABEL)),
            LABEL.into(),
        );
        assert_eq!(r.verdict, AccessVerdict::Unknown);
        assert!(!r.has_access);
        assert_eq!(r.roles, vec!["read".to_string()]);
        assert!(
            r.detail
                .unwrap()
                .contains("matching Selected scope is unknown")
        );
    }

    #[test]
    fn site_verdict_entry_with_matching_scope_is_scoped() {
        let h = held(&[], &[("Sites.Selected", SelectedScopeLevel::Site)]);
        let r = site_verdict(
            Some(&h),
            Some(hit(SelectedScopeLevel::Site, "Contoso")),
            LABEL.into(),
        );
        assert_eq!(r.verdict, AccessVerdict::Scoped);
        assert!(r.has_access);
        let detail = r.detail.unwrap();
        assert!(detail.contains("inherited from “Contoso”"));
        assert!(detail.contains("Sites.Selected"));
    }

    #[test]
    fn site_verdict_entry_without_scope_names_the_required_scope() {
        let h = held(&[], &[("Sites.Selected", SelectedScopeLevel::Site)]);
        let r = site_verdict(
            Some(&h),
            Some(hit(SelectedScopeLevel::File, LABEL)),
            LABEL.into(),
        );
        assert_eq!(r.verdict, AccessVerdict::NoAccess);
        assert!(!r.has_access);
        let detail = r.detail.unwrap();
        assert!(detail.contains("Files.SelectedOperations.Selected"));
        assert!(detail.contains("a file"));
        // An entry on the target itself is not "inherited".
        assert!(!detail.contains("inherited from"));
    }

    fn selected_perm(app_id: Option<&str>, roles: &[&str]) -> SelectedPermission {
        SelectedPermission {
            id: "perm".into(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
            granted_to_v2: Some(SiteIdentitySet {
                application: app_id.map(|id| SiteIdentity {
                    id: Some(id.into()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn roles_for_app_matches_case_insensitively_and_dedupes() {
        let perms = vec![
            selected_perm(Some("AAAA-BBBB"), &["write", "read"]),
            selected_perm(Some("aaaa-bbbb"), &["read"]),
            // A user sharing entry has no `application` and is never a match.
            selected_perm(None, &["owner"]),
            selected_perm(Some("other-app"), &["fullcontrol"]),
        ];
        assert_eq!(
            roles_for_app(&perms, "aaaa-bbbb"),
            Some(vec!["read".to_string(), "write".to_string()])
        );
        assert_eq!(roles_for_app(&perms, "missing-app"), None);
        assert_eq!(
            roles_for_app(&[selected_perm(None, &["owner"])], "aaaa-bbbb"),
            None
        );
    }

    // Wiring only — the asymmetry itself is pinned in core `scoping` tests.
    #[test]
    fn scope_for_level_wires_the_list_item_file_asymmetry() {
        let list_items = held(
            &[],
            &[(
                "ListItems.SelectedOperations.Selected",
                SelectedScopeLevel::ListItem,
            )],
        );
        assert_eq!(
            list_items.scope_for_level(SelectedScopeLevel::File),
            Some("ListItems.SelectedOperations.Selected")
        );
        let files = held(
            &[],
            &[(
                "Files.SelectedOperations.Selected",
                SelectedScopeLevel::File,
            )],
        );
        assert_eq!(files.scope_for_level(SelectedScopeLevel::ListItem), None);
    }
}
