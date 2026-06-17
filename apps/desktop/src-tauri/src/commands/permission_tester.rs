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

use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

use azapptoolkit_core::audit::MailPermissionScope;
use azapptoolkit_core::scoping::{is_scopable_exchange_permission, is_sharepoint_orgwide};
use azapptoolkit_exchange::models::{
    ExoApplicationAccessPolicy, ExoAuthorizationResult, ExoServicePrincipal,
};
use azapptoolkit_exchange::ExchangeClient;

use crate::commands::dispatch::dispatch_capped;
use crate::commands::exchange::{aap_verdict_for, exchange_client, is_org_wide_auth_row};
use crate::commands::graph_roles::graph_role_index;
use crate::dto::permission_tester::{
    MailboxProbeProgress, MailboxReacherRow, MailboxReachersResult, PermissionTestResult,
};
use crate::dto::UiError;
use crate::state::AppState;

/// The Entra layer's input: the mail-scopable Graph application permissions
/// the SP holds as **org-wide Entra app-role grants**. These reach *every*
/// mailbox directly through Graph with no Exchange RBAC involvement —
/// `Test-ServicePrincipalAuthorization` deliberately excludes them — and only
/// a legacy Application Access Policy can constrain them. Returns the matching
/// permission values, or `None` when the SP holds no such grant or can't be
/// resolved. Mirrors path 1 of [`test_site_access`] (org-wide `Sites.*`).
async fn orgwide_mailbox_grant(
    state: &AppState,
    tenant_id: &str,
    app_id: &str,
) -> Option<Vec<String>> {
    let client = state.graph_for(tenant_id);
    let sp = client
        .get_service_principal_by_app_id(app_id)
        .await
        .ok()??;
    let (_, role_value_by_id) = graph_role_index(&client).await.ok()?;
    let assignments = client.list_app_role_assignments(&sp.id).await.ok()?;
    let mut perms: Vec<String> = assignments
        .iter()
        .filter_map(|a| role_value_by_id.get(&a.app_role_id))
        .filter(|value| is_scopable_exchange_permission(value))
        .cloned()
        .collect();
    perms.sort();
    perms.dedup();
    (!perms.is_empty()).then_some(perms)
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
}

/// Evaluates the Entra layer for `perms` (already-confirmed org-wide grants).
/// `policies` is the pre-fetched AAP list (`None` = couldn't be read). The
/// live `Test-ApplicationAccessPolicy` call is made only when a policy
/// actually names this app, so the common no-AAP case costs no extra cmdlet.
async fn entra_reach(
    exo: &ExchangeClient,
    app_id: &str,
    mailbox: &str,
    perms: Vec<String>,
    policies: Option<&[ExoApplicationAccessPolicy]>,
) -> EntraReach {
    let Some(policies) = policies else {
        return EntraReach::Unverified(perms);
    };
    if !policies.iter().any(|p| p.app_id.as_deref() == Some(app_id)) {
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
        3 => "org_wide",
        2 => "scoped",
        1 => "unknown",
        _ => "no_access",
    };
    PermissionTestResult {
        has_access: level >= 2,
        verdict: verdict.into(),
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
    let exo = match exchange_client(&state, &tenant_id) {
        Ok(exo) => exo,
        Err(err) => {
            // No Exchange client at all: an org-wide Entra grant still answers
            // on its own (with the AAP caveat); otherwise nothing can be said.
            return Ok(
                match orgwide_mailbox_grant(&state, &tenant_id, &app_id).await {
                    Some(perms) => synthesize(
                        &mailbox,
                        &EntraReach::Unverified(perms),
                        &RbacReach::Indeterminate,
                    ),
                    None => PermissionTestResult::unknown(
                        &mailbox,
                        format!(
                            "Couldn't reach Exchange to test access ({}). Exchange administrator rights are required.",
                            err.code
                        ),
                    ),
                },
            );
        }
    };

    let rbac = rbac_reach_for(
        &exo,
        &app_id,
        &mailbox,
        "mailbox RBAC access test unavailable",
    )
    .await;

    let entra = match orgwide_mailbox_grant(&state, &tenant_id, &app_id).await {
        Some(perms) => {
            // The AAP list is read only when an Entra grant exists for it to
            // constrain.
            let policies = exo.get_application_access_policies().await.ok();
            entra_reach(&exo, &app_id, &mailbox, perms, policies.as_deref()).await
        }
        None => EntraReach::NotHeld,
    };

    Ok(synthesize(&mailbox, &entra, &rbac))
}

/// In-flight cap for the per-candidate Exchange probes — the admin-API cmdlet
/// is heavyweight, so this stays well below the Graph loops' caps.
const PROBE_CONCURRENCY: usize = 4;

fn emit_probe_progress(app_handle: &AppHandle, progress: MailboxProbeProgress) {
    if let Err(err) = app_handle.emit("mailbox-probe-progress", progress) {
        tracing::warn!(?err, "failed to emit mailbox-probe-progress event");
    }
}

/// The mailbox reverse lookup: which applications can reach `mailbox`?
///
/// Candidates come from two sources, merged by SP object id: ONE paged Graph
/// call — `appRoleAssignedTo` on the Microsoft Graph resource SP is the whole
/// tenant's principal → Graph-app-role matrix — filtered to principals holding
/// a mail-scopable application permission; plus the Exchange SP store
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
/// candidate source is necessarily absent in that degraded mode — the UI's
/// `exchange_available = false` summary already flags the partial coverage.
///
/// Long-running: emits `mailbox-probe-progress` and polls the shared
/// `AppState.sweep_cancel` atomic (the Resource Access page's cancel covers
/// both this probe and the site sweep; the two never run concurrently from the
/// UI, and neither may abort an audit/bulk run).
#[tauri::command]
pub async fn find_mailbox_reachers(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    mailbox: String,
) -> Result<MailboxReachersResult, UiError> {
    state.sweep_cancel.reset();
    let mailbox = mailbox.trim().to_string();
    if mailbox.is_empty() {
        return Err(UiError::validation(
            "missing_mailbox",
            "enter a mailbox address to check",
        ));
    }

    let client = state.graph_for(&tenant_id);
    let (graph_sp_id, role_value_by_id) = graph_role_index(&client).await?;
    let assigned = client.list_app_role_assigned_to(&graph_sp_id).await?;

    // principal id → (display name, held mail-scopable values).
    let mut candidates: HashMap<String, (Option<String>, Vec<String>)> = HashMap::new();
    for a in assigned {
        if a.principal_type.as_deref() != Some("ServicePrincipal") {
            continue;
        }
        let Some(value) = role_value_by_id.get(&a.app_role_id) else {
            continue;
        };
        if !is_scopable_exchange_permission(value) {
            continue;
        }
        let entry = candidates
            .entry(a.principal_id.clone())
            .or_insert_with(|| (a.principal_display_name.clone(), Vec::new()));
        entry.1.push(value.clone());
    }
    for (_, values) in candidates.values_mut() {
        values.sort();
        values.dedup();
    }

    // Best-effort Exchange client; without it every verdict derives from the
    // Entra grants (org-wide reach — never under-reported).
    let exo = exchange_client(&state, &tenant_id).ok();
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
    // Best-effort: an unreadable list leaves the Graph-derived candidates.
    if let Some(exo) = exo.as_deref() {
        match exo.list_service_principals().await {
            Ok(sps) => merge_exchange_candidates(&mut candidates, sps),
            Err(err) => {
                tracing::info!(
                    code = err.ui_code(),
                    "mailbox probe: Exchange SP list unavailable"
                );
            }
        }
    }

    let total = candidates.len();
    emit_probe_progress(
        &app_handle,
        MailboxProbeProgress {
            done: 0,
            total,
            current_app: None,
            cancelled: false,
        },
    );

    let done = Arc::new(Mutex::new(0usize));
    let cancel = state.sweep_cancel.clone();
    let mailbox_shared = Arc::new(mailbox.clone());

    let mut rows: Vec<MailboxReacherRow> = Vec::new();
    let mut cancelled = dispatch_capped(
        candidates,
        || PROBE_CONCURRENCY,
        |(principal_id, (display_name, held))| {
            if cancel.is_cancelled() {
                return None;
            }
            let client = client.clone();
            let exo = exo.clone();
            let policies = policies.clone();
            let app_handle = app_handle.clone();
            let done = done.clone();
            let cancel_for_task = cancel.clone();
            let mailbox = mailbox_shared.clone();
            Some(tokio::spawn(async move {
                let row = probe_candidate(
                    &client,
                    exo.as_deref(),
                    policies.as_deref().map(Vec::as_slice),
                    &mailbox,
                    principal_id,
                    display_name,
                    held,
                )
                .await;
                let mut guard = done.lock().await;
                *guard += 1;
                let progress = MailboxProbeProgress {
                    done: *guard,
                    total,
                    current_app: row.display_name.clone(),
                    cancelled: cancel_for_task.is_cancelled(),
                };
                drop(guard);
                emit_probe_progress(&app_handle, progress);
                row
            }))
        },
        |joined| match joined {
            Ok(row) => rows.push(row),
            Err(err) => tracing::warn!(?err, "mailbox probe: join error"),
        },
    )
    .await;
    cancelled = cancelled || cancel.is_cancelled();

    // Highest-reach first: org-wide, then scoped, then unknown, then no-access;
    // names break ties so the order is stable across runs.
    let rank = |v: &str| match v {
        "org_wide" => 0,
        "scoped" => 1,
        "unknown" => 2,
        _ => 3,
    };
    rows.sort_by(|a, b| {
        rank(&a.verdict)
            .cmp(&rank(&b.verdict))
            .then_with(|| a.display_name.cmp(&b.display_name))
    });

    Ok(MailboxReachersResult {
        tenant_id,
        mailbox,
        total_candidates: total,
        rows,
        exchange_available,
        cancelled,
    })
}

/// Folds the Exchange-registered service principals into the candidate map
/// (keyed by SP object id). A principal already present — it holds an Entra
/// grant — keeps its richer entry; a new one enters with empty held
/// permissions, so its verdict can only come from the Exchange RBAC layer.
fn merge_exchange_candidates(
    candidates: &mut HashMap<String, (Option<String>, Vec<String>)>,
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

/// Probes one candidate principal against the mailbox — the same two-layer
/// union as [`test_mailbox_access`], with the candidate's held Entra grants
/// already known and the AAP list pre-fetched. Infallible by design — every
/// failure path lands in a verdict (`unknown` at worst) so one bad candidate
/// can't abort the whole probe.
async fn probe_candidate(
    client: &azapptoolkit_graph::GraphClient,
    exo: Option<&ExchangeClient>,
    policies: Option<&[ExoApplicationAccessPolicy]>,
    mailbox: &str,
    principal_id: String,
    display_name: Option<String>,
    held_permissions: Vec<String>,
) -> MailboxReacherRow {
    // The Exchange cmdlets and the UI's deep links want the appId, not the SP
    // object id the assignment row carries.
    let app_id = match client
        .get_service_principal_by_object_id(&principal_id)
        .await
    {
        Ok(Some(sp)) => sp.app_id,
        other => {
            if let Err(err) = other {
                tracing::info!(%principal_id, ?err, "mailbox probe: SP resolve failed");
            }
            return MailboxReacherRow {
                app_id: String::new(),
                principal_id,
                display_name,
                held_permissions,
                verdict: "unknown".into(),
                roles: Vec::new(),
                detail: Some("Couldn't resolve the service principal.".into()),
            };
        }
    };

    let result = match exo {
        None => {
            let entra = if held_permissions.is_empty() {
                EntraReach::NotHeld
            } else {
                EntraReach::Unverified(held_permissions.clone())
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
    MailboxReacherRow {
        app_id,
        principal_id,
        display_name,
        held_permissions,
        verdict: result.verdict,
        roles: result.roles,
        detail: result.detail,
    }
}

/// Tests whether `app_id` can access the SharePoint site at `site_url`. Combines
/// the two access paths: (1) an org-wide `Sites.*` (≠ `Sites.Selected`) app-role
/// grant reaches every site regardless of per-site permissions; (2) a per-site
/// permission entry naming this app. Pre-acquires the `Sites.FullControl.All`
/// scope so a missing-consent rejection surfaces as `consent_required` (the page
/// shows a "Grant consent" button) — the site-permission endpoints require it
/// even for reads.
#[tauri::command]
pub async fn test_site_access(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    site_url: String,
) -> Result<PermissionTestResult, UiError> {
    state
        .ensure_sharepoint_token(&tenant_id)
        .await
        .map_err(UiError::from)?;
    let client = state.graph_for(&tenant_id);

    // Path 1: org-wide grant. Look up the app's SP, enumerate its granted Graph
    // app-roles, and flag any broad `Sites.*`. A failure here is non-fatal — fall
    // through to the per-site check.
    let mut orgwide_roles: Vec<String> = Vec::new();
    if let Ok(Some(sp)) = client.get_service_principal_by_app_id(&app_id).await {
        if let Ok((_, role_value_by_id)) = graph_role_index(&client).await {
            if let Ok(assignments) = client.list_app_role_assignments(&sp.id).await {
                for a in &assignments {
                    if let Some(value) = role_value_by_id.get(&a.app_role_id) {
                        if is_sharepoint_orgwide(value) {
                            orgwide_roles.push(value.clone());
                        }
                    }
                }
            }
        }
    }

    let site = client.get_site_by_url(&site_url).await?;
    let label = site.display_name.clone().unwrap_or_else(|| site.id.clone());

    if !orgwide_roles.is_empty() {
        orgwide_roles.sort();
        orgwide_roles.dedup();
        return Ok(PermissionTestResult {
            has_access: true,
            verdict: "org_wide".into(),
            roles: orgwide_roles,
            detail: Some(format!(
                "The app holds an organization-wide SharePoint permission and can access “{label}” (and every other site)."
            )),
            resource_label: label,
        });
    }

    // Path 2: per-site permission entry naming this app.
    let perms = client.list_site_permissions(&site.id).await?;
    let mut site_roles: Vec<String> = perms
        .into_iter()
        .filter(|p| {
            p.granted_to_identities.iter().any(|s| {
                s.application
                    .as_ref()
                    .and_then(|a| a.id.as_deref())
                    .map(|id| id.eq_ignore_ascii_case(&app_id))
                    .unwrap_or(false)
            })
        })
        .flat_map(|p| p.roles)
        .collect();
    site_roles.sort();
    site_roles.dedup();

    if site_roles.is_empty() {
        Ok(PermissionTestResult {
            has_access: false,
            verdict: "no_access".into(),
            roles: Vec::new(),
            detail: Some(format!(
                "The app has no permission on “{label}”, and no organization-wide SharePoint grant."
            )),
            resource_label: label,
        })
    } else {
        Ok(PermissionTestResult {
            has_access: true,
            verdict: "scoped".into(),
            roles: site_roles,
            detail: Some(format!(
                "The app is granted access to “{label}” specifically (Sites.Selected model)."
            )),
            resource_label: label,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(result.verdict, "no_access");
        assert!(result.detail.unwrap().contains("InScope = false"));
    }

    #[test]
    fn in_scope_scoped_row_grants_scoped_access() {
        let reach = rbac_reach_from_rows(&[scoped_row(Some(true)), scoped_row(Some(false))]);
        assert!(matches!(reach, RbacReach::Scoped(_)));
        let result = synthesize("a@x.com", &EntraReach::NotHeld, &reach);
        assert!(result.has_access);
        assert_eq!(result.verdict, "scoped");
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
            "org_wide"
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
        assert_eq!(result.verdict, "unknown");
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
        assert_eq!(result.verdict, "org_wide");
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
        assert_eq!(result.verdict, "no_access");
        assert!(result
            .detail
            .unwrap()
            .contains("blocked for “a@x.com” by a legacy Application Access Policy"));
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
        assert_eq!(result.verdict, "scoped");
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
        assert_eq!(result.verdict, "org_wide");
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
        assert_eq!(result.verdict, "scoped");
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
        let mut candidates: HashMap<String, (Option<String>, Vec<String>)> = HashMap::from([(
            "obj-1".to_string(),
            (
                Some("From Graph".to_string()),
                vec!["Mail.Read".to_string()],
            ),
        )]);
        merge_exchange_candidates(
            &mut candidates,
            vec![
                exo_sp(Some("obj-1"), "From Exchange"),
                exo_sp(Some("obj-2"), "RBAC only"),
                exo_sp(None, "No object id"),
            ],
        );
        assert_eq!(candidates.len(), 2);
        let kept = &candidates["obj-1"];
        assert_eq!(kept.0.as_deref(), Some("From Graph"));
        assert_eq!(kept.1, vec!["Mail.Read".to_string()]);
        let added = &candidates["obj-2"];
        assert_eq!(added.0.as_deref(), Some("RBAC only"));
        assert!(added.1.is_empty());
    }
}
