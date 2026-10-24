//! The dry-run plan: counts, blockers, and the privileged grants restoring a
//! manifest would make — which the run recomputes to decide what it withholds.

use std::collections::{HashMap, HashSet};

use azapptoolkit_core::audit::{
    RiskLevel, is_risky_delegated_scope, risk_level_for_app_permission,
};
use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_core::federation::validate_federated_credential;
use azapptoolkit_core::models::ServicePrincipal;
use azapptoolkit_core::restore_plan::BackupApps;
use azapptoolkit_graph::GraphClient;

use crate::commands::dispatch::SessionDead;
use crate::dto::backup::{
    AppRegistrationBackup, CloudMismatch, EnterpriseAppBackup, PermissionRisk,
    PlannedFederatedCredential, PrivilegedKind, PrivilegedPermission, PrivilegedRestoreItem,
    RestoreApproval, RestorePlan, TenantBackup,
};

use super::manifest::{
    MAX_REPORT_VALUE_CHARS, excerpt, excerpt_to, manifest_problems, schema_too_new,
};
use super::principals::owner_label;
use super::wire::{checked_uris, expired_at_backup, restorable_fic_subject};

/// Pure dry-run analysis (no I/O): the counts plus the cloud/schema/tenant
/// checks derived from the backup. Split out from
/// [`plan_restore`](super::plan_restore) so it is unit-testable without an
/// `AppState`. `dest_cloud` is the destination build's cloud.
pub(super) fn build_restore_plan(
    backup: &TenantBackup,
    tenant_id: String,
    dest_cloud: CloudEnvironment,
) -> RestorePlan {
    let cloud_mismatch = (backup.cloud != dest_cloud).then_some(CloudMismatch {
        backup_cloud: backup.cloud,
        destination_cloud: dest_cloud,
    });
    let sum = |f: fn(&AppRegistrationBackup) -> usize| -> usize {
        backup.app_registrations.iter().map(f).sum()
    };
    let taken_at = backup.created_at;
    let expired_secrets_skipped: usize = backup
        .app_registrations
        .iter()
        .flat_map(|a| &a.secrets)
        .filter(|m| expired_at_backup(m, taken_at))
        .count();
    // Pass 4 forecast, mirroring `restore_enterprise_app`: an enterprise app is
    // replayed only when it is not foreign and its app registration is in this
    // backup with a service principal (Pass 1 creates the SP only then);
    // everything else becomes a runbook item.
    let with_sp: HashSet<&str> = backup
        .app_registrations
        .iter()
        .filter(|a| a.has_service_principal)
        .map(|a| a.source_app_id.as_str())
        .collect();
    let enterprise_apps_to_reapply = backup
        .enterprise_apps
        .iter()
        .filter(|e| !e.is_foreign_tenant && with_sp.contains(e.source_app_id.as_str()))
        .count();
    RestorePlan {
        cloud_mismatch,
        schema_too_new: schema_too_new(backup.schema_version),
        invalid_manifest: manifest_problems(backup),
        tenant_changed: backup.source_tenant_id != tenant_id,
        source_tenant_id: excerpt(&backup.source_tenant_id),
        destination_tenant_id: tenant_id,
        app_registrations_to_create: backup.app_registrations.len(),
        secrets_to_regenerate: sum(|a| a.secrets.len()) - expired_secrets_skipped,
        expired_secrets_skipped,
        certificates_needing_manual_upload: sum(|a| a.certificates.len()),
        // A flexible credential (no subject) is reported, not recreated — see
        // `restorable_fic_subject` — so the preview does not promise it.
        federated_credentials_to_restore: sum(|a| {
            a.federated_credentials
                .iter()
                .filter(|f| f.subject.is_some())
                .count()
        }),
        owners_to_remap: sum(|a| a.owners.len()),
        enterprise_apps_to_reapply,
        enterprise_apps_manual: backup.enterprise_apps.len() - enterprise_apps_to_reapply,
        managed_identities_to_rebind: backup.managed_identities.len(),
        skipped_in_backup: backup.skipped.len(),
        // Needs the destination; `plan_restore` fills it.
        privileged: Vec::new(),
    }
}

/// How Pass 3 and the plan treat a manifest permission's resource.
enum ResourceLookup {
    Found(Box<ServicePrincipal>),
    /// No service principal with that appId in the destination.
    Absent,
    /// The read failed.
    Failed,
}

/// The appIds of every resource an admin-consenting app declares, deduplicated
/// and sorted — the resources a plan has to resolve.
fn consent_resources(backup: &TenantBackup) -> Vec<String> {
    let ids: std::collections::BTreeSet<&str> = backup
        .app_registrations
        .iter()
        .filter(|a| a.admin_consent_granted)
        .flat_map(|a| &a.required_resource_access)
        .map(|r| r.resource_app_id.as_str())
        .collect();
    ids.into_iter().map(str::to_owned).collect()
}

/// Resolves each resource live (`resolve_resource_sp`, after one batched
/// prewarm), noting failures through `session`. Stops at a dead session: every
/// later read would fail the same way.
async fn resolve_resources(
    client: &GraphClient,
    ids: &[String],
    session: &SessionDead,
) -> HashMap<String, ResourceLookup> {
    let mut out = HashMap::new();
    if ids.is_empty() {
        return out;
    }
    client.prewarm_resource_sps(ids).await;
    for id in ids {
        if session.is_dead() {
            break;
        }
        let lookup = match client.resolve_resource_sp(id).await {
            Ok(Some(sp)) => ResourceLookup::Found(Box::new(sp)),
            Ok(None) => ResourceLookup::Absent,
            Err(e) => {
                session.note_code(e.ui_code());
                ResourceLookup::Failed
            }
        };
        out.insert(id.clone(), lookup);
    }
    out
}

/// The risk of an application permission `value`, from `core::audit`.
fn app_role_risk(value: &str) -> PermissionRisk {
    match risk_level_for_app_permission(value) {
        Some(RiskLevel::High | RiskLevel::Critical) => PermissionRisk::High,
        Some(RiskLevel::Medium) => PermissionRisk::Medium,
        _ => PermissionRisk::Low,
    }
}

/// The permissions admin consent would grant `app`, resolved against the
/// destination: `(application, delegated)`.
///
/// A value that cannot be resolved is shown by id with [`PermissionRisk::Unknown`]
/// — a permission nobody can name is treated as high-risk for approval —
/// except on an API this backup itself recreates (`restored_api`): its values
/// are not knowable until it exists, and its roles grant access only to that
/// fresh, empty app.
fn consent_permissions(
    app: &AppRegistrationBackup,
    resources: &HashMap<String, ResourceLookup>,
    in_backup: &HashSet<&str>,
) -> (Vec<PrivilegedPermission>, Vec<PrivilegedPermission>) {
    let mut roles = Vec::new();
    let mut scopes = Vec::new();
    for rra in &app.required_resource_access {
        let lookup = resources.get(&rra.resource_app_id);
        let sp = match lookup {
            Some(ResourceLookup::Found(sp)) => Some(sp.as_ref()),
            _ => None,
        };
        let restored_api = matches!(lookup, Some(ResourceLookup::Absent))
            && in_backup.contains(rra.resource_app_id.as_str());
        for access in &rra.resource_access {
            let is_role = access.r#type == "Role";
            let value = sp
                .and_then(|sp| {
                    if is_role {
                        sp.app_roles
                            .iter()
                            .find(|r| r.id == access.id)
                            .map(|r| r.value.clone())
                    } else {
                        sp.oauth2_permission_scopes
                            .iter()
                            .find(|s| s.id == access.id)
                            .map(|s| s.value.clone())
                    }
                })
                .filter(|v| !v.is_empty());
            let risk = match (&value, is_role) {
                (Some(v), true) => app_role_risk(v),
                (Some(v), false) if is_risky_delegated_scope(v) => PermissionRisk::High,
                (Some(_), false) => PermissionRisk::Low,
                (None, _) if restored_api => PermissionRisk::Low,
                (None, _) => PermissionRisk::Unknown,
            };
            // The resource and permission ids come from the file; the name
            // and value were resolved in the destination.
            let perm = PrivilegedPermission {
                resource_app_id: excerpt(&rra.resource_app_id),
                resource_display_name: sp.map(|sp| sp.display_name.clone()),
                permission_id: excerpt(&access.id),
                value,
                risk,
                restored_api,
            };
            if is_role {
                roles.push(perm);
            } else {
                scopes.push(perm);
            }
        }
    }
    (roles, scopes)
}

/// Whether an app's admin consent needs the operator's approval: it covers any
/// application permission (app-only access; the risk lists are a short
/// denylist, not proof a permission is harmless), or a delegated one that is
/// broad or that nobody can name.
fn consent_needs_approval(
    app_roles: &[PrivilegedPermission],
    delegated: &[PrivilegedPermission],
) -> bool {
    !app_roles.is_empty()
        || delegated
            .iter()
            .any(|p| matches!(p.risk, PermissionRisk::High | PermissionRisk::Unknown))
}

/// The enterprise apps Pass 4 may replay onto `app`'s service principal:
/// every non-foreign one for the app, exactly what
/// [`restore_enterprise_app`](super::enterprise::restore_enterprise_app)
/// accepts. Deliberately NOT conditioned on `has_service_principal`: the SP
/// can exist anyway (Pass 3's consent creates one; an adopted app may already
/// have one), and Pass 4 replays onto whatever SP it finds.
fn replayed_enterprise_apps<'a>(
    backup: &'a TenantBackup,
    app: &'a AppRegistrationBackup,
) -> impl Iterator<Item = &'a EnterpriseAppBackup> {
    backup
        .enterprise_apps
        .iter()
        .filter(move |e| !e.is_foreign_tenant && e.source_app_id == app.source_app_id)
}

/// What restoring `backup` grants from the file, per app registration and
/// managed identity: the admin consent Pass 3 re-grants (values resolved live,
/// risk-ranked by `core::audit`), federated credentials (issuer + subject, and
/// whether validation will refuse them), owners, the groups Pass 4 adds the
/// service principal to, and the Graph app roles Pass 5 re-binds — plus, shown
/// only, pre-authorized clients this backup does not recreate and the users
/// and groups assigned to the app's roles. Read-only.
///
/// Shared by the plan and by [`run_restore`](super::run_restore), which
/// recomputes it rather than trusting the front end, so the approval gate
/// holds for any caller.
pub(super) async fn privileged_restore_items(
    client: &GraphClient,
    backup: &TenantBackup,
    session: &SessionDead,
) -> Vec<PrivilegedRestoreItem> {
    classify(client, backup, session).await.0
}

/// [`privileged_restore_items`], plus the source appIds of the apps that need
/// approval only because a consent resource could not be read (a lookup that
/// failed, or one a dead session stopped before): every permission on one of
/// those is `Unknown`, whatever the plan showed, and an unidentified
/// delegated scope needs approval where the plan may have shown a harmless
/// one and not asked.
async fn classify(
    client: &GraphClient,
    backup: &TenantBackup,
    session: &SessionDead,
) -> (Vec<PrivilegedRestoreItem>, HashSet<String>) {
    // Exact, as `remap_required_resource_access` (Pass 2's resource remap) is.
    let in_backup: HashSet<&str> = backup
        .app_registrations
        .iter()
        .map(|a| a.source_app_id.as_str())
        .collect();
    // Ignoring case, as Pass 2's `plan_pre_authorized` is: a client is foreign
    // here exactly when the run would write it as listed.
    let backup_apps = backup_apps(backup);
    let resource_ids = consent_resources(backup);
    let resources = resolve_resources(client, &resource_ids, session).await;
    // As the items name them (an excerpt of the file's id).
    let unread: HashSet<String> = resource_ids
        .iter()
        .filter(|id| matches!(resources.get(*id), None | Some(ResourceLookup::Failed)))
        .map(|id| excerpt(id))
        .collect();
    let mut needs_approval_only_unread = HashSet::new();
    let mut items = Vec::new();
    for app in &backup.app_registrations {
        let (app_roles, delegated_scopes) = if app.admin_consent_granted {
            consent_permissions(app, &resources, &in_backup)
        } else {
            (Vec::new(), Vec::new())
        };
        let mut external: Vec<String> = app
            .pre_authorized_applications
            .iter()
            .filter(|p| !backup_apps.contains(&p.app_id))
            .map(|p| excerpt(&p.app_id))
            .collect();
        // One per client, as the run writes them.
        external.sort_by_key(|id| id.to_ascii_lowercase());
        external.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        let federated_credentials: Vec<PlannedFederatedCredential> = app
            .federated_credentials
            .iter()
            .filter_map(|fic| {
                let subject = restorable_fic_subject(fic).ok()?;
                let audiences = if fic.audiences.is_empty() {
                    vec![backup.cloud.token_exchange_audience().to_string()]
                } else {
                    fic.audiences.clone()
                };
                // Validator prose quoting a value `core::federation` has
                // already held to its 600-character ceiling, but Debug-escaped,
                // so possibly several times longer. Capped like a report value:
                // bounded, without cutting the explanation the way an
                // 80-character excerpt would.
                let rejected = validate_federated_credential(
                    Some(&fic.name),
                    &fic.issuer,
                    subject,
                    &audiences,
                    fic.description.as_deref(),
                )
                .err()
                .map(|reason| excerpt_to(&reason, MAX_REPORT_VALUE_CHARS));
                Some(PlannedFederatedCredential {
                    name: excerpt(&fic.name),
                    issuer: excerpt(&fic.issuer),
                    subject: excerpt(subject),
                    rejected,
                })
            })
            .collect();
        let group_memberships: Vec<String> = replayed_enterprise_apps(backup, app)
            .flat_map(|e| &e.group_memberships)
            .map(|g| excerpt(&owner_label(g)))
            .collect();
        let app_role_assignees: Vec<String> = replayed_enterprise_apps(backup, app)
            .flat_map(|e| &e.app_role_assignees)
            .map(|a| {
                let who = excerpt(&owner_label(&a.principal));
                match a.app_role_value.as_deref().filter(|v| !v.is_empty()) {
                    Some(role) => format!("{who} ({})", excerpt(role)),
                    None => who,
                }
            })
            .collect();
        let owners: Vec<String> = app
            .owners
            .iter()
            .map(|o| excerpt(&owner_label(o)))
            .collect();
        // Only what Pass 2 would write: the same validator, refusals dropped
        // here (the report names them when the write happens).
        let reply_urls: Vec<String> = [
            &app.web_redirect_uris,
            &app.spa_redirect_uris,
            &app.public_client_redirect_uris,
        ]
        .into_iter()
        .flat_map(|uris| checked_uris(uris, "", &mut Vec::new()))
        .map(|u| excerpt(&u))
        .collect();
        let public_client = app.is_fallback_public_client;
        let grants_consent = !app_roles.is_empty() || !delegated_scopes.is_empty();
        let adds_trust = federated_credentials.iter().any(|f| f.rejected.is_none());
        // Owners, reply URLs and the public-client flag are harmless on their
        // own and standing access with consent behind them: an owner can add
        // a secret, and a reply URL is where consented tokens are delivered,
        // so an app the file both consents and points somewhere needs the
        // operator's eyes. Low-risk delegated consent alone still does not.
        let routes_tokens = !owners.is_empty() || !reply_urls.is_empty() || public_client;
        let requires_approval = (grants_consent
            && (consent_needs_approval(&app_roles, &delegated_scopes) || routes_tokens))
            || adds_trust
            || !group_memberships.is_empty();
        // Approval needed for no reason but an unread API: no application
        // permission (each needs approval whatever it is), nothing else that
        // needs it on its own, and every broad or unknown delegated scope an
        // unidentified one on an API the run could not read.
        if requires_approval
            && app_roles.is_empty()
            && !routes_tokens
            && !adds_trust
            && group_memberships.is_empty()
            && delegated_scopes.iter().all(|p| match p.risk {
                PermissionRisk::Unknown => unread.contains(&p.resource_app_id),
                PermissionRisk::High => false,
                _ => true,
            })
        {
            needs_approval_only_unread.insert(app.source_app_id.clone());
        }
        let shown = grants_consent
            || !external.is_empty()
            || !federated_credentials.is_empty()
            || !group_memberships.is_empty()
            || !app_role_assignees.is_empty()
            || routes_tokens;
        if !shown {
            continue;
        }
        items.push(PrivilegedRestoreItem {
            kind: PrivilegedKind::App,
            source_app_id: app.source_app_id.clone(),
            display_name: excerpt(&app.display_name),
            admin_consent: grants_consent,
            requires_approval,
            app_roles,
            delegated_scopes,
            external_pre_authorized_clients: external,
            federated_credentials,
            owners,
            group_memberships,
            app_role_assignees,
            reply_urls,
            public_client,
        });
    }
    for mi in &backup.managed_identities {
        let app_roles: Vec<PrivilegedPermission> = mi
            .held_app_roles
            .iter()
            .map(|r| {
                // Every field here comes from the file. Risk is ranked on the
                // whole value, then each is shown as an excerpt.
                let value = r.app_role_value.as_deref().filter(|v| !v.is_empty());
                PrivilegedPermission {
                    resource_app_id: excerpt(&r.resource_app_id),
                    resource_display_name: r.resource_display_name.as_deref().map(excerpt),
                    permission_id: excerpt(&r.app_role_id),
                    // No value: Pass 5 cannot re-bind it at all (a warning).
                    risk: value.map_or(PermissionRisk::Unknown, app_role_risk),
                    value: value.map(excerpt),
                    restored_api: false,
                }
            })
            .collect();
        if app_roles.is_empty() {
            continue;
        }
        items.push(PrivilegedRestoreItem {
            kind: PrivilegedKind::ManagedIdentity,
            source_app_id: mi.source_app_id.clone(),
            display_name: excerpt(&mi.display_name),
            // Every app role is app-only access to the resource.
            requires_approval: true,
            app_roles,
            ..Default::default()
        });
    }
    (items, needs_approval_only_unread)
}

/// The label a permission gets in a report line: its value, else its id.
fn permission_label(p: &PrivilegedPermission) -> String {
    match &p.value {
        Some(v) => v.clone(),
        None => format!(
            "unidentified permission {} on {}",
            p.permission_id, p.resource_app_id
        ),
    }
}

/// The backup's own app registrations, for classifying pre-authorized clients
/// ([`plan_pre_authorized`](azapptoolkit_core::restore_plan::plan_pre_authorized))
/// the same way in the plan and in Pass 2.
pub(super) fn backup_apps(backup: &TenantBackup) -> BackupApps {
    BackupApps::new(
        backup
            .app_registrations
            .iter()
            .map(|a| (a.source_app_id.as_str(), a.display_name.as_str())),
    )
}

/// The approval key for an app registration.
pub(super) fn app_approval(source_app_id: &str) -> RestoreApproval {
    RestoreApproval {
        kind: PrivilegedKind::App,
        source_app_id: source_app_id.to_string(),
    }
}

/// Why the run withholds an app's standing access, for the report.
#[derive(Debug, Default)]
pub(super) struct Withheld {
    /// The permissions its admin consent would have granted.
    pub(super) consent: Vec<String>,
    /// The app needs approval only because a permission its consent covers
    /// could not be identified when the run classified it — reading its API in
    /// the destination failed, so it counted as `Unknown`. The plan may never
    /// have asked about this app, which "not approved in the plan" would then
    /// misstate. False when anything else needs approval too: the plan asked.
    pub(super) lookup_failed: bool,
}

/// The app registrations whose standing access the run withholds: approval
/// required ([`PrivilegedRestoreItem::requires_approval`]) and not given. Maps
/// source appId → what its admin consent would have granted, and whether a
/// failed read made it need approval ([`Withheld`]), for the report. Skips the
/// reads entirely when every app is approved.
pub(super) async fn unapproved_apps(
    client: &GraphClient,
    backup: &TenantBackup,
    approved: &HashSet<RestoreApproval>,
    session: &SessionDead,
) -> HashMap<String, Withheld> {
    let any_unapproved = backup
        .app_registrations
        .iter()
        .any(|a| !approved.contains(&app_approval(&a.source_app_id)));
    if !any_unapproved {
        return HashMap::new();
    }
    let (items, only_unread) = classify(client, backup, session).await;
    items
        .into_iter()
        .filter(|i| {
            i.kind == PrivilegedKind::App
                && i.requires_approval
                && !approved.contains(&app_approval(&i.source_app_id))
        })
        .map(|i| {
            let consent = i
                .app_roles
                .iter()
                .chain(&i.delegated_scopes)
                .map(permission_label)
                .collect();
            let lookup_failed = only_unread.contains(&i.source_app_id);
            (
                i.source_app_id,
                Withheld {
                    consent,
                    lookup_failed,
                },
            )
        })
        .collect()
}
