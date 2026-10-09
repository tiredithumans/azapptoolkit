//! Disaster-recovery page: **backup** (capture a portable manifest) and
//! **restore** (replay it into the current tenant). The page is explicit about
//! the two hard DR realities — secret/cert values are never in the backup
//! (restore regenerates secrets and surfaces the show-once values), and managed
//! identities are Azure resources recreated out-of-band.

use std::collections::BTreeSet;

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance, ProgressBar, Spinner, SpinnerSize};

use crate::bindings::{backup, events};
use crate::components::icon::{Icon, IconName};
use crate::components::modal_shell::ModalShell;
use crate::components::scope_badge::app_permission_risk_badge;
use crate::components::ui::{
    Badge, BadgeTone, Callout, Card, CopyableId, FormError, SectionHeader,
};
use crate::hooks::use_progress_stream::use_progress_stream;
use crate::state::use_session;
use crate::util::{count_noun, plural};

#[component]
pub fn DisasterRecoveryView() -> impl IntoView {
    let session = use_session();

    // ---- Backup state ----
    let captured: RwSignal<Option<backup::TenantBackup>> = RwSignal::new(None);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let progress: RwSignal<Option<crate::bindings::bulk::BulkProgress>> = RwSignal::new(None);
    use_progress_stream(progress, events::backup_progress);
    // Highest adaptive concurrency cap seen this run. The backup emits the live
    // cap; when it later drops below this peak, Graph is throttling and the run
    // is backing off — which we surface so a slow backup reads as expected, not
    // broken. Monotonic, so a recovered cap doesn't retroactively hide the notice
    // mid-run; reset when a new run clears `progress`.
    let peak_cap = RwSignal::new(0usize);
    Effect::new(move |_| match progress.get() {
        Some(p) => {
            if let Some(cap) = p.in_flight_cap {
                peak_cap.update(|peak| *peak = (*peak).max(cap));
            }
        }
        None => peak_cap.set(0),
    });

    // ---- Restore state ----
    let loaded: RwSignal<Option<backup::TenantBackup>> = RwSignal::new(None);
    let plan: RwSignal<Option<backup::RestorePlan>> = RwSignal::new(None);
    // Source appIds the operator approved in the plan's privileged list; only
    // these get their high-risk consent / managed-identity roles granted.
    let approvals: RwSignal<BTreeSet<backup::RestoreApproval>> = RwSignal::new(BTreeSet::new());
    let confirm_open = RwSignal::new(false);
    let restoring = RwSignal::new(false);
    let restore_error: RwSignal<Option<String>> = RwSignal::new(None);
    let report: RwSignal<Option<backup::RestoreReport>> = RwSignal::new(None);
    let restore_progress: RwSignal<Option<crate::bindings::bulk::BulkProgress>> =
        RwSignal::new(None);
    use_progress_stream(restore_progress, events::restore_progress);

    // ---- Backup handlers ----
    let run_backup = move |_| {
        if busy.get() {
            return;
        }
        let Some(tenant) = session.active_tenant.get() else {
            return;
        };
        busy.set(true);
        error.set(None);
        captured.set(None);
        progress.set(None);
        leptos::task::spawn_local(async move {
            match backup::backup_tenant(&tenant.tenant_id).await {
                Ok(b) => {
                    let (apps, ent, mis) = (
                        b.app_registrations.len(),
                        b.enterprise_apps.len(),
                        b.managed_identities.len(),
                    );
                    captured.set(Some(b));
                    session.toast_success(format!(
                        "Backed up {}, {}, {}. Save it to a file to keep it.",
                        count_noun(apps, "app registration", "app registrations"),
                        count_noun(ent, "enterprise app", "enterprise apps"),
                        count_noun(mis, "managed identity", "managed identities"),
                    ));
                }
                // A user-initiated cancel comes back as the `cancelled` code —
                // it's not a failure, so show a neutral toast, not a red banner.
                Err(e) if e.code == "cancelled" => {
                    session.toast_success("Backup cancelled.");
                }
                // A dead session mid-backup gets the Re-authenticate toast
                // action (not a dead-end banner); other errors keep the banner.
                Err(e) => {
                    if !session.report_if_session_dead(&e) {
                        error.set(Some(e.message));
                    }
                }
            }
            busy.set(false);
            progress.set(None);
        });
    };
    let cancel_backup = move |_| {
        leptos::task::spawn_local(async move {
            let _ = backup::cancel_backup().await;
        });
    };
    let save_file = move |_| {
        let Some(b) = captured.get() else {
            return;
        };
        leptos::task::spawn_local(async move {
            match backup::save_backup_to_file(&b, "json").await {
                Ok(Some(path)) => {
                    session.toast_success(format!("Backup saved to {path}"));
                }
                Ok(None) => {} // dialog cancelled
                Err(e) => {
                    if !session.report_if_session_dead(&e) {
                        session.toast_error(format!("Couldn't save backup: {}", e.message), None);
                    }
                }
            }
        });
    };

    // ---- Restore handlers ----
    let load_file = move |_| {
        let Some(tenant) = session.active_tenant.get() else {
            return;
        };
        restore_error.set(None);
        report.set(None);
        leptos::task::spawn_local(async move {
            match backup::load_backup_from_file().await {
                Ok(Some(b)) => match backup::plan_restore(&tenant.tenant_id, &b).await {
                    Ok(p) => {
                        // A new file starts with nothing approved.
                        approvals.set(BTreeSet::new());
                        plan.set(Some(p));
                        loaded.set(Some(b));
                    }
                    Err(e) => {
                        if !session.report_if_session_dead(&e) {
                            restore_error.set(Some(e.message));
                        }
                    }
                },
                Ok(None) => {} // dialog cancelled
                Err(e) => {
                    if !session.report_if_session_dead(&e) {
                        restore_error.set(Some(e.message));
                    }
                }
            }
        });
    };
    let do_restore = move |_| {
        let (Some(tenant), Some(b)) = (session.active_tenant.get(), loaded.get()) else {
            return;
        };
        let approved: Vec<backup::RestoreApproval> = approvals.get().into_iter().collect();
        confirm_open.set(false);
        restoring.set(true);
        restore_error.set(None);
        report.set(None);
        restore_progress.set(None);
        leptos::task::spawn_local(async move {
            match backup::restore_tenant(&tenant.tenant_id, &b, &approved).await {
                Ok(r) => {
                    let secrets: usize = r.apps.iter().map(|a| a.regenerated_secrets.len()).sum();
                    session.toast_success(format!(
                        "Restored {}; {} regenerated. Save the report — \
                         the secret values are shown only once.",
                        count_noun(r.apps.len(), "app", "apps"),
                        count_noun(secrets, "secret", "secrets"),
                    ));
                    report.set(Some(r));
                    // A second click would be a second restore, so running it
                    // again requires deliberately re-loading the file.
                    plan.set(None);
                    loaded.set(None);
                }
                Err(e) => {
                    if !session.report_if_session_dead(&e) {
                        restore_error.set(Some(e.message));
                    }
                }
            }
            restoring.set(false);
            restore_progress.set(None);
        });
    };
    let cancel_restore = move |_| {
        leptos::task::spawn_local(async move {
            let _ = backup::cancel_restore().await;
        });
    };
    let save_report = Callback::new(move |()| {
        let Some(r) = report.get() else {
            return;
        };
        leptos::task::spawn_local(async move {
            match backup::save_restore_report_to_file(&r, "json").await {
                Ok(Some(path)) => {
                    session.toast_success(format!("Report saved to {path}"));
                }
                Ok(None) => {} // dialog cancelled
                Err(e) => {
                    if !session.report_if_session_dead(&e) {
                        session.toast_error(format!("Couldn't save report: {}", e.message), None);
                    }
                }
            }
        });
    });

    // Restore is blocked on a cloud mismatch or a too-new manifest (both hard
    // errors from the backend too).
    let plan_blocked = move || plan.get().is_some_and(|p| p.is_blocked());
    // Items whose high-risk grant the restore will skip: approval required,
    // not given. Named in the confirm dialog so skipping is a known choice.
    let unapproved = move || {
        let approved = approvals.get();
        plan.with(|p| {
            p.as_ref().map_or(0, |p| {
                p.privileged
                    .iter()
                    .filter(|i| i.requires_approval && !approved.contains(&approval_key(i)))
                    .count()
            })
        })
    };

    view! {
        <div class="tool-page dr-view">
            <SectionHeader title="Disaster Recovery" crumb="Backup & Restore" />

            // ---------- Backup ----------
            <Card>
                <h2 class="dr-view__card-title">"Back up this tenant"</h2>
                <p class="dr-view__lead">
                    "Captures a portable JSON manifest of every app registration (full \
                     configuration), plus an inventory of enterprise applications and managed \
                     identities. Use it to rebuild the estate in a new tenant during a disaster \
                     recovery."
                </p>
                <ul class="dr-view__notes">
                    <li>
                        <strong>"Secrets and certificates are not included."</strong>
                        " Their values are unrecoverable by design — the backup records only \
                         metadata. Restore generates fresh credentials and gives you a \
                         redistribution report."
                    </li>
                    <li>
                        <strong>"Managed identities can't be restored directly."</strong>
                        " They are Azure resources; recreate them via your infrastructure-as-code, \
                         then re-bind their permissions. The backup captures them as a runbook."
                    </li>
                </ul>

                <div class="dr-view__actions">
                    <Button
                        appearance=ButtonAppearance::Primary
                        disabled=Signal::derive(move || busy.get())
                        on_click=run_backup
                    >
                        {move || {
                            if busy.get() {
                                view! {
                                    <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                    " Backing up…"
                                }
                                    .into_any()
                            } else {
                                view! { <Icon name=IconName::Download size=16 /> " Back up this tenant" }
                                    .into_any()
                            }
                        }}
                    </Button>
                    <Show when=move || busy.get()>
                        <Button appearance=ButtonAppearance::Subtle on_click=cancel_backup>
                            "Cancel"
                        </Button>
                    </Show>
                </div>

                <Show when=move || progress.get().is_some()>
                    {move || {
                        progress.get().map(|p| {
                            let pct = if p.total > 0 { (p.done as f64) / (p.total as f64) } else { 0.0 };
                            let label = p.current_app.clone().map(|n| format!(" — {n}")).unwrap_or_default();
                            let cap_label = p.in_flight_cap.map(|c| format!(" · {c} concurrent")).unwrap_or_default();
                            let cap = p.in_flight_cap;
                            view! {
                                <ProgressBar value=Signal::derive(move || pct) />
                                <p class="dr-view__progress">{format!("Captured {}/{}", p.done, p.total)}{label}{cap_label}</p>
                                <Show when=move || matches!(cap, Some(c) if c < peak_cap.get())>
                                    <p class="dr-view__notice" role="status">
                                        "Microsoft Graph is rate-limiting this backup, so it's automatically slowing down to recover. It will still complete — large tenants just take longer."
                                    </p>
                                </Show>
                            }
                        })
                    }}
                </Show>
                <Show when=move || error.get().is_some()>
                    <FormError>{move || error.get().unwrap_or_default()}</FormError>
                </Show>

                <Show when=move || captured.get().is_some()>
                    {move || {
                        // The `Show` gate makes `None` unreachable today, but a
                        // render closure must never be the thing that panics.
                        let Some(b) = captured.get() else {
                            return ().into_any();
                        };
                        let secrets: usize = b.app_registrations.iter().map(|a| a.secrets.len()).sum();
                        let (apps, ent, mis) = (
                            b.app_registrations.len(),
                            b.enterprise_apps.len(),
                            b.managed_identities.len(),
                        );
                        // Objects the backup could not capture. Rendered
                        // BEFORE the save button, because the decision this
                        // informs is whether to keep this file as the tenant's
                        // DR artifact — a manifest short by an app restores as
                        // if that app never existed, and until now the only
                        // trace was a warn! line in a log nobody reads during an
                        // incident.
                        let skipped_notice = (!b.skipped.is_empty())
                            .then(|| {
                                let n = b.skipped.len();
                                let rows = b
                                    .skipped
                                    .iter()
                                    .map(|s| {
                                        let label = s
                                            .display_name
                                            .clone()
                                            .unwrap_or_else(|| s.object_id.clone());
                                        let detail = format!(" ({}) — {}", s.kind, s.reason);
                                        view! {
                                            <li>
                                                <strong>{label}</strong>
                                                {detail}
                                            </li>
                                        }
                                    })
                                    .collect_view();
                                view! {
                                    <Callout tone="warn">
                                        <p>
                                            {format!(
                                                "{} could not be fully read. This backup is missing what is listed below, and restoring it will not recreate it.",
                                                count_noun(n, "object", "objects"),
                                            )}
                                        </p>
                                        <ul class="dr-view__skipped-list">{rows}</ul>
                                    </Callout>
                                }
                            });
                        view! {
                            <div class="dr-view__result">
                                <p class="dr-view__summary">
                                    {format!(
                                        "Ready: {}, {}, {}. {} will need regeneration on restore.",
                                        count_noun(apps, "app registration", "app registrations"),
                                        count_noun(ent, "enterprise app", "enterprise apps"),
                                        count_noun(mis, "managed identity", "managed identities"),
                                        count_noun(secrets, "secret", "secrets"),
                                    )}
                                </p>
                                {skipped_notice}
                                <Button appearance=ButtonAppearance::Primary on_click=save_file>
                                    <Icon name=IconName::Download size=16 /> " Save backup file…"
                                </Button>
                            </div>
                        }
                            .into_any()
                    }}
                </Show>
            </Card>

            // ---------- Restore ----------
            <Card>
                <h2 class="dr-view__card-title">"Restore into this tenant"</h2>
                <p class="dr-view__lead">
                    "Load a backup file to recreate its app registrations here, re-grant their \
                     permissions, and regenerate their secrets. Object IDs change in a new tenant, \
                     so owners and custom-API references are remapped by name where possible."
                </p>

                <div class="dr-view__actions">
                    <Button
                        appearance=ButtonAppearance::Secondary
                        disabled=Signal::derive(move || restoring.get())
                        on_click=load_file
                    >
                        <Icon name=IconName::Upload size=16 /> " Load backup file…"
                    </Button>
                    <Show when=move || plan.get().is_some() && !plan_blocked() && !restoring.get()>
                        <Button appearance=ButtonAppearance::Primary on_click=move |_| confirm_open.set(true)>
                            "Restore into this tenant…"
                        </Button>
                    </Show>
                    <Show when=move || restoring.get()>
                        <Button appearance=ButtonAppearance::Subtle on_click=cancel_restore>
                            "Cancel"
                        </Button>
                    </Show>
                </div>

                <Show when=move || restore_error.get().is_some()>
                    <FormError>{move || restore_error.get().unwrap_or_default()}</FormError>
                </Show>

                // Plan preview (before confirming).
                <Show when=move || plan.get().is_some() && report.get().is_none()>
                    {move || plan.get().map(|p| view! { <RestorePlanView plan=p approvals=approvals /> })}
                </Show>

                // Live restore progress.
                <Show when=move || restore_progress.get().is_some()>
                    {move || {
                        restore_progress.get().map(|p| {
                            let pct = if p.total > 0 { (p.done as f64) / (p.total as f64) } else { 0.0 };
                            let label = p.current_app.clone().map(|n| format!(" — {n}")).unwrap_or_default();
                            view! {
                                <ProgressBar value=Signal::derive(move || pct) />
                                <p class="dr-view__progress">{format!("Created {}/{}", p.done, p.total)}{label}</p>
                            }
                        })
                    }}
                </Show>

                // Report (after restore).
                <Show when=move || report.get().is_some()>
                    {move || report.get().map(|r| view! { <RestoreReportView report=r on_save=save_report /> })}
                </Show>
            </Card>

            // Confirmation modal.
            <ModalShell
                open=Signal::derive(move || confirm_open.get())
                title=Signal::derive(|| "Restore into this tenant?".to_string())
                on_close=Callback::new(move |()| confirm_open.set(false))
            >
                <p>
                    "This creates new app registrations in the current tenant and regenerates their \
                     secrets. It does not overwrite or delete anything that already exists. Running \
                     it again with the same file recognises the apps an earlier run created (by \
                     their restore tag) and completes them instead of duplicating them. The new \
                     secret values are shown only once — save the report afterwards."
                </p>
                <Show when=move || { unapproved() > 0 }>
                    <p class="dr-view__note">
                        {move || format!(
                            "{} not approved: the restore leaves out {} consent, credentials, owners, group memberships or app roles and lists them in the report for you to grant manually.",
                            count_noun(unapproved(), "item needing approval is", "items needing approval are"),
                            if unapproved() == 1 { "its" } else { "their" },
                        )}
                    </p>
                </Show>
                <div class="dr-view__actions">
                    <Button appearance=ButtonAppearance::Primary on_click=do_restore>"Restore"</Button>
                    <Button appearance=ButtonAppearance::Subtle on_click=move |_| confirm_open.set(false)>
                        "Cancel"
                    </Button>
                </div>
            </ModalShell>
        </div>
    }
}

/// The dry-run plan: the work of all five passes, the blockers (cloud
/// mismatch, too-new manifest, malformed manifest), the tenant-change note, and
/// a duplicate warning when the backup is being restored into the tenant it
/// came from.
#[component]
fn RestorePlanView(
    plan: backup::RestorePlan,
    /// The source appIds approved for their high-risk grants.
    approvals: RwSignal<BTreeSet<backup::RestoreApproval>>,
) -> impl IntoView {
    let privileged = (!plan.privileged.is_empty()).then(|| plan.privileged.clone());
    let cloud = plan.cloud_mismatch.clone();
    let schema = plan.schema_too_new.clone();
    let invalid = (!plan.invalid_manifest.is_empty()).then(|| plan.invalid_manifest.clone());
    let same_tenant = (!plan.tenant_changed).then(|| plan.source_tenant_id.clone());
    view! {
        <div class="dr-view__plan">
            {cloud.map(|m| view! {
                <Callout tone="danger" role="alert">
                    {format!(
                        "This backup is from the \"{}\" cloud, but this app targets \"{}\". \
                         Restore is blocked — use a build configured for the backup's cloud.",
                        m.backup_cloud.as_str(), m.destination_cloud.as_str(),
                    )}
                </Callout>
            })}
            {schema.map(|s| view! {
                <Callout tone="danger" role="alert">
                    {format!(
                        "This backup was written by a newer version of azapptoolkit (manifest \
                         schema {}; this version reads up to {}). Restore is blocked — update \
                         azapptoolkit first.",
                        s.manifest_version, s.supported_version,
                    )}
                </Callout>
            })}
            {invalid.map(|problems| view! {
                <Callout tone="danger" role="alert">
                    {format!(
                        "This backup file is not a valid manifest: {}. Restore is blocked — \
                         restore from an unmodified backup file.",
                        problems.join("; "),
                    )}
                </Callout>
            })}
            {same_tenant.map(|src| view! {
                <Callout tone="warn">
                    {format!(
                        "This backup was taken from this tenant ({src}). Restoring it here does \
                         not roll anything back — it creates a second copy of every app \
                         registration in it, with new appIds and new secrets.",
                    )}
                </Callout>
            })}
            <Show when=move || plan.tenant_changed>
                <p class="dr-view__note">
                    {format!(
                        "Backup is from tenant {} — restoring into a different tenant ({}). \
                         IDs will be reassigned and references remapped by name.",
                        plan.source_tenant_id, plan.destination_tenant_id,
                    )}
                </p>
            </Show>
            <ul class="dr-view__plan-list">
                <li>{format!("{} to create", count_noun(plan.app_registrations_to_create, "app registration", "app registrations"))}</li>
                <li>{format!("{} to regenerate (new values issued)", count_noun(plan.secrets_to_regenerate, "secret", "secrets"))}</li>
                {(plan.expired_secrets_skipped > 0).then(|| view! {
                    <li>{format!(
                        "{} already expired when the backup was taken — not re-issued",
                        count_noun(plan.expired_secrets_skipped, "secret had", "secrets had"),
                    )}</li>
                })}
                <li>{format!("{} manual re-upload", count_noun(plan.certificates_needing_manual_upload, "certificate needs", "certificates need"))}</li>
                <li>{format!("{} to restore (each validated and listed in the report)", count_noun(plan.federated_credentials_to_restore, "federated credential", "federated credentials"))}</li>
                <li>{format!("{} to remap by name", count_noun(plan.owners_to_remap, "owner", "owners"))}</li>
                <li>{format!(
                    "{} to re-apply access to (settings, role assignments, group memberships)",
                    count_noun(plan.enterprise_apps_to_reapply, "enterprise app", "enterprise apps"),
                )}</li>
                {(plan.enterprise_apps_manual > 0).then(|| view! {
                    <li>{format!(
                        "{} manual follow-up (gallery/foreign apps, or no paired app registration in this backup)",
                        count_noun(plan.enterprise_apps_manual, "enterprise app needs", "enterprise apps need"),
                    )}</li>
                })}
                <li>{format!(
                    "{} to re-bind by name — each must already be recreated here; Azure RBAC is always a manual step",
                    count_noun(plan.managed_identities_to_rebind, "managed identity", "managed identities"),
                )}</li>
                {(plan.skipped_in_backup > 0).then(|| view! {
                    <li>{format!(
                        "{} recorded in the backup (objects or parts it could not read) — restoring will not recreate what is missing",
                        count_noun(plan.skipped_in_backup, "gap", "gaps"),
                    )}</li>
                })}
            </ul>
            {privileged.map(|items| view! { <PrivilegedGrants items=items approvals=approvals /> })}
        </div>
    }
}

/// The approval key for a plan item: its kind and source appId, so approving
/// an app never approves a managed identity that shares the id.
fn approval_key(item: &backup::PrivilegedRestoreItem) -> backup::RestoreApproval {
    backup::RestoreApproval {
        kind: item.kind,
        source_app_id: item.source_app_id.clone(),
    }
}

/// The access the backup file would grant — admin consent (with each
/// permission's value and risk), federated credentials, owners, group
/// memberships, managed-identity app roles, and (shown only) pre-authorized
/// clients from outside the backup and role assignees — shown before Confirm,
/// with an approval checkbox on each item that needs one.
#[component]
fn PrivilegedGrants(
    items: Vec<backup::PrivilegedRestoreItem>,
    approvals: RwSignal<BTreeSet<backup::RestoreApproval>>,
) -> impl IntoView {
    let needs_approval = items.iter().filter(|i| i.requires_approval).count();
    let tone = if needs_approval > 0 { "warn" } else { "info" };
    // Every item that needs approval: what "Approve all listed" ticks. After
    // the list, so it is reached only having scrolled past what it approves;
    // nothing starts ticked.
    let all_keys: BTreeSet<backup::RestoreApproval> = items
        .iter()
        .filter(|i| i.requires_approval)
        .map(approval_key)
        .collect();
    view! {
        <div class="dr-view__privileged">
            <h3 class="dr-view__subhead">"Access this restore grants"</h3>
            <Callout tone=tone>
                "These come from the backup file, so whoever wrote the file chose them — review them before you restore. "
                {(needs_approval > 0).then(|| format!(
                    "{} standing access that needs your approval. Unapproved, the app is still created and wired, but its admin consent, federated credentials, owners and group memberships (a managed identity's app roles) are left out and listed in the report. Owners, reply URLs and the public-client flag are shown so you can see where consented tokens would go.",
                    count_noun(needs_approval, "item grants", "items grant"),
                ))}
            </Callout>
            <ul class="dr-view__report-list">
                {items.into_iter().map(|item| view! { <PrivilegedItem item=item approvals=approvals /> }).collect_view()}
            </ul>
            {(needs_approval > 1).then(move || view! {
                <div class="dr-view__actions">
                    <Button
                        appearance=ButtonAppearance::Secondary
                        on_click=move |_| approvals.update(|a| a.extend(all_keys.iter().cloned()))
                    >
                        "Approve all listed"
                    </Button>
                </div>
            })}
        </div>
    }
}

#[component]
fn PrivilegedItem(
    item: backup::PrivilegedRestoreItem,
    approvals: RwSignal<BTreeSet<backup::RestoreApproval>>,
) -> impl IntoView {
    let is_mi = item.kind == backup::PrivilegedKind::ManagedIdentity;
    let key = approval_key(&item);
    let checked_key = key.clone();
    let roles_heading = if is_mi {
        "Graph app roles re-bound:"
    } else {
        "Application permissions consented tenant-wide:"
    };
    let roles = item.app_roles.clone();
    let scopes = item.delegated_scopes.clone();
    let external = item.external_pre_authorized_clients.clone();
    let fics = item.federated_credentials.clone();
    let owners = item.owners.clone();
    let groups = item.group_memberships.clone();
    let assignees = item.app_role_assignees.clone();
    let reply_urls = item.reply_urls.clone();
    let public_client = item.public_client;
    view! {
        <li class="dr-view__report-app dr-view__privileged-item">
            <div class="dr-view__report-head">
                <strong>{item.display_name.clone()}</strong>
                <span class="dr-view__report-id">
                    {if is_mi { "managed identity" } else { "app registration" }}
                </span>
                {item.admin_consent.then(|| view! { <Badge label="admin consent" tone=BadgeTone::Warning /> })}
                {item.requires_approval.then(|| view! { <Badge label="needs approval" tone=BadgeTone::Danger /> })}
            </div>
            {(!roles.is_empty()).then(|| view! {
                <p class="dr-view__report-note">{roles_heading}</p>
                <PermissionList perms=roles delegated=false />
            })}
            {(!scopes.is_empty()).then(|| view! {
                <p class="dr-view__report-note">"Delegated permissions consented for every user:"</p>
                <PermissionList perms=scopes delegated=true />
            })}
            {(!external.is_empty()).then(|| view! {
                <p class="dr-view__report-note">
                    {format!(
                        "Pre-authorized client{} not in this backup (consent-free access to this API): {}",
                        plural(external.len()),
                        external.join(", "),
                    )}
                </p>
            })}
            {(!fics.is_empty()).then(|| view! {
                <p class="dr-view__report-note">"Federated credentials (secretless sign-in):"</p>
                <ul class="dr-view__perm-list">
                    {fics.into_iter().map(|f| {
                        let refused = f.rejected.map(|r| format!(" — will be refused: {r}"));
                        view! {
                            <li>
                                {format!("'{}': issuer {}, subject {}", f.name, f.issuer, f.subject)}
                                {refused}
                            </li>
                        }
                    }).collect_view()}
                </ul>
            })}
            {(!owners.is_empty()).then(|| view! {
                <p class="dr-view__report-note">{format!("Owners: {}", owners.join(", "))}</p>
            })}
            {(!reply_urls.is_empty()).then(|| view! {
                <p class="dr-view__report-note">
                    {format!("Reply URL{}: {}", plural(reply_urls.len()), reply_urls.join(", "))}
                </p>
            })}
            {public_client.then(|| view! {
                <p class="dr-view__report-note">"Public client: tokens without a secret (fallback enabled)"</p>
            })}
            {(!groups.is_empty()).then(|| view! {
                <p class="dr-view__report-note">
                    {format!("Joins group{}: {}", plural(groups.len()), groups.join(", "))}
                </p>
            })}
            {(!assignees.is_empty()).then(|| view! {
                <p class="dr-view__report-note">
                    {format!("Assigned to the app's roles: {}", assignees.join(", "))}
                </p>
            })}
            {item.requires_approval.then(move || view! {
                <label class="checkbox-row dr-view__approve">
                    <input
                        type="checkbox"
                        prop:checked=move || approvals.with(|a| a.contains(&checked_key))
                        on:change=move |ev| {
                            let on = event_target_checked(&ev);
                            let key = key.clone();
                            approvals.update(|a| {
                                if on {
                                    a.insert(key);
                                } else {
                                    a.remove(&key);
                                }
                            });
                        }
                    />
                    {if is_mi {
                        " Approve: re-bind these app roles"
                    } else {
                        " Approve: grant this app's consent, credentials, owners and group memberships"
                    }}
                </label>
            })}
        </li>
    }
}

/// One row per planned permission: its value (or id when it couldn't be
/// resolved), its resource, and its risk badge.
#[component]
fn PermissionList(perms: Vec<backup::PrivilegedPermission>, delegated: bool) -> impl IntoView {
    view! {
        <ul class="dr-view__perm-list">
            {perms.into_iter().map(|p| {
                let resource = p
                    .resource_display_name
                    .clone()
                    .unwrap_or_else(|| p.resource_app_id.clone());
                let label = p.value.clone().unwrap_or_else(|| p.permission_id.clone());
                let badge = permission_risk_badge(&p, delegated);
                view! {
                    <li>
                        <strong>{label}</strong>
                        {format!(" on {resource} ")}
                        {badge}
                    </li>
                }
            }).collect_view()}
        </ul>
    }
}

/// The badge for one planned permission. An application permission's risk
/// comes from the shared `app_permission_risk_badge`; the plan adds the two
/// states only it knows: unresolved, and an API this backup recreates.
fn permission_risk_badge(p: &backup::PrivilegedPermission, delegated: bool) -> AnyView {
    match (p.risk, p.value.as_deref()) {
        (backup::PermissionRisk::Unknown, _) => view! {
            <Badge
                label="Unknown"
                tone=BadgeTone::Unknown
                title="Couldn't be resolved in this tenant, so its risk is unknown — consenting to it needs approval"
            />
        }
        .into_any(),
        _ if p.restored_api => view! {
            <Badge label="API in this backup" tone=BadgeTone::Info title="Defined by an app this restore recreates" />
        }
        .into_any(),
        (backup::PermissionRisk::High, Some(_)) if delegated => view! {
            <Badge label="Broad" tone=BadgeTone::Warning title="Broad delegated permission, consented for every user" />
        }
        .into_any(),
        (_, Some(value)) if !delegated => app_permission_risk_badge(value),
        _ => ().into_any(),
    }
}

/// The restore report: a strong secrets warning, a save button, and per-app
/// detail including the show-once regenerated secret values.
#[component]
fn RestoreReportView(report: backup::RestoreReport, on_save: Callback<()>) -> impl IntoView {
    let total_secrets: usize = report
        .apps
        .iter()
        .map(|a| a.regenerated_secrets.len())
        .sum();
    let has_secrets = total_secrets > 0;
    let apps = report.apps.clone();
    let failures = report.failures.clone();
    let enterprise = report.enterprise_apps.clone();
    let managed = report.managed_identities.clone();
    let manual = report.manual_items.clone();
    // `cancelled` is set for BOTH an operator cancel and a session that died
    // mid-run, and `session_expired` is the only thing that tells them apart —
    // the backend has always set it and nothing here read it. The distinction is
    // the operator's next action: a cancel is resumable as-is, an expired
    // session means the destination tenant was left half-written by a run that
    // stopped where it happened to be, and they must re-authenticate first.
    let session_expired = report.session_expired;
    view! {
        <div class="dr-view__result">
            <p class="dr-view__summary">
                {format!(
                    "Restored {}{}. {} regenerated.",
                    count_noun(report.apps.len(), "app", "apps"),
                    match (report.cancelled, session_expired) {
                        (_, true) => " (stopped early — the sign-in session expired)",
                        (true, false) => " (cancelled before completing — partial)",
                        (false, false) => "",
                    },
                    count_noun(total_secrets, "secret", "secrets"),
                )}
            </p>
            <Show when=move || session_expired>
                <Callout tone="warn">
                    "The sign-in session expired part-way through this restore, so it stopped where it had got to rather than completing. Everything listed below was created and wired; anything absent was not attempted. Re-authenticate and run the restore again with the same backup file — apps this restore already created carry a restore tag and are recognised and finished rather than created twice."
                </Callout>
            </Show>
            <Show when=move || has_secrets>
                <p class="dr-view__warn">
                    "⚠ The regenerated secret values below are shown only once. Save the report, \
                     redistribute the secrets to each app's consumers, then delete the file."
                </p>
            </Show>
            <Button appearance=ButtonAppearance::Primary on_click=move |_| on_save.run(())>
                <Icon name=IconName::Download size=16 /> " Save report (contains secrets)…"
            </Button>

            <ul class="dr-view__report-list">
                {apps.into_iter().map(|a| {
                    let secrets = a.regenerated_secrets.clone();
                    let unresolved = a.unresolved_owners.clone();
                    let certs = a.certificates_needing_manual_upload.clone();
                    let warnings = a.warnings.clone();
                    view! {
                        <li class="dr-view__report-app">
                            <div class="dr-view__report-head">
                                <strong>{a.display_name}</strong>
                                <span class="dr-view__report-id">{format!("new appId {}", a.new_app_id)}</span>
                                {a.consent_granted.then(|| view! { <span class="dr-view__badge">"consent re-granted"</span> })}
                                {a.adopted.then(|| view! { <span class="dr-view__badge">"already restored — completed"</span> })}
                            </div>
                            {(!secrets.is_empty()).then(|| view! {
                                <ul class="dr-view__secrets">
                                    {secrets.into_iter().map(|s| view! {
                                        <li>
                                            <span class="dr-view__secret-name">{s.display_name}": "</span>
                                            // Show-once secret — must be copied in full before it's
                                            // gone, so give it a copy button like the new-secret dialog.
                                            <CopyableId value=s.secret_value label="secret value" full=true />
                                        </li>
                                    }).collect_view()}
                                </ul>
                            })}
                            {(!unresolved.is_empty()).then(|| view! {
                                <p class="dr-view__report-note">
                                    {format!("Unresolved owner{}: {}", plural(unresolved.len()), unresolved.join(", "))}
                                </p>
                            })}
                            {(!certs.is_empty()).then(|| view! {
                                <p class="dr-view__report-note">
                                    {format!("Re-upload certificate{}: {}", plural(certs.len()), certs.join(", "))}
                                </p>
                            })}
                            {(!warnings.is_empty()).then(|| view! {
                                <ul class="dr-view__warnings">
                                    {warnings.into_iter().map(|w| view! { <li>{w}</li> }).collect_view()}
                                </ul>
                            })}
                        </li>
                    }
                }).collect_view()}
            </ul>

            {(!enterprise.is_empty()).then(|| view! {
                <div class="dr-view__enterprise">
                    <h3 class="dr-view__subhead">"Enterprise app access re-applied"</h3>
                    <ul class="dr-view__report-list">
                        {enterprise.into_iter().map(|e| {
                            let unresolved = e.unresolved_principals.clone();
                            let warnings = e.warnings.clone();
                            view! {
                                <li class="dr-view__report-app">
                                    <div class="dr-view__report-head">
                                        <strong>{e.display_name}</strong>
                                        <span class="dr-view__report-id">
                                            {format!("{}, {}", count_noun(e.assignments_applied, "assignment", "assignments"), count_noun(e.group_memberships_applied, "group membership", "group memberships"))}
                                        </span>
                                    </div>
                                    {(!unresolved.is_empty()).then(|| view! {
                                        <p class="dr-view__report-note">
                                            {format!("Unresolved: {}", unresolved.join(", "))}
                                        </p>
                                    })}
                                    {(!warnings.is_empty()).then(|| view! {
                                        <ul class="dr-view__warnings">
                                            {warnings.into_iter().map(|w| view! { <li>{w}</li> }).collect_view()}
                                        </ul>
                                    })}
                                </li>
                            }
                        }).collect_view()}
                    </ul>
                </div>
            })}

            {(!managed.is_empty()).then(|| view! {
                <div class="dr-view__managed">
                    <h3 class="dr-view__subhead">"Managed identity app-roles re-bound"</h3>
                    <ul class="dr-view__report-list">
                        {managed.into_iter().map(|m| {
                            let warnings = m.warnings.clone();
                            view! {
                                <li class="dr-view__report-app">
                                    <div class="dr-view__report-head">
                                        <strong>{m.display_name}</strong>
                                        <span class="dr-view__report-id">
                                            {format!("{} re-bound", count_noun(m.app_roles_rebound, "Graph app role", "Graph app roles"))}
                                        </span>
                                    </div>
                                    {(!warnings.is_empty()).then(|| view! {
                                        <ul class="dr-view__warnings">
                                            {warnings.into_iter().map(|w| view! { <li>{w}</li> }).collect_view()}
                                        </ul>
                                    })}
                                </li>
                            }
                        }).collect_view()}
                    </ul>
                </div>
            })}

            {(!manual.is_empty()).then(|| view! {
                <div class="dr-view__manual">
                    <h3 class="dr-view__subhead">"Manual follow-up required"</h3>
                    <ul class="dr-view__report-list">
                        {manual.into_iter().map(|m| view! {
                            <li class="dr-view__report-app">
                                <strong>{m.display_name}</strong>
                                <p class="dr-view__report-note">{m.reason}</p>
                            </li>
                        }).collect_view()}
                    </ul>
                </div>
            })}

            {(!failures.is_empty()).then(|| view! {
                <div class="dr-view__failures">
                    <FormError>"Apps that could not be created:"</FormError>
                    <ul>
                        {failures.into_iter().map(|f| view! {
                            <li>{format!("{}: {}", f.display_name, f.message)}</li>
                        }).collect_view()}
                    </ul>
                </div>
            })}
        </div>
    }
}
