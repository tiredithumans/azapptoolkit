//! Disaster-recovery page: **backup** (capture a portable manifest) and
//! **restore** (replay it into the current tenant). The page is explicit about
//! the two hard DR realities — secret/cert values are never in the backup
//! (restore regenerates secrets and surfaces the show-once values), and managed
//! identities are Azure resources recreated out-of-band.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance, Spinner, SpinnerSize};

use crate::bindings::{backup, events};
use crate::components::icon::{Icon, IconName};
use crate::components::modal_shell::ModalShell;
use crate::components::ui::{Card, SectionHeader};
use crate::hooks::use_progress_stream::use_progress_stream;
use crate::state::use_session;

#[component]
pub fn DisasterRecoveryView() -> impl IntoView {
    let session = use_session();

    // ---- Backup state ----
    let captured: RwSignal<Option<backup::TenantBackup>> = RwSignal::new(None);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let progress: RwSignal<Option<crate::bindings::bulk::BulkProgress>> = RwSignal::new(None);
    use_progress_stream(progress, events::backup_progress);

    // ---- Restore state ----
    let loaded: RwSignal<Option<backup::TenantBackup>> = RwSignal::new(None);
    let plan: RwSignal<Option<backup::RestorePlan>> = RwSignal::new(None);
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
                        "Backed up {apps} app registration(s), {ent} enterprise app(s), \
                         {mis} managed identity(ies). Save it to a file to keep it."
                    ));
                }
                // A user-initiated cancel comes back as the `cancelled` code —
                // it's not a failure, so show a neutral toast, not a red banner.
                Err(e) if e.code == "cancelled" => {
                    session.toast_success("Backup cancelled.");
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
            progress.set(None);
        });
    };
    let cancel_backup = move |_| {
        leptos::task::spawn_local(async move {
            let _ = backup::cancel_dr().await;
        });
    };
    let save_file = move |_| {
        let Some(b) = captured.get() else {
            return;
        };
        leptos::task::spawn_local(async move {
            match backup::save_backup_to_file(&b, "json").await {
                Ok(Some(path)) => session.toast_success(format!("Backup saved to {path}")),
                Ok(None) => 0,
                Err(e) => session.toast_error(format!("Couldn't save backup: {}", e.message), None),
            };
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
                        plan.set(Some(p));
                        loaded.set(Some(b));
                    }
                    Err(e) => restore_error.set(Some(e.message)),
                },
                Ok(None) => {} // dialog cancelled
                Err(e) => restore_error.set(Some(e.message)),
            }
        });
    };
    let do_restore = move |_| {
        let (Some(tenant), Some(b)) = (session.active_tenant.get(), loaded.get()) else {
            return;
        };
        confirm_open.set(false);
        restoring.set(true);
        restore_error.set(None);
        report.set(None);
        restore_progress.set(None);
        leptos::task::spawn_local(async move {
            match backup::restore_tenant(&tenant.tenant_id, &b).await {
                Ok(r) => {
                    let secrets: usize = r.apps.iter().map(|a| a.regenerated_secrets.len()).sum();
                    session.toast_success(format!(
                        "Restored {} app(s); {} secret(s) regenerated. Save the report — \
                         the secret values are shown only once.",
                        r.apps.len(),
                        secrets
                    ));
                    report.set(Some(r));
                }
                Err(e) => restore_error.set(Some(e.message)),
            }
            restoring.set(false);
            restore_progress.set(None);
        });
    };
    let cancel_restore = move |_| {
        leptos::task::spawn_local(async move {
            let _ = backup::cancel_dr().await;
        });
    };
    let save_report = Callback::new(move |()| {
        let Some(r) = report.get() else {
            return;
        };
        leptos::task::spawn_local(async move {
            match backup::save_restore_report_to_file(&r, "json").await {
                Ok(Some(path)) => session.toast_success(format!("Report saved to {path}")),
                Ok(None) => 0,
                Err(e) => session.toast_error(format!("Couldn't save report: {}", e.message), None),
            };
        });
    });

    // Restore is blocked on a cloud mismatch (a hard error from the backend too).
    let cloud_blocked = move || plan.get().and_then(|p| p.cloud_mismatch).is_some();

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
                            let label = p.current_app.clone().map(|n| format!(" — {n}")).unwrap_or_default();
                            view! { <p class="dr-view__progress">{format!("Captured {}/{}", p.done, p.total)}{label}</p> }
                        })
                    }}
                </Show>
                <Show when=move || error.get().is_some()>
                    <p class="dr-view__error" role="alert">{move || error.get().unwrap_or_default()}</p>
                </Show>

                <Show when=move || captured.get().is_some()>
                    {move || {
                        let b = captured.get().unwrap();
                        let secrets: usize = b.app_registrations.iter().map(|a| a.secrets.len()).sum();
                        let (apps, ent, mis) = (
                            b.app_registrations.len(),
                            b.enterprise_apps.len(),
                            b.managed_identities.len(),
                        );
                        view! {
                            <div class="dr-view__result">
                                <p class="dr-view__summary">
                                    {format!(
                                        "Ready: {apps} app registration(s), {ent} enterprise app(s), \
                                         {mis} managed identity(ies). {secrets} secret(s) will need \
                                         regeneration on restore.",
                                    )}
                                </p>
                                <Button appearance=ButtonAppearance::Primary on_click=save_file>
                                    <Icon name=IconName::Download size=16 /> " Save backup file…"
                                </Button>
                            </div>
                        }
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
                    <Show when=move || plan.get().is_some() && !cloud_blocked() && !restoring.get()>
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
                    <p class="dr-view__error" role="alert">{move || restore_error.get().unwrap_or_default()}</p>
                </Show>

                // Plan preview (before confirming).
                <Show when=move || plan.get().is_some() && report.get().is_none()>
                    {move || plan.get().map(|p| view! { <RestorePlanView plan=p /> })}
                </Show>

                // Live restore progress.
                <Show when=move || restore_progress.get().is_some()>
                    {move || {
                        restore_progress.get().map(|p| {
                            let label = p.current_app.clone().map(|n| format!(" — {n}")).unwrap_or_default();
                            view! { <p class="dr-view__progress">{format!("Created {}/{}", p.done, p.total)}{label}</p> }
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
                     secrets. It does not overwrite or delete anything that already exists. The new \
                     secret values are shown only once — save the report afterwards."
                </p>
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

/// The dry-run plan: counts + the cloud-mismatch blocker + the tenant-change note.
#[component]
fn RestorePlanView(plan: backup::RestorePlan) -> impl IntoView {
    let cloud = plan.cloud_mismatch.clone();
    view! {
        <div class="dr-view__plan">
            {cloud.map(|m| view! {
                <p class="dr-view__error" role="alert">
                    {format!(
                        "This backup is from the \"{}\" cloud, but this app targets \"{}\". \
                         Restore is blocked — use a build configured for the backup's cloud.",
                        m.backup_cloud, m.destination_cloud,
                    )}
                </p>
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
                <li>{format!("{} app registration(s) to create", plan.app_registrations_to_create)}</li>
                <li>{format!("{} secret(s) to regenerate (new values issued)", plan.secrets_to_regenerate)}</li>
                <li>{format!("{} certificate(s) need manual re-upload", plan.certificates_needing_manual_upload)}</li>
                <li>{format!("{} federated credential(s) restored as-is", plan.federated_credentials_to_restore)}</li>
                <li>{format!("{} owner(s) to remap by name", plan.owners_to_remap)}</li>
            </ul>
        </div>
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
    view! {
        <div class="dr-view__result">
            <p class="dr-view__summary">
                {format!(
                    "Restored {} app(s){}. {} secret(s) regenerated.",
                    report.apps.len(),
                    if report.cancelled { " (cancelled before completing — partial)" } else { "" },
                    total_secrets,
                )}
            </p>
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
                            </div>
                            {(!secrets.is_empty()).then(|| view! {
                                <ul class="dr-view__secrets">
                                    {secrets.into_iter().map(|s| view! {
                                        <li>
                                            <span class="dr-view__secret-name">{s.display_name}": "</span>
                                            <code class="dr-view__secret-value">{s.secret_value}</code>
                                        </li>
                                    }).collect_view()}
                                </ul>
                            })}
                            {(!unresolved.is_empty()).then(|| view! {
                                <p class="dr-view__report-note">
                                    {format!("Unresolved owner(s): {}", unresolved.join(", "))}
                                </p>
                            })}
                            {(!certs.is_empty()).then(|| view! {
                                <p class="dr-view__report-note">
                                    {format!("Re-upload certificate(s): {}", certs.join(", "))}
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
                                            {format!("{} assignment(s), {} group membership(s)", e.assignments_applied, e.group_memberships_applied)}
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
                                            {format!("{} Graph app-role(s) re-bound", m.app_roles_rebound)}
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
                    <p class="dr-view__error">"Apps that could not be created:"</p>
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
