//! Key Vault panel — a tenant-wide sweep of every reachable Key Vault's
//! Azure-RBAC role assignments (made on the vault or inherited from an ancestor
//! scope, the latter badged Inherited), filterable by vault or principal. Answers "which
//! apps / managed identities can touch this vault?" (and, filtered by principal,
//! the reverse). Mirrors the Sites panel; the plane is ARM, so consent uses the
//! `arm` feature and rows come from role assignments rather than site grants.

use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, ProgressBar};

use crate::bindings::auth;
use crate::bindings::events;
use crate::bindings::keyvault_rbac::{
    self, KeyVaultAccessRow, KeyVaultSweepProgress, KeyVaultSweepResult,
};
use crate::components::export_menu::ExportMenu;
use crate::components::ui::SearchInput;
use crate::components::ui::{Badge, BadgeTone, Callout, ShowMore};
use crate::components::verify_identity_button::{VERIFY_IDENTITY_MESSAGE, VerifyIdentityButton};
use crate::hooks::use_grid_keynav::use_grid_keynav;
use crate::hooks::use_list_export::use_list_export;
use crate::hooks::use_progress_stream::use_progress_stream;
use crate::state::use_session;
use crate::util::plural;

/// Lowercased haystack of a row's vault + principal + role facets, newline-joined
/// so one search box serves both lookup directions. Built once per sweep result.
fn row_haystack(row: &KeyVaultAccessRow) -> String {
    let mut hay = String::new();
    let mut push = |v: &str| {
        if !v.is_empty() {
            hay.push_str(&v.to_lowercase());
            hay.push('\n');
        }
    };
    push(&row.vault_id);
    if let Some(v) = row.vault_name.as_deref() {
        push(v);
    }
    push(&row.principal_id);
    if let Some(v) = row.principal_display_name.as_deref() {
        push(v);
    }
    if let Some(v) = row.principal_type.as_deref() {
        push(v);
    }
    push(&row.role_name);
    hay
}

/// A stable key for the keyed `<For>`. The scope is part of it: with inherited
/// rows listed, one principal can hold the same role on a vault both directly
/// and from an ancestor (Reader on the vault AND on its subscription).
fn row_key(row: &KeyVaultAccessRow) -> String {
    format!(
        "{}|{}|{}|{}",
        row.vault_id, row.principal_id, row.role_name, row.scope
    )
}

#[component]
pub(super) fn KeyVaultPanel() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let result: RwSignal<Option<KeyVaultSweepResult>> = RwSignal::new(None);
    let scanning = RwSignal::new(false);
    let progress: RwSignal<Option<KeyVaultSweepProgress>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let consent_required = RwSignal::new(false);
    // A Conditional Access step-up for Azure management (`interaction_required`).
    let step_up_required = RwSignal::new(false);
    let search = RwSignal::new(String::new());

    let (filtered_rows, render_limit) =
        super::use_sweep_filter(result, search, |r| &r.rows, row_haystack);
    let tbody_ref: NodeRef<leptos::html::Tbody> = NodeRef::new();
    let on_grid_key = use_grid_keynav(tbody_ref, move || {
        let _ = render_limit.get();
        let _ = filtered_rows.with(|r| r.len());
    });
    let summary = Memo::new(move |_| {
        result.with(|r| {
            r.as_ref().map(|r| {
                filtered_rows.with(|rows| {
                    let distinct_vaults = {
                        let mut ids: Vec<&str> = rows.iter().map(|x| x.vault_id.as_str()).collect();
                        ids.sort_unstable();
                        ids.dedup();
                        ids.len()
                    };
                    format!(
                        "{} role assignment{} across {} vault{} — scanned {} of {} vault{}{}{}{}",
                        rows.len(),
                        plural(rows.len()),
                        distinct_vaults,
                        plural(distinct_vaults),
                        r.vaults_scanned,
                        r.total_vaults,
                        plural(r.total_vaults),
                        if r.vaults_failed > 0 {
                            format!(" ({} failed — coverage is partial)", r.vaults_failed)
                        } else {
                            String::new()
                        },
                        // The other "empty ≠ no access": these vaults answer the
                        // RBAC listing empty by design — their grants are made
                        // through access policies this scan cannot enumerate.
                        if r.vaults_access_policy_mode > 0 {
                            format!(
                                " ({} vault{} in legacy access-policy mode — their access grants are invisible to this scan)",
                                r.vaults_access_policy_mode,
                                plural(r.vaults_access_policy_mode)
                            )
                        } else {
                            String::new()
                        },
                        if r.cancelled {
                            " — scan was cancelled early"
                        } else {
                            ""
                        },
                    )
                })
            })
        })
    });

    // "Who can read this vault?" is an answer an operator gets asked to produce
    // in writing; before this the only way out of the app was a screenshot.
    // Reuses the inventory lists' export handle, and ships the SUMMARY with the
    // rows — a vault whose role read failed contributes none, so a file without
    // "(N failed — coverage is partial)" would overstate what was checked.
    let (export_rows, exporting, do_export) = use_list_export(
        move |rows: Arc<Vec<KeyVaultAccessRow>>, format| async move {
            let coverage = summary.get_untracked().unwrap_or_default();
            keyvault_rbac::save_key_vault_access_to_file(&rows, &coverage, format).await
        },
        "role assignments",
    );
    // Keep the export snapshot in step with what's rendered — what you see is
    // what you export, filter included.
    Effect::new(move |_| export_rows.set_value(Arc::new(filtered_rows.get())));

    use_progress_stream(progress, events::keyvault_sweep_progress);

    // Hydrate from the backend cache on tenant change, guarding the async write
    // against a tenant switch.
    Effect::new(move |_| {
        let t = tenant.get();
        result.set(None);
        error.set(None);
        progress.set(None);
        consent_required.set(false);
        step_up_required.set(false);
        let Some(t) = t else { return };
        let tenant_id = t.tenant_id.clone();
        leptos::task::spawn_local(async move {
            let cached = keyvault_rbac::get_cached_key_vault_access(&tenant_id)
                .await
                .ok()
                .flatten();
            if session.is_active_tenant(&tenant_id) {
                result.set(cached);
            }
        });
    });

    let do_run = move || {
        if scanning.get() {
            return;
        }
        scanning.set(true);
        error.set(None);
        consent_required.set(false);
        step_up_required.set(false);
        progress.set(Some(KeyVaultSweepProgress {
            done: 0,
            total: 0,
            current_vault: None,
            cancelled: false,
        }));
        let t = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = t else {
                scanning.set(false);
                return;
            };
            match keyvault_rbac::sweep_key_vault_access(&t.tenant_id).await {
                Ok(r) => result.set(Some(r)),
                Err(e) => {
                    consent_required.set(e.is_consent_required());
                    step_up_required.set(e.is_interaction_required());
                    // A dead session gets the Re-authenticate lever instead of a
                    // dead-end line; consent and step-up keep this panel's own
                    // buttons.
                    if !session.report_if_session_dead(&e) {
                        error.set(Some(if e.is_interaction_required() {
                            VERIFY_IDENTITY_MESSAGE.to_string()
                        } else {
                            e.message
                        }));
                    }
                }
            }
            scanning.set(false);
            progress.set(None);
        });
    };

    // Interactive consent for the ARM scope, then re-run.
    let grant_consent = move |_| {
        if scanning.get() {
            return;
        }
        let Some(t) = tenant.get() else { return };
        error.set(None);
        leptos::task::spawn_local(async move {
            let res = auth::request_scope_consent(&t.tenant_id, "arm").await;
            // The consent prompt is answered minutes later, perhaps after a
            // sign-out: `do_run` reads `scanning`, which panics once disposed.
            if scanning.is_disposed() || !session.is_active_tenant(&t.tenant_id) {
                return;
            }
            match res {
                Ok(()) => do_run(),
                Err(e) => {
                    if !session.report_if_session_dead(&e) {
                        error.set(Some(e.message));
                    }
                }
            }
        });
    };

    let cancel = move |_| {
        leptos::task::spawn_local(async move {
            let _ = keyvault_rbac::cancel_key_vault_sweep().await;
        });
    };

    view! {
        <Body1>
            "Scans every reachable Key Vault's Azure RBAC role assignments — those made on the vault and those inherited from its resource group, subscription or management group (marked Inherited); search by principal to see the vaults an app or managed identity can reach, or by vault to see who can touch it."
        </Body1>
        <div class="actions-row">
            {move || {
                if scanning.get() {
                    view! {
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(cancel)
                        >
                            "Cancel"
                        </Button>
                    }
                        .into_any()
                } else {
                    view! {
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(move |_| do_run())
                        >
                            {if result.with(|r| r.is_some()) {
                                "Re-scan vaults"
                            } else {
                                "Scan vaults"
                            }}
                        </Button>
                    }
                        .into_any()
                }
            }}
            <div class="page__search">
                <SearchInput value=search placeholder="Filter by vault, principal, or role…" />
            </div>
            <ExportMenu
                disabled=Signal::derive(move || {
                    exporting.get() || filtered_rows.with(Vec::is_empty)
                })
                on_select=Callback::new(do_export)
                options=vec![("csv", "Export as CSV…"), ("json", "Export as JSON…")]
            />
        </div>
        {move || {
            progress
                .get()
                .filter(|_| scanning.get())
                .map(|p| {
                    let pct = if p.total == 0 { 0.0 } else { p.done as f64 / p.total as f64 };
                    view! {
                        <div class="audit-progress">
                            <ProgressBar value=Signal::derive(move || pct) />
                            <Body1>
                                {format!(
                                    "{} / {} vaults{}{}",
                                    p.done,
                                    p.total,
                                    p.current_vault.as_deref().map(|s| format!(" — {s}")).unwrap_or_default(),
                                    if p.cancelled { " (cancelling…)" } else { "" },
                                )}
                            </Body1>
                        </div>
                    }
                })
        }}
        {move || {
            error
                .get()
                .map(|e| {
                    view! {
                        <Callout tone="warn">
                            <Body1>{e}</Body1>
                            {consent_required
                                .get()
                                .then(|| {
                                    view! {
                                        <div class="actions-row">
                                            <Button
                                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                on_click=Box::new(grant_consent)
                                            >
                                                "Grant consent & retry"
                                            </Button>
                                        </div>
                                    }
                                })}
                            {step_up_required
                                .get()
                                .then(|| {
                                    view! {
                                        <VerifyIdentityButton
                                            features=&["arm"]
                                            on_verified=Callback::new(move |()| do_run())
                                        />
                                    }
                                })}
                        </Callout>
                    }
                })
        }}
        {move || {
            if result.with(|r| r.is_none()) {
                return if !scanning.get() {
                    view! {
                        <Body1>
                            "No scan yet for this tenant. Scanning enumerates every Key Vault you can reach and reads its role assignments with the signed-in user's Azure Reader rights — it can take a while on large estates and can be cancelled anytime."
                        </Body1>
                    }
                        .into_any()
                } else {
                    ().into_any()
                };
            }
            let on_grid_key = on_grid_key.clone();
            view! {
                <Body1 class="page__summary">{move || summary.get().unwrap_or_default()}</Body1>
                <Show
                    when=move || filtered_rows.with(|r| !r.is_empty())
                    fallback=|| {
                        view! {
                            <Body1>
                                "No role assignments match. A vault in legacy access-policy mode grants data access through access policies, which aren't listed here (see the Security audit for the broader picture)."
                            </Body1>
                        }
                    }
                >
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>"Vault"</th>
                                <th>"Principal"</th>
                                <th>"Role"</th>
                            </tr>
                        </thead>
                        <tbody node_ref=tbody_ref on:keydown=on_grid_key.clone()>
                            <For
                                each=move || {
                                    let limit = render_limit.get();
                                    filtered_rows
                                        .with(|r| r.iter().take(limit).cloned().collect::<Vec<_>>())
                                }
                                key=row_key
                                children=move |row| {
                                    let vault_primary = row
                                        .vault_name
                                        .clone()
                                        .unwrap_or_else(|| row.vault_id.clone());
                                    let principal_primary = row
                                        .principal_display_name
                                        .clone()
                                        .unwrap_or_else(|| {
                                            row.principal_type
                                                .clone()
                                                .map(|t| format!("({t})"))
                                                .unwrap_or_else(|| "(unknown principal)".into())
                                        });
                                    let principal_secondary = row.principal_id.clone();
                                    let high = row.high_privilege;
                                    let role_name = row.role_name.clone();
                                    let inherited = row.inherited;
                                    let scope = row.scope.clone();
                                    view! {
                                        <tr>
                                            <td class="cell-mid">{vault_primary}</td>
                                            <td class="permission-cell">
                                                <div class="permissions-cell__primary">
                                                    {principal_primary}
                                                </div>
                                                <div class="permissions-cell__secondary mono">
                                                    {principal_secondary}
                                                </div>
                                            </td>
                                            <td class="cell-mid">
                                                {role_name}
                                                {high
                                                    .then(|| {
                                                        view! {
                                                            <Badge label="High-privilege" tone=BadgeTone::Warning />
                                                        }
                                                    })}
                                                {inherited
                                                    .then(|| {
                                                        view! {
                                                            <Badge
                                                                label="Inherited"
                                                                title=format!("Inherited from {scope}")
                                                            />
                                                        }
                                                    })}
                                            </td>
                                        </tr>
                                    }
                                }
                            />
                        </tbody>
                    </table>
                    {move || {
                        let total = filtered_rows.with(|r| r.len());
                        let limit = render_limit.get();
                        view! {
                            <ShowMore
                                total=total
                                limit=limit
                                render_limit=render_limit
                                noun="matching rows"
                            />
                        }
                    }}
                </Show>
            }
                .into_any()
        }}
    }
}
