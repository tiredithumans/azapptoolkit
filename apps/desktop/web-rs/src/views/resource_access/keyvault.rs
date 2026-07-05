//! Key Vault panel — a tenant-wide sweep of every reachable Key Vault's direct
//! Azure-RBAC role assignments, filterable by vault or principal. Answers "which
//! apps / managed identities can touch this vault?" (and, filtered by principal,
//! the reverse). Mirrors the Sites panel; the plane is ARM, so consent uses the
//! `arm` feature and rows come from role assignments rather than site grants.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, ProgressBar};

use crate::bindings::auth;
use crate::bindings::events;
use crate::bindings::keyvault_rbac::{
    self, KeyVaultAccessRow, KeyVaultSweepProgress, KeyVaultSweepResult,
};
use crate::bindings::sharepoint;
use crate::components::ui::SearchInput;
use crate::constants::*;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_grid_keynav::use_grid_keynav;
use crate::hooks::use_progress_stream::use_progress_stream;
use crate::state::use_session;

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

/// A stable key for the keyed `<For>` — one principal holds one role per vault.
fn row_key(row: &KeyVaultAccessRow) -> String {
    format!("{}|{}|{}", row.vault_id, row.principal_id, row.role_name)
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
    let search = RwSignal::new(String::new());

    let search_debounced = use_debounced(search.into(), LIST_FILTER_DEBOUNCE_MS);
    // Lowercased search haystack per row, rebuilt once per sweep result (reads
    // `result`, not the query) so a keystroke just runs `contains`.
    let corpus: Memo<Vec<String>> = Memo::new(move |_| {
        result.with(|r| {
            r.as_ref()
                .map(|r| r.rows.iter().map(row_haystack).collect::<Vec<_>>())
                .unwrap_or_default()
        })
    });
    let filtered_rows = Memo::new(move |_| {
        let needle = search_debounced.get().trim().to_lowercase();
        result.with(|r| {
            r.as_ref()
                .map(|r| {
                    if needle.is_empty() {
                        return r.rows.clone();
                    }
                    corpus.with(|hays| {
                        r.rows
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| hays.get(*i).is_some_and(|h| h.contains(&needle)))
                            .map(|(_, row)| row.clone())
                            .collect::<Vec<_>>()
                    })
                })
                .unwrap_or_default()
        })
    });
    let render_limit = RwSignal::new(RENDER_PAGE);
    Effect::new(move |prev: Option<()>| {
        search_debounced.track();
        let _ = filtered_rows.with(|r| r.len());
        if prev.is_some() {
            render_limit.set(RENDER_PAGE);
        }
    });
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
                        "{} role assignment{} across {} vault{} — scanned {} of {} vault{}{}{}",
                        rows.len(),
                        if rows.len() == 1 { "" } else { "s" },
                        distinct_vaults,
                        if distinct_vaults == 1 { "" } else { "s" },
                        r.vaults_scanned,
                        r.total_vaults,
                        if r.total_vaults == 1 { "" } else { "s" },
                        if r.vaults_failed > 0 {
                            format!(" ({} failed — coverage is partial)", r.vaults_failed)
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

    use_progress_stream(progress, events::keyvault_sweep_progress);

    // Hydrate from the backend cache on tenant change, guarding the async write
    // against a tenant switch.
    Effect::new(move |_| {
        let t = tenant.get();
        result.set(None);
        error.set(None);
        progress.set(None);
        consent_required.set(false);
        let Some(t) = t else { return };
        let tenant_id = t.tenant_id.clone();
        leptos::task::spawn_local(async move {
            let cached = keyvault_rbac::get_cached_key_vault_access(&tenant_id)
                .await
                .ok()
                .flatten();
            let still_active = tenant
                .get_untracked()
                .map(|t| t.tenant_id == tenant_id)
                .unwrap_or(false);
            if still_active {
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
                    consent_required.set(e.code == "consent_required");
                    error.set(Some(e.message));
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
            match auth::request_scope_consent(&t.tenant_id, "arm").await {
                Ok(()) => do_run(),
                Err(e) => error.set(Some(e.message)),
            }
        });
    };

    let cancel = move |_| {
        leptos::task::spawn_local(async move {
            let _ = sharepoint::cancel_resource_sweep().await;
        });
    };

    view! {
        <Body1>
            "Scans every reachable Key Vault's direct Azure RBAC role assignments; search by principal to see the vaults an app or managed identity can reach, or by vault to see who can touch it. Only direct (atScope) grants are shown — roles inherited from the subscription or resource group aren't listed."
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
                        <div class="alert alert--warn">
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
                        </div>
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
                                "No role assignments match. Vaults without direct RBAC assignments produce no rows — a vault in legacy access-policy mode, or one reachable only via inherited subscription roles, won't appear here (see the Security audit for the broader picture)."
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
                                                            <span class="badge badge--warning">
                                                                "High-privilege"
                                                            </span>
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
                        (total > limit)
                            .then(|| {
                                let remaining = total - limit;
                                let next = RENDER_PAGE.min(remaining);
                                view! {
                                    <div class="audit-show-more">
                                        <Body1>
                                            {format!("Showing {limit} of {total} matching rows")}
                                        </Body1>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| {
                                                render_limit.update(|n| *n += RENDER_PAGE)
                                            })
                                        >
                                            {format!("Show {next} more")}
                                        </Button>
                                    </div>
                                }
                            })
                    }}
                </Show>
            }
                .into_any()
        }}
    }
}
