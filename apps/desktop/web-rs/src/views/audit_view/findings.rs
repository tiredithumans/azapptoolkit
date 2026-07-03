//! The Findings pane — the Security workbench's default view.
//!
//! A ranked, grouped list of finding categories (Defender-recommendations
//! style): each group header shows its severity tone, affected-principal
//! count, and a "Fix all" affordance; expanding (accordion, one at a time via
//! `Session.audit_expanded_group`) reveals the affected principals with
//! per-row Open/Fix actions, a per-group multi-select, and the shared
//! `BulkActionBar` offering exactly the fix that pairs with the group's rule.
//! Positive signals (already-scoped access) sit demoted in a collapsed
//! "Healthy configuration" disclosure below the ranked list.

use std::collections::HashSet;

use azapptoolkit_core::audit::AuditPrincipalKind;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::components::bulk_action_bar::BulkActionBar;
use crate::components::select_all_bar::SelectAllBar;
use crate::constants::*;
use crate::state::use_session;

use super::controller::AuditController;
use super::groups::{FindingGroup, GroupSection, group_bulk_actions, group_findings};
use super::row::AuditRowActions;
use super::{last_sign_in_cell, risk_class};

#[component]
pub(crate) fn FindingsPane() -> impl IntoView {
    let session = use_session();
    let ctrl = expect_context::<AuditController>();
    let expanded = session.audit_expanded_group;
    let selection = session.selected_audit_ids;

    let groups = Memo::new(move |_| {
        ctrl.result
            .with(|r| r.as_ref().map(|r| group_findings(&r.items)))
    });

    // Render window inside the one expanded group (a group can hold every app
    // in the tenant). Reset when the expansion changes; clearing the selection
    // there too keeps "Fix selected" scoped to the group the user is looking
    // at (one shared selection set serves both workbench panes).
    let render_limit = RwSignal::new(RENDER_PAGE);
    Effect::new(move |prev: Option<Option<String>>| {
        let cur = expanded.get();
        if let Some(prev) = prev
            && prev != cur
        {
            session.clear_audit_selection();
            render_limit.set(RENDER_PAGE);
        }
        cur
    });

    let healthy_open = RwSignal::new(false);

    view! {
        <div class="findings-pane">
            {move || {
                let Some(gs) = groups.get() else {
                    return view! {
                        <Body1>"Run an audit to populate the findings."</Body1>
                    }
                        .into_any();
                };
                let (actionable, healthy): (Vec<FindingGroup>, Vec<FindingGroup>) = gs
                    .into_iter()
                    .partition(|g| matches!(g.spec.section, GroupSection::Actionable));
                let any_findings = actionable.iter().any(|g| !g.item_indices.is_empty());
                view! {
                    <div class="finding-groups">
                        {(!any_findings)
                            .then(|| {
                                view! {
                                    <div class="alert alert--ok">
                                        "No actionable findings — nothing to fix right now."
                                    </div>
                                }
                            })}
                        {actionable
                            .into_iter()
                            .filter(|g| !g.item_indices.is_empty())
                            .map(|g| {
                                finding_group_view(g, ctrl, expanded, selection, render_limit, true)
                            })
                            .collect_view()}
                        {(!ctrl.report_available.get())
                            .then(|| {
                                view! {
                                    <p class="muted findings-pane__note">
                                        "Unused-app detection is off for this run — it needs the sign-in activity report (AuditLog.Read.All and Entra ID P1/P2). Grant consent above and re-run to enable it."
                                    </p>
                                }
                            })}
                        <div class="finding-groups__healthy">
                            <button
                                type="button"
                                class="finding-group__header finding-group__header--section"
                                on:click=move |_| healthy_open.update(|o| *o = !*o)
                            >
                                <span class="finding-group__chevron">
                                    {move || if healthy_open.get() { "▾" } else { "▸" }}
                                </span>
                                "Healthy configuration"
                            </button>
                            <Show when=move || healthy_open.get()>
                                {healthy
                                    .iter()
                                    .map(|g| {
                                        finding_group_view(
                                            FindingGroup {
                                                spec: g.spec,
                                                item_indices: g.item_indices.clone(),
                                                worst: g.worst,
                                                impact: g.impact,
                                            },
                                            ctrl,
                                            expanded,
                                            selection,
                                            render_limit,
                                            false,
                                        )
                                    })
                                    .collect_view()}
                            </Show>
                        </div>
                    </div>
                }
                    .into_any()
            }}
        </div>
    }
}

/// One finding group: a header row (tone dot, title, count, chevron, optional
/// "Fix all N") plus the expandable panel (blurb, bulk bar, select-all, rows).
/// `actionable` gates the checkbox column, Fix-all, and the bulk bar — Healthy
/// groups render read-only rows.
fn finding_group_view(
    g: FindingGroup,
    ctrl: AuditController,
    expanded: RwSignal<Option<String>>,
    selection: RwSignal<HashSet<String>>,
    render_limit: RwSignal<usize>,
    actionable: bool,
) -> AnyView {
    let session = use_session();
    let key = g.spec.key;
    let title = g.spec.title;
    let blurb = g.spec.blurb;
    let count = g.item_indices.len();
    let is_open = move || expanded.get().as_deref() == Some(key);
    let toggle = move |_| {
        expanded.update(|e| {
            if e.as_deref() == Some(key) {
                *e = None;
            } else {
                *e = Some(key.to_string());
            }
        });
    };

    // Bulk-eligible rows: app registrations only — SP/MI rows must never enter
    // the selection (the bulk commands loop app-registration cores). A derived
    // `Signal` (Copy) so the Fix-all button, its label, and the select-all bar
    // all share it without threading clones.
    let indices = g.item_indices.clone();
    let eligible_ids: Signal<Vec<String>> = Signal::derive({
        let indices = indices.clone();
        move || {
            ctrl.result.with(|r| {
                r.as_ref()
                    .map(|r| {
                        indices
                            .iter()
                            .filter_map(|&i| r.items.get(i))
                            .filter(|it| it.principal_kind == AuditPrincipalKind::Application)
                            .map(|it| it.object_id.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
        }
    });
    let bulk_actions = group_bulk_actions(key);
    let has_bulk = actionable && !bulk_actions.is_empty();
    let fix_all = move |_| {
        let ids: HashSet<String> = eligible_ids.get().into_iter().collect();
        if ids.is_empty() {
            return;
        }
        expanded.set(Some(key.to_string()));
        selection.set(ids);
    };

    let tone = match g.worst {
        azapptoolkit_core::audit::RiskLevel::Critical => "critical",
        azapptoolkit_core::audit::RiskLevel::High => "danger",
        azapptoolkit_core::audit::RiskLevel::Medium => "warning",
        azapptoolkit_core::audit::RiskLevel::Low => "ok",
    };
    let head_class = if actionable {
        "finding-group"
    } else {
        "finding-group finding-group--healthy"
    };

    let rows = {
        let indices = indices.clone();
        move || {
            let limit = render_limit.get();
            ctrl.result.with(|r| {
                r.as_ref()
                    .map(|r| {
                        indices
                            .iter()
                            .take(limit)
                            .filter_map(|&i| r.items.get(i).map(|it| (i, it.clone())))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
        }
    };

    view! {
        <section class=head_class>
            <div class="finding-group__head">
                <button type="button" class="finding-group__header" on:click=toggle>
                    <span class=format!(
                        "finding-group__tone finding-group__tone--{tone}",
                    )></span>
                    <span class="finding-group__title">{title}</span>
                    <span class="finding-group__count">
                        {format!(
                            "{count} {}",
                            if count == 1 { "principal" } else { "principals" },
                        )}
                    </span>
                    <span class="finding-group__chevron">
                        {move || if is_open() { "▾" } else { "▸" }}
                    </span>
                </button>
                // Only on the expanded group — collapsed headers stay calm, and
                // at most one "Fix all" exists at a time (accordion).
                {has_bulk
                    .then(|| {
                        view! {
                            <Show when=is_open>
                                <Button
                                    class="finding-fix-all"
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    on_click=Box::new(fix_all)
                                >
                                    {move || format!("Fix all {}", eligible_ids.get().len())}
                                </Button>
                            </Show>
                        }
                    })}
            </div>
            <Show when=is_open>
                <div class="finding-group__body">
                    <p class="muted finding-group__blurb">{blurb}</p>
                    {(key == "unused" && !ctrl.report_available.get())
                        .then(|| {
                            view! {
                                <div class="alert">
                                    "The sign-in activity report wasn't available for this run, so unused detection carries no signal — grant consent above and re-run."
                                </div>
                            }
                        })}
                    {has_bulk
                        .then(|| {
                            let actions = bulk_actions.clone();
                            view! {
                                <BulkActionBar
                                    selection=selection
                                    actions=Signal::derive(move || actions.clone())
                                    on_done=ctrl.on_bulk_done
                                />
                            }
                        })}
                    {actionable
                        .then(|| {
                            view! {
                                {move || {
                                    let ids = eligible_ids.get();
                                    let label = format!(
                                        "{count} affected — {} selectable for bulk fixes",
                                        ids.len(),
                                    );
                                    view! {
                                        <SelectAllBar
                                            count_label=label
                                            visible_ids=ids
                                            selected=selection
                                        />
                                    }
                                }}
                            }
                        })}
                    <table class="data-table">
                        <thead>
                            <tr>
                                {actionable
                                    .then(|| {
                                        view! {
                                            <th class="data-table__check" aria-label="Select"></th>
                                        }
                                    })}
                                <th>"Application"</th>
                                <th>"Risk"</th>
                                <th>"Score"</th>
                                <th>"Last sign-in"</th>
                                <th>"Actions"</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For
                                each=rows.clone()
                                key=|(_, i)| (i.object_id.clone(), i.remediations.len())
                                children=move |(_, i)| {
                                    let oid = i.object_id.clone();
                                    let oid_change = oid.clone();
                                    let check_label = format!(
                                        "Select {} for bulk actions",
                                        i.application_name,
                                    );
                                    let is_app_reg = i.principal_kind
                                        == AuditPrincipalKind::Application;
                                    view! {
                                        <tr>
                                            {actionable
                                                .then(|| {
                                                    view! {
                                                        <td class="data-table__check">
                                                            {if is_app_reg {
                                                                view! {
                                                                    <input
                                                                        type="checkbox"
                                                                        aria-label=check_label
                                                                        prop:checked=move || session.is_audit_selected(&oid)
                                                                        on:change=move |_| {
                                                                            session.toggle_audit_selected(oid_change.clone())
                                                                        }
                                                                    />
                                                                }
                                                                    .into_any()
                                                            } else {
                                                                view! {
                                                                    <span
                                                                        class="muted"
                                                                        title="Bulk actions target app registrations — this principal has no local one"
                                                                    >
                                                                        "—"
                                                                    </span>
                                                                }
                                                                    .into_any()
                                                            }}
                                                        </td>
                                                    }
                                                })}
                                            <td>
                                                <div>{i.application_name.clone()}</div>
                                                <div class="mono muted finding-group__appid">
                                                    {i.app_id.clone()}
                                                </div>
                                            </td>
                                            <td>
                                                <span class=format!(
                                                    "badge {}",
                                                    risk_class(&i.risk_level),
                                                )>{i.risk_level.as_str()}</span>
                                            </td>
                                            <td>{i.risk_score}</td>
                                            <td>{last_sign_in_cell(&i)}</td>
                                            <td>
                                                <AuditRowActions item=i.clone() on_done=ctrl.on_remediated />
                                            </td>
                                        </tr>
                                    }
                                }
                            />
                        </tbody>
                    </table>
                    {move || {
                        let limit = render_limit.get();
                        (count > limit)
                            .then(|| {
                                let next = RENDER_PAGE.min(count - limit);
                                view! {
                                    <div class="audit-show-more">
                                        <Body1>
                                            {format!("Showing {limit} of {count} affected")}
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
                </div>
            </Show>
        </section>
    }
    .into_any()
}
