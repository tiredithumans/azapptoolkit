//! Access-readiness checklist — what the signed-in user currently holds (active
//! directory roles + consented scopes) vs. what each feature needs, grouped by
//! the three authorization planes.
//!
//! There is no single role that unlocks the whole app (see
//! `docs/operator-rbac/OPERATOR-ROLES.md`), so this page tells the user exactly
//! which roles/scopes to activate. Each capability shows **two** verdicts — the
//! standing role and the consented scope ("Two halves, both required") — as
//! ✓ Have / ✗ Missing / ? Unknown. Reached from the account menu on the top-bar
//! tenant pill; the top-bar "Refresh token" control re-runs this check in place
//! (via `Session::readiness_reload`). Backed by `commands::readiness::check_readiness`,
//! which is best-effort: anything it can't prove comes back as `Unknown`.

use leptos::prelude::*;
use thaw::Body1;

use azapptoolkit_dto::readiness::{ReadinessItem, ReadinessReport, Verdict};

use crate::bindings::readiness;
use crate::state::use_session;

/// (badge class, label) for a verdict pill.
fn verdict_meta(v: Verdict) -> (&'static str, &'static str) {
    match v {
        Verdict::Have => ("badge badge--ok", "✓ Have"),
        Verdict::Missing => ("badge badge--danger", "✗ Missing"),
        Verdict::Unknown => ("badge badge--warning", "? Unknown"),
    }
}

/// Groups items by their plane label, preserving catalog order (the planes are
/// already contiguous in the catalog, so this is a single linear pass).
fn group_by_plane(items: Vec<ReadinessItem>) -> Vec<(String, Vec<ReadinessItem>)> {
    let mut groups: Vec<(String, Vec<ReadinessItem>)> = Vec::new();
    for item in items {
        match groups.last_mut() {
            Some(last) if last.0 == item.plane_label => last.1.push(item),
            _ => groups.push((item.plane_label.clone(), vec![item])),
        }
    }
    groups
}

fn verdict_row(axis: &'static str, verdict: Verdict, detail: String) -> impl IntoView {
    let (class, label) = verdict_meta(verdict);
    view! {
        <div class="readiness__axis">
            <span class="readiness__axis-name">{axis}</span>
            <span class=class>{label}</span>
            <span class="readiness__axis-detail">{detail}</span>
        </div>
    }
}

fn item_card(item: ReadinessItem) -> impl IntoView {
    // The remediation is only useful when at least one half is unmet.
    let show_remediation =
        item.role_verdict != Verdict::Have || item.scope_verdict != Verdict::Have;
    let remediation = show_remediation.then(|| {
        view! { <Body1 class="readiness__remediation">{item.remediation.clone()}</Body1> }
    });
    view! {
        <div class="readiness__item">
            <div class="readiness__item-head">
                <strong>{item.label.clone()}</strong>
                <span class="readiness__desc">{item.description.clone()}</span>
            </div>
            {verdict_row("Role", item.role_verdict, item.role_detail.clone())}
            {verdict_row("Scope", item.scope_verdict, item.scope_detail.clone())}
            {remediation}
        </div>
    }
}

fn render_report(rep: ReadinessReport) -> impl IntoView {
    let indeterminate = rep.directory_roles_indeterminate;
    let banner = indeterminate.then(|| {
        view! {
            <div class="alert alert--warn">
                "Couldn't read your active directory roles, so directory-role requirements show as \
                 \"?\". This is usually a missing Directory.Read.All consent or a tenant that \
                 restricts directory reads."
            </div>
        }
    });
    let groups = group_by_plane(rep.items)
        .into_iter()
        .map(|(plane_label, items)| {
            let cards = items.into_iter().map(item_card).collect_view();
            view! {
                <section class="readiness__group">
                    <h3 class="readiness__group-title">{plane_label}</h3>
                    {cards}
                </section>
            }
        })
        .collect_view();
    view! {
        {banner}
        {groups}
    }
}

#[component]
pub fn ReadinessView() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let report = LocalResource::new(move || {
        let tenant = tenant.get();
        // Track the shared readiness-reload bump so refreshing the token (which
        // re-applies roles) re-runs this check in place — no separate button.
        let _ = session.readiness_reload.get();
        async move {
            match tenant {
                Some(t) => Some(readiness::check_readiness(&t.tenant_id).await),
                None => None,
            }
        }
    });

    view! {
        <div class="readiness">
            <div class="readiness__head">
                <h2 class="readiness__title">"Access Readiness"</h2>
            </div>
            <Body1 class="hint">
                "azapptoolkit acts with your delegated rights across three independent \
                 authorization planes — there is no single role that unlocks everything. This \
                 checks what you currently hold against what each feature needs. A PIM role you \
                 haven't activated shows as Missing; activate it, then use \"Refresh token\" \
                 (top right) — that re-applies your roles and re-runs this check."
            </Body1>
            {move || {
                Suspend::new(async move {
                    match report.await {
                        None => {
                            view! { <Body1>"Sign in to check access readiness."</Body1> }
                                .into_any()
                        }
                        Some(Err(e)) => {
                            view! {
                                <div class="alert alert--warn">
                                    {format!(
                                        "Couldn't check readiness [{}]: {}",
                                        e.code,
                                        e.message,
                                    )}
                                </div>
                            }
                                .into_any()
                        }
                        Some(Ok(rep)) => render_report(rep).into_any(),
                    }
                })
            }}
        </div>
    }
}
