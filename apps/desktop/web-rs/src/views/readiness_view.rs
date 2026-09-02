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
//!
//! The page leads with what is *unmet*: a count line, then the planes holding a
//! gap, then within each plane the Missing capabilities before the Unknown ones
//! before the satisfied ones. Flat catalog order buried the two capabilities an
//! operator was short among a dozen green ticks — the answer was on the page and
//! still had to be hunted for. There is still no general "Re-check" button (the
//! Refresh-token control is that, deliberately); the only Retry is on a check
//! that failed outright, which a new token would not fix.

use leptos::prelude::*;
use thaw::Body1;

use azapptoolkit_dto::readiness::{ReadinessItem, ReadinessReport, Verdict};

use crate::bindings::readiness;
use crate::components::ui::{Callout, SectionHeader, SkeletonList};
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

/// Whether this capability has anything unmet — either half short is a gap,
/// since the two are documented as "both required".
fn is_gap(item: &ReadinessItem) -> bool {
    item.role_verdict != Verdict::Have || item.scope_verdict != Verdict::Have
}

/// Sort rank: proven-missing first, then indeterminate, then satisfied.
///
/// The page's job is to answer "what do I need to activate?", and rendering in
/// flat catalog order buried the two capabilities an operator is short among a
/// dozen green ticks — the answer was on the page and still had to be hunted
/// for. `Missing` outranks `Unknown` because it is actionable: the remediation
/// line under it names the role to activate, where an `Unknown` only means the
/// check could not prove either way.
fn gap_rank(item: &ReadinessItem) -> u8 {
    let worst = |v: Verdict| match v {
        Verdict::Missing => 0u8,
        Verdict::Unknown => 1,
        Verdict::Have => 2,
    };
    worst(item.role_verdict).min(worst(item.scope_verdict))
}

/// Reorders for triage without discarding the plane structure: within a plane
/// the unmet capabilities lead, and planes holding a gap lead the page. Both
/// sorts are stable, so catalog order survives as the tie-break among equals.
fn gaps_first(mut groups: Vec<(String, Vec<ReadinessItem>)>) -> Vec<(String, Vec<ReadinessItem>)> {
    for (_, items) in &mut groups {
        items.sort_by_key(gap_rank);
    }
    groups.sort_by_key(|(_, items)| !items.iter().any(is_gap));
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
            <Callout tone="warn">
                "Couldn't read your active directory roles, so directory-role requirements show as \
                 \"?\". This is usually a missing Directory.Read.All consent or a tenant that \
                 restricts directory reads."
            </Callout>
        }
    });
    // Count before the move: this is the page's headline answer, and it has to
    // be true even when every capability is satisfied ("nothing to activate").
    let total = rep.items.len();
    let gaps = rep.items.iter().filter(|i| is_gap(i)).count();
    let summary = view! {
        <Callout tone=if gaps == 0 { "ok" } else { "warn" }>
            {if gaps == 0 {
                format!("All {total} capabilities are satisfied — nothing to activate.")
            } else {
                format!(
                    "{gaps} of {total} capabilities are missing a role or a scope. They are listed \
                     first below, each with the step that clears it.",
                )
            }}
        </Callout>
    };
    let groups = gaps_first(group_by_plane(rep.items))
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
        {summary}
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
            <SectionHeader title="Access Readiness".to_string() crumb="Account".to_string() />
            <Body1 class="hint">
                "azapptoolkit acts with your delegated rights across three independent \
                 authorization planes — there is no single role that unlocks everything. This \
                 checks what you currently hold against what each feature needs. A PIM role you \
                 haven't activated shows as Missing; activate it, then use \"Refresh token\" \
                 (top right) — that re-applies your roles and re-runs this check."
            </Body1>
            // Local boundary only: the three-plane check is slow (Entra + Azure
            // RBAC + Exchange), and without one this page sat blank while it ran.
            // Deliberately NOT hoisted app-wide — lib.rs warns against that.
            <Suspense fallback=move || view! { <SkeletonList rows=6 /> }>
            {move || {
                Suspend::new(async move {
                    match report.await {
                        None => {
                            view! { <Body1>"Sign in to check access readiness."</Body1> }
                                .into_any()
                        }
                        Some(Err(e)) => {
                            // A Retry here is NOT the "re-check my access"
                            // control the module doc rules out — that one is
                            // "Refresh token", because re-applying an activated
                            // PIM role genuinely needs a new token. This is
                            // recovery from a probe that never returned a
                            // verdict at all (Entra/ARM/Exchange unreachable),
                            // where re-minting a perfectly good token is beside
                            // the point and the operator otherwise has nothing
                            // to press.
                            view! {
                                <Callout tone="warn">
                                    {format!(
                                        "Couldn't check readiness [{}]: {}",
                                        e.code,
                                        e.message,
                                    )}
                                    <button
                                        class="link-btn readiness__retry"
                                        on:click=move |_| session.bump_readiness_reload()
                                    >
                                        "Retry"
                                    </button>
                                </Callout>
                            }
                                .into_any()
                        }
                        Some(Ok(rep)) => render_report(rep).into_any(),
                    }
                })
            }}
            </Suspense>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(plane: &str, role: Verdict, scope: Verdict) -> ReadinessItem {
        ReadinessItem {
            key: format!("{plane}-{role:?}-{scope:?}"),
            plane: plane.into(),
            plane_label: plane.into(),
            label: plane.into(),
            description: String::new(),
            role_verdict: role,
            role_detail: String::new(),
            scope_verdict: scope,
            scope_detail: String::new(),
            remediation: String::new(),
        }
    }

    #[test]
    fn a_capability_is_a_gap_when_either_half_is_short() {
        // "Two halves, both required" — one ✓ is not readiness.
        assert!(!is_gap(&item("p", Verdict::Have, Verdict::Have)));
        assert!(is_gap(&item("p", Verdict::Have, Verdict::Missing)));
        assert!(is_gap(&item("p", Verdict::Missing, Verdict::Have)));
        assert!(is_gap(&item("p", Verdict::Have, Verdict::Unknown)));
    }

    #[test]
    fn planes_with_a_gap_lead_and_missing_leads_within_a_plane() {
        let groups = vec![
            (
                "Clear".to_string(),
                vec![item("Clear", Verdict::Have, Verdict::Have)],
            ),
            (
                "Mixed".to_string(),
                vec![
                    item("Mixed", Verdict::Have, Verdict::Have),
                    item("Mixed", Verdict::Have, Verdict::Unknown),
                    item("Mixed", Verdict::Missing, Verdict::Have),
                ],
            ),
        ];
        let out = gaps_first(groups);
        // The plane holding the gap comes first...
        assert_eq!(out[0].0, "Mixed");
        assert_eq!(out[1].0, "Clear");
        // ...and inside it, Missing before Unknown before Have. Missing outranks
        // Unknown because only Missing carries an actionable remediation.
        let ranks: Vec<u8> = out[0].1.iter().map(gap_rank).collect();
        assert_eq!(ranks, vec![0, 1, 2]);
    }

    #[test]
    fn ordering_is_stable_so_catalog_order_survives_among_equals() {
        let groups = vec![(
            "P".to_string(),
            vec![
                item("first", Verdict::Missing, Verdict::Missing),
                item("second", Verdict::Missing, Verdict::Missing),
            ],
        )];
        let out = gaps_first(groups);
        assert_eq!(out[0].1[0].label, "first");
        assert_eq!(out[0].1[1].label, "second");
    }
}
