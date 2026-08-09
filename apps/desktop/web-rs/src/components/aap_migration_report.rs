//! Shared renderer for an [`AapMigrationReport`] — the outcome (or the dry-run
//! plan) of migrating legacy Application Access Policies to RBAC for
//! Applications.
//!
//! Two surfaces show this report: the Permissions tab's Exchange scoping section
//! and the Security tab's one-click migration Fix. They render it from one
//! component so the two can't describe the same run differently — in particular
//! the `partial` reading below, which is the whole safety story of the flow.

use leptos::prelude::*;

use crate::bindings::exchange::AapMigrationReport;
use crate::components::retired_scope_groups::RetiredScopeGroups;
use crate::components::ui::{Callout, CopyableId};

/// Renders a migration report: a headline that distinguishes plan / done /
/// needs-attention, then one line per application with its scoped roles,
/// stripped org-wide grants, policy disposition and any warnings.
///
/// **`partial` must never read as success.** It means the run did real work but
/// deliberately stopped short — almost always "kept the legacy policy because a
/// grant is still org-wide", which is the fail-closed guard, not a failure. An
/// operator who reads that as "done" walks away believing an app is migrated
/// while the policy is still the only thing confining it.
#[component]
pub fn AapMigrationReportView(report: AapMigrationReport) -> impl IntoView {
    let needs_attention = !report.dry_run && report.items.iter().any(|i| i.status != "migrated");
    let header = match (report.dry_run, needs_attention) {
        (true, _) => format!(
            "Plan: {} app(s) would be migrated. Nothing has changed yet.",
            report.items.len()
        ),
        (false, false) => format!("Migrated {} app(s).", report.items.len()),
        (false, true) => format!(
            "Migrated {} app(s), but some need attention — see the notes below.",
            report.items.len(),
        ),
    };
    // A run stopped by Cancel or a dead session has left the remaining apps on
    // their legacy policies. Never let that read as a completed migration —
    // same rule the audit and DR reports follow for a partial run.
    let incomplete = report.incomplete;
    let tone = if needs_attention || incomplete || !report.failures.is_empty() {
        "warn"
    } else {
        "ok"
    };
    let items = report.items.clone();
    let failures = report.failures.clone();
    // Name the apps a stopped run never reached rather than leaving the operator
    // to diff the report against the tenant — on a run stopped by a dead
    // session, re-running to find out is the action least likely to work.
    let unattempted = report.unattempted.clone();
    let unattempted_count = unattempted.len();
    view! {
        <Callout tone=tone>{header}</Callout>
        <Show when=move || incomplete>
            <Callout tone="warn" role="alert">
                "This run stopped before every app was processed — you cancelled it, or the \
                 session expired. The apps not listed above are still on their legacy \
                 Application Access Policies. Sign in again if needed and re-run to finish."
            </Callout>
        </Show>
        <Show when=move || { unattempted_count > 0 }>
            <details class="aap-unattempted">
                <summary>
                    {format!("{unattempted_count} app(s) not reached — still on legacy policies")}
                </summary>
                <ul class="warnings">
                    {unattempted
                        .clone()
                        .into_iter()
                        .map(|app_id| {
                            view! {
                                <li>
                                    <CopyableId value=app_id label="Application ID" full=true />
                                </li>
                            }
                        })
                        .collect_view()}
                </ul>
            </details>
        </Show>
        <ul class="warnings">
            {items
                .into_iter()
                .map(|i| {
                    let scoped = if i.roles_assigned.is_empty() {
                        "none".to_string()
                    } else {
                        i.roles_assigned.join(", ")
                    };
                    let stripped = if i.removed_entra_grants.is_empty() {
                        "none".to_string()
                    } else {
                        i.removed_entra_grants.join(", ")
                    };
                    let policies = match (
                        i.removed_policies.len(),
                        i.source_policy_identities.len(),
                    ) {
                        (0, n) => format!("{n} kept"),
                        (removed, n) if removed == n => format!("{removed} removed"),
                        (removed, n) => format!("{removed} of {n} removed"),
                    };
                    let line = format!(
                        "{} — {}. Scoped roles: {scoped}. Org-wide grants removed: {stripped}. Legacy policies: {policies}.",
                        i.app_id,
                        i.status,
                    );
                    let warnings = i.warnings.clone();
                    let row_class = if i.status == "migrated" { "" } else { "form-error" };
                    let retired_groups = i.retired_groups.clone();
                    let retired_app_id = i.app_id.clone();
                    view! {
                        <li class=row_class>
                            {line}
                            {(!warnings.is_empty())
                                .then(|| {
                                    view! {
                                        <ul>
                                            {warnings
                                                .into_iter()
                                                .map(|w| view! { <li class="hint">{w}</li> })
                                                .collect_view()}
                                        </ul>
                                    }
                                })}
                            // The legacy policy group the new scope no longer
                            // points at — named, with the guarded cleanup.
                            <RetiredScopeGroups app_id=retired_app_id groups=retired_groups />
                        </li>
                    }
                })
                .collect_view()}
            {failures
                .into_iter()
                .map(|f| view! { <li class="form-error">{f}</li> })
                .collect_view()}
        </ul>
    }
}
