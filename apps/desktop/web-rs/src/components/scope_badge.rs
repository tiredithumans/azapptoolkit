//! Shared rendering for permission *scope* badges, used wherever a service
//! principal's application permissions are listed (app-registration and
//! enterprise-app Permissions tabs, Managed Identity detail).
//!
//! Two scoping models are surfaced:
//! - **Exchange** (mail/calendar/contacts): the effective verdict is resolved
//!   live via `Test-ServicePrincipalAuthorization` and arrives as a
//!   [`MailPermissionScope`].
//! - **SharePoint** (`Sites.*`): scoping is encoded by the permission *name*
//!   (`Sites.Selected` is the scoped model; every other `Sites.*` is org-wide),
//!   so it needs no live lookup and is derived here from the value alone.

use azapptoolkit_core::audit::{
    MailPermissionScope, RiskLevel, ScopeMechanism, risk_level_for_app_permission,
};
use leptos::prelude::*;

use crate::components::ui::Badge;

// Scope predicates are re-exported from `azapptoolkit_core::scoping` so the badge
// rendering here and the backend grant/scope logic share one authoritative
// definition. Both are map-backed, not prefix checks (a `Mail.*`-lookalike with no
// Exchange role is correctly reported as NOT scopable).
//
// Exchange scopability is exposed **only** in its resource-aware form. Mailbox
// permissions live on two resources — Microsoft Graph and the legacy Office 365
// Exchange Online, whose own `Mail.Read`-family appRoles (retired Outlook REST)
// have no RBAC role — and both expose an appRole literally named `Mail.Read`. A
// value-only answer therefore can't be right for every row: it would offer a
// "Scope…" action the backend correctly refuses to honour, show an "Unknown"
// verdict that never arrives, and seed the wizard with the wrong resource. Pass
// the row's own resource (`None` for one the backend didn't resolve ⇒ not
// scopable). The value-only core predicate stays available to the *backend*, whose
// audit gate legitimately scans a flattened value list.
pub use azapptoolkit_core::scoping::is_scopable_exchange_resource_permission as is_exchange_scopable_on;
pub use azapptoolkit_core::scoping::is_sharepoint_orgwide;

/// Risk badge (`High risk` / `Medium`, with a tooltip) for an application
/// permission a principal **holds**, or an empty view when it isn't classified
/// high/medium. The single source for both the held-permission tables
/// (managed-identity, enterprise-app) and the grant-time picker, so a wording
/// change is a one-file edit. Classification is single-sourced from
/// `azapptoolkit_core::audit::risk_level_for_app_permission`.
pub fn app_permission_risk_badge(value: &str) -> AnyView {
    match risk_level_for_app_permission(value) {
        Some(RiskLevel::High) => view! {
            <Badge
                label="High risk"
                tone="danger"
                title="High-risk application permission — runs app-only, without a user"
            />
        }
        .into_any(),
        Some(RiskLevel::Medium) => view! {
            <Badge label="Medium" tone="warning" title="Medium-risk application permission" />
        }
        .into_any(),
        _ => ().into_any(),
    }
}

/// What the "Scope" cell should render for one permission row — the pure
/// decision, split from the markup so the resource-awareness below is
/// unit-testable (rendering returns an opaque `AnyView`).
#[derive(Debug, Clone, PartialEq)]
enum ScopeCell {
    /// A live Exchange verdict (or `Unknown` when the lookup failed).
    Mailbox(MailPermissionScope),
    /// Exchange lookup still in flight.
    Resolving,
    /// `Sites.Selected` — SharePoint's scoped model, derived from the name.
    SitesSelected,
    /// A broad `Sites.*` — org-wide, derived from the name.
    SitesOrgWide,
    /// Not scopable by any mechanism.
    NotApplicable,
}

/// Picks the cell for a row. Mail/calendar/contacts application permissions use
/// the live Exchange verdict (`mail_scope`); SharePoint `Sites.*` permissions
/// derive theirs from the permission name; everything else is a muted dash.
///
/// **The Exchange verdict is gated on the row's own resource *and* on the row
/// being an Application permission**, because `mail_scope` is looked up by the
/// caller from a map keyed on permission *value* alone. Two resources expose an
/// identically named `Mail.Read`/`Mail.ReadWrite`/`Mail.Send`/`Contacts.*` and
/// only Microsoft Graph's is RBAC-scopable, so an ungated lookup makes Office
/// 365 Exchange Online's un-scopable row inherit the Graph row's verdict — an
/// app whose Graph permissions read "Org-wide" paints the legacy rows "Org-wide"
/// too, implying a scope failure on rows that were never scopable. The same hole
/// let a *delegated* `Mail.Read` inherit the application verdict, contradicting
/// this function's own contract.
fn scope_cell_for(
    value: Option<&str>,
    resource_app_id: Option<&str>,
    mail_scope: Option<MailPermissionScope>,
    is_application: bool,
    scope_loading: bool,
) -> ScopeCell {
    if is_application && value.is_some_and(|v| is_exchange_scopable_on(resource_app_id, v)) {
        return match mail_scope {
            Some(scope) => ScopeCell::Mailbox(scope),
            // No live verdict: in flight ⇒ say so; otherwise the lookup failed ⇒
            // "Unknown", not the not-applicable dash, so it isn't mistaken for a
            // non-scopable permission.
            None if scope_loading => ScopeCell::Resolving,
            None => ScopeCell::Mailbox(MailPermissionScope::Unknown),
        };
    }
    match value {
        Some("Sites.Selected") => ScopeCell::SitesSelected,
        Some(v) if is_sharepoint_orgwide(v) => ScopeCell::SitesOrgWide,
        _ => ScopeCell::NotApplicable,
    }
}

/// Renders the "Scope" cell for a permission row — see [`scope_cell_for`] for
/// the decision (including why the Exchange verdict is resource-gated).
/// `is_application` is whether the row is an *application* permission — only
/// those are scopable via Exchange RBAC for Applications, so a delegated mail
/// permission always reads "not applicable" (—). `scope_loading` is whether the
/// Exchange lookup is still in flight, so a scopable row without a verdict reads
/// "Resolving…" instead of the (alarming, and wrong-while-loading) "Unknown".
pub fn permission_scope_cell(
    value: Option<&str>,
    resource_app_id: Option<&str>,
    mail_scope: Option<MailPermissionScope>,
    is_application: bool,
    scope_loading: bool,
) -> AnyView {
    match scope_cell_for(
        value,
        resource_app_id,
        mail_scope,
        is_application,
        scope_loading,
    ) {
        ScopeCell::Mailbox(scope) => mailbox_scope_badge(scope),
        ScopeCell::Resolving => view! {
            <Badge
                label="Resolving…"
                tone="unknown"
                title="Querying Exchange for the effective mailbox scope — this takes a few seconds"
            />
        }
        .into_any(),
        ScopeCell::SitesSelected => view! {
            <Badge
                label="Scoped (selected sites)"
                tone="ok"
                title="Confined to individually-granted sites (Sites.Selected)"
            />
        }
        .into_any(),
        ScopeCell::SitesOrgWide => view! {
            <Badge
                label="Org-wide"
                tone="danger"
                title="Grants access to every site in the tenant"
            />
        }
        .into_any(),
        ScopeCell::NotApplicable => view! { <span class="muted">"—"</span> }.into_any(),
    }
}

/// Renders the live Exchange mailbox-scope verdict as a badge.
pub fn mailbox_scope_badge(scope: MailPermissionScope) -> AnyView {
    match scope {
        MailPermissionScope::NotScopable => view! { <span class="muted">"—"</span> }.into_any(),
        MailPermissionScope::OrgWide => view! {
            <Badge
                label="Org-wide"
                tone="danger"
                title="Reaches every mailbox in the tenant"
            />
        }
        .into_any(),
        MailPermissionScope::Unknown => view! {
            <Badge
                label="Unknown"
                tone="unknown"
                title="Mailbox scoping couldn't be determined — the Exchange admin API was unavailable (it may still be loading, or you may need Exchange admin rights / to grant consent). See the Exchange scoping section below."
            />
        }
        .into_any(),
        MailPermissionScope::Scoped {
            scope_name,
            recipient_filter,
            group_count,
            mechanism,
        } => match mechanism {
            ScopeMechanism::Rbac => {
                let label = match group_count {
                    Some(1) => "Scoped: 1 group".to_string(),
                    Some(n) => format!("Scoped: {n} groups"),
                    None => "Scoped".to_string(),
                };
                let title = recipient_filter
                    .or(scope_name)
                    .unwrap_or_else(|| "Scoped via RBAC for Applications".to_string());
                view! { <Badge label=label tone="ok" title=title /> }.into_any()
            }
            // Legacy Application Access Policy: genuinely scoped, but deprecated —
            // an amber badge nudges migration to RBAC for Applications.
            ScopeMechanism::LegacyApplicationAccessPolicy => {
                let detail = recipient_filter.or(scope_name).unwrap_or_default();
                let title = if detail.is_empty() {
                    "Confined by a legacy Application Access Policy — consider migrating to RBAC for Applications (Exchange scoping section on the Permissions tab).".to_string()
                } else {
                    format!("Legacy Application Access Policy: {detail}. Consider migrating to RBAC for Applications (Exchange scoping section on the Permissions tab).")
                };
                view! { <Badge label="Scoped (legacy)" tone="warning" title=title /> }.into_any()
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::scoping::{
        MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID as EXO,
    };

    const GRAPH: &str = MICROSOFT_GRAPH_APP_ID;

    fn cell(value: &str, resource: &str, scope: Option<MailPermissionScope>) -> ScopeCell {
        scope_cell_for(Some(value), Some(resource), scope, true, false)
    }

    #[test]
    fn exchange_onlines_mail_lookalikes_never_borrow_the_graph_verdict() {
        // The regression: `mail_scope` is looked up by value alone, so an app
        // declaring `Mail.ReadWrite` on BOTH resources handed the Office 365
        // Exchange Online row the Graph row's verdict — painting an un-scopable
        // legacy row "Org-wide" as if its scoping had failed.
        assert_eq!(
            cell("Mail.ReadWrite", EXO, Some(MailPermissionScope::OrgWide)),
            ScopeCell::NotApplicable,
        );
        // ...while Graph's identically named permission still shows its verdict.
        assert_eq!(
            cell("Mail.ReadWrite", GRAPH, Some(MailPermissionScope::OrgWide)),
            ScopeCell::Mailbox(MailPermissionScope::OrgWide),
        );
    }

    #[test]
    fn exchange_onlines_mail_lookalikes_never_read_unknown_or_resolving() {
        // Not just the verdict: a row that can never be scoped must not claim a
        // verdict is coming, in either the loading or the failed state.
        assert_eq!(
            scope_cell_for(Some("Mail.Send"), Some(EXO), None, true, true),
            ScopeCell::NotApplicable,
        );
        assert_eq!(
            scope_cell_for(Some("Mail.Send"), Some(EXO), None, true, false),
            ScopeCell::NotApplicable,
        );
    }

    #[test]
    fn the_ews_scope_on_exchange_online_does_show_its_verdict() {
        // The one mailbox permission that IS scopable on the legacy resource —
        // gating by resource must not swallow it.
        assert_eq!(
            cell(
                "full_access_as_app",
                EXO,
                Some(MailPermissionScope::OrgWide)
            ),
            ScopeCell::Mailbox(MailPermissionScope::OrgWide),
        );
    }

    #[test]
    fn delegated_mail_rows_are_not_applicable_even_with_a_verdict() {
        // Exchange RBAC scopes application permissions only; the value-keyed map
        // would otherwise hand a delegated `Mail.Read` the application verdict.
        assert_eq!(
            scope_cell_for(
                Some("Mail.Read"),
                Some(GRAPH),
                Some(MailPermissionScope::OrgWide),
                false,
                false,
            ),
            ScopeCell::NotApplicable,
        );
    }

    #[test]
    fn a_graph_mail_row_without_a_verdict_resolves_then_reads_unknown() {
        assert_eq!(
            scope_cell_for(Some("Mail.Read"), Some(GRAPH), None, true, true),
            ScopeCell::Resolving,
        );
        assert_eq!(
            scope_cell_for(Some("Mail.Read"), Some(GRAPH), None, true, false),
            ScopeCell::Mailbox(MailPermissionScope::Unknown),
        );
    }

    #[test]
    fn a_row_whose_resource_is_unknown_is_not_applicable() {
        // `None` = a resource this build didn't resolve; it can't be judged
        // scopable, so it must not borrow a verdict either.
        assert_eq!(
            scope_cell_for(
                Some("Mail.Read"),
                None,
                Some(MailPermissionScope::OrgWide),
                true,
                false,
            ),
            ScopeCell::NotApplicable,
        );
    }

    #[test]
    fn sharepoint_verdicts_still_come_from_the_name() {
        assert_eq!(
            cell("Sites.Selected", GRAPH, None),
            ScopeCell::SitesSelected
        );
        assert_eq!(cell("Sites.Read.All", GRAPH, None), ScopeCell::SitesOrgWide);
        assert_eq!(
            cell("Directory.Read.All", GRAPH, None),
            ScopeCell::NotApplicable
        );
    }
}
