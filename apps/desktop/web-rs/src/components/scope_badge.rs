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
    risk_level_for_app_permission, MailPermissionScope, RiskLevel, ScopeMechanism,
};
use leptos::prelude::*;

use crate::components::ui::Badge;

// Scope predicates are re-exported from `azapptoolkit_core::scoping` so the badge
// rendering here and the backend grant/scope logic share one authoritative
// definition. `is_exchange_scopable` keeps the name its callers use, but is now
// the map-backed check (a `Mail.*`-lookalike with no Exchange role is correctly
// reported as NOT scopable, unlike the old prefix check).
pub use azapptoolkit_core::scoping::is_scopable_exchange_permission as is_exchange_scopable;
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

/// Renders the "Scope" cell for a permission row. Mail/calendar/contacts
/// permissions use the live Exchange verdict (`mail_scope`); SharePoint `Sites.*`
/// permissions derive their verdict from the permission name. Everything else
/// shows a muted dash. `is_application` is whether the row is an *application*
/// permission — only those are scopable via Exchange RBAC for Applications, so a
/// delegated mail permission always reads "not applicable" (—).
/// `scope_loading` is whether the Exchange lookup is still in flight — a
/// scopable row without a verdict then reads "Resolving…" instead of the
/// (alarming, and wrong-while-loading) "Unknown".
pub fn permission_scope_cell(
    value: Option<&str>,
    mail_scope: Option<MailPermissionScope>,
    is_application: bool,
    scope_loading: bool,
) -> AnyView {
    if let Some(scope) = mail_scope {
        return mailbox_scope_badge(scope);
    }
    // An application mail-scopable permission with no live verdict: in flight ⇒
    // say so; otherwise the lookup failed ⇒ show "Unknown", not the
    // not-applicable dash, so it isn't mistaken for a non-scopable permission.
    // (Delegated permissions are never RBAC-scopable, so they fall through to —.)
    if is_application && value.map(is_exchange_scopable).unwrap_or(false) {
        if scope_loading {
            return view! {
                <span
                    class="badge badge--unknown"
                    title="Querying Exchange for the effective mailbox scope — this takes a few seconds"
                >
                    "Resolving…"
                </span>
            }
            .into_any();
        }
        return mailbox_scope_badge(MailPermissionScope::Unknown);
    }
    match value {
        Some("Sites.Selected") => view! {
            <span
                class="badge badge--ok"
                title="Confined to individually-granted sites (Sites.Selected)"
            >
                "Scoped (selected sites)"
            </span>
        }
        .into_any(),
        Some(v) if is_sharepoint_orgwide(v) => view! {
            <span class="badge badge--danger" title="Grants access to every site in the tenant">
                "Org-wide"
            </span>
        }
        .into_any(),
        _ => view! { <span class="muted">"—"</span> }.into_any(),
    }
}

/// Renders the live Exchange mailbox-scope verdict as a badge.
pub fn mailbox_scope_badge(scope: MailPermissionScope) -> AnyView {
    match scope {
        MailPermissionScope::NotScopable => view! { <span class="muted">"—"</span> }.into_any(),
        MailPermissionScope::OrgWide => view! {
            <span class="badge badge--danger" title="Reaches every mailbox in the tenant">
                "Org-wide"
            </span>
        }
        .into_any(),
        MailPermissionScope::Unknown => view! {
            <span
                class="badge badge--unknown"
                title="Mailbox scoping couldn't be determined — the Exchange admin API was unavailable (it may still be loading, or you may need Exchange admin rights / to grant consent). See the Exchange scoping section below."
            >
                "Unknown"
            </span>
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
                view! { <span class="badge badge--ok" title=title>{label}</span> }.into_any()
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
                view! { <span class="badge badge--warning" title=title>"Scoped (legacy)"</span> }
                    .into_any()
            }
        },
    }
}
