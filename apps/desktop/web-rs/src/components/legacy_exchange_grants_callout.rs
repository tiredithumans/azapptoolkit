//! Callout for **legacy Office 365 Exchange Online mailbox grants** — the
//! permissions that make a correctly scoped app still read "Org-wide".
//!
//! That resource exposes its own `Mail.*` / `Calendars.*` / `Contacts.*` /
//! `MailboxSettings.*` appRoles (the retired Outlook REST API) alongside the EWS
//! scope. RBAC for Applications covers Microsoft Graph and EWS only, so those
//! roles can never be confined — but they still *name* a mailbox permission, so
//! the backend counts a surviving grant as org-wide reach
//! (`held_orgwide_mail_grants`) and `reconcile_orgwide_grant` flips the
//! identically named **Graph** permission's `Scoped` verdict back to `OrgWide`.
//!
//! Nothing else in the UI could explain that: the legacy rows aren't scopable, so
//! they carry no "Scope…" action and (correctly) no scope badge, while the Graph
//! rows read "Org-wide" with a management scope visibly in place. Re-running the
//! scope flow can't help either — `remove_unscoped_grants` matches targets on
//! `(resource, appRole)`, and these are never targets. Removing the grant is the
//! only fix, so the callout says so.
//!
//! Pure presentation, mirroring [`OrgwideScopeCallout`](super::orgwide_scope_callout):
//! the caller passes the rows it already has and this decides what to say.

use azapptoolkit_core::scoping::is_unscopable_legacy_exchange_permission;
use leptos::prelude::*;

use crate::components::scope_badge::is_exchange_scopable_on;
use crate::components::ui::Callout;

/// One **application** permission row on the principal, reduced to what this
/// callout needs. Callers map their own shape (`ResolvedPermission` on an app
/// registration, `AppRoleGrantDto` on a bare service principal) into this.
#[derive(Clone, PartialEq)]
pub struct AppPermissionRow {
    /// `None` for a resource this build didn't resolve — never judged legacy.
    pub resource_app_id: Option<String>,
    pub value: String,
    /// Whether the principal holds this as a live Entra app-role grant.
    ///
    /// Asymmetric on purpose: only a **granted** legacy row is called out (a
    /// declared-but-ungranted one authorizes nothing), while an ungranted
    /// **Graph** mail declaration still counts toward "a scope is being
    /// defeated" — a migrated app is exactly the case where the Entra grant was
    /// stripped and the RBAC role assignment now carries the access.
    pub granted: bool,
}

/// What the callout should say, decided from the rows.
#[derive(Debug, PartialEq)]
struct Findings {
    /// Granted legacy values, deduped, in row order.
    values: Vec<String>,
    /// Whether the principal also carries an RBAC-scopable mail permission — i.e.
    /// these grants are actively overriding a scope verdict, not merely lingering.
    defeats_scope: bool,
}

fn findings(rows: &[AppPermissionRow]) -> Findings {
    let mut values: Vec<String> = Vec::new();
    let mut defeats_scope = false;
    for row in rows {
        if row.granted
            && row
                .resource_app_id
                .as_deref()
                .is_some_and(|r| is_unscopable_legacy_exchange_permission(r, &row.value))
        {
            if !values.iter().any(|v| v == &row.value) {
                values.push(row.value.clone());
            }
        } else if is_exchange_scopable_on(row.resource_app_id.as_deref(), &row.value) {
            defeats_scope = true;
        }
    }
    Findings {
        values,
        defeats_scope,
    }
}

#[component]
pub fn LegacyExchangeGrantsCallout(
    /// The principal's application permission rows (declared and/or held).
    rows: Vec<AppPermissionRow>,
) -> impl IntoView {
    let Findings {
        values,
        defeats_scope,
    } = findings(&rows);
    (!values.is_empty()).then(|| {
        let listing = values.join(", ");
        let effect = if defeats_scope {
            "RBAC for Applications covers Microsoft Graph and EWS only, so these can't be confined \
             — and because Entra grants and Exchange RBAC union, they override the mailbox scope \
             on the identically named Microsoft Graph permissions above. Removing them is the only \
             fix; re-running the scoping flow won't clear them."
        } else {
            "RBAC for Applications covers Microsoft Graph and EWS only, so these can't be confined \
             — they reach every mailbox until they are removed."
        };
        view! {
            <Callout tone="warn">
                <div>
                    {format!(
                        "Holds Office 365 Exchange Online permissions that Exchange RBAC can't scope: {listing}.",
                    )}
                </div>
                <div>{effect}</div>
                <div>
                    "These appRoles served the Outlook REST API, decommissioned in March 2024. Other permissions on this resource — full_access_as_app, EWS.AccessAsApp, Exchange.ManageAsApp, IMAP/POP/SMTP.AccessAsApp — back protocols that are still live; leave those in place."
                </div>
            </Callout>
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::scoping::{
        MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID as EXO,
    };

    const GRAPH: &str = MICROSOFT_GRAPH_APP_ID;

    fn row(resource: &str, value: &str, granted: bool) -> AppPermissionRow {
        AppPermissionRow {
            resource_app_id: Some(resource.to_string()),
            value: value.to_string(),
            granted,
        }
    }

    #[test]
    fn names_granted_legacy_mail_grants_only() {
        let rows = vec![
            row(EXO, "Mail.ReadWrite", true),
            row(EXO, "Mail.Send", true),
            // Not granted ⇒ authorizes nothing ⇒ not called out.
            row(EXO, "Contacts.ReadWrite", false),
            // Scopable on its own resource ⇒ never called out.
            row(EXO, "full_access_as_app", true),
            // Live protocol roles ⇒ never called out.
            row(EXO, "Exchange.ManageAsApp", true),
            row(EXO, "IMAP.AccessAsApp", true),
            // Graph's identically named permissions ⇒ never called out.
            row(GRAPH, "Mail.ReadWrite", true),
        ];
        assert_eq!(
            findings(&rows).values,
            vec!["Mail.ReadWrite".to_string(), "Mail.Send".to_string()]
        );
    }

    #[test]
    fn the_migrated_app_case_reports_a_defeated_scope() {
        // The shape after an AAP migration: the Graph declarations survive with
        // their Entra grant stripped (RBAC now carries the access), while the
        // legacy Exchange Online grants were never migration targets and remain.
        let rows = vec![
            row(EXO, "Mail.ReadWrite", true),
            row(EXO, "Mail.Send", true),
            row(GRAPH, "Mail.ReadWrite", false),
            row(GRAPH, "Mail.Send", false),
        ];
        let got = findings(&rows);
        assert_eq!(
            got.values,
            vec!["Mail.ReadWrite".to_string(), "Mail.Send".to_string()]
        );
        assert!(
            got.defeats_scope,
            "an ungranted Graph mail declaration still carries an RBAC scope"
        );
    }

    #[test]
    fn a_legacy_grant_alone_does_not_claim_a_scope_is_defeated() {
        // No Graph mail permission in play ⇒ nothing is being overridden; the
        // grant is still org-wide, which is what the shorter copy says.
        let got = findings(&[row(EXO, "Mail.Read", true)]);
        assert_eq!(got.values, vec!["Mail.Read".to_string()]);
        assert!(!got.defeats_scope);
    }

    #[test]
    fn nothing_to_say_without_a_granted_legacy_permission() {
        let rows = vec![
            row(GRAPH, "Mail.Read", true),
            row(GRAPH, "Sites.Read.All", true),
            row(EXO, "full_access_as_app", true),
        ];
        assert!(findings(&rows).values.is_empty());
    }

    #[test]
    fn an_unresolved_resource_is_never_called_out() {
        // Same rule as the scope badge: a resource this build didn't resolve
        // can't be judged, so it must not be named as a thing to delete.
        let rows = vec![AppPermissionRow {
            resource_app_id: None,
            value: "Mail.Read".to_string(),
            granted: true,
        }];
        assert!(findings(&rows).values.is_empty());
    }

    #[test]
    fn duplicate_values_are_listed_once() {
        let rows = vec![row(EXO, "Mail.Read", true), row(EXO, "Mail.Read", true)];
        assert_eq!(findings(&rows).values, vec!["Mail.Read".to_string()]);
    }
}
