//! Permission-*scoping* predicates shared by the backend and the WASM frontend.
//!
//! Both surfaces need to answer the same two questions about an application
//! permission value, and they must answer them identically:
//! - **Exchange** (mail/calendar/contacts, plus the EWS `full_access_as_app`
//!   scope on the legacy Office 365 Exchange Online resource): can this
//!   permission be resource-scoped via RBAC for Applications? The answer is
//!   authoritative only if it matches the exact set Exchange recognises, so it is
//!   derived from the role *map*, never a loose prefix check
//!   (`Mail.ReadWrite.Shared` looks mail-ish but has no Exchange application
//!   role, so it is **not** scopable).
//! - **SharePoint** (`Sites.*`): scoping is encoded by the permission name —
//!   `Sites.Selected` is the scoped model, every other `Sites.*` is org-wide.
//!
//! This lives in `azapptoolkit-core` (which compiles to `wasm32`) so the badge
//! rendering in `web-rs` and the grant/scope logic in the Tauri backend call one
//! definition instead of drifting copies. `azapptoolkit-exchange` re-exports the
//! Exchange helpers for its existing callers.

/// Microsoft Graph's first-party app id — the resource that exposes the
/// mail/calendar/contacts **application** permissions.
pub const MICROSOFT_GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

/// The legacy **Office 365 Exchange Online** resource. It carries the EWS
/// [`EWS_FULL_ACCESS_AS_APP`] scope, which is the one non-Graph permission the
/// old Application Access Policies could confine — so every Exchange scoping
/// path has to understand it, not just the Graph resource.
pub const OFFICE365_EXCHANGE_ONLINE_APP_ID: &str = "00000002-0000-0ff1-ce00-000000000000";

/// Exchange Web Services full-mailbox-access scope, exposed as an appRole on
/// [`OFFICE365_EXCHANGE_ONLINE_APP_ID`] (never on Microsoft Graph). Documented
/// as an Application-Access-Policy-supported scope, and scopable under RBAC for
/// Applications via `Application EWS.AccessAsApp`.
pub const EWS_FULL_ACCESS_AS_APP: &str = "full_access_as_app";

/// RBAC-for-Applications role backing [`EWS_FULL_ACCESS_AS_APP`].
const EWS_ACCESS_AS_APP_ROLE: &str = "Application EWS.AccessAsApp";

/// The Exchange application role for a **Microsoft Graph** mail/calendar/contacts
/// application permission. This set is exactly the Graph permission list
/// Application Access Policies supported, so an AAP migration can always map
/// what a policy was confining.
///
/// Source: <https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac>
/// ("Supported Application Roles") ∩
/// <https://learn.microsoft.com/en-us/exchange/permissions-exo/application-access-policies>
/// ("Supported permissions"). The full RBAC role list is larger (mailbox
/// folders/items, SMTP, MailTips, and the composite full-access roles); those
/// were never AAP-scopable, so they are deliberately absent here.
fn graph_mail_role(value: &str) -> Option<&'static str> {
    let role = match value {
        "Mail.Read" => "Application Mail.Read",
        "Mail.ReadBasic" | "Mail.ReadBasic.All" => "Application Mail.ReadBasic",
        "Mail.ReadWrite" => "Application Mail.ReadWrite",
        "Mail.Send" => "Application Mail.Send",
        "MailboxSettings.Read" => "Application MailboxSettings.Read",
        "MailboxSettings.ReadWrite" => "Application MailboxSettings.ReadWrite",
        "Calendars.Read" => "Application Calendars.Read",
        "Calendars.ReadWrite" => "Application Calendars.ReadWrite",
        "Contacts.Read" => "Application Contacts.Read",
        "Contacts.ReadWrite" => "Application Contacts.ReadWrite",
        _ => return None,
    };
    Some(role)
}

/// The Exchange application role that grants the same capability as the
/// permission `value` on `resource_app_id` — the **authoritative** form, used by
/// every path that has to name a concrete Entra app-role grant (deriving scope
/// targets, stripping the org-wide grant). Returns `None` when the resource
/// doesn't expose a scopable mailbox permission of that name.
///
/// The resource matters: the legacy Office 365 Exchange Online resource exposes
/// `Mail.Read`-style appRoles of its own for the retired Outlook REST API, and
/// those have **no** RBAC-for-Applications counterpart (the supported protocols
/// are MS Graph and EWS only). Matching them to `Application Mail.Read` would
/// claim a scope the toolkit can't actually enforce, so only the EWS scope maps
/// on that resource.
pub fn exchange_role_for_resource_permission(
    resource_app_id: &str,
    value: &str,
) -> Option<&'static str> {
    match resource_app_id {
        MICROSOFT_GRAPH_APP_ID => graph_mail_role(value),
        OFFICE365_EXCHANGE_ONLINE_APP_ID => {
            (value == EWS_FULL_ACCESS_AS_APP).then_some(EWS_ACCESS_AS_APP_ROLE)
        }
        _ => None,
    }
}

/// The Exchange application role for a permission `value` whose resource isn't
/// known at the call site (the effective-scope probe, badge rendering, a
/// caller-supplied permission list). Unambiguous because the two mapped
/// resources share no value names: `full_access_as_app` exists only on Office
/// 365 Exchange Online, and every other mapped value only on Microsoft Graph.
/// Prefer [`exchange_role_for_resource_permission`] wherever the resource IS
/// known.
pub fn exchange_role_for_permission(value: &str) -> Option<&'static str> {
    graph_mail_role(value).or(exchange_role_for_resource_permission(
        OFFICE365_EXCHANGE_ONLINE_APP_ID,
        value,
    ))
}

/// True when `value` is an Exchange mailbox permission that can be
/// resource-scoped via RBAC for Applications. Authoritative (map-backed): a
/// permission that merely *looks* like a mail permission but has no Exchange
/// application role is **not** scopable.
pub fn is_scopable_exchange_permission(value: &str) -> bool {
    exchange_role_for_permission(value).is_some()
}

/// [`is_scopable_exchange_permission`] for a permission whose resource IS known —
/// the form every surface that has a resource id should use. Office 365 Exchange
/// Online's own `Mail.Read`-family appRoles (retired Outlook REST) have no RBAC
/// role, so only the resource-aware answer can tell them apart from Microsoft
/// Graph's identically named ones. A `None` resource means "a resource this build
/// doesn't resolve", which is never scopable.
pub fn is_scopable_exchange_resource_permission(
    resource_app_id: Option<&str>,
    value: &str,
) -> bool {
    resource_app_id.is_some_and(|id| exchange_role_for_resource_permission(id, value).is_some())
}

/// True for a grant that reaches **every** mailbox with full access regardless
/// of which individual mail permission is being examined — today only the EWS
/// [`EWS_FULL_ACCESS_AS_APP`] scope.
///
/// Such a surviving org-wide grant defeats *every* per-permission RBAC scope on
/// the same principal (RBAC and Entra grants union), so the effective-scope
/// reconciliation treats it as a blanket veto rather than matching it against
/// one permission value.
pub fn is_blanket_mailbox_grant(value: &str) -> bool {
    value == EWS_FULL_ACCESS_AS_APP
}

/// True for an org-wide SharePoint permission — every `Sites.*` except
/// `Sites.Selected` (the scoped model). Gates the per-permission "Scope…" action
/// that converts a broad grant to `Sites.Selected` on chosen sites.
pub fn is_sharepoint_orgwide(value: &str) -> bool {
    value.starts_with("Sites.") && value != "Sites.Selected"
}

/// Which scoping *authority* can confine a Graph application permission. Each
/// mechanism has its own target type and apply strategy, but the scope UX shell
/// (pick permission → choose targets → review) is uniform across them — this enum
/// is the dispatch key. Add a variant (plus a target panel + apply arm) to teach
/// the app a new mechanism; nothing else branches on the concrete mechanism.
///
/// Distinct from [`crate::audit::ScopeMechanism`], which is the Exchange-*internal*
/// detail (RBAC vs legacy Application Access Policy) of how mail is confined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    /// Mail/calendar/contacts → confine to mailbox group(s) via Exchange RBAC.
    Exchange,
    /// `Sites.*` → confine to specific sites via `Sites.Selected`.
    SharePoint,
    // Future: AdministrativeUnit (directory perms), AzureRbac (ARM/MI),
    // ResourceSpecificConsent (Teams/Chat — owner-consented, see `admin_applicable`).
}

impl ScopeKind {
    /// Capabilities-catalog key for the role hint a scope action surfaces.
    pub fn capability_key(self) -> &'static str {
        match self {
            ScopeKind::Exchange => "exchange_rbac",
            ScopeKind::SharePoint => "sharepoint_sites_selected",
        }
    }

    /// Whether an admin can apply this scoping centrally. Future owner-consented
    /// mechanisms (Teams/Chat resource-specific consent) return `false`, so the UI
    /// renders guidance instead of an apply button rather than offering a control
    /// that can't work.
    pub fn admin_applicable(self) -> bool {
        match self {
            ScopeKind::Exchange | ScopeKind::SharePoint => true,
        }
    }
}

/// The mechanism (if any) that can resource-scope the permission `value`.
/// Single source of truth: mail/calendar/contacts and the EWS
/// `full_access_as_app` scope → Exchange RBAC; `Sites.Selected` or a broad
/// `Sites.*` → SharePoint `Sites.Selected`; everything else (e.g.
/// `Directory.Read.All`) is org-wide only and returns `None`.
pub fn scope_kind(value: &str) -> Option<ScopeKind> {
    if is_scopable_exchange_permission(value) {
        Some(ScopeKind::Exchange)
    } else if value == "Sites.Selected" || is_sharepoint_orgwide(value) {
        Some(ScopeKind::SharePoint)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_common_mail_permissions() {
        assert_eq!(
            exchange_role_for_permission("Mail.Read"),
            Some("Application Mail.Read")
        );
        assert_eq!(
            exchange_role_for_permission("Calendars.ReadWrite"),
            Some("Application Calendars.ReadWrite")
        );
        assert_eq!(
            exchange_role_for_permission("Mail.ReadBasic.All"),
            Some("Application Mail.ReadBasic")
        );
    }

    #[test]
    fn unmapped_permission_returns_none() {
        assert_eq!(exchange_role_for_permission("User.Read.All"), None);
        assert!(!is_scopable_exchange_permission("Directory.Read.All"));
        assert!(is_scopable_exchange_permission("Mail.Send"));
    }

    #[test]
    fn ews_full_access_as_app_maps_on_the_exchange_online_resource() {
        // The one non-Graph permission Application Access Policies could
        // confine. It must map, or an AAP migration silently leaves the app with
        // org-wide EWS access to every mailbox.
        assert_eq!(
            exchange_role_for_resource_permission(
                OFFICE365_EXCHANGE_ONLINE_APP_ID,
                EWS_FULL_ACCESS_AS_APP
            ),
            Some("Application EWS.AccessAsApp")
        );
        assert!(is_scopable_exchange_permission(EWS_FULL_ACCESS_AS_APP));
        assert_eq!(
            scope_kind(EWS_FULL_ACCESS_AS_APP),
            Some(ScopeKind::Exchange)
        );
        // ...and only on that resource — Graph never exposes it.
        assert_eq!(
            exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, EWS_FULL_ACCESS_AS_APP),
            None
        );
    }

    #[test]
    fn exchange_online_mail_lookalikes_have_no_rbac_role() {
        // Office 365 Exchange Online exposes its own `Mail.Read`-style appRoles
        // for the retired Outlook REST API. RBAC for Applications covers only MS
        // Graph and EWS, so those must NOT map — claiming otherwise would report
        // a scope the toolkit can't enforce and would strip a grant with no
        // scoped replacement.
        for value in ["Mail.Read", "Mail.Send", "Calendars.ReadWrite"] {
            assert_eq!(
                exchange_role_for_resource_permission(OFFICE365_EXCHANGE_ONLINE_APP_ID, value),
                None,
                "{value} on Office 365 Exchange Online must not map to an RBAC role"
            );
            // The same value on Graph does map.
            assert!(exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, value).is_some());
        }
    }

    #[test]
    fn unknown_resource_maps_nothing() {
        assert_eq!(
            exchange_role_for_resource_permission(
                "11111111-2222-3333-4444-555555555555",
                "Mail.Read"
            ),
            None
        );
    }

    #[test]
    fn only_ews_full_access_is_a_blanket_grant() {
        // A blanket grant vetoes every per-permission scope verdict, so the set
        // must stay exactly the permission that really reaches all mailboxes.
        assert!(is_blanket_mailbox_grant(EWS_FULL_ACCESS_AS_APP));
        assert!(!is_blanket_mailbox_grant("Mail.ReadWrite"));
        assert!(!is_blanket_mailbox_grant("Mail.Read"));
    }

    #[test]
    fn loose_mail_lookalikes_are_not_scopable() {
        // The map is authoritative: these look mail-ish but have no Exchange
        // application role, so a prefix check would wrongly call them scopable.
        assert!(!is_scopable_exchange_permission("Mail.ReadWrite.Shared"));
        assert!(!is_scopable_exchange_permission(
            "MailboxSettings.ReadBasic"
        ));
    }

    #[test]
    fn sharepoint_org_wide_is_every_sites_except_selected() {
        assert!(is_sharepoint_orgwide("Sites.Read.All"));
        assert!(is_sharepoint_orgwide("Sites.ReadWrite.All"));
        assert!(is_sharepoint_orgwide("Sites.FullControl.All"));
        assert!(!is_sharepoint_orgwide("Sites.Selected"));
        assert!(!is_sharepoint_orgwide("Mail.Read"));
        assert!(!is_sharepoint_orgwide("Directory.Read.All"));
    }

    #[test]
    fn scope_kind_classifies_by_mechanism() {
        // Mail/calendar/contacts → Exchange RBAC.
        assert_eq!(scope_kind("Mail.Read"), Some(ScopeKind::Exchange));
        assert_eq!(scope_kind("Calendars.ReadWrite"), Some(ScopeKind::Exchange));
        assert_eq!(scope_kind("Contacts.Read"), Some(ScopeKind::Exchange));
        // Both the scoped model and a broad Sites.* → SharePoint.
        assert_eq!(scope_kind("Sites.Selected"), Some(ScopeKind::SharePoint));
        assert_eq!(scope_kind("Sites.Read.All"), Some(ScopeKind::SharePoint));
        assert_eq!(
            scope_kind("Sites.FullControl.All"),
            Some(ScopeKind::SharePoint)
        );
        // Org-wide-only permissions are not scopable.
        assert_eq!(scope_kind("Directory.Read.All"), None);
        assert_eq!(scope_kind("User.Read.All"), None);
        // A mail look-alike with no Exchange role is not scopable.
        assert_eq!(scope_kind("Mail.ReadWrite.Shared"), None);
    }

    #[test]
    fn scope_kind_metadata_is_per_mechanism() {
        assert_eq!(ScopeKind::Exchange.capability_key(), "exchange_rbac");
        assert_eq!(
            ScopeKind::SharePoint.capability_key(),
            "sharepoint_sites_selected"
        );
        assert!(ScopeKind::Exchange.admin_applicable());
        assert!(ScopeKind::SharePoint.admin_applicable());
    }
}
