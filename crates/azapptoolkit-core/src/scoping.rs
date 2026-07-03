//! Permission-*scoping* predicates shared by the backend and the WASM frontend.
//!
//! Both surfaces need to answer the same two questions about a Graph application
//! permission value, and they must answer them identically:
//! - **Exchange** (mail/calendar/contacts): can this permission be resource-scoped
//!   via RBAC for Applications? The answer is authoritative only if it matches the
//!   exact set Exchange recognises, so it is derived from the role *map*, never a
//!   loose prefix check (`Mail.ReadWrite.Shared` looks mail-ish but has no Exchange
//!   application role, so it is **not** scopable).
//! - **SharePoint** (`Sites.*`): scoping is encoded by the permission name —
//!   `Sites.Selected` is the scoped model, every other `Sites.*` is org-wide.
//!
//! This lives in `azapptoolkit-core` (which compiles to `wasm32`) so the badge
//! rendering in `web-rs` and the grant/scope logic in the Tauri backend call one
//! definition instead of drifting copies. `azapptoolkit-exchange` re-exports the
//! Exchange helpers for its existing callers.

/// The Exchange application role that grants the same capability as
/// `graph_permission` (e.g. `Mail.Read` -> `Application Mail.Read`). Returns
/// `None` for Graph permissions that have no Exchange application role (these
/// are not scopable via RBAC for Applications and must stay org-wide).
///
/// Source: <https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac>
/// ("Supported Application Roles"). Only the mail/calendar/contacts subset
/// commonly used with the old Application Access Policies is mapped here; the
/// full role list is larger.
pub fn exchange_role_for_graph_permission(graph_permission: &str) -> Option<&'static str> {
    let role = match graph_permission {
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

/// True when `graph_permission` is an Exchange mailbox permission that can be
/// resource-scoped via RBAC for Applications. Authoritative (map-backed): a
/// permission that merely *looks* like a mail permission but has no Exchange
/// application role is **not** scopable.
pub fn is_scopable_exchange_permission(graph_permission: &str) -> bool {
    exchange_role_for_graph_permission(graph_permission).is_some()
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

/// The mechanism (if any) that can resource-scope the Graph permission `value`.
/// Single source of truth: mail/calendar/contacts → Exchange RBAC; `Sites.Selected`
/// or a broad `Sites.*` → SharePoint `Sites.Selected`; everything else (e.g.
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
            exchange_role_for_graph_permission("Mail.Read"),
            Some("Application Mail.Read")
        );
        assert_eq!(
            exchange_role_for_graph_permission("Calendars.ReadWrite"),
            Some("Application Calendars.ReadWrite")
        );
        assert_eq!(
            exchange_role_for_graph_permission("Mail.ReadBasic.All"),
            Some("Application Mail.ReadBasic")
        );
    }

    #[test]
    fn unmapped_permission_returns_none() {
        assert_eq!(exchange_role_for_graph_permission("User.Read.All"), None);
        assert!(!is_scopable_exchange_permission("Directory.Read.All"));
        assert!(is_scopable_exchange_permission("Mail.Send"));
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
