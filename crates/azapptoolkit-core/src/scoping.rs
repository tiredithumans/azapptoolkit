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
}
