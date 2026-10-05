//! Maps application permissions to the equivalent Exchange Online RBAC
//! "application role" names — the Microsoft Graph mail/calendar/contacts set
//! plus the EWS `full_access_as_app` scope on the legacy Office 365 Exchange
//! Online resource.
//!
//! The canonical mapping now lives in `azapptoolkit_core::scoping` so the WASM
//! frontend's scope badges and this backend share one definition; this module
//! re-exports it for `azapptoolkit-exchange`'s existing callers (and the crate
//! root re-export in `lib.rs`).

// Only the resource-aware forms exist to re-export now: the value-only ones
// were deleted, so the blanket `#[allow(deprecated)]` that used to sit here —
// and hid them from every caller of this crate root — has nothing to allow.
pub use azapptoolkit_core::scoping::{
    EWS_FULL_ACCESS_AS_APP, MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID,
    exchange_role_for_resource_permission, is_aap_confinable_permission, is_blanket_mailbox_grant,
    is_scopable_exchange_resource_permission,
};

/// The composite RBAC-for-Applications roles and the Microsoft Graph permission
/// values each one bundles, from the role table at
/// <https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac>.
/// The one definition the verdict layer (`verdict::row_grants_permission`) and
/// the scoping run's org-wide-assignment warning (`targets::orgwide_role_assignments`)
/// both read.
///
/// A composite role carries none of its bundled permissions' own role names, so
/// a reader matching `RoleName` against `Application Mail.Send` finds nothing.
/// `Test-ServicePrincipalAuthorization` names the bundle in `GrantedPermissions`,
/// but a row without that list (or with it formatted differently) must still
/// confer what the role grants: missing an **org-wide** composite row beside a
/// scoped dedicated one read the permission as scoped while it reached every
/// mailbox.
const COMPOSITE_ROLES: &[(&str, &[&str])] = &[
    (
        "Application Mail Full Access",
        &["Mail.ReadWrite", "Mail.Send"],
    ),
    (
        "Application Exchange Full Access",
        &[
            "Mail.ReadWrite",
            "Mail.Send",
            "MailboxSettings.ReadWrite",
            "Calendars.ReadWrite",
            "Contacts.ReadWrite",
        ],
    ),
];

/// True when `role` is a composite RBAC-for-Applications role (the private
/// `COMPOSITE_ROLES` table) that bundles the Microsoft Graph permission `value`.
/// Both compare case-insensitively: Exchange role names are case-insensitive,
/// and the cmdlets echo whatever case they stored.
pub fn composite_role_confers(role: &str, value: &str) -> bool {
    let (role, value) = (role.trim(), value.trim());
    COMPOSITE_ROLES.iter().any(|(name, bundle)| {
        name.eq_ignore_ascii_case(role) && bundle.iter().any(|v| v.eq_ignore_ascii_case(value))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every bundled value is a Microsoft Graph permission RBAC can scope on its
    /// own, so a composite never confers something the dedicated-role path
    /// could not name — and never the EWS scope, which no composite bundles.
    #[test]
    fn composite_bundles_are_scopable_graph_permissions() {
        for (role, bundle) in COMPOSITE_ROLES {
            for value in *bundle {
                assert!(
                    exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, value).is_some(),
                    "{role} bundles {value}, which must be a scopable Graph permission"
                );
                assert!(composite_role_confers(role, value));
            }
        }
        assert!(composite_role_confers(
            "application exchange full access",
            "calendars.readwrite"
        ));
        assert!(!composite_role_confers(
            "Application Mail Full Access",
            "Calendars.ReadWrite"
        ));
        assert!(!composite_role_confers(
            "Application Exchange Full Access",
            EWS_FULL_ACCESS_AS_APP
        ));
        // A dedicated role is not a composite.
        assert!(!composite_role_confers(
            "Application Mail.Send",
            "Mail.Send"
        ));
    }
}
