//! Resource-scoping classification for permissions granted to a managed
//! identity: which picked or already-held Graph permissions can be confined to
//! a mailbox group (Exchange RBAC) or a SharePoint site (`Sites.Selected`).

use crate::components::scope_badge::{is_exchange_scopable, is_sharepoint_orgwide};
use crate::components::scope_panel::ScopeKind;

use super::MICROSOFT_GRAPH_APP_ID;

/// A permission the user picked that can be scoped to a resource before being
/// granted to the managed identity. Captured when the picker emits a scopable
/// selection so the inline panel can collect the resource (groups / site URL).
#[derive(Clone)]
pub(crate) struct PendingScope {
    /// The managed identity's service-principal object id (assignment target).
    pub(crate) sp_object_id: String,
    /// The managed identity's app id (Exchange SP pointer / site permission).
    pub(crate) app_id: String,
    pub(crate) display_name: String,
    pub(crate) resource_app_id: String,
    pub(crate) permission_value: String,
    pub(crate) kind: ScopeKind,
}

/// Classifies whether a picked Graph permission can be resource-scoped.
pub(crate) fn scope_kind_for(resource_app_id: &str, permission_value: &str) -> Option<ScopeKind> {
    if resource_app_id != MICROSOFT_GRAPH_APP_ID {
        return None;
    }
    if is_exchange_scopable(permission_value) {
        Some(ScopeKind::Exchange)
    } else if permission_value == "Sites.Selected" {
        Some(ScopeKind::SharePoint)
    } else {
        None
    }
}

/// Classifies whether an **already-held** permission can be restricted *per row*
/// after the fact: a broad `Sites.*` grant is SharePoint-scopable — the convert-to-
/// `Sites.Selected` case. Mail/calendar/contacts are excluded — Exchange RBAC
/// scoping is **app-wide** (one management scope binds the whole principal's mail
/// roles), so it's driven by the app-wide "Exchange scoping" section, not a per-row
/// button. Unlike [`scope_kind_for`] (the new-grant picker path) this still treats
/// a broad `Sites.*` as scopable. `app_role_value` is only populated for Microsoft
/// Graph permissions, so a `Some(value)` already implies the Graph resource.
pub(crate) fn existing_scope_kind_for(permission_value: &str) -> Option<ScopeKind> {
    is_sharepoint_orgwide(permission_value).then_some(ScopeKind::SharePoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_kind_for_only_classifies_graph_scopable_grants() {
        assert_eq!(
            scope_kind_for(MICROSOFT_GRAPH_APP_ID, "Mail.Read"),
            Some(ScopeKind::Exchange)
        );
        assert_eq!(
            scope_kind_for(MICROSOFT_GRAPH_APP_ID, "Sites.Selected"),
            Some(ScopeKind::SharePoint)
        );
        assert_eq!(scope_kind_for(MICROSOFT_GRAPH_APP_ID, "User.Read"), None);
        // A non-Graph resource is never Exchange/SharePoint-scopable here.
        assert_eq!(
            scope_kind_for("00000002-0000-0ff1-ce00-000000000000", "Mail.Read"),
            None
        );
    }

    #[test]
    fn existing_scope_kind_for_is_sharepoint_orgwide_only() {
        // Mail/calendar/contacts no longer offer a per-row Scope… — Exchange RBAC
        // scoping is app-wide, driven by the "Exchange scoping" section.
        assert_eq!(existing_scope_kind_for("Mail.Read"), None);
        assert_eq!(
            existing_scope_kind_for("Sites.Read.All"),
            Some(ScopeKind::SharePoint)
        );
        // Sites.Selected is already per-site, so it can't be *re*-scoped.
        assert_eq!(existing_scope_kind_for("Sites.Selected"), None);
        assert_eq!(existing_scope_kind_for("User.Read"), None);
    }
}
