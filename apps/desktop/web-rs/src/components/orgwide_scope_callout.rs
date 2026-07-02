//! Discoverability callout for a service principal holding **organization-wide**
//! access the Grant-access wizard can confine — shown above the held-permissions
//! table on the enterprise-app and managed-identity Permissions tabs. Those
//! surfaces are where a foreign-tenant (no local app registration) principal
//! gets scoped, but the Exchange/SharePoint sections only render further down
//! the page and the per-row "Scope…" only exists for `Sites.*` rows; this
//! callout names the org-wide values up front and opens the wizard pre-seeded,
//! exactly like a row's "Scope…" action.
//!
//! Pure presentation, mirroring [`HeldPermissionsPanel`](super::held_permissions_panel):
//! the caller resolves the grants + the effective mailbox-scope map and passes
//! them in.

use std::collections::HashMap;

use azapptoolkit_core::audit::MailPermissionScope;
use azapptoolkit_dto::managed_identity::AppRoleGrantDto;
use azapptoolkit_dto::permissions::PermissionKind;
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::components::permission_picker::{MICROSOFT_GRAPH_APP_ID, PickerSelection};
use crate::components::scope_badge::{is_exchange_scopable, is_sharepoint_orgwide};

/// The held grants that read as organization-wide, as `(value, app_role_id)`:
/// a scopable mail permission whose resolved verdict is not `Scoped`
/// (`OrgWide`/`Unknown`/unresolved all count — the audit's never-under-report
/// posture), or any org-wide `Sites.*` (`Sites.Selected` excluded — it IS the
/// scoped model).
fn orgwide_grants(
    permissions: &[AppRoleGrantDto],
    scope_map: &HashMap<String, MailPermissionScope>,
) -> Vec<(String, String)> {
    permissions
        .iter()
        .filter_map(|p| {
            let v = p.app_role_value.clone()?;
            let orgwide_mail = is_exchange_scopable(&v)
                && !matches!(scope_map.get(&v), Some(MailPermissionScope::Scoped { .. }));
            (orgwide_mail || is_sharepoint_orgwide(&v)).then(|| (v, p.app_role_id.clone()))
        })
        .collect()
}

#[component]
pub fn OrgwideScopeCallout(
    /// The resolved held grants (the caller awaits its own resource).
    permissions: Vec<AppRoleGrantDto>,
    /// Effective mailbox scope per permission value, resolved by the caller.
    /// Empty = unresolved, so every held mail value reads org-wide.
    scope_map: HashMap<String, MailPermissionScope>,
    /// Opens the caller's scope surface (the Grant-access wizard) pre-seeded to
    /// the first org-wide grant — the same contract as a held row's "Scope…".
    #[prop(into)]
    on_scope: Callback<PickerSelection>,
) -> impl IntoView {
    let orgwide = orgwide_grants(&permissions, &scope_map);
    orgwide.first().cloned().map(|(first_value, first_role_id)| {
        let listing = orgwide
            .iter()
            .map(|(v, _)| v.clone())
            .collect::<Vec<_>>()
            .join(", ");
        // A held mail/Sites value is a Microsoft Graph application role, so the
        // pre-seed selection is fully determined here (same reasoning as the
        // held-permissions row's "Scope…").
        let sel = PickerSelection {
            resource_app_id: MICROSOFT_GRAPH_APP_ID.to_string(),
            kind: PermissionKind::Application,
            permission_id: first_role_id,
            permission_value: first_value,
        };
        view! {
            <div class="alert alert--warn">
                {format!(
                    "This identity holds organization-wide access: {listing}. It can be confined to specific mailboxes (Exchange RBAC) or sites (Sites.Selected).",
                )}
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| on_scope.run(sel.clone()))
                    >
                        "Scope…"
                    </Button>
                </div>
            </div>
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::audit::ScopeMechanism;

    fn grant(value: Option<&str>) -> AppRoleGrantDto {
        AppRoleGrantDto {
            assignment_id: "aid".to_string(),
            resource_id: "res".to_string(),
            resource_display_name: Some("Microsoft Graph".to_string()),
            app_role_id: format!("role-{}", value.unwrap_or("none")),
            app_role_value: value.map(str::to_string),
        }
    }

    #[test]
    fn orgwide_grants_flags_unscoped_mail_and_broad_sites_only() {
        let scoped = MailPermissionScope::Scoped {
            scope_name: Some("azapptoolkit_x".to_string()),
            recipient_filter: None,
            group_count: Some(1),
            mechanism: ScopeMechanism::Rbac,
        };
        let scope_map: HashMap<String, MailPermissionScope> =
            [("Mail.Send".to_string(), scoped)].into();
        let perms = vec![
            grant(Some("Mail.Read")),      // mail, unresolved ⇒ org-wide
            grant(Some("Mail.Send")),      // mail, confirmed scoped ⇒ excluded
            grant(Some("Sites.Read.All")), // broad Sites ⇒ org-wide
            grant(Some("Sites.Selected")), // the scoped model ⇒ excluded
            grant(Some("User.Read.All")),  // not scopable by either mechanism
            grant(None),                   // no value resolved ⇒ excluded
        ];
        let got = orgwide_grants(&perms, &scope_map);
        assert_eq!(
            got,
            vec![
                ("Mail.Read".to_string(), "role-Mail.Read".to_string()),
                (
                    "Sites.Read.All".to_string(),
                    "role-Sites.Read.All".to_string()
                ),
            ]
        );
    }

    #[test]
    fn orgwide_grants_empty_map_counts_every_mail_value() {
        let perms = vec![grant(Some("Mail.Send"))];
        let got = orgwide_grants(&perms, &HashMap::new());
        assert_eq!(got.len(), 1, "unresolved scoping must not under-report");
    }
}
