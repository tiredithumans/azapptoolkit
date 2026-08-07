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
use azapptoolkit_core::scoping::is_blanket_mailbox_grant;

use crate::components::scope_badge::{is_exchange_scopable_on, is_sharepoint_orgwide};
use crate::components::ui::Callout;

/// One held grant that reads as organization-wide, carrying everything the
/// wizard needs to be pre-seeded to it.
struct OrgwideGrant {
    value: String,
    app_role_id: String,
    resource_app_id: String,
}

/// The held grants that read as organization-wide: a scopable mail permission
/// whose resolved verdict is not `Scoped` (`OrgWide`/`Unknown`/unresolved all
/// count — the audit's never-under-report posture), or any org-wide `Sites.*`
/// (`Sites.Selected` excluded — it IS the scoped model).
///
/// Mail scopability is judged against the row's **own resource**: the EWS
/// `full_access_as_app` scope belongs here (it reaches every mailbox, and RBAC
/// can confine it), while Office 365 Exchange Online's un-scopable
/// `Mail.Read`-family roles must not be — offering "Scope…" for one would promise
/// a confinement the backend correctly refuses.
fn orgwide_grants(
    permissions: &[AppRoleGrantDto],
    scope_map: &HashMap<String, MailPermissionScope>,
) -> Vec<OrgwideGrant> {
    permissions
        .iter()
        .filter_map(|p| {
            let value = p.app_role_value.clone()?;
            let orgwide_mail = is_exchange_scopable_on(p.resource_app_id.as_deref(), &value)
                && !matches!(
                    scope_map.get(&value),
                    Some(MailPermissionScope::Scoped { .. })
                );
            (orgwide_mail || is_sharepoint_orgwide(&value)).then(|| OrgwideGrant {
                value,
                app_role_id: p.app_role_id.clone(),
                // A `Sites.*` role is always Microsoft Graph's, so the fallback
                // can't misattribute one.
                resource_app_id: p
                    .resource_app_id
                    .clone()
                    .unwrap_or_else(|| MICROSOFT_GRAPH_APP_ID.to_string()),
            })
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
    let first = orgwide.first().map(|g| PickerSelection {
        resource_app_id: g.resource_app_id.clone(),
        kind: PermissionKind::Application,
        permission_id: g.app_role_id.clone(),
        permission_value: g.value.clone(),
    });
    first.map(|sel| {
        let listing = orgwide
            .iter()
            .map(|g| g.value.clone())
            .collect::<Vec<_>>()
            .join(", ");
        // A blanket grant reaches every mailbox with full access, which overrides
        // any per-permission mailbox scope on this principal — the same rule the
        // backend applies when it forces a scoped verdict back to org-wide. Say so,
        // or a scope that reads "Scoped" elsewhere looks contradictory here.
        let blanket = orgwide
            .iter()
            .any(|g| is_blanket_mailbox_grant(&g.value))
            .then_some(
                " Note: full_access_as_app (Exchange Web Services) reaches every mailbox on its \
                 own, so it overrides any per-permission mailbox scope until it is removed — \
                 scope it first.",
            );
        view! {
            <Callout tone="warn">
                {format!(
                    "This identity holds organization-wide access: {listing}. It can be confined to specific mailboxes (Exchange RBAC) or sites (Sites.Selected).",
                )}
                {blanket}
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| on_scope.run(sel.clone()))
                    >
                        "Scope…"
                    </Button>
                </div>
            </Callout>
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::audit::ScopeMechanism;

    fn grant(value: Option<&str>) -> AppRoleGrantDto {
        on_resource(value, Some(MICROSOFT_GRAPH_APP_ID))
    }

    fn on_resource(value: Option<&str>, resource_app_id: Option<&str>) -> AppRoleGrantDto {
        AppRoleGrantDto {
            assignment_id: "aid".to_string(),
            resource_id: "res".to_string(),
            resource_app_id: resource_app_id.map(str::to_string),
            resource_display_name: Some("Microsoft Graph".to_string()),
            app_role_id: format!("role-{}", value.unwrap_or("none")),
            app_role_value: value.map(str::to_string),
        }
    }

    /// Office 365 Exchange Online's app id — the resource that carries the EWS
    /// scope (and its own un-scopable `Mail.Read` family).
    const EXO: &str = "00000002-0000-0ff1-ce00-000000000000";

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
        let got: Vec<(String, String)> = orgwide_grants(&perms, &scope_map)
            .into_iter()
            .map(|g| (g.value, g.app_role_id))
            .collect();
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

    #[test]
    fn orgwide_grants_flag_the_ews_scope_and_seed_its_own_resource() {
        // `full_access_as_app` reaches every mailbox and RBAC can confine it, so it
        // belongs in the callout — and the wizard must be seeded with the Exchange
        // Online resource, not Microsoft Graph, or the pre-seeded selection names a
        // permission that resource doesn't have.
        let perms = vec![on_resource(Some("full_access_as_app"), Some(EXO))];
        let got = orgwide_grants(&perms, &HashMap::new());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].value, "full_access_as_app");
        assert_eq!(got[0].resource_app_id, EXO);
    }

    #[test]
    fn orgwide_grants_skip_exchange_onlines_unscopable_mail_roles() {
        // Same value name, different resource: Office 365 Exchange Online's
        // `Mail.Read` (retired Outlook REST) has no RBAC role, so offering "Scope…"
        // would promise a confinement the backend refuses to apply.
        let perms = vec![on_resource(Some("Mail.Read"), Some(EXO))];
        assert!(orgwide_grants(&perms, &HashMap::new()).is_empty());
        // ...while Graph's identically named permission IS flagged.
        let perms = vec![on_resource(Some("Mail.Read"), Some(MICROSOFT_GRAPH_APP_ID))];
        assert_eq!(orgwide_grants(&perms, &HashMap::new()).len(), 1);
    }

    #[test]
    fn orgwide_grants_skip_a_row_whose_resource_is_unknown() {
        // An unresolved resource can't be judged scopable; the row already renders
        // id-only, so it must not gain a scope affordance either.
        let perms = vec![on_resource(Some("Mail.Read"), None)];
        assert!(orgwide_grants(&perms, &HashMap::new()).is_empty());
    }
}
