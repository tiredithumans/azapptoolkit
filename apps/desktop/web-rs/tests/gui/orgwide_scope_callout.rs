//! GUI tests for the org-wide discoverability callout (`OrgwideScopeCallout`)
//! on a bare service principal's Permissions surface: it names the held
//! org-wide values up front and its "Scope…" opens the Grant-access wizard
//! pre-seeded (jumping to the choose-access step), and it stays hidden when
//! everything held is already scoped. Mounted via the managed-identity detail
//! window — the enterprise pane renders the identical shared component from
//! the same inputs.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::exchange::MailScopeEntry;
use azapptoolkit_dto::managed_identity::AzureRolesResult;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::managed_identities::ManagedIdentityDetailWindow;

fn click_button(label: &str) {
    for el in ts::query_all("button") {
        if el.text_content().unwrap_or_default().trim() == label {
            let el: web_sys::HtmlElement = el.unchecked_into();
            el.click();
            return;
        }
    }
    panic!("no button labelled `{label}`");
}

/// Mount the MI detail window on its Permissions tab with the given held
/// grants (mail scoping unresolved — the empty map reads org-wide).
async fn mount_with_grants(values: &[&str]) -> ts::Mounted {
    let grants: Vec<_> = values.iter().map(|v| fixtures::held_grant(v)).collect();
    mount_with(grants).await
}

/// As [`mount_with_grants`], but the caller supplies the grant DTOs — so a test
/// can hold a permission on the legacy Office 365 Exchange Online resource
/// instead of Microsoft Graph.
async fn mount_with(
    grants: Vec<azapptoolkit_dto::managed_identity::AppRoleGrantDto>,
) -> ts::Mounted {
    ts::reset();
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-prod-api"]),
    );
    ts::mock_ok("list_held_app_role_grants", &grants);
    ts::mock_ok(
        "get_mail_scopes_for_principal",
        &Vec::<MailScopeEntry>::new(),
    );
    ts::mock_ok(
        "list_managed_identity_azure_roles",
        &AzureRolesResult::default(),
    );
    ts::mock_ok(
        "list_catalog_resources",
        &vec![fixtures::graph_resource_summary()],
    );
    ts::mock_ok(
        "list_resource_permission_counts",
        &vec![fixtures::graph_resource_summary()],
    );
    ts::mock_ok(
        "list_resource_permissions",
        &fixtures::graph_resource_permissions(&["Mail.Read", "Mail.ReadWrite", "User.Read.All"]),
    );

    let m = ts::mount_view(|| {
        view! { <ManagedIdentityDetailWindow mi_id=Signal::derive(|| "mi-0".to_string()) /> }
    });
    m.session.last_mi_tab.set("permissions".to_string());
    ts::wait_for(|| ts::body_contains("Current permissions")).await;
    m
}

#[wasm_bindgen_test]
async fn callout_names_orgwide_values_and_scope_opens_the_wizard_preseeded() {
    let _m = mount_with_grants(&["Mail.ReadWrite"]).await;
    ts::wait_for(|| ts::body_contains("holds organization-wide access")).await;
    assert!(
        ts::body_contains("Mail.ReadWrite"),
        "the callout names the org-wide value"
    );
    // Its "Scope…" opens the Grant-access wizard pre-seeded to that permission —
    // the preseed contract jumps straight to the choose-access step.
    click_button("Scope…");
    ts::wait_for(|| ts::body_contains("Step 2 of 3")).await;
}

#[wasm_bindgen_test]
async fn callout_names_the_ews_scope_and_warns_that_it_overrides_mailbox_scopes() {
    // `full_access_as_app` lives on Office 365 Exchange Online, not Microsoft
    // Graph. It reaches every mailbox with full access, so it must appear here —
    // and the note has to say it overrides per-permission mailbox scopes, matching
    // the backend rule that forces a scoped verdict back to org-wide while it
    // survives.
    let _m = mount_with(vec![fixtures::held_exchange_grant("full_access_as_app")]).await;
    ts::wait_for(|| ts::body_contains("holds organization-wide access")).await;
    assert!(
        ts::body_contains("full_access_as_app"),
        "the callout names the EWS scope"
    );
    assert!(
        ts::body_contains("overrides any per-permission mailbox scope"),
        "the blanket-grant note explains why other scopes don't help yet"
    );
}

#[wasm_bindgen_test]
async fn callout_ignores_exchange_onlines_unscopable_mail_role() {
    // Same value name as Graph's, different resource: Office 365 Exchange Online's
    // `Mail.Read` (retired Outlook REST) has no RBAC role, so offering "Scope…"
    // would promise a confinement the backend refuses to apply.
    let _m = mount_with(vec![fixtures::held_exchange_grant("Mail.Read")]).await;
    ts::wait_for(|| ts::body_contains("Mail.Read")).await;
    assert!(
        !ts::body_contains("holds organization-wide access"),
        "an un-scopable Exchange Online role must not offer scoping"
    );
}

#[wasm_bindgen_test]
async fn callout_stays_hidden_when_nothing_held_is_orgwide() {
    // `Sites.Selected` is the scoped SharePoint model and `User.Read.All` has no
    // scoping mechanism — neither reads as scopable org-wide access.
    let _m = mount_with_grants(&["Sites.Selected", "User.Read.All"]).await;
    ts::wait_for(|| ts::body_contains("Sites.Selected")).await;
    assert!(
        !ts::body_contains("holds organization-wide access"),
        "no callout without an org-wide scopable grant"
    );
}
