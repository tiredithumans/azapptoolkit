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

wasm_bindgen_test_configure!(run_in_browser);

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
    ts::reset();
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-prod-api"]),
    );
    let grants: Vec<_> = values.iter().map(|v| fixtures::held_grant(v)).collect();
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
