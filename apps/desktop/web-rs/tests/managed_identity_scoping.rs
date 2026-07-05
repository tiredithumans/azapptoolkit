//! GUI test for the Managed Identity grant path through the unified "Grant
//! access" wizard. The retired inline "Add permission" picker/Grant button is
//! gone: granting an application permission to a managed identity (a bare service
//! principal) now goes through the wizard's org-wide path
//! (`grant_managed_identity_permission`), and scoping is reachable from the same
//! wizard (its mechanism coverage lives in `scope_wizard.rs`).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::exchange::MailScopeEntry;
use azapptoolkit_dto::managed_identity::{
    AppRoleGrantDto, AzureRolesResult, GrantManagedIdentityResult,
};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::managed_identities::ManagedIdentityDetailWindow;

wasm_bindgen_test_configure!(run_in_browser);

fn mi_grant_result() -> GrantManagedIdentityResult {
    GrantManagedIdentityResult {
        managed_identity_id: "mi-0".to_string(),
        granted: vec!["Mail.Read".to_string()],
        skipped: Vec::new(),
        failures: Vec::new(),
    }
}

/// Click the first top-level (non-modal) button with this label.
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

fn next_enabled() -> bool {
    ts::query_all("button").iter().any(|el| {
        el.text_content().unwrap_or_default().trim() == "Next"
            && el
                .dyn_ref::<web_sys::HtmlButtonElement>()
                .map(|b| !b.disabled())
                .unwrap_or(false)
    })
}

/// Click a button inside the open wizard modal (disambiguated from the pane's
/// own "Grant access" entry button).
fn click_modal_button(label: &str) {
    for el in ts::query_all(".modal button") {
        if el.text_content().unwrap_or_default().trim() == label {
            let el: web_sys::HtmlElement = el.unchecked_into();
            el.click();
            return;
        }
    }
    panic!("no modal button labelled `{label}`");
}

/// Toggle the catalog row whose permission value matches `value` exactly.
fn select_permission(value: &str) {
    for row in ts::query_all(".permission-picker__row") {
        let head = row
            .query_selector(".permission-picker__row-head strong")
            .ok()
            .flatten();
        let is_match = head
            .map(|h| h.text_content().unwrap_or_default().trim() == value)
            .unwrap_or(false);
        if is_match {
            let cb = row
                .query_selector(".permission-picker__check")
                .ok()
                .flatten()
                .expect("permission row has a checkbox");
            let el: web_sys::HtmlElement = cb.unchecked_into();
            el.click();
            return;
        }
    }
    panic!("no permission row for `{value}`");
}

/// Mock the MI resolution + detail resources + catalog, mount the self-contained
/// detail window for the identity, and land on its Permissions tab. The window
/// resolves the identity (id `mi-0`) from the mocked `list_managed_identities`.
async fn mount_mi_permissions() -> ts::Mounted {
    ts::reset();
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-prod-api"]),
    );
    ts::mock_ok("list_held_app_role_grants", &Vec::<AppRoleGrantDto>::new());
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
        &fixtures::graph_resource_permissions(&["Mail.Read", "User.Read.All"]),
    );

    let m = ts::mount_view(|| {
        view! { <ManagedIdentityDetailWindow mi_id=Signal::derive(|| "mi-0".to_string()) /> }
    });
    // Land the pane on its Permissions tab (consumed once on mount, before the
    // window's resource resolves and mounts the pane).
    m.session.last_mi_tab.set("permissions".to_string());
    ts::wait_for(|| ts::body_contains("Current permissions")).await;
    m
}

#[wasm_bindgen_test]
async fn granting_a_permission_orgwide_through_the_wizard() {
    let _m = mount_mi_permissions().await;
    ts::mock_ok("grant_managed_identity_permission", &mi_grant_result());

    // Open the unified wizard from the pane's "Grant access" button.
    click_button("Grant access");
    ts::wait_for(|| !ts::query_all(".permission-picker__row").is_empty()).await;

    // Step 1 — pick a non-scopable permission, so the wizard offers org-wide only
    // (the bare-SP grant goes through `grant_managed_identity_permission`).
    select_permission("User.Read.All");
    ts::wait_for(next_enabled).await;
    click_modal_button("Next");

    // Step 2 — not scopable: the note explains why, and org-wide is forced.
    ts::wait_for(|| ts::body_contains("can't be scoped together")).await;
    click_modal_button("Next");

    // Step 3 — review, then grant.
    ts::wait_for(|| ts::body_contains("EVERY resource")).await;
    click_modal_button("Grant access");
    ts::wait_for(|| ts::call_count("grant_managed_identity_permission") == 1).await;

    let call = ts::last_call("grant_managed_identity_permission").unwrap();
    assert!(
        call.args
            .get("roles")
            .and_then(|r| r.as_array())
            .map(|a| a.iter().any(|v| v.as_str() == Some("User.Read.All")))
            .unwrap_or(false),
        "the picked permission is granted org-wide by value"
    );
}

#[wasm_bindgen_test]
async fn detail_pane_offers_the_grant_wizard() {
    let _m = mount_mi_permissions().await;
    // The single unified entry point opens the wizard (full catalog).
    click_button("Grant access");
    ts::wait_for(|| ts::body_contains("Step 1 of 3 — Select permissions")).await;
}
