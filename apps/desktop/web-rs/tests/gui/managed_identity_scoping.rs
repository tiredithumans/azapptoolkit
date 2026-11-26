//! GUI test for the Managed Identity grant path through the unified "Grant
//! access" wizard. The retired inline "Add permission" picker/Grant button is
//! gone: granting an application permission to a managed identity (a bare service
//! principal) now goes through the wizard's org-wide path
//! (`grant_managed_identity_permission`), and scoping is reachable from the same
//! wizard (its mechanism coverage lives in `scope_wizard.rs`).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::exchange::MailScopeEntry;
use azapptoolkit_dto::managed_identity::{
    AppRoleGrantDto, AzureRolesResult, GrantManagedIdentityResult,
};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::managed_identities::ManagedIdentityDetailWindow;

fn mi_grant_result() -> GrantManagedIdentityResult {
    GrantManagedIdentityResult {
        managed_identity_id: "mi-0".to_string(),
        granted: vec!["Mail.Read".to_string()],
        skipped: Vec::new(),
        failures: Vec::new(),
    }
}

/// Mock the MI resolution + detail resources + catalog, mount the self-contained
/// detail window for the identity, and land on its Permissions tab. The window
/// resolves the identity (id `mi-0`) from the mocked `list_managed_identities`.
async fn mount_mi_permissions() -> ts::Mounted {
    mount_mi_permissions_with(Vec::new(), Vec::new()).await
}

/// [`mount_mi_permissions`] holding `grants`, with `expiries` set on them.
async fn mount_mi_permissions_with(
    grants: Vec<AppRoleGrantDto>,
    expiries: Vec<azapptoolkit_core::audit::GrantExpiry>,
) -> ts::Mounted {
    ts::reset();
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-prod-api"]),
    );
    ts::mock_ok("list_held_app_role_grants", &grants);
    ts::mock_ok("get_grant_expiries", &expiries);
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
    ts::click_button_labelled("Grant access");
    ts::wait_for(|| !ts::query_all(".permission-picker__row").is_empty()).await;

    // Step 1 — pick a non-scopable permission, so the wizard offers org-wide only
    // (the bare-SP grant goes through `grant_managed_identity_permission`).
    ts::select_picker_permission("User.Read.All");
    ts::wait_for(|| ts::button_labelled_enabled("Next")).await;
    // Wizard buttons are scoped to the modal, disambiguated from the pane's own
    // "Grant access" entry button.
    ts::click_button_labelled_in(".modal", "Next");

    // Step 2 — not scopable: the note explains why, and org-wide is forced.
    ts::wait_for(|| ts::body_contains("can't be scoped together")).await;
    ts::click_button_labelled_in(".modal", "Next");

    // Step 3 — review, then grant.
    ts::wait_for(|| ts::body_contains("EVERY resource")).await;
    ts::click_button_labelled_in(".modal", "Grant access");
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
    ts::click_button_labelled("Grant access");
    ts::wait_for(|| ts::body_contains("Step 1 of 3 — Select permissions")).await;
}

/// A managed identity's held grants show their expiry dates and offer the
/// Expiry button: the only way to extend or clear a date it was given.
/// The held-permissions panel offers Meeting policy… on an online-meeting
/// grant and not on others (C3i).
#[wasm_bindgen_test]
async fn a_managed_identitys_meeting_grant_offers_the_meeting_policy() {
    use wasm_bindgen::JsCast;
    let _m = mount_mi_permissions_with(
        vec![
            fixtures::held_grant("OnlineMeetings.Read.All"),
            fixtures::held_grant("User.Read.All"),
        ],
        Vec::new(),
    )
    .await;
    ts::wait_for(|| ts::body_contains("OnlineMeetings.Read.All")).await;
    assert!(ts::query("[aria-label='Meeting policy for User.Read.All']").is_none());
    let button: web_sys::HtmlElement =
        ts::query("[aria-label='Meeting policy for OnlineMeetings.Read.All']")
            .expect("the meeting grant's button")
            .unchecked_into();
    button.click();
    ts::wait_for(|| ts::body_contains("Meeting access policy")).await;
}

#[wasm_bindgen_test]
async fn a_managed_identitys_held_grant_shows_and_edits_its_expiry() {
    use wasm_bindgen::JsCast;
    let grant = fixtures::held_grant("User.Read.All");
    let expiry = azapptoolkit_core::audit::GrantExpiry {
        resource_app_id: fixtures::MICROSOFT_GRAPH_APP_ID.to_string(),
        app_role_id: grant.app_role_id.clone(),
        expires_on: "2099-12-24".parse().unwrap(),
    };
    let _m = mount_mi_permissions_with(vec![grant], vec![expiry]).await;
    ts::wait_for(|| ts::body_contains("Expires 2099-12-24")).await;
    let button: web_sys::HtmlElement =
        ts::query("[aria-label='Set expiry for User.Read.All on Microsoft Graph']")
            .expect("the held grant's Expiry button")
            .unchecked_into();
    button.click();
    ts::wait_for(|| ts::body_contains("Expiry for User.Read.All")).await;
}
