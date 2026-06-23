//! GUI test for the Managed Identity grant path after scoping was unified into
//! the "Grant scoped access" wizard. Granting a permission from the picker now
//! grants it **org-wide** directly (via `grant_managed_identity_permission`) with
//! no inline scope panel — scoping a permission is done through the wizard (its
//! own coverage lives in `scope_wizard.rs`), reachable from the detail pane's
//! "Grant scoped access…" button or a held row's "Scope…".
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::exchange::MailScopeEntry;
use azapptoolkit_dto::managed_identity::{
    AppRoleGrantDto, AzureRolesResult, GrantManagedIdentityResult,
};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::managed_identities::ManagedIdentitiesView;

wasm_bindgen_test_configure!(run_in_browser);

fn mi_grant_result() -> GrantManagedIdentityResult {
    GrantManagedIdentityResult {
        managed_identity_id: "mi-0".to_string(),
        granted: vec!["Mail.Read".to_string()],
        skipped: Vec::new(),
        failures: Vec::new(),
    }
}

/// Mocks the MI list + detail pane + picker, mounts the view, selects the one
/// managed identity on its Permissions tab, and reveals the picker — leaving a
/// single `Mail.Read` application-permission row with its Grant button.
async fn mount_and_open_picker() -> ts::Mounted {
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
        &fixtures::graph_resource_permissions(&["Mail.Read"]),
    );

    let m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });

    ts::wait_for(|| ts::query_all(".app-list__row").len() == 1).await;
    m.session.last_mi_tab.set("permissions".to_string());
    m.session
        .selected_managed_identity_id
        .set(Some("mi-0".to_string()));
    ts::wait_for(|| ts::body_contains("Grant application permissions")).await;
    ts::click(".mi-grant header button");
    ts::wait_for(|| {
        ts::body_contains("Mail.Read") && !ts::query_all(".permission-picker__row").is_empty()
    })
    .await;

    m
}

#[wasm_bindgen_test]
async fn granting_a_mail_permission_grants_orgwide_directly() {
    let _m = mount_and_open_picker().await;
    ts::mock_ok("grant_managed_identity_permission", &mi_grant_result());

    // Grant the (only) row — Mail.Read.
    ts::click(".permission-picker__row button");
    ts::wait_for(|| ts::call_count("grant_managed_identity_permission") == 1).await;

    // No inline scope panel — scoping is via the wizard now.
    assert!(
        ts::query(".mi-scope-panel").is_none(),
        "the inline scope panel was retired; the wizard handles scoping"
    );
    let call = ts::last_call("grant_managed_identity_permission").unwrap();
    assert!(
        call.args
            .get("roles")
            .and_then(|r| r.as_array())
            .map(|a| a.iter().any(|v| v.as_str() == Some("Mail.Read")))
            .unwrap_or(false),
        "the picked permission is granted org-wide"
    );
}

#[wasm_bindgen_test]
async fn detail_pane_offers_the_scope_wizard() {
    let _m = mount_and_open_picker().await;
    // The streamlined scoping entry point is always present on the pane.
    assert!(ts::body_contains("Grant scoped access"));
}
