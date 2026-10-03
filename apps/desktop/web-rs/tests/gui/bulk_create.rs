//! GUI tests for F283 — bulk create from a file. "Load from file…" fills the
//! Create apps textarea (the review surface) without creating anything, the
//! loaded owners/permissions ride the create call, and a created-but-partial
//! row is reported as a problem rather than counted as a clean success.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::bulk::{
    BulkCreateOutcome, BulkCreatePermission, BulkCreateResult, BulkCreateSpec,
};
use azapptoolkit_dto::permissions::PermissionKind;
use azapptoolkit_web_rs::test_support as ts;
use azapptoolkit_web_rs::views::bulk_actions_view::BulkActionsView;

fn imported_spec() -> BulkCreateSpec {
    BulkCreateSpec {
        display_name: "Payroll Sync".to_string(),
        sign_in_audience: Some("AzureADMyOrg".to_string()),
        description: None,
        owner_upns: vec!["alice@contoso.com".to_string()],
        permissions: vec![BulkCreatePermission {
            resource: "Microsoft Graph".to_string(),
            value: "User.Read.All".to_string(),
            kind: PermissionKind::Application,
        }],
    }
}

fn textarea_value() -> String {
    ts::query(".bulk-action textarea")
        .map(|el| el.unchecked_into::<web_sys::HtmlTextAreaElement>().value())
        .unwrap_or_default()
}

async fn mount_create_tab() -> ts::Mounted {
    let m = ts::mount_view(|| view! { <BulkActionsView /> });
    ts::wait_for(|| ts::query("[role=tab]").is_some()).await;
    ts::click_button_labelled_in("[role=tablist]", "Create apps");
    ts::wait_for(|| ts::has_button_labelled("Load from file…")).await;
    m
}

#[wasm_bindgen_test]
async fn load_from_file_fills_the_textarea_and_creates_nothing() {
    ts::reset();
    ts::mock_ok(
        "load_bulk_create_specs_from_file",
        &Some(vec![imported_spec()]),
    );
    let _m = mount_create_tab().await;

    ts::click_button_labelled("Load from file…");
    ts::wait_for(|| textarea_value().contains("Payroll Sync")).await;
    let loaded: Vec<BulkCreateSpec> = serde_json::from_str(&textarea_value()).unwrap();
    assert_eq!(loaded[0].owner_upns, ["alice@contoso.com"]);
    assert_eq!(loaded[0].permissions.len(), 1);
    assert_eq!(ts::call_count("bulk_create_applications"), 0);
}

#[wasm_bindgen_test]
async fn a_cancelled_dialog_leaves_the_textarea_alone() {
    ts::reset();
    ts::mock_ok(
        "load_bulk_create_specs_from_file",
        &None::<Vec<BulkCreateSpec>>,
    );
    let _m = mount_create_tab().await;
    ts::set_textarea_value(".bulk-action textarea", "[{\"displayName\":\"Typed\"}]");

    ts::click_button_labelled("Load from file…");
    ts::wait_for(|| ts::call_count("load_bulk_create_specs_from_file") == 1).await;
    ts::tick().await;
    assert!(textarea_value().contains("Typed"));
}

#[wasm_bindgen_test]
async fn a_partial_create_is_a_problem_and_declared_permissions_say_unconsented() {
    ts::reset();
    ts::mock_ok(
        "bulk_create_applications",
        &BulkCreateResult {
            validate_only: false,
            outcomes: vec![BulkCreateOutcome {
                display_name: "Payroll Sync".to_string(),
                status: "created".to_string(),
                app_id: Some("app-1".to_string()),
                message: Some("Owner(s) not added: alice@contoso.com.".to_string()),
                error: None,
            }],
            cancelled: false,
        },
    );
    let _m = mount_create_tab().await;
    let json = serde_json::to_string(&vec![imported_spec()]).unwrap();
    ts::set_textarea_value(".bulk-action textarea", &json);

    ts::click_button_labelled_in(".bulk-action", "Create apps");
    ts::wait_for(|| ts::body_contains("Owner(s) not added")).await;
    assert!(ts::body_contains("0 ok, 1 problem"), "{}", ts::body_text());
    assert!(
        ts::body_contains("not consented yet"),
        "{}",
        ts::body_text()
    );

    let call = ts::last_call("bulk_create_applications").unwrap();
    assert_eq!(call.args["specs"][0]["ownerUpns"][0], "alice@contoso.com");
    assert_eq!(
        call.args["specs"][0]["permissions"][0]["value"],
        "User.Read.All"
    );
}
