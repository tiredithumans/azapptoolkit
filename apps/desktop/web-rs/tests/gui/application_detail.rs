//! GUI tests for the App Registration detail pane. Driven by an `object_id`
//! prop; auto-loads `get_application_detail` on mount.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::application_detail_pane::ApplicationDetailPane;

#[wasm_bindgen_test]
async fn loads_and_renders_detail() {
    ts::reset();
    ts::mock_ok(
        "get_application_detail",
        &fixtures::application_detail("obj-1", "app-1", "Contoso CRM"),
    );

    let _m = ts::mount_view(
        || view! { <ApplicationDetailPane object_id=Signal::derive(|| "obj-1".to_string()) /> },
    );

    ts::wait_for(|| ts::body_contains("Contoso CRM")).await;
    let call = ts::last_call("get_application_detail").unwrap();
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    assert_eq!(call.arg_str("objectId").as_deref(), Some("obj-1"));
}

#[wasm_bindgen_test]
async fn overview_renders_internal_notes() {
    ts::reset();
    // Seed the detail fixture with internal notes; the Overview tab (default)
    // must surface them as a read field.
    let mut detail = fixtures::application_detail("obj-1", "app-1", "Contoso CRM");
    detail.application.notes = Some("Rotate secrets quarterly.".to_string());
    ts::mock_ok("get_application_detail", &detail);

    let _m = ts::mount_view(
        || view! { <ApplicationDetailPane object_id=Signal::derive(|| "obj-1".to_string()) /> },
    );

    ts::wait_for(|| ts::body_contains("Rotate secrets quarterly.")).await;
    assert!(ts::body_contains("Internal notes"));
}

#[wasm_bindgen_test]
async fn header_copy_shows_copied_badge() {
    ts::reset();
    ts::mock_ok(
        "get_application_detail",
        &fixtures::application_detail("obj-1", "app-1", "Contoso CRM"),
    );

    let _m = ts::mount_view(
        || view! { <ApplicationDetailPane object_id=Signal::derive(|| "obj-1".to_string()) /> },
    );
    ts::wait_for(|| ts::body_contains("Contoso CRM")).await;

    // The header's app-id copy button confirms the copy (shared CopyIconButton).
    ts::click("button[aria-label=\"Copy app id\"]");
    ts::wait_for(|| ts::query(".copyable-id__copied").is_some()).await;
}

#[wasm_bindgen_test]
async fn error_state_offers_retry_that_reloads() {
    ts::reset();
    ts::mock_err(
        "get_application_detail",
        &fixtures::ui_error("not_found", "Application not found in this tenant"),
    );

    let _m = ts::mount_view(
        || view! { <ApplicationDetailPane object_id=Signal::derive(|| "obj-1".to_string()) /> },
    );

    ts::wait_for(|| ts::body_contains("Application not found")).await;
    // The Err branch is no longer a dead-end: a Retry button re-runs the load.
    ts::wait_for(|| ts::query(".ui-load-error button").is_some()).await;
    let before = ts::call_count("get_application_detail");
    ts::click(".ui-load-error button");
    ts::wait_for(|| ts::call_count("get_application_detail") > before).await;
}

/// The two list reload counters, read without tracking.
fn reloads(m: &ts::Mounted) -> (u32, u32) {
    (
        m.session.apps_reload.get_untracked(),
        m.session.enterprise_apps_reload.get_untracked(),
    )
}

/// A delete from the detail pane refreshes both lists: the row used to linger
/// in App Registrations until something else refetched, and Graph deletes the
/// app's service principal along with it. The backend patches its caches for
/// the delete, so both refetches are cache hits.
#[wasm_bindgen_test]
async fn deleting_from_the_detail_pane_refreshes_both_lists() {
    ts::reset();
    ts::mock_ok(
        "get_application_detail",
        &fixtures::application_detail("obj-1", "app-1", "Contoso CRM"),
    );
    ts::mock_ok("delete_application", &());

    let m = ts::mount_view(
        || view! { <ApplicationDetailPane object_id=Signal::derive(|| "obj-1".to_string()) /> },
    );
    ts::wait_for(|| ts::body_contains("Contoso CRM")).await;
    let (apps, enterprise) = reloads(&m);

    ts::click_button_labelled("Delete");
    ts::wait_for(|| ts::query(".modal").is_some()).await;
    ts::click_button_labelled_in(".modal", "Delete");

    ts::wait_for(|| reloads(&m) == (apps + 1, enterprise + 1)).await;
    assert_eq!(
        ts::last_call("delete_application")
            .unwrap()
            .arg_str("objectId")
            .as_deref(),
        Some("obj-1")
    );
}

/// [`ts::wait_for`] that names the step it was stuck on and dumps the page.
async fn settle(step: &str, f: impl Fn() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        ts::tick().await;
    }
    panic!("stuck at {step}; body:\n{}", ts::body_text());
}

/// A rename refreshes the App Registrations list, whose rows show the name.
/// A description edit does not: no list shows it.
#[wasm_bindgen_test]
async fn a_rename_refreshes_the_app_list_and_a_description_edit_does_not() {
    ts::reset();
    ts::mock_ok(
        "get_application_detail",
        &fixtures::application_detail("obj-1", "app-1", "Contoso CRM"),
    );
    ts::mock_ok("update_application", &());

    let m = ts::mount_view(
        || view! { <ApplicationDetailPane object_id=Signal::derive(|| "obj-1".to_string()) /> },
    );
    settle("loaded", || ts::body_contains("Contoso CRM")).await;
    let (apps, _) = reloads(&m);

    ts::click_button_labelled("Edit");
    settle("rename form", || {
        ts::query(".overview-tab .form-grid input").is_some()
    })
    .await;
    ts::set_input_value(".overview-tab .form-grid input", "Contoso CRM v2");
    settle("rename Save enabled", || {
        ts::button_labelled_enabled("Save")
    })
    .await;
    ts::click_button_labelled("Save");
    settle("rename landed", || reloads(&m).0 == apps + 1).await;

    settle("Edit again", || ts::button_labelled_enabled("Edit")).await;
    ts::click_button_labelled("Edit");
    settle("description form", || {
        ts::query(".overview-tab textarea").is_some()
    })
    .await;
    ts::set_input_value(".overview-tab textarea", "A new description");
    settle("description Save enabled", || {
        ts::button_labelled_enabled("Save")
    })
    .await;
    ts::click_button_labelled("Save");
    settle("description sent", || {
        ts::call_count("update_application") == 2
    })
    .await;
    settle("form closed", || ts::button_labelled_enabled("Edit")).await;
    assert_eq!(
        reloads(&m).0,
        apps + 1,
        "a description edit refetched the list"
    );
}
