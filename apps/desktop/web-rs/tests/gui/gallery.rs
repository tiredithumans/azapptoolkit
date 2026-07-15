//! GUI test for the "Browse the Entra gallery" flow (New-application → gallery):
//! search → pick a template → confirm (name) → create. Mounts the dialog with a
//! mocked `applicationTemplates` search + a mocked instantiate, and asserts the
//! create command is called with the picked template id + the entered name.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::dialogs::gallery_dialog::GalleryDialog;

#[wasm_bindgen_test]
async fn browse_pick_and_create_from_gallery() {
    ts::reset();
    ts::mock_ok(
        "search_application_templates",
        &fixtures::gallery_search_results(),
    );
    ts::mock_ok(
        "create_gallery_application",
        &fixtures::gallery_app_summary(),
    );

    let _m = ts::mount_view(|| {
        view! {
            <GalleryDialog
                open=Signal::derive(|| true)
                on_close=Callback::new(|()| {})
                on_created=Callback::new(|()| {})
            />
        }
    });

    // Type a 2+ char query → the debounced search resolves and the sample
    // templates render.
    ts::set_input_value(".gallery-browse input", "sales");
    ts::wait_for(|| ts::body_contains("Salesforce")).await;

    // Pick the first result → the confirm stage (name field, pre-filled).
    ts::click(".gallery-result");
    ts::wait_for(|| ts::body_contains("Name for this application")).await;

    // Create → instantiate is called with the picked template + the name.
    ts::click(".gallery-create");
    ts::wait_for(|| ts::call_count("create_gallery_application") == 1).await;
    let call = ts::last_call("create_gallery_application").expect("create called");
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    assert!(
        call.arg_str("templateId").is_some(),
        "the picked template id is sent"
    );
    assert_eq!(call.arg_str("displayName").as_deref(), Some("Salesforce"));
}

/// A search that matched nothing must SAY so. It previously fell back to "Type
/// an app name to search the gallery." — telling operators to start typing when
/// they already had, which is what made a miss look like a broken search.
#[wasm_bindgen_test]
async fn zero_results_says_no_match_not_type_a_name() {
    ts::reset();
    ts::mock_ok(
        "search_application_templates",
        &fixtures::gallery_search_no_matches(),
    );

    let _m = ts::mount_view(|| {
        view! {
            <GalleryDialog
                open=Signal::derive(|| true)
                on_close=Callback::new(|()| {})
                on_created=Callback::new(|()| {})
            />
        }
    });

    // Before typing, the prompt is correct — this is the one case that earns
    // it. Awaited, not asserted outright: the resource resolves through
    // `Suspense`, so the first tick can still be the "Searching…" fallback.
    ts::wait_for(|| ts::body_contains("Type an app name to search the gallery.")).await;

    ts::set_input_value(".gallery-browse input", "nonesuch");
    ts::wait_for(|| ts::body_contains("No gallery apps match")).await;
    assert!(
        !ts::body_contains("Type an app name to search the gallery."),
        "a search that ran must not fall back to the start-typing prompt"
    );
}
