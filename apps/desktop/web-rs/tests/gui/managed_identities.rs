//! GUI tests for the Managed Identities list. Unlike the App/Enterprise lists
//! this view has no result-count line, so assertions key off the shared
//! `.app-list__row` rows, the command recorder, and `body_contains`.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::ipc_mock;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::managed_identities::ManagedIdentitiesView;

#[wasm_bindgen_test]
async fn loads_and_renders_rows() {
    ts::reset();
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-prod-api", "mi-staging-worker"]),
    );

    let _m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });

    ts::wait_for(|| ts::query_all(".app-list__row").len() == 2).await;
    assert_eq!(
        ts::last_call("list_managed_identities")
            .unwrap()
            .arg_str("tenantId")
            .as_deref(),
        Some("test-tenant")
    );
}

/// A11Y-02: the third virtualized inventory list gets the same roving-tabindex
/// row navigation as the other two (wired once, in the shared `VirtualList`).
#[wasm_bindgen_test]
async fn arrow_keys_move_focus_between_rows() {
    ts::reset();
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-first", "mi-second"]),
    );

    let _m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });
    ts::wait_for(|| ts::query_all(".app-list__row[tabindex='0']").len() == 1).await;

    ts::focus(".app-list__row");
    ts::press_key(".app-list__row", "ArrowDown");
    assert!(ts::text(".app-list__row[tabindex='0']").contains("mi-second"));
}

#[wasm_bindgen_test]
async fn error_state_renders_message() {
    ts::reset();
    ts::mock_err(
        "list_managed_identities",
        &fixtures::ui_error("forbidden", "Directory read permission required"),
    );

    let _m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });

    ts::wait_for(|| ts::body_contains("Directory read permission required")).await;
}

#[wasm_bindgen_test]
async fn retry_after_error_refetches() {
    ts::reset();
    ts::mock_err("list_managed_identities", &fixtures::throttled_error());

    let _m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });
    // The MI list now renders its load failure via the shared `DetailLoadError`
    // (raw `UiError` message, no "Failed to load:" prefix) — see the P3 grammar.
    ts::wait_for(|| ts::body_contains(fixtures::THROTTLED_MESSAGE)).await;

    // The transient failure clears: Retry refetches in place (no remount).
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-recovered"]),
    );
    ts::click(".app-list__error button");

    ts::wait_for(|| ts::query_all(".app-list__row").len() == 1).await;
    assert_eq!(ts::call_count("list_managed_identities"), 2);
}

#[wasm_bindgen_test]
async fn empty_list_renders_no_rows() {
    ts::reset();
    ts::mock_ok(
        "list_managed_identities",
        &Vec::<azapptoolkit_dto::managed_identity::ManagedIdentityDto>::new(),
    );

    let _m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });

    ts::wait_for(|| ts::call_count("list_managed_identities") == 1).await;
    ts::tick().await;
    assert_eq!(ts::query_all(".app-list__row").len(), 0);
}

#[wasm_bindgen_test]
async fn refresh_invokes_invalidate_list_cache() {
    ts::reset();
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-solo"]),
    );
    ts::mock_ok("invalidate_list_cache", &());

    let _m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });
    ts::wait_for(|| ts::query_all(".app-list__row").len() == 1).await;

    ts::click("button[aria-label=\"Refresh managed identities\"]");

    ts::wait_for(|| ts::call_count("invalidate_list_cache") >= 1).await;
    let call = ts::last_call("invalidate_list_cache").unwrap();
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    // ListCacheKindDto is `rename_all = "snake_case"` → ManagedIdentities.
    assert_eq!(call.arg_str("kind").as_deref(), Some("managed_identities"));
}

/// The inventory export hands the save command exactly the rows the active
/// facet left ("what you see is what you export").
#[wasm_bindgen_test]
async fn export_saves_the_rows_the_facet_left() {
    ts::reset();
    let mut disabled = fixtures::managed_identity("mi-2", "mi-staging-worker");
    disabled.account_enabled = Some(false);
    ts::mock_ok(
        "list_managed_identities",
        &vec![fixtures::managed_identity("mi-1", "mi-prod-api"), disabled],
    );
    ts::mock_ok("save_managed_identities_to_file", &Option::<String>::None);

    let m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });
    ts::wait_for(|| ts::query_all(".app-list__row").len() == 2).await;

    m.session.tenant_ui.mi_facet.set("disabled".to_string());
    ts::wait_for(|| ts::query_all(".app-list__row").len() == 1).await;

    ts::click_button_labelled("Export");
    ts::wait_for(|| !ts::query_all("[role=\"menuitem\"]").is_empty()).await;
    ts::click_button_labelled("Export as CSV…");
    ts::wait_for(|| ts::call_count("save_managed_identities_to_file") == 1).await;

    let call = ts::last_call("save_managed_identities_to_file").expect("recorded call");
    assert_eq!(call.arg_str("format").as_deref(), Some("csv"));
    let ids: Vec<_> = call
        .args
        .get("rows")
        .and_then(|v| v.as_array())
        .expect("a rows array")
        .iter()
        .map(|r| r.get("id").and_then(|n| n.as_str()))
        .collect();
    assert_eq!(ids, [Some("mi-2")]);
}

/// Cross-tenant leakage, the repo's #1 footgun. This view stays mounted across
/// a tenant switch, and its export snapshot used to outlive the rows it came
/// from: tenant B has no managed identities, so the loaded list never mounts
/// to replace it, and "Export as CSV…" saved tenant A's identities.
#[wasm_bindgen_test]
async fn export_after_a_tenant_switch_never_saves_the_previous_tenants_rows() {
    ts::reset();
    ipc_mock::mock_each("list_managed_identities", |args| {
        if args.get("tenantId").and_then(|t| t.as_str()) == Some("test-tenant") {
            fixtures::managed_identities(&["mi-prod-api", "mi-staging-worker"])
        } else {
            Vec::new()
        }
    });
    ts::mock_ok("save_managed_identities_to_file", &Option::<String>::None);

    let m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });
    ts::wait_for(|| ts::query_all(".app-list__row").len() == 2).await;

    let mut other = ts::test_tenant();
    other.tenant_id = "other-tenant".into();
    m.session.set_active_tenant(Some(other));
    ts::wait_for(|| ts::body_contains("No managed identities yet")).await;

    ts::click_button_labelled("Export");
    ts::wait_for(|| !ts::query_all("[role=\"menuitem\"]").is_empty()).await;
    ts::click_button_labelled("Export as CSV…");
    for _ in 0..5 {
        ts::tick().await;
    }
    assert_eq!(
        ts::call_count("save_managed_identities_to_file"),
        0,
        "the export saved the previous tenant's identities"
    );
}
