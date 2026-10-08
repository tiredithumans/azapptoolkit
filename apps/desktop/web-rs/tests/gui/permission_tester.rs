//! GUI tests for the Permission tester: the seeded identity and the
//! SharePoint grants table (F094).
//!
//! A "Test access…" affordance seeds `tenant_ui.tester_app_id` and navigates
//! here. The view is keep-alive, so the seed is consumed by an Effect rather
//! than at mount — and consumed ONCE, so a later visit can't clobber an
//! identity the operator typed by hand.
//!
//! The table tests drive the probe flow (seed → SharePoint tab → URL → "Test
//! access") and pin the revoke path: a confirm, one `remove_selected_item_permission`
//! call against the *tested* URL, then a re-probe that re-reads verdict and
//! entries together.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::state::use_session;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::permission_tester_view::PermissionTesterView;

const GUID: &str = "11111111-2222-3333-4444-555555555555";
const PICKER: &str = ".tester-picker input";

fn picker_value() -> String {
    ts::query(PICKER)
        .expect("picker input")
        .dyn_into::<web_sys::HtmlInputElement>()
        .expect("input element")
        .value()
}

/// The keep-alive path: the view is already mounted when the seed arrives.
#[wasm_bindgen_test]
async fn seeded_app_id_fills_picker_once() {
    ts::reset();
    ts::mock_ok("global_search", &fixtures::global_search_apps(&[]));

    let m = ts::mount_view(|| view! { <PermissionTesterView /> });
    ts::tick().await;

    m.session.open_permission_tester_for(GUID.into());
    ts::tick().await;

    assert_eq!(picker_value(), GUID);
    assert_eq!(
        m.session.tenant_ui.tester_app_id.get_untracked(),
        None,
        "the seed is consumed"
    );

    // A manual edit afterwards survives: the one-shot does not re-fire.
    ts::set_input_value(PICKER, "manual");
    ts::tick().await;
    assert_eq!(picker_value(), "manual");
}

/// The first-mount path: the seed is set before the view mounts, so the
/// tenant-reset Effect and the seed Effect run in the same tick — the seed
/// must win.
#[wasm_bindgen_test]
async fn a_seed_set_before_first_mount_survives_the_tenant_reset() {
    ts::reset();
    ts::mock_ok("global_search", &fixtures::global_search_apps(&[]));

    let m = ts::mount_view(|| {
        use_session()
            .tenant_ui
            .tester_app_id
            .set(Some(GUID.to_string()));
        view! { <PermissionTesterView /> }
    });
    ts::tick().await;

    assert_eq!(picker_value(), GUID);
    assert_eq!(m.session.tenant_ui.tester_app_id.get_untracked(), None);
}

/// The picker's listbox holds only options: the empty-result text is in a
/// sibling `role="status"` region, so a screen reader never announces it as if
/// it were an identity to pick.
#[wasm_bindgen_test]
async fn the_picker_says_no_match_outside_its_listbox() {
    ts::reset();
    ts::mock_ok("global_search", &fixtures::global_search_apps(&[]));

    let _m = ts::mount_view(|| view! { <PermissionTesterView /> });
    // Let the mount-time tenant reset run first, or it clears the query.
    ts::tick().await;
    ts::focus(PICKER);
    ts::set_input_value(PICKER, "zqx");

    let status = || {
        ts::query(".tester-picker__results [role=status]")
            .and_then(|e| e.text_content())
            .unwrap_or_default()
    };
    ts::wait_for(|| status().contains("No matching identities.")).await;
    let listbox = ts::query("#tester-listbox").expect("the listbox renders while open");
    assert!(
        !listbox
            .text_content()
            .unwrap_or_default()
            .contains("No matching identities.")
    );
    assert_eq!(listbox.children().length(), 0);
}

const URL: &str = "https://contoso.sharepoint.com/sites/Finance/Shared Documents/Invoices";
const URL_INPUT: &str = "input[placeholder^='https://']";

/// Mount the tester, seed the identity, switch to the SharePoint tab, type the
/// resource URL and fire the probe. Callers `ts::reset()` and register their
/// mocks *before* calling this — the mocked commands must be in the bridge
/// before the first invoke reaches it.
async fn mount_and_probe() -> ts::Mounted {
    ts::mock_ok("global_search", &fixtures::global_search_apps(&[]));
    let m = ts::mount_view(|| view! { <PermissionTesterView /> });
    ts::tick().await;
    m.session.open_permission_tester_for(GUID.into());
    ts::tick().await;
    ts::click_button_labelled("SharePoint resource");
    // The tab swap is a reactive DOM write — without a tick the SharePoint URL
    // input is not yet rendered and `set_input_value` below no-ops silently.
    ts::tick().await;
    ts::set_input_value(URL_INPUT, URL);
    ts::tick().await;
    ts::click_button_labelled("Test access");
    m
}

/// The rows rendered under the last probe (0 = the section is not on screen).
fn grant_rows() -> usize {
    ts::query_all(".permission-tester__grants tbody tr").len()
}

fn revoke_buttons() -> usize {
    ts::query_all(".permission-tester__grants tbody button")
        .into_iter()
        .filter(|b| b.text_content().unwrap_or_default().trim() == "Revoke")
        .count()
}

/// F094: the probe's own resource lists its Selected entries underneath the
/// verdict, and a revocable entry is one of the four shapes the tester must
/// distinguish — app grants get a Revoke, user/group sharing never does (that
/// would cut a person's access), and the call goes to the *tested* URL with
/// the entry id. A successful revoke re-probes (verdict + table together)
/// rather than optimistically dropping the row.
#[wasm_bindgen_test]
async fn revoke_targets_the_tested_url_and_reruns_the_probe() {
    ts::reset();
    ts::mock_ok(
        "test_site_access",
        &serde_json::json!({
            "has_access": true,
            "verdict": "scoped",
            "roles": ["Write"],
            "detail": "Scoped via a Selected grant on this resource.",
            "resource_label": "Finance / Invoices",
        }),
    );
    ts::mock_ok(
        "list_selected_item_permissions",
        &serde_json::json!([
            {
                "id": "perm-1",
                "roles": ["Write"],
                "app_id": "99999999-8888-7777-6666-555555555555",
                "app_display_name": "Contoso Sync",
            },
            {
                "id": "perm-2", "roles": ["Read"], "app_id": null, "app_display_name": null,
                "principals": [{ "kind": "site_group", "id": "10",
                                 "display_name": "Finance Members", "detail": null }],
            },
            {
                "id": "perm-3", "roles": ["Write"], "app_id": null, "app_display_name": null,
                "principals": [{ "kind": "user", "id": "u-1",
                                 "display_name": "Jane Doe", "detail": "jane@contoso.com" }],
            },
        ]),
    );
    ts::mock_ok("remove_selected_item_permission", &serde_json::json!(null));
    let _m = mount_and_probe().await;

    ts::wait_for(|| grant_rows() == 3).await;
    assert!(ts::body_contains("Contoso Sync"));
    // Who each non-app entry is, by name, instead of "user or group".
    assert!(ts::body_contains("SharePoint group · Finance Members"));
    assert!(ts::body_contains("User · Jane Doe"));
    assert!(ts::body_contains("jane@contoso.com"));
    assert_eq!(
        revoke_buttons(),
        1,
        "only the app-grant row offers a Revoke"
    );

    // The row button opens the confirm; the dialog's own confirm shares the
    // "Revoke" text, so it must be clicked through the modal scope.
    ts::click_button_labelled_in(".permission-tester__grants", "Revoke");
    ts::wait_for(|| ts::query(".modal").is_some()).await;
    ts::click_button_labelled_in(".modal", "Revoke");

    ts::wait_for(|| ts::call_count("remove_selected_item_permission") == 1).await;
    let call = ts::last_call("remove_selected_item_permission").expect("revoke was called");
    assert_eq!(call.arg_str("url").as_deref(), Some(URL));
    assert_eq!(call.arg_str("permissionId").as_deref(), Some("perm-1"));

    // Fresh verdict + fresh table: the re-probe is the proof the revoke
    // landed, not a row deleted client-side.
    ts::wait_for(|| {
        ts::call_count("test_site_access") == 2
            && ts::call_count("list_selected_item_permissions") == 2
    })
    .await;
    ts::wait_for(|| ts::query(".modal").is_none()).await;
}

/// An empty list must stay a "no grants ON this resource" statement: both
/// sentences that keep it from reading as "no item-level access anywhere" are
/// on screen, and with no app grants there is nothing to revoke.
#[wasm_bindgen_test]
async fn an_empty_list_still_says_what_it_does_not_prove() {
    ts::reset();
    ts::mock_ok(
        "test_site_access",
        &serde_json::json!({
            "has_access": false,
            "verdict": "no_access",
            "roles": [],
            "detail": "No grant covers this resource.",
            "resource_label": "Finance / Invoices",
        }),
    );
    ts::mock_ok("list_selected_item_permissions", &Vec::<String>::new());
    let _m = mount_and_probe().await;

    ts::wait_for(|| ts::body_contains("No app grants on this resource")).await;
    assert!(ts::body_contains(
        "This is not proof the app has no item-level access"
    ));
    assert!(ts::body_contains(
        "never that the app has no item-level access"
    ));
    assert_eq!(revoke_buttons(), 0);
}

/// A failed entry read must NOT render as an empty list — the table appears
/// only on a read that answered. The verdict above stays (it is complete);
/// the failed read surfaces as its own error line.
#[wasm_bindgen_test]
async fn a_failed_entry_read_never_renders_as_no_grants() {
    ts::reset();
    ts::mock_ok(
        "test_site_access",
        &serde_json::json!({
            "has_access": true,
            "verdict": "scoped",
            "roles": ["Write"],
            "detail": "Scoped via a Selected grant on this resource.",
            "resource_label": "Finance / Invoices",
        }),
    );
    ts::mock_err(
        "list_selected_item_permissions",
        &fixtures::ui_error("graph_error", "SharePoint request failed: 400"),
    );
    let _m = mount_and_probe().await;

    ts::wait_for(|| ts::body_contains("could not be read")).await;
    assert!(
        ts::body_contains("Has access — scoped"),
        "the verdict stands"
    );
    assert!(
        !ts::body_contains("Selected item permissions on this resource"),
        "an unread resource must not render as 'no grants'"
    );
}

/// The seeded appId resolves to the identity's display name: the debounced
/// search for it returns the exact hit, and the field shows the name rather
/// than a bare GUID (the tested appId is unchanged).
#[wasm_bindgen_test]
async fn a_seeded_app_id_is_shown_by_display_name() {
    ts::reset();
    // `global_search_apps` keys its first hit as appId "app-0".
    ts::mock_ok(
        "global_search",
        &fixtures::global_search_apps(&["Contoso Mailer"]),
    );

    let m = ts::mount_view(|| view! { <PermissionTesterView /> });
    ts::tick().await;

    m.session.open_permission_tester_for("app-0".into());
    ts::wait_for(|| picker_value() == "Contoso Mailer").await;
    assert!(
        ts::body_contains("app-0"),
        "the selected appId is still shown"
    );
}
