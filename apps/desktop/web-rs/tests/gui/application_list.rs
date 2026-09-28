//! GUI functionality tests for the App Registrations list — the anchor view
//! that proves the harness. These mount the *real* `ApplicationList` component
//! in a headless browser with the Tauri backend mocked (no tenant, no Graph),
//! and assert on what a user would see and do: rows render, the filter narrows
//! them, the error/empty states show, and the Refresh button fires the right
//! command.
//!
//! `#![cfg(target_arch = "wasm32")]` keeps these out of the host `just web-test`
//! run (they only execute under `just web-itest` via wasm-bindgen-test in a
//! browser). Build/run requires the `test-support` feature.
#![cfg(target_arch = "wasm32")]

use azapptoolkit_core::audit::ListCredentialStatus;
use chrono::{Duration, Utc};
use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::ipc_mock;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::application_list::ApplicationList;

/// The text input the list filters on (the only non-checkbox input in the pane;
/// row + select-all controls are checkboxes).
const SEARCH: &str = ".app-list input:not([type=checkbox])";
/// Result-count line from `SelectAllBar` — reflects the filtered total
/// independent of row virtualization, so it's the robust assertion target.
const COUNT: &str = ".app-list__count";

#[wasm_bindgen_test]
async fn loads_and_renders_rows() {
    ts::reset();
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Contoso CRM", "Fabrikam API", "Northwind Portal"]),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });

    ts::wait_for(|| ts::text(COUNT) == "3 app registrations").await;
    assert_eq!(ts::query_all(".app-list__row").len(), 3);
}

#[wasm_bindgen_test]
async fn search_narrows_rows() {
    ts::reset();
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Contoso CRM", "Fabrikam API", "Northwind Portal"]),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "3 app registrations").await;

    // Typing is debounced (~300ms) then applied in memory; wait_for polls past it.
    ts::set_input_value(SEARCH, "contoso");
    ts::wait_for(|| ts::text(COUNT) == "1 of 3 app registrations").await;
    assert_eq!(ts::query_all(".app-list__row").len(), 1);
}

/// SCL-01: an operator pastes the appId out of a sign-in log or a ticket. The
/// list printed that id on every row while matching only the display name.
#[wasm_bindgen_test]
async fn search_matches_the_app_id() {
    ts::reset();
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Contoso CRM", "Fabrikam API", "Northwind Portal"]),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "3 app registrations").await;

    // `fixtures::app_row` derives the appId from the object id (`obj-1-appid`).
    ts::set_input_value(SEARCH, "obj-1-appid");
    ts::wait_for(|| ts::text(COUNT) == "1 of 3 app registrations").await;
    assert_eq!(ts::query_all(".app-list__row").len(), 1);
}

/// SCL-02: the credential state the list already filters on now reaches the row.
#[wasm_bindgen_test]
async fn rows_show_credential_state_and_expiry() {
    ts::reset();
    let mut rows = fixtures::apps(&["Expiring App"]);
    rows[0].credential_status = ListCredentialStatus::Expiring;
    // Plus an hour so the render's own `Utc::now()`, taken a few ms later,
    // still truncates to 9 whole days rather than 8.
    rows[0].soonest_credential_expiry = Some(Utc::now() + Duration::days(9) + Duration::hours(1));
    ts::mock_ok("list_applications_with_pairing", &rows);

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::query(".app-list__row").is_some()).await;

    assert_eq!(ts::text(".app-list__row .badge"), "Expiring");
    assert_eq!(ts::text(".app-list__row-expiry"), "9d left");
}

/// SCL-02: rows arrive in whatever order Graph returned; the sort is applied
/// between the filtered set and the virtualized window.
#[wasm_bindgen_test]
async fn sorting_by_name_reorders_the_rows() {
    ts::reset();
    // Deliberately a fixture whose Graph order heads with neither the A→Z nor
    // the Z→A row, so all three steps of the cycle are distinguishable.
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Mike", "Alpha", "Zulu"]),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "3 app registrations").await;
    assert_eq!(ts::text(".app-list__row-title"), "Mike");

    // The toggle's state is a real `"true"`/`"false"` string, never a boolean
    // attribute (`aria-pressed=""` / absent).
    let pressed =
        || ts::query(".app-list__sortbar button").and_then(|b| b.get_attribute("aria-pressed"));
    assert_eq!(pressed().as_deref(), Some("false"));

    // Name: A→Z, then reversed, then back to the order Graph returned.
    ts::click(".app-list__sortbar button");
    ts::wait_for(|| ts::text(".app-list__row-title") == "Alpha").await;
    assert_eq!(pressed().as_deref(), Some("true"));
    ts::click(".app-list__sortbar button");
    ts::wait_for(|| ts::text(".app-list__row-title") == "Zulu").await;
    assert_eq!(pressed().as_deref(), Some("true"));
    ts::click(".app-list__sortbar button");
    ts::wait_for(|| ts::text(".app-list__row-title") == "Mike").await;
    assert_eq!(pressed().as_deref(), Some("false"));
    assert_eq!(ts::query_all(".app-list__row").len(), 3);
}

/// A11Y-06: the pairing arrow is a SIBLING of the row button, not a button
/// nested inside one — which is invalid HTML and put the arrow's label in the
/// middle of the row's accessible name.
#[wasm_bindgen_test]
async fn the_pair_arrow_is_not_nested_in_the_row_button() {
    ts::reset();
    let mut rows = fixtures::apps(&["Paired App"]);
    rows[0].paired_service_principal_id = Some("sp-0".to_string());
    ts::mock_ok("list_applications_with_pairing", &rows);

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::query(".pair-arrow").is_some()).await;

    assert!(ts::query(".app-list__row-btn .pair-arrow").is_none());
    assert!(ts::query(".app-list__row > .pair-arrow").is_some());
}

/// A11Y-02: crossing the inventory by Tab alone costs ~2 presses per row. The
/// rendered window carries a roving tabindex and Arrow/Home/End move it.
#[wasm_bindgen_test]
async fn arrow_keys_move_focus_between_rows() {
    ts::reset();
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["First App", "Second App", "Third App"]),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "3 app registrations").await;
    // Exactly one row is in the tab order at a time (the roving tabindex).
    ts::wait_for(|| ts::query_all(".app-list__row[tabindex='0']").len() == 1).await;

    // The tab stop rides along with focus, so it is what the move is read from.
    ts::focus(".app-list__row");
    ts::press_key(".app-list__row", "ArrowDown");
    assert!(ts::text(".app-list__row[tabindex='0']").contains("Second App"));
    ts::press_key(".app-list__row[tabindex='0']", "ArrowUp");
    assert!(ts::text(".app-list__row[tabindex='0']").contains("First App"));
}

#[wasm_bindgen_test]
async fn error_state_renders_message() {
    ts::reset();
    ts::mock_err(
        "list_applications_with_pairing",
        &fixtures::ui_error(
            "consent_required",
            "Admin consent is required for Microsoft Graph",
        ),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });

    ts::wait_for(|| ts::query(".app-list__error").is_some()).await;
    assert!(ts::text(".app-list__error").contains("Admin consent is required"));
}

#[wasm_bindgen_test]
async fn empty_tenant_shows_create_cta() {
    ts::reset();
    ts::mock_ok("list_applications_with_pairing", &fixtures::no_apps());

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });

    ts::wait_for(|| ts::text(COUNT) == "0 app registrations").await;
    assert_eq!(ts::query_all(".app-list__row").len(), 0);
    // A genuinely empty tenant gets an onboarding CTA, not the "adjust your
    // filters" copy meant for a filtered-empty list.
    ts::wait_for(|| ts::query(".ui-empty__title").is_some()).await;
    assert_eq!(ts::text(".ui-empty__title"), "No app registrations yet");
    assert!(ts::text(".ui-empty").contains("New app"));
}

#[wasm_bindgen_test]
async fn refresh_invokes_invalidate_list_cache() {
    ts::reset();
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Solo App"]),
    );
    ts::mock_ok("invalidate_list_cache", &()); // command returns ()

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "1 app registrations").await;

    ts::click("button[aria-label=\"Refresh App Registrations\"]");

    ts::wait_for(|| ts::call_count("invalidate_list_cache") >= 1).await;
    let call = ts::last_call("invalidate_list_cache").expect("recorded call");
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    // The per-page Refresh scopes invalidation to this list's kind only.
    assert_eq!(call.arg_str("kind").as_deref(), Some("apps"));
}

/// Refresh refetches only once the backend has dropped its cached list. The
/// backend's cache-hit path is synchronous, so a refetch started before the
/// invalidation lands re-serves the very list Refresh meant to drop. The mock
/// plays that cache: it serves the old rows until the invalidation arrives.
#[wasm_bindgen_test]
async fn refresh_refetches_only_after_the_cache_is_dropped() {
    ts::reset();
    ipc_mock::mock_each("list_applications_with_pairing", |_| {
        if ts::call_count("invalidate_list_cache") == 0 {
            fixtures::apps(&["Before Refresh"])
        } else {
            fixtures::apps(&["After Refresh"])
        }
    });
    ts::mock_ok("invalidate_list_cache", &());

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::body_contains("Before Refresh")).await;

    ts::click("button[aria-label=\"Refresh App Registrations\"]");

    ts::wait_for(|| ts::body_contains("After Refresh")).await;
    let call = ts::last_call("invalidate_list_cache").expect("recorded call");
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    assert_eq!(call.arg_str("kind").as_deref(), Some("apps"));
}

/// A reload (delete, remove-expired, "Fix", Refresh) remounts the loaded list
/// body — its `<Suspense>` re-runs — and used to throw the operator back to the
/// first row of a long list. The offset now lives on `tenant_ui` and is
/// replayed into the fresh scroller; a search still snaps to the top.
#[wasm_bindgen_test]
async fn refetch_keeps_the_scroll_position() {
    use wasm_bindgen::JsCast;

    ts::reset();
    let names: Vec<String> = (0..200).map(|i| format!("App {i:03}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    ts::mock_ok("list_applications_with_pairing", &fixtures::apps(&names));

    // GUI tests load no `styles.css`: give the scroller a real viewport and the
    // rows their absolute positioning (ROW_HEIGHT is 52px).
    let m = ts::mount_view(|| {
        view! {
            <style>
                {".app-list__scroller{height:260px;overflow:auto;position:relative}\
                  .app-list__sizer{position:relative}\
                  .app-list__row{position:absolute;left:0;width:100%}"}
            </style>
            <ApplicationList />
        }
    });
    ts::wait_for(|| ts::text(COUNT) == "200 app registrations").await;

    let scroller = || -> web_sys::HtmlElement {
        ts::query(".app-list__scroller")
            .expect("the list scroller")
            .unchecked_into()
    };
    let el = scroller();
    el.set_scroll_top(5200);
    let _ = el.dispatch_event(&web_sys::Event::new("scroll").unwrap());
    ts::wait_for(|| m.session.tenant_ui.apps_scroll_top.get_untracked() >= 5000.0).await;

    m.session.bump_apps_reload();
    ts::wait_for(|| ts::call_count("list_applications_with_pairing") >= 2).await;
    // A new scroller element, landed back at the operator's row.
    ts::wait_for(|| {
        ts::query(".app-list__scroller")
            .map(|el| el.unchecked_into::<web_sys::HtmlElement>().scroll_top() >= 5000)
            .unwrap_or(false)
            && ts::body_contains("App 100")
    })
    .await;

    // A new row set within the instance still starts at the top.
    ts::set_input_value(SEARCH, "App 1");
    ts::wait_for(|| m.session.tenant_ui.apps_scroll_top.get_untracked() == 0.0).await;
}

/// A search that matches nothing unmounts the list (the empty state replaces
/// it) before the list's own snap-to-top can run. The carried offset must still
/// reset, or the next non-empty result would reopen at the old row set's
/// position instead of the top.
#[wasm_bindgen_test]
async fn an_empty_search_does_not_carry_the_offset_into_the_next_result() {
    use wasm_bindgen::JsCast;

    ts::reset();
    let names: Vec<String> = (0..200).map(|i| format!("App {i:03}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    ts::mock_ok("list_applications_with_pairing", &fixtures::apps(&names));

    let m = ts::mount_view(|| {
        view! {
            <style>
                {".app-list__scroller{height:260px;overflow:auto;position:relative}\
                  .app-list__sizer{position:relative}\
                  .app-list__row{position:absolute;left:0;width:100%}"}
            </style>
            <ApplicationList />
        }
    });
    ts::wait_for(|| ts::text(COUNT) == "200 app registrations").await;

    let el: web_sys::HtmlElement = ts::query(".app-list__scroller")
        .expect("the list scroller")
        .unchecked_into();
    el.set_scroll_top(5200);
    let _ = el.dispatch_event(&web_sys::Event::new("scroll").unwrap());
    ts::wait_for(|| m.session.tenant_ui.apps_scroll_top.get_untracked() >= 5000.0).await;

    ts::set_input_value(SEARCH, "no such app");
    ts::wait_for(|| ts::body_contains("No matching apps")).await;
    ts::wait_for(|| m.session.tenant_ui.apps_scroll_top.get_untracked() == 0.0).await;

    // 100 rows (5200px) under a 260px viewport: a stale 5200 would clamp to a
    // non-zero offset here, so a zero really is "started at the top".
    ts::set_input_value(SEARCH, "App 0");
    ts::wait_for(|| ts::text(COUNT) == "100 of 200 app registrations").await;
    ts::wait_for(|| ts::body_contains("App 000")).await;
    // Give a (wrong) replay from the mount effect / ResizeObserver its chance.
    for _ in 0..10 {
        ts::tick().await;
    }
    let scroller: web_sys::HtmlElement = ts::query(".app-list__scroller")
        .expect("the list is back")
        .unchecked_into();
    assert_eq!(scroller.scroll_top(), 0, "the new result starts at the top");
    assert_eq!(m.session.tenant_ui.apps_scroll_top.get_untracked(), 0.0);
    assert!(ts::body_contains("App 000"));
}

/// Home's "With secrets" metric drills here (`open_apps_with_facet`): the list
/// lands filtered to apps holding a client secret, with the collapsed filter
/// drawer opened once by the destination-aware one-shot so the active chip is
/// visible.
#[wasm_bindgen_test]
async fn a_home_drill_lands_on_the_with_secrets_chip() {
    ts::reset();
    let mut with_secret = fixtures::app_row("app-1", "Payroll API");
    with_secret.password_credential_count = 1;
    let mut cert_only = fixtures::app_row("app-2", "HR Sync");
    cert_only.password_credential_count = 0;
    cert_only.key_credential_count = 1;
    ts::mock_ok(
        "list_applications_with_pairing",
        &vec![with_secret, cert_only],
    );

    let m = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "2 app registrations").await;
    assert!(
        ts::query(".filter-chips").is_none(),
        "drawer starts collapsed"
    );

    m.session.open_apps_with_facet("secrets");

    ts::wait_for(|| ts::query(".filter-chips").is_some()).await;
    ts::wait_for(|| ts::text(COUNT) == "1 of 2 app registrations").await;
    assert!(ts::body_contains("Payroll API"));
    assert!(!ts::body_contains("HR Sync"));
    assert!(ts::body_contains("With secrets"));
    assert_eq!(
        m.session.tenant_ui.pending_open_filters.get_untracked(),
        None
    );
    assert_eq!(m.session.tenant_ui.apps_facet.get_untracked(), "secrets");
}

/// The two date filters sat under a visible `<label>` that labelled nothing
/// (no `for`, no wrapping), so a screen reader announced two bare "date"
/// fields. Each carries its own name, in the order it renders; the saved-view
/// name box is named too, not left to its placeholder.
#[wasm_bindgen_test]
async fn filter_drawer_fields_have_accessible_names() {
    ts::reset();
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Contoso CRM"]),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "1 app registrations").await;

    if ts::query_all(".date-range-field__native").is_empty() {
        ts::click(".filter-toggle");
    }
    ts::wait_for(|| ts::query_all(".date-range-field__native").len() == 2).await;
    let names: Vec<String> = ts::query_all(".date-range-field__native")
        .iter()
        .map(|el| el.get_attribute("aria-label").unwrap_or_default())
        .collect();
    assert_eq!(names, ["Created before", "Created after"]);

    ts::click_button_labelled("+ Save view");
    ts::wait_for(|| ts::query(".saved-views__input").is_some()).await;
    assert!(
        ts::query("input.saved-views__input[aria-label=\"View name\"]").is_some(),
        "the saved-view name box needs a name beyond its placeholder"
    );
}

/// The filter chip whose visible label (not its count) reads `label`. Chip
/// `textContent` includes the count, so match the label child.
fn chip(label: &str) -> Option<web_sys::Element> {
    ts::query_all(".filter-chip").into_iter().find(|c| {
        c.query_selector(".filter-chip__label")
            .ok()
            .flatten()
            .and_then(|l| l.text_content())
            .is_some_and(|t| t.trim() == label)
    })
}

fn attr(el: Option<web_sys::Element>, name: &str) -> Option<String> {
    el.and_then(|e| e.get_attribute(name))
}

/// The Filters toggle says whether its drawer is open, and the facet chips say
/// which one is applied, as real `"true"`/`"false"` strings — the active chip
/// used to be marked by color alone, and a bare-bool binding renders
/// `aria-expanded=""` / nothing, which no screen reader reads as a state.
#[wasm_bindgen_test]
async fn filter_toggle_and_chips_expose_their_state() {
    use wasm_bindgen::JsCast;
    ts::reset();
    let mut with_secret = fixtures::app_row("app-1", "Payroll API");
    with_secret.password_credential_count = 1;
    let mut cert_only = fixtures::app_row("app-2", "HR Sync");
    cert_only.password_credential_count = 0;
    cert_only.key_credential_count = 1;
    ts::mock_ok(
        "list_applications_with_pairing",
        &vec![with_secret, cert_only],
    );

    let _m = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "2 app registrations").await;
    assert!(
        ts::query(".filter-chips").is_none(),
        "drawer starts collapsed"
    );
    assert_eq!(
        attr(ts::query(".filter-toggle"), "aria-expanded").as_deref(),
        Some("false")
    );

    ts::click(".filter-toggle");
    ts::wait_for(|| ts::query(".filter-chips").is_some()).await;
    assert_eq!(
        attr(ts::query(".filter-toggle"), "aria-expanded").as_deref(),
        Some("true")
    );

    assert_eq!(attr(chip("All"), "aria-pressed").as_deref(), Some("true"));
    assert_eq!(
        attr(chip("With secrets"), "aria-pressed").as_deref(),
        Some("false")
    );
    let chips = ts::query_all(".filter-chip");
    assert!(!chips.is_empty());
    for c in &chips {
        let state = c.get_attribute("aria-pressed");
        assert!(
            matches!(state.as_deref(), Some("true" | "false")),
            "every chip carries a string aria-pressed, got {state:?} on {:?}",
            c.text_content()
        );
    }

    chip("With secrets")
        .expect("With secrets chip")
        .unchecked_ref::<web_sys::HtmlElement>()
        .click();
    ts::wait_for(|| {
        attr(chip("With secrets"), "aria-pressed").as_deref() == Some("true")
            && attr(chip("All"), "aria-pressed").as_deref() == Some("false")
    })
    .await;
}
