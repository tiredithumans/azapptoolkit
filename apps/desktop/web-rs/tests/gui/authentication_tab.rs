//! GUI tests for the Authentication tab's per-row redirect-URI editor.
//!
//! Mounts `AuthenticationTab` directly rather than clicking through
//! `ApplicationDetailPane`: the pane resolves its initial tab during setup, so
//! driving it to a non-default tab from a test needs machinery this behaviour
//! doesn't warrant. The tab owns its own load, so it stands alone.
#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::tabs::authentication_tab::AuthenticationTab;

const WEB_ROWS: &str = ".uri-list--web .uri-list__row";
const WEB_INPUTS: &str = ".uri-list--web .uri-list__row input";

fn mount(web: &[&str], spa: &[&str]) -> ts::Mounted {
    ts::mock_ok(
        "get_application_authentication",
        &fixtures::application_authentication(web, spa, &[]),
    );
    ts::mock_ok("set_application_authentication", &());
    let detail = Arc::new(fixtures::application_detail(
        "obj-1",
        "app-1",
        "Contoso CRM",
    ));
    ts::mount_view(move || {
        let d = detail.clone();
        view! {
            <AuthenticationTab
                detail=Signal::derive(move || d.clone())
                on_changed=Callback::new(|_| ())
            />
        }
    })
}

/// Input *values* — `body_contains` cannot see them.
fn values(selector: &str) -> Vec<String> {
    ts::query_all(selector)
        .into_iter()
        .filter_map(|e| e.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|i| i.value())
        .collect()
}

/// Click the first `<button>` whose visible text is exactly `label`. The three
/// lists deliberately spell their Add buttons out in full, so this is
/// unambiguous.
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

/// True when the focused element matches `selector`.
fn focused_matches(selector: &str) -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.active_element())
        .is_some_and(|el| el.matches(selector).unwrap_or(false))
}

#[wasm_bindgen_test]
async fn renders_one_row_per_uri_and_counts_them() {
    ts::reset();
    let _m = mount(
        &[
            "https://a.contoso.com/cb",
            "https://b.contoso.com/cb",
            "https://c.contoso.com/cb",
        ],
        &[],
    );

    ts::wait_for(|| ts::query_all(WEB_ROWS).len() == 3).await;
    assert_eq!(
        values(WEB_INPUTS),
        [
            "https://a.contoso.com/cb",
            "https://b.contoso.com/cb",
            "https://c.contoso.com/cb"
        ]
    );
    // The count rides in the section title, matching "Secrets (2)" on the
    // sibling tabs.
    assert_eq!(
        ts::text(".uri-list--web .uri-list__label"),
        "Web redirect URIs (3)"
    );
    // An empty platform keeps exactly one blank row, so there is always
    // somewhere to type or paste.
    assert_eq!(ts::query_all(".uri-list--spa .uri-list__row").len(), 1);
    assert_eq!(
        ts::text(".uri-list--spa .uri-list__label"),
        "Single-page application (SPA) redirect URIs (0)"
    );

    let call = ts::last_call("get_application_authentication").unwrap();
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    assert_eq!(call.arg_str("objectId").as_deref(), Some("obj-1"));
}

#[wasm_bindgen_test]
async fn add_focuses_the_new_row_and_remove_drops_only_that_row() {
    ts::reset();
    let _m = mount(&["https://a/cb", "https://b/cb", "https://c/cb"], &[]);
    ts::wait_for(|| ts::query_all(WEB_ROWS).len() == 3).await;

    click_button("Add web redirect URI");
    ts::wait_for(|| ts::query_all(WEB_ROWS).len() == 4).await;
    // The new row takes focus, so typing can start immediately.
    ts::wait_for(|| focused_matches(".uri-list--web .uri-list__row:nth-child(4) input")).await;

    // Remove the middle row. A positional key would have shifted the values.
    ts::click(
        ".uri-list--web .uri-list__row:nth-child(2) button[aria-label=\"Remove web redirect URI\"]",
    );
    ts::wait_for(|| values(WEB_INPUTS) == ["https://a/cb", "https://c/cb", ""]).await;
    assert_eq!(
        ts::text(".uri-list--web .uri-list__status"),
        "Removed. 3 web redirect URIs left."
    );
}

#[wasm_bindgen_test]
async fn a_rejected_uri_marks_its_own_row_without_blocking_save() {
    ts::reset();
    let _m = mount(&["https://ok.contoso.com/cb", "https://b/cb"], &[]);
    ts::wait_for(|| ts::query_all(WEB_ROWS).len() == 2).await;

    ts::set_input_value(
        ".uri-list--web .uri-list__row:nth-child(2) input",
        "https://*.contoso.com/auth",
    );
    // The reason is the backend's, with the echoed URI stripped — the row is
    // the pointer.
    ts::wait_for(|| ts::body_contains("wildcard redirect URIs are not allowed")).await;
    assert!(!ts::body_contains(
        "wildcard redirect URIs are not allowed: "
    ));
    assert_eq!(
        ts::query_all(".uri-list--web .uri-list__row--rejected").len(),
        1
    );
    assert_eq!(
        ts::query(".uri-list--web .uri-list__row:nth-child(2) input")
            .unwrap()
            .get_attribute("aria-invalid")
            .as_deref(),
        Some("true")
    );

    // Advisory only: Save still reaches the backend, which stays the authority.
    let save = ts::query(".actions-row button").unwrap();
    assert!(save.get_attribute("disabled").is_none());
    click_button("Save");
    ts::wait_for(|| ts::call_count("set_application_authentication") == 1).await;
}

#[wasm_bindgen_test]
async fn save_sends_one_entry_per_row_trimmed_with_blanks_dropped() {
    ts::reset();
    let _m = mount(&["https://a/cb"], &["https://spa.contoso.com/"]);
    ts::wait_for(|| ts::query_all(WEB_ROWS).len() == 1).await;

    click_button("Add web redirect URI");
    ts::wait_for(|| ts::query_all(WEB_ROWS).len() == 2).await;
    ts::set_input_value(
        ".uri-list--web .uri-list__row:nth-child(2) input",
        "  https://b/cb?x=1,2;3  ",
    );
    click_button("Add web redirect URI"); // left blank on purpose
    ts::wait_for(|| ts::query_all(WEB_ROWS).len() == 3).await;

    click_button("Save");
    ts::wait_for(|| ts::call_count("set_application_authentication") == 1).await;
    let input = ts::last_call("set_application_authentication")
        .unwrap()
        .args["input"]
        .clone();
    // Trimmed, blank dropped, and the comma/semicolon NOT split into extras.
    assert_eq!(
        input["webRedirectUris"],
        serde_json::json!(["https://a/cb", "https://b/cb?x=1,2;3"])
    );
    assert_eq!(
        input["spaRedirectUris"],
        serde_json::json!(["https://spa.contoso.com/"])
    );
    assert_eq!(input["publicClientRedirectUris"], serde_json::json!([]));
    // A successful save round-trips the full-replace read.
    ts::wait_for(|| ts::call_count("get_application_authentication") == 2).await;
}
