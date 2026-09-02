//! GUI test for the post-sweep confirmation on the Credentials tab.
//!
//! "Remove N expired" and the Key Vault rotation both mutate, then reload the
//! application detail — and that reload re-runs the resource the whole tab is
//! rendered from, unmounting it. A confirmation parked in a signal that lives
//! inside the tab is therefore destroyed on the same tick it is created: the
//! operator sees the row vanish and is never told what happened, or whether
//! part of it failed. The confirmation has to outlive the subtree, which is
//! what the session toast stack is for.
#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use azapptoolkit_core::models::PasswordCredential;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::applications::{KeyFailure, RemoveExpiredResult};
use azapptoolkit_web_rs::components::toast::ToastHost;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::tabs::credentials_tab::CredentialsTab;

/// Clicks the first button whose trimmed text matches exactly.
fn click_button(label: &str) {
    for el in ts::query_all("button") {
        if el.text_content().unwrap_or_default().trim() == label {
            let el: web_sys::HtmlElement = el.unchecked_into();
            el.click();
            return;
        }
    }
    let seen: Vec<String> = ts::query_all("button")
        .iter()
        .map(|e| e.text_content().unwrap_or_default().trim().to_string())
        .collect();
    panic!("no button labelled `{label}`; saw {seen:?}");
}

fn expired_secret(key_id: &str) -> PasswordCredential {
    PasswordCredential {
        key_id: key_id.to_string(),
        display_name: Some(key_id.to_string()),
        end_date_time: Some(chrono::Utc::now() - chrono::Duration::days(30)),
        ..Default::default()
    }
}

/// Mounts the tab next to a real `ToastHost`, with an `on_changed` that stands
/// in for the detail pane's `bump_reload`: the callback the pane passes tears
/// this subtree down, so anything the tab kept locally is gone by the time the
/// operator looks. Only state held outside it — the toast stack — survives.
fn mount_with_toasts(secrets: Vec<PasswordCredential>) -> ts::Mounted {
    let mut d = fixtures::application_detail("obj-1", "app-1", "Contoso CRM");
    d.application.password_credentials = secrets;
    let detail = Arc::new(d);
    ts::mount_view(move || {
        let detail = detail.clone();
        let detail = Signal::derive(move || detail.clone());
        view! {
            <ToastHost />
            <CredentialsTab detail=detail on_changed=Callback::new(|()| {}) />
        }
    })
}

/// A completed sweep must say so somewhere that outlives the reload.
#[wasm_bindgen_test]
async fn a_completed_sweep_confirms_itself_outside_the_reloaded_subtree() {
    ts::reset();
    ts::mock_ok(
        "remove_expired_passwords",
        &RemoveExpiredResult {
            removed_key_ids: vec!["key-1".to_string(), "key-2".to_string()],
            failures: Vec::new(),
        },
    );
    let _m = mount_with_toasts(vec![expired_secret("key-1"), expired_secret("key-2")]);

    ts::wait_for(|| ts::body_contains("Remove 2 expired")).await;
    click_button("Remove 2 expired");
    ts::wait_for(|| ts::body_contains("Remove all expired secrets?")).await;
    // The modal covers the tab it was opened from, and the workspace can have
    // several app windows open behind it — so "this application" has to be a
    // name, not a pronoun.
    assert_eq!(
        ts::query(".confirm-dialog__subject")
            .and_then(|el| el.text_content())
            .as_deref(),
        Some("Contoso CRM"),
    );
    click_button("Remove expired");
    ts::wait_for(|| ts::call_count("remove_expired_passwords") == 1).await;

    // In the toast stack, which the shell mounts above the detail pane — not in
    // the tab, which the reload replaces.
    ts::wait_for(|| ts::query(".toast").is_some()).await;
    assert!(
        ts::text(".toast").contains("Removed 2 expired secret(s)"),
        "the sweep must report what it removed, got {:?}",
        ts::text(".toast"),
    );
}

/// A PARTIAL sweep must not read as a clean one.
///
/// Some secrets removed and some refused is the case the operator most needs to
/// see, and the one a vanishing confirmation hides best: the list comes back
/// shorter, so the sweep looks like it worked.
#[wasm_bindgen_test]
async fn a_partial_sweep_says_that_some_secrets_survived() {
    ts::reset();
    ts::mock_ok(
        "remove_expired_passwords",
        &RemoveExpiredResult {
            removed_key_ids: vec!["key-1".to_string()],
            failures: vec![KeyFailure {
                key_id: "key-2".to_string(),
                message: "Insufficient privileges.".to_string(),
            }],
        },
    );
    let _m = mount_with_toasts(vec![expired_secret("key-1"), expired_secret("key-2")]);

    ts::wait_for(|| ts::body_contains("Remove 2 expired")).await;
    click_button("Remove 2 expired");
    ts::wait_for(|| ts::body_contains("Remove all expired secrets?")).await;
    click_button("Remove expired");
    ts::wait_for(|| ts::call_count("remove_expired_passwords") == 1).await;

    ts::wait_for(|| ts::query(".toast").is_some()).await;
    let toast = ts::text(".toast");
    assert!(
        toast.contains("Removed 1 expired secret(s)") && toast.contains("1 could not be removed"),
        "a partial sweep must name the part that failed, got {toast:?}"
    );
    // Error-toned, so it lingers longer than a routine success.
    assert!(
        ts::query(".toast--error").is_some(),
        "a partial failure must not be styled as a clean success"
    );
}
