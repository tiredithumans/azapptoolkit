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
use azapptoolkit_dto::keyvault::RotateCredentialResult;
use azapptoolkit_web_rs::components::toast::ToastHost;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::tabs::credentials_tab::CredentialsTab;

fn expired_secret(key_id: &str) -> PasswordCredential {
    PasswordCredential {
        key_id: key_id.to_string(),
        display_name: Some(key_id.to_string()),
        end_date_time: Some(chrono::Utc::now() - chrono::Duration::days(30)),
        ..Default::default()
    }
}

fn active_secret(key_id: &str) -> PasswordCredential {
    PasswordCredential {
        key_id: key_id.to_string(),
        display_name: Some(key_id.to_string()),
        end_date_time: Some(chrono::Utc::now() + chrono::Duration::days(90)),
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
    ts::click_button_labelled("Remove 2 expired");
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
    ts::click_button_labelled("Remove expired");
    ts::wait_for(|| ts::call_count("remove_expired_passwords") == 1).await;

    // In the toast stack, which the shell mounts above the detail pane — not in
    // the tab, which the reload replaces.
    ts::wait_for(|| ts::query(".toast").is_some()).await;
    assert!(
        ts::text(".toast").contains("Removed 2 expired secrets"),
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
                code: "forbidden".to_string(),
                message: "Insufficient privileges.".to_string(),
            }],
        },
    );
    let _m = mount_with_toasts(vec![expired_secret("key-1"), expired_secret("key-2")]);

    ts::wait_for(|| ts::body_contains("Remove 2 expired")).await;
    ts::click_button_labelled("Remove 2 expired");
    ts::wait_for(|| ts::body_contains("Remove all expired secrets?")).await;
    ts::click_button_labelled("Remove expired");
    ts::wait_for(|| ts::call_count("remove_expired_passwords") == 1).await;

    ts::wait_for(|| ts::query(".toast").is_some()).await;
    let toast = ts::text(".toast");
    assert!(
        toast.contains("Removed 1 expired secret;") && toast.contains("1 could not be removed"),
        "a partial sweep must name the part that failed, got {toast:?}"
    );
    // Error-toned, so it lingers longer than a routine success.
    assert!(
        ts::query(".toast--error").is_some(),
        "a partial failure must not be styled as a clean success"
    );
}

/// A sweep the backend stopped on a dead session (a re-auth-fatal failure
/// code) must offer the in-place Re-authenticate, not just a failure count the
/// operator can do nothing with.
#[wasm_bindgen_test]
async fn a_sweep_stopped_by_a_dead_session_offers_reauthentication() {
    ts::reset();
    ts::mock_ok(
        "remove_expired_passwords",
        &RemoveExpiredResult {
            removed_key_ids: vec!["key-1".to_string()],
            failures: vec![KeyFailure {
                key_id: "key-2".to_string(),
                code: "refresh_missing".to_string(),
                message: "Your sign-in has expired.".to_string(),
            }],
        },
    );
    let _m = mount_with_toasts(vec![expired_secret("key-1"), expired_secret("key-2")]);

    ts::wait_for(|| ts::body_contains("Remove 2 expired")).await;
    ts::click_button_labelled("Remove 2 expired");
    ts::wait_for(|| ts::body_contains("Remove all expired secrets?")).await;
    ts::click_button_labelled("Remove expired");
    ts::wait_for(|| ts::call_count("remove_expired_passwords") == 1).await;

    ts::wait_for(|| {
        ts::query_all(".toast").iter().any(|t| {
            t.text_content()
                .unwrap_or_default()
                .contains("Re-authenticate")
        })
    })
    .await;
}

/// Mocks what the rotate dialog reads on open (the tenant default vault and the
/// vault picker's discovery) plus a rotation that removed one of two secrets
/// and warned about the other.
fn mock_rotation() {
    ts::mock_ok(
        "get_tenant_defaults",
        &azapptoolkit_core::defaults::TenantDefaults {
            default_vault: Some("kv-contoso".into()),
            ..Default::default()
        },
    );
    ts::mock_ok("list_available_key_vaults", &Vec::<String>::new());
    ts::mock_ok(
        "rotate_app_credential",
        &RotateCredentialResult {
            new_key_id: "key-new".to_string(),
            vault_name: "kv-contoso".to_string(),
            secret_name: "secret-app-1".to_string(),
            expires: None,
            removed_key_ids: vec!["key-1".to_string()],
            warnings: vec!["failed to remove key-2: forbidden".to_string()],
        },
    );
}

/// Opens the rotate dialog, waits for the async vault prefill, and clicks the
/// danger button — which must open a confirm, not dispatch.
async fn open_rotate_remove_confirm() {
    ts::wait_for(|| ts::body_contains("Rotate into Key Vault…")).await;
    ts::click_button_labelled("Rotate into Key Vault…");
    ts::wait_for(|| {
        ts::query_all(".modal input").iter().any(|el| {
            el.clone()
                .unchecked_into::<web_sys::HtmlInputElement>()
                .value()
                == "kv-contoso"
        })
    })
    .await;
    ts::wait_for(|| ts::body_contains("Rotate & remove 2 existing")).await;
    ts::click_button_labelled("Rotate & remove 2 existing");
    ts::wait_for(|| ts::body_contains("Remove every existing client secret?")).await;
}

/// "Rotate & remove" deletes every client secret on the app, active ones
/// included. It used to do that on one click under a label with no count; it
/// must name how many, ask first, and report a removal that failed by name
/// rather than "see the log" (there is no log viewer in the UI).
#[wasm_bindgen_test]
async fn rotate_and_remove_names_the_count_and_waits_for_confirmation() {
    ts::reset();
    mock_rotation();
    let _m = mount_with_toasts(vec![active_secret("key-1"), active_secret("key-2")]);

    open_rotate_remove_confirm().await;
    assert_eq!(
        ts::call_count("rotate_app_credential"),
        0,
        "the danger button must open a confirm, not rotate"
    );
    let subject = ts::text(".confirm-dialog__subject");
    assert!(
        subject.contains("Contoso CRM") && subject.contains("2 existing"),
        "the confirm must name the app and the count, got {subject:?}"
    );

    ts::click_button_labelled("Rotate & remove");
    ts::wait_for(|| ts::call_count("rotate_app_credential") == 1).await;
    let call = ts::last_call("rotate_app_credential").unwrap();
    assert_eq!(
        call.args["input"]["removeKeyIds"],
        serde_json::json!(["key-1", "key-2"]),
        "the set removed is the set the confirm counted"
    );

    ts::wait_for(|| ts::query(".toast").is_some()).await;
    assert!(
        ts::text(".toast").contains("failed to remove key-2"),
        "a secret that survived must be named, got {:?}",
        ts::text(".toast"),
    );
}

/// With the confirm stacked on the rotate dialog, one Escape reaches both
/// modals' listeners. It must back out of the confirm only — not also throw
/// away the vault and secret name the operator filled in underneath.
#[wasm_bindgen_test]
async fn escape_on_the_rotate_confirm_closes_only_the_confirm() {
    ts::reset();
    mock_rotation();
    let _m = mount_with_toasts(vec![active_secret("key-1"), active_secret("key-2")]);

    open_rotate_remove_confirm().await;
    ts::press_key("body", "Escape");
    ts::tick().await;

    assert!(
        !ts::body_contains("Remove every existing client secret?"),
        "Escape must close the confirm"
    );
    assert!(
        ts::body_contains("Rotate secret into Key Vault"),
        "and leave the rotate dialog underneath open"
    );
    assert_eq!(ts::call_count("rotate_app_credential"), 0);
}
