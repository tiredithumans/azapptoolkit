//! GUI tests for the Scope-column banner (`ScopeUnavailableBanner`) when the
//! Exchange mailbox-scope lookup fails because the session is dead: the
//! banner raises the session's Re-authenticate lever and keeps its Retry for
//! once that lever has run (nothing else re-runs the lookup), while an
//! ordinary failure keeps its Retry and raises no session lever.
//! Mounted through the app-registration Permissions tab, which renders the
//! banner from `get_mail_permission_scopes`.
#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::permissions::PermissionKind;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::tabs::permissions_tab::PermissionsTab;

const BANNER: &str = "Mailbox scoping (Scope column) unavailable";

/// The Permissions tab of an app holding one scopable mail permission, so the
/// tab runs the mailbox-scope lookup on mount.
fn mount() -> ts::Mounted {
    let mut detail = fixtures::application_detail("obj-1", "app-1", "Contoso Mailer");
    detail.resolved_permissions = vec![fixtures::resolved_permission(
        fixtures::MICROSOFT_GRAPH_APP_ID,
        "Microsoft Graph",
        "Mail.Read",
        "Read mail in all mailboxes",
        PermissionKind::Application,
    )];
    let detail = Arc::new(detail);
    ts::mount_view(move || {
        let d = detail.clone();
        view! {
            <PermissionsTab detail=Signal::derive(move || d.clone()) on_changed=Callback::new(|()| {}) />
        }
    })
}

/// The labels of the buttons inside the banner.
fn banner_buttons() -> Vec<String> {
    ts::query_all("[role=status]")
        .into_iter()
        .find(|el| el.text_content().unwrap_or_default().contains(BANNER))
        .map(|banner| {
            let buttons = banner.query_selector_all("button").unwrap();
            (0..buttons.length())
                .filter_map(|i| buttons.item(i))
                .map(|b| b.text_content().unwrap_or_default().trim().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn toast_actions(m: &ts::Mounted) -> Vec<Option<String>> {
    m.session
        .toasts
        .with_untracked(|l| l.iter().map(|t| t.action_label.clone()).collect())
}

#[wasm_bindgen_test]
async fn a_dead_session_raises_reauthenticate_and_keeps_the_retry() {
    ts::reset();
    ts::mock_err(
        "get_mail_permission_scopes",
        &fixtures::ui_error("refresh_missing", "refresh token missing"),
    );
    let m = mount();

    ts::wait_for(|| ts::body_contains(BANNER)).await;
    ts::wait_until("the Re-authenticate toast", || {
        toast_actions(&m).contains(&Some("Re-authenticate".to_string()))
    })
    .await;
    assert!(ts::body_contains(
        "Re-authenticate from the notice, then select Retry."
    ));
    assert!(
        banner_buttons().iter().any(|b| b == "Retry"),
        "after re-authenticating, the banner's Retry is the way back: {:?}",
        banner_buttons()
    );
}

#[wasm_bindgen_test]
async fn an_ordinary_failure_keeps_its_retry_and_raises_no_session_lever() {
    ts::reset();
    ts::mock_err(
        "get_mail_permission_scopes",
        &fixtures::ui_error("forbidden", "The EXO Role Management role is missing."),
    );
    let m = mount();

    ts::wait_for(|| ts::body_contains(BANNER)).await;
    assert!(ts::body_contains("Role Management"));
    assert!(banner_buttons().iter().any(|b| b == "Retry"));
    assert!(
        !toast_actions(&m)
            .iter()
            .flatten()
            .any(|l| l == "Re-authenticate" || l == "Refresh token"),
        "{:?}",
        toast_actions(&m)
    );
}
