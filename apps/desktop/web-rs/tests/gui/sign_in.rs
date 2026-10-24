//! GUI tests for the sign-in surfaces that recover from an environment
//! problem rather than a credential one: an offline launch (the restore could
//! not reach Entra ID, so the card offers a Retry of the silent restore), and a
//! browser that would not open (the sign-in link is offered in the app).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use azapptoolkit_dto::events as names;
use azapptoolkit_web_rs::bindings::TenantContext;
use azapptoolkit_web_rs::components::browser_fallback_notice::BrowserFallbackNotice;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::sign_in::{RestoringSession, SignInScreen};

/// The sign-in card as `Root` paints it after a launch restore that could not
/// reach Entra ID. `mount_view` presets a signed-in tenant; the card is only
/// ever shown signed out, so the test clears it.
fn mount_offline_card() -> ts::Mounted {
    let m = ts::mount_view(|| {
        view! {
            <SignInScreen
                tenant="test-tenant".to_string()
                on_reconfigure=Callback::new(|_| ())
                restore_failure=RwSignal::new(Some("network".to_string()))
            />
        }
    });
    m.session.active_tenant.set(None);
    m
}

#[wasm_bindgen_test]
async fn offline_launch_offers_retry_and_retry_restores_without_a_browser() {
    ts::reset();
    ts::mock_ok("restore_session", &Some(ts::test_tenant()));

    let m = mount_offline_card();
    ts::wait_for(|| ts::body_contains("Couldn't reach Entra ID")).await;

    ts::click(".signin-restore-retry");
    ts::wait_for(|| {
        ts::call_count("restore_session") == 1 && m.session.active_tenant.get_untracked().is_some()
    })
    .await;
    assert_eq!(
        ts::call_count("sign_in"),
        0,
        "Retry is the silent restore, never a browser sign-in"
    );
}

#[wasm_bindgen_test]
async fn a_retry_that_is_still_offline_keeps_the_callout() {
    ts::reset();
    ts::mock_err(
        "restore_session",
        &fixtures::ui_error("network", "error sending request"),
    );

    let m = mount_offline_card();
    ts::wait_for(|| ts::body_contains("Couldn't reach Entra ID")).await;

    ts::click(".signin-restore-retry");
    ts::wait_for(|| ts::call_count("restore_session") == 1).await;
    ts::tick().await;
    assert!(ts::body_contains("Couldn't reach Entra ID"));
    assert!(ts::query(".signin-restore-retry").is_some());
    assert!(m.session.active_tenant.get_untracked().is_none());
    assert_eq!(ts::call_count("sign_in"), 0);
}

#[wasm_bindgen_test]
async fn a_retry_that_finds_no_session_falls_back_to_the_plain_card() {
    ts::reset();
    ts::mock_ok("restore_session", &None::<TenantContext>);

    let m = mount_offline_card();
    ts::wait_for(|| ts::body_contains("Couldn't reach Entra ID")).await;

    ts::click(".signin-restore-retry");
    ts::wait_for(|| !ts::body_contains("Couldn't reach Entra ID")).await;
    assert_eq!(ts::call_count("restore_session"), 1);
    assert!(m.session.active_tenant.get_untracked().is_none());
    assert!(ts::body_contains("Sign in with Entra ID"));
}

/// An unreachable or throttled token endpoint can hold the launch restore for
/// a minute or more behind a bare spinner. Past a few seconds the card says so
/// and offers to stop waiting (`Root` then moves the restore fence, so the late
/// answer lands nothing — pinned natively by `views::sign_in` tests).
#[wasm_bindgen_test]
async fn a_slow_restore_offers_to_sign_in_instead() {
    ts::reset();
    let chose = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&chose);
    let _m = ts::mount_view(move || {
        let seen = Arc::clone(&seen);
        view! {
            <RestoringSession
                on_sign_in_instead=Callback::new(move |()| seen.store(true, Ordering::SeqCst))
                slow_after=Duration::from_millis(10)
            />
        }
    });
    assert!(ts::body_contains("Restoring your session"));
    assert!(
        !ts::body_contains("Still restoring"),
        "a quick restore stays a bare spinner"
    );

    ts::wait_for(|| ts::body_contains("Still restoring your session")).await;
    ts::click(".signin-restore-skip");
    assert!(
        chose.load(Ordering::SeqCst),
        "Sign in instead ends the wait"
    );
}

/// The card's own Sign in moves the restore fence, so a Retry still in flight
/// cannot sign a session in behind the browser sign-in.
#[wasm_bindgen_test]
async fn signing_in_from_the_card_moves_the_restore_fence() {
    ts::reset();
    ts::mock_ok("sign_in", &fixtures::sign_in_outcome(ts::test_tenant()));
    let generation = RwSignal::new(0u64);
    let m = ts::mount_view(move || {
        view! {
            <SignInScreen
                tenant="test-tenant".to_string()
                on_reconfigure=Callback::new(|_| ())
                restore_generation=generation
            />
        }
    });
    m.session.active_tenant.set(None);

    ts::click_button_labelled("Sign in with Entra ID");
    ts::wait_for(|| ts::call_count("sign_in") == 1).await;
    assert_eq!(
        generation.get_untracked(),
        1,
        "the Sign in click moved the fence"
    );
}

/// A proxy (or an unavailable Entra ID) at launch is not a network problem:
/// the callout says what the sign-in hint says, and still offers Retry.
#[wasm_bindgen_test]
async fn a_proxy_at_launch_is_named_in_the_restore_callout() {
    ts::reset();
    let m = ts::mount_view(|| {
        view! {
            <SignInScreen
                tenant="test-tenant".to_string()
                on_reconfigure=Callback::new(|_| ())
                restore_failure=RwSignal::new(Some("unexpected_responder".to_string()))
            />
        }
    });
    m.session.active_tenant.set(None);

    ts::wait_for(|| ts::body_contains("Couldn't restore your session")).await;
    assert!(ts::body_contains("proxy"));
    assert!(!ts::body_contains("check your network connection"));
    assert!(ts::query(".signin-restore-retry").is_some());
}

#[wasm_bindgen_test]
async fn a_browser_that_would_not_open_shows_the_sign_in_link_until_the_flow_ends() {
    ts::reset();
    let _m = ts::mount_view(|| view! { <BrowserFallbackNotice /> });
    // The hook subscribes in a spawned task; let it register the listener.
    ts::tick().await;
    ts::tick().await;

    ts::emit_event(
        names::AUTH_BROWSER_FALLBACK,
        &Some("https://login.microsoftonline.com/t/oauth2/v2.0/authorize?state=abc"),
    );
    ts::wait_for(|| ts::body_contains("Couldn't open your browser")).await;
    assert!(ts::body_contains("state=abc"));
    assert!(ts::query(".browser-fallback .copy-block").is_some());

    ts::emit_event(names::AUTH_BROWSER_FALLBACK, &None::<String>);
    ts::wait_for(|| ts::query(".browser-fallback").is_none()).await;
}
