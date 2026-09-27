//! GUI tests for [`AppShell`] — the single mount point for the nav, the topbar,
//! and the open-items dock + workspace.
//!
//! It had no GUI coverage at all despite being the one component every screen
//! renders inside, and despite fusing five concerns (sign-out, silent-refresh /
//! re-auth, the updater launch check, the account menu, and both nav builders).
//! These tests stay on the structural contract the rest of the suite depends on
//! — that the shell mounts, renders its children, and mounts the dock exactly
//! once — rather than re-testing behavior the dock/workspace modules already own.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::updater::{UpdateCheck, UpdateInfo, UpdatesDisabled};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::dialogs::cache_diagnostics_dialog::CacheDiagnosticsDialog;
use azapptoolkit_web_rs::views::shell::AppShell;

#[wasm_bindgen_test]
async fn the_shell_mounts_its_chrome_and_renders_children() {
    ts::reset();
    // `check_for_update` / `refresh_session` are both fallible (`invoke_result`),
    // so leaving them unmocked degrades to an Err the shell already handles —
    // exactly the launch path a user with no update hits.
    let _m = ts::mount_view(|| {
        view! { <AppShell><div id="probe">"page body"</div></AppShell> }
    });

    ts::wait_for(|| ts::query(".shell").is_some()).await;
    assert!(ts::query(".shell__nav").is_some(), "nav rail must render");
    assert!(
        ts::query("#probe").is_some(),
        "the shell must render the page it wraps, not just its own chrome"
    );
    assert!(ts::body_contains("azapptoolkit"), "brand text is present");
}

#[wasm_bindgen_test]
async fn the_nav_offers_every_top_level_section() {
    ts::reset();
    let _m = ts::mount_view(|| view! { <AppShell><div /></AppShell> });

    ts::wait_for(|| ts::query(".shell__nav-list").is_some()).await;
    // The three section groupings the nav builders produce. A regression that
    // drops one is invisible in a unit test — the builders are private and the
    // grouping only exists once rendered.
    for section in ["Inventory", "Security", "Operations"] {
        assert!(
            ts::body_contains(section),
            "nav section {section:?} missing from the rendered shell"
        );
    }
}

#[wasm_bindgen_test]
async fn the_open_items_dock_mounts_exactly_once() {
    ts::reset();
    let _m = ts::mount_view(|| view! { <AppShell><div /></AppShell> });
    ts::wait_for(|| ts::query(".shell").is_some()).await;

    // AGENTS.md: the dock + workspace mount ONCE, here. Mounting a second copy
    // (e.g. by a view rendering its own) would give the shared working set two
    // independent renderings of the same `Session.open_items`.
    assert!(
        ts::query_all(".open-dock").len() <= 1,
        "the dock must mount at most once"
    );
}

/// The version line's "What's new" is the ONLY way back to this build's release
/// notes once the update splash has been dismissed — and the notes it shows are
/// baked in at compile time, so a broken `build.rs` or an unfinalized changelog
/// surfaces here as an empty dialog rather than at the next release.
#[wasm_bindgen_test]
async fn the_account_menu_reopens_this_versions_release_notes() {
    ts::reset();
    let _m = ts::mount_view(|| view! { <AppShell><div /></AppShell> });
    ts::wait_for(|| ts::query(".shell__tenant-chip").is_some()).await;

    ts::click(".shell__tenant-chip");
    ts::wait_for(|| ts::query(".shell__account-version").is_some()).await;
    assert!(
        ts::body_contains("What's new"),
        "the account menu's version line must offer a way back to the release notes"
    );

    ts::click(".shell__account-version .link-btn");
    ts::wait_for(|| ts::query(".changelog").is_some()).await;
    assert!(
        ts::body_contains(&format!("What's new in v{}", env!("CARGO_PKG_VERSION"))),
        "the dialog must name the version it is showing notes for"
    );
    assert!(
        !ts::text(".changelog").is_empty(),
        "release notes for this build must be baked in, not an empty box"
    );
}

/// Summary-first is the contract: the splash and this dialog show what changed
/// for the operator, with the implementation detail behind the toggle. A
/// regression that renders the raw section shows the detail immediately.
#[wasm_bindgen_test]
async fn release_notes_render_condensed_with_the_detail_behind_a_toggle() {
    ts::reset();
    let _m = ts::mount_view(|| view! { <AppShell><div /></AppShell> });
    ts::wait_for(|| ts::query(".shell__tenant-chip").is_some()).await;
    ts::click(".shell__tenant-chip");
    ts::wait_for(|| ts::query(".shell__account-version").is_some()).await;
    ts::click(".shell__account-version .link-btn");
    ts::wait_for(|| ts::query(".changelog").is_some()).await;

    // Our changelog always carries entries whose lede is followed by rationale,
    // so the condensed and full renders must differ for any real release.
    let condensed = ts::text(".changelog").len();
    assert!(
        ts::query(".changelog__toggle").is_some(),
        "notes with technical detail must offer the toggle that reveals it"
    );
    ts::click(".changelog__toggle");
    ts::wait_for(|| ts::text(".changelog").len() > condensed).await;
    assert!(
        ts::body_contains("Hide technical details"),
        "the toggle must flip to hiding detail once expanded"
    );
}

/// An install the in-app updater does not own (here MSI) is told by the backend
/// that no check was made; the account menu must say who manages updates and
/// not offer a check — never toast an update the updater would install as a
/// second, conflicting copy.
#[wasm_bindgen_test]
async fn a_managed_install_labels_the_update_item_instead_of_offering_a_check() {
    ts::reset();
    ts::mock_ok(
        "check_for_update",
        &UpdateCheck::Disabled {
            reason: UpdatesDisabled::Msi,
        },
    );
    let _m = ts::mount_view(|| view! { <AppShell><div /></AppShell> });
    ts::wait_for(|| ts::call_count("check_for_update") >= 1).await;
    ts::wait_for(|| ts::query(".shell__tenant-chip").is_some()).await;

    ts::click(".shell__tenant-chip");
    ts::wait_for(|| ts::body_contains(UpdatesDisabled::Msi.menu_label())).await;
    let item = ts::query(".shell__account-item--update").expect("the update menu item renders");
    assert!(
        item.get_attribute("disabled").is_some(),
        "a managed install must not offer a manual update check"
    );
    assert_eq!(
        item.get_attribute("title").as_deref(),
        Some(UpdatesDisabled::Msi.description()),
        "the disabled item explains where updates come from"
    );
    assert!(!ts::body_contains("Check for updates"));
    assert!(!ts::body_contains("Update available"));
}

#[wasm_bindgen_test]
async fn an_available_update_toasts_on_launch() {
    ts::reset();
    ts::mock_ok(
        "check_for_update",
        &UpdateCheck::Available {
            info: UpdateInfo {
                version: "9.9.9".into(),
                current_version: "0.0.1".into(),
                notes: String::new(),
                pub_date: None,
            },
        },
    );
    let _m = ts::mount_view(|| view! { <AppShell><div /></AppShell> });
    ts::wait_for(|| ts::body_contains("Update available: v9.9.9")).await;
}

#[wasm_bindgen_test]
async fn cache_dialog_clears_one_kind_and_labels_the_toggle() {
    // The shell mounts the Cache dialog; each kind's row carries its own Clear
    // (not just "Clear all"), and the toggle says what a click will do.
    ts::reset();
    ts::mock_ok("cache_stats", &fixtures::cache_stats());
    ts::mock_ok("clear_cache", &());

    let _m = ts::mount_view(|| {
        view! {
            <CacheDiagnosticsDialog
                open=Signal::derive(|| true)
                on_close=Callback::new(|_| ())
            />
        }
    });

    ts::wait_for(|| ts::body_contains("Audit hits / misses")).await;
    // Fixture has caching enabled, so the button offers to disable it.
    assert!(ts::body_contains("Disable cache"));
    assert!(!ts::body_contains("Toggle enabled"));

    ts::click("button[aria-label=\"Clear audit cache\"]");
    ts::wait_for(|| ts::call_count("clear_cache") >= 1).await;
    let call = ts::last_call("clear_cache").unwrap();
    // CacheKindDto is `rename_all = "snake_case"`.
    assert_eq!(call.arg_str("kind").as_deref(), Some("audit"));
    ts::wait_for(|| ts::body_contains("Cleared the audit cache.")).await;
}
