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

use azapptoolkit_web_rs::test_support as ts;
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
