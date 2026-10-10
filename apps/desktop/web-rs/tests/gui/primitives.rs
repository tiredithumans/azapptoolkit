//! The design-system primitives' keyboard and ARIA contracts, mounted bare.
//!
//! `components/ui` carries the app-wide keyboard behaviour — `TabBar`'s roving
//! tabindex and arrow keys, `DataTable`'s row navigation, `ModalShell`'s focus
//! trap — and every other GUI module only exercised them incidentally through
//! whichever view happened to mount them. Each contract is pinned here on the
//! primitive itself, so a regression names the primitive.
//!
//! Lives in shard 4: every one of these primitives is already linked there
//! (Settings mounts TabBar and DetailSkeleton, Key Vault mounts DataTable, the
//! shortcuts tests mount ModalShell), so the module adds only test code.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::components::modal_shell::ModalShell;
use azapptoolkit_web_rs::components::ui::{DataTable, SkeletonList, TabBar, TabBarItem, tab_id};
use azapptoolkit_web_rs::test_support::{self as ts};

/// A tab strip names itself, keeps exactly one tab stop, moves selection AND
/// focus with the arrows (wrapping) and Home/End, and links its tabs to the
/// panel it switches.
#[wasm_bindgen_test]
async fn tab_bar_names_itself_and_moves_with_arrows_home_and_end() {
    ts::reset();
    let selected = RwSignal::new("b".to_string());
    let _m = ts::mount_view(move || {
        view! {
            <TabBar
                label="Letters"
                panel_id="letters-panel"
                selected=selected
                items=vec![
                    TabBarItem { value: "a", label: "A" },
                    TabBarItem { value: "b", label: "B" },
                    TabBarItem { value: "c", label: "C" },
                ]
            />
            <div
                id="letters-panel"
                role="tabpanel"
                aria-labelledby=move || tab_id("letters-panel", &selected.get())
            >
                "panel"
            </div>
        }
    });
    ts::wait_until("the tablist", || ts::query("[role=tablist]").is_some()).await;
    let list = ts::query("[role=tablist]").unwrap();
    assert_eq!(list.get_attribute("aria-label").as_deref(), Some("Letters"));

    // Roving tabindex: the selected tab is the one tab stop, and it names its panel.
    assert_eq!(ts::query_all("[role=tab][tabindex='0']").len(), 1);
    assert_eq!(ts::text("[role=tab][tabindex='0']"), "B");
    let active = ts::query("[role=tab][aria-selected='true']").unwrap();
    assert_eq!(
        active.get_attribute("aria-controls").as_deref(),
        Some("letters-panel")
    );
    assert_eq!(
        active.get_attribute("id").as_deref(),
        Some("letters-panel-tab-b")
    );

    ts::focus("#letters-panel-tab-b");
    ts::press_key("#letters-panel-tab-b", "ArrowRight");
    ts::tick().await;
    assert_eq!(selected.get_untracked(), "c");
    assert!(
        ts::focused_matches("#letters-panel-tab-c"),
        "focus follows selection"
    );
    ts::press_key("#letters-panel-tab-c", "ArrowRight");
    ts::tick().await;
    assert_eq!(selected.get_untracked(), "a", "wraps at the end");
    ts::press_key("#letters-panel-tab-a", "ArrowLeft");
    ts::tick().await;
    assert_eq!(selected.get_untracked(), "c", "wraps at the start");
    ts::press_key("#letters-panel-tab-c", "Home");
    ts::tick().await;
    assert_eq!(selected.get_untracked(), "a");
    ts::press_key("#letters-panel-tab-a", "End");
    ts::tick().await;
    assert_eq!(selected.get_untracked(), "c");
    assert_eq!(ts::query_all("[role=tab][tabindex='0']").len(), 1);
    assert_eq!(
        ts::query("#letters-panel")
            .unwrap()
            .get_attribute("aria-labelledby")
            .as_deref(),
        Some("letters-panel-tab-c"),
        "the panel is labelled by the active tab"
    );
}

/// A `DataTable` seeds one tab stop among its rows, Home/End/arrows move it,
/// and Enter activates the focused row's first button.
#[wasm_bindgen_test]
async fn data_table_rows_take_arrows_home_end_and_enter() {
    ts::reset();
    let clicked = RwSignal::new(String::new());
    let _m = ts::mount_view(move || {
        view! {
            <DataTable
                headers=vec!["Name", ""]
                rows=vec!["one", "two", "three"]
                empty_message="none"
                row=move |name: &'static str| {
                    view! {
                        <tr>
                            <td>{name}</td>
                            <td>
                                <button type="button" on:click=move |_| clicked.set(name.to_string())>
                                    "Open"
                                </button>
                            </td>
                        </tr>
                    }
                        .into_any()
                }
            />
        }
    });
    let rows = ".data-table tbody tr";
    ts::wait_until("three rows", || ts::query_all(rows).len() == 3).await;
    ts::wait_until("the roving tab stop", || {
        ts::query(".data-table tbody tr[tabindex='0']").is_some()
    })
    .await;
    assert_eq!(ts::query_all(".data-table tbody tr[tabindex='0']").len(), 1);

    ts::focus(".data-table tbody tr[tabindex='0']");
    ts::press_key(".data-table tbody tr[tabindex='0']", "End");
    ts::tick().await;
    assert!(ts::focused_matches(".data-table tbody tr:nth-child(3)"));
    ts::press_key(".data-table tbody tr:nth-child(3)", "Home");
    ts::tick().await;
    assert!(ts::focused_matches(".data-table tbody tr:nth-child(1)"));
    ts::press_key(".data-table tbody tr:nth-child(1)", "ArrowDown");
    ts::tick().await;
    assert!(ts::focused_matches(".data-table tbody tr:nth-child(2)"));
    ts::press_key(".data-table tbody tr:nth-child(2)", "Enter");
    ts::tick().await;
    assert_eq!(
        clicked.get_untracked(),
        "two",
        "Enter presses the row's first button"
    );
}

/// A `ModalShell` takes focus on open, cycles Tab and Shift+Tab at its edges,
/// closes on Escape, and hands focus back to the trigger on close.
#[wasm_bindgen_test]
async fn modal_shell_traps_focus_closes_on_escape_and_returns_focus() {
    ts::reset();
    let open = RwSignal::new(false);
    let closes = RwSignal::new(0u32);
    let _m = ts::mount_view(move || {
        view! {
            <button type="button" class="probe">"open"</button>
            <ModalShell
                open=Signal::derive(move || open.get())
                title="Trap".to_string()
                on_close=Callback::new(move |()| closes.update(|n| *n += 1))
            >
                <button type="button" class="first">"first"</button>
                <button type="button" class="last">"last"</button>
            </ModalShell>
        }
    });
    ts::wait_until("the probe", || ts::query(".probe").is_some()).await;
    ts::focus(".probe");
    open.set(true);
    ts::wait_until("focus on the first control", || {
        ts::focused_matches(".first")
    })
    .await;

    ts::focus(".last");
    ts::press_key(".last", "Tab");
    ts::tick().await;
    assert!(
        ts::focused_matches(".first"),
        "Tab wraps from the last control"
    );
    ts::press_key_with_shift(".first", "Tab");
    ts::tick().await;
    assert!(
        ts::focused_matches(".last"),
        "Shift+Tab wraps from the first control"
    );

    ts::press_key("body", "Escape");
    ts::tick().await;
    assert_eq!(closes.get_untracked(), 1, "Escape asks to close");
    open.set(false);
    ts::wait_until("focus back on the trigger", || {
        ts::focused_matches(".probe")
    })
    .await;
}

/// Escape is refused while the dialog is busy, and altogether when the dialog
/// says so (a one-time secret reveal).
#[wasm_bindgen_test]
async fn modal_shell_ignores_escape_while_busy_or_when_told_to() {
    ts::reset();
    let closes = RwSignal::new(0u32);
    let busy = RwSignal::new(true);
    let _m = ts::mount_view(move || {
        view! {
            <ModalShell
                open=Signal::derive(|| true)
                title="Busy".to_string()
                busy=Signal::derive(move || busy.get())
                on_close=Callback::new(move |()| closes.update(|n| *n += 1))
            >
                <button type="button">"a"</button>
            </ModalShell>
            <ModalShell
                open=Signal::derive(|| true)
                title="Sticky".to_string()
                close_on_escape=false
                on_close=Callback::new(move |()| closes.update(|n| *n += 1))
            >
                <button type="button">"b"</button>
            </ModalShell>
        }
    });
    ts::wait_until("both dialogs", || {
        ts::query_all(".modal-backdrop").len() == 2
    })
    .await;
    ts::press_key("body", "Escape");
    ts::tick().await;
    assert_eq!(closes.get_untracked(), 0);
    // The positive control: once the first dialog is no longer busy, the same
    // Escape closes it — and only it.
    busy.set(false);
    ts::tick().await;
    ts::press_key("body", "Escape");
    ts::tick().await;
    assert_eq!(closes.get_untracked(), 1);
}

/// A skeleton is a status region that says it is loading, not a silent block.
#[wasm_bindgen_test]
async fn skeletons_announce_loading() {
    ts::reset();
    let _m = ts::mount_view(|| view! { <SkeletonList rows=2 /> });
    ts::wait_until("the skeleton", || ts::query(".ui-skel-list").is_some()).await;
    let region = ts::query(".ui-skel-list").unwrap();
    assert_eq!(region.get_attribute("role").as_deref(), Some("status"));
    assert!(ts::text(".ui-skel-list .visually-hidden").contains("Loading"));
    assert_eq!(ts::query_all(".ui-skel-list .ui-skel-row").len(), 2);
}
