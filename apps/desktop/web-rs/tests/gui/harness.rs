//! Tests for the GUI test harness itself — chiefly, that one broken test
//! cannot break the ones after it; also that the shared label-based button
//! helpers every flow test leans on match what they claim to.
//!
//! wasm tests compile with `panic = abort`, so a failed assertion or a
//! `wait_for` timeout kills the module **without unwinding**: `Mounted`'s `Drop`
//! never runs and the dead view stays in `document.body` for the remainder of
//! the shard. That is not hypothetical — it turned a single real failure into
//! four red tests, three of them in modules whose code was fine, because their
//! globally-scoped counts (`tbody tr`, `tbody input[type=checkbox]`) quietly
//! absorbed the leaked rows.
//!
//! `std::mem::forget` reproduces that precisely: it drops the handle's ownership
//! without running `Drop`, which is exactly what an abort does.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support as ts;

/// A view distinctive enough that a leak is unambiguous in the assertions.
fn leaky_view() -> impl IntoView {
    view! {
        <table>
            <tbody>
                <tr class="harness-probe">
                    <td>"leaked-row-marker"</td>
                </tr>
            </tbody>
        </table>
    }
}

#[wasm_bindgen_test]
async fn a_test_that_aborts_mid_mount_does_not_leak_into_the_next_one() {
    ts::reset();

    // Simulate a test that panicked: mounted, then died without unwinding.
    let mounted = ts::mount_view(leaky_view);
    ts::wait_for(|| ts::body_contains("leaked-row-marker")).await;
    std::mem::forget(mounted);

    // The next test starts the way every test starts.
    ts::reset();

    assert!(
        !ts::body_contains("leaked-row-marker"),
        "a view left behind by an aborted test must not survive into the next \
         test — it silently corrupts any assertion that counts DOM nodes",
    );
    assert_eq!(
        ts::query_all(".harness-probe").len(),
        0,
        "the leaked row is still queryable",
    );
}

#[wasm_bindgen_test]
async fn mounting_twice_leaves_exactly_one_view_in_the_document() {
    ts::reset();

    // Two mounts without an intervening reset — the shape a test takes when it
    // remounts to check a different state.
    let first = ts::mount_view(leaky_view);
    ts::wait_for(|| ts::query_all(".harness-probe").len() == 1).await;
    std::mem::forget(first);

    let _second = ts::mount_view(leaky_view);
    ts::wait_for(|| !ts::query_all(".harness-probe").is_empty()).await;

    assert_eq!(
        ts::query_all(".harness-probe").len(),
        1,
        "mounting must sweep an orphaned host, or a remount doubles every count \
         the test then makes",
    );
}

#[wasm_bindgen_test]
async fn label_helpers_match_trimmed_text_and_respect_scope() {
    ts::reset();
    let outer = RwSignal::new(0u32);
    let modal = RwSignal::new(0u32);
    let _m = ts::mount_view(move || {
        view! {
            <div class="harness-labels">
                <button on:click=move |_| outer.update(|n| *n += 1)>" Save "</button>
                <button disabled=true>"Next"</button>
                <div class="modal">
                    <button on:click=move |_| modal.update(|n| *n += 1)>"Save"</button>
                </div>
                <input class="probe" />
            </div>
        }
    });
    ts::wait_for(|| ts::query(".harness-labels").is_some()).await;

    // Trimmed, exact — never a prefix.
    assert!(
        ts::has_button_labelled("Save"),
        "surrounding whitespace is trimmed"
    );
    assert!(
        !ts::has_button_labelled("Sav"),
        "a label is an exact match, not a prefix"
    );
    assert!(ts::button_labelled("Next").is_some());
    assert!(
        !ts::button_labelled_enabled("Next"),
        "a disabled button is not enabled"
    );
    assert!(ts::button_labelled_enabled("Save"));

    // Scoped: only the modal's button is reachable under `.modal`.
    ts::click_button_labelled_in(".modal", "Save");
    ts::tick().await;
    assert_eq!((outer.get_untracked(), modal.get_untracked()), (0, 1));
    assert!(ts::button_labelled_in(".modal", "Next").is_none());

    // Unscoped: the first match in document order.
    ts::click_button_labelled("Save");
    ts::tick().await;
    assert_eq!((outer.get_untracked(), modal.get_untracked()), (1, 1));

    ts::focus(".probe");
    assert!(ts::focused_matches(".probe"));
    assert!(!ts::focused_matches(".modal button"));
}
