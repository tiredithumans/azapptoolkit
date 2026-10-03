//! GUI tests for F266 — the recycle bin: the "Recently deleted" dialog and the
//! bulk bar's post-delete Undo.
//!
//! Both exist because the delete's 30-day window was invisible: the copy now
//! points at real exits (Undo right after the run, the dialog anytime), and
//! these tests pin that the exits actually fire the restore/purge commands with
//! the right ids. The dialog mounts directly here; the Undo test mounts the
//! real `ApplicationList` so the whole arm → type-DELETE → run → Undo gesture
//! runs against the shipped `BulkActionBar`.
#![cfg(target_arch = "wasm32")]

use chrono::{Duration, Utc};
use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::applications::{DeletedAppDto, DeletedAppsDto};
use azapptoolkit_dto::bulk::{BulkRestoreOutcome, BulkRestoreResult};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::application_list::ApplicationList;
use azapptoolkit_web_rs::views::dialogs::deleted_apps_dialog::DeletedAppsDialog;

/// A one-row bin for the action tests, so ids are exact and asserted.
fn one_row_bin() -> DeletedAppsDto {
    DeletedAppsDto {
        apps: vec![DeletedAppDto {
            object_id: "del-1".to_string(),
            app_id: Some("app-1".to_string()),
            display_name: Some("Contoso CRM".to_string()),
            deleted_date_time: Some(Utc::now() - Duration::days(4)),
        }],
        truncated: false,
    }
}

fn clean_restore(object_id: &str, sp_restored: bool) -> BulkRestoreResult {
    BulkRestoreResult {
        outcomes: vec![BulkRestoreOutcome {
            object_id: object_id.to_string(),
            restored: true,
            sp_restored,
            error: None,
        }],
        cancelled: false,
    }
}

/// Mount the dialog open — the shell mounts it only while `deleted_open` is
/// set, and ModalShell `<Show>`-gates its children on `open`.
fn mount_dialog(dto: &DeletedAppsDto) -> ts::Mounted {
    ts::mock_ok("list_recently_deleted", dto);
    ts::mount_view(|| {
        view! {
            <DeletedAppsDialog
                open=Signal::derive(move || true)
                on_close=Callback::new(move |_: ()| {})
                on_mutated=Callback::new(move |_: ()| {})
            />
        }
    })
}

/// Like `ts::wait_for`, but names the step and dumps the body on timeout.
async fn settle(step: &str, f: impl Fn() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        ts::tick().await;
    }
    panic!("stuck at {step}; body:\n{}", ts::body_text());
}

#[wasm_bindgen_test]
async fn the_dialog_lists_the_recycle_bin() {
    ts::reset();
    let _m = mount_dialog(&fixtures::deleted_apps());

    ts::wait_for(|| ts::body_contains("Contoso CRM")).await;
    assert!(ts::body_contains("HR Sync"));
    assert_eq!(ts::query_all(".permissions-cell__primary").len(), 2);

    let call = ts::last_call("list_recently_deleted").expect("the bin was read");
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
}

/// The dialog's whole premise: every listed row can come back. A restore must
/// hit `bulk_restore_deleted` with the row's object id (not the appId) and
/// refetch the bin so the restored row disappears.
#[wasm_bindgen_test]
async fn restore_calls_the_restore_command_and_refetches() {
    ts::reset();
    ts::mock_ok("bulk_restore_deleted", &clean_restore("del-1", true));
    let _m = mount_dialog(&one_row_bin());

    ts::wait_for(|| ts::has_button_labelled("Restore")).await;
    ts::click_button_labelled("Restore");

    settle("restore ran", || {
        ts::call_count("bulk_restore_deleted") == 1
    })
    .await;
    let call = ts::last_call("bulk_restore_deleted").unwrap();
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    assert_eq!(
        call.args
            .get("objectIds")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
        Some(vec!["del-1"]),
        "the restore takes the deleted object's own id"
    );
    // Refetch, or the dialog keeps listing an app it just restored.
    ts::wait_for(|| ts::call_count("list_recently_deleted") == 2).await;
}

/// Permanent deletion skips the 30-day window and cannot be undone, so the
/// button arms on the first click and only fires on the second.
#[wasm_bindgen_test]
async fn delete_forever_needs_two_clicks() {
    ts::reset();
    ts::mock_ok("purge_deleted_application", &());
    let _m = mount_dialog(&one_row_bin());

    ts::wait_for(|| ts::has_button_labelled("Delete forever")).await;
    ts::click_button_labelled("Delete forever");
    ts::tick().await;
    assert_eq!(
        ts::call_count("purge_deleted_application"),
        0,
        "the first click only arms the row"
    );

    ts::wait_for(|| ts::has_button_labelled("Confirm permanent delete")).await;
    ts::click_button_labelled("Confirm permanent delete");
    ts::wait_for(|| ts::call_count("purge_deleted_application") == 1).await;
    let call = ts::last_call("purge_deleted_application").unwrap();
    assert_eq!(call.arg_str("objectId").as_deref(), Some("del-1"));
}

#[wasm_bindgen_test]
async fn an_empty_bin_says_so() {
    ts::reset();
    let _m = mount_dialog(&DeletedAppsDto {
        apps: vec![],
        truncated: false,
    });

    ts::wait_for(|| ts::body_contains("Recycle bin is empty")).await;
    assert!(!ts::body_contains("Restore"));
}

/// A capped read is not an empty bin: the warn callout is the only signal the
/// list is partial.
#[wasm_bindgen_test]
async fn a_truncated_bin_says_it_is_partial() {
    ts::reset();
    let mut dto = one_row_bin();
    dto.truncated = true;
    let _m = mount_dialog(&dto);

    ts::wait_for(|| ts::body_contains("this list is partial")).await;
}

/// The Undo path: after a delete run, the bar replays the run's confirmed-gone
/// ids through the recycle bin. The ids come from the run's result snapshot,
/// NOT the current selection — the delete drops them from the selection the
/// moment they are confirmed gone, so if Undo re-read the selection it would
/// always restore nothing.
#[wasm_bindgen_test]
async fn undo_after_a_bulk_delete_restores_the_deleted_app() {
    ts::reset();
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Solo App"]),
    );
    ts::mock_ok(
        "bulk_delete_applications",
        &azapptoolkit_dto::bulk::BulkDeleteResult {
            deleted: vec!["obj-0".to_string()],
            failed: vec![],
            cancelled: false,
        },
    );
    ts::mock_ok("bulk_restore_deleted", &clean_restore("obj-0", true));

    let m = ts::mount_view(|| view! { <ApplicationList /> });
    settle("rows", || ts::query(".app-list__row").is_some()).await;

    // Seed the selection through the shared set (same home as the row
    // checkboxes) — one checked app is all the bar needs to appear.
    m.session.tenant_ui.selected_app_ids.update(|sel| {
        sel.insert("obj-0".to_string());
    });
    settle("bar", || ts::body_contains("1 selected")).await;

    ts::click_button_labelled_in(".bulk-action-bar__actions", "Delete");
    let gate = ".bulk-action-bar__confirm .confirm-gate input";
    settle("gate", || ts::query(gate).is_some()).await;
    ts::set_input_value(gate, "DELETE");
    settle("confirm armed", || {
        ts::button_labelled_in(".bulk-action-bar__confirm", "Delete")
            .is_some_and(|b| !b.has_attribute("disabled"))
    })
    .await;
    ts::click_button_labelled_in(".bulk-action-bar__confirm", "Delete");

    settle("delete ran", || {
        ts::call_count("bulk_delete_applications") == 1
    })
    .await;
    settle("delete summary", || {
        ts::body_contains("Deleted 1 app; 0 failed.")
    })
    .await;
    // The deleted id left the selection with the delete — Undo must still offer
    // exactly it.
    assert!(
        m.session
            .tenant_ui
            .selected_app_ids
            .get_untracked()
            .is_empty(),
        "the confirmed-gone id left the selection"
    );

    settle("undo button", || {
        ts::has_button_labelled("Undo (restore 1 deleted)")
    })
    .await;
    ts::click_button_labelled("Undo (restore 1 deleted)");

    settle("restore ran", || {
        ts::call_count("bulk_restore_deleted") == 1
    })
    .await;
    let call = ts::last_call("bulk_restore_deleted").unwrap();
    assert_eq!(
        call.args
            .get("objectIds")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
        Some(vec!["obj-0"]),
        "Undo replays the run's deleted ids, not the (now empty) selection"
    );
    settle("restore summary", || {
        ts::body_contains("Restored 1 of 1 deleted app.")
    })
    .await;
}
