//! `use_list_export` — the shared CSV/JSON inventory-export handle for the three
//! tenant list views (App Registrations, Enterprise Applications, Managed
//! Identities). Each carried an identical `export_rows` snapshot + `exporting`
//! double-submit guard + `do_export` spawn that saves via the OS dialog and
//! toasts the outcome; only the save command and the noun differed.

use std::future::Future;
use std::sync::Arc;

use leptos::prelude::*;

use azapptoolkit_dto::UiError;

use crate::state::use_session;

/// Wires up the inventory export for a list view. `save` performs the IPC save
/// (it receives the current snapshot + the `"csv"`/`"json"` format and returns
/// the chosen path, or `None` when the user cancels the save dialog); `noun`
/// names the rows in the success toast (`"Exported N {noun} to …"`).
///
/// Returns `(export_rows, exporting, do_export)`:
/// - `export_rows` — the shared snapshot to hand to
///   [`use_filtered_list`](crate::hooks::use_filtered_list) as its `export_rows`,
///   so "what you see is what you export" (the `Arc` makes each snapshot a
///   pointer copy, not a row-by-row clone).
/// - `exporting` — the in-flight guard, for disabling the export buttons.
/// - `do_export` — call with `"csv"` / `"json"` to run the export (no-op while
///   one is in flight or the snapshot is empty).
// The return is a documented 3-tuple whose third member is an opaque closure;
// a type alias can't name the `impl Fn`, and a struct would leak the closure's
// unnameable type as a generic param at every call site for no readability win.
#[allow(clippy::type_complexity)]
pub fn use_list_export<T, F, Fut>(
    save: F,
    noun: &'static str,
) -> (
    StoredValue<Arc<Vec<T>>>,
    RwSignal<bool>,
    impl Fn(&'static str) + Copy + 'static,
)
where
    T: Send + Sync + 'static,
    F: Fn(Arc<Vec<T>>, &'static str) -> Fut + Copy + 'static,
    Fut: Future<Output = Result<Option<String>, UiError>> + 'static,
{
    let session = use_session();
    let export_rows: StoredValue<Arc<Vec<T>>> = StoredValue::new(Arc::new(Vec::new()));
    let exporting = RwSignal::new(false);
    let do_export = move |format: &'static str| {
        if exporting.get_untracked() {
            return;
        }
        let rows = export_rows.get_value();
        if rows.is_empty() {
            return;
        }
        exporting.set(true);
        leptos::task::spawn_local(async move {
            let count = rows.len();
            match save(rows, format).await {
                Ok(Some(path)) => {
                    session.toast_success(format!("Exported {count} {noun} to {path}"));
                }
                Ok(None) => {}
                Err(e) => {
                    session.report_command_error(&e);
                }
            }
            exporting.set(false);
        });
    };
    (export_rows, exporting, do_export)
}
