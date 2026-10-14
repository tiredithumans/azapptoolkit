//! `use_list_export` — the shared CSV/JSON inventory-export handle for the three
//! tenant list views (App Registrations, Enterprise Applications, Managed
//! Identities). Each carried an identical `export_rows` snapshot + `exporting`
//! double-submit guard + `do_export` spawn that saves via the OS dialog and
//! toasts the outcome; only the save command and the noun differed.

use std::future::Future;
use std::sync::Arc;

use leptos::prelude::*;

use azapptoolkit_dto::UiError;

use crate::state::{Session, use_session};

/// One list fetch's rows, each wrapped ONCE in an `Arc`, tagged with the tenant
/// the fetch ran for. The `Arc`s let every filter stage share the rows instead
/// of copying them ([`use_filtered_list`](crate::hooks::use_filtered_list));
/// the tenant lets the export snapshot taken from them refuse to save once
/// another tenant is active ([`ExportRows::publish`]).
pub struct TenantRows<T> {
    /// The tenant the fetch ran for; `None` when nobody was signed in.
    pub tenant_id: Option<String>,
    pub rows: Vec<Arc<T>>,
}

impl<T> TenantRows<T> {
    pub fn new(tenant_id: Option<&str>, rows: Vec<T>) -> Self {
        Self {
            tenant_id: tenant_id.map(str::to_owned),
            rows: rows.into_iter().map(Arc::new).collect(),
        }
    }
}

// By hand: a derive would demand `T: Clone`, and cloning these is refcount
// bumps (the list resource's own `.await` clones its value).
impl<T> Clone for TenantRows<T> {
    fn clone(&self) -> Self {
        Self {
            tenant_id: self.tenant_id.clone(),
            rows: self.rows.clone(),
        }
    }
}

/// What "Export" saves, and the tenant it was taken for.
struct Snapshot<T> {
    tenant_id: Option<String>,
    rows: Arc<Vec<T>>,
}

impl<T> Snapshot<T> {
    fn empty() -> Self {
        Self {
            tenant_id: None,
            rows: Arc::new(Vec::new()),
        }
    }
}

/// A list view's export snapshot (`Copy`). Created by [`use_list_export`] in the
/// view, filled by the loaded list body through [`publish`](Self::publish).
pub struct ExportRows<T: Send + Sync + 'static>(StoredValue<Snapshot<T>>);

impl<T: Send + Sync + 'static> Clone for ExportRows<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Send + Sync + 'static> Copy for ExportRows<T> {}

impl<T: Send + Sync + 'static> ExportRows<T> {
    /// Keeps the snapshot equal to `rows` (the body's on-screen row set, so
    /// "what you see is what you export") for as long as the calling component
    /// lives, tagged with `tenant_id`, the tenant the rows were fetched for;
    /// empties it when that component is disposed. Call it from the loaded list
    /// body, never from the view that owns the snapshot.
    ///
    /// The views stay mounted across a tenant switch, and an untagged snapshot
    /// outlived its rows: a new tenant whose own list was empty, failed to load
    /// or was still loading never mounted a body to replace it, so "Export"
    /// saved the previous tenant's list. That is cross-tenant leakage, the
    /// repo's #1 footgun. The tag, not the timing, keeps it out: emptying the
    /// snapshot on a fetch or an unmount alone depends on landing after the old
    /// body's last write (its memos re-run when the switch resets the filters),
    /// while a snapshot whose tenant is not the active one is never saved,
    /// whichever write landed last.
    pub fn publish(self, tenant_id: Option<String>, rows: Memo<Arc<Vec<T>>>) {
        Effect::new(move |_| self.set(tenant_id.clone(), rows.get()));
        // `set_value` is a no-op once the view's snapshot is itself disposed
        // (a sign-out unmounts both).
        let snapshot = self.0;
        on_cleanup(move || snapshot.set_value(Snapshot::empty()));
    }

    /// Replaces the snapshot with `rows`, taken for `tenant_id`. The building
    /// block of [`publish`](Self::publish), for a component that owns its rows
    /// for its whole life instead of per fetch (the Resource Access lenses):
    /// such a caller must itself drop its rows on a tenant switch, and pass the
    /// tenant those rows were loaded for.
    pub fn set(self, tenant_id: Option<String>, rows: Arc<Vec<T>>) {
        self.0.set_value(Snapshot { tenant_id, rows });
    }

    /// The rows to save: `None` unless the snapshot was taken for the active
    /// tenant and holds at least one row.
    fn for_active_tenant(self, session: Session) -> Option<Arc<Vec<T>>> {
        self.0.with_value(|s| {
            let current = s
                .tenant_id
                .as_deref()
                .is_some_and(|t| session.is_active_tenant(t));
            (current && !s.rows.is_empty()).then(|| Arc::clone(&s.rows))
        })
    }
}

/// Wires up the inventory export for a list view. `save` performs the IPC save
/// (it receives the current snapshot + the `"csv"`/`"json"` format and returns
/// the chosen path, or `None` when the user cancels the save dialog); `noun`
/// names the rows in the success toast (`"Exported N {noun} to …"`).
///
/// Returns `(export_rows, exporting, do_export)`:
/// - `export_rows` — the shared snapshot. Hand it to the loaded list body,
///   which [`publish`](ExportRows::publish)es its on-screen rows into it, so
///   "what you see is what you export" (the `Arc` makes each snapshot a pointer
///   copy, not a row-by-row clone).
/// - `exporting` — the in-flight guard, for disabling the export buttons.
/// - `do_export` — call with `"csv"` / `"json"` to run the export (no-op while
///   one is in flight, when the snapshot is empty, or when it was taken for a
///   tenant other than the active one).
// The return is a documented 3-tuple whose third member is an opaque closure;
// a type alias can't name the `impl Fn`, and a struct would leak the closure's
// unnameable type as a generic param at every call site for no readability win.
#[allow(clippy::type_complexity)]
pub fn use_list_export<T, F, Fut>(
    save: F,
    noun: &'static str,
) -> (
    ExportRows<T>,
    RwSignal<bool>,
    impl Fn(&'static str) + Copy + 'static,
)
where
    T: Send + Sync + 'static,
    F: Fn(Arc<Vec<T>>, &'static str) -> Fut + Copy + 'static,
    Fut: Future<Output = Result<Option<String>, UiError>> + 'static,
{
    let session = use_session();
    let export_rows = ExportRows(StoredValue::new(Snapshot::empty()));
    let exporting = RwSignal::new(false);
    let do_export = move |format: &'static str| {
        if exporting.get_untracked() {
            return;
        }
        let Some(rows) = export_rows.for_active_tenant(session) else {
            return;
        };
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
