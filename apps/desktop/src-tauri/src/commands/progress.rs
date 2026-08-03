//! One progress-event emitter for every long-running command.
//!
//! Seven command files each carried a byte-identical private helper — emit the
//! payload, log a warning if the webview is gone — differing only in the event
//! name and the payload type. The shape is the same everywhere because the
//! contract is: **progress is best-effort**. A failed emit must never abort the
//! run (the work is still valid; only the UI update is lost), so every one of
//! them logged and carried on, and any new one has to as well.

use serde::Serialize;
use tauri::{AppHandle, Emitter};

/// Emits a progress event to the webview, logging and continuing on failure.
///
/// `event` is the channel the frontend's `use_progress_stream` subscribes to
/// (`audit-progress`, `bulk-progress`, …); it is `&'static str` so the name is
/// always a literal at the call site rather than a computed string.
/// Generic over the Tauri runtime so tests can pass a `MockRuntime` handle
/// (`tauri::test::mock_app()`) instead of needing a real webview. Production
/// call sites are unaffected: bare `AppHandle` is `AppHandle<Wry>`.
pub(crate) fn emit_progress<R: tauri::Runtime, P: Serialize + Clone>(
    app_handle: &AppHandle<R>,
    event: &'static str,
    payload: P,
) {
    if let Err(err) = app_handle.emit(event, payload) {
        tracing::warn!(?err, event, "failed to emit progress event");
    }
}
