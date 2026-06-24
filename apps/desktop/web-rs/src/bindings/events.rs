//! Streamed Tauri events emitted by long-running backend operations. Each
//! helper returns a `futures::Stream` of payload values; the stream
//! auto-cleans its underlying listener when dropped.

use futures::{Stream, StreamExt};
use tauri_sys::event::{Event, listen};

use super::audit::AuditProgress;
use super::bulk::BulkProgress;
use super::permission_tester::MailboxProbeProgress;
use super::sharepoint::SiteSweepProgress;

/// Subscribes to `audit-progress`. Yields the payload directly (the
/// surrounding `Event` envelope is unwrapped internally since callers don't
/// care about the listener id or event name).
pub async fn audit_progress() -> Result<impl Stream<Item = AuditProgress>, JsErrString> {
    let stream = listen::<AuditProgress>("audit-progress")
        .await
        .map_err(|e| JsErrString(format!("{e:?}")))?;
    Ok(stream.map(|ev: Event<AuditProgress>| ev.payload))
}

pub async fn bulk_progress() -> Result<impl Stream<Item = BulkProgress>, JsErrString> {
    let stream = listen::<BulkProgress>("bulk-progress")
        .await
        .map_err(|e| JsErrString(format!("{e:?}")))?;
    Ok(stream.map(|ev: Event<BulkProgress>| ev.payload))
}

/// Subscribes to `backup-progress`. The DR backup fan-out reuses the
/// [`BulkProgress`] shape but on its own channel, so a backup's progress can't
/// be confused with a concurrent bulk run's.
pub async fn backup_progress() -> Result<impl Stream<Item = BulkProgress>, JsErrString> {
    let stream = listen::<BulkProgress>("backup-progress")
        .await
        .map_err(|e| JsErrString(format!("{e:?}")))?;
    Ok(stream.map(|ev: Event<BulkProgress>| ev.payload))
}

/// Subscribes to `restore-progress` (the DR restore fan-out, [`BulkProgress`]
/// shape on its own channel).
pub async fn restore_progress() -> Result<impl Stream<Item = BulkProgress>, JsErrString> {
    let stream = listen::<BulkProgress>("restore-progress")
        .await
        .map_err(|e| JsErrString(format!("{e:?}")))?;
    Ok(stream.map(|ev: Event<BulkProgress>| ev.payload))
}

pub async fn site_sweep_progress() -> Result<impl Stream<Item = SiteSweepProgress>, JsErrString> {
    let stream = listen::<SiteSweepProgress>("site-sweep-progress")
        .await
        .map_err(|e| JsErrString(format!("{e:?}")))?;
    Ok(stream.map(|ev: Event<SiteSweepProgress>| ev.payload))
}

pub async fn mailbox_probe_progress()
-> Result<impl Stream<Item = MailboxProbeProgress>, JsErrString> {
    let stream = listen::<MailboxProbeProgress>("mailbox-probe-progress")
        .await
        .map_err(|e| JsErrString(format!("{e:?}")))?;
    Ok(stream.map(|ev: Event<MailboxProbeProgress>| ev.payload))
}

/// Lossy `String`-typed wrapper for `tauri_sys::Error`. The underlying error
/// type does not implement `Clone`/`PartialEq`, so we capture its `Debug` form
/// at the point of failure and let callers display it.
#[derive(Debug, Clone)]
pub struct JsErrString(pub String);
