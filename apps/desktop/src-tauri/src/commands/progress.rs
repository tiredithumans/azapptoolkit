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

/// Where a long-running driver sends its progress events.
///
/// Production passes the command's `AppHandle`; tests pass
/// `commands::test_support::Recorder`, which keeps every `(event, payload)`
/// so a test can assert the progress sequence as well as the loop control.
///
/// This trait is the test seam, not a `tauri::Runtime` generic: `tauri`'s
/// `test` feature (for `tauri::test::mock_app()` / `MockRuntime`) is
/// **intentionally not enabled** — it broke the Windows test binary with
/// STATUS_ENTRYPOINT_NOT_FOUND, since enabling it alongside the WebView2
/// runtime mismatches an entrypoint at link time (see `d8d293e`). So a driver
/// that emits progress takes `&impl ProgressSink`, never a concrete
/// `&AppHandle`, which is what lets its loop run in a test at all.
///
/// The method is generic over the payload, so the trait is not dyn-compatible:
/// callers take `&impl ProgressSink` / `S: ProgressSink`, never `dyn`. It is
/// named `emit_event` rather than `emit` so the `AppHandle` impl does not
/// collide with `tauri::Emitter::emit`.
pub(crate) trait ProgressSink {
    /// Emits one progress event. Best-effort: an implementation logs and
    /// carries on, it never fails the run.
    fn emit_event<P: Serialize + Clone>(&self, event: &'static str, payload: P);
}

impl<R: tauri::Runtime> ProgressSink for AppHandle<R> {
    fn emit_event<P: Serialize + Clone>(&self, event: &'static str, payload: P) {
        if let Err(err) = Emitter::emit(self, event, payload) {
            tracing::warn!(?err, event, "failed to emit progress event");
        }
    }
}

/// Emits a progress event to `sink`, logging and continuing on failure.
///
/// `event` is the channel the frontend's `use_progress_stream` subscribes to —
/// always one of the `crate::dto::events` names, never a literal or a computed
/// string (`repo_invariants/ipc.rs` fails either), hence `&'static str`.
pub(crate) fn emit_progress<S: ProgressSink, P: Serialize + Clone>(
    sink: &S,
    event: &'static str,
    payload: P,
) {
    sink.emit_event(event, payload);
}

/// Rate limit for a progress stream whose ticks are not paced by the network.
///
/// The audit's per-app scoring is mostly CPU once its prefetches land, so a
/// 10,000-app run emitted 10,000 events in a few seconds — each one a
/// main-thread webview eval that the progress view re-renders on, at exactly
/// the moment Cancel should stay responsive. At most one event per
/// [`Self::INTERVAL`] gets through, plus any tick flagged `must` (the last
/// one, so the bar always lands on its final count).
pub(crate) struct EmitGate {
    start: std::time::Instant,
    /// Milliseconds since `start` of the last event let through;
    /// `u64::MAX` before the first.
    last_ms: std::sync::atomic::AtomicU64,
}

impl EmitGate {
    pub(crate) const INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

    pub(crate) fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
            last_ms: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    /// Whether this tick may be emitted. One caller wins per interval; `must`
    /// always passes.
    pub(crate) fn allow(&self, must: bool) -> bool {
        use std::sync::atomic::Ordering;
        let now = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        let interval = u64::try_from(Self::INTERVAL.as_millis()).unwrap_or(100);
        let last = self.last_ms.load(Ordering::Relaxed);
        let due = last == u64::MAX || now.saturating_sub(last) >= interval;
        if must {
            self.last_ms.store(now, Ordering::Relaxed);
            return true;
        }
        due && self
            .last_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_emit_gate_passes_the_first_tick_then_one_per_interval_and_every_must() {
        let gate = super::EmitGate::new();
        assert!(gate.allow(false), "the first tick shows the run started");
        assert!(!gate.allow(false), "a burst inside the interval is dropped");
        assert!(gate.allow(true), "the final tick always lands");
        std::thread::sleep(super::EmitGate::INTERVAL + std::time::Duration::from_millis(20));
        assert!(gate.allow(false));
    }

    use super::emit_progress;
    use crate::commands::test_support::Recorder;
    use crate::dto::bulk::BulkProgress;

    #[test]
    fn emit_progress_hands_the_sink_the_event_name_and_payload() {
        let rec = Recorder::default();
        emit_progress(
            &rec,
            "x-progress",
            BulkProgress {
                done: 1,
                total: 3,
                current_app: Some("a".into()),
                cancelled: false,
                in_flight_cap: Some(2),
            },
        );
        assert_eq!(rec.names(), ["x-progress"]);
        let got = rec.payloads::<BulkProgress>("x-progress");
        assert_eq!(got.len(), 1);
        assert_eq!(
            (
                got[0].done,
                got[0].total,
                got[0].current_app.as_deref(),
                got[0].cancelled,
                got[0].in_flight_cap
            ),
            (1, 3, Some("a"), false, Some(2))
        );
    }
}
