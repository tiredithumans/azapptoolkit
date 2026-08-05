//! Bounded-concurrency task dispatch shared by the long-running fan-out
//! commands (security audit, site sweep, mailbox probe, bulk credential
//! sweep).
//!
//! Exists because the per-command backpressure loops each awaited a completed
//! task with `let _ = futures.next().await` to enforce their in-flight cap —
//! silently dropping one finished result per dispatch past the cap, so any
//! run larger than the cap returned only the final in-flight handful. Routing
//! every loop through this driver makes that impossible by construction.

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::task::{JoinError, JoinHandle};

use crate::dto::UiError;

/// Latches "the session is dead" across a [`dispatch_capped`] run.
///
/// A re-auth-fatal failure means every remaining item would fail identically,
/// so the run must stop rather than return a silently partial result the UI
/// presents as complete — in a DR backup or a `Sites.Selected` sweep that is a
/// wrong answer, not a slow one. `UiError::is_reauth_fatal` is the single
/// definition of the codes (azapptoolkit-dto, shared by both tiers).
///
/// An `Arc<AtomicBool>` rather than a `Cell`: the enclosing `#[tauri::command]`
/// future must be `Send` (a `Cell` held across an await is not), and cloning it
/// into a spawned task lets a fan-out whose per-item errors never reach the
/// collector — a DR backup chunk, say — report the dead session itself.
#[derive(Clone, Default)]
pub(crate) struct SessionDead(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl SessionDead {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn get(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Gate `dispatch_capped`'s `spawn` on this: returning `None` stops
    /// dispatch while letting in-flight tasks drain into `collect`.
    pub(crate) fn is_dead(&self) -> bool {
        self.get()
    }

    /// Records a per-item failure. Returns `true` when it ended the session.
    pub(crate) fn note(&self, err: impl Into<UiError>) -> bool {
        let fatal = err.into().is_reauth_fatal();
        if fatal {
            self.set();
        }
        fatal
    }

    /// Records a failure held only by reference, via its stable `ui_code()`.
    /// Routed through [`Self::note`] so `UiError::is_reauth_fatal` stays the
    /// single definition of which codes are fatal.
    pub(crate) fn note_code(&self, code: &str) -> bool {
        self.note(UiError::new(code, String::new(), false))
    }

    /// Records an already-classified verdict, for a task that could only send
    /// the boolean back (its error type didn't survive the task boundary).
    pub(crate) fn note_fatal(&self, fatal: bool) -> bool {
        if fatal {
            self.set();
        }
        fatal
    }

    /// The error a command should return instead of a partial result.
    pub(crate) fn err(&self, what: &str) -> UiError {
        UiError::new(
            "refresh_missing",
            format!(
                "the session ended partway through {what}, so the result would be incomplete. \
                 Sign in again and re-run it."
            ),
            false,
        )
    }
}

/// Spawns one task per item with at most `cap()` in flight, feeding **every**
/// completed task to `collect` — including the ones awaited just to enforce
/// the cap. `cap` is re-read between completions so an adaptive limit (the
/// audit's throttle tracker) takes effect mid-run. `spawn` returning `None`
/// stops dispatch (the per-item cancellation check); tasks already in flight
/// still drain into `collect`. Returns `true` when dispatch stopped early —
/// callers latch this rather than re-reading a shared cancel flag that a
/// concurrent command may have reset.
pub(crate) async fn dispatch_capped<I, T>(
    items: impl IntoIterator<Item = I>,
    cap: impl Fn() -> usize,
    mut spawn: impl FnMut(I) -> Option<JoinHandle<T>>,
    mut collect: impl FnMut(Result<T, JoinError>),
) -> bool {
    let mut in_flight = FuturesUnordered::new();
    let mut stopped_early = false;
    for item in items {
        let Some(handle) = spawn(item) else {
            stopped_early = true;
            break;
        };
        in_flight.push(handle);
        while in_flight.len() >= cap().max(1) {
            let Some(joined) = in_flight.next().await else {
                break;
            };
            collect(joined);
        }
    }
    while let Some(joined) = in_flight.next().await {
        collect(joined);
    }
    stopped_early
}

/// Resolves a batched Graph read, degrading to per-item reads when the whole
/// batch failed.
///
/// The batched fan-out contract is that a whole-batch failure costs the batch,
/// not the run: the caller falls back to individual reads so one bad `$batch`
/// POST can't lose a chunk of a backup. That block — match, log, loop, collect —
/// was written out six times in `backup.rs` alone, each differing only in the
/// noun and which client method to call per item.
///
/// `per_item` is only invoked on the whole-batch failure path, so the happy path
/// costs nothing.
pub(crate) async fn batch_or_serial<T, I, F, Fut>(
    what: &str,
    ids: &[I],
    batched: Result<Vec<T>, azapptoolkit_graph::GraphError>,
    per_item: F,
) -> Vec<T>
where
    // Owned item, not `&I`: the per-item Graph calls take `&str` and their
    // futures borrow it, so a `Fn(&I) -> Fut` bound cannot name a lifetime that
    // outlives the closure call. Callers pass an `async move` block that owns
    // its id instead.
    I: Clone,
    F: Fn(I) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    match batched {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, what, "batch failed; per-item fallback");
            let mut v = Vec::with_capacity(ids.len());
            for id in ids {
                v.push(per_item(id.clone()).await);
            }
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression for the dropped-results bug: a result that completes while
    // the backpressure wait enforces the cap must reach `collect`. The old
    // loops discarded it, so a run larger than the cap returned only the
    // final in-flight handful.
    #[tokio::test]
    async fn collects_every_result_past_the_cap() {
        let mut got: Vec<u32> = Vec::new();
        let stopped = dispatch_capped(
            0..50u32,
            || 4,
            |i| Some(tokio::spawn(async move { i })),
            |joined| got.push(joined.expect("task panicked")),
        )
        .await;
        assert!(!stopped);
        got.sort_unstable();
        assert_eq!(got, (0..50).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn declined_spawn_stops_dispatch_but_drains_in_flight() {
        let mut got: Vec<u32> = Vec::new();
        let stopped = dispatch_capped(
            0..50u32,
            || 4,
            |i| (i < 10).then(|| tokio::spawn(async move { i })),
            |joined| got.push(joined.expect("task panicked")),
        )
        .await;
        assert!(stopped);
        got.sort_unstable();
        assert_eq!(got, (0..10).collect::<Vec<_>>());
    }

    // The cap is the driver's whole reason to exist (backpressure against
    // Graph 429s) — `collects_every_result_past_the_cap` alone would still
    // pass if the cap were ignored and all 50 tasks spawned at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn in_flight_never_exceeds_the_cap() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let in_flight = Arc::new(AtomicUsize::new(0));
        let high_water = Arc::new(AtomicUsize::new(0));
        let mut got = 0usize;
        dispatch_capped(
            0..64u32,
            || 4,
            |i| {
                let in_flight = in_flight.clone();
                let high_water = high_water.clone();
                Some(tokio::spawn(async move {
                    let now = in_flight.fetch_add(1, Ordering::AcqRel) + 1;
                    high_water.fetch_max(now, Ordering::AcqRel);
                    tokio::task::yield_now().await; // let siblings overlap
                    in_flight.fetch_sub(1, Ordering::AcqRel);
                    i
                }))
            },
            |joined| {
                joined.expect("task panicked");
                got += 1;
            },
        )
        .await;
        assert_eq!(got, 64);
        assert!(
            high_water.load(Ordering::Acquire) <= 4,
            "backpressure must hold in-flight at the cap (saw {})",
            high_water.load(Ordering::Acquire)
        );
    }

    #[tokio::test]
    async fn a_panicked_task_reaches_collect_as_a_join_error_without_stalling() {
        let (mut ok, mut panics) = (0usize, 0usize);
        let stopped = dispatch_capped(
            0..10u32,
            || 2,
            |i| {
                Some(tokio::spawn(async move {
                    assert!(i != 3, "boom");
                    i
                }))
            },
            |joined| match joined {
                Ok(_) => ok += 1,
                Err(e) if e.is_panic() => panics += 1,
                Err(e) => panic!("unexpected join error: {e:?}"),
            },
        )
        .await;
        assert!(!stopped);
        assert_eq!((ok, panics), (9, 1));
    }
}
