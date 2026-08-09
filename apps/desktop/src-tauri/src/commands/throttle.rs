//! Adaptive in-flight concurrency, shared by the long-running Graph fan-out
//! commands (the security audit and the DR backup).
//!
//! A [`ConcurrencyThrottle`] wired as the Graph client's
//! [`ThrottleObserver`](azapptoolkit_graph::ThrottleObserver) decrements the
//! in-flight cap on every 429 and gradually recovers it after a quiet window.
//! Callers pass `|| throttle.current_limit()` as the `cap` to
//! [`dispatch_capped`](crate::commands::dispatch::dispatch_capped), which
//! re-reads it between completions so the limit takes effect mid-run.
//!
//! Extracted from the audit command so the backup gets the same proven
//! back-off behaviour rather than a second, subtly different copy.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use azapptoolkit_graph::{GraphClient, ThrottleObserver};

/// Minimum in-flight floor: a single request still makes forward progress.
pub(crate) const MIN_CONCURRENCY: usize = 1;
/// Minimum seconds between cap halvings. The transport notifies the observer
/// on *every* 429 — including each retry of one hot request — so without a
/// window a single request retrying three times collapsed the cap 8→1 while
/// the other lanes were healthy.
const HALVE_WINDOW_SECS: u64 = 2;
/// Quiet seconds required before a permit is restored; also the recovery
/// loop's tick interval.
const RECOVERY_SECS: u64 = 30;

/// Shared mutable state for the tracker. Held by `Arc` so the background
/// recovery loop can adjust `current` while the run holds the tracker.
struct ThrottleInner {
    current: AtomicUsize,
    max: usize,
    /// Most recent throttle event (`tokio::time::Instant`, so paused-clock
    /// tests can drive it). Gates both the halve window and recovery quiet.
    last_throttle: std::sync::Mutex<Option<tokio::time::Instant>>,
}

/// Adjusts a fan-out's in-flight concurrency cap in response to Graph's 429s.
/// A throttle event halves the cap (floored at [`MIN_CONCURRENCY`]) at most
/// once per [`HALVE_WINDOW_SECS`]; one long-lived recovery loop restores one
/// permit per [`RECOVERY_SECS`] tick once the last tick's window was quiet,
/// capped at the initial value. (The previous spawn-a-timer-per-429 shape made
/// a throttle storm snap the cap from the floor back to max in a single burst
/// ~30s later, re-triggering the storm — a sawtooth.)
pub(crate) struct ConcurrencyThrottle {
    inner: Arc<ThrottleInner>,
}

impl ConcurrencyThrottle {
    /// Must be called from a Tokio runtime context (spawns the recovery loop).
    pub(crate) fn new(initial: usize) -> Self {
        let inner = Arc::new(ThrottleInner {
            current: AtomicUsize::new(initial.max(MIN_CONCURRENCY)),
            max: initial,
            last_throttle: std::sync::Mutex::new(None),
        });
        // The loop holds only a Weak: it exits when the run drops its last
        // tracker handle, so it can't outlive the command it serves.
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(RECOVERY_SECS)).await;
                let Some(inner) = weak.upgrade() else { break };
                let quiet = inner
                    .last_throttle
                    .lock()
                    .expect("tracker mutex poisoned")
                    .is_some_and(|t| t.elapsed().as_secs() >= RECOVERY_SECS);
                if quiet {
                    let prev = inner.current.load(Ordering::Acquire);
                    let next = (prev + 1).min(inner.max);
                    if next > prev {
                        inner.current.store(next, Ordering::Release);
                        tracing::info!(
                            from = prev,
                            to = next,
                            "throttle: recovering in-flight cap"
                        );
                    }
                }
            }
        });
        Self { inner }
    }

    pub(crate) fn current_limit(&self) -> usize {
        self.inner.current.load(Ordering::Acquire)
    }
}

impl ThrottleObserver for ConcurrencyThrottle {
    fn on_throttle(&self, retry_after_secs: Option<u64>) {
        let now = tokio::time::Instant::now();
        let within_window = {
            let mut last = self
                .inner
                .last_throttle
                .lock()
                .expect("tracker mutex poisoned");
            let within = last.is_some_and(|t| now.duration_since(t).as_secs() < HALVE_WINDOW_SECS);
            *last = Some(now);
            within
        };
        if within_window {
            // One halving per pressure window — retries of a single hot
            // request must not cascade the cap to the floor.
            return;
        }
        let prev = self.inner.current.load(Ordering::Acquire);
        let next = (prev / 2).max(MIN_CONCURRENCY);
        if next < prev {
            self.inner.current.store(next, Ordering::Release);
            tracing::info!(
                from = prev,
                to = next,
                ?retry_after_secs,
                "throttle: throttled, reducing in-flight cap"
            );
        }
    }
}

/// RAII guard that attaches `tracker` as `client`'s throttle observer and
/// detaches it on drop. However the command exits — including an early `?`
/// return — the shared per-tenant `GraphClient` is never left with a stale
/// observer that would halve its in-flight cap on a *later*, unrelated 429.
/// Hold the returned guard for the command's whole duration.
pub(crate) struct ThrottleGuard {
    client: Arc<GraphClient>,
}

impl ThrottleGuard {
    pub(crate) fn attach(client: Arc<GraphClient>, tracker: Arc<ConcurrencyThrottle>) -> Self {
        client.set_throttle_observer(tracker);
        Self { client }
    }
}

impl Drop for ThrottleGuard {
    fn drop(&mut self) {
        self.client.clear_throttle_observer();
    }
}

/// The adaptive-throttle + completion-counter pair every capped fan-out needs,
/// wired once.
///
/// Four commands each built this by hand — `bulk_delete_applications`,
/// `bulk_grant_permissions`, `run_audit` and `sweep_site_permissions` — as an
/// `Arc<ConcurrencyThrottle>`, a `ThrottleGuard::attach`, and an
/// `Arc<Mutex<usize>>` bumped inside the spawned task before emitting progress.
/// Four copies of the wiring is four places to get the *observer lifetime* and
/// the *cap re-read* right, and that scaffold is where `dispatch_capped`'s
/// `is_dead()` gating and the progress contract live.
///
/// Deliberately NOT a generic fan-out driver: the per-item work, the result
/// collection and the progress payload genuinely differ per command
/// (`BulkProgress` vs `AuditProgress`), and a driver abstract enough to cover
/// all of them would hide the gating rather than share it. This shares the
/// mechanical part and leaves the decisions visible at each call site.
pub(crate) struct FanOutMeter {
    tracker: Arc<ConcurrencyThrottle>,
    done: Arc<tokio::sync::Mutex<usize>>,
    /// Detaches the observer on drop; held, never read.
    _guard: ThrottleGuard,
}

impl FanOutMeter {
    /// Starts at `initial` in-flight and attaches the observer to `client`.
    pub(crate) fn attach(client: Arc<GraphClient>, initial: usize) -> Self {
        let tracker = Arc::new(ConcurrencyThrottle::new(initial));
        let _guard = ThrottleGuard::attach(client, tracker.clone());
        Self {
            tracker,
            done: Arc::new(tokio::sync::Mutex::new(0usize)),
            _guard,
        }
    }

    /// The live in-flight cap. `dispatch_capped` re-reads this between
    /// completions, so a mid-run halving takes effect without restarting.
    pub(crate) fn limit(&self) -> usize {
        self.tracker.current_limit()
    }

    /// The count so far. Read by a command that continues emitting progress
    /// after the fan-out has joined (the audit's sequential phase 2).
    pub(crate) async fn done(&self) -> usize {
        *self.done.lock().await
    }

    /// A handle the spawned tasks own. The meter itself is not `Clone` on
    /// purpose — the guard's lifetime is the command's, and cloning it would
    /// invite a task outliving the detach.
    pub(crate) fn ticker(&self) -> FanOutTicker {
        FanOutTicker {
            tracker: self.tracker.clone(),
            done: self.done.clone(),
        }
    }
}

/// The task-side half of a [`FanOutMeter`]: counts one completion and reports
/// the live cap alongside it.
#[derive(Clone)]
pub(crate) struct FanOutTicker {
    tracker: Arc<ConcurrencyThrottle>,
    done: Arc<tokio::sync::Mutex<usize>>,
}

impl FanOutTicker {
    /// Records one completed item and returns `(done_so_far, in_flight_cap)`.
    ///
    /// Both are read under the same lock acquisition so a progress event can
    /// never pair a count with a cap from a different instant — which is the
    /// kind of skew that makes a progress bar jump backwards.
    pub(crate) async fn tick(&self) -> (usize, usize) {
        let mut guard = self.done.lock().await;
        *guard += 1;
        let done = *guard;
        drop(guard);
        (done, self.tracker.current_limit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn on_throttle_halves_once_per_window_and_floors_at_one() {
        let tracker = ConcurrencyThrottle::new(8);
        tracker.on_throttle(None);
        assert_eq!(tracker.current_limit(), 4);
        // Same pressure window — the retries of one hot request must not
        // cascade the cap toward the floor.
        tracker.on_throttle(None);
        tracker.on_throttle(None);
        assert_eq!(tracker.current_limit(), 4);
        // Past the window: a fresh pressure event halves again, flooring at 1.
        tokio::time::advance(std::time::Duration::from_secs(HALVE_WINDOW_SECS + 1)).await;
        tracker.on_throttle(None);
        assert_eq!(tracker.current_limit(), 2);
        tokio::time::advance(std::time::Duration::from_secs(HALVE_WINDOW_SECS + 1)).await;
        tracker.on_throttle(None);
        assert_eq!(tracker.current_limit(), 1);
        tokio::time::advance(std::time::Duration::from_secs(HALVE_WINDOW_SECS + 1)).await;
        tracker.on_throttle(None);
        assert_eq!(tracker.current_limit(), MIN_CONCURRENCY);
    }

    /// Advances the paused clock, then yields so a timer-woken task (the
    /// tracker's recovery loop) actually runs — `advance()` alone only moves
    /// the timer wheel.
    async fn advance_and_run(secs: u64) {
        tokio::time::advance(std::time::Duration::from_secs(secs)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_restores_one_permit_per_quiet_tick_capped_at_initial() {
        let tracker = ConcurrencyThrottle::new(4);
        // Let the recovery loop register its first sleep before time moves, so
        // the tick timeline below is deterministic (t = 30, 60, 90, …).
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        tracker.on_throttle(None); // 4 → 2 at t≈0
        advance_and_run(HALVE_WINDOW_SECS + 1).await;
        tracker.on_throttle(None); // 2 → 1 at t≈3
        assert_eq!(tracker.current_limit(), 1);
        // First recovery tick (t=30) sees only ~27 quiet seconds — no permit
        // yet; recovery requires a full quiet window, not just elapsed time.
        advance_and_run(27).await;
        assert_eq!(tracker.current_limit(), 1);
        // Each subsequent quiet tick restores exactly one permit (never the
        // old burst-back-to-max sawtooth), capped at the initial value.
        advance_and_run(30).await;
        assert_eq!(tracker.current_limit(), 2);
        advance_and_run(30).await;
        assert_eq!(tracker.current_limit(), 3);
        advance_and_run(30).await;
        assert_eq!(tracker.current_limit(), 4);
        advance_and_run(30).await;
        assert_eq!(tracker.current_limit(), 4, "never recovers past initial");
    }
}
