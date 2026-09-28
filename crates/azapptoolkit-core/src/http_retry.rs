//! Shared retry policy for the Graph, ARM, Key Vault and Exchange HTTP clients:
//! the budget constants, the jittered sleep / backoff helpers, and the loop
//! itself ([`with_retries`]).
//!
//! The loop used to be owned by each crate, on the grounds that they map HTTP
//! status to their own error enums differently and Graph has a throttle
//! observer. That difference is real, but it is per-*attempt* classification —
//! it does not require re-deriving the budget comparison, the sleep call and the
//! backoff advance in four files, where three of them can drift without anything
//! noticing. [`Attempt`] is the seam: the caller classifies, this module decides
//! whether and when to go round again.
//!
//! Classification itself is shared where the error enums are: ARM and Key Vault
//! both map a failed response through [`crate::http_error::failed_response`]
//! over the [`crate::http_error::HttpStatusError`] constructors the
//! `http_error_enum!` macro emits. Graph keeps its own mapping (the CAE 401
//! re-mint and the throttle observer), and Exchange its own because its
//! `Forbidden` is a struct variant.
//!
//! Graph keeps one loop of its own on top, for the CAE claims-challenge re-mint,
//! which is deliberately *outside* the transient budget.

/// The single definition of which failure classes are worth retrying, keyed by
/// the `ui_code()` every client error exposes.
///
/// Each of the four clients had its own `is_retryable` matching its own enum's
/// variants — four identical policies in four files, so adding a retryable
/// class (or noticing one was missing from just one client) was a four-file
/// edit with nothing to catch a miss. The per-crate `ui_code` table stays where
/// it is: mapping *variants* to a class is genuinely per-crate; deciding which
/// classes retry is not.
pub fn is_retryable_code(ui_code: &str) -> bool {
    matches!(ui_code, "throttled" | "server_error" | "network_error")
}

/// Connect budget every HTTP client builder sets (`.connect_timeout(…)`),
/// separate from its total `.timeout(…)`.
///
/// The total ceiling is sized for the *slowest legitimate response* (60s for a
/// 999-app Graph page or a 20-request `$batch`, 120s for a Log Analytics query).
/// Without a separate connect budget a host that accepts no connection — a
/// SYN-blackholed `management.azure.com`, `*.vault.azure.net`,
/// `outlook.office365.com` or Log Analytics host behind an egress allow-list
/// that admitted Graph only — burns that whole ceiling before the retry loop
/// even sees a failure, and does it once per attempt: 4 × 60s + 7s of backoff
/// ≈ 247s for an idempotent read. A TCP+TLS handshake to any Azure endpoint is
/// sub-second in practice, so 10s is generous, and the same read now fails in
/// 4 × 10s + 7s ≈ 47s.
///
/// One definition so the clients cannot drift: only Graph had one, and
/// `repo_invariants/trust.rs` (`every_http_client_has_a_connect_budget`) now
/// fails any `Client::builder()` that does not set it.
pub const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Maximum number of retries on transient failure (5xx, 429, network error).
pub const MAX_RETRIES: u32 = 3;

/// Initial backoff in milliseconds. Doubles on each transient retry up to
/// [`MAX_DELAY_MS`].
pub const BASE_DELAY_MS: u64 = 1000;

/// Upper bound on the *jittered exponential backoff* (the no-`Retry-After`
/// fallback). It does **not** cap an explicit `Retry-After`, which is honored
/// verbatim up to [`RETRY_AFTER_MAX_SECS`] — see [`sleep_before_retry`].
pub const MAX_DELAY_MS: u64 = 30_000;

/// Sanity ceiling for an explicit `Retry-After`, in seconds. Far above any
/// realistic Graph / ARM / Key Vault throttle (which is seconds to a few
/// minutes), this exists only to bound a pathological or buggy header so a
/// single retry can't hang the app for hours. It is deliberately **not** the
/// old [`MAX_DELAY_MS`] (30s) clamp, which truncated legitimate multi-minute
/// write-quota waits and caused premature re-throttling — Microsoft requires
/// waiting *exactly* the advertised `Retry-After`.
pub const RETRY_AFTER_MAX_SECS: u64 = 300;

/// Doubles `delay_ms` and clamps to [`MAX_DELAY_MS`]. Returns the value the
/// caller should use for its *next* attempt.
pub fn next_backoff_ms(delay_ms: u64) -> u64 {
    (delay_ms.saturating_mul(2)).min(MAX_DELAY_MS)
}

/// Parses a `Retry-After` header value (the integer-seconds form, which is
/// what AAD/Graph/Key Vault send). Returns `None` if the value is missing or
/// not a plain decimal number — the HTTP-date variant of Retry-After is rare
/// against these endpoints and is intentionally treated as missing here so
/// the caller falls back to the exponential backoff.
pub fn parse_retry_after_seconds(header_value: Option<&str>) -> Option<u64> {
    header_value?.trim().parse::<u64>().ok()
}

/// Milliseconds to wait for an explicit `Retry-After` of `secs` seconds:
/// honored verbatim (no jitter) and bounded only by the generous
/// [`RETRY_AFTER_MAX_SECS`] sanity ceiling — **not** the 30s
/// [`MAX_DELAY_MS`] backoff clamp. Pure so the honor-exactly behavior is
/// unit-testable; [`sleep_before_retry`] wraps the async sleep.
pub fn retry_after_millis(secs: u64) -> u64 {
    secs.min(RETRY_AFTER_MAX_SECS).saturating_mul(1000)
}

/// Waits before the next retry attempt. When the service sent an explicit
/// `Retry-After`, it is honored *exactly* (no jitter, no 30s clamp — only the
/// [`RETRY_AFTER_MAX_SECS`] sanity bound): Microsoft Graph / ARM / Key Vault
/// require waiting the advertised value, and write quotas legitimately return
/// multi-minute waits that retrying sooner would just re-throttle. Without a
/// header, falls back to jittered exponential backoff bounded by
/// [`MAX_DELAY_MS`] so concurrent callers don't synchronize on retry boundaries.
pub async fn sleep_before_retry(retry_after_secs: Option<u64>, fallback_ms: u64) {
    match retry_after_secs {
        Some(secs) => {
            use std::time::Duration;
            tokio::time::sleep(Duration::from_millis(retry_after_millis(secs))).await;
        }
        None => sleep_with_jitter(fallback_ms).await,
    }
}

/// Sleeps for `base_ms` plus 0–10% random jitter, capped at
/// [`MAX_DELAY_MS`]. Used between retry attempts so concurrent callers do
/// not synchronize on retry boundaries.
pub async fn sleep_with_jitter(base_ms: u64) {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    // Cheap deterministic-ish jitter: take a small fraction of the current
    // nanoseconds to add 0–10% of `base_ms`.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let jitter = (base_ms / 10).max(1);
    let extra = nanos % jitter;
    let total = base_ms.saturating_add(extra).min(MAX_DELAY_MS);
    tokio::time::sleep(Duration::from_millis(total)).await;
}

/// Why an attempt is being retried — the half of the classification the loop
/// cannot infer and the caller cannot act on alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryReason {
    /// An explicit throttle (429). The service rejected the request **before**
    /// doing any work, so replaying it is safe for any verb.
    Throttled,
    /// A network failure or a 5xx: there may be no response at all, so a write
    /// may already have committed server-side. Safe to replay only when the
    /// request is idempotent.
    Transient,
}

/// Whether a request can be safely re-sent when its outcome is unknown.
///
/// This distinction has to live at this seam. `with_retries` re-invokes the
/// caller's whole closure — request send included — and the transport routes
/// every verb through it, so a `POST /applications/{id}/addPassword` that hit a
/// connection reset or a 502 *after* Graph committed the write was replayed up
/// to three more times. The registration ended up with several client secrets
/// while the operator only ever saw the plaintext of the last one: an orphaned,
/// never-rotated credential, which is exactly the class of thing this tool
/// exists to surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    /// GET/HEAD/PUT/DELETE, or a POST that is semantically a read (a `$batch`
    /// of GET sub-requests, or an Exchange `Get-`/`Test-` cmdlet — every cmdlet
    /// is a POST). Every transient class is retried.
    Idempotent,
    /// A POST/PATCH that creates or mutates. Only [`RetryReason::Throttled`] is
    /// retried.
    NonIdempotent,
}

/// How one attempt ended, as the calling client classifies it.
///
/// The classification stays with the caller, because what a status means can
/// differ per client (Graph's CAE 401 re-mint and throttle observer, Exchange's
/// struct `Forbidden`); ARM and Key Vault share
/// [`crate::http_error::failed_response`]. Deciding *how many* times to retry
/// and *how long* to wait is never per-client.
pub enum Attempt<T, E> {
    /// Terminal, success or failure. Returned to the caller as-is.
    Done(Result<T, E>),
    /// Transient. Retried while budget remains **and** `reason` is safe for the
    /// request's [`RetryClass`]; once exhausted or refused, `err` is returned.
    /// `retry_after_secs` comes from the response header, honored exactly (see
    /// [`sleep_before_retry`]).
    Retry {
        reason: RetryReason,
        /// HTTP status; `None` = no response (a network failure). Logged
        /// instead of the error itself whenever there is one, because a
        /// `Server` error's Display embeds the response body.
        status: Option<u16>,
        retry_after_secs: Option<u64>,
        err: E,
    },
}

/// Runs `attempt` under the shared retry budget and backoff policy.
///
/// The four HTTP clients each open-coded this loop over the very primitives in
/// this module — same `MAX_RETRIES` comparison, same `sleep_before_retry`, same
/// `next_backoff_ms`, same `attempt += 1` — differing only in how they turned a
/// status into their own error and, for Graph, a throttle-observer callback.
/// Retry *semantics* are a policy, and a policy re-derived in four places is one
/// that can silently diverge in three of them. Exchange was the last client to
/// move — every Exchange call is a POST, so it takes its class from the cmdlet
/// verb — and `repo_invariants/trust.rs` now fails any source outside this
/// module that names the raw schedule primitives (`MAX_RETRIES`,
/// `next_backoff_ms`, `sleep_before_retry`, …).
///
/// `attempt` receives the zero-based attempt number (for its own logging) and
/// does its own send, status mapping and body reading; everything about
/// *whether and when to go round again* lives here.
///
/// `label` names the request in the log (`graph GET /v1.0/servicePrincipals/{id}/…`,
/// an Exchange cmdlet), so a 429 storm and a 5xx outage can be told apart and
/// traced to the fan-out that caused them. Every retry and the final give-up
/// log the [`RetryReason`] and the HTTP status; a failure with no response logs
/// its error (the URL plus its cause chain) instead, since it carries no body.
///
/// `class` is **required**, not defaulted: a caller that has not decided whether
/// its request may be replayed has not thought about the failure that matters,
/// and the safe answer differs per call site rather than per crate.
pub async fn with_retries<T, E, F, Fut>(
    label: &str,
    class: RetryClass,
    mut attempt: F,
) -> Result<T, E>
where
    E: std::fmt::Display,
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Attempt<T, E>>,
{
    let mut budget = RetryBudget::new();
    loop {
        match attempt(budget.attempt()).await {
            Attempt::Done(result) => return result,
            Attempt::Retry {
                reason,
                status,
                retry_after_secs,
                err,
            } => {
                // A transient failure leaves the outcome unknown, so replaying a
                // mutation risks committing it twice. A 429 does not: the
                // service refused before doing the work.
                if reason == RetryReason::Transient && class == RetryClass::NonIdempotent {
                    tracing::debug!(
                        label,
                        reason = ?reason,
                        status = ?status,
                        "not replaying a non-idempotent request after a transient failure"
                    );
                    return Err(err);
                }
                if !budget.may_retry() {
                    tracing::warn!(
                        label,
                        attempts = budget.attempt() + 1,
                        reason = ?reason,
                        status = ?status,
                        "retry budget exhausted; surfacing the last error"
                    );
                    return Err(err);
                }
                match status {
                    // Never `%err` when there is a response: a `Server` error's
                    // Display embeds the body, and bodies are not logged.
                    Some(status) => tracing::warn!(
                        label,
                        attempt = budget.attempt(),
                        reason = ?reason,
                        status,
                        retry_after_secs = ?retry_after_secs,
                        "transient failure; retrying"
                    ),
                    // No response, so no body: the error is the URL plus the
                    // cause chain (DNS, connect, TLS, proxy), which is the point.
                    None => tracing::warn!(
                        label,
                        attempt = budget.attempt(),
                        reason = ?reason,
                        cause = %err,
                        "transient failure; retrying"
                    ),
                }
                budget.wait(retry_after_secs).await;
            }
        }
    }
}

/// The retry *schedule*: how many attempts remain and how long the next wait is.
///
/// [`with_retries`] covers the common shape — one operation, retried whole — but
/// Graph's `$batch` retries only the **throttled sub-requests** of a partial
/// response, so its loop carries state across attempts and cannot be expressed
/// as `FnMut(u32) -> Future<Attempt<T, E>>`. It therefore open-coded the
/// schedule against the raw primitives: its own `attempt` counter, its own
/// `delay_ms`, its own `attempt < MAX_RETRIES` comparison. Same policy, second
/// implementation — so a change to the budget or the backoff curve reached the
/// four unified clients and not the batch path.
///
/// This is the piece both shapes genuinely share. `with_retries` is now a thin
/// wrapper over it, and the batch loop drives the same type.
pub struct RetryBudget {
    attempt: u32,
    delay_ms: u64,
}

impl Default for RetryBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl RetryBudget {
    pub fn new() -> Self {
        Self {
            attempt: 0,
            delay_ms: BASE_DELAY_MS,
        }
    }

    /// Zero-based number of the attempt about to run (or running).
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Whether another attempt is allowed. Does **not** consume the budget —
    /// call [`Self::wait`] to do that.
    pub fn may_retry(&self) -> bool {
        self.attempt < MAX_RETRIES
    }

    /// Sleeps out the backoff, then advances to the next attempt. An explicit
    /// `Retry-After` is honored exactly; only the no-header path uses jittered
    /// exponential backoff.
    pub async fn wait(&mut self, retry_after_secs: Option<u64>) {
        sleep_before_retry(retry_after_secs, self.delay_ms).await;
        self.attempt += 1;
        self.delay_ms = next_backoff_ms(self.delay_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    #[test]
    fn next_backoff_doubles_then_clamps() {
        assert_eq!(next_backoff_ms(BASE_DELAY_MS), 2000);
        assert_eq!(next_backoff_ms(2000), 4000);
        // Past MAX_DELAY_MS, it stays clamped.
        assert_eq!(next_backoff_ms(MAX_DELAY_MS), MAX_DELAY_MS);
        assert_eq!(next_backoff_ms(MAX_DELAY_MS * 4), MAX_DELAY_MS);
    }

    #[test]
    fn retry_after_is_honored_exactly_not_clamped_to_backoff() {
        // A few-second wait is honored verbatim.
        assert_eq!(retry_after_millis(10), 10_000);
        // A multi-minute write-quota wait is NOT truncated to MAX_DELAY_MS (30s) —
        // this is the whole point of the fix.
        assert_eq!(retry_after_millis(120), 120_000);
        assert!(retry_after_millis(120) > MAX_DELAY_MS);
        // Only a pathological/buggy value hits the generous sanity ceiling.
        assert_eq!(retry_after_millis(10_000), RETRY_AFTER_MAX_SECS * 1000);
        // No overflow on an absurd header value.
        assert_eq!(retry_after_millis(u64::MAX), RETRY_AFTER_MAX_SECS * 1000);
    }

    /// Virtual elapsed time across `f`. `start_paused` means sleeps resolve
    /// instantly while `Instant` still reports the full duration, so these
    /// assert the real wait without spending it.
    async fn virtual_elapsed(f: impl Future<Output = ()>) -> u64 {
        let start = tokio::time::Instant::now();
        f.await;
        start.elapsed().as_millis() as u64
    }

    #[tokio::test(start_paused = true)]
    async fn sleep_before_retry_honors_an_explicit_retry_after_exactly() {
        // The branch that matters most: an explicit Retry-After must be waited
        // verbatim — no jitter added, and NOT clamped to the 30s backoff bound.
        // Retrying sooner than advertised just re-throttles, and Microsoft
        // requires the exact wait. The pure helper was tested; that this is the
        // branch actually taken was not.
        assert_eq!(
            virtual_elapsed(sleep_before_retry(Some(10), BASE_DELAY_MS)).await,
            10_000
        );
        // A multi-minute write-quota wait survives intact, well past MAX_DELAY_MS.
        let long = virtual_elapsed(sleep_before_retry(Some(120), BASE_DELAY_MS)).await;
        assert_eq!(long, 120_000);
        assert!(long > MAX_DELAY_MS);
        // The fallback is ignored entirely when a header is present.
        assert_eq!(
            virtual_elapsed(sleep_before_retry(Some(5), 30_000)).await,
            5_000
        );
        // A pathological header is bounded by the sanity ceiling, not honored.
        assert_eq!(
            virtual_elapsed(sleep_before_retry(Some(u64::MAX), BASE_DELAY_MS)).await,
            RETRY_AFTER_MAX_SECS * 1000
        );
    }

    #[tokio::test(start_paused = true)]
    async fn sleep_before_retry_falls_back_to_jittered_backoff() {
        // No header ⇒ the jittered path: at least the base (never retry early)
        // and at most base + 10%, so concurrent callers desynchronize without
        // the delay drifting somewhere unrelated.
        let waited = virtual_elapsed(sleep_before_retry(None, BASE_DELAY_MS)).await;
        assert!(
            (BASE_DELAY_MS..=BASE_DELAY_MS + BASE_DELAY_MS / 10).contains(&waited),
            "expected {BASE_DELAY_MS}..={} ms, waited {waited}",
            BASE_DELAY_MS + BASE_DELAY_MS / 10
        );
        // The jittered fallback IS bounded by MAX_DELAY_MS (unlike Retry-After).
        let capped = virtual_elapsed(sleep_before_retry(None, MAX_DELAY_MS * 2)).await;
        assert_eq!(capped, MAX_DELAY_MS);
    }

    #[tokio::test(start_paused = true)]
    async fn with_retries_returns_a_terminal_outcome_without_waiting() {
        let mut calls = 0;
        let out: Result<&str, &str> = with_retries("test", RetryClass::Idempotent, |_| {
            calls += 1;
            async { Attempt::Done(Ok("ok")) }
        })
        .await;
        assert_eq!(out, Ok("ok"));
        assert_eq!(calls, 1, "a terminal outcome must not retry");

        // A terminal *failure* is equally final — only `Retry` goes round again.
        let mut calls = 0;
        let out: Result<&str, &str> = with_retries("test", RetryClass::Idempotent, |_| {
            calls += 1;
            async { Attempt::Done(Err("forbidden")) }
        })
        .await;
        assert_eq!(out, Err("forbidden"));
        assert_eq!(calls, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn with_retries_stops_after_max_retries_and_returns_the_last_error() {
        let mut calls = 0;
        let out: Result<(), &str> = with_retries("test", RetryClass::Idempotent, |n| {
            calls += 1;
            async move {
                Attempt::Retry {
                    reason: RetryReason::Transient,
                    status: Some(503),
                    retry_after_secs: None,
                    err: if n >= MAX_RETRIES {
                        "last"
                    } else {
                        "transient"
                    },
                }
            }
        })
        .await;
        assert_eq!(out, Err("last"));
        // The budget is MAX_RETRIES *retries*, so MAX_RETRIES + 1 attempts.
        assert_eq!(calls, MAX_RETRIES + 1);
    }

    /// The bug this class exists for: `with_retries` re-invokes the caller's
    /// whole closure, request send included. A `POST .../addPassword` that got
    /// a connection reset or a 502 *after* Graph committed the write was
    /// replayed up to three more times, leaving the registration with several
    /// client secrets while the operator saw the plaintext of only the last —
    /// an orphaned, never-rotated credential.
    #[tokio::test(start_paused = true)]
    async fn a_non_idempotent_request_is_not_replayed_after_a_transient_failure() {
        let mut calls = 0;
        let out: Result<(), &str> = with_retries("test", RetryClass::NonIdempotent, |_| {
            calls += 1;
            async {
                Attempt::Retry {
                    reason: RetryReason::Transient,
                    status: None,
                    retry_after_secs: None,
                    err: "reset",
                }
            }
        })
        .await;
        assert_eq!(out, Err("reset"));
        assert_eq!(calls, 1, "the write must be attempted exactly once");

        // The same failure IS replayed when the request is idempotent.
        let mut calls = 0;
        let out: Result<(), &str> = with_retries("test", RetryClass::Idempotent, |_| {
            calls += 1;
            async {
                Attempt::Retry {
                    reason: RetryReason::Transient,
                    status: None,
                    retry_after_secs: None,
                    err: "reset",
                }
            }
        })
        .await;
        assert_eq!(out, Err("reset"));
        assert_eq!(calls, MAX_RETRIES + 1);
    }

    /// A 429 is rejected *before* the service does the work, so replaying it
    /// cannot double-commit — every verb keeps its throttle retries, which is
    /// what stops this change turning a busy tenant into a wall of failures.
    #[tokio::test(start_paused = true)]
    async fn a_throttle_is_retried_for_every_verb() {
        for class in [RetryClass::Idempotent, RetryClass::NonIdempotent] {
            let mut calls = 0;
            let out: Result<(), &str> = with_retries("test", class, |_| {
                calls += 1;
                async {
                    Attempt::Retry {
                        reason: RetryReason::Throttled,
                        status: Some(429),
                        retry_after_secs: Some(1),
                        err: "429",
                    }
                }
            })
            .await;
            assert_eq!(out, Err("429"));
            assert_eq!(calls, MAX_RETRIES + 1, "{class:?} must retry a throttle");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn with_retries_backs_off_exponentially_and_honors_retry_after() {
        // Without a header: BASE, then doubling. With one: exactly the header.
        let waited = virtual_elapsed(async {
            let _: Result<(), &str> = with_retries("test", RetryClass::Idempotent, |_| async {
                Attempt::Retry {
                    reason: RetryReason::Transient,
                    status: None,
                    retry_after_secs: None,
                    err: "reset",
                }
            })
            .await;
        })
        .await;
        // 1000 + 2000 + 4000, each plus up to 10% jitter.
        let base = BASE_DELAY_MS + 2 * BASE_DELAY_MS + 4 * BASE_DELAY_MS;
        assert!(
            (base..=base + base / 10).contains(&waited),
            "expected ~{base} ms of backoff, waited {waited}"
        );

        let waited = virtual_elapsed(async {
            let _: Result<(), &str> = with_retries("test", RetryClass::Idempotent, |_| async {
                Attempt::Retry {
                    reason: RetryReason::Transient,
                    status: None,
                    retry_after_secs: Some(7),
                    err: "reset",
                }
            })
            .await;
        })
        .await;
        assert_eq!(
            waited,
            3 * 7_000,
            "an explicit Retry-After is honored exactly on every attempt"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn with_retries_can_succeed_on_a_later_attempt() {
        let mut calls = 0;
        let out: Result<&str, &str> = with_retries("test", RetryClass::Idempotent, |_| {
            calls += 1;
            let attempt = calls;
            async move {
                if attempt < 3 {
                    Attempt::Retry {
                        reason: RetryReason::Transient,
                        status: None,
                        retry_after_secs: None,
                        err: "transient",
                    }
                } else {
                    Attempt::Done(Ok("recovered"))
                }
            }
        })
        .await;
        assert_eq!(out, Ok("recovered"));
        assert_eq!(calls, 3);
    }

    #[test]
    fn parse_retry_after_seconds_handles_normal_input() {
        assert_eq!(parse_retry_after_seconds(Some("0")), Some(0));
        assert_eq!(parse_retry_after_seconds(Some("30")), Some(30));
        assert_eq!(parse_retry_after_seconds(Some(" 12 ")), Some(12));
    }

    #[test]
    fn parse_retry_after_seconds_ignores_garbage_and_http_dates() {
        assert_eq!(parse_retry_after_seconds(None), None);
        assert_eq!(parse_retry_after_seconds(Some("")), None);
        assert_eq!(parse_retry_after_seconds(Some("abc")), None);
        // HTTP-date variant of Retry-After — treated as missing.
        assert_eq!(
            parse_retry_after_seconds(Some("Wed, 21 Oct 2026 07:28:00 GMT")),
            None
        );
    }
}
