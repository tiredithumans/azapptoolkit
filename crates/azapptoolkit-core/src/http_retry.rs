//! Shared retry knobs and timing helpers used by the Graph, Key Vault, and
//! Exchange HTTP clients. The full retry *loop* is still owned by each crate
//! because they map HTTP status -> their own error enum differently and each
//! has its own observer hooks. This module only consolidates the pieces that
//! were copied verbatim across all three: the budget constants and the
//! jittered sleep / backoff helpers.

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

#[cfg(test)]
mod tests {
    use super::*;

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
