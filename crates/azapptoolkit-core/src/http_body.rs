//! One definition of how much of an HTTP response body a client reads.
//!
//! The workspace `reqwest` has the `gzip` feature (Graph's list pages are
//! megabytes of JSON), and reqwest drops `Content-Length` when it inflates a
//! body, so the header cannot bound what a reply decodes to: a few KiB of gzip
//! can inflate to gigabytes, and `resp.bytes()` / `resp.text()` buffer all of
//! it. A running total of the **decoded** bytes is the real guard.
//!
//! [`BodyCap`] is that total as a pure accumulator: core has no `reqwest` or
//! `bytes` dependency, so each transport drives it from a short
//! `resp.chunk()` loop of its own. A success body past its cap is the
//! client's `Protocol` error (`protocol_error`, never retried — see
//! [`crate::http_retry::is_retryable_code`]); an error body is cut at
//! [`MAX_ERROR_BODY_BYTES`] instead, because the status decides the error and
//! `sanitize_error_body` keeps only its first 800 characters anyway. Pinned by
//! `repo_invariants/trust.rs` (`no_client_reads_an_unbounded_body`).

use std::fmt;

/// Decoded bytes a client accepts in one success body.
///
/// The largest legitimate reply is a 999-row `/applications` page with the
/// widest `$select` (both credential arrays, `owners` expanded), estimated at
/// about 30 MB in the worst case; 64 MiB leaves twice that. The estimate is not
/// a measurement — confirm it against real tenants before tightening.
pub const MAX_SUCCESS_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Bytes of an error body a client keeps: enough for any real Graph, ARM,
/// Key Vault or Exchange error, with the rest of a proxy's block page dropped
/// unread.
pub const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// A body that would decode past its cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyTooLarge {
    /// The cap it passed, in bytes.
    pub limit: usize,
}

impl fmt::Display for BodyTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const KIB: usize = 1024;
        const MIB: usize = 1024 * KIB;
        let limit = self.limit;
        if limit >= MIB && limit.is_multiple_of(MIB) {
            write!(f, "response body exceeds the {} MiB limit", limit / MIB)
        } else if limit >= KIB && limit.is_multiple_of(KIB) {
            write!(f, "response body exceeds the {} KiB limit", limit / KIB)
        } else {
            write!(f, "response body exceeds the {limit}-byte limit")
        }
    }
}

impl std::error::Error for BodyTooLarge {}

/// The running total of one body's decoded bytes against a cap.
#[derive(Debug, Clone)]
pub struct BodyCap {
    max: usize,
    declared: Option<u64>,
    read: usize,
}

impl BodyCap {
    /// An accumulator for one body of at most `max` decoded bytes.
    /// `content_length` is the response's declared length, if it has one —
    /// never trusted as the bound (it is absent on an inflated body and can
    /// understate any other), only used to refuse early.
    pub fn new(content_length: Option<u64>, max: usize) -> Self {
        Self {
            max,
            declared: content_length,
            read: 0,
        }
    }

    /// Refuses, before a byte is read, a body whose declared length is already
    /// past the cap.
    pub fn check_declared(&self) -> Result<(), BodyTooLarge> {
        let max = u64::try_from(self.max).unwrap_or(u64::MAX);
        match self.declared {
            Some(n) if n > max => Err(BodyTooLarge { limit: self.max }),
            _ => Ok(()),
        }
    }

    /// Records `len` more decoded bytes, failing once the running total would
    /// pass the cap — the strict reader's step (a success body).
    pub fn push(&mut self, len: usize) -> Result<(), BodyTooLarge> {
        match self.read.checked_add(len) {
            Some(total) if total <= self.max => {
                self.read = total;
                Ok(())
            }
            _ => Err(BodyTooLarge { limit: self.max }),
        }
    }

    /// Records as many of `len` bytes as still fit and returns that count —
    /// the truncating reader's step (an error body). A return below `len`
    /// means the cap is reached and the rest of the body is not worth reading.
    pub fn take(&mut self, len: usize) -> usize {
        let n = len.min(self.max - self.read);
        self.read += n;
        n
    }

    /// Decoded bytes recorded so far.
    pub fn read(&self) -> usize {
        self.read
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_accepts_a_body_that_ends_exactly_at_the_cap() {
        let mut cap = BodyCap::new(None, 10);
        assert_eq!(cap.push(4), Ok(()));
        assert_eq!(cap.push(6), Ok(()));
        assert_eq!(cap.read(), 10);
        assert_eq!(cap.push(0), Ok(()));
    }

    #[test]
    fn push_refuses_the_chunk_that_passes_the_cap_and_records_nothing_of_it() {
        let mut cap = BodyCap::new(None, 10);
        cap.push(8).unwrap();
        assert_eq!(cap.push(3), Err(BodyTooLarge { limit: 10 }));
        assert_eq!(cap.read(), 8);
        // A length that would overflow the running total is past any cap.
        assert_eq!(cap.push(usize::MAX), Err(BodyTooLarge { limit: 10 }));
    }

    #[test]
    fn the_declared_length_refuses_early_but_never_bounds_the_read() {
        assert_eq!(
            BodyCap::new(Some(11), 10).check_declared(),
            Err(BodyTooLarge { limit: 10 })
        );
        assert_eq!(BodyCap::new(Some(10), 10).check_declared(), Ok(()));
        assert_eq!(BodyCap::new(None, 10).check_declared(), Ok(()));
        // Declared small, decoded large: the running total still trips.
        let mut cap = BodyCap::new(Some(2), 10);
        assert_eq!(cap.check_declared(), Ok(()));
        assert_eq!(cap.push(11), Err(BodyTooLarge { limit: 10 }));
    }

    #[test]
    fn take_keeps_a_prefix_up_to_the_cap() {
        let mut cap = BodyCap::new(None, 10);
        assert_eq!(cap.take(6), 6);
        assert_eq!(cap.take(6), 4);
        assert_eq!(cap.take(6), 0);
        assert_eq!(cap.read(), 10);
    }

    #[test]
    fn the_refusal_names_the_limit_in_the_largest_whole_unit() {
        let text = |limit| BodyTooLarge { limit }.to_string();
        assert_eq!(
            text(MAX_SUCCESS_BODY_BYTES),
            "response body exceeds the 64 MiB limit"
        );
        assert_eq!(
            text(MAX_ERROR_BODY_BYTES),
            "response body exceeds the 64 KiB limit"
        );
        assert_eq!(text(1000), "response body exceeds the 1000-byte limit");
    }
}
