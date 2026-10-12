//! Partitioned tenant-wide directory scans: a whole collection read as 16
//! concurrent `startswith(appId,'h')` slices instead of one serial chain of
//! `@odata.nextLink`s.
//!
//! Paging is serial by construction (each request needs the previous
//! response's `nextLink`), and `/servicePrincipals` is documented at 100 rows a
//! page whatever `$top` asks for, so a cold launch in a large tenant waited on
//! one long chain before any list could render. Every `appId` is a GUID, so its
//! first hex digit puts each row in exactly one of 16 disjoint slices; reading
//! them concurrently divides the chain by up to 16.
//!
//! Correctness comes first: this feeds a security tool's inventory, and a
//! dropped slice would be a silently missing app.
//! - Graph documents `startswith` on `appId` for `/servicePrincipals` but not
//!   for `/applications`, so support is learned at runtime per collection: a
//!   400 in plain mode retries once as an advanced query, and a 400 there pins
//!   the collection to the serial read for this client (one per tenant,
//!   dropped by the sign-out sweep).
//! - The merged result is checked before it is trusted ([`merge_slices`]):
//!   every row under its slice's prefix, every row of the unfiltered first page
//!   present, and the total within a small tolerance of `/$count`. Anything off
//!   falls back to the serial read, logs a `warn`, and pins the collection
//!   serial.

use std::collections::HashSet;

use super::*;

/// What a collection has shown it accepts, learned per [`GraphClient`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SliceMode {
    /// `startswith(appId,…)` slices work as a plain read.
    Plain,
    /// They work only as an advanced query (`$count=true`, eventual).
    Advanced,
    /// Rejected, or failed validation: read serially.
    Serial,
}

/// The slice prefixes: a GUID's first character is one lowercase hex digit.
const SLICE_PREFIXES: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Below this many pages in all, the serial chain is no longer than the
/// partitioned read's fan-out, so the scan stays serial.
const MIN_PAGES_TO_PARTITION: u64 = 4;

/// A row of a collection a partitioned scan can split and de-duplicate.
pub(crate) trait DirectoryRow {
    fn object_id(&self) -> &str;
    fn app_id(&self) -> &str;
}

impl DirectoryRow for Application {
    fn object_id(&self) -> &str {
        &self.id
    }
    fn app_id(&self) -> &str {
        &self.app_id
    }
}

impl DirectoryRow for ServicePrincipal {
    fn object_id(&self) -> &str {
        &self.id
    }
    fn app_id(&self) -> &str {
        &self.app_id
    }
}

/// One slice's rows, read to exhaustion or to the scan's cap.
pub(crate) struct Slice<T> {
    pub(crate) prefix: char,
    pub(crate) rows: Vec<T>,
    pub(crate) truncated: bool,
}

impl GraphClient {
    /// Every row of the collection at `path`, up to `cap`, and whether the cap
    /// (or the page limit) cut it short: the tenant-wide scans' read.
    ///
    /// `params` is the caller's whole query (`$select`, `$top`); it must not
    /// carry a `$filter`, `$search` or `$expand`. Page one and `/$count` are
    /// fetched together. A collection that fits in a few pages, has no count,
    /// is far past `cap`, or has shown it cannot be sliced reads serially from
    /// page one; otherwise the rest is read as 16 concurrent `appId` slices.
    /// Writes the scan's `azapptoolkit::graph::scan` line.
    pub(crate) async fn scan_directory_capped<T>(
        &self,
        scan: &'static str,
        path: &'static str,
        params: &[(&str, &str)],
        cap: usize,
    ) -> Result<(Vec<T>, bool)>
    where
        T: DeserializeOwned + DirectoryRow + Send,
    {
        let started = std::time::Instant::now();
        let known = self.slice_mode(path);
        // The count decides whether slicing pays; fetching it beside page one
        // costs no round trip. Skipped where slicing is known not to work.
        let (probe, count) = if known == Some(SliceMode::Serial) {
            (self.get_json::<Paged<T>>(path, params, false).await, None)
        } else {
            let (probe, count) = futures::future::join(
                self.get_json::<Paged<T>>(path, params, false),
                self.count_collection(path),
            )
            .await;
            (probe, Some(count))
        };
        let probe = probe?;
        let first_page = (probe.items.len(), started.elapsed());
        let (rows, truncated, strategy) = self
            .finish_scan(path, params, probe, count, known, cap)
            .await?;
        log_directory_scan(scan, strategy, started, first_page, rows.len(), truncated);
        Ok((rows, truncated))
    }

    /// Everything after page one: serial, or sliced and validated. Returns the
    /// rows, the truncation flag and the strategy the scan line reports.
    async fn finish_scan<T>(
        &self,
        path: &'static str,
        params: &[(&str, &str)],
        probe: Paged<T>,
        count: Option<Result<u64>>,
        known: Option<SliceMode>,
        cap: usize,
    ) -> Result<(Vec<T>, bool, &'static str)>
    where
        T: DeserializeOwned + DirectoryRow + Send,
    {
        if probe.next_link.is_none() {
            return self.serial_rest(probe, cap, "single_page").await;
        }
        let count = match count {
            None => return self.serial_rest(probe, cap, "serial").await,
            Some(Err(err)) => {
                tracing::debug!(
                    target: "azapptoolkit::graph::scan",
                    path,
                    code = %err.ui_code(),
                    "no /$count for this collection; reading serially"
                );
                return self.serial_rest(probe, cap, "serial_no_count").await;
            }
            Some(Ok(count)) => count,
        };
        let page_size = u64::try_from(probe.items.len().max(1)).unwrap_or(u64::MAX);
        if count.div_ceil(page_size) < MIN_PAGES_TO_PARTITION {
            return self.serial_rest(probe, cap, "serial_small").await;
        }
        // Far past the cap the slices would hold up to 16 × cap rows before
        // truncating, so a tenant that large keeps today's serial read.
        if count > u64::try_from(cap).unwrap_or(u64::MAX).saturating_mul(2) {
            return self.serial_rest(probe, cap, "serial_over_cap").await;
        }

        let modes: &[SliceMode] = match known {
            Some(SliceMode::Plain) => &[SliceMode::Plain],
            Some(SliceMode::Advanced) => &[SliceMode::Advanced],
            _ => &[SliceMode::Plain, SliceMode::Advanced],
        };
        for &mode in modes {
            let slices = match self.read_slices::<T>(path, params, cap, mode).await {
                Ok(slices) => slices,
                Err(GraphError::Api { status: 400, .. }) => {
                    tracing::debug!(
                        target: "azapptoolkit::graph::scan",
                        path,
                        ?mode,
                        "appId slices rejected (400)"
                    );
                    continue;
                }
                Err(err) => return Err(err),
            };
            match merge_slices(&probe.items, slices, count, cap) {
                Ok((rows, truncated)) => {
                    self.set_slice_mode(path, mode);
                    let strategy = match mode {
                        SliceMode::Advanced => "partitioned_advanced",
                        _ => "partitioned",
                    };
                    return Ok((rows, truncated, strategy));
                }
                Err(reason) => {
                    tracing::warn!(
                        target: "azapptoolkit::graph::scan",
                        path,
                        reason,
                        count,
                        "partitioned read failed validation; reading serially"
                    );
                    self.set_slice_mode(path, SliceMode::Serial);
                    return self.serial_rest(probe, cap, "serial_fallback").await;
                }
            }
        }
        self.set_slice_mode(path, SliceMode::Serial);
        self.serial_rest(probe, cap, "serial_fallback").await
    }

    /// The serial read: follow page one's `nextLink`s up to `cap`.
    async fn serial_rest<T: DeserializeOwned>(
        &self,
        probe: Paged<T>,
        cap: usize,
        strategy: &'static str,
    ) -> Result<(Vec<T>, bool, &'static str)> {
        let (rows, truncated) = self.collect_all_pages_capped(probe, cap, false).await?;
        Ok((rows, truncated, strategy))
    }

    /// The 16 slices, read concurrently, in prefix order. Each slice pages
    /// serially with the consistency its own page one was sent with.
    ///
    /// `try_join_all`, not `stream::buffered`: the stream adapter's
    /// higher-ranked lifetimes break the Send inference the Tauri command
    /// handlers need (see `batch.rs`).
    async fn read_slices<T>(
        &self,
        path: &'static str,
        params: &[(&str, &str)],
        cap: usize,
        mode: SliceMode,
    ) -> Result<Vec<Slice<T>>>
    where
        T: DeserializeOwned + Send,
    {
        let advanced = mode == SliceMode::Advanced;
        futures::future::try_join_all(SLICE_PREFIXES.iter().map(|&prefix| async move {
            let filter = format!("startswith(appId,'{prefix}')");
            let mut query: Vec<(&str, &str)> = params.to_vec();
            query.push(("$filter", filter.as_str()));
            if advanced {
                query.push(("$count", "true"));
            }
            let page: Paged<T> = self.get_json(path, &query, advanced).await?;
            let (rows, truncated) = self.collect_all_pages_capped(page, cap, advanced).await?;
            Ok::<_, GraphError>(Slice {
                prefix,
                rows,
                truncated,
            })
        }))
        .await
    }

    /// `GET {path}/$count`: the collection's size from the advanced-query
    /// index (eventual, so it can lag a just-written object). Graph answers in
    /// `text/plain`, sometimes behind a UTF-8 byte-order mark.
    pub(crate) async fn count_collection(&self, path: &str) -> Result<u64> {
        let bytes = self
            .send_core(Method::GET, &format!("{path}/$count"), &[], true, None)
            .await?;
        let text =
            std::str::from_utf8(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))?;
        text.trim_start_matches('\u{feff}')
            .trim()
            .parse::<u64>()
            .map_err(|e| GraphError::Deserialize(format!("$count: {e}")))
    }

    fn slice_mode(&self, path: &'static str) -> Option<SliceMode> {
        self.slice_modes.lock().get(path).copied()
    }

    fn set_slice_mode(&self, path: &'static str, mode: SliceMode) {
        self.slice_modes.lock().insert(path, mode);
    }
}

/// Merges the slices in prefix order and checks the result can be trusted.
/// `Err` names the failed check; the caller then reads serially.
///
/// - `slice_page_limit`: a slice stopped at the page limit below the cap (a
///   cyclic or pathologically empty `nextLink` chain), so it is incomplete.
/// - `prefix_mismatch`: a row outside its slice's prefix — Graph ignored or
///   misread the filter, so the slices are not disjoint and complete.
/// - `probe_row_missing`: a row of the unfiltered page one is in no slice.
/// - `count_shortfall`: fewer rows than `/$count` beyond the tolerance
///   (`max(2, count / 1000)`, for the index's lag). Skipped when the cap cut a
///   slice short, since the union is then short by design.
///
/// Rows are de-duplicated by object id (first occurrence wins), then cut to
/// `cap`; the flag is set when rows existed past it.
pub(crate) fn merge_slices<T: DirectoryRow>(
    probe: &[T],
    slices: Vec<Slice<T>>,
    count: u64,
    cap: usize,
) -> std::result::Result<(Vec<T>, bool), &'static str> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut rows: Vec<T> = Vec::new();
    let mut any_truncated = false;
    for slice in slices {
        if slice.truncated && slice.rows.len() < cap {
            return Err("slice_page_limit");
        }
        any_truncated |= slice.truncated;
        for row in slice.rows {
            let first = row.app_id().chars().next().map(|c| c.to_ascii_lowercase());
            if first != Some(slice.prefix) {
                return Err("prefix_mismatch");
            }
            if seen.insert(row.object_id().to_owned()) {
                rows.push(row);
            }
        }
    }
    if probe.iter().any(|r| !seen.contains(r.object_id())) {
        return Err("probe_row_missing");
    }
    let union = u64::try_from(rows.len()).unwrap_or(u64::MAX);
    if !any_truncated && union.saturating_add((count / 1000).max(2)) < count {
        return Err("count_shortfall");
    }
    let truncated = any_truncated || rows.len() > cap;
    rows.truncate(cap);
    Ok((rows, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(id: &str, app_id: &str) -> ServicePrincipal {
        serde_json::from_value(serde_json::json!({ "id": id, "appId": app_id }))
            .expect("service principal")
    }

    fn slice(prefix: char, rows: Vec<ServicePrincipal>) -> Slice<ServicePrincipal> {
        Slice {
            prefix,
            rows,
            truncated: false,
        }
    }

    fn ids(rows: &[ServicePrincipal]) -> Vec<&str> {
        rows.iter().map(|r| r.id.as_str()).collect()
    }

    #[test]
    fn merges_in_prefix_order_and_drops_duplicates() {
        let probe = vec![sp("a1", "a0")];
        let slices = vec![
            slice('0', vec![sp("z1", "01"), sp("z2", "0f")]),
            slice('a', vec![sp("a1", "a0"), sp("a1", "a0")]),
            slice('f', vec![sp("f1", "F9")]),
        ];
        let (rows, truncated) = merge_slices(&probe, slices, 4, 100).expect("valid");
        assert_eq!(ids(&rows), ["z1", "z2", "a1", "f1"]);
        assert!(!truncated);
    }

    #[test]
    fn a_row_outside_its_prefix_fails() {
        let slices = vec![slice('1', vec![sp("x", "2abc")])];
        assert_eq!(
            merge_slices(&[], slices, 1, 100).map(|_| ()),
            Err("prefix_mismatch")
        );
    }

    #[test]
    fn a_missing_probe_row_fails() {
        let probe = vec![sp("p", "3000")];
        let slices = vec![slice('3', vec![sp("q", "3001")])];
        assert_eq!(
            merge_slices(&probe, slices, 1, 100).map(|_| ()),
            Err("probe_row_missing")
        );
    }

    #[test]
    fn a_count_shortfall_past_the_tolerance_fails() {
        let rows: Vec<_> = (0..10).map(|i| sp(&format!("o{i}"), "7a")).collect();
        // Within the tolerance of 2: passes.
        assert!(merge_slices(&[], vec![slice('7', rows.clone())], 12, 100).is_ok());
        // Three short: fails.
        assert_eq!(
            merge_slices(&[], vec![slice('7', rows)], 13, 100).map(|_| ()),
            Err("count_shortfall")
        );
    }

    #[test]
    fn the_cap_is_exact_and_flags_truncation() {
        let a: Vec<_> = (0..3).map(|i| sp(&format!("a{i}"), "a1")).collect();
        let b: Vec<_> = (0..3).map(|i| sp(&format!("b{i}"), "b1")).collect();
        let (rows, truncated) =
            merge_slices(&[], vec![slice('a', a), slice('b', b)], 6, 4).expect("valid");
        assert_eq!(ids(&rows), ["a0", "a1", "a2", "b0"]);
        assert!(truncated);
    }

    #[test]
    fn a_slice_stopped_by_the_page_limit_under_the_cap_fails() {
        let stopped = Slice {
            prefix: 'c',
            rows: vec![sp("c1", "c1")],
            truncated: true,
        };
        assert_eq!(
            merge_slices(&[], vec![stopped], 1, 100).map(|_| ()),
            Err("slice_page_limit")
        );
    }

    #[test]
    fn the_prefixes_cover_every_guid_once() {
        for c in "0123456789abcdef".chars() {
            assert_eq!(SLICE_PREFIXES.iter().filter(|p| **p == c).count(), 1);
        }
        assert_eq!(SLICE_PREFIXES.len(), 16);
    }
}
