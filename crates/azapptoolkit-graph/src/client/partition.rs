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
//!   400 on a slice's page one in plain mode retries once as an advanced
//!   query, and a 400 there pins the collection to the serial read for this
//!   client (one per tenant, dropped by the sign-out sweep).
//! - The merged result is checked before it is trusted ([`merge_slices`]):
//!   every row under its slice's prefix, every row of the unfiltered first page
//!   present, and the union no shorter than `/$count`. There is no tolerance:
//!   a principal with no `appId` is in no slice, and letting the union run a
//!   few rows short would drop exactly those principals. Anything off falls
//!   back to the serial read and logs a `warn`. A structural refusal (a row
//!   outside its prefix, a row no slice can hold) pins the collection serial.
//!   A slice still throttled (429) when its retries ran out is transient: it
//!   says nothing about the filter or the index, so it is not a lag strike
//!   (it neither counts nor clears one) and the next scan slices again. It
//!   has its own, looser bound instead: [`MAX_TRANSIENT_REFUSALS`] throttled
//!   waves with no validated merge between them pin the collection serial,
//!   since sixteen concurrent chains are then only adding to the load. Any
//!   other lag-type refusal (a server or network error included) is judged
//!   by the serial read it falls back to: when every row the serial read
//!   returned was already in the slices' union, the slices were complete and
//!   only `/$count` was stale (the index lags a delete), so nothing is held
//!   against the collection; otherwise it counts, and [`MAX_LAG_REFUSALS`] in
//!   a row pin the collection serial.
//! - The residual gap is the index lag itself: `/$count` comes from the
//!   eventually-consistent index while plain slices read the directory, so a
//!   principal with no `appId` created inside the lag window is in neither
//!   and the union check cannot see it until the index has counted it. The
//!   first scan whose rows include such a principal pins the collection serial
//!   for the client's lifetime, so the window closes on the next refusal.

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

/// What a client remembers about one collection's slicing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SliceMemo {
    /// The mode that last worked, or `Serial` once the collection is pinned.
    pub(crate) mode: Option<SliceMode>,
    /// Lag-type refusals in a row; a merge that validated resets it.
    pub(crate) lag_refusals: u8,
    /// Throttled waves ([`Refusal::SliceTransient`]) in a row; a merge that
    /// validated resets it.
    pub(crate) transient_refusals: u8,
}

/// The slice prefixes: a GUID's first character is one lowercase hex digit.
const SLICE_PREFIXES: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Below this many pages in all, the serial chain is no longer than the
/// partitioned read's fan-out, so the scan stays serial.
const MIN_PAGES_TO_PARTITION: u64 = 4;

/// Lag-type refusals in a row that the serial read did not clear (see
/// [`GraphClient::refuse`]) before a collection is pinned serial for the
/// client's lifetime: enough to ride out one index-lag window, not enough to
/// pay 16 wasted chains on every scan of a tenant that never validates.
const MAX_LAG_REFUSALS: u8 = 2;

/// Throttled slice waves in a row (no validated merge between them) before a
/// collection is pinned serial for the client's lifetime. Looser than
/// [`MAX_LAG_REFUSALS`]: a 429 says nothing about the slicing, so a couple of
/// busy scans must not cost the session its fast read, but a tenant throttled
/// scan after scan is better served by one chain than by sixteen that each
/// fail and then pay the serial read anyway.
const MAX_TRANSIENT_REFUSALS: u8 = 3;

/// Why a sliced read was refused. `Err` from [`merge_slices`] names the check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A slice stopped at the page limit below the cap (a cyclic or
    /// pathologically empty `nextLink` chain), so it is incomplete.
    SlicePageLimit,
    /// A row outside its slice's prefix: Graph ignored or misread the filter,
    /// so the slices are not disjoint and complete.
    PrefixMismatch,
    /// A row with no `appId`: no slice can hold it, so no sliced read of this
    /// collection is ever complete.
    UnslicedRow,
    /// A row of the unfiltered page one is in no slice.
    ProbeRowMissing,
    /// Fewer rows than `/$count`. Skipped when the cap cut a slice short,
    /// since the union is then short by design.
    CountShortfall,
    /// A slice failed for a reason that says nothing about the filter: a 400
    /// on a continuation page, or a server or network error its retries could
    /// not outwait, on any page. The wave is incomplete.
    SliceFailed,
    /// A slice was still throttled (429) when its retries ran out, on any
    /// page. The wave is incomplete, and the refusal is about Graph's load,
    /// not the slicing: it counts toward [`MAX_TRANSIENT_REFUSALS`], never
    /// [`MAX_LAG_REFUSALS`], so two busy minutes do not pin a tenant serial
    /// (and leave it on the slow read for the client's lifetime).
    SliceTransient,
    /// A mode that validated before answered 400 on a slice's page one.
    ModeRejected,
}

impl Refusal {
    /// A structural refusal cannot clear by waiting, so the collection is
    /// pinned serial at once; the rest can be the index lagging the directory.
    pub(crate) fn is_structural(self) -> bool {
        matches!(
            self,
            Refusal::SlicePageLimit | Refusal::PrefixMismatch | Refusal::UnslicedRow
        )
    }

    /// A transient refusal says nothing about the slicing: it neither counts
    /// toward [`MAX_LAG_REFUSALS`] nor clears those strikes, and is bounded by
    /// [`MAX_TRANSIENT_REFUSALS`] instead.
    pub(crate) fn is_transient(self) -> bool {
        matches!(self, Refusal::SliceTransient)
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Refusal::SlicePageLimit => "slice_page_limit",
            Refusal::PrefixMismatch => "prefix_mismatch",
            Refusal::UnslicedRow => "unsliced_row",
            Refusal::ProbeRowMissing => "probe_row_missing",
            Refusal::CountShortfall => "count_shortfall",
            Refusal::SliceFailed => "slice_failed",
            Refusal::SliceTransient => "slice_transient",
            Refusal::ModeRejected => "mode_rejected",
        }
    }
}

/// A refused merge: the check that failed, and the object ids the slices did
/// return, so the serial read that follows can tell a stale `/$count` from
/// slices that really missed a row.
#[derive(Debug)]
pub(crate) struct Refused {
    pub(crate) reason: Refusal,
    pub(crate) union: HashSet<String>,
}

impl From<Refusal> for Refused {
    fn from(reason: Refusal) -> Self {
        Refused {
            reason,
            union: HashSet::new(),
        }
    }
}

/// How a wave of slices failed to read.
enum SliceError {
    /// A slice's page one answered 400: this mode's filter is not accepted.
    Rejected,
    /// A slice's page one holds a row outside its prefix: Graph misread the
    /// filter, and paging the rest would only fetch the whole collection
    /// sixteen times over.
    Mismatch,
    /// Any other failure, on page one or a continuation.
    Graph(GraphError),
}

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

/// The slice a row belongs to: its `appId`'s first character, lowercased.
fn slice_of<T: DirectoryRow>(row: &T) -> Option<char> {
    row.app_id().chars().next().map(|c| c.to_ascii_lowercase())
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
        let known = self.slice_memo(path).mode;
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
        // A row with no appId can be in no slice, whichever path returned it:
        // from now on this collection is read serially.
        if rows.iter().any(|r| r.app_id().is_empty()) {
            self.update_slice_memo(path, |memo| memo.mode = Some(SliceMode::Serial));
        }
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
        // A principal with no appId is in no slice. One on page one proves the
        // tenant cannot be sliced, before any slice is asked for.
        if probe.items.iter().any(|r| r.app_id().is_empty()) {
            return self
                .refuse(path, probe, cap, Refusal::UnslicedRow.into(), count)
                .await;
        }

        let modes: &[SliceMode] = match known {
            Some(SliceMode::Plain) => &[SliceMode::Plain],
            Some(SliceMode::Advanced) => &[SliceMode::Advanced],
            _ => &[SliceMode::Plain, SliceMode::Advanced],
        };
        for &mode in modes {
            let slices = match self.read_slices::<T>(path, params, cap, mode).await {
                Ok(slices) => slices,
                Err(SliceError::Rejected) => {
                    tracing::debug!(
                        target: "azapptoolkit::graph::scan",
                        path,
                        ?mode,
                        "appId slices rejected (400)"
                    );
                    continue;
                }
                Err(SliceError::Mismatch) => {
                    return self
                        .refuse(path, probe, cap, Refusal::PrefixMismatch.into(), count)
                        .await;
                }
                // A continuation 400, or a throttle, server or network error
                // the retries could not outwait on any page, says nothing
                // about the filter: the serial read supplies this scan. A
                // throttle is Graph's load, bounded on its own; the rest are
                // judged like a refused merge.
                Err(SliceError::Graph(err))
                    if err.is_retryable() || matches!(err, GraphError::Api { status: 400, .. }) =>
                {
                    tracing::warn!(
                        target: "azapptoolkit::graph::scan",
                        path,
                        ?mode,
                        code = %err.ui_code(),
                        "a slice failed; reading serially"
                    );
                    let reason = if matches!(err, GraphError::Throttled { .. }) {
                        Refusal::SliceTransient
                    } else {
                        Refusal::SliceFailed
                    };
                    return self.refuse(path, probe, cap, reason.into(), count).await;
                }
                Err(SliceError::Graph(err)) => return Err(err),
            };
            match merge_slices(&probe.items, slices, count, cap) {
                Ok((rows, truncated)) => {
                    self.update_slice_memo(path, |memo| {
                        memo.mode = Some(mode);
                        memo.lag_refusals = 0;
                        memo.transient_refusals = 0;
                    });
                    let strategy = match mode {
                        SliceMode::Advanced => "partitioned_advanced",
                        _ => "partitioned",
                    };
                    return Ok((rows, truncated, strategy));
                }
                Err(refused) => return self.refuse(path, probe, cap, refused, count).await,
            }
        }
        if known.is_some() {
            // A mode that validated before is evidence the filter works: one
            // 400 is judged like any other failed wave, not pinned outright.
            return self
                .refuse(path, probe, cap, Refusal::ModeRejected.into(), count)
                .await;
        }
        self.update_slice_memo(path, |memo| memo.mode = Some(SliceMode::Serial));
        self.serial_rest(probe, cap, "serial_fallback").await
    }

    /// The serial read after a refused sliced read, and what the client keeps
    /// of the refusal.
    ///
    /// A structural refusal pins the collection serial before the read (so a
    /// serial read that then fails does not buy the wasted wave again), and so
    /// does a serial result holding a row no slice could have returned. A
    /// transient refusal ([`Refusal::is_transient`]) leaves the lag strikes as
    /// they were and counts toward [`MAX_TRANSIENT_REFUSALS`] instead. Any
    /// other lag-type refusal is judged by that result: when
    /// every row the serial read returned was already in the slices' union
    /// (and nothing was cut by the cap), the slices were complete and only
    /// `/$count` was stale, so the refusal is not held against the collection;
    /// otherwise it is counted, and [`MAX_LAG_REFUSALS`] in a row pin the
    /// collection serial.
    async fn refuse<T>(
        &self,
        path: &'static str,
        probe: Paged<T>,
        cap: usize,
        refused: Refused,
        count: u64,
    ) -> Result<(Vec<T>, bool, &'static str)>
    where
        T: DeserializeOwned + DirectoryRow,
    {
        let Refused { reason, union } = refused;
        tracing::warn!(
            target: "azapptoolkit::graph::scan",
            path,
            reason = reason.as_str(),
            count,
            "partitioned read failed validation; reading serially"
        );
        if reason.is_structural() {
            self.update_slice_memo(path, |memo| memo.mode = Some(SliceMode::Serial));
        }
        let (rows, truncated, strategy) = self.serial_rest(probe, cap, "serial_fallback").await?;
        let structural = reason.is_structural() || rows.iter().any(|r| r.app_id().is_empty());
        let slices_were_complete = !structural
            && !truncated
            && !union.is_empty()
            && rows.iter().all(|r| union.contains(r.object_id()));
        // A transient refusal is Graph being busy, not wrong: no lag strike,
        // and no clear either — a wave that never finished proved nothing
        // about the merge. It has its own bound.
        self.update_slice_memo(path, |memo| {
            if structural {
                memo.mode = Some(SliceMode::Serial);
            } else if reason.is_transient() {
                memo.transient_refusals = memo.transient_refusals.saturating_add(1);
                if memo.transient_refusals >= MAX_TRANSIENT_REFUSALS {
                    memo.mode = Some(SliceMode::Serial);
                }
            } else if !slices_were_complete {
                memo.lag_refusals = memo.lag_refusals.saturating_add(1);
                if memo.lag_refusals >= MAX_LAG_REFUSALS {
                    memo.mode = Some(SliceMode::Serial);
                }
            }
        });
        Ok((rows, truncated, strategy))
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
    ) -> std::result::Result<Vec<Slice<T>>, SliceError>
    where
        T: DeserializeOwned + DirectoryRow + Send,
    {
        let advanced = mode == SliceMode::Advanced;
        futures::future::try_join_all(SLICE_PREFIXES.iter().map(|&prefix| async move {
            let filter = format!("startswith(appId,'{prefix}')");
            let mut query: Vec<(&str, &str)> = params.to_vec();
            query.push(("$filter", filter.as_str()));
            if advanced {
                query.push(("$count", "true"));
            }
            let page: Paged<T> = match self.get_json(path, &query, advanced).await {
                Ok(page) => page,
                Err(GraphError::Api { status: 400, .. }) => return Err(SliceError::Rejected),
                Err(err) => return Err(SliceError::Graph(err)),
            };
            if page.items.iter().any(|r| slice_of(r) != Some(prefix)) {
                return Err(SliceError::Mismatch);
            }
            let (rows, truncated) = self
                .collect_all_pages_capped(page, cap, advanced)
                .await
                .map_err(SliceError::Graph)?;
            Ok(Slice {
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

    fn slice_memo(&self, path: &'static str) -> SliceMemo {
        self.slice_memos
            .lock()
            .get(path)
            .copied()
            .unwrap_or_default()
    }

    fn update_slice_memo(&self, path: &'static str, update: impl FnOnce(&mut SliceMemo)) {
        update(self.slice_memos.lock().entry(path).or_default());
    }
}

/// Merges the slices in prefix order and checks the result can be trusted.
/// `Err` names the failed check and carries the union's ids; the caller then
/// reads serially.
///
/// The count check is skipped when the cap cut a slice short: the union is
/// then short by design, and the result is flagged truncated.
///
/// Rows are de-duplicated by object id (first occurrence wins), then cut to
/// `cap`; the flag is set when rows existed past it.
pub(crate) fn merge_slices<T: DirectoryRow>(
    probe: &[T],
    slices: Vec<Slice<T>>,
    count: u64,
    cap: usize,
) -> std::result::Result<(Vec<T>, bool), Refused> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut rows: Vec<T> = Vec::new();
    let mut any_truncated = false;
    for slice in slices {
        if slice.truncated && slice.rows.len() < cap {
            return Err(Refusal::SlicePageLimit.into());
        }
        any_truncated |= slice.truncated;
        for row in slice.rows {
            if slice_of(&row) != Some(slice.prefix) {
                return Err(Refusal::PrefixMismatch.into());
            }
            if seen.insert(row.object_id().to_owned()) {
                rows.push(row);
            }
        }
    }
    if probe.iter().any(|r| r.app_id().is_empty()) {
        return Err(Refusal::UnslicedRow.into());
    }
    if probe.iter().any(|r| !seen.contains(r.object_id())) {
        return Err(Refused {
            reason: Refusal::ProbeRowMissing,
            union: seen,
        });
    }
    let union = u64::try_from(rows.len()).unwrap_or(u64::MAX);
    if !any_truncated && union < count {
        return Err(Refused {
            reason: Refusal::CountShortfall,
            union: seen,
        });
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
            merge_slices(&[], slices, 1, 100)
                .map(|_| ())
                .unwrap_err()
                .reason,
            Refusal::PrefixMismatch
        );
    }

    #[test]
    fn a_missing_probe_row_fails() {
        let probe = vec![sp("p", "3000")];
        let slices = vec![slice('3', vec![sp("q", "3001")])];
        let refused = merge_slices(&probe, slices, 1, 100)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(refused.reason, Refusal::ProbeRowMissing);
        assert_eq!(
            refused.union.len(),
            1,
            "the union rides along for the serial read to judge"
        );
    }

    /// A principal with no `appId` on the probe page is refused before the
    /// missing-row check, as the structural reason it is.
    #[test]
    fn a_probe_row_without_an_app_id_is_structural() {
        let probe = vec![sp("agent", ""), sp("p", "3000")];
        let slices = vec![slice('3', vec![sp("p", "3000")])];
        let refusal = merge_slices(&probe, slices, 2, 100)
            .map(|_| ())
            .unwrap_err()
            .reason;
        assert_eq!(refusal, Refusal::UnslicedRow);
        assert!(refusal.is_structural());
        assert!(!Refusal::CountShortfall.is_structural());
        assert!(!Refusal::ProbeRowMissing.is_structural());
        assert!(!Refusal::SliceFailed.is_structural());
        assert!(!Refusal::SliceTransient.is_structural());
        assert!(Refusal::SliceTransient.is_transient());
        assert!(!Refusal::SliceFailed.is_transient());
        assert!(!Refusal::ModeRejected.is_structural());
    }

    /// No tolerance on the count: one row short is one principal dropped.
    #[test]
    fn any_count_shortfall_fails() {
        let rows: Vec<_> = (0..10).map(|i| sp(&format!("o{i}"), "7a")).collect();
        assert!(merge_slices(&[], vec![slice('7', rows.clone())], 10, 100).is_ok());
        // The index can lag a just-created object: an over-count passes.
        assert!(merge_slices(&[], vec![slice('7', rows.clone())], 9, 100).is_ok());
        let refused = merge_slices(&[], vec![slice('7', rows)], 11, 100)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(refused.reason, Refusal::CountShortfall);
        assert_eq!(refused.union.len(), 10);
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
            merge_slices(&[], vec![stopped], 1, 100)
                .map(|_| ())
                .unwrap_err()
                .reason,
            Refusal::SlicePageLimit
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
