//! Data plumbing shared by the tenant list views (App Registrations, Enterprise
//! Applications). Operates on the *loaded* rows and owns the layered filter
//! memos the three lists hand-rolled identically: a `base` set (search + an
//! extra predicate such as a creation-date range), a facet partition (`shown`),
//! per-facet counts for the chips, and the "what you see is what you export"
//! snapshot.
//!
//! It is deliberately scoped to the loaded body — the async fetch / refresh and
//! the chrome live in the view and [`ListScaffold`](crate::components::list_scaffold).
//! Pair it with the scaffold; see `application_list.rs` for a worked call site.
//!
//! `Memo::new` requires its closure (and value) to be `Send + Sync + 'static`,
//! so the generic predicates are bounded the same way. The views satisfy this:
//! their closures capture only `Copy` signals (or nothing).

use std::sync::Arc;

use leptos::prelude::*;

/// One facet chip's identity (label/value) plus its membership test, evaluated
/// over the `base` set to produce both the partition and the chip's count.
pub struct Facet<T> {
    pub label: &'static str,
    pub value: &'static str,
    predicate: Arc<dyn Fn(&T) -> bool + Send + Sync>,
}

impl<T> Facet<T> {
    pub fn new(
        label: &'static str,
        value: &'static str,
        predicate: impl Fn(&T) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            label,
            value,
            predicate: Arc::new(predicate),
        }
    }
}

/// Inputs to [`use_filtered_list`]. The two closures and the facet predicates
/// are the only per-view-specific pieces; everything else is wiring.
pub struct FilteredListSpec<T, S, E> {
    /// The loaded rows (pre-filter).
    pub items: Vec<T>,
    /// Debounced filter query (the caller lifts + debounces it).
    pub search: Signal<String>,
    /// Whether `row` matches the already-trimmed-and-lowercased needle.
    pub search_match: S,
    /// True when any non-search, non-facet filter (e.g. a date range) is active.
    /// Lets `base` short-circuit to a pointer copy of the full set when nothing
    /// is filtering — avoids cloning every row on an unfiltered list.
    pub extra_active: Signal<bool>,
    /// Whether `row` passes the extra filters (date range, …). Should read its
    /// own signals so `base` re-runs when they change.
    pub extra: E,
    /// The active facet value (two-way bound to the chips).
    pub facet: RwSignal<String>,
    /// The "show everything" sentinel value (`"any"` / `"all"`).
    pub facet_any: &'static str,
    /// Facet partitions of `base`; their counts populate the chips.
    pub facets: Vec<Facet<T>>,
    /// Optional export snapshot, kept in step with `shown` (a pointer copy).
    pub export_rows: Option<StoredValue<Arc<Vec<T>>>>,
}

/// Reactive handles over the loaded list. `Clone`; its `Memo`s are `Copy`.
#[derive(Clone)]
pub struct FilteredList<T: Send + Sync + 'static> {
    /// Rows after search + extra filters, before the facet partition. The facet
    /// chip counts (and the "all" chip) are over this set.
    pub base: Memo<Arc<Vec<T>>>,
    /// Rows after the active facet partition — the `VirtualList` input.
    pub shown: Memo<Arc<Vec<T>>>,
    /// Total loaded rows (pre-filter) — the "N of M" denominator.
    pub total: usize,
    /// Per-facet counts over `base`, aligned with `facet_values`.
    counts: Memo<Vec<usize>>,
    /// Facet values in the same order as `counts`, for value→index lookup.
    facet_values: Arc<Vec<&'static str>>,
}

impl<T: Send + Sync + 'static> FilteredList<T> {
    /// Rows in `base` (the "All" chip's count / facet denominator).
    pub fn base_total(&self) -> Signal<usize> {
        let base = self.base;
        Signal::derive(move || base.with(|b| b.len()))
    }

    /// Rows currently shown after the facet partition (the "N of M" numerator).
    pub fn shown_total(&self) -> Signal<usize> {
        let shown = self.shown;
        Signal::derive(move || shown.with(|s| s.len()))
    }

    /// Count of `base` rows matching the facet with this `value` (0 if unknown).
    /// Create these once per render (not inside a re-running closure) so the
    /// derived signals aren't rebuilt every tick.
    pub fn count_of(&self, value: &'static str) -> Signal<usize> {
        let counts = self.counts;
        let values = Arc::clone(&self.facet_values);
        Signal::derive(move || {
            values
                .iter()
                .position(|v| *v == value)
                .map(|i| counts.with(|c| c.get(i).copied().unwrap_or(0)))
                .unwrap_or(0)
        })
    }
}

/// Build the filter memos for a loaded list. See the module docs.
pub fn use_filtered_list<T, S, E>(spec: FilteredListSpec<T, S, E>) -> FilteredList<T>
where
    T: Clone + PartialEq + Send + Sync + 'static,
    S: Fn(&T, &str) -> bool + Send + Sync + 'static,
    E: Fn(&T) -> bool + Send + Sync + 'static,
{
    let FilteredListSpec {
        items,
        search,
        search_match,
        extra_active,
        extra,
        facet,
        facet_any,
        facets,
        export_rows,
    } = spec;

    let total = items.len();
    let all = Arc::new(items);
    let facets = Arc::new(facets);
    let facet_values: Arc<Vec<&'static str>> = Arc::new(facets.iter().map(|f| f.value).collect());

    // base = search + extra filters. Short-circuits to a pointer copy of the
    // full set when nothing is filtering, mirroring the hand-rolled lists.
    let base = Memo::new(move |_| {
        let needle = search.with(|s| s.trim().to_lowercase());
        let extra_on = extra_active.get();
        if needle.is_empty() && !extra_on {
            return Arc::clone(&all);
        }
        Arc::new(
            all.iter()
                .filter(|row| (needle.is_empty() || search_match(row, &needle)) && extra(row))
                .cloned()
                .collect::<Vec<_>>(),
        )
    });

    let counts = {
        let facets = Arc::clone(&facets);
        Memo::new(move |_| {
            base.with(|b| {
                facets
                    .iter()
                    .map(|f| b.iter().filter(|r| (f.predicate)(r)).count())
                    .collect::<Vec<usize>>()
            })
        })
    };

    let shown = {
        let facets = Arc::clone(&facets);
        Memo::new(move |_| {
            let active = facet.get();
            if active == facet_any {
                return base.get();
            }
            match facets.iter().find(|f| f.value == active) {
                Some(f) => {
                    let pred = Arc::clone(&f.predicate);
                    base.with(|b| {
                        Arc::new(b.iter().filter(|r| pred(r)).cloned().collect::<Vec<_>>())
                    })
                }
                // Unknown facet (stale saved view) → no partition.
                None => base.get(),
            }
        })
    };

    // Keep the export snapshot in step with what's shown (a pointer copy).
    if let Some(export_rows) = export_rows {
        Effect::new(move |_| export_rows.set_value(shown.get()));
    }

    FilteredList {
        base,
        shown,
        total,
        counts,
        facet_values,
    }
}
