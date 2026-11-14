use std::time::Duration;

use chrono::{DateTime, Utc};
use leptos::prelude::*;

use crate::bindings::diagnostics::{self, ListCacheKindDto};
use crate::state::Session;
use crate::util::{fmt_datetime, relative_time};

/// How often the stamp re-reads the clock. Coarse on purpose: the phrase only
/// changes by the minute.
const TICK: Duration = Duration::from_secs(30);

/// "Updated 5 min ago" beside a list's or board's Refresh — how old the data
/// on screen is, with the exact time on hover.
///
/// The lists are served from a long-lived backend cache and patched in place,
/// and only the audit said how old its numbers were ("Scanned … ago"). Every
/// other list looked equally current whether it was read a second or an hour
/// ago, so the only way to be sure was to press Refresh.
///
/// Renders nothing until `loaded_at` is set. The phrase ticks on its own timer
/// so it does not go stale itself.
#[component]
pub fn DataAge(#[prop(into)] loaded_at: Signal<Option<DateTime<Utc>>>) -> impl IntoView {
    let now = RwSignal::new(Utc::now());
    if let Ok(timer) = set_interval_with_handle(move || now.set(Utc::now()), TICK) {
        on_cleanup(move || timer.clear());
    }
    view! {
        {move || {
            loaded_at
                .get()
                .map(|at| {
                    // The later of the two: the timer's clock can be up to one
                    // tick behind a stamp that just landed.
                    let reference = now.get().max(at);
                    view! {
                        <span class="data-age" title=format!("Read at {}", fmt_datetime(at))>
                            {format!("Updated {}", relative_time(reference, at))}
                        </span>
                    }
                })
        }}
    }
}

/// Stamp `loaded_at` for data that just loaded for `tenant_id`.
///
/// With a `kind`, asks the backend how old its cached entry is — the read may
/// have been answered from a cache filled long before — and back-dates the
/// stamp by that. With `None` (a live read with no cache behind it), or when
/// the backend has no age to give, the data is as old as this moment.
pub fn stamp_data_age(
    session: Session,
    tenant_id: String,
    kind: Option<ListCacheKindDto>,
    loaded_at: RwSignal<Option<DateTime<Utc>>>,
) {
    leptos::task::spawn_local(async move {
        let age_secs = match kind {
            Some(kind) => diagnostics::list_cache_age(tenant_id.clone(), kind)
                .await
                .ok()
                .flatten(),
            None => None,
        };
        // A switched tenant's list is not this one's to date.
        if !session.is_active_tenant(&tenant_id) {
            return;
        }
        let age = chrono::Duration::seconds(i64::try_from(age_secs.unwrap_or(0)).unwrap_or(0));
        loaded_at.set(Some(Utc::now() - age));
    });
}
