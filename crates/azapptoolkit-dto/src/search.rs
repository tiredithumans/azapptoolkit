//! Global-search IPC DTOs.
//!
//! The frontend's top-bar search invokes `global_search` with a free-form
//! query; the backend routes it to display-name `startswith` lookups or
//! GUID exact lookups across all three identity kinds, then returns
//! grouped, lightweight rows for the dropdown — plus the per-kind match totals
//! and the index-coverage flag the dropdown needs in order to admit what it
//! left out.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub id: String,
    pub app_id: Option<String>,
    pub display_name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalSearchResults {
    pub query: String,
    pub looked_up_as_guid: bool,
    pub app_registrations: Vec<SearchHit>,
    pub enterprise_apps: Vec<SearchHit>,
    pub managed_identities: Vec<SearchHit>,
    /// How many rows each bucket matched **before** the per-kind display cap.
    ///
    /// The dropdown shows the best few per kind; without the pre-cap count it
    /// renders exactly that many rows and stops, which an operator reads as
    /// "these are all of them". On a tenant where 200 apps contain "svc" that
    /// is a lie the fastest input path in the app tells silently — so the count
    /// rides along and the group footer says how much was left off.
    ///
    /// `#[serde(default)]` on all five additive fields: a payload written by an
    /// older backend (or a fixture that predates them) still deserializes, and
    /// a zero total is indistinguishable from "no cap applied" because
    /// `total > shown` is the only question the frontend asks.
    #[serde(default)]
    pub app_registrations_total: usize,
    #[serde(default)]
    pub enterprise_apps_total: usize,
    #[serde(default)]
    pub managed_identities_total: usize,
    /// The service-principal index this query filtered had itself truncated at
    /// [`Self::corpus_cap`], so the results cover only that subset.
    ///
    /// The same signal the three inventory lists render through `IndexCapNotice`
    /// — search was blind to it, which is the worse half of the same bug: a list
    /// showing a partial set at least shows *something*, while a search over a
    /// capped corpus answers "No matches." for a principal that is genuinely
    /// present.
    #[serde(default)]
    pub corpus_truncated: bool,
    /// The index cap itself, so the notice can name the number without the
    /// frontend keeping its own copy in sync (mirroring `DirectoryIndexStatus`).
    #[serde(default)]
    pub corpus_cap: usize,
}
