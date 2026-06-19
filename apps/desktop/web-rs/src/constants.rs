//! Shared constants for list rendering, virtual scrolling, and filtering.
//! Extracted from individual view files to prevent drift between the three
//! data-table lists (app regs, enterprise apps, managed identities).

/// Fixed row height in pixels for all data-table lists (app regs, enterprise
/// apps, managed identities). All three use 52px so the UI looks uniform.
pub const ROW_HEIGHT: f64 = 52.0;

/// Number of rows to render outside the visible window for scroll smoothness.
pub const OVERSCAN: usize = 8;

/// Windowed render page size for audit/resource-access tables. Each "Load more"
/// button loads one page at a time.
pub const RENDER_PAGE: usize = 200;

/// Number of inline issues to show per audit finding before truncating with
/// "n more…" text.
pub const ISSUES_INLINE: usize = 2;

/// Backend safety cap on apps materialized for a list (see `APPS_MAX` in
/// `commands/applications.rs`). Real tenants stay well under it.
pub const APPS_HARD_CAP: usize = 10_000;

/// List filter debounce in milliseconds. Filters run in-memory over cached
/// rows, so the delay only smooths re-render — not network traffic.
pub const LIST_FILTER_DEBOUNCE_MS: i32 = 300;
