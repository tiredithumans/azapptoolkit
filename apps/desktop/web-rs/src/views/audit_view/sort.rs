//! Sortable audit-table column.

/// A sortable audit-table column. The backend's original order (risk-ranked) is
/// the unsorted default; clicking a header cycles default-direction → reverse →
/// back to unsorted so that default order is always recoverable.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SortCol {
    Name,
    Score,
    LastSignIn,
}

impl SortCol {
    /// First-click direction: highest score / most-recent sign-in first (the
    /// triage need), names A→Z.
    pub(super) fn default_desc(self) -> bool {
        !matches!(self, SortCol::Name)
    }
}
