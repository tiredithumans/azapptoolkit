//! Application detail-pane tab identity. A typed enum so the match in
//! `ApplicationDetailPane` is exhaustive — adding a tab forces an update here,
//! which the compiler enforces. The pane still stores the *string* value (Thaw's
//! `TabList` is string-keyed and two-way bound); this enum is the bridge between
//! that string and an exhaustive match.

/// Tabs for the app registration detail pane, in display order. String values
/// match the `Tab value` attributes used by Thaw's `TabList`. Stale persisted or
/// deep-linked values are clamped to a live tab via [`AppTab::from_str`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppTab {
    Overview,
    Credentials,
    Authentication,
    Owners,
    Permissions,
    ExposeApi,
    ConditionalAccess,
    Activity,
}

impl AppTab {
    /// All tabs in display order — used to build the `TabList`.
    pub const ALL: &'static [Self] = &[
        Self::Overview,
        Self::Credentials,
        Self::Authentication,
        Self::Owners,
        Self::Permissions,
        Self::ExposeApi,
        Self::ConditionalAccess,
        Self::Activity,
    ];

    /// Resolve a persisted/deep-linked string to a tab, clamping values left over
    /// from merged or removed tabs so they land on a live tab instead of being
    /// dropped: the former "federated" tab → Credentials, the merged "insights"
    /// tab → Conditional Access, and the former Exchange/SharePoint access tabs →
    /// Permissions (now sections below the permissions table). Unknown → Overview.
    // Infallible (clamps to Overview, never errors), so the std `FromStr` trait —
    // with its mandatory `Err` type and `Result` return — would be the wrong shape;
    // keep the inherent total method.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "overview" => Self::Overview,
            "credentials" | "federated" => Self::Credentials,
            "authentication" => Self::Authentication,
            "owners" => Self::Owners,
            "permissions" | "exchange" | "sharepoint" => Self::Permissions,
            "exposeApi" => Self::ExposeApi,
            "conditionalAccess" | "insights" => Self::ConditionalAccess,
            "activity" => Self::Activity,
            _ => Self::Overview,
        }
    }

    /// The string value used by Thaw's `Tab` component (and persisted state).
    pub fn value(&self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Credentials => "credentials",
            Self::Authentication => "authentication",
            Self::Owners => "owners",
            Self::Permissions => "permissions",
            Self::ExposeApi => "exposeApi",
            Self::ConditionalAccess => "conditionalAccess",
            Self::Activity => "activity",
        }
    }

    /// Display label for the tab list.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Credentials => "Credentials",
            Self::Authentication => "Authentication",
            Self::Owners => "Owners",
            // "API permissions" (the portal's term) — the permissions this app
            // *requests* (requiredResourceAccess), distinct from the *held* grants
            // the Enterprise App / Managed Identity "Permissions" tabs show.
            Self::Permissions => "API permissions",
            Self::ExposeApi => "Expose an API",
            Self::ConditionalAccess => "Conditional Access",
            Self::Activity => "Activity",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AppTab;

    #[test]
    fn from_str_clamps_stale_values_to_live_tabs() {
        // Stale values mapped by the old normalize_app_tab logic.
        assert_eq!(AppTab::from_str("federated"), AppTab::Credentials);
        assert_eq!(AppTab::from_str("insights"), AppTab::ConditionalAccess);
        assert_eq!(AppTab::from_str("exchange"), AppTab::Permissions);
        assert_eq!(AppTab::from_str("sharepoint"), AppTab::Permissions);

        // Live values pass through.
        assert_eq!(AppTab::from_str("permissions"), AppTab::Permissions);
        assert_eq!(AppTab::from_str("overview"), AppTab::Overview);

        // Unknown values fall back to Overview.
        assert_eq!(AppTab::from_str("nonexistent"), AppTab::Overview);
    }

    #[test]
    fn value_and_label_match_each_tab() {
        assert_eq!(AppTab::Overview.value(), "overview");
        assert_eq!(AppTab::ExposeApi.value(), "exposeApi");
        assert_eq!(AppTab::ConditionalAccess.value(), "conditionalAccess");
        assert_eq!(AppTab::ExposeApi.label(), "Expose an API");
    }

    #[test]
    fn all_lists_every_tab_in_order() {
        assert_eq!(AppTab::ALL.len(), 8);
        assert_eq!(AppTab::ALL[0], AppTab::Overview);
        assert_eq!(AppTab::ALL[7], AppTab::Activity);
    }

    #[test]
    fn from_str_roundtrips_all_live_values() {
        for tab in AppTab::ALL {
            assert_eq!(AppTab::from_str(tab.value()), *tab);
        }
    }
}
