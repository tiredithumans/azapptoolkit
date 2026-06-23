//! Enterprise-application detail-pane tab identity. A typed enum so the match in
//! `EnterpriseApplicationDetailPane` is exhaustive — adding a tab forces an
//! update here, which the compiler enforces (replacing the former 10 inline
//! string arms with a "Unknown tab" fallthrough). The pane still stores the
//! *string* value (Thaw's `TabList` is string-keyed and two-way bound); this enum
//! bridges that string and an exhaustive match. Mirrors [`super::app_tab::AppTab`].

/// Tabs for the enterprise application detail pane, in display order. String
/// values match the `Tab value` attributes used by Thaw's `TabList`. Stale
/// persisted or deep-linked values are clamped to a live tab via
/// [`EnterpriseTab::from_str`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterpriseTab {
    Overview,
    Sso,
    Credentials,
    Owners,
    Permissions,
    AppRoles,
    Access,
    Provisioning,
    ConditionalAccess,
    Activity,
}

impl EnterpriseTab {
    /// All tabs in display order — used to build the `TabList`.
    pub const ALL: &'static [Self] = &[
        Self::Overview,
        Self::Sso,
        Self::Credentials,
        Self::Owners,
        Self::Permissions,
        Self::AppRoles,
        Self::Access,
        Self::Provisioning,
        Self::ConditionalAccess,
        Self::Activity,
    ];

    /// Resolve a persisted/deep-linked string to a tab, clamping the merged
    /// "insights" tab → Conditional Access so a stale value lands on a live tab
    /// instead of being dropped. Unknown → Overview.
    // Infallible (clamps to Overview), so the std `FromStr` trait — with its
    // mandatory `Err` and `Result` return — is the wrong shape; keep the inherent
    // total method (matches `AppTab::from_str`).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "overview" => Self::Overview,
            "sso" => Self::Sso,
            "credentials" => Self::Credentials,
            "owners" => Self::Owners,
            "permissions" => Self::Permissions,
            "appRoles" => Self::AppRoles,
            "access" => Self::Access,
            "provisioning" => Self::Provisioning,
            "conditionalAccess" | "insights" => Self::ConditionalAccess,
            "activity" => Self::Activity,
            _ => Self::Overview,
        }
    }

    /// The string value used by Thaw's `Tab` component (and persisted state).
    pub fn value(&self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Sso => "sso",
            Self::Credentials => "credentials",
            Self::Owners => "owners",
            Self::Permissions => "permissions",
            Self::AppRoles => "appRoles",
            Self::Access => "access",
            Self::Provisioning => "provisioning",
            Self::ConditionalAccess => "conditionalAccess",
            Self::Activity => "activity",
        }
    }

    /// Display label for the tab list.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Sso => "SSO",
            Self::Credentials => "Credentials",
            Self::Owners => "Owners",
            // The permissions this app *holds* (granted app-role assignments +
            // delegated grants), distinct from the app-registration "API
            // permissions" tab (the permissions it *requests*).
            Self::Permissions => "Permissions",
            Self::AppRoles => "App roles",
            Self::Access => "Access",
            Self::Provisioning => "Provisioning",
            Self::ConditionalAccess => "Conditional Access",
            Self::Activity => "Activity",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EnterpriseTab;

    #[test]
    fn from_str_clamps_stale_insights_to_conditional_access() {
        assert_eq!(
            EnterpriseTab::from_str("insights"),
            EnterpriseTab::ConditionalAccess
        );
        // Live values pass through.
        assert_eq!(EnterpriseTab::from_str("appRoles"), EnterpriseTab::AppRoles);
        assert_eq!(EnterpriseTab::from_str("access"), EnterpriseTab::Access);
        // Unknown values fall back to Overview.
        assert_eq!(EnterpriseTab::from_str("nope"), EnterpriseTab::Overview);
    }

    #[test]
    fn from_str_roundtrips_all_live_values() {
        for tab in EnterpriseTab::ALL {
            assert_eq!(EnterpriseTab::from_str(tab.value()), *tab);
        }
    }

    #[test]
    fn all_lists_every_tab_in_order() {
        assert_eq!(EnterpriseTab::ALL.len(), 10);
        assert_eq!(EnterpriseTab::ALL[0], EnterpriseTab::Overview);
        assert_eq!(EnterpriseTab::ALL[9], EnterpriseTab::Activity);
    }
}
