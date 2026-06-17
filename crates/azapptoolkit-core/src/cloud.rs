//! Microsoft national/sovereign cloud endpoint selection.
//!
//! Every Microsoft service this toolkit talks to (Entra login, Graph, Exchange
//! Online, Key Vault, ARM) lives at a different host in each sovereign cloud, so
//! a tenant in US Gov / DoD / 21Vianet cannot use the commercial endpoints. The
//! cloud is a *deployment-time* choice (not a per-session toggle), selected via
//! the `AZAPPTOOLKIT_CLOUD` env var and defaulting to the commercial cloud.
//!
//! Endpoint values are from Microsoft's national-cloud / Graph deployment docs:
//! <https://learn.microsoft.com/en-us/graph/deployments> and
//! <https://learn.microsoft.com/en-us/entra/identity-platform/authentication-national-cloud>.

/// A Microsoft cloud instance. The commercial cloud is the default; the others
/// are the sovereign deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloudEnvironment {
    /// Global / commercial Azure (Azure AD `AzureCloud`).
    #[default]
    Commercial,
    /// US Government (GCC High) — `AzureUSGovernment`.
    UsGov,
    /// US Government DoD.
    UsGovDod,
    /// Azure China (21Vianet) — `AzureChinaCloud`.
    China,
}

impl CloudEnvironment {
    /// Canonical lowercase identifier (round-trips through [`Self::parse`]).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Commercial => "commercial",
            Self::UsGov => "usgov",
            Self::UsGovDod => "usgovdod",
            Self::China => "china",
        }
    }

    /// Human-readable label for the UI / logs.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Commercial => "Commercial (global)",
            Self::UsGov => "US Gov (GCC High)",
            Self::UsGovDod => "US Gov DoD",
            Self::China => "China (21Vianet)",
        }
    }

    /// Lenient parse of a cloud identifier (case-insensitive, common aliases).
    /// `None` for an unrecognized value so the caller can warn rather than
    /// silently defaulting.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "commercial" | "public" | "global" | "azurecloud" => Some(Self::Commercial),
            "usgov" | "gcchigh" | "gcc-high" | "usgovernment" | "azureusgovernment" => {
                Some(Self::UsGov)
            }
            "usgovdod" | "dod" | "usgovernmentdod" => Some(Self::UsGovDod),
            "china" | "21vianet" | "mooncake" | "azurechinacloud" => Some(Self::China),
            _ => None,
        }
    }

    /// Reads `AZAPPTOOLKIT_CLOUD`, defaulting to [`Self::Commercial`]. An
    /// unrecognized value logs a warning and falls back to commercial.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_env() -> Self {
        match std::env::var("AZAPPTOOLKIT_CLOUD") {
            Ok(v) if !v.trim().is_empty() => match Self::parse(&v) {
                Some(c) => c,
                None => {
                    tracing::warn!(
                        value = %v,
                        "unrecognized AZAPPTOOLKIT_CLOUD; using the commercial cloud"
                    );
                    Self::Commercial
                }
            },
            _ => Self::Commercial,
        }
    }

    /// Entra authority root (no trailing slash); authorities are
    /// `{root}/{tenant_id}`.
    pub fn login_authority_root(&self) -> &'static str {
        match self {
            Self::Commercial => "https://login.microsoftonline.com",
            Self::UsGov | Self::UsGovDod => "https://login.microsoftonline.us",
            Self::China => "https://login.partner.microsoftonline.cn",
        }
    }

    /// Microsoft Graph resource origin — the audience prefix for Graph delegated
    /// scopes (`{resource}/Directory.Read.All`).
    pub fn graph_resource(&self) -> &'static str {
        match self {
            Self::Commercial => "https://graph.microsoft.com",
            Self::UsGov => "https://graph.microsoft.us",
            Self::UsGovDod => "https://dod-graph.microsoft.us",
            Self::China => "https://microsoftgraph.chinacloudapi.cn",
        }
    }

    /// Microsoft Graph v1.0 base URL (the [`graph_resource`](Self::graph_resource)
    /// plus the version segment).
    pub fn graph_base(&self) -> String {
        format!("{}/v1.0", self.graph_resource())
    }

    /// Exchange Online Admin API origin — both the `Exchange.Manage` scope
    /// audience and the admin-API base host.
    pub fn exchange_resource(&self) -> &'static str {
        match self {
            Self::Commercial => "https://outlook.office365.com",
            Self::UsGov => "https://outlook.office365.us",
            Self::UsGovDod => "https://outlook-dod.office365.us",
            Self::China => "https://partner.outlook.cn",
        }
    }

    /// Key Vault DNS suffix (vault URLs are `https://{vault-name}.{suffix}`).
    pub fn keyvault_dns_suffix(&self) -> &'static str {
        match self {
            Self::Commercial => "vault.azure.net",
            Self::UsGov | Self::UsGovDod => "vault.usgovcloudapi.net",
            Self::China => "vault.azure.cn",
        }
    }

    /// Key Vault resource origin — the audience for the Key Vault `.default`
    /// token (`https://{dns-suffix}`).
    pub fn keyvault_resource(&self) -> String {
        format!("https://{}", self.keyvault_dns_suffix())
    }

    /// Azure Resource Manager origin — both the ARM `.default` scope audience and
    /// the ARM REST base host.
    pub fn arm_resource(&self) -> &'static str {
        match self {
            Self::Commercial => "https://management.azure.com",
            Self::UsGov | Self::UsGovDod => "https://management.usgovcloudapi.net",
            Self::China => "https://management.chinacloudapi.cn",
        }
    }

    /// Azure Monitor Logs query API origin — both the Log Analytics `.default`
    /// scope audience and the query base host (`{resource}/v1/workspaces/...`).
    /// Commercial uses the current `api.loganalytics.azure.com` (the legacy
    /// `api.loganalytics.io` remains supported but is being replaced).
    pub fn log_analytics_resource(&self) -> &'static str {
        match self {
            Self::Commercial => "https://api.loganalytics.azure.com",
            Self::UsGov | Self::UsGovDod => "https://api.loganalytics.us",
            Self::China => "https://api.loganalytics.azure.cn",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commercial_endpoints_are_byte_for_byte_the_legacy_constants() {
        // These must exactly equal the previously-hardcoded values so the
        // commercial cloud (the default) is unchanged.
        let c = CloudEnvironment::Commercial;
        assert_eq!(
            c.login_authority_root(),
            "https://login.microsoftonline.com"
        );
        assert_eq!(c.graph_resource(), "https://graph.microsoft.com");
        assert_eq!(c.graph_base(), "https://graph.microsoft.com/v1.0");
        assert_eq!(c.exchange_resource(), "https://outlook.office365.com");
        assert_eq!(c.keyvault_dns_suffix(), "vault.azure.net");
        assert_eq!(c.keyvault_resource(), "https://vault.azure.net");
        assert_eq!(c.arm_resource(), "https://management.azure.com");
        assert_eq!(
            c.log_analytics_resource(),
            "https://api.loganalytics.azure.com"
        );
    }

    #[test]
    fn us_gov_endpoints_match_the_documented_hosts() {
        let g = CloudEnvironment::UsGov;
        assert_eq!(g.login_authority_root(), "https://login.microsoftonline.us");
        assert_eq!(g.graph_base(), "https://graph.microsoft.us/v1.0");
        assert_eq!(g.exchange_resource(), "https://outlook.office365.us");
        assert_eq!(g.keyvault_resource(), "https://vault.usgovcloudapi.net");
        assert_eq!(g.arm_resource(), "https://management.usgovcloudapi.net");
        assert_eq!(g.log_analytics_resource(), "https://api.loganalytics.us");
    }

    #[test]
    fn dod_uses_the_dod_graph_and_exchange_hosts() {
        let d = CloudEnvironment::UsGovDod;
        assert_eq!(d.login_authority_root(), "https://login.microsoftonline.us");
        assert_eq!(d.graph_base(), "https://dod-graph.microsoft.us/v1.0");
        assert_eq!(d.exchange_resource(), "https://outlook-dod.office365.us");
        assert_eq!(d.arm_resource(), "https://management.usgovcloudapi.net");
    }

    #[test]
    fn china_endpoints_match_the_documented_hosts() {
        let c = CloudEnvironment::China;
        assert_eq!(
            c.login_authority_root(),
            "https://login.partner.microsoftonline.cn"
        );
        assert_eq!(
            c.graph_base(),
            "https://microsoftgraph.chinacloudapi.cn/v1.0"
        );
        assert_eq!(c.exchange_resource(), "https://partner.outlook.cn");
        assert_eq!(c.keyvault_resource(), "https://vault.azure.cn");
        assert_eq!(c.arm_resource(), "https://management.chinacloudapi.cn");
        assert_eq!(
            c.log_analytics_resource(),
            "https://api.loganalytics.azure.cn"
        );
    }

    #[test]
    fn parse_is_lenient_and_round_trips() {
        assert_eq!(
            CloudEnvironment::parse("").unwrap(),
            CloudEnvironment::Commercial
        );
        assert_eq!(
            CloudEnvironment::parse("  GCCHigh ").unwrap(),
            CloudEnvironment::UsGov
        );
        assert_eq!(
            CloudEnvironment::parse("DoD").unwrap(),
            CloudEnvironment::UsGovDod
        );
        assert_eq!(
            CloudEnvironment::parse("21Vianet").unwrap(),
            CloudEnvironment::China
        );
        assert!(CloudEnvironment::parse("nope").is_none());
        for c in [
            CloudEnvironment::Commercial,
            CloudEnvironment::UsGov,
            CloudEnvironment::UsGovDod,
            CloudEnvironment::China,
        ] {
            assert_eq!(CloudEnvironment::parse(c.as_str()).unwrap(), c);
        }
    }
}
