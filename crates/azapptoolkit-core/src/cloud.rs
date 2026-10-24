//! Microsoft national/sovereign cloud endpoint selection.
//!
//! Every Microsoft service this toolkit talks to (Entra login, Graph, Exchange
//! Online, Key Vault, ARM, Log Analytics) lives at a different host in each
//! sovereign cloud, so a tenant in US Gov / DoD / 21Vianet cannot use the
//! commercial endpoints. The cloud is a *deployment-time* choice (not a
//! per-session toggle), selected via `AZAPPTOOLKIT_CLOUD` (the runtime env var,
//! or baked at build time by the desktop crate) and defaulting to the
//! commercial cloud — see [`CloudEnvironment::select`].
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
    /// Every cloud, in the order the valid `AZAPPTOOLKIT_CLOUD` values are
    /// listed to an operator.
    pub const ALL: [Self; 4] = [Self::Commercial, Self::UsGov, Self::UsGovDod, Self::China];

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

    /// Every spelling [`Self::parse`] accepts for this cloud, lowercase, the
    /// canonical [`Self::as_str`] first, then the common aliases. The one
    /// vocabulary: `parse` reads it, and the desktop build script's
    /// `.env` check is held to it by a conformance test.
    pub fn accepted_names(&self) -> &'static [&'static str] {
        match self {
            Self::Commercial => &["commercial", "public", "global", "azurecloud"],
            Self::UsGov => &[
                "usgov",
                "gcchigh",
                "gcc-high",
                "usgovernment",
                "azureusgovernment",
            ],
            Self::UsGovDod => &["usgovdod", "dod", "usgovernmentdod"],
            Self::China => &["china", "21vianet", "mooncake", "azurechinacloud"],
        }
    }

    /// Lenient parse of a cloud identifier (case-insensitive, trimmed, any of
    /// [`Self::accepted_names`]; blank is the commercial default). `None` for
    /// an unrecognized value so the caller can warn rather than silently
    /// defaulting.
    pub fn parse(s: &str) -> Option<Self> {
        let name = s.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Some(Self::Commercial);
        }
        Self::ALL
            .into_iter()
            .find(|c| c.accepted_names().contains(&name.as_str()))
    }

    /// Resolves the cloud from its layers: the runtime `AZAPPTOOLKIT_CLOUD` env
    /// var, else the build-time bake, else [`Self::Commercial`]. A blank value
    /// counts as unset; an unrecognized one logs a warning and falls through to
    /// the next layer. Pure, so the precedence is testable without touching the
    /// process environment.
    pub fn select(env: Option<&str>, baked: Option<&str>) -> Self {
        Self::select_with_warning(env, baked).0
    }

    /// [`Self::select`], plus the operator-facing sentence when a layer named a
    /// cloud this build does not know — so the sign-in card can say the value
    /// was ignored (and which cloud is used instead) rather than leave a
    /// sovereign-cloud operator at a commercial login page wondering why. Names
    /// the ignored value(s) and lists the valid ones; `None` when nothing was
    /// ignored.
    pub fn select_with_warning(env: Option<&str>, baked: Option<&str>) -> (Self, Option<String>) {
        let mut ignored = Vec::new();
        let mut chosen = Self::Commercial;
        for (layer, value) in [("environment variable", env), ("build-time .env", baked)] {
            let Some(v) = value.filter(|v| !v.trim().is_empty()) else {
                continue;
            };
            match Self::parse(v) {
                Some(c) => {
                    chosen = c;
                    break;
                }
                None => {
                    tracing::warn!(
                        value = %v,
                        layer,
                        "unrecognized AZAPPTOOLKIT_CLOUD; ignoring it"
                    );
                    ignored.push(format!("\"{}\" (from the {layer})", v.trim()));
                }
            }
        }
        let warning = (!ignored.is_empty()).then(|| {
            let valid: Vec<&str> = Self::ALL.iter().map(Self::as_str).collect();
            format!(
                "AZAPPTOOLKIT_CLOUD {} is not a cloud azapptoolkit knows, so it was ignored and \
                 sign-in uses {}. Valid values: {} — correct it, then restart azapptoolkit.",
                ignored.join(" and "),
                chosen.display_name(),
                valid.join(", ")
            )
        });
        (chosen, warning)
    }

    /// Reads `AZAPPTOOLKIT_CLOUD` from the process environment, falling back to
    /// `baked` (the desktop crate's build-time value) and then to
    /// [`Self::Commercial`] — [`Self::select`] over the live env var.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_env_or(baked: Option<&str>) -> Self {
        Self::from_env_or_with_warning(baked).0
    }

    /// [`Self::from_env_or`] with [`Self::select_with_warning`]'s sentence for
    /// an ignored value.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_env_or_with_warning(baked: Option<&str>) -> (Self, Option<String>) {
        let env = std::env::var("AZAPPTOOLKIT_CLOUD").ok();
        Self::select_with_warning(env.as_deref(), baked)
    }

    /// Reads `AZAPPTOOLKIT_CLOUD`, defaulting to [`Self::Commercial`] (no
    /// build-time layer). An unrecognized value logs a warning and falls back
    /// to commercial.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_env() -> Self {
        Self::from_env_or(None)
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

    /// Entra's generic non-gallery ("custom") application template id — the
    /// template the SSO wizard instantiates. It differs per cloud; Learn lists
    /// global `8adf8e6e-…`, US government `4602d0b4-…` and China (21Vianet)
    /// `5a532e38-…`. DoD is not listed separately: it is served by the US
    /// Government cloud here, as it is for the login authority (an inference).
    /// <https://learn.microsoft.com/powershell/module/microsoft.entra.applications/new-entraapplicationfromapplicationtemplate>
    pub fn custom_app_template_id(&self) -> &'static str {
        match self {
            Self::Commercial => "8adf8e6e-67b2-4cf2-a259-e3dc5476c621",
            Self::UsGov | Self::UsGovDod => "4602d0b4-76bb-404b-bca9-2652e1a39c6d",
            Self::China => "5a532e38-1581-4918-9658-008dc27c1d68",
        }
    }

    /// SAML IdP entity id / issuer root (no trailing slash); the issuer is
    /// `{root}/{tenant_id}/`. Global and US Government use `sts.windows.net`
    /// (<https://learn.microsoft.com/entra/identity-platform/reference-saml-tokens>).
    /// For China (21Vianet) no Entra page states the SAML issuer; the only Learn
    /// evidence is the Dynamics 365 performance-SDK guidance, which names
    /// `https://sts.chinacloudapi.cn/` as the identity provider for 21Vianet
    /// deployments.
    pub fn saml_issuer_root(&self) -> &'static str {
        match self {
            Self::Commercial | Self::UsGov | Self::UsGovDod => "https://sts.windows.net",
            Self::China => "https://sts.chinacloudapi.cn",
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

    /// The `aud` value Entra requires in an external token presented for
    /// workload-identity-federation token exchange — the recommended value for
    /// a federated identity credential's `audiences`.
    ///
    /// Cloud-specific: a commercial `api://AzureADTokenExchange` in a sovereign
    /// tenant creates a credential Graph accepts without error and that then
    /// fails, silently, at exchange time. DoD is served by the US Government
    /// cloud here, as it is for the login authority.
    /// <https://learn.microsoft.com/entra/workload-id/workload-identity-federation-config-app-trust-managed-identity>
    pub fn token_exchange_audience(&self) -> &'static str {
        match self {
            Self::Commercial => "api://AzureADTokenExchange",
            Self::UsGov | Self::UsGovDod => "api://AzureADTokenExchangeUSGov",
            Self::China => "api://AzureADTokenExchangeChina",
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

    /// Microsoft Entra admin center origin for this cloud — the three hosts in
    /// Learn's Entra FAQ firewall allow-list (`entra.microsoft.com`,
    /// `entra.microsoft.us`, `entra.microsoftonline.cn`). DoD shares the US
    /// Government admin center, as it does the login authority.
    /// <https://learn.microsoft.com/entra/fundamentals/faq>
    pub fn entra_admin_center(&self) -> &'static str {
        match self {
            Self::Commercial => "https://entra.microsoft.com",
            Self::UsGov | Self::UsGovDod => "https://entra.microsoft.us",
            Self::China => "https://entra.microsoftonline.cn",
        }
    }

    /// PIM "My roles → Microsoft Entra roles" in this cloud's admin center —
    /// where an operator activates an eligible directory role. The readiness
    /// checklist links it under a role that reads Missing.
    pub fn pim_my_roles_url(&self) -> String {
        format!(
            "{}/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadmigratedroles",
            self.entra_admin_center()
        )
    }
}

/// Serialized as [`CloudEnvironment::as_str`] — the one wire vocabulary for a
/// cloud (a backup manifest's `cloud`, a restore plan's mismatch). Hand-written
/// rather than a serde `rename_all` so `as_str`/`parse` stay the only
/// definition of the labels.
impl serde::Serialize for CloudEnvironment {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Read back through [`CloudEnvironment::parse`], except that a blank value is
/// rejected: `parse("")` means "unset, use the default" for the env var, but a
/// manifest with an empty cloud must not quietly pass as commercial and slip
/// past restore's cross-cloud check.
impl<'de> serde::Deserialize<'de> for CloudEnvironment {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        if s.trim().is_empty() {
            return Err(D::Error::custom("cloud is empty"));
        }
        Self::parse(&s).ok_or_else(|| D::Error::custom(format!("unknown cloud '{s}'")))
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
        assert_eq!(
            c.custom_app_template_id(),
            "8adf8e6e-67b2-4cf2-a259-e3dc5476c621"
        );
        assert_eq!(c.saml_issuer_root(), "https://sts.windows.net");
    }

    #[test]
    fn custom_app_template_id_is_the_documented_non_gallery_template_per_cloud() {
        assert_eq!(
            CloudEnvironment::Commercial.custom_app_template_id(),
            "8adf8e6e-67b2-4cf2-a259-e3dc5476c621"
        );
        assert_eq!(
            CloudEnvironment::UsGov.custom_app_template_id(),
            "4602d0b4-76bb-404b-bca9-2652e1a39c6d"
        );
        assert_eq!(
            CloudEnvironment::UsGovDod.custom_app_template_id(),
            CloudEnvironment::UsGov.custom_app_template_id()
        );
        assert_eq!(
            CloudEnvironment::China.custom_app_template_id(),
            "5a532e38-1581-4918-9658-008dc27c1d68"
        );
    }

    #[test]
    fn select_prefers_env_then_baked_then_commercial() {
        use CloudEnvironment::*;
        assert_eq!(
            CloudEnvironment::select(Some("usgov"), Some("china")),
            UsGov
        );
        assert_eq!(CloudEnvironment::select(None, Some("china")), China);
        assert_eq!(CloudEnvironment::select(Some("  "), Some("china")), China);
        assert_eq!(
            CloudEnvironment::select(Some("bogus"), Some("usgovdod")),
            UsGovDod
        );
        assert_eq!(CloudEnvironment::select(None, Some("bogus")), Commercial);
        assert_eq!(CloudEnvironment::select(None, None), Commercial);
        assert_eq!(CloudEnvironment::select(Some(""), Some("")), Commercial);
    }

    /// An ignored value is said out loud: which value, from where, the cloud
    /// used instead, and the values that would have worked.
    #[test]
    fn select_with_warning_names_an_ignored_value_and_the_valid_ones() {
        use CloudEnvironment::*;
        for (env, baked) in [
            (Some("usgov"), Some("china")),
            (None, Some("china")),
            (None, None),
            (Some(" "), Some("")),
        ] {
            let (cloud, warning) = CloudEnvironment::select_with_warning(env, baked);
            assert_eq!(cloud, CloudEnvironment::select(env, baked));
            assert_eq!(warning, None, "{env:?} / {baked:?}");
        }

        let (cloud, warning) = CloudEnvironment::select_with_warning(Some("usgovv"), None);
        assert_eq!(cloud, Commercial);
        let warning = warning.expect("an ignored value warns");
        assert!(
            warning.contains("\"usgovv\" (from the environment variable)"),
            "{warning}"
        );
        assert!(warning.contains("Commercial (global)"), "{warning}");
        for c in CloudEnvironment::ALL {
            assert!(
                warning.contains(c.as_str()),
                "{warning} lacks {}",
                c.as_str()
            );
        }

        // A bad env var falls through to a good bake, and says so.
        let (cloud, warning) = CloudEnvironment::select_with_warning(Some("bogus"), Some("china"));
        assert_eq!(cloud, China);
        assert!(warning.unwrap().contains("China (21Vianet)"));

        // Both layers bad: both are named.
        let (_, warning) = CloudEnvironment::select_with_warning(Some("a"), Some("b"));
        let warning = warning.unwrap();
        assert!(
            warning.contains("\"a\" (from the environment variable)"),
            "{warning}"
        );
        assert!(
            warning.contains("\"b\" (from the build-time .env)"),
            "{warning}"
        );
    }

    #[test]
    fn every_cloud_is_listed_once_and_parses_from_its_own_name() {
        // Exhaustive (no wildcard): a new cloud must take a place in `ALL`
        // before this compiles, or the valid-values list would omit it.
        let place = |c: CloudEnvironment| match c {
            CloudEnvironment::Commercial => 0,
            CloudEnvironment::UsGov => 1,
            CloudEnvironment::UsGovDod => 2,
            CloudEnvironment::China => 3,
        };
        for (i, c) in CloudEnvironment::ALL.iter().enumerate() {
            assert_eq!(place(*c), i, "{c:?}");
            assert_eq!(CloudEnvironment::parse(c.as_str()), Some(*c));
        }
    }

    #[test]
    fn pim_link_stays_in_each_clouds_admin_center() {
        for (cloud, host) in [
            (CloudEnvironment::Commercial, "https://entra.microsoft.com/"),
            (CloudEnvironment::UsGov, "https://entra.microsoft.us/"),
            (CloudEnvironment::UsGovDod, "https://entra.microsoft.us/"),
            (CloudEnvironment::China, "https://entra.microsoftonline.cn/"),
        ] {
            let url = cloud.pim_my_roles_url();
            assert!(url.starts_with(host), "{cloud:?}: {url}");
            assert!(
                url.contains("Microsoft_Azure_PIMCommon"),
                "{cloud:?}: {url}"
            );
        }
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
        assert_eq!(g.saml_issuer_root(), "https://sts.windows.net");
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
        assert_eq!(c.saml_issuer_root(), "https://sts.chinacloudapi.cn");
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

    /// Each accepted name leads with the canonical one, parses back to its own
    /// cloud in any case, and belongs to exactly one cloud.
    #[test]
    fn accepted_names_are_canonical_first_and_unambiguous() {
        let mut seen = std::collections::HashSet::new();
        for c in CloudEnvironment::ALL {
            assert_eq!(c.accepted_names()[0], c.as_str(), "{c:?}");
            for name in c.accepted_names() {
                assert_eq!(*name, name.to_ascii_lowercase(), "{name}");
                assert_eq!(CloudEnvironment::parse(name), Some(c), "{name}");
                assert_eq!(CloudEnvironment::parse(&name.to_ascii_uppercase()), Some(c));
                assert!(seen.insert(*name), "{name} names two clouds");
            }
        }
    }

    #[test]
    fn serde_uses_the_as_str_vocabulary() {
        use serde_json::json;
        for c in [
            CloudEnvironment::Commercial,
            CloudEnvironment::UsGov,
            CloudEnvironment::UsGovDod,
            CloudEnvironment::China,
        ] {
            assert_eq!(serde_json::to_value(c).unwrap(), json!(c.as_str()));
            let back: CloudEnvironment = serde_json::from_value(json!(c.as_str())).unwrap();
            assert_eq!(back, c);
        }
        // Lenient on read, like `parse`.
        let commercial: CloudEnvironment = serde_json::from_value(json!("Commercial")).unwrap();
        assert_eq!(commercial, CloudEnvironment::Commercial);
        // A blank label must not default to commercial, and an unknown one fails.
        assert!(serde_json::from_value::<CloudEnvironment>(json!("")).is_err());
        assert!(serde_json::from_value::<CloudEnvironment>(json!("mars")).is_err());
    }
}
