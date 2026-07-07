//! Per-tenant operator defaults, persisted inside `settings.json` (see
//! [`crate::settings::UserSettings`]) and edited from the Settings page.
//!
//! Everything here is keyed by tenant because the values are tenant-specific: a
//! default *owner* is a directory-object id that only exists in one tenant, and
//! a vault *binding* names a vault reachable from one tenant. Nothing sensitive
//! is stored — only display names, directory ids, vault/secret names, and email
//! addresses (no secrets), consistent with the security invariant.
//!
//! The types double as the IPC payload for `get_tenant_defaults` /
//! `set_tenant_defaults`; the frontend uses them directly.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A directory principal saved as a default owner — the subset of
/// [`crate::models::DirectoryObject`] needed to re-add it without re-searching.
/// `odata_type` is retained for display (user vs group vs service principal);
/// applying an owner only needs `id`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPrincipal {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub user_principal_name: Option<String>,
    #[serde(default)]
    pub odata_type: Option<String>,
}

/// Where an app registration's rotated client secret is stored. `secret_name`
/// is remembered so a later rotation can pre-select the same secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppVaultBinding {
    pub vault_name: String,
    #[serde(default)]
    pub secret_name: Option<String>,
}

/// Defaults that apply to app registrations. Their owners may be users, groups,
/// or service principals (Graph accepts all three as app-registration owners).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRegistrationDefaults {
    #[serde(default)]
    pub default_owners: Vec<StoredPrincipal>,
}

/// Defaults that apply to enterprise applications (service principals). SP owners
/// may only be **users** (Graph rejects groups), and the SSO notification email
/// default seeds the SAML signing-certificate-expiry recipient list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseApplicationDefaults {
    #[serde(default)]
    pub default_owners: Vec<StoredPrincipal>,
    #[serde(default)]
    pub default_notification_emails: Vec<String>,
}

/// All operator defaults for a single tenant.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantDefaults {
    #[serde(default)]
    pub app_registration: AppRegistrationDefaults,
    #[serde(default)]
    pub enterprise_application: EnterpriseApplicationDefaults,
    /// Management-scope-name template for **all** Exchange mailbox scoping —
    /// fresh scoped grants and the legacy-AAP migration alike. `{appId}` is
    /// substituted with the app's client id. Blank/`None` ⇒ the built-in
    /// `app_scope_{appId}` default. See [`Self::scope_name_for`].
    #[serde(default)]
    pub scope_name_pattern: Option<String>,
    /// Mail-enabled-security-group-name template for the toolkit-managed scope
    /// group whose membership defines which mailboxes an app can reach (used by
    /// all Exchange scoping). `{appId}` is substituted with the app's client id.
    /// Blank/`None` ⇒ the built-in `app_scope_group_{appId}` default. See
    /// [`Self::group_name_for`].
    #[serde(default)]
    pub group_name_pattern: Option<String>,
    /// Key Vault secret-name template for credential rotation. `{appId}` is
    /// substituted with the app's client id. Blank/`None` ⇒ the built-in
    /// `secret-{appId}` default. See [`Self::secret_name_for`]. (Key Vault secret
    /// names allow only alphanumerics and dashes — no underscores — so the prefix
    /// is `secret-`, not `secret_`.)
    #[serde(default)]
    pub secret_name_pattern: Option<String>,
    /// Tenant-level fallback vault for credential rotation (used when an app has
    /// no [`app_vaults`](Self::app_vaults) binding yet).
    #[serde(default)]
    pub default_vault: Option<String>,
    /// Per-app-registration memory of where each app's secret was last rotated,
    /// keyed by the app's client (application) id.
    #[serde(default)]
    pub app_vaults: BTreeMap<String, AppVaultBinding>,
}

/// The built-in management-scope-name prefix, used by
/// [`TenantDefaults::scope_name_for`] when no custom pattern is set. The
/// `{appId}` placeholder in a custom pattern is replaced with the app's client id.
pub const DEFAULT_SCOPE_NAME_PREFIX: &str = "app_scope_";
/// The built-in mail-enabled-scope-group-name prefix, used by
/// [`TenantDefaults::group_name_for`] when no custom pattern is set. Deliberately
/// distinct from [`DEFAULT_SCOPE_NAME_PREFIX`] so a management scope and its
/// backing mail-group never collide on name.
pub const DEFAULT_GROUP_NAME_PREFIX: &str = "app_scope_group_";
/// Placeholder token substituted in a custom [`TenantDefaults::scope_name_pattern`],
/// [`TenantDefaults::group_name_pattern`], or [`TenantDefaults::secret_name_pattern`].
pub const SCOPE_NAME_PLACEHOLDER: &str = "{appId}";
/// The built-in Key Vault secret-name prefix. Uses a dash (KV secret names
/// forbid underscores).
pub const DEFAULT_SECRET_NAME_PREFIX: &str = "secret-";

impl TenantDefaults {
    /// Resolves the management-scope name for `app_id`: the custom pattern with
    /// `{appId}` substituted if one is set (and non-blank), else the built-in
    /// `app_scope_<app_id>`.
    pub fn scope_name_for(&self, app_id: &str) -> String {
        match self.scope_name_pattern.as_deref().map(str::trim) {
            Some(pat) if !pat.is_empty() => pat.replace(SCOPE_NAME_PLACEHOLDER, app_id),
            _ => format!("{DEFAULT_SCOPE_NAME_PREFIX}{app_id}"),
        }
    }

    /// Resolves the mail-enabled-security-group name for `app_id`: the custom
    /// pattern with `{appId}` substituted if one is set (and non-blank), else the
    /// built-in `app_scope_group_<app_id>`. Kept distinct from
    /// [`scope_name_for`](Self::scope_name_for) so a scope and its backing group
    /// never collide on name.
    pub fn group_name_for(&self, app_id: &str) -> String {
        match self.group_name_pattern.as_deref().map(str::trim) {
            Some(pat) if !pat.is_empty() => pat.replace(SCOPE_NAME_PLACEHOLDER, app_id),
            _ => format!("{DEFAULT_GROUP_NAME_PREFIX}{app_id}"),
        }
    }

    /// Resolves the Key Vault secret name for `app_id`: the custom pattern with
    /// `{appId}` substituted if one is set (and non-blank), else the built-in
    /// `secret-<app_id>`. The caller should still sanitize to KV-safe characters.
    pub fn secret_name_for(&self, app_id: &str) -> String {
        match self.secret_name_pattern.as_deref().map(str::trim) {
            Some(pat) if !pat.is_empty() => pat.replace(SCOPE_NAME_PLACEHOLDER, app_id),
            _ => format!("{DEFAULT_SECRET_NAME_PREFIX}{app_id}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_name_falls_back_to_the_builtin_default() {
        let d = TenantDefaults::default();
        assert_eq!(d.scope_name_for("app-1"), "app_scope_app-1");
    }

    #[test]
    fn blank_pattern_is_treated_as_unset() {
        let d = TenantDefaults {
            scope_name_pattern: Some("   ".into()),
            ..Default::default()
        };
        assert_eq!(d.scope_name_for("app-1"), "app_scope_app-1");
    }

    #[test]
    fn custom_pattern_substitutes_the_app_id() {
        let d = TenantDefaults {
            scope_name_pattern: Some("scope-{appId}-mail".into()),
            ..Default::default()
        };
        assert_eq!(d.scope_name_for("app-1"), "scope-app-1-mail");
    }

    #[test]
    fn group_name_defaults_to_app_scope_group_and_honors_a_pattern() {
        let d = TenantDefaults::default();
        assert_eq!(d.group_name_for("app-1"), "app_scope_group_app-1");
        let custom = TenantDefaults {
            group_name_pattern: Some("grp-{appId}".into()),
            ..Default::default()
        };
        assert_eq!(custom.group_name_for("app-1"), "grp-app-1");
        // Blank pattern falls back to the built-in default.
        let blank = TenantDefaults {
            group_name_pattern: Some("  ".into()),
            ..Default::default()
        };
        assert_eq!(blank.group_name_for("app-1"), "app_scope_group_app-1");
    }

    #[test]
    fn scope_and_group_default_names_stay_distinct() {
        // The management scope and its backing mail-group must never collide on
        // name (mirrors the backend `scope_and_group_names_follow_distinct_conventions`).
        let d = TenantDefaults::default();
        assert_ne!(d.scope_name_for("app-1"), d.group_name_for("app-1"));
    }

    #[test]
    fn secret_name_defaults_to_secret_dash_appid_and_honors_a_pattern() {
        // KV secret names forbid underscores, so the built-in prefix is `secret-`.
        let d = TenantDefaults::default();
        assert_eq!(d.secret_name_for("app-1"), "secret-app-1");
        let custom = TenantDefaults {
            secret_name_pattern: Some("kv-{appId}-rot".into()),
            ..Default::default()
        };
        assert_eq!(custom.secret_name_for("app-1"), "kv-app-1-rot");
        // Blank pattern falls back to the built-in default.
        let blank = TenantDefaults {
            secret_name_pattern: Some("  ".into()),
            ..Default::default()
        };
        assert_eq!(blank.secret_name_for("app-1"), "secret-app-1");
    }

    #[test]
    fn round_trips_through_json() {
        let d = TenantDefaults {
            app_registration: AppRegistrationDefaults {
                default_owners: vec![StoredPrincipal {
                    id: "u-1".into(),
                    display_name: Some("Ada".into()),
                    user_principal_name: Some("ada@contoso.com".into()),
                    odata_type: Some("#microsoft.graph.user".into()),
                }],
            },
            enterprise_application: EnterpriseApplicationDefaults {
                default_owners: vec![],
                default_notification_emails: vec!["ops@contoso.com".into()],
            },
            scope_name_pattern: None,
            group_name_pattern: Some("grp-{appId}".into()),
            secret_name_pattern: Some("secret-{appId}".into()),
            default_vault: Some("kv-contoso".into()),
            app_vaults: BTreeMap::from([(
                "app-1".into(),
                AppVaultBinding {
                    vault_name: "kv-contoso".into(),
                    secret_name: Some("app-1-secret".into()),
                },
            )]),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: TenantDefaults = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}
