//! Signed-in identity context shared across the IPC boundary.
//!
//! Lives in core (not auth) so both the auth crate and the WASM frontend can
//! use one definition — the frontend can't depend on auth (tokio/reqwest), and
//! dto already depends on auth, so auth can't depend on dto.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantContext {
    pub tenant_id: String,
    pub account_oid: String,
    pub username: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignInOutcome {
    pub tenant: TenantContext,
}

/// The one spelling of a configured tenant id: trimmed and ASCII-lowercased.
///
/// Entra issues the id token's `tid` claim (and so every `TenantContext`,
/// cache key and keyring entry derived from it) as a lowercase GUID, while
/// the configured value is operator-typed and a GUID is case-insensitive. Every
/// place a configured tenant enters the app (the auth service, `AppState`
/// resolution, the config screen's save) goes through this, so an uppercase
/// GUID compares equal to its `tid` instead of failing sign-in after a full
/// browser round trip and never matching the remembered account at launch.
pub fn canonical_tenant_id(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_tenant_id_matches_the_lowercase_tid() {
        assert_eq!(
            canonical_tenant_id(" 3FA85F64-5717-4562-B3FC-2C963F66AFA6 "),
            "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        );
        assert_eq!(
            canonical_tenant_id("3fa85f64-5717-4562-b3fc-2c963f66afa6"),
            "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        );
    }

    #[test]
    fn tenant_context_round_trips_through_json() {
        let original = TenantContext {
            tenant_id: "11111111-1111-1111-1111-111111111111".into(),
            account_oid: "22222222-2222-2222-2222-222222222222".into(),
            username: Some("user@contoso.com".into()),
            display_name: Some("Test User".into()),
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: TenantContext = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn tenant_context_uses_snake_case_keys_on_wire() {
        let t = TenantContext {
            tenant_id: "t".into(),
            account_oid: "o".into(),
            username: None,
            display_name: None,
        };
        let v: serde_json::Value = serde_json::to_value(&t).unwrap();
        assert!(v.get("tenant_id").is_some());
        assert!(v.get("account_oid").is_some());
        // Frontend reads these keys; renaming the struct fields must not
        // silently shift the wire shape.
        assert!(v.get("tenantId").is_none());
    }

    #[test]
    fn tenant_context_null_optional_fields_deserialize_as_none() {
        // What the frontend currently sends when a user has no UPN / display
        // name configured: explicit null rather than an omitted key.
        let json = r#"{"tenant_id":"t","account_oid":"o","username":null,"display_name":null}"#;
        let t: TenantContext = serde_json::from_str(json).unwrap();
        assert!(t.username.is_none());
        assert!(t.display_name.is_none());
    }

    #[test]
    fn sign_in_outcome_round_trips() {
        let outcome = SignInOutcome {
            tenant: TenantContext {
                tenant_id: "t".into(),
                account_oid: "o".into(),
                username: None,
                display_name: None,
            },
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: SignInOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome.tenant, back.tenant);
    }
}
