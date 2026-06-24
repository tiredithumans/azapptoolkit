//! Single-sign-on (SAML / OIDC) setup IPC DTOs.
//!
//! Drives the "New SSO application" wizard and the enterprise-app detail "SSO"
//! tab. Input types use `camelCase` (the Tauri JS-arg convention); the summary
//! result types follow the `CreateApplicationResult` precedent and keep the
//! struct's snake_case field names — the front-end reuses these exact structs,
//! so serialization is symmetric either way.

use serde::{Deserialize, Serialize};

/// One claim-schema entry in a claims-mapping policy (a row in the portal's
/// "Attributes & Claims" blade). Models the full documented entry — see
/// <https://learn.microsoft.com/entra/identity-platform/reference-claims-customization>.
///
/// The value comes from one of three shapes:
/// - **attribute**: `source` (`user`/`application`/`resource`/`audience`/`company`)
///   + `id` (the source property, e.g. `userprincipalname`),
/// - **extension attribute**: `source` + `extension_id`,
/// - **constant**: `value` only (no `source`),
/// - **transformation-sourced**: `source = "transformation"` + `id` (the
///   transformation's id; emitted as `TransformationID` in the Graph schema).
///
/// The emitted claim is named by `saml_claim_type` (SAML token claim URI) and/or
/// `jwt_claim_type` (JWT/OIDC token claim name); at least one is normally set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimSchemaEntryDto {
    /// `Source`: `user` | `application` | `resource` | `audience` | `company` |
    /// `transformation`. `None` ⇒ a constant claim (`value`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// `ID` — the source attribute; or the transformation id when
    /// `source == "transformation"` (emitted as `TransformationID`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `ExtensionID` — a directory extension attribute (alternative to `id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_id: Option<String>,
    /// `Value` — a static constant value (used instead of `source`/`id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// `SamlClaimType` — the claim URI emitted in SAML tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_claim_type: Option<String>,
    /// `JwtClaimType` — the claim name emitted in JWT/OIDC tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_claim_type: Option<String>,
    /// `SAMLNameForm` — the SAML `NameFormat` attribute, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_name_form: Option<String>,
}

/// An input claim for a claims transformation (`InputClaims[]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransformInputClaimDto {
    /// `ClaimTypeReferenceId` — joined with a claim-schema entry's `id`.
    pub claim_type_reference_id: String,
    /// `TransformationClaimType` — a unique input name expected by the method.
    pub transformation_claim_type: String,
    /// `TreatAsMultiValue` — apply to all values of a multi-valued claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub treat_as_multi_value: Option<bool>,
}

/// A constant input parameter for a claims transformation (`InputParameters[]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransformParamDto {
    /// `ID` — a unique input name expected by the method (e.g. `separator`).
    pub id: String,
    /// `Value` — the constant value passed to the transformation.
    pub value: String,
}

/// An output claim produced by a claims transformation (`OutputClaims[]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransformOutputClaimDto {
    /// `ClaimTypeReferenceId` — joined with a claim-schema entry's `id`.
    pub claim_type_reference_id: String,
    /// `TransformationClaimType` — a unique output name expected by the method.
    pub transformation_claim_type: String,
}

/// One claims-transformation entry (`ClaimsTransformation[]`). Generates data
/// for a transformation-sourced claim schema entry that references it by `id`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimsTransformationDto {
    /// `ID` — referenced by a schema entry's `TransformationID`. Must be unique.
    pub id: String,
    /// `TransformationMethod` — `Join` | `ExtractMailPrefix` | `ToLowercase()` |
    /// `ToUppercase()` | `RegexReplace()`.
    pub method: String,
    #[serde(default)]
    pub input_claims: Vec<TransformInputClaimDto>,
    #[serde(default)]
    pub input_parameters: Vec<TransformParamDto>,
    #[serde(default)]
    pub output_claims: Vec<TransformOutputClaimDto>,
}

fn default_true() -> bool {
    true
}

/// A full claims-mapping policy as edited in the "Attributes & claims" UI. The
/// backend translates this clean (camelCase) model to/from Microsoft's
/// PascalCase `ClaimsMappingPolicy` definition JSON. Policy-level fields this
/// model doesn't surface (e.g. `GroupFilter`, `issuerWithApplicationId`,
/// `audienceOverride`) are round-tripped untouched via [`Self::preserved_options`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimsPolicyDto {
    /// `IncludeBasicClaimSet` — emit the basic claim set alongside the schema.
    /// Defaults to `true`: Entra includes the basic set when no policy is
    /// assigned, so seeding a fresh editor with `false` would make adding a
    /// first custom claim silently *suppress* the basic set.
    #[serde(default = "default_true")]
    pub include_basic_claim_set: bool,
    #[serde(default)]
    pub schema: Vec<ClaimSchemaEntryDto>,
    #[serde(default)]
    pub transformations: Vec<ClaimsTransformationDto>,
    /// Opaque JSON object string of policy-level keys the editor doesn't model
    /// (captured on read, re-merged on write so a save never drops them). The
    /// frontend treats this as an opaque blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preserved_options: Option<String>,
}

impl Default for ClaimsPolicyDto {
    fn default() -> Self {
        Self {
            include_basic_claim_set: true,
            schema: Vec::new(),
            transformations: Vec::new(),
            preserved_options: None,
        }
    }
}

impl ClaimsPolicyDto {
    /// True when saving this policy would be a no-op — no schema entries, no
    /// transformations, no preserved advanced options, and the basic claim set
    /// left at Entra's default (included). Used to decide between "create+assign"
    /// and "remove the policy entirely". Anything else (incl. *suppressing* the
    /// basic set, or a preserved group-filter/issuer override) is a real policy.
    pub fn is_empty(&self) -> bool {
        self.schema.is_empty()
            && self.transformations.is_empty()
            && self.preserved_options.is_none()
            && self.include_basic_claim_set
    }
}

/// Input for `create_saml_sso_application`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlSsoConfigInput {
    pub display_name: String,
    /// SP identifier / Entity ID → `identifierUris[0]`.
    pub entity_id: String,
    /// Assertion Consumer Service (Reply) URL → `web.redirectUris[0]`.
    pub reply_url: String,
    pub logout_url: Option<String>,
    /// Subject for the generated token-signing certificate (e.g. `CN=Contoso`).
    /// Defaults to `CN={display_name}` server-side when omitted.
    pub cert_subject: Option<String>,
    /// Certificate validity in days; defaults to 365 server-side.
    pub cert_lifetime_days: Option<u32>,
    /// Optional custom claims-mapping policy; `None`/empty leaves Entra's default
    /// claim set (and avoids the `Policy.ReadWrite.ApplicationConfiguration`
    /// consent).
    #[serde(default)]
    pub claims_policy: Option<ClaimsPolicyDto>,
    /// Optional SAML signing-certificate expiry notification recipients
    /// (`notificationEmailAddresses`). Entra also seeds the creating admin.
    #[serde(default)]
    pub notification_emails: Vec<String>,
}

/// Input for `create_oidc_sso_application`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcSsoConfigInput {
    pub display_name: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub spa_redirect_uris: Vec<String>,
    /// When set, mint a client secret with this display name (returned once).
    pub secret_display_name: Option<String>,
    /// Secret lifetime in days; defaults to 180 server-side when omitted.
    pub secret_lifetime_days: Option<u32>,
}

/// App-owner output summary for a SAML SSO integration. Also the result of
/// `create_saml_sso_application`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SamlSsoSummary {
    /// Application object id.
    pub object_id: String,
    pub service_principal_id: String,
    /// Application (client) id.
    pub app_id: String,
    /// Microsoft Entra Identifier / Issuer: `https://sts.windows.net/{tenant}/`.
    pub entity_id_issuer: String,
    /// Login URL: `https://login.microsoftonline.com/{tenant}/saml2`.
    pub login_url: String,
    /// Logout URL: `https://login.microsoftonline.com/{tenant}/saml2`.
    pub logout_url: String,
    /// App Federation Metadata URL.
    pub federation_metadata_url: String,
    /// The configured SP identifier (Entity ID) on the app side.
    pub sp_entity_id: String,
    /// The configured Reply / ACS URL.
    pub reply_url: String,
    pub signing_cert_base64: Option<String>,
    pub signing_cert_thumbprint: Option<String>,
    pub signing_cert_expiry: Option<String>,
    /// Set when a custom claims-mapping policy was created and assigned.
    pub claims_policy_id: Option<String>,
}

/// App-owner output summary for an OIDC SSO integration. Also the result of
/// `create_oidc_sso_application`. `client_secret` is populated only at creation
/// (show-once) and never re-read.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OidcSsoSummary {
    pub object_id: String,
    pub service_principal_id: String,
    pub client_id: String,
    pub tenant_id: String,
    /// Authority: `https://login.microsoftonline.com/{tenant}/v2.0`.
    pub authority: String,
    /// OIDC discovery document URL.
    pub discovery_url: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub spa_redirect_uris: Vec<String>,
    pub client_secret: Option<String>,
    pub client_secret_expiry: Option<String>,
}

/// Current SSO configuration of an existing enterprise app, read by
/// `get_sso_config` to drive the detail-pane "SSO" tab.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SsoConfigDto {
    pub object_id: String,
    pub service_principal_id: String,
    pub app_id: String,
    /// `preferredSingleSignOnMode`: `saml`, `oidc`, `password`, … or `None`.
    pub sso_mode: Option<String>,
    /// `identifierUris[0]` (SAML Entity ID), if any. Kept for the app-owner
    /// summary; the SSO tab edits the full [`Self::identifier_uris`] list.
    pub entity_id: Option<String>,
    /// All SAML identifiers (`identifierUris`) — the portal allows several.
    #[serde(default)]
    pub identifier_uris: Vec<String>,
    #[serde(default)]
    pub reply_urls: Vec<String>,
    pub logout_url: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub spa_redirect_uris: Vec<String>,
    pub signing_cert_thumbprint: Option<String>,
    pub signing_cert_expiry: Option<String>,
    /// SAML signing-cert expiry notification recipients
    /// (`notificationEmailAddresses` on the service principal).
    #[serde(default)]
    pub notification_emails: Vec<String>,
    /// The currently assigned claims-mapping policy, decoded for editing.
    /// `None` when no policy is assigned (or the read was skipped on missing
    /// scope/consent).
    #[serde(default)]
    pub claims_policy: Option<ClaimsPolicyDto>,
    pub claims_policy_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saml_input_uses_camel_case_args() {
        let input = SamlSsoConfigInput {
            display_name: "Demo".into(),
            entity_id: "https://app/saml".into(),
            reply_url: "https://app/acs".into(),
            logout_url: None,
            cert_subject: None,
            cert_lifetime_days: Some(365),
            claims_policy: Some(ClaimsPolicyDto {
                include_basic_claim_set: true,
                schema: vec![ClaimSchemaEntryDto {
                    source: Some("user".into()),
                    id: Some("userprincipalname".into()),
                    saml_claim_type: Some("https://example/role".into()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            notification_emails: vec!["admin@contoso.com".into()],
        };
        let json = serde_json::to_value(&input).unwrap();
        // Tauri sends args as camelCase; assert the wire names match.
        assert!(json.get("displayName").is_some());
        assert!(json.get("entityId").is_some());
        assert!(json.get("replyUrl").is_some());
        assert!(json.get("certLifetimeDays").is_some());
        assert!(json.get("notificationEmails").is_some());
        assert_eq!(
            json["claimsPolicy"]["schema"][0]["samlClaimType"],
            "https://example/role"
        );
        assert_eq!(json["claimsPolicy"]["includeBasicClaimSet"], true);
    }

    #[test]
    fn claims_policy_is_empty_only_at_entra_defaults() {
        // Default (basic set included, nothing custom) ⇒ removing the policy.
        assert!(ClaimsPolicyDto::default().is_empty());
        // Suppressing the basic set is a real policy even with no claims.
        assert!(
            !ClaimsPolicyDto {
                include_basic_claim_set: false,
                ..Default::default()
            }
            .is_empty()
        );
        // A preserved advanced option (e.g. group filter) is a real policy.
        assert!(
            !ClaimsPolicyDto {
                preserved_options: Some("{\"GroupFilter\":{}}".into()),
                ..Default::default()
            }
            .is_empty()
        );
        // A schema entry is a real policy.
        assert!(
            !ClaimsPolicyDto {
                schema: vec![ClaimSchemaEntryDto::default()],
                ..Default::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn claim_schema_entry_omits_empty_optional_fields() {
        // A constant claim: only `value` + `jwtClaimType` set; no `source`/`id`.
        let entry = ClaimSchemaEntryDto {
            value: Some("sandbox".into()),
            jwt_claim_type: Some("env".into()),
            ..Default::default()
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["value"], "sandbox");
        assert_eq!(json["jwtClaimType"], "env");
        // Unset optionals must not serialize (camelCase + skip_serializing_if).
        assert!(json.get("source").is_none());
        assert!(json.get("id").is_none());
        assert!(json.get("samlClaimType").is_none());
    }

    #[test]
    fn oidc_input_defaults_collections() {
        let json = r#"{"displayName":"Demo"}"#;
        let input: OidcSsoConfigInput = serde_json::from_str(json).unwrap();
        assert!(input.redirect_uris.is_empty());
        assert!(input.spa_redirect_uris.is_empty());
        assert!(input.secret_display_name.is_none());
    }

    #[test]
    fn summaries_round_trip() {
        let saml = SamlSsoSummary {
            object_id: "o".into(),
            app_id: "a".into(),
            ..Default::default()
        };
        let back: SamlSsoSummary =
            serde_json::from_str(&serde_json::to_string(&saml).unwrap()).unwrap();
        assert_eq!(back.object_id, "o");

        let oidc = OidcSsoSummary {
            client_id: "c".into(),
            ..Default::default()
        };
        let back: OidcSsoSummary =
            serde_json::from_str(&serde_json::to_string(&oidc).unwrap()).unwrap();
        assert_eq!(back.client_id, "c");
    }
}
