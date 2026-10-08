//! The "Attributes & claims" view: an app's SAML claims as the Entra admin
//! center shows them (the required Name ID claim, then every additional claim),
//! read from whichever policy is in effect.
//!
//! Entra applies the first of these that exists:
//! 1. an assigned **claims mapping policy** (the legacy model, and what this
//!    app's editor writes): authoritative, and while it is assigned the admin
//!    center can't edit the app's claims;
//! 2. the **custom claims policy** the admin center writes;
//! 3. Entra's **defaults** (`dto::sso::DEFAULT_SAML_CLAIMS`).
//!
//! Values are written as the admin center writes them (`user.mail`,
//! `"constant"`, `Join(user.givenname, ".", user.surname)`), so the two can be
//! compared side by side. Pure: `get_sso_config_core` does the reads.

use azapptoolkit_core::models::{
    CustomClaim, CustomClaimAttribute, CustomClaimConfiguration, CustomClaimsPolicy,
};

use crate::dto::sso::{
    ClaimRowDto, ClaimSchemaEntryDto, ClaimsPolicyDto, ClaimsSource, ClaimsTransformationDto,
    ClaimsViewDto, DEFAULT_NAME_ID_ATTRIBUTE, DEFAULT_NAME_ID_FORMAT, DEFAULT_SAML_CLAIMS,
    NAME_IDENTIFIER_CLAIM,
};

/// The admin center's label for the required claim.
const NAME_ID_LABEL: &str = "Unique User Identifier (Name ID)";
/// The SAML claim URI the admin center lists group claims under.
const GROUPS_CLAIM: &str = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups";

/// An assigned claims mapping policy, decoded, with its display name.
pub(crate) struct AssignedMappingPolicy<'a> {
    pub(crate) policy: &'a ClaimsPolicyDto,
    pub(crate) name: Option<&'a str>,
}

/// The app's claims as the admin center shows them. `group_claims` is the
/// application's `groupMembershipClaims`.
pub(crate) fn claims_view(
    mapping: Option<AssignedMappingPolicy<'_>>,
    portal: Option<&CustomClaimsPolicy>,
    group_claims: Option<&str>,
) -> ClaimsViewDto {
    let mut view = match (mapping, portal) {
        (Some(mapping), portal) => from_mapping_policy(&mapping, portal.is_some()),
        (None, Some(portal)) => from_portal_policy(portal),
        (None, None) => ClaimsViewDto {
            source: ClaimsSource::Default,
            mapping_policy_name: None,
            portal_policy_overridden: false,
            portal_policy_unreadable: false,
            required: default_name_id(),
            additional: default_claims(),
        },
    };
    if let Some(groups) = group_claims
        .map(str::trim)
        .filter(|g| !g.is_empty() && !g.eq_ignore_ascii_case("none"))
    {
        let listed = view
            .additional
            .iter()
            .any(|row| row.name.eq_ignore_ascii_case(GROUPS_CLAIM) || row.name == "groups");
        if !listed {
            view.additional.push(ClaimRowDto {
                name: GROUPS_CLAIM.into(),
                token_types: vec!["SAML".into()],
                value: format!("user.groups [{groups}]"),
                detail: None,
            });
        }
    }
    view
}

fn default_name_id() -> ClaimRowDto {
    ClaimRowDto {
        name: NAME_ID_LABEL.into(),
        token_types: vec!["SAML".into()],
        value: format!("user.{DEFAULT_NAME_ID_ATTRIBUTE}"),
        detail: Some(format!("[nameid-format:{DEFAULT_NAME_ID_FORMAT}]")),
    }
}

fn default_claims() -> Vec<ClaimRowDto> {
    DEFAULT_SAML_CLAIMS
        .iter()
        .map(|&(_, uri, attribute)| ClaimRowDto {
            name: uri.into(),
            token_types: vec!["SAML".into()],
            value: format!("user.{attribute}"),
            detail: None,
        })
        .collect()
}

/// Appends each default claim that no listed claim of the same name supersedes.
fn merge_basic_set(rows: &mut Vec<ClaimRowDto>) {
    for basic in default_claims() {
        if !rows
            .iter()
            .any(|r| r.name.eq_ignore_ascii_case(&basic.name))
        {
            rows.push(basic);
        }
    }
}

// ---------------- Claims mapping policy ----------------

fn from_mapping_policy(mapping: &AssignedMappingPolicy<'_>, portal_exists: bool) -> ClaimsViewDto {
    let policy = mapping.policy;
    let is_name_id = |e: &ClaimSchemaEntryDto| {
        e.saml_claim_type
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case(NAME_IDENTIFIER_CLAIM))
    };
    let required = match policy.schema.iter().find(|e| is_name_id(e)) {
        Some(entry) => ClaimRowDto {
            name: NAME_ID_LABEL.into(),
            token_types: vec!["SAML".into()],
            value: schema_value(entry, policy),
            detail: None,
        },
        None if policy.include_basic_claim_set => default_name_id(),
        None => ClaimRowDto {
            name: NAME_ID_LABEL.into(),
            token_types: vec!["SAML".into()],
            value: "(not mapped by this policy)".into(),
            detail: None,
        },
    };
    let mut additional: Vec<ClaimRowDto> = policy
        .schema
        .iter()
        .filter(|e| !is_name_id(e))
        .map(|entry| {
            let mut token_types = Vec::new();
            if entry.saml_claim_type.is_some() {
                token_types.push("SAML".to_string());
            }
            if entry.jwt_claim_type.is_some() {
                token_types.push("JWT".to_string());
            }
            ClaimRowDto {
                name: entry
                    .saml_claim_type
                    .clone()
                    .or_else(|| entry.jwt_claim_type.clone())
                    .unwrap_or_else(|| "(unnamed)".into()),
                token_types,
                value: schema_value(entry, policy),
                detail: None,
            }
        })
        .collect();
    if policy.include_basic_claim_set {
        merge_basic_set(&mut additional);
    }
    ClaimsViewDto {
        source: ClaimsSource::MappingPolicy,
        mapping_policy_name: mapping.name.map(str::to_string),
        portal_policy_overridden: portal_exists,
        portal_policy_unreadable: false,
        required,
        additional,
    }
}

/// A schema entry's value. A transformation-sourced entry names its method and
/// the claims and constants it takes.
fn schema_value(entry: &ClaimSchemaEntryDto, policy: &ClaimsPolicyDto) -> String {
    let source = entry.source.as_deref();
    if source.is_some_and(|s| s.eq_ignore_ascii_case("transformation")) {
        return entry
            .transformation_id
            .as_deref()
            .and_then(|id| policy.transformations.iter().find(|t| t.id == id))
            .map_or_else(
                || "(transformation)".into(),
                |t| mapping_transformation(t, policy),
            );
    }
    match (
        source,
        entry.extension_id.as_deref(),
        entry.id.as_deref(),
        entry.value.as_deref(),
    ) {
        (Some(source), Some(extension), _, _) => format!("{source}.{extension}"),
        (Some(source), None, Some(id), _) => format!("{source}.{id}"),
        (None, _, _, Some(value)) => format!("\"{value}\""),
        _ => "(no value)".into(),
    }
}

fn mapping_transformation(t: &ClaimsTransformationDto, policy: &ClaimsPolicyDto) -> String {
    let mut args: Vec<String> = t
        .input_claims
        .iter()
        .map(|input| {
            // An input refers to another schema entry by its `ID`.
            policy
                .schema
                .iter()
                .find(|e| {
                    e.id.as_deref() == Some(input.claim_type_reference_id.as_str())
                        && !e
                            .source
                            .as_deref()
                            .is_some_and(|s| s.eq_ignore_ascii_case("transformation"))
                })
                .map_or_else(
                    || input.claim_type_reference_id.clone(),
                    |e| schema_value(e, policy),
                )
        })
        .collect();
    args.extend(
        t.input_parameters
            .iter()
            .map(|p| format!("\"{}\"", p.value)),
    );
    let method = t.method.trim_end_matches("()");
    format!("{method}({})", args.join(", "))
}

// ---------------- Custom claims policy (the admin center's) ----------------

fn from_portal_policy(policy: &CustomClaimsPolicy) -> ClaimsViewDto {
    let required = match policy.claims.iter().find(|c| c.is_name_id()) {
        Some(name_id) => {
            let format = name_id
                .name_id_format
                .as_deref()
                .filter(|f| !f.is_empty() && !f.eq_ignore_ascii_case("default"))
                .unwrap_or(DEFAULT_NAME_ID_FORMAT);
            ClaimRowDto {
                name: NAME_ID_LABEL.into(),
                token_types: vec!["SAML".into()],
                value: claim_value(name_id),
                detail: Some(
                    [
                        Some(format!("[nameid-format:{format}]")),
                        conditions_note(name_id),
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" "),
                ),
            }
        }
        None => default_name_id(),
    };
    let mut additional: Vec<ClaimRowDto> = policy
        .claims
        .iter()
        .filter(|c| !c.is_name_id())
        .map(|claim| ClaimRowDto {
            name: claim_name(claim),
            token_types: claim
                .token_format
                .iter()
                .map(|f| f.to_ascii_uppercase())
                .collect(),
            value: claim_value(claim),
            detail: conditions_note(claim),
        })
        .collect();
    if policy.include_basic_claim_set == Some(true) {
        merge_basic_set(&mut additional);
    }
    ClaimsViewDto {
        source: ClaimsSource::PortalPolicy,
        mapping_policy_name: None,
        portal_policy_overridden: false,
        portal_policy_unreadable: false,
        required,
        additional,
    }
}

/// `namespace/name`, as the admin center lists a claim.
fn claim_name(claim: &CustomClaim) -> String {
    let name = claim.name.as_deref().map(str::trim).unwrap_or_default();
    match claim
        .namespace
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        Some(namespace) if !name.is_empty() => {
            format!("{}/{name}", namespace.trim_end_matches('/'))
        }
        _ if !name.is_empty() => name.to_string(),
        _ => "(unnamed)".into(),
    }
}

/// The configuration that applies when no condition matches (the value the
/// admin center lists), else the first.
fn default_configuration(claim: &CustomClaim) -> Option<&CustomClaimConfiguration> {
    claim
        .configurations
        .iter()
        .find(|c| c.condition.as_ref().is_none_or(serde_json::Value::is_null))
        .or_else(|| claim.configurations.first())
}

fn conditions_note(claim: &CustomClaim) -> Option<String> {
    let conditional = claim
        .configurations
        .iter()
        .filter(|c| c.condition.as_ref().is_some_and(|v| !v.is_null()))
        .count();
    (conditional > 0).then(|| match conditional {
        1 => "+1 conditional value".to_string(),
        n => format!("+{n} conditional values"),
    })
}

fn claim_value(claim: &CustomClaim) -> String {
    let Some(config) = default_configuration(claim) else {
        return "(no value)".into();
    };
    if let Some(first) = config.transformations.first() {
        let rendered = portal_transformation(first);
        return if config.transformations.len() > 1 {
            format!("{rendered} …")
        } else {
            rendered
        };
    }
    config
        .attribute
        .as_ref()
        .map_or_else(|| "(no value)".into(), attribute_value)
}

fn attribute_value(attribute: &CustomClaimAttribute) -> String {
    let constant = attribute
        .odata_type
        .as_deref()
        .is_some_and(|t| t.to_ascii_lowercase().contains("valuebased"));
    match (
        constant,
        attribute.value.as_deref(),
        attribute.id.as_deref(),
    ) {
        (true, Some(value), _) | (false, Some(value), None) => format!("\"{value}\""),
        (_, _, Some(id)) => format!(
            "{}.{}",
            attribute.source.as_deref().unwrap_or("user").trim(),
            id.trim()
        ),
        _ => "(no value)".into(),
    }
}

/// `Join(user.givenname, ".", user.surname)` from a typed transformation such
/// as `#microsoft.graph.joinTransformation`; an unrecognised shape still names
/// itself rather than disappearing.
fn portal_transformation(t: &serde_json::Value) -> String {
    let method = t
        .get("@odata.type")
        .and_then(serde_json::Value::as_str)
        .map(|ty| {
            let bare = ty.rsplit('.').next().unwrap_or(ty);
            let bare = bare.strip_suffix("Transformation").unwrap_or(bare);
            let mut chars = bare.chars();
            chars
                .next()
                .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "Transformation".into());
    let input = |key: &str| {
        t.get(key)
            .and_then(|i| i.get("attribute"))
            .and_then(|a| serde_json::from_value::<CustomClaimAttribute>(a.clone()).ok())
            .map(|a| attribute_value(&a))
    };
    let separator = t
        .get("separator")
        .and_then(serde_json::Value::as_str)
        .map(|s| format!("\"{s}\""));
    let args: Vec<String> = [input("input"), separator, input("input2")]
        .into_iter()
        .flatten()
        .collect();
    format!("{method}({})", args.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::sso::{TransformInputClaimDto, TransformParamDto};

    fn portal(json: serde_json::Value) -> CustomClaimsPolicy {
        serde_json::from_value(json).expect("a customClaimsPolicy")
    }

    fn sourced(id: &str) -> serde_json::Value {
        serde_json::json!({ "@odata.type": "#microsoft.graph.sourcedAttribute",
                            "id": id, "source": "user", "isExtensionAttribute": false })
    }

    fn claim(namespace: &str, name: &str, attribute: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "@odata.type": "#microsoft.graph.customClaim",
            "name": name, "namespace": namespace, "tokenFormat": ["saml"],
            "configurations": [{ "condition": null, "attribute": attribute, "transformations": [] }]
        })
    }

    #[test]
    fn nothing_customized_shows_entra_defaults() {
        let view = claims_view(None, None, None);
        assert_eq!(view.source, ClaimsSource::Default);
        assert_eq!(view.required.value, "user.userprincipalname");
        assert_eq!(
            view.required.detail.as_deref(),
            Some("[nameid-format:emailAddress]")
        );
        assert_eq!(
            view.additional
                .iter()
                .map(|r| r.value.as_str())
                .collect::<Vec<_>>(),
            [
                "user.mail",
                "user.givenname",
                "user.userprincipalname",
                "user.surname"
            ]
        );
    }

    /// The admin center's policy: the Name ID claim is the Required claim with
    /// its format, and every custom claim is listed, the basic set too when on.
    #[test]
    fn the_portal_policy_splits_name_id_from_every_additional_claim() {
        let policy = portal(serde_json::json!({
            "includeBasicClaimSet": false,
            "claims": [
                { "@odata.type": "#microsoft.graph.samlNameIdClaim", "nameIdFormat": "persistent",
                  "configurations": [{ "attribute": sourced("employeeid") }] },
                claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims", "emailaddress", sourced("mail")),
                claim("", "department", sourced(" department")),
                claim("http://contoso.com/claims", "tier",
                    serde_json::json!({ "@odata.type": "#microsoft.graph.valueBasedAttribute", "value": "gold" })),
            ]
        }));
        let view = claims_view(None, Some(&policy), None);

        assert_eq!(view.source, ClaimsSource::PortalPolicy);
        assert_eq!(view.required.name, "Unique User Identifier (Name ID)");
        assert_eq!(view.required.value, "user.employeeid");
        assert_eq!(
            view.required.detail.as_deref(),
            Some("[nameid-format:persistent]")
        );
        let rows: Vec<(&str, &str)> = view
            .additional
            .iter()
            .map(|r| (r.name.as_str(), r.value.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                (
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                    "user.mail"
                ),
                ("department", "user.department"),
                ("http://contoso.com/claims/tier", "\"gold\""),
            ],
            "every claim, no basic set (it is off)"
        );
        assert_eq!(view.additional[0].token_types, ["SAML"]);
    }

    #[test]
    fn a_portal_policy_with_the_basic_set_on_adds_the_defaults_it_does_not_override() {
        let policy = portal(serde_json::json!({
            "includeBasicClaimSet": true,
            "claims": [claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims", "givenname", sourced("nickname"))]
        }));
        let view = claims_view(None, Some(&policy), None);
        assert_eq!(
            view.required.value, "user.userprincipalname",
            "default Name ID"
        );
        let givenname: Vec<&ClaimRowDto> = view
            .additional
            .iter()
            .filter(|r| r.name.ends_with("/givenname"))
            .collect();
        assert_eq!(
            givenname.len(),
            1,
            "the policy's givenname supersedes the default"
        );
        assert_eq!(givenname[0].value, "user.nickname");
        assert_eq!(view.additional.len(), 4);
    }

    #[test]
    fn transformations_and_conditions_read_as_the_portal_writes_them() {
        let policy = portal(serde_json::json!({ "claims": [{
            "@odata.type": "#microsoft.graph.customClaim",
            "name": "JoinedData", "tokenFormat": ["saml", "jwt"],
            "configurations": [
                { "condition": { "memberOf": ["g1"] }, "attribute": sourced("mail") },
                { "condition": null, "transformations": [{
                    "@odata.type": "#microsoft.graph.joinTransformation",
                    "separator": ".",
                    "input": { "attribute": sourced("givenname") },
                    "input2": { "attribute": sourced("surname") }
                }] }
            ]
        }]}));
        let view = claims_view(None, Some(&policy), None);
        let row = &view.additional[0];
        assert_eq!(row.value, "Join(user.givenname, \".\", user.surname)");
        assert_eq!(row.detail.as_deref(), Some("+1 conditional value"));
        assert_eq!(row.token_types, ["SAML", "JWT"]);
    }

    /// An assigned mapping policy is what Entra applies; the admin center's
    /// policy, if any, is overridden, and the view says so.
    #[test]
    fn a_mapping_policy_wins_and_its_name_id_entry_is_the_required_claim() {
        let mapping = ClaimsPolicyDto {
            include_basic_claim_set: false,
            schema: vec![
                ClaimSchemaEntryDto {
                    source: Some("user".into()),
                    id: Some("employeeid".into()),
                    saml_claim_type: Some(NAME_IDENTIFIER_CLAIM.into()),
                    ..Default::default()
                },
                ClaimSchemaEntryDto {
                    value: Some("Sandbox".into()),
                    saml_claim_type: Some("http://contoso.com/env".into()),
                    ..Default::default()
                },
                ClaimSchemaEntryDto {
                    source: Some("user".into()),
                    extension_id: Some("extension_abc_costCenter".into()),
                    jwt_claim_type: Some("cost_center".into()),
                    ..Default::default()
                },
                ClaimSchemaEntryDto {
                    source: Some("user".into()),
                    id: Some("mail".into()),
                    ..Default::default()
                },
                ClaimSchemaEntryDto {
                    source: Some("transformation".into()),
                    id: Some("out".into()),
                    transformation_id: Some("t1".into()),
                    saml_claim_type: Some("http://contoso.com/alias".into()),
                    ..Default::default()
                },
            ],
            transformations: vec![ClaimsTransformationDto {
                id: "t1".into(),
                method: "ToLowercase()".into(),
                input_claims: vec![TransformInputClaimDto {
                    claim_type_reference_id: "mail".into(),
                    transformation_claim_type: "inputClaim".into(),
                    treat_as_multi_value: None,
                }],
                input_parameters: vec![TransformParamDto {
                    id: "x".into(),
                    value: "y".into(),
                    data_type: None,
                }],
                output_claims: Vec::new(),
            }],
            preserved_options: None,
        };
        let portal = portal(serde_json::json!({ "claims": [] }));
        let view = claims_view(
            Some(AssignedMappingPolicy {
                policy: &mapping,
                name: Some("Custom claims"),
            }),
            Some(&portal),
            None,
        );

        assert_eq!(view.source, ClaimsSource::MappingPolicy);
        assert_eq!(view.mapping_policy_name.as_deref(), Some("Custom claims"));
        assert!(view.portal_policy_overridden);
        assert_eq!(view.required.value, "user.employeeid");
        let rows: Vec<(&str, &str, Vec<String>)> = view
            .additional
            .iter()
            .map(|r| (r.name.as_str(), r.value.as_str(), r.token_types.clone()))
            .collect();
        assert_eq!(
            rows[0],
            (
                "http://contoso.com/env",
                "\"Sandbox\"",
                vec!["SAML".to_string()]
            )
        );
        assert_eq!(
            rows[1],
            (
                "cost_center",
                "user.extension_abc_costCenter",
                vec!["JWT".to_string()]
            ),
            "a JWT-only claim is listed and labelled"
        );
        assert_eq!(rows[2].0, "(unnamed)");
        assert_eq!(rows[3].1, "ToLowercase(user.mail, \"y\")");
        assert_eq!(view.additional.len(), 4, "the basic set is off");
    }

    #[test]
    fn a_mapping_policy_with_the_basic_set_on_keeps_the_default_name_id() {
        let mapping = ClaimsPolicyDto::default();
        let view = claims_view(
            Some(AssignedMappingPolicy {
                policy: &mapping,
                name: None,
            }),
            None,
            None,
        );
        assert!(!view.portal_policy_overridden);
        assert_eq!(view.required.value, "user.userprincipalname");
        assert_eq!(view.additional.len(), 4);
    }

    #[test]
    fn group_claims_are_listed_once() {
        let view = claims_view(None, None, Some("SecurityGroup"));
        let last = view.additional.last().unwrap();
        assert_eq!(last.name, GROUPS_CLAIM);
        assert_eq!(last.value, "user.groups [SecurityGroup]");

        assert_eq!(claims_view(None, None, Some("None")).additional.len(), 4);

        let policy = portal(serde_json::json!({ "claims": [
            claim("http://schemas.microsoft.com/ws/2008/06/identity/claims", "groups", sourced("groups"))
        ]}));
        let view = claims_view(None, Some(&policy), Some("All"));
        assert_eq!(
            view.additional.len(),
            1,
            "the policy's own groups claim is not repeated"
        );
    }
}
