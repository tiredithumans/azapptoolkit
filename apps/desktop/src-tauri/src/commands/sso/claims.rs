//! Claims-mapping-policy codec.
//!
//! The pure serialize/parse layer between the editable [`ClaimsPolicyDto`] and
//! the JSON string Graph stores in a `ClaimsMappingPolicy` definition. Self
//! contained — it never touches Graph or `State`, so it lives apart from the SSO
//! orchestration in `super` and is the prime correctness target of the claims
//! feature (round-trip tested below). `super` re-uses [`build_claims_definition`]
//! (write) and [`parse_claims_definition`] (read).

use crate::dto::sso::{
    ClaimSchemaEntryDto, ClaimsPolicyDto, ClaimsTransformationDto, TransformInputClaimDto,
    TransformOutputClaimDto, TransformParamDto,
};

/// Top-level keys of a `ClaimsMappingPolicy` definition that this editor models
/// directly. Anything else (e.g. `GroupFilter`, `issuerWithApplicationId`,
/// `audienceOverride`) is preserved verbatim so a save never drops it.
const MANAGED_POLICY_KEYS: [&str; 4] = [
    "Version",
    "IncludeBasicClaimSet",
    "ClaimsSchema",
    "ClaimsTransformation",
];

/// Reads the first non-empty string among `keys` from `obj` (tolerant of the
/// casing variants Graph accepts, e.g. `JwtClaimType` vs `JWTClaimType`).
fn str_field(obj: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| obj.get(*k).and_then(|v| v.as_str()))
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

/// Serializes one [`ClaimSchemaEntryDto`] to a Graph `ClaimsSchema` entry. Empty
/// fields are omitted. A transformation-sourced entry emits its `id` as
/// `TransformationID` (Graph's name for the transformation reference).
fn build_schema_entry(e: &ClaimSchemaEntryDto) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    let put = |m: &mut serde_json::Map<String, serde_json::Value>, k: &str, v: &Option<String>| {
        if let Some(s) = v.as_deref().filter(|s| !s.is_empty()) {
            m.insert(k.to_string(), serde_json::Value::String(s.to_string()));
        }
    };
    put(&mut m, "Value", &e.value);
    put(&mut m, "Source", &e.source);
    if let Some(id) = e.id.as_deref().filter(|s| !s.is_empty()) {
        let key = if e.source.as_deref() == Some("transformation") {
            "TransformationID"
        } else {
            "ID"
        };
        m.insert(key.to_string(), serde_json::Value::String(id.to_string()));
    }
    put(&mut m, "ExtensionID", &e.extension_id);
    put(&mut m, "SamlClaimType", &e.saml_claim_type);
    put(&mut m, "JwtClaimType", &e.jwt_claim_type);
    put(&mut m, "SAMLNameForm", &e.saml_name_form);
    serde_json::Value::Object(m)
}

/// Serializes one [`ClaimsTransformationDto`] to a Graph `ClaimsTransformation`
/// entry. Empty sub-lists are omitted.
fn build_transformation(t: &ClaimsTransformationDto) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("ID".into(), serde_json::Value::String(t.id.clone()));
    m.insert(
        "TransformationMethod".into(),
        serde_json::Value::String(t.method.clone()),
    );
    if !t.input_claims.is_empty() {
        let arr: Vec<_> = t
            .input_claims
            .iter()
            .map(|c| {
                let mut im = serde_json::json!({
                    "ClaimTypeReferenceId": c.claim_type_reference_id,
                    "TransformationClaimType": c.transformation_claim_type,
                });
                if c.treat_as_multi_value == Some(true) {
                    im["TreatAsMultiValue"] = serde_json::Value::Bool(true);
                }
                im
            })
            .collect();
        m.insert("InputClaims".into(), serde_json::Value::Array(arr));
    }
    if !t.input_parameters.is_empty() {
        let arr: Vec<_> = t
            .input_parameters
            .iter()
            .map(|p| serde_json::json!({ "ID": p.id, "Value": p.value }))
            .collect();
        m.insert("InputParameters".into(), serde_json::Value::Array(arr));
    }
    if !t.output_claims.is_empty() {
        let arr: Vec<_> = t
            .output_claims
            .iter()
            .map(|c| {
                serde_json::json!({
                    "ClaimTypeReferenceId": c.claim_type_reference_id,
                    "TransformationClaimType": c.transformation_claim_type,
                })
            })
            .collect();
        m.insert("OutputClaims".into(), serde_json::Value::Array(arr));
    }
    serde_json::Value::Object(m)
}

/// Builds the `claimsMappingPolicy` definition JSON for `policy`. Returns the
/// single JSON string Graph stores in the policy's `definition` array. Pure and
/// unit-tested — the prime correctness target of the claims feature. Preserved
/// policy-level options (captured on read) are merged back without clobbering
/// the keys this editor manages.
pub(super) fn build_claims_definition(policy: &ClaimsPolicyDto) -> String {
    let schema: Vec<serde_json::Value> = policy.schema.iter().map(build_schema_entry).collect();
    let transforms: Vec<serde_json::Value> = policy
        .transformations
        .iter()
        .map(build_transformation)
        .collect();

    let mut obj = serde_json::Map::new();
    obj.insert("Version".into(), serde_json::json!(1));
    // Graph expects the boolean as a quoted string ("true"/"false").
    obj.insert(
        "IncludeBasicClaimSet".into(),
        serde_json::Value::String(if policy.include_basic_claim_set {
            "true".into()
        } else {
            "false".into()
        }),
    );
    obj.insert("ClaimsSchema".into(), serde_json::Value::Array(schema));
    if !transforms.is_empty() {
        obj.insert(
            "ClaimsTransformation".into(),
            serde_json::Value::Array(transforms),
        );
    }
    if let Some(serde_json::Value::Object(extra)) = policy
        .preserved_options
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
    {
        for (k, v) in extra {
            // Never let a preserved blob overwrite a key we manage.
            obj.entry(k).or_insert(v);
        }
    }
    serde_json::json!({ "ClaimsMappingPolicy": obj }).to_string()
}

/// Decodes a `claimsMappingPolicy` definition string into the editable
/// [`ClaimsPolicyDto`]. Tolerant: unknown shapes yield an empty policy. Unmanaged
/// policy-level keys are stashed in `preserved_options` for lossless round-trip.
pub(super) fn parse_claims_definition(definition: &str) -> ClaimsPolicyDto {
    let Some(policy) = serde_json::from_str::<serde_json::Value>(definition)
        .ok()
        .and_then(|v| v.get("ClaimsMappingPolicy").cloned())
        .and_then(|p| p.as_object().cloned())
    else {
        return ClaimsPolicyDto::default();
    };

    let include_basic_claim_set = match policy.get("IncludeBasicClaimSet") {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    };
    let schema = policy
        .get("ClaimsSchema")
        .and_then(|s| s.as_array())
        .map(|arr| arr.iter().filter_map(parse_schema_entry).collect())
        .unwrap_or_default();
    let transformations = policy
        .get("ClaimsTransformation")
        .and_then(|s| s.as_array())
        .map(|arr| arr.iter().filter_map(parse_transformation).collect())
        .unwrap_or_default();
    let preserved: serde_json::Map<String, serde_json::Value> = policy
        .iter()
        .filter(|(k, _)| !MANAGED_POLICY_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let preserved_options =
        (!preserved.is_empty()).then(|| serde_json::Value::Object(preserved).to_string());

    ClaimsPolicyDto {
        include_basic_claim_set,
        schema,
        transformations,
        preserved_options,
    }
}

/// Decodes one Graph `ClaimsSchema` entry. `TransformationID` and `ID` both map
/// to the DTO's `id` (build re-emits the right key based on `source`).
fn parse_schema_entry(row: &serde_json::Value) -> Option<ClaimSchemaEntryDto> {
    let obj = row.as_object()?;
    Some(ClaimSchemaEntryDto {
        source: str_field(obj, &["Source"]),
        id: str_field(obj, &["ID", "TransformationID"]),
        extension_id: str_field(obj, &["ExtensionID"]),
        value: str_field(obj, &["Value"]),
        saml_claim_type: str_field(obj, &["SamlClaimType", "SAMLClaimType"]),
        jwt_claim_type: str_field(obj, &["JwtClaimType", "JWTClaimType"]),
        saml_name_form: str_field(obj, &["SAMLNameForm", "SamlNameForm"]),
    })
}

/// Maps the JSON object array at `obj[key]` through `f` (non-object elements are
/// skipped). Returns an empty Vec when the key is absent or not an array.
fn map_json_array<T>(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    f: impl Fn(&serde_json::Map<String, serde_json::Value>) -> T,
) -> Vec<T> {
    obj.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|c| c.as_object()).map(f).collect())
        .unwrap_or_default()
}

/// Decodes one Graph `ClaimsTransformation` entry. Returns `None` for an entry
/// with neither an id nor a method (garbage).
fn parse_transformation(row: &serde_json::Value) -> Option<ClaimsTransformationDto> {
    let obj = row.as_object()?;
    let id = str_field(obj, &["ID"]).unwrap_or_default();
    let method = str_field(obj, &["TransformationMethod"]).unwrap_or_default();
    if id.is_empty() && method.is_empty() {
        return None;
    }
    let input_claims = map_json_array(obj, "InputClaims", |o| TransformInputClaimDto {
        claim_type_reference_id: str_field(o, &["ClaimTypeReferenceId"]).unwrap_or_default(),
        transformation_claim_type: str_field(o, &["TransformationClaimType"]).unwrap_or_default(),
        treat_as_multi_value: o.get("TreatAsMultiValue").and_then(|v| v.as_bool()),
    });
    let input_parameters = map_json_array(obj, "InputParameters", |o| TransformParamDto {
        id: str_field(o, &["ID"]).unwrap_or_default(),
        value: str_field(o, &["Value"]).unwrap_or_default(),
    });
    let output_claims = map_json_array(obj, "OutputClaims", |o| TransformOutputClaimDto {
        claim_type_reference_id: str_field(o, &["ClaimTypeReferenceId"]).unwrap_or_default(),
        transformation_claim_type: str_field(o, &["TransformationClaimType"]).unwrap_or_default(),
    });
    Some(ClaimsTransformationDto {
        id,
        method,
        input_claims,
        input_parameters,
        output_claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_claims_definition_shapes_schema() {
        let policy = ClaimsPolicyDto {
            include_basic_claim_set: true,
            schema: vec![ClaimSchemaEntryDto {
                source: Some("user".into()),
                id: Some("userprincipalname".into()),
                saml_claim_type: Some(
                    "https://aws.amazon.com/SAML/Attributes/RoleSessionName".into(),
                ),
                jwt_claim_type: Some("upn".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let json = build_claims_definition(&policy);
        // Must be a single valid JSON string Graph can store in `definition[0]`.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let schema = &parsed["ClaimsMappingPolicy"]["ClaimsSchema"];
        assert_eq!(parsed["ClaimsMappingPolicy"]["Version"], 1);
        // Graph wants the basic-claim-set flag as a quoted string, not a bool.
        assert_eq!(
            parsed["ClaimsMappingPolicy"]["IncludeBasicClaimSet"],
            "true"
        );
        assert_eq!(schema.as_array().unwrap().len(), 1);
        assert_eq!(schema[0]["Source"], "user");
        assert_eq!(schema[0]["ID"], "userprincipalname");
        assert_eq!(schema[0]["JwtClaimType"], "upn");
        // No transformations ⇒ the key is omitted entirely.
        assert!(
            parsed["ClaimsMappingPolicy"]
                .get("ClaimsTransformation")
                .is_none()
        );
    }

    #[test]
    fn build_claims_definition_writes_exactly_the_managed_keys() {
        // The writer must emit exactly the keys listed in MANAGED_POLICY_KEYS —
        // those are the keys the preserve-without-clobber merge guards (a
        // preserved blob can only `or_insert` around them). A managed key added
        // to the writer but not the list (or vice versa) would let a preserved
        // blob silently clobber it, so pin the two together. Include a schema
        // entry and a transformation so all four managed keys are present.
        let policy = ClaimsPolicyDto {
            include_basic_claim_set: true,
            schema: vec![ClaimSchemaEntryDto {
                source: Some("user".into()),
                id: Some("upn".into()),
                jwt_claim_type: Some("upn".into()),
                ..Default::default()
            }],
            transformations: vec![ClaimsTransformationDto {
                id: "X".into(),
                method: "Join".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let json = build_claims_definition(&policy);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let written: std::collections::HashSet<String> = v["ClaimsMappingPolicy"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let managed: std::collections::HashSet<String> =
            MANAGED_POLICY_KEYS.iter().map(|s| s.to_string()).collect();
        assert_eq!(written, managed);
    }

    #[test]
    fn build_claims_definition_empty_is_valid() {
        // Explicitly suppress the basic set to exercise the "false" path (the
        // DTO default is now `true`).
        let policy = ClaimsPolicyDto {
            include_basic_claim_set: false,
            ..Default::default()
        };
        let json = build_claims_definition(&policy);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["ClaimsMappingPolicy"]["ClaimsSchema"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        // The basic-claim-set flag serializes as a quoted string, not a bool.
        assert_eq!(
            parsed["ClaimsMappingPolicy"]["IncludeBasicClaimSet"],
            "false"
        );
    }

    #[test]
    fn claims_policy_round_trips_attribute_constant_extension() {
        let policy = ClaimsPolicyDto {
            include_basic_claim_set: true,
            schema: vec![
                ClaimSchemaEntryDto {
                    source: Some("user".into()),
                    id: Some("mail".into()),
                    saml_claim_type: Some(
                        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".into(),
                    ),
                    jwt_claim_type: Some("email".into()),
                    ..Default::default()
                },
                // constant claim — only Value + JwtClaimType
                ClaimSchemaEntryDto {
                    value: Some("sandbox".into()),
                    jwt_claim_type: Some("env".into()),
                    ..Default::default()
                },
                // directory extension attribute
                ClaimSchemaEntryDto {
                    source: Some("user".into()),
                    extension_id: Some("extension_abc_legacyId".into()),
                    jwt_claim_type: Some("legacyId".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let json = build_claims_definition(&policy);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let schema = v["ClaimsMappingPolicy"]["ClaimsSchema"].as_array().unwrap();
        assert_eq!(schema.len(), 3);
        // Constant claim must not carry a Source/ID.
        assert_eq!(schema[1]["Value"], "sandbox");
        assert!(schema[1].get("Source").is_none());
        assert_eq!(schema[2]["ExtensionID"], "extension_abc_legacyId");

        let back = parse_claims_definition(&json);
        assert!(back.include_basic_claim_set);
        assert_eq!(back.schema.len(), 3);
        assert_eq!(back.schema[0].id.as_deref(), Some("mail"));
        assert_eq!(back.schema[0].jwt_claim_type.as_deref(), Some("email"));
        assert_eq!(back.schema[1].value.as_deref(), Some("sandbox"));
        assert_eq!(back.schema[1].source, None);
        assert_eq!(
            back.schema[2].extension_id.as_deref(),
            Some("extension_abc_legacyId")
        );
    }

    #[test]
    fn claims_policy_round_trips_transformation() {
        let policy = ClaimsPolicyDto {
            schema: vec![ClaimSchemaEntryDto {
                source: Some("transformation".into()),
                id: Some("JoinUpnDomain".into()),
                saml_claim_type: Some("https://example/joined".into()),
                ..Default::default()
            }],
            transformations: vec![ClaimsTransformationDto {
                id: "JoinUpnDomain".into(),
                method: "Join".into(),
                input_claims: vec![TransformInputClaimDto {
                    claim_type_reference_id: "string1".into(),
                    transformation_claim_type: "string1".into(),
                    treat_as_multi_value: None,
                }],
                input_parameters: vec![TransformParamDto {
                    id: "separator".into(),
                    value: ".".into(),
                }],
                output_claims: vec![TransformOutputClaimDto {
                    claim_type_reference_id: "JoinUpnDomain".into(),
                    transformation_claim_type: "outputClaim".into(),
                }],
            }],
            ..Default::default()
        };
        let json = build_claims_definition(&policy);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // A transformation-sourced entry emits TransformationID, not ID.
        let entry = &v["ClaimsMappingPolicy"]["ClaimsSchema"][0];
        assert_eq!(entry["TransformationID"], "JoinUpnDomain");
        assert!(entry.get("ID").is_none());
        let transform = &v["ClaimsMappingPolicy"]["ClaimsTransformation"][0];
        assert_eq!(transform["TransformationMethod"], "Join");
        assert_eq!(transform["InputParameters"][0]["Value"], ".");

        let back = parse_claims_definition(&json);
        assert_eq!(back.schema[0].source.as_deref(), Some("transformation"));
        assert_eq!(back.schema[0].id.as_deref(), Some("JoinUpnDomain"));
        assert_eq!(back.transformations.len(), 1);
        assert_eq!(back.transformations[0].method, "Join");
        assert_eq!(back.transformations[0].input_parameters[0].value, ".");
        assert_eq!(
            back.transformations[0].output_claims[0].transformation_claim_type,
            "outputClaim"
        );
    }

    #[test]
    fn claims_policy_preserves_unmanaged_options() {
        // A GroupFilter (not modeled by the editor) must survive a round-trip.
        let definition = r#"{"ClaimsMappingPolicy":{"Version":1,"IncludeBasicClaimSet":"true","ClaimsSchema":[{"Source":"user","ID":"mail","SamlClaimType":"urn:mail"}],"GroupFilter":{"MatchOn":"displayname","Type":"prefix","Value":"App-"}}}"#;
        let parsed = parse_claims_definition(definition);
        assert!(parsed.include_basic_claim_set);
        assert!(parsed.preserved_options.is_some());

        let rebuilt = build_claims_definition(&parsed);
        let v: serde_json::Value = serde_json::from_str(&rebuilt).unwrap();
        assert_eq!(
            v["ClaimsMappingPolicy"]["GroupFilter"]["MatchOn"],
            "displayname"
        );
        // The managed keys are still present and correct.
        assert_eq!(v["ClaimsMappingPolicy"]["ClaimsSchema"][0]["ID"], "mail");
    }

    #[test]
    fn include_basic_claim_set_parses_bool_or_string() {
        let from_string = parse_claims_definition(
            r#"{"ClaimsMappingPolicy":{"IncludeBasicClaimSet":"true","ClaimsSchema":[]}}"#,
        );
        assert!(from_string.include_basic_claim_set);
        let from_bool = parse_claims_definition(
            r#"{"ClaimsMappingPolicy":{"IncludeBasicClaimSet":true,"ClaimsSchema":[]}}"#,
        );
        assert!(from_bool.include_basic_claim_set);
    }

    #[test]
    fn parse_claims_definition_tolerates_garbage() {
        assert!(parse_claims_definition("not json").is_empty());
        assert!(parse_claims_definition("{}").is_empty());
    }
}
