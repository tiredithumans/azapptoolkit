use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Single entry from `GET /secrets`. Metadata only — the actual value only
/// ships from `GET /secrets/{name}/{version?}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretItem {
    /// Full resource id: `https://{vault}.vault.azure.net/secrets/{name}`.
    pub id: String,
    #[serde(default)]
    pub attributes: Option<SecretAttributes>,
    #[serde(default)]
    pub tags: Option<std::collections::HashMap<String, String>>,
    #[serde(default, rename = "contentType")]
    pub content_type: Option<String>,
}

impl SecretItem {
    /// Strips the vault host + `/secrets/` prefix off `id` to yield the
    /// user-visible name.
    pub fn name(&self) -> Option<&str> {
        self.id.rsplit('/').next()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAttributes {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default, with = "optional_unix_timestamp")]
    pub created: Option<DateTime<Utc>>,
    #[serde(default, with = "optional_unix_timestamp")]
    pub updated: Option<DateTime<Utc>>,
    #[serde(default, with = "optional_unix_timestamp", rename = "exp")]
    pub expires: Option<DateTime<Utc>>,
    #[serde(default, with = "optional_unix_timestamp", rename = "nbf")]
    pub not_before: Option<DateTime<Utc>>,
}

/// `GET /secrets/{name}` — full value included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretValue {
    pub value: String,
    pub id: String,
    #[serde(default)]
    pub attributes: Option<SecretAttributes>,
    #[serde(default, rename = "contentType")]
    pub content_type: Option<String>,
    #[serde(default)]
    pub tags: Option<std::collections::HashMap<String, String>>,
}

/// Body for `PUT /secrets/{name}`. Only `value` is required; everything else
/// is optional (Key Vault applies defaults).
#[derive(Debug, Clone, Default, Serialize)]
pub struct SecretSetRequest {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "contentType")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<SecretAttributesRequest>,
}

/// Request-shape for attributes on create/update. Key Vault expects Unix
/// seconds for `exp` and `nbf`; serde handles the convert via
/// `optional_unix_timestamp`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SecretAttributesRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "exp",
        with = "optional_unix_timestamp_ser"
    )]
    pub expires: Option<DateTime<Utc>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "nbf",
        with = "optional_unix_timestamp_ser"
    )]
    pub not_before: Option<DateTime<Utc>>,
}

/// Alias for public consumers who want a stable name.
pub type SecretProperties = SecretAttributes;

mod optional_unix_timestamp {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(dt) => serializer.serialize_i64(dt.timestamp()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<i64>::deserialize(deserializer)?;
        Ok(opt.and_then(|t| Utc.timestamp_opt(t, 0).single()))
    }
}

mod optional_unix_timestamp_ser {
    use chrono::{DateTime, Utc};
    use serde::Serializer;

    pub fn serialize<S>(value: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(dt) => serializer.serialize_i64(dt.timestamp()),
            None => serializer.serialize_none(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Paged<T> {
    pub value: Vec<T>,
    #[serde(rename = "nextLink", default)]
    pub next_link: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_item_extracts_name_from_id() {
        let item: SecretItem =
            serde_json::from_str(r#"{"id":"https://v.vault.azure.net/secrets/foo"}"#).unwrap();
        assert_eq!(item.name(), Some("foo"));
    }

    #[test]
    fn set_request_omits_none_fields() {
        let req = SecretSetRequest {
            value: "v".into(),
            ..Default::default()
        };
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(s, r#"{"value":"v"}"#);
    }
}
