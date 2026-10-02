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
///
/// Deserialize-only on purpose: the IPC boundary maps a fetched secret into
/// `KvSecretValueDto` field by field, and nothing serializes one. A derived
/// `Serialize` would be a plaintext path (`serde_json::to_string`, a JSON
/// tracing layer) around the redacted `Debug` below; if one is ever needed,
/// hand-write it with the value redacted. Pinned by
/// `secret_value_has_no_serialize_path`.
#[derive(Clone, Deserialize)]
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

/// Manual impl so a stray `{:?}` can't log the secret value — the read-side
/// twin of [`SecretSetRequest`]'s redacted Debug. No zeroize-on-drop: the
/// value is moved into the IPC DTO the user asked to view, so a Drop impl
/// would only forbid that field move without closing any real exposure.
impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretValue")
            .field("value", &"<redacted>")
            .field("id", &self.id)
            .field("attributes", &self.attributes)
            .field("content_type", &self.content_type)
            .field("tags", &self.tags)
            .finish()
    }
}

/// Body for `PUT /secrets/{name}`. Only `value` is required; everything else
/// is optional (Key Vault applies defaults).
#[derive(Clone, Default, Serialize)]
pub struct SecretSetRequest {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "contentType")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<SecretAttributesRequest>,
}

/// Live secret material; wipe on drop so freed heap pages don't retain the
/// plaintext (matches `AccessToken` / `GeneratedCert`). Serialized body and
/// transport buffers are the same accepted limits as token handling.
impl Drop for SecretSetRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.value.zeroize();
    }
}

/// Manual impl so a stray `{:?}` can't log the secret value (mirrors
/// `PasswordCredential`'s redacted Debug).
impl std::fmt::Debug for SecretSetRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretSetRequest")
            .field("value", &"<redacted>")
            .field("content_type", &self.content_type)
            .field("tags", &self.tags)
            .field("attributes", &self.attributes)
            .finish()
    }
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

mod optional_unix_timestamp {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    // `serialize_with` hands the helper `&Option<T>` by contract — the
    // signature is serde's, not a style choice.
    #[allow(clippy::ref_option)]
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

    // `serialize_with` hands the helper `&Option<T>` by contract — the
    // signature is serde's, not a style choice.
    #[allow(clippy::ref_option)]
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

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Paged<T> {
    pub value: Vec<T>,
    #[serde(rename = "nextLink", default)]
    pub next_link: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SecretValue` carries a fetched secret in plaintext; its `Debug` is
    /// redacted, and a `Serialize` (derived or hand-written) would bypass that.
    /// Source-scanned because a missing trait cannot be asserted at runtime.
    #[test]
    fn secret_value_has_no_serialize_path() {
        let src = include_str!("models.rs");
        let decl = src
            .find("pub struct SecretValue")
            .expect("SecretValue declaration");
        let derive = src[..decl].rfind("#[derive(").expect("SecretValue derive");
        let derive_list = &src[derive..decl];
        assert!(
            !derive_list
                .split(|c: char| c == '(' || c == ')' || c == ',' || c.is_whitespace())
                .any(|t| t == "Serialize" || t.ends_with("::Serialize")),
            "SecretValue must not derive Serialize: {derive_list}"
        );
        assert!(
            !src.contains(concat!("Serialize for ", "SecretValue")),
            "SecretValue must not implement Serialize"
        );
    }

    #[test]
    fn secret_item_extracts_name_from_id() {
        let item: SecretItem =
            serde_json::from_str(r#"{"id":"https://v.vault.azure.net/secrets/foo"}"#).unwrap();
        assert_eq!(item.name(), Some("foo"));
    }

    #[test]
    fn secret_value_debug_redacts_the_secret() {
        let sv: SecretValue = serde_json::from_str(
            r#"{"value":"s3cret-material","id":"https://v.vault.azure.net/secrets/foo/1"}"#,
        )
        .unwrap();
        let dbg = format!("{sv:?}");
        assert!(!dbg.contains("s3cret-material"), "leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn set_request_omits_none_fields() {
        // Explicit fields: a `..` update moves out of the base value, which
        // the Drop (zeroize) impl forbids (E0509).
        let req = SecretSetRequest {
            value: "v".into(),
            content_type: None,
            tags: None,
            attributes: None,
        };
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(s, r#"{"value":"v"}"#);
    }

    /// The rotation write sends `exp` (and may send `nbf`) under `attributes`
    /// as Unix **seconds** — a rename slip or millisecond/RFC 3339 encoding
    /// would leave every rotated secret without an expiry Key Vault honours.
    #[test]
    fn set_request_serialises_exp_and_nbf_as_unix_seconds() {
        use chrono::TimeZone;
        // Explicit fields: the Drop (zeroize) impl forbids `..Default::default()`.
        let req = SecretSetRequest {
            value: "v".into(),
            content_type: None,
            tags: None,
            attributes: Some(SecretAttributesRequest {
                enabled: Some(true),
                expires: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
                not_before: Some(Utc.with_ymd_and_hms(2025, 12, 31, 0, 0, 0).unwrap()),
            }),
        };
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(
            s,
            r#"{"value":"v","attributes":{"enabled":true,"exp":1767225600,"nbf":1767139200}}"#
        );
    }
}
