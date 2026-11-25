//! Grant expiries: a date after which an application-permission grant should
//! be revoked, stored as a tag on the holding service principal.
//!
//! The tag is `azapptoolkit:grantExpiry:v1|<resourceAppId>|<appRoleId>|<YYYY-MM-DD>`.
//! Microsoft has no expiry for application grants and the toolkit runs nothing
//! in the background, so an expiry is enforced by the audit (Rule 25) and its
//! one-click revoke. Tags are shared by every operator of the tenant, and read
//! as untrusted input: a malformed tag of our family is ignored.
//! Pure, so the WASM frontend shows existing expiries with the same codec.

use jiff::Timestamp;
use jiff::civil::Date;
use serde::{Deserialize, Serialize};

use crate::guid::is_guid;

/// The tag family prefix (shared with every version).
pub const GRANT_EXPIRY_TAG_FAMILY: &str = "azapptoolkit:grantExpiry:";
const V1: &str = "v1|";

/// One grant's expiry, as its tag records it. Ids are lower-case GUIDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantExpiry {
    pub resource_app_id: String,
    pub app_role_id: String,
    pub expires_on: Date,
}

/// The tag for `e`, or `None` when either id isn't a GUID.
pub fn encode_expiry_tag(e: &GrantExpiry) -> Option<String> {
    if !is_guid(&e.resource_app_id) || !is_guid(&e.app_role_id) {
        return None;
    }
    Some(format!(
        "{GRANT_EXPIRY_TAG_FAMILY}{V1}{}|{}|{}",
        e.resource_app_id.to_ascii_lowercase(),
        e.app_role_id.to_ascii_lowercase(),
        e.expires_on
    ))
}

/// `None` = not one of our tags; `Some(None)` = ours but unusable (unknown
/// version, a bad id or date); `Some(Some(_))` = a valid expiry.
pub fn decode_expiry_tag(tag: &str) -> Option<Option<GrantExpiry>> {
    let rest = tag.strip_prefix(GRANT_EXPIRY_TAG_FAMILY)?;
    let Some(body) = rest.strip_prefix(V1) else {
        return Some(None);
    };
    let parts: Vec<&str> = body.split('|').collect();
    let [resource, role, date] = parts.as_slice() else {
        return Some(None);
    };
    if !is_guid(resource) || !is_guid(role) {
        return Some(None);
    }
    let Ok(expires_on) = date.parse::<Date>() else {
        return Some(None);
    };
    Some(Some(GrantExpiry {
        resource_app_id: resource.to_ascii_lowercase(),
        app_role_id: role.to_ascii_lowercase(),
        expires_on,
    }))
}

/// Rule 25's Fix for the named expired grants (the names ride `targets` for
/// the confirm).
pub fn revoke_expired_remediation(names: &[String]) -> super::RemediationAction {
    super::RemediationAction {
        kind: super::RemediationKind::RevokeExpiredGrants,
        label: format!(
            "Revoke {} expired grant{}",
            names.len(),
            if names.len() == 1 { "" } else { "s" }
        ),
        detail: names.join(", "),
        targets: names.to_vec(),
    }
}

/// Every valid expiry among a principal's tags.
pub fn expiries_in(tags: &[String]) -> Vec<GrantExpiry> {
    tags.iter()
        .filter_map(|t| decode_expiry_tag(t).flatten())
        .collect()
}

/// An expiry has passed once its whole day (UTC) is over: a grant expiring
/// today is still valid today.
pub fn expiry_has_passed(expires_on: Date, now: Timestamp) -> bool {
    jiff::tz::Offset::UTC.to_datetime(now).date() > expires_on
}

/// `tags` with this `(resource, role)`'s expiry set to `expires_on` (or
/// cleared on `None`): every tag of our family for the pair is removed, case-
/// insensitively, and the new one appended; other tags keep their order.
/// `None` only when the ids aren't GUIDs.
pub fn with_expiry(
    tags: &[String],
    resource_app_id: &str,
    app_role_id: &str,
    expires_on: Option<Date>,
) -> Option<Vec<String>> {
    if !is_guid(resource_app_id) || !is_guid(app_role_id) {
        return None;
    }
    let same_pair = |e: &GrantExpiry| {
        e.resource_app_id.eq_ignore_ascii_case(resource_app_id)
            && e.app_role_id.eq_ignore_ascii_case(app_role_id)
    };
    let mut out: Vec<String> = tags
        .iter()
        .filter(|t| !matches!(decode_expiry_tag(t), Some(Some(e)) if same_pair(&e)))
        .cloned()
        .collect();
    if let Some(expires_on) = expires_on {
        out.push(encode_expiry_tag(&GrantExpiry {
            resource_app_id: resource_app_id.to_string(),
            app_role_id: app_role_id.to_string(),
            expires_on,
        })?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RES: &str = "00000003-0000-0000-c000-000000000000";
    const ROLE: &str = "45bbb07e-7321-4fd7-a8f6-3ff27e6a81c8";

    fn date(s: &str) -> Date {
        s.parse().unwrap()
    }

    fn expiry(d: &str) -> GrantExpiry {
        GrantExpiry {
            resource_app_id: RES.into(),
            app_role_id: ROLE.into(),
            expires_on: date(d),
        }
    }

    #[test]
    fn tag_round_trips_and_normalises_case() {
        let tag = encode_expiry_tag(&expiry("2026-12-24")).unwrap();
        assert_eq!(
            tag,
            format!("azapptoolkit:grantExpiry:v1|{RES}|{ROLE}|2026-12-24")
        );
        assert_eq!(decode_expiry_tag(&tag), Some(Some(expiry("2026-12-24"))));
        let upper = GrantExpiry {
            resource_app_id: RES.to_uppercase(),
            app_role_id: ROLE.to_uppercase(),
            expires_on: date("2026-12-24"),
        };
        assert_eq!(encode_expiry_tag(&upper), Some(tag));
        let bad = GrantExpiry {
            app_role_id: "not-a-guid".into(),
            ..expiry("2026-12-24")
        };
        assert_eq!(encode_expiry_tag(&bad), None);
    }

    #[test]
    fn decode_treats_foreign_and_malformed_tags_apart() {
        assert_eq!(decode_expiry_tag("HideApp"), None);
        assert_eq!(decode_expiry_tag("azapptoolkit:spItem:v1|site|a|b"), None);
        for ours in [
            format!("azapptoolkit:grantExpiry:v1|{RES}|{ROLE}|2026-13-40"),
            format!("azapptoolkit:grantExpiry:v1|nope|{ROLE}|2026-12-24"),
            format!("azapptoolkit:grantExpiry:v2|{RES}|{ROLE}|2026-12-24"),
            "azapptoolkit:grantExpiry:v1|too|few".to_string(),
        ] {
            assert_eq!(decode_expiry_tag(&ours), Some(None), "{ours}");
        }
        let tags = vec![
            "HideApp".to_string(),
            encode_expiry_tag(&expiry("2026-12-24")).unwrap(),
            format!("azapptoolkit:grantExpiry:v1|{RES}|{ROLE}|garbage"),
        ];
        assert_eq!(expiries_in(&tags), vec![expiry("2026-12-24")]);
    }

    #[test]
    fn an_expiry_passes_at_the_end_of_its_day_utc() {
        let now: Timestamp = "2026-12-24T23:59:00Z".parse().unwrap();
        assert!(
            !expiry_has_passed(date("2026-12-24"), now),
            "today is not past"
        );
        assert!(expiry_has_passed(date("2026-12-23"), now));
        assert!(!expiry_has_passed(date("2026-12-25"), now));
    }

    #[test]
    fn with_expiry_replaces_clears_and_keeps_other_tags() {
        let old = encode_expiry_tag(&expiry("2026-12-01")).unwrap();
        let shouted = old.replace(RES, &RES.to_uppercase());
        let tags = vec!["HideApp".to_string(), old.clone(), shouted];
        let set = with_expiry(&tags, RES, ROLE, Some(date("2027-01-31"))).unwrap();
        assert_eq!(
            set,
            vec![
                "HideApp".to_string(),
                encode_expiry_tag(&expiry("2027-01-31")).unwrap()
            ]
        );
        let cleared = with_expiry(&set, &RES.to_uppercase(), ROLE, None).unwrap();
        assert_eq!(cleared, vec!["HideApp".to_string()]);
        assert_eq!(with_expiry(&tags, "nope", ROLE, None), None);
    }
}
