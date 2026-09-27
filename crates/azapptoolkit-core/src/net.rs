//! Origin guard shared by the HTTP client crates (Graph, Exchange, Key Vault,
//! ARM).
//!
//! A paging `nextLink` is attacker-influenced server output: following it
//! verbatim would attach the bearer token to whatever host the response named.
//! Every client that follows absolute links must check [`same_origin`] first.
//! Single-sourced here because the copies had already drifted — the Graph
//! client's rejected embedded credentials while Key Vault's didn't.

/// True when `candidate` has the same scheme/host/port as `base`. Embedded
/// credentials (`user:pass@host`) are rejected outright: `Url::origin()`
/// ignores userinfo, so a link carrying it would otherwise pass the origin
/// compare, and no Azure service emits one.
pub fn same_origin(base: &str, candidate: &str) -> bool {
    match (url::Url::parse(base), url::Url::parse(candidate)) {
        (Ok(b), Ok(c)) => {
            if !c.username().is_empty() || c.password().is_some() {
                return false;
            }
            b.origin() == c.origin()
        }
        _ => false,
    }
}

/// Host component of `url` for safe error display. The full URL is
/// attacker-influenced (a malicious `nextLink` in a server response) and may
/// carry tokens, paths, or query material that must not reach logs, audit
/// output, or the error UI; the bare host is enough to diagnose.
pub fn redacted_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "<unparseable>".into())
}

/// The endpoint *family* of `url` for a retry/throttle log label: the path
/// only, with every segment that looks like an identifier masked to `{id}`.
///
/// `https://graph.microsoft.com/v1.0/servicePrincipals/<guid>/appRoleAssignedTo?$filter=…`
/// becomes `/v1.0/servicePrincipals/{id}/appRoleAssignedTo`: enough to tell
/// which fan-out a 429 storm is hitting, with no object ids, UPNs or SharePoint
/// site ids (`host,guid,guid`) in the log, and never the query string (so no
/// `$filter` values). A segment survives only when it is made of ASCII letters,
/// digits, `.`, `$` or `_`, contains at least one letter, and is not a hex run
/// of 16 or more characters. Unparsable input yields `<invalid url>`.
pub fn endpoint_family(url: &str) -> String {
    let Ok(parsed) = url::Url::parse(url) else {
        return "<invalid url>".to_string();
    };
    let masked: Vec<&str> = parsed
        .path()
        .split('/')
        .map(|seg| {
            if seg.is_empty() || is_literal_path_segment(seg) {
                seg
            } else {
                "{id}"
            }
        })
        .collect();
    masked.join("/")
}

/// Whether a path segment is a literal route name (`servicePrincipals`,
/// `v1.0`, `$batch`) rather than an identifier — see [`endpoint_family`].
fn is_literal_path_segment(seg: &str) -> bool {
    let charset_ok = seg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '$' | '_'));
    let has_letter = seg.chars().any(|c| c.is_ascii_alphabetic());
    let long_hex = seg.len() >= 16 && seg.chars().all(|c| c.is_ascii_hexdigit());
    charset_ok && has_letter && !long_hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_family_masks_identifiers_and_drops_the_query() {
        for (url, expected) in [
            (
                "https://graph.microsoft.com/v1.0/servicePrincipals/0b1f9851-1bf0-433f-aec3-cb9272f093dc/appRoleAssignedTo",
                "/v1.0/servicePrincipals/{id}/appRoleAssignedTo",
            ),
            ("https://graph.microsoft.com/v1.0/$batch", "/v1.0/$batch"),
            (
                "https://graph.microsoft.com/v1.0/users/a@b.com",
                "/v1.0/users/{id}",
            ),
            (
                "https://graph.microsoft.com/v1.0/sites/x.sharepoint.com,11111111-2222-3333-4444-555555555555,66666666-7777-8888-9999-000000000000/permissions",
                "/v1.0/sites/{id}/permissions",
            ),
            (
                "https://graph.microsoft.com/v1.0/applications?$filter=displayName%20eq%20'secret'&$top=999",
                "/v1.0/applications",
            ),
            // A bare hex run (a thumbprint, a compact id) is an identifier too;
            // a purely numeric segment has no letter.
            (
                "https://management.azure.com/providers/0123456789abcdef0123/x/42",
                "/providers/{id}/x/{id}",
            ),
            ("not a url", "<invalid url>"),
        ] {
            assert_eq!(endpoint_family(url), expected, "{url}");
        }
    }

    #[test]
    fn same_origin_matches_scheme_host_port() {
        let base = "https://graph.microsoft.com/v1.0";
        assert!(same_origin(base, "https://graph.microsoft.com/v1.0/foo"));
        assert!(same_origin(base, "https://graph.microsoft.com/beta/other"));
        assert!(!same_origin(base, "https://evil.example.com/v1.0/foo"));
        assert!(!same_origin(base, "http://graph.microsoft.com/v1.0/foo"));
        assert!(!same_origin(base, "https://graph.microsoft.com:8443/v1.0"));
        assert!(!same_origin(base, "not a url"));
    }

    #[test]
    fn same_origin_rejects_embedded_credentials() {
        // `Url::origin()` ignores userinfo, so these would pass a bare origin
        // compare — the hardened check refuses them outright.
        let base = "https://graph.microsoft.com/v1.0";
        assert!(!same_origin(
            base,
            "https://user:pass@graph.microsoft.com/v1.0/foo"
        ));
        assert!(!same_origin(base, "https://user@graph.microsoft.com/v1.0"));
    }

    #[test]
    fn redacted_host_strips_path_and_query() {
        assert_eq!(
            redacted_host("https://evil.example.com/steal?token=s3cret"),
            "evil.example.com"
        );
        assert_eq!(redacted_host("not a url"), "<unparseable>");
    }
}
