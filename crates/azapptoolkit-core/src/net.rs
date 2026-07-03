//! Origin guard shared by the HTTP client crates (Graph, Key Vault, ARM).
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

#[cfg(test)]
mod tests {
    use super::*;

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
