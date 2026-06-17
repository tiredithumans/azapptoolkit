//! Redirect (reply) URI validation for application registrations.
//!
//! Enforces Microsoft's app-registration security best practices on the URIs
//! this toolkit writes (SSO setup): no wildcard reply URLs, no insecure schemes
//! (`http` except loopback, `urn:`), prefer `https`. See
//! <https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration>.
//!
//! String-based (no URL-parser dependency): anything malformed is treated
//! conservatively, and the one allowed `http` case is the loopback address used
//! by native/desktop dev clients.

/// Validates a single redirect URI. Returns a human-readable reason on
/// rejection so the caller can surface it verbatim.
pub fn validate_redirect_uri(uri: &str) -> Result<(), String> {
    let u = uri.trim();
    if u.is_empty() {
        return Err("redirect URI is empty".into());
    }
    // Wildcards defeat exact reply-URL matching and are a known phishing vector.
    if u.contains('*') {
        return Err(format!("wildcard redirect URIs are not allowed: {uri}"));
    }
    let lower = u.to_ascii_lowercase();
    if lower.starts_with("urn:") {
        return Err(format!(
            "insecure 'urn:' redirect URIs are not allowed: {uri}"
        ));
    }
    if let Some(rest) = lower.strip_prefix("http://") {
        // Loopback is the only permitted plaintext-http case (native dev clients).
        let authority = rest.split('/').next().unwrap_or("");
        let host = if let Some(bracketed) = authority.strip_prefix('[') {
            // IPv6 literal `[::1]:port` → `::1`.
            bracketed.split(']').next().unwrap_or("")
        } else {
            authority.split(':').next().unwrap_or("")
        };
        if !matches!(host, "localhost" | "127.0.0.1" | "::1") {
            return Err(format!(
                "insecure http redirect URIs are not allowed (use https): {uri}"
            ));
        }
    }
    Ok(())
}

/// Validates every URI in `uris`, returning the first rejection reason.
pub fn validate_redirect_uris<S: AsRef<str>>(uris: &[S]) -> Result<(), String> {
    for u in uris {
        validate_redirect_uri(u.as_ref())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_and_loopback_http() {
        assert!(validate_redirect_uri("https://app.contoso.com/auth").is_ok());
        assert!(validate_redirect_uri("https://contoso.com").is_ok());
        assert!(validate_redirect_uri("http://localhost:5173/callback").is_ok());
        assert!(validate_redirect_uri("http://127.0.0.1:8400/").is_ok());
        assert!(validate_redirect_uri("http://[::1]:8400/cb").is_ok());
        // A custom app scheme (mobile/desktop public client) is not http/urn/wildcard.
        assert!(validate_redirect_uri("myapp://auth").is_ok());
    }

    #[test]
    fn rejects_wildcards() {
        assert!(validate_redirect_uri("https://*.contoso.com/auth").is_err());
        assert!(validate_redirect_uri("https://contoso.com/*").is_err());
    }

    #[test]
    fn rejects_insecure_http_and_urn() {
        assert!(validate_redirect_uri("http://app.contoso.com/auth").is_err());
        // A hostname that merely starts with "localhost" is NOT loopback.
        assert!(validate_redirect_uri("http://localhost.evil.com/auth").is_err());
        assert!(validate_redirect_uri("urn:ietf:wg:oauth:2.0:oob").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_redirect_uri("   ").is_err());
    }

    #[test]
    fn validate_many_reports_first_failure() {
        let uris = ["https://ok.contoso.com", "https://*.bad.com"];
        assert!(validate_redirect_uris(&uris).is_err());
        let good = ["https://a.contoso.com", "http://localhost/cb"];
        assert!(validate_redirect_uris(&good).is_ok());
    }
}
