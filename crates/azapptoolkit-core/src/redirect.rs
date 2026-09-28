//! Redirect (reply) URI validation for application registrations.
//!
//! Enforces Microsoft's app-registration security best practices on the URIs
//! this toolkit writes (SSO setup): no wildcard reply URLs, no insecure schemes
//! (`http` except loopback, `urn:`), prefer `https`. See
//! <https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration>.
//!
//! It also enforces Entra's two hard limits on a reply URL — at most
//! [`MAX_REDIRECT_URI_LEN`] characters, and no IPv6 loopback (`[::1]`) — so the
//! inline row check catches them before the PATCH instead of the whole save
//! failing with a generic Graph 400. See
//! <https://learn.microsoft.com/en-us/entra/identity-platform/reply-url>.
//!
//! String-based (no URL-parser dependency): anything malformed is treated
//! conservatively, and the one allowed `http` case is the loopback address used
//! by native/desktop dev clients.

/// Entra's per-URI length limit: "You can use a maximum of 256 characters for
/// each redirect URI you add to an app registration" (Microsoft Learn,
/// "Redirect URI (reply URL) outline and restrictions",
/// <https://learn.microsoft.com/en-us/entra/identity-platform/reply-url>).
/// Counted in characters, as Microsoft states it, not bytes.
pub const MAX_REDIRECT_URI_LEN: usize = 256;

/// Validates a single redirect URI. Returns a human-readable reason on
/// rejection so the caller can surface it verbatim.
pub fn validate_redirect_uri(uri: &str) -> Result<(), String> {
    let u = uri.trim();
    if u.is_empty() {
        return Err("redirect URI is empty".into());
    }
    let len = u.chars().count();
    if len > MAX_REDIRECT_URI_LEN {
        // The message ends in `: {uri}` like every other rejection, so the
        // inline row hint (`uri_list_editor::redirect_uri_reason`) can strip
        // the echo instead of repeating a 300-character URI.
        return Err(format!(
            "redirect URI is {len} characters; Entra allows at most \
             {MAX_REDIRECT_URI_LEN}: {uri}"
        ));
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
        // Userinfo comes first and is separated from the real host by the LAST
        // `@`. Splitting the authority on `:` before considering it read
        // `http://127.0.0.1:1@evil.com/cb` as host `127.0.0.1` — so the one
        // intentional plaintext exception admitted a reply URL pointed at an
        // arbitrary host. `localhost:80@evil.com` and `[::1]@evil.com` bypassed
        // it the same way. `net::same_origin` rejects embedded credentials
        // outright for the same reason.
        let authority = authority.rsplit('@').next().unwrap_or("");
        let host = if let Some(bracketed) = authority.strip_prefix('[') {
            // IPv6 literal `[::1]:port` → `::1`.
            bracketed.split(']').next().unwrap_or("")
        } else {
            authority.split(':').next().unwrap_or("")
        };
        // Microsoft: "The IPv6 loopback address ([::1]) isn't currently
        // supported" (reply-url page above). Entra rejects it, so it is not in
        // the loopback set; restore `"::1"` here if Entra adds support.
        if host == "::1" {
            return Err(format!(
                "Entra doesn't support the IPv6 loopback address [::1] in redirect URIs; \
                 use http://localhost or http://127.0.0.1: {uri}"
            ));
        }
        if !matches!(host, "localhost" | "127.0.0.1") {
            return Err(format!(
                "insecure http redirect URIs are not allowed (use https): {uri}"
            ));
        }
    }
    Ok(())
}

/// Validates a front-channel logout URL. Same rules as a reply URL (no
/// wildcard, no `urn:`, `http` only for loopback, Entra's length limit) plus:
/// it must be `https` (or loopback `http`), never a custom scheme — Entra
/// loads it in a hidden iframe, and MSAL's "Signing out users" guidance says
/// the page "must be loaded via https".
///
/// Loopback `http` stays allowed on purpose: the Authentication tab is a full
/// replace that re-sends the current value, so refusing an existing
/// `http://localhost/...` logout URL would make every save of the tab fail.
pub fn validate_logout_url(url: &str) -> Result<(), String> {
    validate_redirect_uri(url)?;
    let lower = url.trim().to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err(format!(
            "front-channel logout URL must be an https address: {url}"
        ));
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

    /// Userinfo lets a plaintext reply URL name a loopback host it does not
    /// actually resolve to. The authority was split on `:` before `@` was
    /// considered, so everything before the first colon read as the host.
    #[test]
    fn rejects_a_loopback_host_disguised_by_userinfo() {
        for uri in [
            // `127.0.0.1:1` is userinfo; the real host is evil.com.
            "http://127.0.0.1:1@evil.com/cb",
            "http://localhost:80@evil.com/cb",
            "http://[::1]@evil.com/cb",
            // Multiple `@` — the LAST one separates the host, so an early
            // loopback-looking segment must not win.
            "http://localhost@127.0.0.1@evil.com/cb",
            // Bare userinfo with no port.
            "http://localhost@evil.com/cb",
        ] {
            assert!(
                validate_redirect_uri(uri).is_err(),
                "{uri} names evil.com, not a loopback host"
            );
        }
        // The genuine loopback forms still pass, userinfo-free.
        assert!(validate_redirect_uri("http://localhost:5173/callback").is_ok());
        assert!(validate_redirect_uri("http://127.0.0.1:8400/cb").is_ok());
    }

    /// Entra rejects the IPv6 loopback in a reply URL, so the pre-flight does
    /// too — with the reason, not the generic "use https".
    #[test]
    fn rejects_the_ipv6_loopback_entra_does_not_support() {
        for uri in ["http://[::1]:8400/cb", "http://[::1]/"] {
            let err = validate_redirect_uri(uri).unwrap_err();
            assert!(err.contains("[::1]"), "{uri}: {err}");
            assert!(!err.contains("use https"), "{uri}: {err}");
            assert!(err.ends_with(&format!(": {uri}")), "{uri}: {err}");
        }
    }

    #[test]
    fn enforces_entras_256_character_limit() {
        let prefix = "https://contoso.com/";
        let of_len = |n: usize| format!("{prefix}{}", "a".repeat(n - prefix.len()));
        let at_limit = of_len(MAX_REDIRECT_URI_LEN);
        assert_eq!(at_limit.chars().count(), 256);
        assert!(validate_redirect_uri(&at_limit).is_ok());

        let over = of_len(MAX_REDIRECT_URI_LEN + 1);
        let err = validate_redirect_uri(&over).unwrap_err();
        assert!(err.contains("256"), "{err}");
        assert!(
            err.ends_with(&format!(": {over}")),
            "the row hint strips this suffix"
        );

        // Characters, not bytes: 256 characters with a multibyte one is more
        // than 256 bytes and still within the limit.
        let multibyte = format!(
            "{prefix}é{}",
            "a".repeat(MAX_REDIRECT_URI_LEN - prefix.len() - 1)
        );
        assert_eq!(multibyte.chars().count(), 256);
        assert!(multibyte.len() > 256);
        assert!(validate_redirect_uri(&multibyte).is_ok());
    }

    #[test]
    fn validate_logout_url_requires_a_web_address() {
        for ok in [
            "https://contoso.com/signout",
            "http://localhost:5000/signout",
            "  https://contoso.com/signout  ",
        ] {
            assert!(validate_logout_url(ok).is_ok(), "{ok}");
        }
        let too_long = format!("https://contoso.com/{}", "a".repeat(300));
        for bad in [
            "myapp://signout",
            "javascript:alert(1)",
            "https://*.contoso.com/signout",
            "http://contoso.com/signout",
            "urn:x",
            "http://[::1]/signout",
            too_long.as_str(),
        ] {
            assert!(validate_logout_url(bad).is_err(), "{bad}");
        }
        let err = validate_logout_url("myapp://signout").unwrap_err();
        assert!(err.contains("https"), "{err}");
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
