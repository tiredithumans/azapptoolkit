//! Federated identity credential (workload identity federation) validation.
//!
//! A federated identity credential is a **trust**, not a setting: any external
//! identity presenting a token whose `iss` / `sub` / `aud` match one can obtain
//! access tokens as the application — with no secret to leak and no expiry to
//! notice. That makes its three defining values security-critical in exactly the
//! way the sibling redirect (reply) URIs already are, and this module is the
//! [`redirect`](crate::redirect) counterpart for them.
//!
//! Validating locally matters more here than for most inputs, because Graph will
//! not do it for you: Microsoft documents that an incorrect issuer or subject
//! **"is created successfully without error"** and that "the error does not
//! become apparent until the token exchange fails". A silently-accepted trust is
//! the worst case for a value that may have arrived from a backup file the
//! operator did not author.
//!
//! Every rule below is Microsoft's own, from
//! <https://learn.microsoft.com/entra/workload-id/workload-identity-federation-considerations>.
//! String-based, like `redirect` — anything malformed is treated conservatively.

/// Character ceiling Entra applies to `issuer`, `subject`, each `audiences`
/// entry, and `description`.
const MAX_FIELD_LEN: usize = 600;

/// `name` is 3–120 characters, URL-friendly.
const NAME_MIN_LEN: usize = 3;
const NAME_MAX_LEN: usize = 120;

/// Validates a federated identity credential before it is written.
///
/// `name` is `Some` on create and **`None` on update** — Graph makes the name
/// immutable, so the update path has none to check.
///
/// Returns a human-readable reason on rejection so the caller can surface it
/// verbatim, the same contract as [`crate::redirect::validate_redirect_uri`].
pub fn validate_federated_credential(
    name: Option<&str>,
    issuer: &str,
    subject: &str,
    audiences: &[String],
    description: Option<&str>,
) -> Result<(), String> {
    if let Some(name) = name {
        validate_credential_name(name)?;
    }
    validate_issuer(issuer)?;
    validate_field("subject", subject)?;

    // Required, and Entra accepts exactly one value. An empty list would let
    // Graph pick nothing at all to match `aud` against.
    if audiences.is_empty() {
        return Err(
            "at least one audience is required (Entra recommends 'api://AzureADTokenExchange')"
                .into(),
        );
    }
    for audience in audiences {
        validate_field("audience", audience)?;
    }

    if let Some(description) = description
        && description.chars().count() > MAX_FIELD_LEN
    {
        return Err(format!(
            "description is longer than {MAX_FIELD_LEN} characters"
        ));
    }
    Ok(())
}

/// `name` must be 3–120 URL-friendly characters: alphanumeric, dash or
/// underscore, with an alphanumeric first character. It is immutable once
/// created, so a bad one has to be deleted and re-made.
fn validate_credential_name(name: &str) -> Result<(), String> {
    let len = name.chars().count();
    if !(NAME_MIN_LEN..=NAME_MAX_LEN).contains(&len) {
        return Err(format!(
            "credential name must be {NAME_MIN_LEN}-{NAME_MAX_LEN} characters (got {len})"
        ));
    }
    if !name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(format!(
            "credential name must start with a letter or digit: {name}"
        ));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_')
    {
        return Err(format!(
            "credential name may only contain letters, digits, '-' and '_' (found '{bad}'): {name}"
        ));
    }
    Ok(())
}

/// The issuer is the URL Entra fetches signing keys from to validate the
/// external token, so it carries the whole trust decision.
fn validate_issuer(issuer: &str) -> Result<(), String> {
    validate_field("issuer", issuer)?;

    // OpenID Connect requires an issuer identifier to use the https scheme, and
    // Entra fetches the provider's keys from this URL. Plain http would let
    // whoever controls the network path supply those keys.
    let lower = issuer.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("https://") else {
        return Err(format!(
            "issuer must be an https URL (the external provider's OpenID Connect issuer): {issuer}"
        ));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // `https://` with nothing after it names no provider.
    if authority.is_empty() {
        return Err(format!("issuer URL has no host: {issuer}"));
    }
    // Userinfo is separated from the real host by `@`, so
    // `https://token.actions.githubusercontent.com@evil.example/` fetches its
    // OIDC metadata and signing keys from **evil.example** while reading as
    // GitHub everywhere the value is displayed. This module is the only control
    // on the issuer — Graph accepts an incorrect one silently (see the module
    // doc) — and both call sites depend on it, including the untrusted restore
    // path. The result would be a secretless, non-expiring trust.
    if authority.contains('@') {
        return Err(format!(
            "issuer URL embeds credentials, which hide the host the keys are \
             actually fetched from: {issuer}"
        ));
    }
    Ok(())
}

/// The checks every value shares: present, within the length ceiling, no
/// surrounding whitespace, and no wildcard.
fn validate_field(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} is required"));
    }
    // Entra documents that leading or trailing whitespace in the issuer blocks
    // the token exchange — and it does so silently, at exchange time.
    if value.trim() != value {
        return Err(format!(
            "{label} has leading or trailing whitespace, which silently blocks the token exchange: {value:?}"
        ));
    }
    if value.chars().count() > MAX_FIELD_LEN {
        return Err(format!("{label} is longer than {MAX_FIELD_LEN} characters"));
    }
    // "Wildcard characters aren't supported in any federated identity credential
    // property value" — a value containing one cannot match a real token claim,
    // so it is either a mistake or an attempt to broaden the trust.
    if value.contains('*') {
        return Err(format!("{label} may not contain a wildcard: {value}"));
    }
    // Control characters cannot appear in a JWT claim being matched, and would
    // make the stored value unreadable in the UI and in operator-facing reports.
    if let Some(bad) = value.chars().find(|c| c.is_control()) {
        return Err(format!(
            "{label} contains a control character (U+{:04X})",
            bad as u32
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aud() -> Vec<String> {
        vec!["api://AzureADTokenExchange".to_string()]
    }

    fn check(name: &str, issuer: &str, subject: &str) -> Result<(), String> {
        validate_federated_credential(Some(name), issuer, subject, &aud(), None)
    }

    #[test]
    fn accepts_the_documented_scenarios() {
        // GitHub Actions.
        assert!(
            check(
                "github-main",
                "https://token.actions.githubusercontent.com",
                "repo:contoso/app:ref:refs/heads/main",
            )
            .is_ok()
        );
        // Kubernetes (AKS OIDC issuer).
        assert!(
            check(
                "k8s_sa",
                "https://oidc.prod-aks.azure.com/00000000-0000-0000-0000-000000000000/",
                "system:serviceaccount:erp8asle:pod-identity-sa",
            )
            .is_ok()
        );
        // Google Cloud — the subject is a bare numeric id.
        assert!(
            check(
                "GcpFederation",
                "https://accounts.google.com",
                "112633961854638529490"
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_a_non_https_issuer() {
        assert!(check("ok-name", "http://issuer.example", "sub").is_err());
        // Not a URL at all.
        assert!(check("ok-name", "issuer.example", "sub").is_err());
        // Loopback is NOT an exception here (unlike a redirect URI): Entra
        // fetches the signing keys from this URL server-side.
        assert!(check("ok-name", "http://localhost:8080", "sub").is_err());
        assert!(check("ok-name", "https://", "sub").is_err());
    }

    /// A federated credential is a secretless, non-expiring trust, and the
    /// issuer is the URL Entra fetches the signing keys from. Userinfo lets that
    /// URL read as a well-known provider while pointing somewhere else — and
    /// Graph accepts an incorrect issuer without error, so this is the only
    /// place it can be caught.
    #[test]
    fn rejects_a_userinfo_disguised_host() {
        for issuer in [
            "https://token.actions.githubusercontent.com@evil.example/",
            "https://token.actions.githubusercontent.com@evil.example",
            "https://accounts.google.com@evil.example/o/oauth2",
            // The last `@` wins, so an early legitimate-looking segment is not
            // a way through.
            "https://a@token.actions.githubusercontent.com@evil.example/",
        ] {
            assert!(
                check("ok-name", issuer, "sub").is_err(),
                "{issuer} fetches keys from evil.example"
            );
        }
        // The real issuers still pass.
        assert!(
            check(
                "ok-name",
                "https://token.actions.githubusercontent.com",
                "sub"
            )
            .is_ok()
        );
        assert!(check("ok-name", "https://accounts.google.com", "sub").is_ok());
    }

    #[test]
    fn rejects_wildcards_in_every_value() {
        assert!(check("ok-name", "https://issuer.example/*", "sub").is_err());
        assert!(check("ok-name", "https://issuer.example", "repo:contoso/*").is_err());
        assert!(
            validate_federated_credential(
                Some("ok-name"),
                "https://issuer.example",
                "sub",
                &["api://*".to_string()],
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_surrounding_whitespace_that_would_silently_break_the_exchange() {
        assert!(check("ok-name", " https://issuer.example", "sub").is_err());
        assert!(check("ok-name", "https://issuer.example ", "sub").is_err());
        assert!(check("ok-name", "https://issuer.example", "sub\n").is_err());
    }

    #[test]
    fn rejects_missing_values() {
        assert!(check("ok-name", "", "sub").is_err());
        assert!(check("ok-name", "https://issuer.example", "   ").is_err());
        assert!(
            validate_federated_credential(
                Some("ok-name"),
                "https://issuer.example",
                "sub",
                &[],
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn enforces_the_name_rules_entra_documents() {
        let ok = |n: &str| check(n, "https://issuer.example", "sub").is_ok();
        assert!(ok("abc"));
        assert!(ok("a-b_c9"));
        assert!(!ok("ab")); // shorter than 3
        assert!(!ok(&"a".repeat(121))); // longer than 120
        assert!(!ok("-leading-dash")); // first character must be alphanumeric
        assert!(!ok("has space"));
        assert!(!ok("has.dot"));
    }

    #[test]
    fn the_update_path_skips_the_immutable_name() {
        // `None` is the update path: Graph makes `name` immutable, so there is
        // nothing to validate — but the trust-defining values still are.
        assert!(
            validate_federated_credential(None, "https://issuer.example", "sub", &aud(), None)
                .is_ok()
        );
        assert!(
            validate_federated_credential(None, "http://issuer.example", "sub", &aud(), None)
                .is_err()
        );
    }

    #[test]
    fn enforces_the_600_character_ceiling() {
        let long = format!("https://issuer.example/{}", "a".repeat(600));
        assert!(check("ok-name", &long, "sub").is_err());
        assert!(check("ok-name", "https://issuer.example", &"s".repeat(601)).is_err());
        assert!(
            validate_federated_credential(
                Some("ok-name"),
                "https://issuer.example",
                "sub",
                &aud(),
                Some(&"d".repeat(601)),
            )
            .is_err()
        );
    }
}
