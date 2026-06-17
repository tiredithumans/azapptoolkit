//! Validation for Key Vault identifiers that flow into request URLs.
//!
//! `vault_name` is interpolated into the request host and `secret_name` into
//! the request path, both from untrusted IPC input. Rejecting anything outside
//! Azure's documented naming rules closes the SSRF / path-traversal vector
//! (e.g. a `vault_name` of `evil.example.com/x?` or a `secret_name` of `../`).

use crate::error::{KeyVaultError, Result};

/// Azure Key Vault name rules: 3–24 chars, ASCII alphanumeric and hyphens
/// only, must start with a letter, end with a letter or digit, no consecutive
/// hyphens.
pub fn validate_vault_name(name: &str) -> Result<()> {
    let ok = (3..=24).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name.ends_with(|c: char| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !name.contains("--");
    if ok {
        Ok(())
    } else {
        Err(KeyVaultError::InvalidName(format!(
            "{name:?} is not a valid Key Vault name"
        )))
    }
}

/// Azure Key Vault secret name rules: 1–127 chars, ASCII alphanumeric and
/// hyphens only.
pub fn validate_secret_name(name: &str) -> Result<()> {
    let ok = (1..=127).contains(&name.len())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(KeyVaultError::InvalidName(format!(
            "{name:?} is not a valid Key Vault secret name"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_vault_names() {
        for name in ["my-vault", "abc", "Vault-01", "a1b2c3d4e5f6g7h8i9j0k1l2"] {
            assert!(validate_vault_name(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn rejects_ssrf_and_malformed_vault_names() {
        for name in [
            "ev",                         // too short
            "evil.example.com",           // dots (would redirect the host)
            "evil.example.com/secrets/x", // slash + path
            "vault?x=1",                  // query
            "vault--name",                // consecutive hyphens
            "-vault",                     // leading hyphen
            "vault-",                     // trailing hyphen
            "1vault",                     // leading digit
            "vault_name",                 // underscore
            "this-name-is-way-too-long-for-a-vault",
        ] {
            assert!(
                validate_vault_name(name).is_err(),
                "{name} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_path_traversal_secret_names() {
        for name in ["", "..", "../../etc", "a/b", "a%2Fb", "name?x"] {
            assert!(
                validate_secret_name(name).is_err(),
                "{name} should be rejected"
            );
        }
        assert!(validate_secret_name("my-secret-01").is_ok());
    }
}
