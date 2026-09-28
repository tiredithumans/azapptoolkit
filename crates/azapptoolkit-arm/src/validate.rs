//! Shape checks for ARM-supplied identifiers before they are spliced into a
//! request URL.
//!
//! Subscription ids, Log Analytics workspace ids and resource ids reach this
//! crate straight out of earlier ARM responses (or, for a role-assignment
//! scope, from the operator) — the same attacker-influenced server-output
//! class `collect_paged` guards `nextLink` for. The composed URL keeps the ARM
//! host either way, but a `?` or `#` rewrites or truncates the query the call
//! depends on, and a `..` segment (or its `%2e%2e` form) is normalised away by
//! the URL parser, walking the call to a different path with the operator's
//! token. Mirrors `azapptoolkit-keyvault`'s `validate` module. The refusals
//! never echo the value.

use azapptoolkit_core::guid::is_guid;

use crate::error::{ArmError, Result};

/// Refuses a `value` that is not a canonical 8-4-4-4-12 GUID.
pub(crate) fn require_guid(what: &str, value: &str) -> Result<()> {
    if is_guid(value) {
        Ok(())
    } else {
        Err(ArmError::Protocol(format!(
            "refusing a {what} that is not a GUID"
        )))
    }
}

/// Refuses a `value` that is not an absolute ARM resource path: it must start
/// with `/` and contain no `?`, `#`, `\`, `%`, control character, or `.` /
/// `..` segment.
///
/// Non-ASCII is allowed (a resource-group name may hold Unicode letters), and
/// so is an `@` — after the leading `/` it sits in the path, past the
/// authority, where it is inert.
pub(crate) fn require_arm_path(what: &str, value: &str) -> Result<()> {
    let ok = value.starts_with('/')
        && !value.contains(['?', '#', '\\', '%'])
        && !value.chars().any(char::is_control)
        && !value.split('/').any(|seg| seg == "." || seg == "..");
    if ok {
        Ok(())
    } else {
        Err(ArmError::Protocol(format!(
            "refusing a {what} that is not an absolute ARM path"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_guid_accepts_only_a_canonical_guid() {
        assert!(require_guid("subscription id", "3fa85f64-5717-4562-b3fc-2c963f66afa6").is_ok());
        assert!(require_guid("subscription id", "3FA85F64-5717-4562-B3FC-2C963F66AFA6").is_ok());
        for bad in [
            "sub?api-version=x",
            "../providers/x",
            "",
            "sub-1",
            "3fa85f64-5717-4562-b3fc-2c963f66afa6/../x",
        ] {
            let err = require_guid("subscription id", bad).unwrap_err();
            assert!(
                matches!(&err, ArmError::Protocol(m) if m == "refusing a subscription id that is not a GUID"),
                "{bad:?}: {err:?}"
            );
        }
    }

    #[test]
    fn require_arm_path_accepts_an_absolute_resource_path() {
        for good in [
            "/subscriptions/s/rg",
            "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-1",
            // Trailing slash and Unicode resource-group names are real ARM paths.
            "/subscriptions/s/",
            "/subscriptions/s/resourceGroups/grüße",
            // `@` after the leading `/` is inert (in the path, not the authority).
            "/subscriptions/s/x@y",
        ] {
            assert!(require_arm_path("scope", good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn require_arm_path_refuses_what_reshapes_the_url() {
        for bad in [
            "subscriptions/s",
            "",
            "/a/../b",
            "/a/..",
            "/a/./b",
            "/a/%2e%2e/b",
            "/a\\..\\b",
            "/a?x",
            "/a#f",
            "/a/\nb",
        ] {
            let err = require_arm_path("scope", bad).unwrap_err();
            assert!(
                matches!(&err, ArmError::Protocol(m) if m == "refusing a scope that is not an absolute ARM path"),
                "{bad:?}: {err:?}"
            );
        }
    }
}
