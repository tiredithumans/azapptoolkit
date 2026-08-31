//! The single certificate-thumbprint converter shared by both trees.
//!
//! A certificate thumbprint in the Entra world is the **SHA-1** digest of the
//! certificate DER, and it reaches us written three different ways. Every
//! surface that displays or compares one goes through [`canonical`], so the
//! backend, the WASM frontend, and what the Entra portal shows can never drift
//! apart again.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// Renders raw digest bytes as the uppercase, separator-free hex string the
/// Entra portal shows in its Thumbprint column.
pub fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02X}");
        acc
    })
}

/// The canonical (uppercase hex) thumbprint for a `keyCredentials` entry's
/// `customKeyIdentifier`.
///
/// **The two fields are in different encodings, and this is the bug that made
/// the whole SSO rollover feature silently inert.** `customKeyIdentifier` is
/// `Edm.Binary`, so Graph serializes it as **base64 of the SHA-1 thumbprint
/// bytes** (`"2iD8ppbE+D6Kmu1ZvjM2jtQh88E="`), while
/// `preferredTokenSigningKeyThumbprint` is a String holding the **hex** form
/// (`"DA20FCA696C4F83E8A9AED59BE33368ED421F3C1"`) — the same 20 bytes, written
/// two ways. Comparing them directly never matches, so no certificate was ever
/// recognised as active: every app read as "Staged", every expiry read
/// "Unknown", the work-queue filter matched nothing, and bulk staging skipped
/// every app. Nothing errored; the board simply reported all-clear forever.
///
/// Both the display value and the `preferredTokenSigningKeyThumbprint` we PATCH
/// come from here, so what an operator reads matches what the Entra portal shows
/// and what activation actually writes.
///
/// Accepts the hex form unchanged: a certificate uploaded by hand (rather than
/// minted by `addTokenSigningCertificate`) can carry `customKeyIdentifier`
/// already written as hex, and Microsoft's own upload guidance describes it as
/// "the certificate thumbprint hash". That case is **not** decorative — a
/// 40-character hex string is also valid base64, so decoding it blindly yields
/// 30 bytes of garbage and renders 60 plausible-looking hex characters rather
/// than failing.
pub fn canonical(custom_key_identifier: &str) -> Option<String> {
    let raw = custom_key_identifier.trim();
    if raw.is_empty() {
        return None;
    }
    // Already hex (40 chars = 20 SHA-1 bytes) — normalise case only.
    if raw.len() == 40 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(raw.to_ascii_uppercase());
    }
    // Otherwise base64 of the raw thumbprint bytes.
    let bytes = STANDARD.decode(raw).ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(hex_upper(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair Microsoft's own `addTokenSigningCertificate` reference returns
    /// for ONE certificate — `customKeyIdentifier` base64, `thumbprint` hex.
    /// Copied verbatim from the API docs, so this test fails if the
    /// normalisation ever stops handling what Graph actually sends.
    const DOC_CKI: &str = "2iD8ppbE+D6Kmu1ZvjM2jtQh88E=";
    const DOC_THUMBPRINT: &str = "DA20FCA696C4F83E8A9AED59BE33368ED421F3C1";

    #[test]
    fn base64_and_hex_are_two_spellings_of_the_same_bytes() {
        assert_eq!(
            canonical(DOC_CKI).as_deref(),
            Some(DOC_THUMBPRINT),
            "base64 customKeyIdentifier must normalise to the hex thumbprint",
        );
        // And the raw base64 never equals the hex — the original bug, pinned.
        assert_ne!(DOC_CKI, DOC_THUMBPRINT);
    }

    #[test]
    fn an_already_hex_identifier_passes_through_rather_than_decoding() {
        assert_eq!(canonical(DOC_THUMBPRINT).as_deref(), Some(DOC_THUMBPRINT));
        assert_eq!(
            canonical(&DOC_THUMBPRINT.to_ascii_lowercase()).as_deref(),
            Some(DOC_THUMBPRINT),
            "hex is normalised to upper case so display and comparison agree",
        );

        // Regression: this 40-character hex identifier is ALSO valid base64
        // (length 40 % 4 == 0, every character in the alphabet), so a blind
        // decode silently produced 30 bytes and rendered 60 bogus hex chars
        // instead of the operator's actual thumbprint.
        let hex = "0f7a2c9b1e4d6a8f3b5c2e1d9a4f6b8c0e2d4a6f";
        assert!(STANDARD.decode(hex).is_ok(), "premise: also valid base64");
        assert_eq!(
            canonical(hex).as_deref(),
            Some("0F7A2C9B1E4D6A8F3B5C2E1D9A4F6B8C0E2D4A6F"),
        );
    }

    #[test]
    fn undecodable_input_is_none_rather_than_a_value_that_matches_nothing() {
        assert_eq!(canonical(""), None);
        assert_eq!(canonical("   "), None);
        assert_eq!(canonical("not base64 !!"), None);
    }

    #[test]
    fn hex_upper_renders_uppercase_pairs() {
        assert_eq!(hex_upper(&[0xAB, 0xCD, 0x01]), "ABCD01");
        assert_eq!(hex_upper(&[]), "");
    }
}
