//! Shared GUID helpers for the command layer: client-side v4 generation (the
//! portal-style pattern — supplying the id makes the write self-contained and,
//! for ARM role assignments, idempotent on retry) and the strict canonical
//! validator (re-exported from `azapptoolkit_core::guid`, which the ARM client
//! shares). Single-sourced so the generator can't drift between domains and
//! the two former `is_guid` copies (`search` strict-positional vs `config`
//! split-based) can't diverge again. [`require_app_id`] is the boundary check
//! for an application (client) id the webview sends.

use crate::dto::UiError;

/// A random v4 GUID in canonical lowercase 8-4-4-4-12 form.
pub(crate) fn new_v4_guid() -> String {
    use rand::Rng as _;
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1 (RFC 4122)
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// Strict 8-4-4-4-12 hex check (case-insensitive). No braces, no urn-prefix.
/// The one definition lives in core, where the ARM client uses it too.
pub(crate) use azapptoolkit_core::guid::is_guid;

/// Refuses an application (client) id the webview sent unless it is a GUID
/// (`invalid_app_id`).
///
/// The graph client keys its per-app service-principal cache as
/// `{tenant}|{appId}` and the audit's lean projection as
/// `{tenant}|{appId}|lean`, in one bucket, so an `app_id` of `X|lean` names app
/// X's lean entry: its lookup misses, and the empty result is stored over X's.
/// Every command whose `app_id` reaches one of those reads calls this first
/// (pinned by `trust.rs::every_ipc_app_id_is_a_guid_before_it_keys_the_sp_cache`).
pub(crate) fn require_app_id(app_id: &str) -> Result<(), UiError> {
    if is_guid(app_id) {
        Ok(())
    } else {
        Err(UiError::validation(
            "invalid_app_id",
            "The application (client) ID must be a GUID.",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_guid_is_v4_canonical() {
        let g = new_v4_guid();
        assert!(is_guid(&g), "not a GUID: {g}");
        assert_eq!(g.as_bytes()[14], b'4', "version nibble");
        assert!(
            matches!(g.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
            "variant nibble: {g}"
        );
        // Vanishingly unlikely to collide — pins that it's actually random.
        assert_ne!(g, new_v4_guid());
    }

    /// An app id that is not a GUID never reaches a cache key: `X|lean` is the
    /// spelling that named another app's lean service-principal entry.
    #[test]
    fn an_app_id_must_be_a_guid() {
        let app = "71487acd-ec93-476d-bd0e-6c8b31831053";
        assert!(require_app_id(app).is_ok());
        assert!(require_app_id(&app.to_ascii_uppercase()).is_ok());
        for bad in [
            format!("{app}|lean"),
            "app-1".to_string(),
            String::new(),
            format!("{{{app}}}"),
        ] {
            let err = require_app_id(&bad).expect_err(&bad);
            assert_eq!(err.code, "invalid_app_id", "{bad}");
        }
    }
}
