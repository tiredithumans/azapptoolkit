//! Small shared helpers that don't belong to a single component.

use std::collections::HashSet;
use std::hash::Hash;

use leptos::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// Keep-alive wrapper for a tab/view: the body mounts on first visit (tracked in
/// `visited`) and thereafter stays in the DOM, toggled via `display` so its
/// state (scroll, inputs, loaded resources) survives switching away and back.
/// Generic over the key `K` so it serves both the shell's `ActiveView` nav and a
/// detail pane's string-keyed sub-tabs (`target` takes anything `Into<K>`, e.g.
/// a `&'static str` for a `String` key).
pub fn keep_alive<K, F, V>(
    active: RwSignal<K>,
    visited: RwSignal<HashSet<K>>,
    target: impl Into<K>,
    body: F,
) -> impl IntoView
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    F: Fn() -> V + Send + Sync + 'static,
    V: IntoView + 'static,
{
    let target = target.into();
    let key = target.clone();
    view! {
        <Show when=move || visited.with(|s| s.contains(&key)) fallback=|| ()>
            {
                // Clone per render so the inner `style:display` closure owns its
                // own key — the Show children fn must stay `Fn`, not move the
                // captured `target` out (matters when K isn't `Copy`, e.g. String).
                let target = target.clone();
                view! {
                    <div style:display=move || {
                        if active.with(|a| *a == target) { "contents" } else { "none" }
                    }>{body()}</div>
                }
            }
        </Show>
    }
}

/// Copies `value` to the system clipboard (fire-and-forget). Shared by the
/// detail panes and the SSO summary, all of which surface copy-to-clipboard
/// fields.
pub fn copy_text(value: String) {
    leptos::task::spawn_local(async move {
        if let Some(win) = web_sys::window() {
            let promise = win.navigator().clipboard().write_text(&value);
            let _ = JsFuture::from(promise).await;
        }
    });
}

/// The standard "no tenant selected" IPC error. Views guard on the active
/// tenant before invoking a command; centralizing this keeps the code + message
/// identical everywhere (it had been independently redefined in 7 files).
pub fn no_tenant() -> azapptoolkit_dto::UiError {
    azapptoolkit_dto::UiError {
        code: "no_tenant".into(),
        message: "tenant missing".into(),
        retryable: false,
    }
}

/// Converts raw certificate file bytes into the text payload
/// `add_certificate_credential` accepts. Three file shapes exist in the wild:
/// PEM text and bare-base64 text pass through unchanged (the backend's
/// normalizer already handles both), while binary DER (`.cer`/`.crt` exported
/// as DER — never valid UTF-8 in practice, the second byte is a bare
/// continuation byte) is base64-encoded. Double-encoding a base64 text file
/// would make Graph see text bytes instead of the certificate.
pub fn cert_payload_from_bytes(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let is_bare_base64 = |text: &str| {
        let stripped: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        !stripped.is_empty() && STANDARD.decode(&stripped).is_ok()
    };
    match std::str::from_utf8(bytes) {
        Ok(text) if text.contains("-----BEGIN") || is_bare_base64(text) => text.to_string(),
        _ => STANDARD.encode(bytes),
    }
}

/// Renders Graph's `customKeyIdentifier` (base64-encoded SHA-1 thumbprint
/// bytes) as the uppercase hex string the portal shows in its Thumbprint
/// column. Returns `None` when the value isn't valid base64.
pub fn thumbprint_hex(custom_key_identifier_b64: &str) -> Option<String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let bytes = STANDARD.decode(custom_key_identifier_b64).ok()?;
    Some(bytes.iter().map(|b| format!("{b:02X}")).collect())
}

/// Splits a free-text box into trimmed, non-empty entries, accepting newline-,
/// comma-, or semicolon-separated input. Shared by every scope form (Exchange
/// mail-enabled group lists, SharePoint site URLs) and the audit's scoping
/// remediations, which all let an admin paste a list however they like.
pub fn parse_lines(raw: &str) -> Vec<String> {
    raw.split(['\n', ',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Inclusive `[after, before]` creation-date filter shared by the App
/// Registration and Enterprise Application lists. Both bounds are day-granular
/// and optional — an unset date picker leaves that side open, and with both
/// unset every row passes. When either bound is set, a row whose creation
/// timestamp is missing is excluded (it can't be placed in the window). An
/// inverted range (`after` later than `before`) matches nothing.
pub fn created_in_range(
    created: Option<chrono::DateTime<chrono::Utc>>,
    after: Option<chrono::NaiveDate>,
    before: Option<chrono::NaiveDate>,
) -> bool {
    let Some(day) = created.map(|c| c.date_naive()) else {
        // Unknown creation date: keep it only while neither bound is active.
        return after.is_none() && before.is_none();
    };
    after.is_none_or(|a| day >= a) && before.is_none_or(|b| day <= b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lines_splits_on_newline_comma_semicolon_and_trims() {
        assert_eq!(parse_lines("group1\ngroup2"), ["group1", "group2"]);
        assert_eq!(parse_lines("a, b; c"), ["a", "b", "c"]);
        assert_eq!(parse_lines("  spaces  \n  trim  "), ["spaces", "trim"]);
    }

    #[test]
    fn parse_lines_drops_empty_fields() {
        assert!(parse_lines("").is_empty());
        assert!(parse_lines("\n\n,;").is_empty());
        assert_eq!(parse_lines("a,,,b"), ["a", "b"]);
    }

    #[test]
    fn cert_payload_passes_pem_text_through() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAAAA==\n-----END CERTIFICATE-----\n";
        assert_eq!(cert_payload_from_bytes(pem.as_bytes()), pem);
    }

    #[test]
    fn cert_payload_base64_encodes_binary_der() {
        // 0x30 = ASN.1 SEQUENCE — the first byte of any real DER certificate.
        let der = [0x30u8, 0x82, 0x01, 0x0a, 0x00, 0xff];
        assert_eq!(cert_payload_from_bytes(&der), "MIIBCgD/");
    }

    #[test]
    fn cert_payload_passes_bare_base64_text_through() {
        // A .pem/.cer holding bare base64 (no armour) must NOT be re-encoded —
        // Graph would otherwise see the text bytes instead of the certificate.
        assert_eq!(cert_payload_from_bytes(b"MIIBCgD/\n"), "MIIBCgD/\n");
    }

    #[test]
    fn cert_payload_encodes_non_base64_text_as_binary() {
        // Text that is neither PEM nor base64 falls through to the binary
        // path; the backend's decode then rejects it loudly either way.
        let payload = cert_payload_from_bytes(b"not a certificate!");
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        assert_eq!(STANDARD.decode(payload).unwrap(), b"not a certificate!");
    }

    #[test]
    fn thumbprint_hex_renders_uppercase_pairs() {
        // base64 of bytes [0xAB, 0xCD, 0x01]
        assert_eq!(thumbprint_hex("q80B").as_deref(), Some("ABCD01"));
        assert!(thumbprint_hex("!!notbase64!!").is_none());
    }

    #[test]
    fn created_in_range_bounds_are_inclusive_and_optional() {
        use chrono::{NaiveDate, TimeZone, Utc};
        let at = |y, m, d| Utc.with_ymd_and_hms(y, m, d, 12, 0, 0).single();
        let on = |y, m, d| NaiveDate::from_ymd_opt(y, m, d);
        let created = at(2024, 6, 15);

        // No bounds → always included (even a missing creation date).
        assert!(created_in_range(created, None, None));
        assert!(created_in_range(None, None, None));

        // Lower bound is inclusive.
        assert!(created_in_range(created, on(2024, 6, 15), None));
        assert!(created_in_range(created, on(2024, 6, 14), None));
        assert!(!created_in_range(created, on(2024, 6, 16), None));

        // Upper bound is inclusive.
        assert!(created_in_range(created, None, on(2024, 6, 15)));
        assert!(created_in_range(created, None, on(2024, 6, 16)));
        assert!(!created_in_range(created, None, on(2024, 6, 14)));

        // Closed window.
        assert!(created_in_range(created, on(2024, 6, 1), on(2024, 6, 30)));
        assert!(!created_in_range(created, on(2024, 7, 1), on(2024, 7, 31)));

        // Inverted range (after later than before) matches nothing.
        assert!(!created_in_range(created, on(2024, 6, 20), on(2024, 6, 10)));

        // A missing creation date is excluded once any bound is active.
        assert!(!created_in_range(None, on(2024, 1, 1), None));
        assert!(!created_in_range(None, None, on(2024, 12, 31)));
    }
}
