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
///
/// The body is erased to `AnyView` **here**, not at the call sites. A detail
/// pane mounts eight to ten tabs through this, and Leptos view types are deeply
/// nested tuples: carrying them through the `Show`/`div` wrapper concretely made
/// every instantiation a distinct, enormous type and crashed `rust-lld` with a
/// SIGBUS while linking the wasm binary (an LLVM crash, not a diagnosable
/// error). Erasing once collapses the wrapper's type to the same shape for every
/// tab, which is what the `match`-with-`.into_any()`-arms these calls replaced
/// was doing implicitly. Don't "optimize" this boxing away.
pub fn keep_alive<K, F, V>(
    active: RwSignal<K>,
    visited: RwSignal<HashSet<K>>,
    target: impl Into<K>,
    body: F,
) -> impl IntoView
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    F: Fn() -> V + Send + Sync + 'static,
    V: IntoView + Send + 'static,
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
                    }>{body().into_any()}</div>
                }
            }
        </Show>
    }
}

/// Reads a `localStorage` value by key, returning `None` when the key is
/// absent or the storage API is unavailable. Shared by the credential
/// rotate-vault prefill (`credentials_tab`) and the saved-views persistence
/// (`saved_views`), where it had been independently redefined byte-for-byte.
pub fn ls_get(key: &str) -> Option<String> {
    web_sys::window()?
        .local_storage()
        .ok()
        .flatten()?
        .get_item(key)
        .ok()
        .flatten()
}

/// Writes a `localStorage` value (fire-and-forget; a storage failure is
/// silently ignored). Paired with [`ls_get`].
pub fn ls_set(key: &str, value: &str) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item(key, value);
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
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    let is_bare_base64 = |text: &str| {
        let stripped: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        !stripped.is_empty() && STANDARD.decode(&stripped).is_ok()
    };
    match std::str::from_utf8(bytes) {
        Ok(text) if text.contains("-----BEGIN") || is_bare_base64(text) => text.to_string(),
        _ => STANDARD.encode(bytes),
    }
}

/// Renders Graph's `customKeyIdentifier` as the uppercase hex string the portal
/// shows in its Thumbprint column.
///
/// One definition only: [`azapptoolkit_core::thumbprint::canonical`], shared
/// with the backend. Decoding it here by hand is what made a hand-uploaded
/// certificate — whose identifier is already hex, and whose 40 hex characters
/// are *also* valid base64 — render 60 characters of garbage instead of its
/// thumbprint.
pub fn thumbprint_hex(custom_key_identifier: &str) -> Option<String> {
    azapptoolkit_core::thumbprint::canonical(custom_key_identifier)
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

/// A timestamp rendered for display: the relative phrase a surface shows and
/// the exact UTC stamp it hovers. Paired because a relative phrase alone is
/// unciteable — an operator writing a change ticket needs the absolute time —
/// and an absolute stamp alone is the thing nobody does the arithmetic on.
pub struct TimeAgo {
    pub relative: String,
    pub exact: String,
}

/// Renders `then` as a short "how long ago" phrase relative to `now`.
///
/// Deliberately coarse: the question a posture surface answers is "are these
/// numbers current?", not "how many seconds old are they?", so the buckets
/// stop at days and a sub-minute age reads "just now". A `then` in the future
/// (clock skew across a suspend/resume, or a machine whose clock drifted)
/// reads "just now" as well rather than "in 3 minutes" — the phrase describes
/// something that already happened.
pub fn relative_time(
    now: chrono::DateTime<chrono::Utc>,
    then: chrono::DateTime<chrono::Utc>,
) -> String {
    let secs = (now - then).num_seconds();
    if secs < 60 {
        return "just now".to_string();
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins} min ago");
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours} hour{} ago", plural(hours));
    }
    let days = hours / 24;
    format!("{days} day{} ago", plural(days))
}

fn plural(n: i64) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Parses an RFC3339 timestamp (as every backend DTO carries one) into its
/// display pair. `None` when the string isn't a timestamp — the caller renders
/// nothing at all, because a stamp we can't read is a bug on our side, not a
/// state an operator can act on.
pub fn time_ago(rfc3339: &str) -> Option<TimeAgo> {
    let then = chrono::DateTime::parse_from_rfc3339(rfc3339)
        .ok()?
        .with_timezone(&chrono::Utc);
    Some(TimeAgo {
        relative: relative_time(chrono::Utc::now(), then),
        // The same absolute format the Activity tab uses for a last sign-in.
        exact: then.format("%Y-%m-%d %H:%M UTC").to_string(),
    })
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
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        assert_eq!(STANDARD.decode(payload).unwrap(), b"not a certificate!");
    }

    #[test]
    fn thumbprint_hex_renders_uppercase_pairs() {
        // base64 of bytes [0xAB, 0xCD, 0x01]
        assert_eq!(thumbprint_hex("q80B").as_deref(), Some("ABCD01"));
        assert!(thumbprint_hex("!!notbase64!!").is_none());
        // An already-hex identifier passes through instead of being decoded as
        // base64 (which it also is) into 60 characters of garbage.
        assert_eq!(
            thumbprint_hex("0f7a2c9b1e4d6a8f3b5c2e1d9a4f6b8c0e2d4a6f").as_deref(),
            Some("0F7A2C9B1E4D6A8F3B5C2E1D9A4F6B8C0E2D4A6F"),
        );
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

    #[test]
    fn relative_time_buckets_by_minutes_hours_then_days() {
        use chrono::{Duration, TimeZone, Utc};
        let now = Utc.with_ymd_and_hms(2026, 9, 2, 12, 0, 0).unwrap();
        let ago = |d: Duration| relative_time(now, now - d);

        assert_eq!(ago(Duration::seconds(0)), "just now");
        assert_eq!(ago(Duration::seconds(59)), "just now");
        assert_eq!(ago(Duration::minutes(1)), "1 min ago");
        assert_eq!(ago(Duration::minutes(12)), "12 min ago");
        assert_eq!(ago(Duration::minutes(59)), "59 min ago");
        assert_eq!(ago(Duration::hours(1)), "1 hour ago");
        assert_eq!(ago(Duration::hours(3)), "3 hours ago");
        assert_eq!(ago(Duration::hours(23)), "23 hours ago");
        assert_eq!(ago(Duration::days(1)), "1 day ago");
        assert_eq!(ago(Duration::days(9)), "9 days ago");
        // Truncation, never rounding up: 89 minutes is "1 hour ago", so the
        // phrase can never claim a scan is fresher than it is.
        assert_eq!(ago(Duration::minutes(89)), "1 hour ago");
    }

    #[test]
    fn a_future_timestamp_reads_as_just_now() {
        // Clock skew (a suspended laptop, a drifted VM) must not produce
        // "-3 min ago" on a security surface.
        use chrono::{Duration, TimeZone, Utc};
        let now = Utc.with_ymd_and_hms(2026, 9, 2, 12, 0, 0).unwrap();
        assert_eq!(relative_time(now, now + Duration::hours(2)), "just now");
    }

    #[test]
    fn time_ago_parses_rfc3339_and_pairs_it_with_the_exact_stamp() {
        let t = time_ago("2026-09-02T09:30:00+00:00").expect("valid RFC3339");
        assert_eq!(t.exact, "2026-09-02 09:30 UTC");
        assert!(t.relative.ends_with("ago") || t.relative == "just now");
        // A non-UTC offset is normalized to UTC rather than displayed as-is.
        let offset = time_ago("2026-09-02T11:30:00+02:00").expect("valid RFC3339");
        assert_eq!(offset.exact, "2026-09-02 09:30 UTC");
        // Unparseable input renders nothing at all.
        assert!(time_ago("not a timestamp").is_none());
    }
}

/// Case-insensitive substring test that allocates **nothing** for the common
/// (ASCII) case.
///
/// `needle_lower` must already be lowercased — every caller lowercases the query
/// once per keystroke. The haystack, though, is a different row on every call:
/// `haystack.to_lowercase().contains(needle)` allocated one `String` per row per
/// filter pass, so a settled keystroke over a 10 000-row tenant list allocated
/// tens of thousands of times.
///
/// For an all-ASCII haystack, ASCII-insensitive matching is *identical* to full
/// Unicode lowercasing, so the fast path is exact rather than an approximation.
/// A haystack containing non-ASCII falls back to the allocating form, which
/// keeps locale-correct behaviour (Turkish dotted I, Greek final sigma, …) for
/// the names that actually need it.
pub fn contains_ignore_case(haystack: &str, needle_lower: &str) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if haystack.is_ascii() {
        if !needle_lower.is_ascii() {
            // A non-ASCII needle cannot occur in an ASCII haystack.
            return false;
        }
        let (hay, needle) = (haystack.as_bytes(), needle_lower.as_bytes());
        if needle.len() > hay.len() {
            return false;
        }
        return hay
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle));
    }
    haystack.to_lowercase().contains(needle_lower)
}

#[cfg(test)]
mod contains_ignore_case_tests {
    use super::contains_ignore_case;

    #[test]
    fn matches_case_insensitively_and_anywhere() {
        assert!(contains_ignore_case("Contoso CRM", "crm"));
        assert!(contains_ignore_case("Contoso CRM", "contoso"));
        assert!(contains_ignore_case("Contoso CRM", "oso c"));
        assert!(!contains_ignore_case("Contoso CRM", "fabrikam"));
    }

    #[test]
    fn an_empty_needle_matches_everything() {
        assert!(contains_ignore_case("", ""));
        assert!(contains_ignore_case("anything", ""));
    }

    #[test]
    fn a_needle_longer_than_the_haystack_cannot_match() {
        assert!(!contains_ignore_case("ab", "abc"));
    }

    /// The ASCII fast path must not change results for non-ASCII names — the
    /// fallback has to agree with the allocating form it replaces.
    #[test]
    fn non_ascii_haystacks_still_match_case_insensitively() {
        assert!(contains_ignore_case("Ünternehmen Größe", "größe"));
        assert!(contains_ignore_case("ΑΘΗΝΑ", "αθηνα"));
        assert_eq!(
            contains_ignore_case("Ünternehmen", "ünter"),
            "Ünternehmen".to_lowercase().contains("ünter"),
        );
    }

    /// A non-ASCII needle against an ASCII haystack takes the early-out; it must
    /// agree with the allocating form (which also cannot match).
    #[test]
    fn a_non_ascii_needle_never_matches_an_ascii_haystack() {
        assert!(!contains_ignore_case("Contoso", "ü"));
        assert_eq!(
            contains_ignore_case("Contoso", "ü"),
            "Contoso".to_lowercase().contains("ü"),
        );
    }
}
