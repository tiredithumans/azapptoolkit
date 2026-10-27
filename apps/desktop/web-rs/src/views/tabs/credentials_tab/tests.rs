//! Unit tests for the Credentials tab (`super`).

use super::*;

fn d(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
}

/// The Last-used column's three states must stay distinguishable, and the
/// fold must match the backend's: one credential can appear under both the
/// `application` and `servicePrincipal` origins and newest date wins; a
/// row with no date is "tracked, never used"; no row is UNKNOWN — never
/// rendered as if it meant unused. A row must also never be read against a
/// different app's credentials.
#[test]
fn last_used_cell_reads_three_states() {
    use azapptoolkit_dto::credentials::CredentialUsageRow;
    use chrono::{TimeZone, Utc};
    let old = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    let fresh = Utc.with_ymd_and_hms(2026, 9, 20, 8, 30, 0).unwrap();
    let row =
        |app_id: &str, key_id: &str, last_used: Option<chrono::DateTime<Utc>>| CredentialUsageRow {
            app_id: app_id.into(),
            key_id: key_id.into(),
            last_used,
        };
    let dto = CredentialUsageDto {
        available: true,
        rows: vec![
            row("app-1", "k-used", Some(old)),
            row("app-1", "k-used", Some(fresh)),
            row("app-1", "k-never", None),
        ],
    };
    let map = usage_lookup(Some(&dto));
    assert_eq!(last_used_text(&map, "app-1", "k-used"), "2026-09-20");
    assert_eq!(last_used_text(&map, "app-1", "k-never"), "No use recorded");
    assert_eq!(last_used_text(&map, "app-1", "k-unknown"), "—");
    assert_eq!(last_used_text(&map, "app-2", "k-used"), "—");
    // Unavailable report (or none) → nothing is knowable, everything "—".
    let off = CredentialUsageDto {
        available: false,
        rows: vec![row("app-1", "k-used", Some(fresh))],
    };
    assert!(usage_lookup(Some(&off)).is_empty());
    assert_eq!(
        last_used_text(&usage_lookup(Some(&off)), "app-1", "k-used"),
        "—"
    );
    assert!(usage_lookup(None).is_empty());
}

const TODAY: &str = "2026-01-01";

/// The Key Vault secret NAME derived from a credential's display name.
///
/// Key Vault accepts `[0-9a-zA-Z-]` only, so everything else has to go — and
/// the empty result has to become a valid fallback rather than a rejected
/// request. What matters beyond legality is DISTINCTNESS: this name selects
/// which secret a rotate writes a new version of, so two apps sharing one
/// name means one app's rotate lands on the other's credential.
#[test]
fn secret_names_are_reduced_to_what_key_vault_accepts() {
    // Already valid: unchanged.
    assert_eq!(sanitize_secret_name("api-prod-2026"), "api-prod-2026");
    // Disallowed characters become a separator rather than vanishing, and
    // runs collapse to a single hyphen with the ends trimmed.
    assert_eq!(
        sanitize_secret_name("My App / prod_v1.2"),
        "My-App-prod-v1-2"
    );
    assert_eq!(sanitize_secret_name("api prod-2026"), "api-prod-2026");
    assert_eq!(sanitize_secret_name("  lead and trail  "), "lead-and-trail");
    // The regression this replaced: these two used to collapse to the same
    // name, so the second write versioned the first instead of creating a
    // sibling.
    assert_ne!(sanitize_secret_name("a.b"), sanitize_secret_name("ab"));
    assert_eq!(sanitize_secret_name("a.b"), "a-b");
    // Non-ASCII is still dropped rather than transliterated, so a wholly
    // non-Latin name reduces to nothing — but it no longer lands on a shared
    // literal. Every such app used to get exactly `client-secret`.
    assert_eq!(sanitize_secret_name("Zurich"), "Zurich");
    let a = sanitize_secret_name("\u{4f60}\u{597d}");
    let b = sanitize_secret_name("\u{3053}\u{3093}\u{306b}\u{3061}\u{306f}");
    assert!(a.starts_with("client-secret-"), "got {a}");
    assert_ne!(a, b, "two non-Latin names must not share a secret name");
    // The digest has to reproduce across processes and toolchains, or a
    // rotate would orphan every version written under the old name.
    assert_eq!(a, sanitize_secret_name("\u{4f60}\u{597d}"));
    // Genuinely empty input keeps the bare fallback — there is nothing to
    // discriminate on, and it is the documented default.
    assert_eq!(sanitize_secret_name(""), "client-secret");
    assert_eq!(sanitize_secret_name("   "), "client-secret");
    // The output is always a legal Key Vault secret name.
    for input in ["", "  ", "a b", "\u{e9}\u{e8}", "ok-1", "!!!", "..a..b.."] {
        let out = sanitize_secret_name(input);
        assert!(!out.is_empty(), "{input:?} produced an empty name");
        assert!(
            out.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "{input:?} produced an illegal name: {out}"
        );
        assert!(
            !out.starts_with('-') && !out.ends_with('-'),
            "{input:?} -> {out}"
        );
        assert!(!out.contains("--"), "{input:?} -> {out}");
    }
}

#[test]
fn presets_map_to_lifetime_days() {
    let mut numeric = Vec::new();
    for (preset, _) in EXPIRES_PRESETS.iter().filter(|(p, _)| *p != CUSTOM_PRESET) {
        let (days, start, end) = resolve_expiry_fields(preset, None, None, d(TODAY)).unwrap();
        assert_eq!(days, Some(preset.parse::<u32>().unwrap()));
        assert!(start.is_none() && end.is_none());
        numeric.push(preset.parse::<u32>().unwrap());
    }
    // The two presets that carry policy restate the dto constants.
    assert_eq!(
        numeric[0], DEFAULT_SECRET_LIFETIME_DAYS,
        "the first preset is the recommended default"
    );
    assert_eq!(
        numeric.iter().copied().max(),
        Some(MAX_SECRET_LIFETIME_DAYS),
        "the longest preset is the cap"
    );
}

#[test]
fn custom_resolves_midnight_utc_window() {
    let (days, start, end) = resolve_expiry_fields(
        CUSTOM_PRESET,
        Some(d("2026-02-01")),
        Some(d("2026-08-01")),
        d(TODAY),
    )
    .unwrap();
    assert!(days.is_none());
    assert_eq!(start.unwrap().to_rfc3339(), "2026-02-01T00:00:00+00:00");
    assert_eq!(end.unwrap().to_rfc3339(), "2026-08-01T00:00:00+00:00");
}

#[test]
fn custom_requires_end_after_start_and_caps_at_24_months() {
    assert!(resolve_expiry_fields(CUSTOM_PRESET, None, None, d(TODAY)).is_err());
    assert!(
        resolve_expiry_fields(
            CUSTOM_PRESET,
            Some(d("2026-06-01")),
            Some(d("2026-06-01")),
            d(TODAY),
        )
        .is_err()
    );
    // Without an explicit start, "today" anchors the window.
    assert!(resolve_expiry_fields(CUSTOM_PRESET, None, Some(d("2025-12-01")), d(TODAY)).is_err());
    assert!(
        resolve_expiry_fields(
            CUSTOM_PRESET,
            Some(d("2026-01-01")),
            Some(d("2028-06-01")),
            d(TODAY),
        )
        .is_err()
    );
}

/// The rotate and generate-certificate lifetimes are typed free text. They
/// used to be coerced — garbage became 180/365 days, an over-long value was
/// clamped to the cap — so the credential minted was not the one asked for
/// and nothing said so. Now anything but an in-range whole number is an
/// error the dialog shows, and nothing is dispatched.
#[test]
fn lifetime_inputs_are_validated_not_coerced() {
    for (raw, want) in [("180", 180), (" 90 ", 90), ("1", 1), ("730", 730)] {
        assert_eq!(
            parse_days(raw, 1, MAX_SECRET_LIFETIME_DAYS),
            Ok(want),
            "{raw:?}"
        );
    }
    assert_eq!(parse_days("1095", 1, MAX_CERT_VALIDITY_DAYS), Ok(1095));
    for raw in [
        "",
        "   ",
        "abc",
        "0",
        "731",
        "3650",
        "90 days",
        "-5",
        "1.5",
        "99999999999",
    ] {
        assert!(
            parse_days(raw, 1, MAX_SECRET_LIFETIME_DAYS).is_err(),
            "{raw:?} must be rejected, not coerced"
        );
    }
    assert_eq!(
        parse_days("3650", 1, MAX_CERT_VALIDITY_DAYS),
        Err("Enter a whole number of days between 1 and 1095.".to_string())
    );
}
