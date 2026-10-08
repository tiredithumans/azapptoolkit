//! Unit tests for the SSO command layer (`super`).

use super::board::{sso_cert_status, sso_certificates_to_csv};
use super::config::{
    build_sso_summary, extract_app_sso_fields, extract_request_signature_verification,
    extract_sp_sso_fields,
};
use super::metadata::parse_signing_certs;
use super::rollover::{activation_target, build_rollover, is_preferred_key, retire_target};

use crate::dto::sso::{SigningCertRolloverDto, SsoCertificateRowDto, SsoConfigDto, SsoSummary};

use super::*;

#[test]
fn claims_policy_403_names_the_claims_roles() {
    let forbidden = UiError {
        code: "forbidden".into(),
        message: "graph said no".into(),
        retryable: false,
    };
    let err = claims_policy_err(forbidden);
    assert!(err.message.starts_with("graph said no "));
    assert!(err.message.contains("Application Administrator"));
    let other = UiError {
        code: "graph_error".into(),
        message: "boom".into(),
        retryable: false,
    };
    assert_eq!(claims_policy_err(other).message, "boom");
}

#[test]
fn a_claims_save_plan_never_edits_or_deletes_a_shared_policy() {
    let sp = "sp";
    let one = vec!["p".to_string()];
    let sole = vec!["sp".to_string()];
    let shared = vec!["sp".to_string(), "other".to_string()];
    /// (assigned, appliesTo, editor empty, expected plan)
    type Case<'a> = (&'a [String], Option<&'a [String]>, bool, ClaimsWrite);
    let none: Vec<String> = Vec::new();
    let cases: [Case; 9] = [
        (&[], None, true, ClaimsWrite::Nothing),
        (&[], None, false, ClaimsWrite::Create),
        (
            &one,
            Some(&sole),
            false,
            ClaimsWrite::PatchInPlace("p".into()),
        ),
        (
            &one,
            Some(&shared),
            false,
            ClaimsWrite::Fork { detach: "p".into() },
        ),
        (
            &one,
            Some(&sole),
            true,
            ClaimsWrite::Detach {
                policy_id: "p".into(),
                delete: true,
            },
        ),
        (
            &one,
            Some(&shared),
            true,
            ClaimsWrite::Detach {
                policy_id: "p".into(),
                delete: false,
            },
        ),
        // No appliesTo proof ⇒ never treated as owned.
        (&one, None, false, ClaimsWrite::Fork { detach: "p".into() }),
        // An empty appliesTo is inconsistent state, not proof of ownership:
        // never patched in place, never deleted.
        (
            &one,
            Some(&none),
            false,
            ClaimsWrite::Fork { detach: "p".into() },
        ),
        (
            &one,
            Some(&none),
            true,
            ClaimsWrite::Detach {
                policy_id: "p".into(),
                delete: false,
            },
        ),
    ];
    for (assigned, subjects, empty, want) in cases {
        assert_eq!(
            plan_claims_write(sp, assigned, subjects, empty).unwrap(),
            want,
            "assigned={assigned:?} subjects={subjects:?} empty={empty}"
        );
    }
    // More than one assigned policy fails closed, empty or not.
    let two = vec!["a".to_string(), "b".to_string()];
    for empty in [true, false] {
        let err = plan_claims_write(sp, &two, None, empty).unwrap_err();
        assert_eq!(err.code, "multiple_claims_policies");
    }
}

#[test]
fn a_signing_certificate_lifetime_is_bounded_by_entras_three_year_ceiling() {
    // Default when none is supplied.
    assert_eq!(resolve_cert_lifetime_days(None).unwrap(), 365);
    assert_eq!(resolve_cert_lifetime_days(Some(1)).unwrap(), 1);
    assert_eq!(
        resolve_cert_lifetime_days(Some(MAX_CERT_LIFETIME_DAYS)).unwrap(),
        MAX_CERT_LIFETIME_DAYS
    );
    // A certificate that never practically expires is a trust that never
    // has to be re-established — and Graph refuses past three years anyway.
    let err = resolve_cert_lifetime_days(Some(MAX_CERT_LIFETIME_DAYS + 1)).unwrap_err();
    assert_eq!(err.code, "invalid_cert_lifetime");
    // Zero would mint an already-expired certificate.
    assert!(resolve_cert_lifetime_days(Some(0)).is_err());
    // And an absurd value never reaches `chrono::Duration::days`, which
    // panics rather than saturating.
    assert!(resolve_cert_lifetime_days(Some(u32::MAX)).is_err());
}

#[test]
fn a_client_secret_lifetime_is_bounded_by_entras_two_year_cap() {
    // Default when none is supplied — the portal's recommended preset.
    assert_eq!(resolve_secret_lifetime_days(None).unwrap(), 180);
    assert_eq!(resolve_secret_lifetime_days(Some(1)).unwrap(), 1);
    assert_eq!(resolve_secret_lifetime_days(Some(730)).unwrap(), 730);
    // The same 24-month cap the Credentials tab applies.
    let err = resolve_secret_lifetime_days(Some(731)).unwrap_err();
    assert_eq!(err.code, "invalid_secret_lifetime");
    // Zero would mint an already-expired secret.
    let err = resolve_secret_lifetime_days(Some(0)).unwrap_err();
    assert_eq!(err.code, "invalid_secret_lifetime");
    // And an absurd value never reaches `chrono` inside `add_password`,
    // whose `now + Duration` panics rather than saturating.
    let err = resolve_secret_lifetime_days(Some(u32::MAX)).unwrap_err();
    assert_eq!(err.code, "invalid_secret_lifetime");
}

#[test]
fn cert_subject_requires_cn_prefix() {
    // Graph's addTokenSigningCertificate rejects a displayName that
    // doesn't start with CN= — pin the fail-fast mirror of that rule.
    assert!(validate_cert_subject("CN=Contoso SSO").is_ok());
    assert!(validate_cert_subject("cn=lowercase").is_ok());
    for bad in ["Contoso", "O=Contoso", " ", "CN"] {
        let err = validate_cert_subject(bad).unwrap_err();
        assert_eq!(err.code, "invalid_cert_subject", "input: {bad:?}");
    }
}

#[test]
fn sanitize_notification_emails_trims_and_dedupes() {
    let out = sanitize_notification_emails(&[
        " a@x.com ".into(),
        "A@X.com".into(), // case-insensitive dupe of the first
        String::new(),
        "b@y.com".into(),
    ]);
    assert_eq!(out, vec!["a@x.com".to_string(), "b@y.com".to_string()]);
}

#[test]
fn saml_urls_match_spec() {
    let (issuer, login, logout, metadata) =
        saml_summary_urls(CloudEnvironment::Commercial, "tid", "aid");
    assert_eq!(issuer, "https://sts.windows.net/tid/");
    assert_eq!(login, "https://login.microsoftonline.com/tid/saml2");
    assert_eq!(logout, login);
    assert_eq!(
        metadata,
        "https://login.microsoftonline.com/tid/federationmetadata/2007-06/federationmetadata.xml?appid=aid"
    );
}

#[test]
fn saml_and_oidc_urls_follow_the_cloud() {
    let (issuer, login, logout, metadata) =
        saml_summary_urls(CloudEnvironment::UsGov, "tid", "aid");
    assert_eq!(issuer, "https://sts.windows.net/tid/");
    assert_eq!(login, "https://login.microsoftonline.us/tid/saml2");
    assert_eq!(logout, login);
    assert_eq!(
        metadata,
        "https://login.microsoftonline.us/tid/federationmetadata/2007-06/federationmetadata.xml?appid=aid"
    );
    let (authority, _) = oidc_summary_urls(CloudEnvironment::UsGov, "tid");
    assert_eq!(authority, "https://login.microsoftonline.us/tid/v2.0");

    let (issuer, login, _, metadata) = saml_summary_urls(CloudEnvironment::China, "tid", "aid");
    assert_eq!(issuer, "https://sts.chinacloudapi.cn/tid/");
    assert_eq!(login, "https://login.partner.microsoftonline.cn/tid/saml2");
    assert!(
        metadata.starts_with("https://login.partner.microsoftonline.cn/tid/"),
        "{metadata}"
    );
    let (authority, discovery) = oidc_summary_urls(CloudEnvironment::China, "tid");
    assert_eq!(
        authority,
        "https://login.partner.microsoftonline.cn/tid/v2.0"
    );
    assert!(discovery.starts_with(&authority), "{discovery}");

    let (_, dod_login, _, _) = saml_summary_urls(CloudEnvironment::UsGovDod, "tid", "aid");
    assert_eq!(dod_login, "https://login.microsoftonline.us/tid/saml2");
}

#[test]
fn oidc_urls_match_spec() {
    let (authority, discovery) = oidc_summary_urls(CloudEnvironment::Commercial, "tid");
    assert_eq!(authority, "https://login.microsoftonline.com/tid/v2.0");
    assert_eq!(
        discovery,
        "https://login.microsoftonline.com/tid/v2.0/.well-known/openid-configuration"
    );
}

#[test]
fn extract_app_sso_fields_reads_uris() {
    let app = serde_json::json!({
        "identifierUris": ["https://app/saml", "https://app/saml2"],
        "web": { "redirectUris": ["https://app/acs", "https://app/acs2"], "logoutUrl": "https://app/logout" },
        "spa": { "redirectUris": ["https://app/spa"] }
    });
    let (identifiers, web_redirects, logout, spa) = extract_app_sso_fields(&app);
    // All identifiers and reply URLs are returned (multi-value support).
    assert_eq!(
        identifiers,
        vec![
            "https://app/saml".to_string(),
            "https://app/saml2".to_string()
        ]
    );
    assert_eq!(
        web_redirects,
        vec![
            "https://app/acs".to_string(),
            "https://app/acs2".to_string()
        ]
    );
    assert_eq!(logout.as_deref(), Some("https://app/logout"));
    assert_eq!(spa, vec!["https://app/spa".to_string()]);
}

#[test]
fn extract_request_signature_verification_never_flags_unknown() {
    // Full block: the SAML app requires signed requests but still accepts the
    // weak SHA-1 family — both halves must arrive so the tab can warn.
    let full = serde_json::json!({
        "requestSignatureVerification": {
            "@odata.type": "#microsoft.graph.requestSignatureVerification",
            "isSignedRequestRequired": true,
            "allowedWeakAlgorithms": "rsaSha1"
        }
    });
    assert_eq!(
        extract_request_signature_verification(&full),
        (Some(true), Some("rsaSha1".to_string()))
    );
    // A non-SAML app returns no block at all: (None, None) = unknown, which the
    // tab renders as silence — never as "verification off".
    let bare = serde_json::json!({ "id": "app-1", "web": {} });
    assert_eq!(extract_request_signature_verification(&bare), (None, None));
    // "none" means no weak algorithm is allowed, not an allowance: it
    // normalises to None so the UI can't flag a healthy app. A non-bool
    // `isSignedRequestRequired` (a mis-shaped open type) is likewise unknown.
    let healthy = serde_json::json!({
        "requestSignatureVerification": {
            "isSignedRequestRequired": "yes",
            "allowedWeakAlgorithms": "none"
        }
    });
    assert_eq!(
        extract_request_signature_verification(&healthy),
        (None, None)
    );
    // Verification explicitly off is KNOWN off — the tab must show that, and an
    // empty algorithm string is not an allowance.
    let off = serde_json::json!({
        "requestSignatureVerification": {
            "isSignedRequestRequired": false,
            "allowedWeakAlgorithms": ""
        }
    });
    assert_eq!(
        extract_request_signature_verification(&off),
        (Some(false), None)
    );
}

#[test]
fn extract_sp_sso_fields_matches_expiry_by_thumbprint_case_insensitively() {
    // The signing-cert expiry is the keyCredentials entry whose
    // customKeyIdentifier matches the preferred thumbprint — and the match is
    // case-insensitive (Graph stores customKeyIdentifier uppercase). A
    // non-matching credential's endDateTime must be ignored.
    let sp = serde_json::json!({
        "appId": "app-123",
        "preferredSingleSignOnMode": "saml",
        "preferredTokenSigningKeyThumbprint": A_HEX,
        "keyCredentials": [
            { "customKeyIdentifier": B_B64, "endDateTime": "2000-01-01T00:00:00Z" },
            { "customKeyIdentifier": A_B64, "endDateTime": "2030-06-01T00:00:00Z" }
        ],
        "notificationEmailAddresses": ["a@x.com", "b@y.com"]
    });
    let (app_id, sso_mode, thumbprint, expiry, emails) = extract_sp_sso_fields(&sp);
    assert_eq!(app_id, "app-123");
    assert_eq!(sso_mode.as_deref(), Some("saml"));
    assert_eq!(thumbprint.as_deref(), Some(A_HEX));
    // Picked the matching (upper-cased) credential, not the first one.
    assert_eq!(expiry.as_deref(), Some("2030-06-01T00:00:00Z"));
    assert_eq!(emails, vec!["a@x.com".to_string(), "b@y.com".to_string()]);
}

// ---------------- staged rollover ----------------

use azapptoolkit_dto::sso::{CertStatus, RolloverPhase};

// REAL encoding pairs: `customKeyIdentifier` as Graph serializes it (base64
// of the 20 SHA-1 bytes) alongside the hex `preferredTokenSigningKeyThumbprint`
// for the SAME certificate. The previous fixtures used invented hex on both
// sides, which is precisely why these tests passed while the feature was
// inert against a real tenant: they asserted our assumption, not Graph's
// behaviour. Never hand-write a `customKeyIdentifier` again — derive it.
const A_B64: &str = "ATKoPe8CbYUF5PKRSLDOvhutu7A=";
const A_HEX: &str = "0132A83DEF026D8505E4F29148B0CEBE1BADBBB0";
const B_B64: &str = "7uqUyFZqj3EYkgjAu6GFqd4tB30=";
const B_HEX: &str = "EEEA94C8566A8F71189208C0BBA185A9DE2D077D";

/// `now` for the rollover tables below. Fixed so "expired" and "valid" are
/// properties of the fixture, not of the day the suite runs.
fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

/// One `keyCredentials` entry. `thumbprint_b64` is the base64
/// `customKeyIdentifier` exactly as Graph returns it.
fn cred(key_id: &str, thumbprint_b64: &str, end: &str, usage: &str) -> serde_json::Value {
    serde_json::json!({
        "keyId": key_id,
        "customKeyIdentifier": thumbprint_b64,
        "displayName": "CN=Contoso",
        "endDateTime": end,
        "usage": usage,
        "type": "AsymmetricX509Cert",
    })
}

fn sp_with(preferred: Option<&str>, creds: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "appId": "app-1",
        "preferredSingleSignOnMode": "saml",
        "preferredTokenSigningKeyThumbprint": preferred,
        "keyCredentials": creds,
    })
}

#[test]
fn the_two_thumbprint_fields_are_different_encodings_of_the_same_bytes() {
    // The pair Microsoft's own `addTokenSigningCertificate` reference returns
    // for ONE certificate — `customKeyIdentifier` base64, `thumbprint` hex.
    // The encodings themselves are pinned in `core::thumbprint`; what this
    // test holds is that the *comparison* normalises both sides.
    const DOC_CKI: &str = "2iD8ppbE+D6Kmu1ZvjM2jtQh88E=";
    const DOC_THUMBPRINT: &str = "DA20FCA696C4F83E8A9AED59BE33368ED421F3C1";

    assert!(
        is_preferred_key(DOC_CKI, DOC_THUMBPRINT),
        "these two ARE the same certificate; comparing them raw is what made \
         every app read as Staged, every expiry Unknown, and bulk staging a \
         no-op",
    );
    // Case-insensitive on the hex side — Entra is not consistent about it.
    assert!(is_preferred_key(
        DOC_CKI,
        &DOC_THUMBPRINT.to_ascii_lowercase()
    ));
    // A hand-uploaded certificate can carry the identifier already in hex.
    assert!(is_preferred_key(DOC_THUMBPRINT, DOC_THUMBPRINT));
    // An identifier that cannot be normalised matches nothing rather than
    // matching everything.
    assert!(!is_preferred_key("not base64 !!", DOC_THUMBPRINT));
    assert!(!is_preferred_key("", DOC_THUMBPRINT));
}

#[test]
fn rollover_metadata_url_follows_the_cloud() {
    let roll = build_rollover(
        &sp_with(
            Some(A_HEX),
            vec![cred("k1", A_B64, "2027-01-01T00:00:00Z", "Verify")],
        ),
        "sp-1",
        "tid",
        CloudEnvironment::UsGov,
        now(),
    );
    assert!(
        roll.federation_metadata_url
            .starts_with("https://login.microsoftonline.us/"),
        "{}",
        roll.federation_metadata_url
    );
}

#[test]
fn rollover_phase_reads_the_four_states_off_live_sp_state() {
    // Steady: one valid certificate, and it's the preferred one.
    let roll = build_rollover(
        &sp_with(
            Some(A_HEX),
            vec![cred("k1", A_B64, "2027-01-01T00:00:00Z", "Verify")],
        ),
        "sp-1",
        "tid",
        CloudEnvironment::Commercial,
        now(),
    );
    assert_eq!(roll.phase, RolloverPhase::Steady);
    assert_eq!(roll.staged_thumbprint, None);
    // Nothing staged ⇒ no deadline to show.
    assert_eq!(roll.auto_promote_deadline, None);

    // Staged: a newer valid certificate exists but isn't preferred yet.
    let roll = build_rollover(
        &sp_with(
            Some(A_HEX),
            vec![
                cred("k1", A_B64, "2026-06-01T00:00:00Z", "Verify"),
                cred("k2", B_B64, "2029-01-01T00:00:00Z", "Verify"),
            ],
        ),
        "sp-1",
        "tid",
        CloudEnvironment::Commercial,
        now(),
    );
    assert_eq!(roll.phase, RolloverPhase::Staged);
    assert_eq!(roll.staged_thumbprint.as_deref(), Some(B_HEX));
    // The ACTIVE certificate's expiry is the activation deadline: once it
    // passes, Entra promotes the staged certificate on its own.
    assert_eq!(
        roll.auto_promote_deadline.as_deref(),
        Some("2026-06-01T00:00:00Z")
    );

    // PendingRetire: the newest certificate is active, the older one is the
    // rollback target and still present.
    let roll = build_rollover(
        &sp_with(
            Some(B_HEX),
            vec![
                cred("k1", A_B64, "2026-06-01T00:00:00Z", "Verify"),
                cred("k2", B_B64, "2029-01-01T00:00:00Z", "Verify"),
            ],
        ),
        "sp-1",
        "tid",
        CloudEnvironment::Commercial,
        now(),
    );
    assert_eq!(roll.phase, RolloverPhase::PendingRetire);
    assert_eq!(
        roll.certs
            .iter()
            .find(|c| c.thumbprint == A_HEX)
            .map(|c| c.status),
        Some(CertStatus::Superseded)
    );

    // Unconfigured: no preferred key at all.
    let roll = build_rollover(
        &sp_with(
            None,
            vec![cred("k1", "AAA", "2027-01-01T00:00:00Z", "Verify")],
        ),
        "sp-1",
        "tid",
        CloudEnvironment::Commercial,
        now(),
    );
    assert_eq!(roll.phase, RolloverPhase::Unconfigured);
}

#[test]
fn an_expired_active_certificate_means_entra_already_promoted_the_staged_one() {
    // The trap from Microsoft's own docs: with an expired active certificate
    // and a valid inactive one, Entra signs with the inactive one — so the
    // deadline is in the PAST and the UI must not call this "steady".
    let roll = build_rollover(
        &sp_with(
            Some(A_HEX),
            vec![
                cred("k1", A_B64, "2025-06-01T00:00:00Z", "Verify"),
                cred("k2", B_B64, "2029-01-01T00:00:00Z", "Verify"),
            ],
        ),
        "sp-1",
        "tid",
        CloudEnvironment::Commercial,
        now(),
    );
    assert_eq!(roll.phase, RolloverPhase::Staged);
    assert_eq!(roll.staged_thumbprint.as_deref(), Some(B_HEX));
    let active = roll.certs.iter().find(|c| c.is_active).unwrap();
    // Still the nominated key, but it can't sign — both facts are visible.
    assert!(active.is_active);
    assert_eq!(active.status, CertStatus::Expired);
    assert!(active.days_to_expiry.is_some_and(|d| d < 0));
    assert_eq!(
        roll.auto_promote_deadline.as_deref(),
        Some("2025-06-01T00:00:00Z")
    );
}

#[test]
fn the_sign_verify_pair_graph_returns_is_one_certificate_not_two() {
    // `addTokenSigningCertificate` writes TWO keyCredentials entries sharing
    // one customKeyIdentifier. Listing both would show every certificate
    // twice and make a one-certificate app look mid-rollover.
    let roll = build_rollover(
        &sp_with(
            Some(A_HEX),
            vec![
                cred("k1", A_B64, "2027-01-01T00:00:00Z", "Sign"),
                cred("k2", A_B64, "2027-01-01T00:00:00Z", "Verify"),
            ],
        ),
        "sp-1",
        "tid",
        CloudEnvironment::Commercial,
        now(),
    );
    assert_eq!(roll.certs.len(), 1);
    assert_eq!(roll.phase, RolloverPhase::Steady);
}

#[test]
fn rollover_matches_the_preferred_thumbprint_case_insensitively_and_sorts_newest_first() {
    // Graph reports customKeyIdentifier uppercase; the preferred field can
    // differ in case. A case-sensitive match would show NO active
    // certificate and read as a broken app.
    let roll = build_rollover(
        &sp_with(
            // Lower-case preferred value: Entra is inconsistent about case.
            Some(&B_HEX.to_ascii_lowercase()),
            vec![
                cred("k1", A_B64, "2026-06-01T00:00:00Z", "Verify"),
                cred("k2", B_B64, "2029-01-01T00:00:00Z", "Verify"),
            ],
        ),
        "sp-1",
        "tid",
        CloudEnvironment::Commercial,
        now(),
    );
    assert_eq!(roll.certs[0].thumbprint, B_HEX, "newest first");
    assert!(roll.certs[0].is_active);
    assert_eq!(roll.certs[0].status, CertStatus::Active);
    // The nomination is canonical too, so the expiry board's Thumbprint
    // column shows the same upper-case value as the SSO tab.
    assert_eq!(roll.active_thumbprint.as_deref(), Some(B_HEX));
    // The metadata URL is the app's own, so the panel can link it directly.
    assert!(roll.federation_metadata_url.ends_with("appid=app-1"));
}

#[test]
fn the_preferred_thumbprint_is_upper_cased_but_a_malformed_one_is_kept_verbatim() {
    // Lower-case hex through the SSO tab's read: canonical upper case.
    let sp = serde_json::json!({
        "appId": "app-1",
        "preferredTokenSigningKeyThumbprint": A_HEX.to_ascii_lowercase(),
        "keyCredentials": [ cred("k1", A_B64, "2030-06-01T00:00:00Z", "Verify") ],
    });
    let (_, _, thumbprint, expiry, _) = extract_sp_sso_fields(&sp);
    assert_eq!(thumbprint.as_deref(), Some(A_HEX));
    assert_eq!(expiry.as_deref(), Some("2030-06-01T00:00:00Z"));

    // A nomination that is not a hex thumbprint stays visible as-is:
    // `canonical` would read "ABCD" as base64 and invent a different value.
    for bad in ["ABCD", "not-a-thumbprint"] {
        let roll = build_rollover(
            &sp_with(
                Some(bad),
                vec![cred("k1", A_B64, "2029-01-01T00:00:00Z", "Verify")],
            ),
            "sp-1",
            "tid",
            CloudEnvironment::Commercial,
            now(),
        );
        assert_eq!(roll.active_thumbprint.as_deref(), Some(bad));
        assert!(roll.certs.iter().all(|c| !c.is_active), "{bad}");
        let (_, _, thumbprint, _, _) = extract_sp_sso_fields(&sp_with(Some(bad), vec![]));
        assert_eq!(thumbprint.as_deref(), Some(bad));
    }
}

#[test]
fn the_owner_summary_follows_the_saved_mode() {
    let cfg = |mode: Option<&str>| SsoConfigDto {
        object_id: "obj-1".into(),
        service_principal_id: "sp-1".into(),
        app_id: "app-1".into(),
        sso_mode: mode.map(str::to_string),
        entity_id: Some("https://app/saml".into()),
        reply_urls: vec!["https://app/acs".into(), "https://app/acs2".into()],
        redirect_uris: vec!["https://app/acs".into(), "https://app/acs2".into()],
        spa_redirect_uris: vec!["https://app/spa".into()],
        signing_cert_thumbprint: Some(A_HEX.into()),
        claims_policy_id: Some("pol-1".into()),
        ..Default::default()
    };

    match build_sso_summary(CloudEnvironment::Commercial, "tid", &cfg(Some("saml"))) {
        Some(SsoSummary::Saml(s)) => {
            assert!(s.login_url.ends_with("/tid/saml2"), "{}", s.login_url);
            assert!(
                s.federation_metadata_url.ends_with("appid=app-1"),
                "{}",
                s.federation_metadata_url
            );
            assert_eq!(s.sp_entity_id, "https://app/saml");
            assert_eq!(s.reply_url, "https://app/acs");
            assert_eq!(s.signing_cert_base64, None);
            assert_eq!(s.signing_cert_thumbprint.as_deref(), Some(A_HEX));
            assert_eq!(s.claims_policy_id.as_deref(), Some("pol-1"));
            assert!(s.warnings.is_empty());
        }
        other => panic!("a SAML app must get a SAML summary, got {other:?}"),
    }
    match build_sso_summary(CloudEnvironment::Commercial, "tid", &cfg(Some("oidc"))) {
        Some(SsoSummary::Oidc(s)) => {
            assert!(s.authority.ends_with("/tid/v2.0"), "{}", s.authority);
            assert_eq!(s.client_id, "app-1");
            assert_eq!(s.tenant_id, "tid");
            assert_eq!(s.redirect_uris.len(), 2);
            assert_eq!(s.client_secret, None);
        }
        other => panic!("an OIDC app must get an OIDC summary, got {other:?}"),
    }
    for mode in [Some("password"), Some("SAML"), None] {
        assert!(
            build_sso_summary(CloudEnvironment::Commercial, "tid", &cfg(mode)).is_none(),
            "{mode:?}"
        );
    }
    // The URLs follow the configured cloud.
    match build_sso_summary(CloudEnvironment::UsGov, "tid", &cfg(Some("saml"))) {
        Some(SsoSummary::Saml(s)) => {
            assert_eq!(s.login_url, "https://login.microsoftonline.us/tid/saml2");
        }
        other => panic!("{other:?}"),
    }
    match build_sso_summary(CloudEnvironment::UsGov, "tid", &cfg(Some("oidc"))) {
        Some(SsoSummary::Oidc(s)) => {
            assert_eq!(s.authority, "https://login.microsoftonline.us/tid/v2.0");
        }
        other => panic!("{other:?}"),
    }
}

/// A hand-built active cert for the [`sso_cert_status`] table below.
fn active_cert(days: Option<i64>, status: CertStatus) -> azapptoolkit_dto::sso::SigningCertDto {
    azapptoolkit_dto::sso::SigningCertDto {
        key_id: "k1".to_string(),
        thumbprint: A_HEX.to_string(),
        display_name: None,
        start_date_time: None,
        end_date_time: None,
        is_active: true,
        days_to_expiry: days,
        status,
    }
}

#[test]
fn an_unreadable_expiry_is_unknown_not_healthy() {
    use azapptoolkit_core::audit::CredentialStatus;
    // A certificate whose expiry can't be resolved must never read as
    // Active: on an expiry board, "we couldn't tell" and "it's fine" have
    // opposite consequences, and Unknown is what sorts it out of the
    // all-clear.
    assert_eq!(sso_cert_status(None), CredentialStatus::Unknown);
    assert_eq!(
        sso_cert_status(Some(&active_cert(None, CertStatus::Active))),
        CredentialStatus::Unknown
    );
    assert_eq!(
        sso_cert_status(Some(&active_cert(Some(-1), CertStatus::Expired))),
        CredentialStatus::Expired
    );
    // The threshold matches the audit's credential rules exactly, so
    // "Expiring Soon" means the same number of days on both boards.
    assert_eq!(
        sso_cert_status(Some(&active_cert(Some(30), CertStatus::Active))),
        CredentialStatus::ExpiringSoon
    );
    assert_eq!(
        sso_cert_status(Some(&active_cert(Some(0), CertStatus::Active))),
        CredentialStatus::ExpiringSoon
    );
    assert_eq!(
        sso_cert_status(Some(&active_cert(Some(31), CertStatus::Active))),
        CredentialStatus::Active
    );
    // The timestamp verdict wins over the day count: a certificate whose
    // `CertStatus` says Expired is Expired on the board even when the day
    // count reads 0 (the expired-at-this-exact-second edge).
    assert_eq!(
        sso_cert_status(Some(&active_cert(Some(0), CertStatus::Expired))),
        CredentialStatus::Expired
    );
}

#[test]
fn a_certificate_expired_less_than_a_day_ago_still_reads_expired() {
    // `now()` is 2026-01-01T00:00:00Z; this cert expired 12 hours earlier.
    // Truncating division called this `0` days — the same number as a cert
    // *expiring* in 12 hours — so the board showed "0d left", the Expired
    // facet missed it, and the SSO tab contradicted itself in a single row
    // (badge "Expired", text "0 days left").
    let roll = build_rollover(
        &sp_with(
            Some(A_HEX),
            vec![cred("k1", A_B64, "2025-12-31T12:00:00Z", "Verify")],
        ),
        "sp-1",
        "tid",
        CloudEnvironment::Commercial,
        now(),
    );
    let active = roll.certs.iter().find(|c| c.is_active);
    let c = active.unwrap();
    assert_eq!(c.status, CertStatus::Expired);
    assert_eq!(c.days_to_expiry, Some(-1), "floored, not truncated to 0");
    assert_eq!(
        sso_cert_status(active),
        azapptoolkit_core::audit::CredentialStatus::Expired
    );

    // And the mirror case: expiring in 12 hours is `0d left`, not expired.
    let roll = build_rollover(
        &sp_with(
            Some(A_HEX),
            vec![cred("k1", A_B64, "2026-01-01T12:00:00Z", "Verify")],
        ),
        "sp-1",
        "tid",
        CloudEnvironment::Commercial,
        now(),
    );
    let active = roll.certs.iter().find(|c| c.is_active);
    assert_eq!(active.unwrap().days_to_expiry, Some(0));
    assert_eq!(active.unwrap().status, CertStatus::Active);
    assert_eq!(
        sso_cert_status(active),
        azapptoolkit_core::audit::CredentialStatus::ExpiringSoon
    );
}

#[test]
fn the_expiry_board_csv_guards_tenant_controlled_display_names() {
    use azapptoolkit_core::audit::CredentialStatus;
    // Display names are tenant-controllable, so a name starting with `=`
    // must not reach a spreadsheet as a formula.
    let rows = vec![SsoCertificateRowDto {
        service_principal_id: "sp-1".into(),
        app_id: "app-1".into(),
        display_name: "=cmd|'/c calc'!A1".into(),
        thumbprint: Some("AAA".into()),
        end_date_time: Some("2027-01-01T00:00:00Z".into()),
        days_to_expiry: Some(12),
        status: CredentialStatus::ExpiringSoon,
        phase: azapptoolkit_dto::sso::RolloverPhase::Staged,
        has_staged_replacement: true,
        notification_emails_configured: false,
    }];
    let csv = sso_certificates_to_csv(&rows);
    assert!(csv.starts_with("Application,AppId,ServicePrincipalId,"));
    assert!(
        !csv.contains("\n=cmd"),
        "a formula-leading display name reached the CSV unguarded: {csv}"
    );
    // The two columns that make a row actionable survive the round trip.
    assert!(csv.contains(",yes,no\n"), "staged/notified columns: {csv}");
}

#[test]
fn parse_signing_certs_reads_signing_keys_and_skips_encryption_ones() {
    let xml = r#"
        <EntityDescriptor>
          <IDPSSODescriptor>
            <KeyDescriptor use="signing">
              <KeyInfo><X509Data><X509Certificate>MIIC
              AAAA</X509Certificate></X509Data></KeyInfo>
            </KeyDescriptor>
            <KeyDescriptor use="encryption">
              <KeyInfo><X509Data><X509Certificate>SHOULDNOTAPPEAR</X509Certificate></X509Data></KeyInfo>
            </KeyDescriptor>
            <KeyDescriptor use="signing">
              <KeyInfo><X509Data><X509Certificate>MIICBBBB</X509Certificate></X509Data></KeyInfo>
            </KeyDescriptor>
          </IDPSSODescriptor>
        </EntityDescriptor>"#;
    let certs = parse_signing_certs(xml);
    // Whitespace inside the base64 body is stripped, encryption keys skipped.
    assert_eq!(certs, vec!["MIICAAAA".to_string(), "MIICBBBB".to_string()]);
    // Two published signing keys is the precondition for an app that polls
    // metadata to discover a staged certificate before it goes live.
    assert_eq!(certs.len(), 2);
}

#[test]
fn parse_signing_certs_counts_a_use_less_descriptor_and_dedupes() {
    // Per the SAML metadata spec a KeyDescriptor with no `use` is valid for
    // signing, so it counts. The same body repeated is still one key.
    let xml = "<KeyDescriptor><X509Certificate>DUP</X509Certificate></KeyDescriptor>\
               <KeyDescriptor use=\"signing\"><X509Certificate>DUP</X509Certificate></KeyDescriptor>";
    assert_eq!(parse_signing_certs(xml), vec!["DUP".to_string()]);
}

#[test]
fn parse_signing_certs_reads_namespace_prefixed_metadata() {
    // The shape real SAML metadata actually has — Microsoft's own federation
    // metadata is namespace-prefixed. Matching the bare `<KeyDescriptor`
    // literal returned ZERO certificates for every such document, and
    // `probe_federation_metadata` reported that as "0 published",
    // indistinguishable from an app that genuinely publishes none.
    let xml = r#"
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
          <md:IDPSSODescriptor>
            <md:KeyDescriptor use="signing">
              <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICAAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
            </md:KeyDescriptor>
            <md:KeyDescriptor use="encryption">
              <ds:KeyInfo><ds:X509Data><ds:X509Certificate>SHOULDNOTAPPEAR</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
            </md:KeyDescriptor>
            <md:KeyDescriptor use="signing">
              <ds:X509Certificate>MIICBBBB</ds:X509Certificate>
            </md:KeyDescriptor>
          </md:IDPSSODescriptor>
        </md:EntityDescriptor>"#;
    assert_eq!(
        parse_signing_certs(xml),
        vec!["MIICAAAA".to_string(), "MIICBBBB".to_string()]
    );
}

#[test]
fn parse_signing_certs_attributes_each_key_to_its_own_descriptor() {
    // The encryption descriptor sits BETWEEN two signing ones, so a parser
    // that does not bound each block would leak its key into a neighbour.
    let xml = "<KeyDescriptor use=\"signing\"><X509Certificate>A</X509Certificate></KeyDescriptor>\
               <KeyDescriptor use=\"encryption\"><X509Certificate>E</X509Certificate></KeyDescriptor>\
               <KeyDescriptor use=\"signing\"><X509Certificate>B</X509Certificate></KeyDescriptor>";
    assert_eq!(
        parse_signing_certs(xml),
        vec!["A".to_string(), "B".to_string()]
    );
    // And a similarly-named element must not match.
    assert!(parse_signing_certs("<X509CertificateChain>NO</X509CertificateChain>").is_empty());
}

#[test]
fn parse_signing_certs_never_fabricates_a_match_from_junk() {
    // A malformed or empty document yields nothing — the probe reports "0
    // published" next to the HTTP status rather than inventing a key.
    assert!(parse_signing_certs("").is_empty());
    assert!(parse_signing_certs("<html>404</html>").is_empty());
    // An unterminated element is not a certificate.
    assert!(parse_signing_certs("<KeyDescriptor><X509Certificate>oops").is_empty());
}

#[test]
fn extract_sp_sso_fields_absent_fields_default_empty() {
    // A minimal SP (no SSO mode / thumbprint / creds / emails) yields all
    // `None`/empty — no expiry probe fires without a thumbprint.
    let sp = serde_json::json!({ "appId": "app-only" });
    let (app_id, sso_mode, thumbprint, expiry, emails) = extract_sp_sso_fields(&sp);
    assert_eq!(app_id, "app-only");
    assert_eq!(sso_mode, None);
    assert_eq!(thumbprint, None);
    assert_eq!(expiry, None);
    assert!(emails.is_empty());
}

// ---------------- rollover guards ----------------

fn roll(preferred: &str, creds: Vec<serde_json::Value>) -> SigningCertRolloverDto {
    build_rollover(
        &sp_with(Some(preferred), creds),
        "sp-1",
        "tid",
        CloudEnvironment::Commercial,
        now(),
    )
}

/// A preferred and valid, B newer and not yet nominated.
fn staged() -> SigningCertRolloverDto {
    roll(
        A_HEX,
        vec![
            cred("k1", A_B64, "2026-06-01T00:00:00Z", "Verify"),
            cred("k2", B_B64, "2029-01-01T00:00:00Z", "Verify"),
        ],
    )
}

/// A still nominated but expired; B valid.
fn expired_active() -> SigningCertRolloverDto {
    roll(
        A_HEX,
        vec![
            cred("k1", A_B64, "2025-06-01T00:00:00Z", "Verify"),
            cred("k2", B_B64, "2029-01-01T00:00:00Z", "Verify"),
        ],
    )
}

/// B activated, A still valid — the rollback.
fn pending_retire() -> SigningCertRolloverDto {
    roll(
        B_HEX,
        vec![
            cred("k1", A_B64, "2026-06-01T00:00:00Z", "Verify"),
            cred("k2", B_B64, "2029-01-01T00:00:00Z", "Verify"),
        ],
    )
}

/// B nominated, A expired and no longer nominated.
fn expired_leftover() -> SigningCertRolloverDto {
    roll(
        B_HEX,
        vec![
            cred("k1", A_B64, "2025-06-01T00:00:00Z", "Verify"),
            cred("k2", B_B64, "2029-01-01T00:00:00Z", "Verify"),
        ],
    )
}

#[test]
fn retire_guard_refuses_the_active_the_staged_and_a_missing_certificate() {
    let r = staged();
    let err = retire_target(&r, "k1").expect_err("the active cert signs today");
    assert_eq!(err.code, "cert_is_active");
    assert!(
        err.message.contains("signing assertions right now"),
        "{}",
        err.message
    );
    let err = retire_target(&r, "k2").expect_err("the staged cert is a pending rollover");
    assert_eq!(err.code, "cert_is_staged");
    let err = retire_target(&r, "nope").expect_err("a vanished cert");
    assert_eq!(err.code, "cert_not_found");

    // Expired but still nominated: same code, the honest message.
    let r = expired_active();
    let err = retire_target(&r, "k1").expect_err("the nomination would dangle");
    assert_eq!(err.code, "cert_is_active");
    assert!(
        err.message.contains("has expired but is still nominated"),
        "{}",
        err.message
    );

    // The superseded certificate after activation is what retire is for.
    let r = pending_retire();
    assert_eq!(retire_target(&r, "k1").expect("superseded").key_id, "k1");

    // An expired, non-nominated certificate passes — the per-row Remove.
    let r = expired_leftover();
    assert_eq!(
        retire_target(&r, "k1").expect("expired leftover").key_id,
        "k1"
    );
}

#[test]
fn activation_guard_refuses_missing_and_expired_and_is_a_no_op_when_active() {
    let r = staged();
    let hit = activation_target(&r, B_HEX).expect("staged cert activates");
    assert_eq!(hit.map(|c| c.key_id.as_str()), Some("k2"));
    let hit = activation_target(&r, &B_HEX.to_ascii_lowercase())
        .expect("the thumbprint match is case-insensitive");
    assert_eq!(hit.map(|c| c.key_id.as_str()), Some("k2"));
    // Idempotent: activating the active key is a no-op, not an error.
    assert!(activation_target(&r, A_HEX).expect("no-op").is_none());
    let err = activation_target(&r, "DEADBEEF").expect_err("not on the SP");
    assert_eq!(err.code, "cert_not_staged");

    // Revert: the superseded certificate can be re-nominated.
    let r = pending_retire();
    let hit = activation_target(&r, A_HEX).expect("revert");
    assert_eq!(hit.map(|c| c.key_id.as_str()), Some("k1"));

    // Expired wins over the "already active" no-op.
    let err = activation_target(&expired_active(), A_HEX).expect_err("expired + nominated");
    assert_eq!(err.code, "cert_expired");
    let err = activation_target(&expired_leftover(), A_HEX).expect_err("expired");
    assert_eq!(err.code, "cert_expired");
}

/// The admin center's custom claims policy is a global-cloud-only beta API.
/// A national cloud must not ask for it: the call can never succeed there, and
/// a failed claims read turns claims editing off.
#[test]
fn the_admin_center_claims_read_is_global_cloud_only() {
    use azapptoolkit_core::cloud::CloudEnvironment;
    assert!(super::config::portal_claims_readable(
        CloudEnvironment::Commercial
    ));
    for cloud in [
        CloudEnvironment::UsGov,
        CloudEnvironment::UsGovDod,
        CloudEnvironment::China,
    ] {
        assert!(!super::config::portal_claims_readable(cloud), "{cloud:?}");
    }
}
