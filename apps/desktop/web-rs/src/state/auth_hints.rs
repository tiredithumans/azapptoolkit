//! What to do about a failed interactive Entra round trip: the sign-in card's
//! hint line (`views::sign_in`) and the recovery lever re-pushed when a
//! re-authentication, consent or step-up itself fails (`Session`'s
//! `reauth_in_place`, `spawn_scope_consent`, `spawn_scope_step_up`). One table,
//! so the two surfaces never tell an operator two different things about the
//! same failure — and its wording names no control only one of them has.

use azapptoolkit_dto::UiError;

/// One actionable recovery step per `UiError.code` (codes from
/// `azapptoolkit-dto`'s `AuthError` mapping), refined by the `AADSTSnnnnn` code
/// Entra embeds in the message whenever it sent one.
///
/// The code-level arms below are broad by necessity: `token_exchange` alone
/// covers every rejection Entra can hand back at the exchange — wrong tenant,
/// unknown client id, unregistered redirect URI, a Conditional Access block.
/// The AADSTS number is the part that says *which*, and the app was already
/// holding it: `azapptoolkit-auth`'s `redacted_aad_error` deliberately keeps
/// that number while dropping the tenant/user GUIDs, correlation ids and client
/// IPs around it. Until now the operator read the number on screen and had to
/// leave the app to search it.
pub fn recovery_hint(code: &str, message: &str) -> &'static str {
    if let Some(specific) = aadsts_hint(message) {
        return specific;
    }
    match code {
        "network" => "Check your network connection, then retry.",
        // Not Entra's answer at all: a proxy, firewall or TLS inspection
        // answered in its place (a block page, a portal, a refused redirect).
        "unexpected_responder" => {
            "Something other than Entra ID answered the sign-in — a proxy, firewall \
             or TLS inspection. Allow your cloud's login host \
             (login.microsoftonline.com), then retry."
        }
        // Entra (or the path to it) throttled or failed through the retry
        // budget: nothing to fix in the configuration.
        "service_unavailable" => {
            "Entra ID is busy or temporarily unavailable — wait a minute, then retry."
        }
        "keyring" => {
            "The OS credential store couldn't be reached — unlock your \
             keychain/credential manager, then retry."
        }
        // No store at all — nothing to unlock. Registration is memoised for the
        // process, so a provider started afterwards needs a restart.
        "keyring_unavailable" => {
            "No OS credential store is available, so azapptoolkit can't keep your \
             sign-in. On Linux it needs a running Secret Service (GNOME Keyring or \
             KWallet) in your desktop session — start one, then restart azapptoolkit."
        }
        "authorization" | "consent_required" => {
            "The sign-in was declined. An administrator may need to grant the app \
             consent in this tenant before you can sign in."
        }
        // Also the app's own checks on the answer (a nonce or tenant mismatch,
        // a malformed id token), so it does not claim Entra rejected anything.
        "token_exchange" => {
            "The token exchange failed — check the client and tenant IDs (Change \
             above), then retry."
        }
        // The redirect listener, before any browser: a port the OS or security
        // software refused.
        "loopback" => {
            "Couldn't open the local sign-in listener on 127.0.0.1 — check security \
             software, then retry."
        }
        // A closed tab, a Cancel at Entra, or the 5-minute redirect wait
        // (`REDIRECT_WAIT`) running out — the backend can't tell them apart.
        "cancelled" => {
            "The browser sign-in was closed, or not finished within 5 minutes — retry \
             when ready."
        }
        _ => "Check your network, then retry.",
    }
}

/// The `AADSTSnnnnn` codes an operator actually hits at sign-in, each translated
/// into the step that clears it.
///
/// Deliberately a short list. A confidently wrong instruction is worse than the
/// generic one, so anything not listed here falls back to the code-level hint
/// rather than guessing — and the raw code stays on the error line above the
/// hint either way, for anyone filing a ticket.
fn aadsts_hint(message: &str) -> Option<&'static str> {
    let idx = message.find("AADSTS")?;
    let digits: String = message[idx + "AADSTS".len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    Some(match digits.as_str() {
        // The two "you are pointed at the wrong directory" shapes. A well-formed
        // but wrong tenant GUID fails exactly like this, so the hint points at
        // the card's own Change link, which reopens the config form holding
        // both ids — Settings is behind the sign-in that just failed.
        "90002" | "900023" => {
            "That tenant doesn't resolve. Select Change above to correct the tenant \
             ID — a well-formed but wrong GUID fails exactly this way."
        }
        "700016" | "700054" => {
            "No app registration with this client ID exists in the configured \
             tenant. Select Change above to check the client ID, or that you're \
             pointed at the right tenant."
        }
        // Right tenant, wrong account.
        "50020" | "50034" | "500011" => {
            "Your account isn't in this tenant (or is a guest without access here). \
             Sign in with an account from the configured tenant."
        }
        "50105" => {
            "Your account isn't assigned to this application. An administrator has \
             to assign you, or turn off the assignment requirement on it."
        }
        "50126" => "That username or password was rejected — retry, or reset your password.",
        // Consent. Distinct from a decline: one needs an admin, the other needs
        // the same operator to accept the prompt.
        "65001" => {
            "An administrator needs to grant this app consent in the tenant before \
             anyone can sign in to it."
        }
        "65004" => "Consent was declined. Retry and accept the permissions prompt to continue.",
        // Policy interrupts: retrying alone will not clear a CA block.
        "53003" => {
            "A Conditional Access policy blocked this sign-in. You may need a \
             compliant or joined device, or your identity admin has to allow this \
             app in the policy."
        }
        "50076" | "50079" | "50158" => {
            "Entra needs additional verification. Retry and complete the \
             multi-factor prompt."
        }
        // What the app sends (`http://127.0.0.1:{port}`) and what the README
        // registers: Entra matches the loopback host, not `localhost`.
        "50011" => {
            "Entra rejected the redirect URI. This build's app registration needs a \
             loopback (http://127.0.0.1) redirect URI under Mobile and desktop \
             applications."
        }
        _ => return None,
    })
}

/// The message of a recovery lever re-pushed because the lever itself failed:
/// `prefix` ("Couldn't re-authenticate"), then the step that clears `e`.
///
/// [`recovery_hint`], except where it would point at the configured ids: the
/// session was signed in with those, so an `authorization` or `token_exchange`
/// failure without a known AADSTS code is something else (the round trip
/// completed as a different account, a nonce mismatch) and its own message —
/// shown before this change, never logged — says what.
pub(crate) fn lever_failure_message(prefix: &str, e: &UiError) -> String {
    let detail = match e.code.as_str() {
        "authorization" | "token_exchange" if aadsts_hint(&e.message).is_none() => {
            e.message.as_str()
        }
        code => recovery_hint(code, &e.message),
    };
    format!("{prefix} — {detail}")
}

#[cfg(test)]
mod tests {
    use super::{aadsts_hint, lever_failure_message, recovery_hint};
    use azapptoolkit_dto::UiError;

    #[test]
    fn an_aadsts_code_beats_the_generic_code_hint() {
        // `token_exchange` is the catch-all for every exchange rejection, so
        // without the number it can only say "verify the ids". With it, the
        // hint names the actual cause.
        let hint = recovery_hint("token_exchange", "invalid_request (AADSTS90002)");
        assert!(hint.contains("tenant doesn't resolve"), "{hint}");
    }

    #[test]
    fn a_wrong_id_hint_points_at_the_cards_change_link_not_settings() {
        // These render on the sign-in card, where Settings is unreachable (it is
        // behind the sign-in that failed); the card's Change link is the way to
        // the ids.
        for code in ["90002", "900023", "700016", "700054"] {
            let hint = recovery_hint("token_exchange", &format!("invalid_request (AADSTS{code})"));
            assert!(hint.contains("Change"), "AADSTS{code}: {hint}");
            assert!(!hint.contains("Settings"), "AADSTS{code}: {hint}");
        }
    }

    #[test]
    fn an_abandoned_browser_sign_in_says_so() {
        // The backend produces `cancelled` for a closed tab, a Cancel at Entra,
        // AND the 5-minute redirect wait running out — so the hint covers the
        // timeout too, instead of telling an operator who was mid-MFA that they
        // closed the browser.
        assert_eq!(
            recovery_hint(
                "cancelled",
                "sign-in was cancelled or not completed in the browser"
            ),
            "The browser sign-in was closed, or not finished within 5 minutes — retry when ready.",
        );
    }

    #[test]
    fn a_failed_exchange_does_not_claim_entra_rejected_it() {
        // `token_exchange` also carries the app's own checks (a nonce or tenant
        // mismatch), so the hint says what failed, not who.
        let hint = recovery_hint(
            "token_exchange",
            "token exchange failed: id_token nonce mismatch",
        );
        assert!(!hint.contains("rejected"), "{hint}");
        assert!(hint.contains("client and tenant IDs"), "{hint}");
    }

    #[test]
    fn a_listener_failure_is_not_blamed_on_the_network() {
        let hint = recovery_hint("loopback", "loopback listener failed: Address in use");
        assert!(hint.contains("127.0.0.1"), "{hint}");
        assert!(hint.contains("security software"), "{hint}");
        assert_ne!(hint, recovery_hint("network", "x"));
    }

    #[test]
    fn a_foreign_responder_names_the_proxy_and_the_login_host() {
        let hint = recovery_hint(
            "unexpected_responder",
            "something other than Entra ID answered the token request (HTTP 403, html body)",
        );
        assert!(hint.contains("proxy"), "{hint}");
        assert!(hint.contains("login.microsoftonline.com"), "{hint}");
        let busy = recovery_hint("service_unavailable", "HTTP 503");
        assert!(busy.contains("wait a minute"), "{busy}");
    }

    #[test]
    fn the_redirect_uri_hint_names_the_loopback_ip_the_app_sends() {
        let hint = aadsts_hint("invalid_request (AADSTS50011)").unwrap();
        assert!(hint.contains("http://127.0.0.1"), "{hint}");
        assert!(!hint.contains("localhost"), "{hint}");
    }

    #[test]
    fn an_unmapped_or_absent_code_falls_back_rather_than_guessing() {
        assert!(aadsts_hint("invalid_request (AADSTS99999)").is_none());
        assert!(aadsts_hint("invalid_request").is_none());
        // "AADSTS" with no digits after it yields no code (mirrors the
        // extractor in azapptoolkit-auth's `wire.rs`).
        assert!(aadsts_hint("AADSTS: malformed").is_none());
        assert_eq!(
            recovery_hint("network", "connection refused"),
            "Check your network connection, then retry.",
        );
    }

    #[test]
    fn no_hint_names_a_control_only_the_sign_in_card_has() {
        // The table also feeds a failed lever's toast, whose button is
        // Re-authenticate / Grant consent / Verify identity — not Sign in.
        for code in [
            "network",
            "unexpected_responder",
            "service_unavailable",
            "keyring",
            "keyring_unavailable",
            "loopback",
            "cancelled",
            "something_new",
        ] {
            let hint = recovery_hint(code, "x");
            assert!(!hint.contains("Sign in"), "{code}: {hint}");
        }
        for aadsts in ["65004", "50076", "50079", "50158"] {
            let hint = aadsts_hint(&format!("x (AADSTS{aadsts})")).unwrap();
            assert!(!hint.contains("Sign in"), "AADSTS{aadsts}: {hint}");
        }
    }

    #[test]
    fn a_missing_credential_store_is_not_told_to_unlock_it() {
        let hint = recovery_hint(
            "keyring_unavailable",
            "no OS credential store is available: no session bus",
        );
        assert!(hint.contains("Secret Service"), "{hint}");
        assert!(hint.contains("restart"), "{hint}");
        assert!(!hint.contains("unlock"), "{hint}");
    }

    #[test]
    fn consent_needed_and_consent_declined_do_not_share_a_hint() {
        // Load-bearing split: 65001 needs an administrator, 65004 needs this
        // same operator to accept the prompt. One hint for both sends half the
        // people to the wrong place.
        let needed = aadsts_hint("invalid_grant (AADSTS65001)").unwrap();
        let declined = aadsts_hint("invalid_grant (AADSTS65004)").unwrap();
        assert!(needed.contains("administrator"), "{needed}");
        assert!(
            declined.contains("accept the permissions prompt"),
            "{declined}"
        );
        assert_ne!(needed, declined);
    }

    #[test]
    fn a_failed_lever_says_what_clears_it() {
        let cancelled = UiError::new(
            "cancelled",
            "sign-in was cancelled or not completed in the browser",
            false,
        );
        assert_eq!(
            lever_failure_message("Couldn't re-authenticate", &cancelled),
            "Couldn't re-authenticate — The browser sign-in was closed, or not finished \
             within 5 minutes — retry when ready.",
        );
        // An identity mismatch is not a config problem: its own message names
        // the fix, where the code-level hint would blame consent.
        let other_account = UiError::new(
            "authorization",
            "authorization request failed: re-authentication completed with a different \
             account — use Sign Out to switch",
            true,
        );
        let text = lever_failure_message("Couldn't re-authenticate", &other_account);
        assert!(text.contains("use Sign Out to switch"), "{text}");
        assert!(!text.contains("administrator"), "{text}");
        // A coded decline still gets its AADSTS step.
        let declined = UiError::new(
            "authorization",
            "authorization request failed: access_denied (AADSTS65004)",
            true,
        );
        let text = lever_failure_message("Couldn't grant consent", &declined);
        assert!(text.contains("accept the permissions prompt"), "{text}");
    }
}
