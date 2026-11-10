//! The random values an authorization-code flow needs: the CSRF `state`, the
//! OIDC `nonce`, and the PKCE verifier / S256 challenge pair (RFC 7636).
//!
//! These three types are everything this crate ever used from the `oauth2`
//! crate, which brought `rand` 0.8, `thiserror` 1 and `serde_path_to_error`
//! with it — second majors of crates the tree already had, on the sign-in
//! path. Randomness and SHA-256 come from `aws-lc-rs`, which rustls already
//! compiles in, and the verifier is wiped on drop (the `oauth2` one was not).

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

/// `len` bytes from the OS CSPRNG, base64url-encoded without padding.
fn random_urlsafe(len: usize) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new(vec![0u8; len]);
    // The system RNG failing is not a state to continue a sign-in from.
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("the operating system's random number generator is unavailable");
    Zeroizing::new(URL_SAFE_NO_PAD.encode(&*bytes))
}

/// An unguessable single-use value: the authorize request's `state` or `nonce`.
pub(crate) struct CsrfToken(String);

impl CsrfToken {
    /// 16 random bytes (128 bits), as 22 base64url characters.
    pub(crate) fn new_random() -> Self {
        Self::new_random_len(16)
    }

    pub(crate) fn new_random_len(bytes: u32) -> Self {
        Self(random_urlsafe(bytes as usize).to_string())
    }

    pub(crate) fn secret(&self) -> &String {
        &self.0
    }
}

/// The S256 `code_challenge` sent on the authorize request.
pub(crate) struct PkceCodeChallenge(String);

/// The `code_verifier` redeemed with the code. Wiped on drop.
pub(crate) struct PkceCodeVerifier(Zeroizing<String>);

impl PkceCodeChallenge {
    /// A fresh verifier (32 random bytes → 43 characters, inside RFC 7636's
    /// 43–128) and its challenge, `BASE64URL(SHA256(ASCII(verifier)))`.
    pub(crate) fn new_random_sha256() -> (Self, PkceCodeVerifier) {
        let verifier = random_urlsafe(32);
        (Self(challenge_for(&verifier)), PkceCodeVerifier(verifier))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl PkceCodeVerifier {
    pub(crate) fn into_secret(self) -> Zeroizing<String> {
        self.0
    }
}

fn challenge_for(verifier: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 appendix B's worked example.
    #[test]
    fn the_challenge_is_the_rfc_7636_s256_transform() {
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn values_are_fresh_urlsafe_and_the_documented_length() {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let verifier = verifier.into_secret();
        assert_eq!(verifier.len(), 43);
        assert_eq!(challenge.as_str(), challenge_for(&verifier));
        let (a, b) = (CsrfToken::new_random(), CsrfToken::new_random());
        assert_eq!(a.secret().len(), 22);
        assert_ne!(a.secret(), b.secret());
        let urlsafe = |s: &str| {
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        assert!(urlsafe(a.secret()) && urlsafe(&verifier) && urlsafe(challenge.as_str()));
    }
}
