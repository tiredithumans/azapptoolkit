//! Every path that mints an authentication trust validates its inputs.
//!
//! A federated identity credential lets an external identity obtain tokens as
//! the application **with no secret and no expiry**, and Graph does not check
//! it: Microsoft documents that a wrong issuer or subject "is created
//! successfully without error", failing only later at token exchange. So the
//! validation is entirely ours, and a call site that skips it is a silent
//! widening — exactly the shape of the gap this rule was written for, where the
//! interactive editor and the DR restore had drifted apart and only the restore
//! path wrote a trust straight from an untrusted file.
//!
//! Derived from the source tree, not from a list: a third call site added later
//! is caught because it *constructs the request*, not because someone
//! remembered to add it here.

use super::sources::command_modules;

/// The two ways a trust reaches Graph. `Patch` is the update path — it rewrites
/// issuer/subject on an existing credential, which repoints the trust just as
/// completely as creating one.
const TRUST_WRITES: [&str; 2] = ["FederatedCredentialRequest {", "FederatedCredentialPatch {"];

/// The single validator. `core::federation` owns the rules; a command may call
/// it directly or through a thin local wrapper, so the rule matches the name.
const VALIDATOR: &str = "validate_federated_credential";

#[test]
fn every_command_that_writes_a_federation_trust_validates_it_first() {
    let mut found = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    for (name, src) in command_modules() {
        for line in src.lines() {
            let trimmed = line.trim_start();
            // Doc comments legitimately name the types.
            if trimmed.starts_with("//") {
                continue;
            }
            if !TRUST_WRITES.iter().any(|w| trimmed.contains(w)) {
                continue;
            }
            found += 1;
            if !src.contains(VALIDATOR) {
                offenders.push(format!("{name} — {trimmed}"));
            }
        }
    }

    assert!(
        found >= 2,
        "found only {found} federation-trust write(s) in the command tree — the source walk or \
         the detector is broken, and a rule that scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "these modules write a federated identity credential without calling `{VALIDATOR}`.\n\
         A federated identity credential is a sign-in trust that needs no secret and never \
         expires, and Graph accepts a bad one without error — the check has to happen here, on \
         every path, or a value from an untrusted backup file becomes standing access:\n  {}",
        offenders.join("\n  ")
    );
}

/// Every command that writes a redirect URI validates it first.
///
/// The sibling of the federation rule above, and it exists for the same reason:
/// the interactive authentication editor and the four SSO sites ran
/// `core::redirect` before their PATCH, and the DR restore — whose input is an
/// untrusted *file* — did not. A reply URL is where auth codes are delivered,
/// so a manifest carrying `https://*.evil.example/cb` or a plaintext
/// `http://attacker.example/cb` created the app in the operator's tenant with
/// those URLs and the codes could be collected by the attacker's host.
///
/// Derived from the source tree, not a list: any future command that builds an
/// authentication patch is caught because it *constructs the patch*.
#[test]
fn every_command_that_writes_a_redirect_uri_validates_it_first() {
    /// The patch types that carry reply URLs to Graph.
    const REDIRECT_WRITES: [&str; 3] = [
        "ApplicationWebPatch {",
        "ApplicationSpaPatch {",
        "ApplicationPublicClientPatch {",
    ];
    /// `core::redirect` owns the rules; a command may call either entry point,
    /// directly or through a thin local wrapper, so the rule matches the stem.
    const VALIDATOR: &str = "validate_redirect_uri";

    let mut found = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    for (name, src) in command_modules() {
        for line in src.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if !REDIRECT_WRITES.iter().any(|w| trimmed.contains(w)) {
                continue;
            }
            found += 1;
            if !src.contains(VALIDATOR) {
                offenders.push(format!("{name} — {trimmed}"));
            }
        }
    }

    assert!(
        found >= 2,
        "only {found} redirect-URI write(s) found — the source walk is broken, and a rule that \
         scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "command(s) writing a redirect URI without validating it: {offenders:#?}\n\
         A reply URL decides where auth codes are delivered. Run \
         `core::redirect::validate_redirect_uri(s)` over every list before the patch and report \
         each rejection, the way `restore.rs::checked_uris` does."
    );
}

/// Every `with_retries` call site states its [`RetryClass`] explicitly.
///
/// The loop re-invokes the caller's whole closure, request send included, so a
/// non-idempotent write replayed after a connection reset or a 5xx may commit
/// twice — `POST .../addPassword` left registrations holding several client
/// secrets, only the last of which the operator ever saw in plaintext.
///
/// The class is a required parameter, so the compiler already forces *an*
/// answer. What it cannot force is that the answer was derived rather than
/// guessed: this rule keeps a verb-dispatching transport from hard-coding
/// `Idempotent` just to compile. Such a transport must route through a
/// `retry_class_for` helper; only a call site whose verb is a literal at that
/// line may state the class directly.
#[test]
fn every_retry_call_site_derives_its_idempotency_class() {
    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../crates")
        .canonicalize()
        .expect("crates dir");
    let mut files = Vec::new();
    rust_files(&crates, &mut files);
    assert!(!files.is_empty(), "the source walk found no crate sources");

    let mut offenders: Vec<String> = Vec::new();
    let mut found = 0usize;
    for src in files {
        let text = std::fs::read_to_string(&src).expect("read source");
        // The definition itself, not a call site.
        if src.ends_with("http_retry.rs") || !text.contains("with_retries(") {
            continue;
        }
        found += 1;
        let derived = text.contains("retry_class_for(");
        let pinned_to_a_literal_verb =
            text.contains("RetryClass::Idempotent") && text.contains("Method::");
        if !derived && !pinned_to_a_literal_verb {
            offenders.push(
                src.strip_prefix(&crates)
                    .unwrap_or(&src)
                    .display()
                    .to_string(),
            );
        }
    }

    assert!(
        found >= 3,
        "only {found} file(s) call with_retries — the source walk is broken, and a rule that \
         scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "with_retries call site(s) that neither derive their class from the verb nor pin it to a \
         literal one: {offenders:#?}\n\
         Route the transport through a `retry_class_for(&method)` helper so a POST/PATCH cannot \
         silently inherit a GET's replay policy."
    );
}
