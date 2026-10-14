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
//!
//! Checked **per function, with one helper level**, not per module. The first
//! form asked only whether the *module* named the validator, which is the
//! helper bleed `sources::commands` documents: `sso/mod.rs` and `restore.rs`
//! both contain `validate_redirect_uri`, so a new command in either that built
//! a patch straight from its input passed. [`unvalidated_writes`] holds the
//! write and the check to the same function, or to every in-module caller of
//! the helper the write sits in.

use super::sources::{balanced_block, command_modules, functions_in};

/// The two ways a trust reaches Graph. `Patch` is the update path — it rewrites
/// issuer/subject on an existing credential, which repoints the trust just as
/// completely as creating one.
const TRUST_WRITES: [&str; 2] = ["FederatedCredentialRequest {", "FederatedCredentialPatch {"];

/// The single federation validator. `core::federation` owns the rules; a
/// function may call it directly or through a thin local wrapper
/// (`check_federated_credential`), so the rule matches the name.
const FEDERATION_VALIDATOR: &str = "validate_federated_credential";

/// The patch types that carry reply URLs to Graph.
const REDIRECT_WRITES: [&str; 3] = [
    "ApplicationWebPatch {",
    "ApplicationSpaPatch {",
    "ApplicationPublicClientPatch {",
];

/// `core::redirect` owns the rules; a function may call either entry point
/// (`validate_redirect_uri` / `validate_redirect_uris`), directly or through a
/// thin local wrapper (`checked_uris`), so the rule matches the stem.
const REDIRECT_VALIDATOR: &str = "validate_redirect_uri";

/// `core::redirect::validate_logout_url` — the reply-URL rules plus https (or
/// loopback http) only. A function that checks only its reply URLs with
/// [`REDIRECT_VALIDATOR`] does not satisfy it: the stems differ on purpose.
const LOGOUT_VALIDATOR: &str = "validate_logout_url";

/// The one call that mints a SAML signing certificate.
const CERT_MINTS: [&str; 1] = [".add_token_signing_certificate("];

/// The one bound on a signing certificate's lifetime.
const CERT_LIFETIME_BOUND: &str = "resolve_cert_lifetime_days";

/// Whether `body` names `ident` with an identifier boundary before it —
/// `reconfigure(` is not a call to `configure(`.
fn names(body: &str, ident: &str) -> bool {
    body.match_indices(ident).any(|(at, _)| {
        body[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
    })
}

/// `(writing functions found, offenders)` over `modules`, at **function**
/// granularity.
///
/// A function whose own body constructs one of `writes` passes when that body
/// names `validator`, or calls a module-local validator wrapper (a function
/// whose body names the validator and writes nothing — `check_federated_credential`,
/// `checked_uris`). Otherwise it passes one level up: it has at least one
/// in-module caller and **every** caller validates the same way. Offenders are
/// `module::fn`.
fn unvalidated_writes(
    modules: &[(String, String)],
    writes: &[&str],
    validator: &str,
) -> (usize, Vec<String>) {
    unvalidated_writes_by(
        modules,
        |body| writes.iter().any(|w| body.contains(w)),
        validator,
    )
}

/// [`unvalidated_writes`] with the write detected by a predicate over a
/// function body rather than a list of needles — for a write that is one
/// *field* of a patch (the logout URL), not the patch itself.
fn unvalidated_writes_by(
    modules: &[(String, String)],
    writes_in: impl Fn(&str) -> bool,
    validator: &str,
) -> (usize, Vec<String>) {
    let mut found = 0usize;
    let mut offenders = Vec::new();
    for (module, src) in modules {
        let fns = functions_in(src);
        let wrappers: Vec<&str> = fns
            .iter()
            .filter(|f| names(&f.body, validator) && !writes_in(&f.body))
            .map(|f| f.name.as_str())
            .collect();
        let validates = |body: &str| {
            names(body, validator) || wrappers.iter().any(|w| names(body, &format!("{w}(")))
        };
        for (i, f) in fns.iter().enumerate() {
            if !writes_in(&f.body) {
                continue;
            }
            found += 1;
            if validates(&f.body) {
                continue;
            }
            let call = format!("{}(", f.name);
            let callers: Vec<&str> = fns
                .iter()
                .enumerate()
                .filter(|(j, g)| *j != i && names(&g.body, &call))
                .map(|(_, g)| g.body.as_str())
                .collect();
            if callers.is_empty() || !callers.iter().all(|body| validates(body)) {
                offenders.push(format!("{module}::{}", f.name));
            }
        }
    }
    (found, offenders)
}

/// Every function that writes a federation trust validates it first (per
/// function, one helper level — see the module doc).
#[test]
fn every_command_that_writes_a_federation_trust_validates_it_first() {
    let (found, offenders) =
        unvalidated_writes(&command_modules(), &TRUST_WRITES, FEDERATION_VALIDATOR);

    assert!(
        found >= 2,
        "found only {found} federation-trust write(s) in the command tree — the source walk or \
         the detector is broken, and a rule that scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "these functions write a federated identity credential without calling \
         `{FEDERATION_VALIDATOR}` (in their own body, or in every in-module caller).\n\
         A federated identity credential is a sign-in trust that needs no secret and never \
         expires, and Graph accepts a bad one without error — the check has to happen here, on \
         every path, or a value from an untrusted backup file becomes standing access:\n  {}",
        offenders.join("\n  ")
    );
}

/// Every function that writes a redirect URI validates it first (per function,
/// one helper level — see the module doc).
///
/// The sibling of the federation rule above, and it exists for the same reason:
/// the interactive authentication editor and the four SSO sites ran
/// `core::redirect` before their PATCH, and the DR restore — whose input is an
/// untrusted *file* — did not. A reply URL is where auth codes are delivered,
/// so a manifest carrying `https://*.evil.example/cb` or a plaintext
/// `http://attacker.example/cb` created the app in the operator's tenant with
/// those URLs and the codes could be collected by the attacker's host.
///
/// Derived from the source tree, not a list: any future function that builds
/// an authentication patch is caught because it *constructs the patch*.
#[test]
fn every_command_that_writes_a_redirect_uri_validates_it_first() {
    let (found, offenders) =
        unvalidated_writes(&command_modules(), &REDIRECT_WRITES, REDIRECT_VALIDATOR);

    assert!(
        found >= 2,
        "only {found} redirect-URI write(s) found — the source walk is broken, and a rule that \
         scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "function(s) writing a redirect URI without validating it (in their own body, or in \
         every in-module caller): {offenders:#?}\n\
         A reply URL decides where auth codes are delivered. Run \
         `core::redirect::validate_redirect_uri(s)` over every list before the patch and report \
         each rejection, the way `restore.rs::checked_uris` does."
    );
}

/// Whether `body` writes a front-channel logout URL: an `ApplicationWebPatch`
/// literal whose `logout_url` field is set from anything but `None` — written
/// out (`logout_url: value`) or in shorthand (`logout_url,` from a local of
/// that name).
fn writes_a_logout_url(body: &str) -> bool {
    body.match_indices("ApplicationWebPatch {").any(|(at, _)| {
        balanced_block(body, at).is_some_and(|block| {
            block.match_indices("logout_url").any(|(f, m)| {
                // A field position: first in the literal, or after a `,` — not
                // `input.logout_url` or `Some(logout_url)` in a value.
                let before = block[..f].trim_end();
                if !(before.ends_with('{') || before.ends_with(',')) {
                    return false;
                }
                let after = block[f + m.len()..].trim_start();
                match after.strip_prefix(':') {
                    Some(value) => !value.trim_start().starts_with("None"),
                    None => after.starts_with(',') || after.starts_with('}'),
                }
            })
        })
    })
}

/// Every function that writes a logout URL validates it as one first (per
/// function, one helper level — see the module doc).
///
/// The reply-URL rule above could not see this: it is satisfied by any
/// `validate_redirect_uri*` call in the function, and the SAML URL editor, the
/// SAML create wizard and the DR restore all validated their *reply* URLs and
/// then wrote the logout URL unchecked (the restore through the reply-URL rule,
/// which lets a custom scheme through). Entra loads the logout URL in a hidden
/// iframe at sign-out, so it is held to `core::redirect::validate_logout_url`.
///
/// Blind spots: only `ApplicationWebPatch` literals are seen, so a logout URL
/// sent through raw JSON or another patch type escapes the rule; and any
/// non-`None` value counts as a write, so a function that only ever clears the
/// field (`Some(String::new())`) still has to name the validator.
#[test]
fn every_command_that_writes_a_logout_url_validates_it_first() {
    let (found, offenders) =
        unvalidated_writes_by(&command_modules(), writes_a_logout_url, LOGOUT_VALIDATOR);

    // The Authentication tab, the SAML URL editor, the SAML create wizard and
    // the restore.
    assert!(
        found >= 4,
        "only {found} logout-URL write(s) found — the source walk or the detector is broken, \
         and a rule that scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "function(s) writing a logout URL without calling `{LOGOUT_VALIDATOR}` (in their own \
         body, or in every in-module caller): {offenders:#?}\n\
         A reply-URL check is not enough: `validate_redirect_uri` accepts a custom scheme, and \
         the logout URL must be https. Trim it and run \
         `core::redirect::validate_logout_url` before the patch."
    );
}

/// The logout rule must fire on a function that checks only its reply URLs —
/// the shape it was written for — and on a shorthand field, and must not count
/// `logout_url: None`.
#[test]
fn the_logout_rule_is_not_satisfied_by_a_reply_url_check() {
    let module = r#"
#[tauri::command]
pub async fn set_urls(input: Input) -> Result<(), UiError> {
    validate_redirect_uris(&input.replies).map_err(invalid)?;
    let web = ApplicationWebPatch {
        redirect_uris: Some(input.replies),
        logout_url: input.logout_url.filter(|s| !s.is_empty()),
    };
    Ok(())
}

#[tauri::command]
pub async fn set_checked(input: Input) -> Result<(), UiError> {
    if let Some(u) = input.logout_url.as_deref() {
        validate_logout_url(u).map_err(invalid)?;
    }
    let web = ApplicationWebPatch { redirect_uris: None, logout_url: input.logout_url };
    Ok(())
}

#[tauri::command]
pub async fn set_oidc(input: Input) -> Result<(), UiError> {
    let web = ApplicationWebPatch {
        redirect_uris: Some(input.replies),
        logout_url: None,
    };
    Ok(())
}

#[tauri::command]
pub async fn set_shorthand(input: Input) -> Result<(), UiError> {
    let logout_url = input.logout_url.map(|s| s.trim().to_string());
    let web = ApplicationWebPatch { redirect_uris: None, logout_url };
    Ok(())
}
"#;
    let modules = vec![("commands/fixture.rs".to_string(), module.to_string())];
    let (found, offenders) = unvalidated_writes_by(&modules, writes_a_logout_url, LOGOUT_VALIDATOR);
    assert_eq!(
        found, 3,
        "set_urls, set_checked and set_shorthand write; set_oidc clears"
    );
    assert_eq!(
        offenders,
        vec![
            "commands/fixture.rs::set_urls".to_string(),
            "commands/fixture.rs::set_shorthand".to_string(),
        ]
    );
    // The reply-URL rule passes `set_urls`: that is the gap.
    let (_, offenders) = unvalidated_writes(&modules, &REDIRECT_WRITES, REDIRECT_VALIDATOR);
    assert!(!offenders.contains(&"commands/fixture.rs::set_urls".to_string()));
}

/// The manifest checks `restore_tenant` must run before it touches the tenant.
const RESTORE_REFUSALS: [&str; 2] = ["check_manifest_schema(", "validate_manifest("];

/// Where `body` first names `needle` as a call (identifier boundary before it):
/// `validate_manifest(` is not a call to `manifest(`.
fn first_call(body: &str, needle: &str) -> Option<usize> {
    body.match_indices(needle).map(|(at, _)| at).find(|&at| {
        body[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
    })
}

/// `restore_tenant` refuses a too-new or malformed manifest before its first
/// Graph client exists.
///
/// The plan shows both as blockers, but the plan is advisory: the frontend
/// could skip it, and the restore's own refusal is what stops a repeated or
/// empty source appId from being adopted, tagged and wired twice. Deleting
/// either call, or moving it below `graph_for(`, fails here rather than in a
/// tenant.
#[test]
fn restore_refuses_a_bad_manifest_before_its_first_write() {
    let modules = command_modules();
    let (_, src) = modules
        .iter()
        .find(|(m, _)| m == "commands/restore.rs")
        .expect("commands/restore.rs is in the source walk");
    let fns = functions_in(src);
    let body = &fns
        .iter()
        .find(|f| f.name == "restore_tenant")
        .expect("restore_tenant is defined in restore.rs")
        .body;
    let client = first_call(body, "graph_for(").expect("restore_tenant builds a Graph client");
    for refusal in RESTORE_REFUSALS {
        let at = first_call(body, refusal)
            .unwrap_or_else(|| panic!("restore_tenant no longer calls `{refusal}..)`"));
        assert!(
            at < client,
            "restore_tenant calls `{refusal}..)` only after `graph_for(` — a refused manifest \
             must be refused before the restore can write anything"
        );
    }
}

/// Every function that mints a SAML signing certificate bounds its lifetime
/// first, through `sso::resolve_cert_lifetime_days` (per function, one helper
/// level — see the module doc).
///
/// The signing certificate is the trust every SAML assertion is checked
/// against, so its lifetime is the window a stolen key stays useful: an
/// unbounded value is a trust that never has to be re-established. The bound
/// is one function, table-tested in `sso/mod.rs`; this rule is what makes a
/// third mint site that skips it fail CI rather than review.
#[test]
fn every_signing_certificate_mint_bounds_its_lifetime_first() {
    let (found, offenders) =
        unvalidated_writes(&command_modules(), &CERT_MINTS, CERT_LIFETIME_BOUND);

    assert!(
        found >= 2,
        "only {found} signing-certificate mint(s) found — the source walk is broken, and a rule \
         that scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "function(s) minting a SAML signing certificate without bounding its lifetime through \
         `{CERT_LIFETIME_BOUND}` (in their own body, or in every in-module caller): \
         {offenders:#?}"
    );
}

/// The rules above must fire on a write whose *module* validates but whose
/// *function* does not — the gap the module-level form left open.
#[test]
fn the_trust_rules_check_each_function_not_its_module() {
    let module = r#"
#[tauri::command]
pub async fn set_web(input: Input) -> Result<(), UiError> {
    validate_redirect_uri(&input.uri).map_err(invalid)?;
    let web = ApplicationWebPatch { redirect_uris: Some(input.uris) };
    Ok(())
}

#[tauri::command]
pub async fn create(input: Input) -> Result<(), UiError> {
    for uri in &input.uris {
        azapptoolkit_core::redirect::validate_redirect_uri(uri).map_err(invalid)?;
    }
    configure(&input).await
}

async fn configure(input: &Input) -> Result<(), UiError> {
    let spa = ApplicationSpaPatch { redirect_uris: Some(input.uris.clone()) };
    Ok(())
}

#[tauri::command]
pub async fn drifted(input: Input) -> Result<(), UiError> {
    // validate_redirect_uri is the caller's job
    let web = ApplicationWebPatch { redirect_uris: Some(input.uris) };
    Ok(())
}
"#;
    let modules = vec![("commands/fixture.rs".to_string(), module.to_string())];
    let (found, offenders) = unvalidated_writes(&modules, &REDIRECT_WRITES, REDIRECT_VALIDATOR);
    assert_eq!(found, 3, "set_web, configure and drifted each write");
    assert_eq!(offenders, vec!["commands/fixture.rs::drifted".to_string()]);
    // The module as a whole names the validator — the old module-level form
    // passed `drifted`.
    assert!(module.contains(REDIRECT_VALIDATOR));

    // A helper is judged by its callers: one no in-module caller reaches is
    // flagged (`reapply(` is not a call to `apply(`), and a thin local
    // wrapper around the validator satisfies the function that calls it.
    let module = r#"
fn checked(uris: &[String]) -> Result<Vec<String>, String> {
    for uri in uris {
        validate_redirect_uri(uri)?;
    }
    Ok(uris.to_vec())
}

#[tauri::command]
pub async fn wrapped(input: Input) -> Result<(), UiError> {
    let uris = checked(&input.uris).map_err(invalid)?;
    let web = ApplicationWebPatch { redirect_uris: Some(uris) };
    Ok(())
}

#[tauri::command]
pub async fn validated(input: Input) -> Result<(), UiError> {
    validate_redirect_uri(&input.uri).map_err(invalid)?;
    reapply(&input).await
}

async fn apply(input: &Input) -> Result<(), UiError> {
    let spa = ApplicationSpaPatch { redirect_uris: Some(input.uris.clone()) };
    Ok(())
}
"#;
    let modules = vec![("commands/fixture.rs".to_string(), module.to_string())];
    let (found, offenders) = unvalidated_writes(&modules, &REDIRECT_WRITES, REDIRECT_VALIDATOR);
    assert_eq!(found, 2, "wrapped and apply each write");
    assert_eq!(offenders, vec!["commands/fixture.rs::apply".to_string()]);

    // And a helper with an in-module caller that does not validate is flagged
    // even though another caller does.
    let module = r#"
#[tauri::command]
pub async fn guarded(input: Input) -> Result<(), UiError> {
    validate_redirect_uri(&input.uri).map_err(invalid)?;
    apply(&input).await
}

#[tauri::command]
pub async fn unguarded(input: Input) -> Result<(), UiError> {
    apply(&input).await
}

async fn apply(input: &Input) -> Result<(), UiError> {
    let spa = ApplicationSpaPatch { redirect_uris: Some(input.uris.clone()) };
    Ok(())
}
"#;
    let modules = vec![("commands/fixture.rs".to_string(), module.to_string())];
    let (_, offenders) = unvalidated_writes(&modules, &REDIRECT_WRITES, REDIRECT_VALIDATOR);
    assert_eq!(offenders, vec!["commands/fixture.rs::apply".to_string()]);
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
    let mut offenders: Vec<String> = Vec::new();
    let mut found = 0usize;
    for (root, src) in retry_scan_sources() {
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
            offenders.push(relative(&root, &src));
        }
    }

    // Graph, ARM, Key Vault and Exchange transports.
    assert!(
        found >= 4,
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

/// The retry schedule's raw primitives. Naming one outside `http_retry.rs` is
/// an open-coded loop: its own attempt counter, its own sleep, its own budget.
const RAW_RETRY_PRIMITIVES: [&str; 5] = [
    "MAX_RETRIES",
    "BASE_DELAY_MS",
    "next_backoff_ms",
    "sleep_before_retry",
    "sleep_with_jitter",
];

/// The first raw retry primitive a non-comment line of `src` names, if any.
/// Matches whole identifiers only (`MY_MAX_RETRIES` is not `MAX_RETRIES`).
fn names_a_raw_retry_primitive(src: &str) -> Option<&'static str> {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    src.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .find_map(|line| {
            RAW_RETRY_PRIMITIVES.into_iter().find(|name| {
                line.match_indices(name).any(|(at, _)| {
                    let before = line[..at].chars().next_back();
                    let after = line[at + name.len()..].chars().next();
                    !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
                })
            })
        })
}

/// No client open-codes the retry schedule.
///
/// The rule above only sees `with_retries(` call sites, so a transport that
/// never adopted the shared loop was invisible to it: the Exchange client ran
/// its own `attempt < MAX_RETRIES` loop and replayed `New-*`/`Remove-*`
/// cmdlets after a 5xx, the exact failure `RetryClass` exists to prevent.
/// Banning the primitives outside `http_retry.rs` closes that gap without
/// flagging the desktop's legitimate non-retrying reqwest calls.
#[test]
fn no_client_open_codes_the_retry_schedule() {
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for (root, src) in retry_scan_sources() {
        if src.ends_with("http_retry.rs") {
            continue;
        }
        scanned += 1;
        let text = std::fs::read_to_string(&src).expect("read source");
        if let Some(name) = names_a_raw_retry_primitive(&text) {
            offenders.push(format!("{} — names `{name}`", relative(&root, &src)));
        }
    }

    assert!(
        scanned > 0,
        "the source walk found nothing — a rule that scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "source(s) open-coding the retry schedule: {offenders:#?}\n\
         Route the loop through `with_retries` + `retry_class_for` (or drive a `RetryBudget` for \
         a stateful loop): an open-coded loop escapes the RetryClass rule, so a write can be \
         replayed after an unknown outcome."
    );
}

/// The raw-primitive rule must actually FIRE on the shape it exists to catch,
/// and not on a comment or on the sanctioned seams.
#[test]
fn the_raw_retry_primitive_rule_fires_on_an_open_coded_loop() {
    let open_coded = r#"
        let mut attempt = 0u32;
        loop {
            if attempt < MAX_RETRIES {
                sleep_before_retry(retry_after, delay_ms).await;
                attempt += 1;
                continue;
            }
        }
    "#;
    assert_eq!(names_a_raw_retry_primitive(open_coded), Some("MAX_RETRIES"));
    assert_eq!(
        names_a_raw_retry_primitive("    delay = next_backoff_ms(delay);"),
        Some("next_backoff_ms")
    );
    assert_eq!(
        names_a_raw_retry_primitive("use http_retry::{BASE_DELAY_MS, with_retries};"),
        Some("BASE_DELAY_MS")
    );

    // A comment that talks about the budget is not a loop.
    let comment_only =
        "    /// retried up to `MAX_RETRIES` times\n    // after MAX_RETRIES it surfaces";
    assert_eq!(names_a_raw_retry_primitive(comment_only), None);

    // The sanctioned seams, and an identifier that merely contains a name.
    let sanctioned = r#"
        with_retries(cmdlet, retry_class_for(cmdlet), |_| async { todo!() }).await;
        let mut budget = RetryBudget::new();
        const MY_MAX_RETRIES_HINT: u32 = 1;
    "#;
    assert_eq!(names_a_raw_retry_primitive(sanctioned), None);
}

/// The connect-budget violations in `src` (comment lines ignored).
///
/// Every `Client::builder()` must set `.connect_timeout(` before its
/// `.build()`, and must not fall back with `.unwrap_or_default()` — the default
/// client has no timeout at all. A bare `reqwest::Client::new()` /
/// `Client::default()` is the same unbudgeted client by another name.
fn http_client_budget_violations(src: &str) -> Vec<&'static str> {
    let code: String = src
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let standalone = |needle: &str| {
        code.match_indices(needle)
            .any(|(at, _)| !code[..at].chars().next_back().is_some_and(is_ident))
    };
    let mut out = Vec::new();
    for (at, _) in code.match_indices("Client::builder()") {
        let rest = &code[at..];
        let Some(build) = rest.find(".build()") else {
            out.push("a `Client::builder()` with no `.build()`");
            continue;
        };
        if !rest[..build].contains(".connect_timeout(") {
            out.push("a `Client::builder()` without `.connect_timeout(CONNECT_TIMEOUT)`");
        }
        let after = rest[build + ".build()".len()..].trim_start();
        if after.starts_with(".unwrap_or_default()") {
            out.push("a `.build().unwrap_or_default()` (the default client has no timeout)");
        }
    }
    if standalone("Client::new()") {
        out.push("a `Client::new()` (no connect budget)");
    }
    if standalone("Client::default()") {
        out.push("a `Client::default()` (no connect budget)");
    }
    out
}

/// Every HTTP client the app builds has a connect budget.
///
/// Only the Graph client set one, so on a network that silently drops traffic
/// to `management.azure.com`, a key vault, `outlook.office365.com` or Log
/// Analytics every attempt ran to the full 60–120s total timeout: about four
/// minutes for an idempotent read before a cause-less network error. The
/// budget is `core::http_retry::CONNECT_TIMEOUT`; this rule makes a new client
/// unable to forget it. Test code is exempt (it builds throwaway clients to
/// obtain a `reqwest::Error` without a socket).
#[test]
fn every_http_client_has_a_connect_budget() {
    let mut offenders: Vec<String> = Vec::new();
    let mut builders = 0usize;
    for (root, src) in retry_scan_sources() {
        let is_test_file = src.components().any(|c| c.as_os_str() == "tests")
            || src.file_name().is_some_and(|f| f == "tests.rs");
        if is_test_file {
            continue;
        }
        let text = std::fs::read_to_string(&src).expect("read source");
        let code = super::sources::strip_tests(&text);
        builders += code
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .map(|line| line.matches("Client::builder()").count())
            .sum::<usize>();
        for violation in http_client_budget_violations(&code) {
            offenders.push(format!("{} — {violation}", relative(&root, &src)));
        }
    }

    // Graph, ARM, Log Analytics, Key Vault, Exchange, auth and the SSO
    // metadata probe.
    assert!(
        builders >= 7,
        "found only {builders} `Client::builder()` call(s) — the source walk is broken, and a \
         rule that scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "HTTP client(s) without a connect budget: {offenders:#?}\n\
         Add `.connect_timeout(azapptoolkit_core::http_retry::CONNECT_TIMEOUT)` to the builder \
         and `.expect(\"reqwest client builds\")` it: a host that accepts no connection otherwise \
         burns the whole total timeout once per retry attempt."
    );
}

/// The connect-budget rule must fire on the shapes it exists to catch.
#[test]
fn the_connect_budget_rule_fires_on_an_unbudgeted_client() {
    let unbudgeted = r#"
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap_or_default();
    "#;
    assert_eq!(
        http_client_budget_violations(unbudgeted),
        vec![
            "a `Client::builder()` without `.connect_timeout(CONNECT_TIMEOUT)`",
            "a `.build().unwrap_or_default()` (the default client has no timeout)",
        ]
    );
    assert_eq!(
        http_client_budget_violations("let c = reqwest::Client::new();"),
        vec!["a `Client::new()` (no connect budget)"]
    );

    let budgeted = r#"
        // A comment naming reqwest::Client::new() is not a client.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .connect_timeout(azapptoolkit_core::http_retry::CONNECT_TIMEOUT)
            .build()
            .expect("reqwest client builds");
        let graph = GraphClient::new(tenant, read, write, cache);
        let other = ExchangeClient::default();
    "#;
    assert!(http_client_budget_violations(budgeted).is_empty());

    // An out-of-line test-module declaration does not hide the builder below
    // it; a trailing inline test module (and its throwaway client) is dropped.
    let file = "#[cfg(test)]\nmod tests;\nlet c = reqwest::Client::builder().build();\n\
                #[cfg(test)]\nmod t { let c = reqwest::Client::new(); }";
    assert_eq!(
        http_client_budget_violations(&super::sources::strip_tests(file)),
        vec!["a `Client::builder()` without `.connect_timeout(CONNECT_TIMEOUT)`"]
    );
}

/// The two HTTP clients whose replies carry secrets never ask for a compressed
/// body.
///
/// The workspace `reqwest` has the `gzip` feature for Graph's megabyte list
/// pages, and a feature is on for every client in the build. The `/token`
/// client reads the access and refresh tokens into a `Zeroizing` buffer, and a
/// Key Vault secret read returns the secret value: an inflate buffer would be
/// one more plaintext copy nobody wipes, for replies of a few KiB. Pinned per
/// builder function, so moving the builder without the opt-out fails here.
#[test]
fn secret_bearing_http_clients_never_inflate() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../crates");
    for (file, function) in [
        ("azapptoolkit-auth/src/service/mod.rs", "token_http_client"),
        ("azapptoolkit-keyvault/src/client.rs", "with_base_url"),
    ] {
        let src = std::fs::read_to_string(crates.join(file))
            .unwrap_or_else(|e| panic!("read {file}: {e}"));
        let found = functions_in(&src);
        let builder = found
            .iter()
            .find(|f| f.name == function)
            .unwrap_or_else(|| panic!("`fn {function}` not found in {file} — update this rule"));
        assert!(
            builder.body.contains("Client::builder()"),
            "`{file}::{function}` no longer builds the HTTP client — point this rule at the \
             function that does"
        );
        assert!(
            builder.body.contains(".no_gzip()"),
            "`{file}::{function}` builds a client without `.no_gzip()`: its replies carry \
             secrets, and the workspace `gzip` feature would inflate them into a buffer nobody \
             wipes"
        );
    }
}

/// The `reqwest::Response` readers that buffer the whole body, however large.
const UNBOUNDED_BODY_READS: [&str; 3] = ["bytes", "text", "json"];

/// Every whole-body read in `src` awaited on a response — `.bytes().await`,
/// `.text().await`, `.json().await` or `.json::<T>().await` — by method name,
/// in order. Comments and string literals are ignored and whitespace is
/// squeezed out first, so a read split over lines (`resp.bytes()\n.await`)
/// still counts; a call that is not awaited (`name.bytes().all(..)`) does not.
fn unbounded_body_reads(src: &str) -> Vec<&'static str> {
    let code = super::sources::code_mask(src);
    let squeezed: String = src
        .char_indices()
        .filter(|&(i, c)| code[i] && !c.is_whitespace())
        .map(|(_, c)| c)
        .collect();
    let mut hits: Vec<(usize, &'static str)> = Vec::new();
    for name in UNBOUNDED_BODY_READS {
        let needle = format!(".{name}");
        for (at, _) in squeezed.match_indices(&needle) {
            let mut rest = &squeezed[at + needle.len()..];
            // `.text_with_charset(` / `.json_value(` are other methods.
            if rest
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                continue;
            }
            if let Some(generic) = rest.strip_prefix("::<") {
                let mut depth = 1usize;
                let Some(end) = generic.char_indices().find_map(|(i, c)| {
                    match c {
                        '<' => depth += 1,
                        '>' => depth -= 1,
                        _ => {}
                    }
                    (depth == 0).then_some(i)
                }) else {
                    continue;
                };
                rest = &generic[end + 1..];
            }
            if rest.starts_with("().await") {
                hits.push((at, name));
            }
        }
    }
    hits.sort_unstable();
    hits.into_iter().map(|(_, name)| name).collect()
}

/// No client reads a response body without a size cap.
///
/// The workspace `reqwest` has the `gzip` feature, and reqwest drops
/// `Content-Length` when it inflates, so `resp.bytes()` / `resp.text()` /
/// `resp.json()` buffer whatever a reply decodes to: a few KiB on the wire can
/// be gigabytes in memory, and an error body was read whole before
/// `sanitize_error_body` kept 800 characters of it. Every reader instead runs
/// a capped `resp.chunk()` loop — `core::http_body::BodyCap` in the client
/// transports (a success body past `MAX_SUCCESS_BODY_BYTES` is the client's
/// `Protocol` error, an error body is cut at `MAX_ERROR_BODY_BYTES`) and the
/// SSO metadata probe (1 MiB), a 64 KiB `Zeroizing` buffer in the `/token`
/// reader. Test code is exempt (it reads
/// bodies the test itself served).
#[test]
fn no_client_reads_an_unbounded_body() {
    let mut offenders: Vec<String> = Vec::new();
    let mut capped_readers = 0usize;
    for (root, src) in retry_scan_sources() {
        let is_test_file = src.components().any(|c| c.as_os_str() == "tests")
            || src.file_name().is_some_and(|f| f == "tests.rs");
        if is_test_file {
            continue;
        }
        let text = std::fs::read_to_string(&src).expect("read source");
        let code = super::sources::strip_tests(&text);
        if code.contains("BodyCap::new(") {
            capped_readers += 1;
        }
        for name in unbounded_body_reads(&code) {
            offenders.push(format!("{} — `.{name}().await`", relative(&root, &src)));
        }
    }

    // Graph, ARM, Key Vault, Exchange and the SSO metadata probe.
    assert!(
        capped_readers >= 5,
        "only {capped_readers} source(s) read a body through `BodyCap` — the source walk is \
         broken, or a client lost its capped reader"
    );
    assert!(
        offenders.is_empty(),
        "response bodies read whole, with no size cap: {offenders:#?}\n\
         Read the body with a `resp.chunk()` loop over `azapptoolkit_core::http_body::BodyCap` \
         (the transports' `read_success_body` / `read_error_body`): the `gzip` feature means \
         `Content-Length` cannot bound what a reply decodes to."
    );
}

/// The body-cap rule must fire on a whole-body read however it is laid out,
/// and not on a chunk loop, a request builder, a comment or a byte iterator.
#[test]
fn the_body_cap_rule_fires_on_an_unbounded_read() {
    assert_eq!(
        unbounded_body_reads("let b = resp.bytes()\n    .await?;"),
        vec!["bytes"]
    );
    assert_eq!(
        unbounded_body_reads("let t = resp\n    .text()\n    .await\n    .unwrap_or_default();"),
        vec!["text"]
    );
    assert_eq!(
        unbounded_body_reads("let v = resp.json::<Vec<Paged<T>>>().await?; resp.text().await"),
        vec!["json", "text"]
    );
    for clean in [
        "name.bytes().all(|b| b.is_ascii_lowercase())",
        "// rather than `resp.bytes().await`, which buffers it all",
        "let doc = \"resp.text().await\";",
        "while let Some(chunk) = resp.chunk().await? { cap.push(chunk.len())?; }",
        "let resp = http.post(url).json(&body).send().await?;",
        "let n = s.text_len().await;",
    ] {
        assert!(unbounded_body_reads(clean).is_empty(), "fired on {clean:?}");
    }
}

/// Every Rust source the retry and client-budget rules scan, paired with the root it was
/// found under (for readable offender paths): the shared crates AND the
/// desktop backend, which hosts HTTP code of its own (`cert.rs`, the SSO
/// metadata probe, the updater) and is where a one-off retry wrapper would
/// most likely appear.
fn retry_scan_sources() -> Vec<(std::path::PathBuf, std::path::PathBuf)> {
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

    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    for (dir, what) in [
        (manifest.join("../../../crates"), "crates"),
        (manifest.join("src"), "desktop backend"),
    ] {
        let root = dir
            .canonicalize()
            .unwrap_or_else(|e| panic!("{what} dir: {e}"));
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        assert!(
            !files.is_empty(),
            "the source walk found no {what} sources — the rule would pass vacuously"
        );
        sources.extend(files.into_iter().map(|f| (root.clone(), f)));
    }
    sources
}

fn relative(root: &std::path::Path, src: &std::path::Path) -> String {
    src.strip_prefix(root).unwrap_or(src).display().to_string()
}

/// The calls that prove an id may stand in a request path. Any
/// `validate_*(` call counts too (`azapptoolkit-keyvault`'s
/// `validate_secret_name` / `validate_secret_version` / `validate_vault_name`).
const PATH_VALIDATORS: [&str; 3] = ["require_path_segment", "require_guid", "require_arm_path"];

/// Placeholders that are spliced into a path without a single-segment check,
/// each named, with why that is safe: `(file, function, placeholders,
/// reason)`. Every placeholder is listed by name (`{}` for a positional one),
/// so a new id spliced into one of these functions is an offender like
/// anywhere else, and a placeholder that no longer appears fails the stale
/// check — the table cannot outlive the code it excuses.
const PATH_SPLICE_EXEMPT: &[(&str, &str, &[&str], &str)] = &[
    (
        "azapptoolkit-graph/src/client/sharepoint.rs",
        "site_lookup_path",
        &["trimmed", "host", "rel"],
        "rebuilds an operator-pasted site URL from `url::Url`'s parsed segments and refuses `:`, \
         an encoded `/ \\ : .`, a non-hostname, credentials and a port (its own unit tests pin it)",
    ),
    (
        "azapptoolkit-graph/src/client/sharepoint.rs",
        "url_host_and_segments",
        &["trimmed"],
        "the item resolver's URL parser: prefixes a scheme before `url::Url` parses the text, and \
         applies the same parsed-segment rule as `site_lookup_path`",
    ),
    (
        "azapptoolkit-graph/src/client/sharepoint.rs",
        "site_collection_url",
        &["host", "{}"],
        "builds a URL (not a request path) from `url_host_and_segments`' checked host and \
         segments; it reaches Graph only through `site_lookup_path`",
    ),
    (
        "azapptoolkit-graph/src/client/sharepoint.rs",
        "descend_one_segment",
        &["next"],
        "extends a site's `webUrl` by one parsed segment; the result reaches Graph only through \
         `site_lookup_path`",
    ),
    (
        "azapptoolkit-graph/src/client/sharepoint.rs",
        "get_drive_item_by_path",
        &["rel_path"],
        "several segments by design (`root:/{path}:` addressing) and `pub(crate)`: its one caller \
         passes `site_relative_path`'s output, built from `url_host_and_segments`, which refuses \
         `:` and an encoded `/ \\ : .` per segment",
    ),
];

/// The units the path-splice scan must find splices in: every Graph client
/// domain module (a `name.rs` file or a `name/` directory) and the ARM and Key
/// Vault crate roots. A unit that contributes nothing has dropped out of the
/// scan (moved, renamed, or unreadable), which the function floor alone does
/// not catch: moving `applications.rs` into `applications/` used to lose 19
/// functions and still pass.
const PATH_SPLICE_UNITS: [&str; 9] = [
    "azapptoolkit-graph/src/client/applications",
    "azapptoolkit-graph/src/client/credentials",
    "azapptoolkit-graph/src/client/directory",
    "azapptoolkit-graph/src/client/policies",
    "azapptoolkit-graph/src/client/roles_grants",
    "azapptoolkit-graph/src/client/service_principals",
    "azapptoolkit-graph/src/client/sharepoint",
    "azapptoolkit-arm/src",
    "azapptoolkit-keyvault/src",
];

/// Whether `file` (crate-relative, `/`-separated) belongs to `unit`.
fn in_splice_unit(file: &str, unit: &str) -> bool {
    file.strip_suffix(".rs") == Some(unit)
        || file
            .strip_prefix(unit)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The placeholders spliced into the **path** of every `format!` literal in
/// `body`: the text before the first `?`, where a `{x}` directly after a `/`
/// is a path segment. `Some(name)` for a named `/{name}`, `None` for a
/// positional `/{}` or `/{0}`, which cannot be tied to a check by name.
/// `{{`/`}}` escapes are skipped.
fn path_placeholders(body: &str) -> Vec<Option<String>> {
    let code = super::sources::code_mask(body);
    let mut out = Vec::new();
    for (at, m) in body.match_indices("format!(") {
        let starts_ident = body[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if !code[at] || starts_ident {
            continue;
        }
        let Some(literal) = leading_string_literal(&body[at + m.len()..]) else {
            continue;
        };
        let path = literal.split('?').next().unwrap_or_default();
        let bytes = path.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'{' if bytes.get(i + 1) == Some(&b'{') => i += 2,
                b'{' => {
                    let Some(close) = path[i..].find('}') else {
                        break;
                    };
                    let inner = &path[i + 1..i + close];
                    let name = inner.split(':').next().unwrap_or_default();
                    if i > 0 && bytes[i - 1] == b'/' {
                        let positional =
                            name.is_empty() || name.bytes().all(|b| b.is_ascii_digit());
                        out.push((!positional).then(|| name.to_string()));
                    }
                    i += close + 1;
                }
                _ => i += 1,
            }
        }
    }
    out
}

/// The contents of the string literal (plain or raw) that `rest` opens with,
/// after leading whitespace; escapes are left as written.
fn leading_string_literal(rest: &str) -> Option<&str> {
    let rest = rest.trim_start();
    if let Some(body) = rest.strip_prefix('"') {
        let bytes = body.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => i += 2,
                b'"' => return Some(&body[..i]),
                _ => i += 1,
            }
        }
        return None;
    }
    let raw = rest.strip_prefix('r')?;
    let hashes = raw.len() - raw.trim_start_matches('#').len();
    let body = raw[hashes..].strip_prefix('"')?;
    let close = format!("\"{}", "#".repeat(hashes));
    body.find(&close).map(|end| &body[..end])
}

/// The variables `body` proves are path-safe: every identifier passed to a
/// [`PATH_VALIDATORS`] or `validate_*` call whose result is propagated with
/// `?`. String literals in the arguments (the `"site id"` label) and field
/// names (`site.id` proves `site`, not `id`) do not count, and neither does a
/// call whose result is dropped.
fn path_checked_idents(body: &str) -> Vec<String> {
    let code = super::sources::code_mask(body);
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = Vec::new();
    for (at, c) in body.char_indices() {
        if !code[at] || !is_ident(c) || body[..at].chars().next_back().is_some_and(is_ident) {
            continue;
        }
        let name: String = body[at..].chars().take_while(|&c| is_ident(c)).collect();
        let is_validator = PATH_VALIDATORS.contains(&name.as_str())
            || (name.starts_with("validate_") && name.len() > "validate_".len());
        let open = at + name.len();
        if !is_validator || body.as_bytes().get(open) != Some(&b'(') {
            continue;
        }
        let (mut depth, mut close) = (0usize, None);
        for (i, b) in body.bytes().enumerate().skip(open) {
            if !code[i] {
                continue;
            }
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            continue;
        };
        if !body[close + 1..].trim_start().starts_with('?') {
            continue;
        }
        for (i, c) in body[open + 1..close].char_indices() {
            let i = open + 1 + i;
            let starts = code[i]
                && (c.is_ascii_alphabetic() || c == '_')
                && !body[..i].chars().next_back().is_some_and(is_ident)
                && !body[..i].trim_end().ends_with('.');
            if starts {
                out.push(body[i..].chars().take_while(|&c| is_ident(c)).collect());
            }
        }
    }
    out
}

/// For each function in `src` that splices at least one placeholder into a
/// request path: its name and the placeholders no check covers (`{}` for a
/// positional one).
fn unchecked_path_splices(src: &str) -> Vec<(String, Vec<String>)> {
    functions_in(src)
        .into_iter()
        .filter_map(|f| {
            let spliced = path_placeholders(&f.body);
            if spliced.is_empty() {
                return None;
            }
            let checked = path_checked_idents(&f.body);
            let unchecked = spliced
                .into_iter()
                .filter_map(|p| match p {
                    Some(name) if checked.contains(&name) => None,
                    Some(name) => Some(name),
                    None => Some("{}".to_string()),
                })
                .collect();
            Some((f.name, unchecked))
        })
        .collect()
}

/// Every Rust source the path-splice rule reads, as (crate-relative name,
/// source with test items stripped): the Graph client's modules, walked
/// recursively but not `client/tests/`, and the whole of the ARM and Key Vault
/// crates. An unreadable directory fails the walk rather than shrinking it.
fn path_splice_sources() -> Vec<(String, String)> {
    fn rust_files(dir: &std::path::Path, skip: &[&str], out: &mut Vec<std::path::PathBuf>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("path-splice scan: read {}: {e}", dir.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("path-splice scan: list {}: {e}", dir.display()))
                .path();
            if path.is_dir() {
                if !path
                    .file_name()
                    .is_some_and(|n| skip.iter().any(|s| n == *s))
                {
                    rust_files(&path, skip, out);
                }
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
    rust_files(
        &crates.join("azapptoolkit-graph/src/client"),
        &["tests"],
        &mut files,
    );
    rust_files(&crates.join("azapptoolkit-arm/src"), &[], &mut files);
    rust_files(&crates.join("azapptoolkit-keyvault/src"), &[], &mut files);
    files.sort();
    files
        .into_iter()
        .map(|file| {
            let text = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("path-splice scan: read {}: {e}", file.display()));
            let name = relative(&crates, &file).replace('\\', "/");
            (name, super::sources::strip_tests(&text))
        })
        .collect()
}

/// Every id a client splices into a request path is shape-checked in the
/// function that splices it, and the site lookup validates the operator's URL.
///
/// `send_core` joins a path onto the base URL with `format!` and the `url`
/// crate resolves `..`, `%2e%2e` and `\`, while a `?` or `#` rewrites the
/// query, so an id like `../servicePrincipals/X` retargets the request: a
/// `delete_application` call deletes a service principal, and a SharePoint
/// permission DELETE on the `Sites.FullControl.All` bearer walks up to
/// `/drives/{d}/items/{i}` and deletes a file. Ids reach the clients from the
/// webview, app-registration tags and earlier responses, so the check sits at
/// the client boundary rather than trusting every caller.
///
/// The rule: every `/{name}` placeholder in the path part (before `?`) of a
/// `format!` literal names a variable the same function passes to
/// `require_path_segment` / `require_guid` / `require_arm_path` / `validate_*`
/// with the result propagated by `?`; a `$batch` helper checks inside its
/// closure. A positional `/{}` is an offender — name the id. Per function: a
/// wrapper does not inherit its callee's check, and a callee does not inherit
/// its caller's. Blind spots: a path built without `format!` (`push_str`,
/// `url::Url::join`), assembled from a pre-joined variable, or spliced without
/// a `/` before it (ARM's `"{}{role_definition_id}"`, checked by
/// `require_arm_path` all the same).
#[test]
fn every_client_path_splice_is_shape_checked() {
    let mut functions = 0usize;
    let mut per_unit = [0usize; PATH_SPLICE_UNITS.len()];
    let mut offenders: Vec<String> = Vec::new();
    let mut exemptions_hit: Vec<(&str, &str, &str)> = Vec::new();
    for (file, src) in path_splice_sources() {
        for (func, unchecked) in unchecked_path_splices(&src) {
            functions += 1;
            for (unit, count) in PATH_SPLICE_UNITS.iter().zip(per_unit.iter_mut()) {
                if in_splice_unit(&file, unit) {
                    *count += 1;
                }
            }
            for name in unchecked {
                let exempt = PATH_SPLICE_EXEMPT.iter().find_map(|(f, fun, names, _)| {
                    (*f == file && *fun == func)
                        .then(|| names.iter().find(|n| **n == name))
                        .flatten()
                        .map(|n| (*f, *fun, *n))
                });
                match exempt {
                    Some(hit) => exemptions_hit.push(hit),
                    None => offenders.push(format!("{file}::{func} — {{{name}}}")),
                }
            }
        }
    }

    let lost: Vec<&str> = PATH_SPLICE_UNITS
        .iter()
        .zip(per_unit)
        .filter(|(_, count)| *count == 0)
        .map(|(unit, _)| *unit)
        .collect();
    assert!(
        lost.is_empty(),
        "no path splice found in {lost:?} — the module moved, was renamed or dropped out of the \
         scan; point `PATH_SPLICE_UNITS` (and the walk) at where it lives now"
    );
    assert!(
        functions >= 90,
        "found only {functions} function(s) that splice an id into a request path across the \
         Graph, ARM and Key Vault clients — the scan is broken, and a rule that scans nothing \
         passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "id(s) spliced into a request path without a shape check: {offenders:#?}\n\
         Call `validate::require_path_segment(\"<what>\", id)?` (Graph; `require_guid` / \
         `require_arm_path` / `validate_*` in ARM and Key Vault) at the top of the function, or \
         inside the closure for a `$batch` sub-URL, and name a positional `{{}}`. Otherwise add a \
         justified entry to `PATH_SPLICE_EXEMPT`."
    );
    for (file, func, placeholders, _) in PATH_SPLICE_EXEMPT {
        for placeholder in *placeholders {
            assert!(
                exemptions_hit.contains(&(*file, *func, *placeholder)),
                "stale path-splice exemption `{file}::{func}` ({{{placeholder}}}) — it matches no \
                 unchecked placeholder; remove it"
            );
        }
    }

    let graph = path_splice_sources()
        .into_iter()
        .find(|(file, _)| file == "azapptoolkit-graph/src/client/sharepoint.rs")
        .expect("graph client/sharepoint.rs is in the scan");
    let fns = functions_in(&graph.1);
    let lookup = fns
        .iter()
        .find(|f| f.name == "get_site_by_url")
        .expect("graph client/sharepoint.rs lost get_site_by_url");
    assert!(
        names(&lookup.body, "site_lookup_path(") && names(&lookup.body, "require_path_segment("),
        "get_site_by_url must build its path through site_lookup_path (which refuses anything but \
         a plain site address) and shape-check the id Graph answers with"
    );
}

/// The path-splice rule must fire on an unchecked id, on a check whose result
/// is dropped, on a label or a field that merely shares the id's name, and on
/// a positional placeholder — and must pass a checked splice, a check inside a
/// `$batch` closure, a query value and an escaped brace.
#[test]
fn the_path_splice_rule_fires_on_an_unchecked_id() {
    let src = r##"
impl Client {
    pub async fn unchecked(&self, object_id: &str) -> Result<()> {
        let path = format!("/applications/{object_id}");
        self.send(&path).await
    }

    pub async fn checked(&self, object_id: &str, name: &str) -> Result<()> {
        validate::require_path_segment("object id", object_id)?;
        let url = format!(
            "{}/applications/{object_id}/owners?$filter=startswith(x,'/{name}')",
            self.base_url
        );
        self.send(&url).await
    }

    pub async fn dropped(&self, object_id: &str) -> Result<()> {
        let _ = validate::require_path_segment("object id", object_id);
        self.send(&format!("/applications/{object_id}")).await
    }

    pub async fn label_only(&self, id: &str, other: &str) -> Result<()> {
        validate::require_path_segment("site id", other)?;
        // format!("/sites/{other}") in a comment is not a splice
        self.send(&format!("/sites/{id}")).await
    }

    pub async fn field_only(&self, site: &Site, id: &str) -> Result<()> {
        validate::require_path_segment("site id", &site.id)?;
        self.send(&format!("/sites/{id}/drives")).await
    }

    pub async fn positional(&self, t: &Target) -> Result<()> {
        require_path_segment("site id", t.site_id)?;
        self.send(&format!("/sites/{}", t.site_id)).await
    }

    pub async fn batched(&self, ids: &[String]) -> Result<()> {
        let urls: Vec<String> = ids
            .iter()
            .map(|id| {
                validate::require_path_segment("object id", id)?;
                Ok(format!("/applications/{id}"))
            })
            .collect::<Result<_>>()?;
        self.batch(&urls).await
    }

    pub fn vault(name: &str) -> Result<String> {
        crate::validate::validate_vault_name(name)?;
        Ok(format!("https://{name}.vault.azure.net/secrets/{{literal}}"))
    }

    pub fn not_a_path(name: &str) -> String {
        format!("displayName eq '{name}'")
    }
}
"##;
    let got = unchecked_path_splices(src);
    let expect = |name: &str, unchecked: &[&str]| {
        let found = got
            .iter()
            .find(|(f, _)| f == name)
            .unwrap_or_else(|| panic!("`{name}` was not seen as a path splice: {got:?}"));
        assert_eq!(found.1, unchecked, "`{name}`");
    };
    expect("unchecked", &["object_id"]);
    expect("checked", &[]);
    expect("dropped", &["object_id"]);
    expect("label_only", &["id"]);
    expect("field_only", &["id"]);
    expect("positional", &["{}"]);
    expect("batched", &[]);
    expect("vault", &[]);
    assert!(
        got.iter().all(|(f, _)| f != "not_a_path"),
        "a filter literal is not a path: {got:?}"
    );

    // A unit is its own file or anything under its directory, never a sibling
    // that merely shares the prefix.
    let unit = "azapptoolkit-graph/src/client/applications";
    assert!(in_splice_unit(
        "azapptoolkit-graph/src/client/applications.rs",
        unit
    ));
    assert!(in_splice_unit(
        "azapptoolkit-graph/src/client/applications/owners.rs",
        unit
    ));
    assert!(!in_splice_unit(
        "azapptoolkit-graph/src/client/applications_extra.rs",
        unit
    ));
    assert!(in_splice_unit(
        "azapptoolkit-arm/src/client.rs",
        "azapptoolkit-arm/src"
    ));
}
