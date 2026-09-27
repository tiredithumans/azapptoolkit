//! One definition of the HTTP client error taxonomy the typed clients share:
//! Graph, ARM and Key Vault are instances of this macro. Exchange stays
//! hand-written because its `Forbidden { detail, had_diagnostics }` is a struct
//! variant the `extra` arm cannot express; `azapptoolkit-exchange`'s
//! `tests/error_conformance.rs` pins it to an instance of this macro instead.
//!
//! `GraphError`, `ArmError` and `KeyVaultError` were three hand-maintained
//! enums with byte-for-byte identical variants, identical `#[error(…)]`
//! strings, identical `ui_code()` arms and identical doc comments — differing
//! only in the name of the API-error variant's wire code (`graph_error` /
//! `arm_error` / `vault_error`) and, for Key Vault, one extra variant.
//!
//! That is a live hazard rather than mere repetition: `ui_code()` is what the
//! front end branches on and what `is_retryable`/`is_reauth_fatal` are computed
//! from, so a change made in two of the three files is a client whose 429s stop
//! being retried or whose dead session stops halting a fan-out. PR #195 fixed
//! exactly that class of bug by collapsing four retry loops onto
//! [`crate::http_retry`] and two re-auth classifiers onto [`crate::reauth`];
//! these enums are the copies it did not reach.
//!
//! The macro generates the shared shape. A crate supplies its API-error wording
//! and code, and any variants genuinely its own.

/// Defines a client error enum with the shared HTTP taxonomy.
///
/// Generates the ten common variants, `is_retryable` (delegating to
/// [`crate::http_retry::is_retryable_code`]) and `ui_code` (the single
/// variant-to-wire-code table). The `Token` arm passes every classified auth
/// code through via [`crate::reauth::passthrough_code`] rather than flattening
/// it — only the re-auth-fatal ones halt a fan-out; the rest (`consent_required`,
/// a refresh-time `network_error`) reach the UI's recovery action or the retry
/// policy. Flattening is what once made `is_reauth_fatal` unfirable for every
/// client call, so a fan-out warned its way through a dead session and returned
/// a partial result the UI presented as complete.
///
/// `ui_hint` is deliberately NOT generated: it is the one method that genuinely
/// differs per crate (each names a different Azure RBAC role from the
/// capabilities catalog), so each crate writes its own `impl` block.
///
/// ```ignore
/// azapptoolkit_core::http_error_enum! {
///     /// Errors from the Widget API.
///     pub enum WidgetError {
///         api_display = "widget error",
///         api_code = "widget_error",
///         extra {
///             /// Client-side name validation.
///             InvalidName(String) => "invalid_name", display = "invalid name: {0}",
///         }
///     }
/// }
/// ```
#[macro_export]
macro_rules! http_error_enum {
    (
        $(#[$enum_meta:meta])*
        pub enum $name:ident {
            api_display = $api_display:literal,
            api_code = $api_code:literal
            $(, extra {
                $(
                    $(#[$vmeta:meta])*
                    $variant:ident($vty:ty) => $vcode:literal, display = $vdisplay:literal
                ),* $(,)?
            })?
            $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, ::thiserror::Error)]
        pub enum $name {
            #[error("unauthorized (401)")]
            Unauthorized,

            #[error("forbidden (403): {0}")]
            Forbidden(String),

            #[error("not found (404): {0}")]
            NotFound(String),

            #[error(
                "throttled (429): the service is limiting requests. {}, then try again.",
                $crate::http_error::ThrottleWait(*.retry_after_secs)
            )]
            Throttled { retry_after_secs: Option<u64> },

            #[error($api_display)]
            Api { status: u16, body: String },

            #[error("server error ({status}): {body}")]
            Server { status: u16, body: String },

            #[error("network: {0}")]
            Network(String),

            #[error("deserialize: {0}")]
            Deserialize(String),

            /// Carries the auth classification across the `BearerProvider`
            /// boundary. A bare `String` here is what made `is_reauth_fatal`
            /// unfirable for every client call.
            #[error("token: {0}")]
            Token($crate::token::TokenError),

            /// Client-side contract violation — e.g. a paging `nextLink`
            /// pointing off this API's origin, refused before the bearer is
            /// attached.
            #[error("protocol: {0}")]
            Protocol(String),

            $($(
                $(#[$vmeta])*
                #[error($vdisplay)]
                $variant($vty),
            )*)?
        }

        impl $name {
            /// Delegates to the shared policy — see
            /// [`azapptoolkit_core::http_retry::is_retryable_code`]. `ui_code`
            /// is the only variant-to-class table.
            pub fn is_retryable(&self) -> bool {
                $crate::http_retry::is_retryable_code(self.ui_code())
            }

            /// The stable wire code the front end branches on.
            pub fn ui_code(&self) -> &'static str {
                match self {
                    $name::Unauthorized => "unauthorized",
                    $name::Forbidden(_) => "forbidden",
                    $name::NotFound(_) => "not_found",
                    $name::Throttled { .. } => "throttled",
                    $name::Api { .. } => $api_code,
                    $name::Server { .. } => "server_error",
                    $name::Network(_) => "network_error",
                    $name::Deserialize(_) => "deserialize_error",
                    // Pass every classified auth code through instead of
                    // flattening it: the fatal ones stop a long-running fan-out,
                    // the rest reach their recovery action / the retry policy.
                    $name::Token(t) => {
                        $crate::reauth::passthrough_code(&t.code).unwrap_or("token_error")
                    }
                    $name::Protocol(_) => "protocol_error",
                    $($( $name::$variant(_) => $vcode, )*)?
                }
            }
        }

        impl From<::serde_json::Error> for $name {
            fn from(value: ::serde_json::Error) -> Self {
                $name::Deserialize(value.to_string())
            }
        }
    };
}

/// The operator-facing wait for a throttled request's `Retry-After`, shared by
/// [`http_error_enum!`] and the hand-written `ExchangeError` so the two Display
/// strings cannot drift (`azapptoolkit-exchange/tests/error_conformance.rs`
/// pins them equal).
///
/// It exists because the old `{retry_after_secs:?}` interpolation printed the
/// Rust `Option` Debug form — "retry after Some(30)s" / "retry after Nones" —
/// verbatim into the error the UI shows once the retries are spent.
pub struct ThrottleWait(pub Option<u64>);

impl std::fmt::Display for ThrottleWait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            None | Some(0) => f.write_str("Wait a moment"),
            Some(1) => f.write_str("Wait 1 second"),
            Some(n) => write!(f, "Wait {n} seconds"),
        }
    }
}

/// Renders an error and every `source()` beneath it as one line:
/// `outer: cause: root cause`.
///
/// `reqwest` 0.12+ no longer appends its source chain to `Display`, so
/// `err.to_string()` on a failed send reads only "error sending request for
/// url (…)" whether the cause was DNS, a connect timeout, a refused port, a
/// proxy or a TLS interception failure — the one detail an operator behind a
/// corporate proxy needs. Dependency-free (core carries no `reqwest`, and the
/// WASM frontend depends on core): every client crate passes its concrete error
/// here.
///
/// A cause that is empty, or whose text the line already contains (hyper and
/// hyper-util often restate their inner error), is skipped; the walk stops
/// after [`MAX_ERROR_CHAIN_DEPTH`] levels as a guard against a cyclic chain.
pub fn describe_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut next = err.source();
    let mut depth = 0;
    while let Some(cause) = next {
        if depth >= MAX_ERROR_CHAIN_DEPTH {
            break;
        }
        let text = cause.to_string();
        if !text.is_empty() && !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        next = cause.source();
        depth += 1;
    }
    out
}

/// How many `source()` levels [`describe_error_chain`] follows.
pub const MAX_ERROR_CHAIN_DEPTH: usize = 8;

/// Upper bound, in characters, on an HTTP error body kept in a client error —
/// see [`sanitize_error_body`].
pub const ERROR_BODY_MAX_CHARS: usize = 800;

/// Normalizes an HTTP error-response body before it is stored in a client error
/// (and so before it reaches a `?err` log line or the UI's `UiError.message`).
///
/// Every client's error bodies go through here — Graph, ARM, Key Vault and
/// Exchange. Responses are sometimes binary or NUL-padded (a 403 from an
/// Exchange front-end proxy is a long run of `\0`), or a multi-megabyte HTML
/// block page from a proxy or WAF, which would otherwise land verbatim in the
/// rolling log and in a toast. Strips control characters (keeping ordinary
/// whitespace), trims, and caps the length at [`ERROR_BODY_MAX_CHARS`] with a
/// trailing `…`; returns `<no body>` when nothing printable remains.
pub fn sanitize_error_body(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return "<no body>".to_string();
    }
    let mut out: String = trimmed.chars().take(ERROR_BODY_MAX_CHARS).collect();
    if trimmed.chars().count() > ERROR_BODY_MAX_CHARS {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_wait_reads_as_plain_english() {
        for (secs, expected) in [
            (None, "Wait a moment"),
            (Some(0), "Wait a moment"),
            (Some(1), "Wait 1 second"),
            (Some(30), "Wait 30 seconds"),
        ] {
            assert_eq!(ThrottleWait(secs).to_string(), expected, "{secs:?}");
        }
    }

    #[derive(Debug)]
    struct Chain(&'static str, Option<Box<Chain>>);

    impl std::fmt::Display for Chain {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Chain {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1
                .as_deref()
                .map(|c| c as &(dyn std::error::Error + 'static))
        }
    }

    #[test]
    fn describe_error_chain_appends_each_cause_in_order() {
        let err = Chain(
            "error sending request for url (https://example.invalid/)",
            Some(Box::new(Chain(
                "client error (Connect)",
                Some(Box::new(Chain(
                    "tcp connect error: Connection refused",
                    None,
                ))),
            ))),
        );
        assert_eq!(
            describe_error_chain(&err),
            "error sending request for url (https://example.invalid/): \
             client error (Connect): tcp connect error: Connection refused"
        );
    }

    #[test]
    fn describe_error_chain_skips_empty_and_restated_causes() {
        let err = Chain(
            "dns error: no such host",
            Some(Box::new(Chain(
                "",
                Some(Box::new(Chain(
                    "no such host",
                    Some(Box::new(Chain("resolver gave up", None))),
                ))),
            ))),
        );
        assert_eq!(
            describe_error_chain(&err),
            "dns error: no such host: resolver gave up"
        );
        // A bare error is its own Display.
        assert_eq!(describe_error_chain(&Chain("plain", None)), "plain");
    }

    #[test]
    fn sanitize_error_body_strips_nul_padding_trims_and_caps() {
        // A NUL-padded 403 body (observed from an edge proxy) collapses to the
        // placeholder rather than a screenful of escaped \0 in the logs.
        assert_eq!(sanitize_error_body(&"\0".repeat(256)), "<no body>");
        assert_eq!(sanitize_error_body(""), "<no body>");
        // Control chars are stripped; ordinary text + whitespace survive trimmed.
        assert_eq!(sanitize_error_body("  Forbidden\0\u{7}  "), "Forbidden");
        assert_eq!(sanitize_error_body("line1\nline2"), "line1\nline2");
        // Over-long bodies are capped with an ellipsis marker.
        let out = sanitize_error_body(&"x".repeat(1000));
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), ERROR_BODY_MAX_CHARS + 1);
        // At the cap exactly, nothing is marked as truncated.
        let exact = "y".repeat(ERROR_BODY_MAX_CHARS);
        assert_eq!(sanitize_error_body(&exact), exact);
    }
}
