//! One definition of the HTTP client error taxonomy the four typed clients
//! share.
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
/// Generates the nine common variants, `is_retryable` (delegating to
/// [`crate::http_retry::is_retryable_code`]) and `ui_code` (the single
/// variant-to-wire-code table). The `Token` arm passes an auth classification
/// through via [`crate::reauth::passthrough_code`] rather than flattening it —
/// flattening is what once made `is_reauth_fatal` unfirable for every client
/// call, so a fan-out warned its way through a dead session and returned a
/// partial result the UI presented as complete.
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

            #[error("throttled (429); retry after {retry_after_secs:?}s")]
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
                    // Pass an auth classification through instead of flattening
                    // it: `is_reauth_fatal` is what stops a long-running fan-out.
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
