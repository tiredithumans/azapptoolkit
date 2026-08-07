use thiserror::Error;

pub type Result<T> = std::result::Result<T, GraphError>;

#[derive(Debug, Error)]
pub enum GraphError {
    #[error("unauthorized (401)")]
    Unauthorized,

    #[error("forbidden (403): {0}")]
    Forbidden(String),

    #[error("not found (404): {0}")]
    NotFound(String),

    #[error("throttled (429); retry after {retry_after_secs:?}s")]
    Throttled { retry_after_secs: Option<u64> },

    #[error("server error ({status}): {body}")]
    Server { status: u16, body: String },

    #[error("graph error ({status}): {body}")]
    Api { status: u16, body: String },

    #[error("network: {0}")]
    Network(String),

    #[error("deserialize: {0}")]
    Deserialize(String),

    #[error("token: {0}")]
    Token(azapptoolkit_core::token::TokenError),

    #[error("protocol: {0}")]
    Protocol(String),
}

impl From<serde_json::Error> for GraphError {
    fn from(value: serde_json::Error) -> Self {
        GraphError::Deserialize(value.to_string())
    }
}

impl GraphError {
    /// Delegates to the shared policy — see
    /// [`azapptoolkit_core::http_retry::is_retryable_code`]. `ui_code` below is
    /// this crate's only variant-to-class table.
    pub fn is_retryable(&self) -> bool {
        azapptoolkit_core::http_retry::is_retryable_code(self.ui_code())
    }

    pub fn ui_code(&self) -> &'static str {
        match self {
            GraphError::Unauthorized => "unauthorized",
            GraphError::Forbidden(_) => "forbidden",
            GraphError::NotFound(_) => "not_found",
            GraphError::Throttled { .. } => "throttled",
            GraphError::Server { .. } => "server_error",
            GraphError::Api { .. } => "graph_error",
            GraphError::Network(_) => "network_error",
            GraphError::Deserialize(_) => "deserialize_error",
            // Pass an auth classification through instead of flattening it:
            // `is_reauth_fatal` is what stops a long-running fan-out.
            GraphError::Token(t) => {
                azapptoolkit_core::reauth::passthrough_code(&t.code).unwrap_or("token_error")
            }
            GraphError::Protocol(_) => "protocol_error",
        }
    }
}
