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
    Token(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("url: {0}")]
    Url(#[from] url::ParseError),
}

impl From<serde_json::Error> for GraphError {
    fn from(value: serde_json::Error) -> Self {
        GraphError::Deserialize(value.to_string())
    }
}

impl GraphError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            GraphError::Throttled { .. } | GraphError::Server { .. } | GraphError::Network(_)
        )
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
            GraphError::Token(_) => "token_error",
            GraphError::Protocol(_) => "protocol_error",
            GraphError::Url(_) => "url_error",
        }
    }
}
