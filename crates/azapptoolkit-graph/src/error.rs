//! Graph client errors.
//!
//! The taxonomy is generated from [`azapptoolkit_core::http_error_enum`] — one
//! definition shared with `ArmError` and `KeyVaultError`, which were previously
//! three byte-for-byte identical hand-maintained copies. See that module for
//! why the duplication was a hazard and not just noise.

pub type Result<T> = std::result::Result<T, GraphError>;

azapptoolkit_core::http_error_enum! {
    /// Every failure mode of a Microsoft Graph call.
    pub enum GraphError {
        api_display = "graph error ({status}): {body}",
        api_code = "graph_error",
    }
}
