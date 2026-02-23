//! Error types for OMR core.

/// Errors returned by OMR core helpers.
#[derive(thiserror::Error, Debug)]
pub enum OmrError {
    #[error("Matrix is not invertible")]
    InvertibleMatrix,
}
