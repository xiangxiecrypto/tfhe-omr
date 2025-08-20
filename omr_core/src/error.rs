#[derive(thiserror::Error, Debug)]
pub enum OmrError {
    #[error("Matrix is not invertible")]
    InvertibleMatrix,
}
