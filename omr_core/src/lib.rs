//! # OMR Core
//!
//! Core implementation of InstantOMR. The `Sender` encrypts clue strings, the
//! `Detector` performs two-layer TFHE functional bootstrapping plus homomorphic
//! trace to mark pertinent messages, then uses RLWE encoding to build a digest.
//! The `Retriever` decodes that digest into indices and payloads.

mod error;

mod parameters;
mod payload;

mod lut;
pub(crate) mod matrix;

mod detector;
mod key_gen;
pub mod retriever;
mod sender;

pub use error::OmrError;

pub use parameters::*;
pub use payload::{Payload, PAYLOAD_LENGTH};

pub use lut::LookUpTable;

pub use detector::{DetectTimeInfo, DetectTimeInfoPerMessage, Detector};
pub use key_gen::{ClueKey, DetectionKey, KeyGen, SecretKeyPack};
pub use retriever::Retriever;
pub use sender::Sender;
