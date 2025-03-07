//! # OMR Core

mod parameters;
mod payload;
mod srlc;

mod lut;

mod detector;
mod key_gen;
mod retrieval;
mod sender;

pub use parameters::*;
pub use payload::{Payload, PAYLOAD_LENGTH};
pub use srlc::SrlcParams;

pub use lut::LookUpTable;

pub use detector::{DetectTimeInfo, DetectTimeInfoPerMessage, Detector};
pub use key_gen::{ClueKey, DetectionKey, KeyGen, SecretKeyPack};
pub use retrieval::{RetrievalParams, Retriever};
pub use sender::Sender;
