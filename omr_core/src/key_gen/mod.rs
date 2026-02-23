//! Key generation wrappers for OMR keys.

use crate::OmrParameters;

mod clue;
mod detection;
mod secret;

use rand::{CryptoRng, Rng};

pub use clue::ClueKey;
pub use detection::DetectionKey;
pub use secret::SecretKeyPack;

/// Key generation entry point.
pub struct KeyGen;

impl KeyGen {
    /// Generates secret key pack.
    #[inline]
    pub fn generate_secret_key<R>(params: OmrParameters, rng: &mut R) -> SecretKeyPack
    where
        R: Rng + CryptoRng,
    {
        SecretKeyPack::new(params, rng)
    }
}
