use crate::OmrParameters;

mod clue;
mod detection;
mod secret;

use rand::{CryptoRng, Rng};

pub use clue::ClueKey;
pub use detection::DetectionKey;
pub use secret::SecretKeyPack;

/// Struct of key generation.
pub struct KeyGen;

impl KeyGen {
    #[inline]
    pub fn generate_secret_key<R>(params: OmrParameters, rng: &mut R) -> SecretKeyPack
    where
        R: Rng + CryptoRng,
    {
        SecretKeyPack::new(params, rng)
    }
}
