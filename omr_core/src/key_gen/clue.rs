//! Clue key for sender-side clue encryption.

use algebra::utils::Size;
use fhe_core::{CmLweCiphertext, LweParameters, LwePublicKeyRlweMode};
use rand::{CryptoRng, Rng};

use crate::{ClueModulus, ClueValue};

/// RLWE public key used to encrypt the clue string.
pub struct ClueKey {
    key: LwePublicKeyRlweMode<ClueValue>,
    params: LweParameters<ClueValue, ClueModulus>,
}

impl ClueKey {
    /// Creates a new [`ClueKey`].
    #[inline]
    pub fn new(
        key: LwePublicKeyRlweMode<ClueValue>,
        params: LweParameters<ClueValue, ClueModulus>,
    ) -> Self {
        Self { key, params }
    }

    /// Generates a clue which contains `count` 0.
    #[inline]
    pub fn gen_clues<R>(&self, count: usize, rng: &mut R) -> CmLweCiphertext<ClueValue>
    where
        R: Rng + CryptoRng,
    {
        let messages = vec![0; count];
        self.key
            .encrypt_multi_messages(&messages, &self.params, rng)
    }
}

impl Size for ClueKey {
    #[inline]
    fn size(&self) -> usize {
        self.key.size()
    }
}
