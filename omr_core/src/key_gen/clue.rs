use fhe_core::{CmLweCiphertext, LweParameters, LwePublicKeyRlweMode};
use rand::{CryptoRng, Rng};

use crate::{LweModulus, LweValue};

/// The clue key.
pub struct ClueKey {
    key: LwePublicKeyRlweMode<LweValue>,
    params: LweParameters<LweValue, LweModulus>,
}

impl ClueKey {
    /// Creates a new [`ClueKey`].
    #[inline]
    pub fn new(
        key: LwePublicKeyRlweMode<LweValue>,
        params: LweParameters<LweValue, LweModulus>,
    ) -> Self {
        Self { key, params }
    }

    /// Generates a clue which contains `count` 0.
    #[inline]
    pub fn gen_clues<R>(&self, count: usize, rng: &mut R) -> CmLweCiphertext<LweValue>
    where
        R: Rng + CryptoRng,
    {
        let messages = vec![0; count];
        self.key
            .encrypt_multi_messages(&messages, &self.params, rng)
    }
}
