use algebra::utils::Size;
use fhe_core::CmLweCiphertext;
use rand::{CryptoRng, Rng};

use crate::{ClueKey, ClueValue};

/// The sender.
pub struct Sender {
    clue_key: ClueKey,
    clue_count: usize,
}

impl Sender {
    /// Creates a new [`Sender`].
    #[inline]
    pub fn new(clue_key: ClueKey, clue_count: usize) -> Self {
        Self {
            clue_key,
            clue_count,
        }
    }

    /// Generates clues.
    #[inline]
    pub fn gen_clues<R>(&self, rng: &mut R) -> CmLweCiphertext<ClueValue>
    where
        R: Rng + CryptoRng,
    {
        self.clue_key.gen_clues(self.clue_count, rng)
    }

    /// Returns the size of the clue key.
    #[inline]
    pub fn clue_key_size(&self) -> usize {
        self.clue_key.size()
    }
}
