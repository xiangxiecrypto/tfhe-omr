use fhe_core::{LweParameters, LwePublicKeyRlweMode};

use crate::{LweModulus, LweValue};

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
}
