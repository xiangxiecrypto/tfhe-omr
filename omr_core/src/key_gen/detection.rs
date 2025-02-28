use algebra::{modulus::ShoupFactor, Field};
use fhe_core::{BlindRotationKey, NonPowOf2LweKeySwitchingKey, TraceKey};

use crate::{ClueModulus, FirstLevelField, OmrParameters, SecondLevelField};

/// tfhe omr's detection key.
pub struct DetectionKey {
    first_level_blind_rotation_key: BlindRotationKey<FirstLevelField>,
    first_level_key_switching_key: NonPowOf2LweKeySwitchingKey<<FirstLevelField as Field>::ValueT>,
    second_level_blind_rotation_key: BlindRotationKey<SecondLevelField>,
    second_level_ring_dimension_inv: ShoupFactor<<SecondLevelField as Field>::ValueT>,
    trace_key: TraceKey<SecondLevelField>,
    params: OmrParameters,
}

impl DetectionKey {
    /// Creates a new [`DetectionKey`].
    #[inline]
    pub fn new(
        first_level_blind_rotation_key: BlindRotationKey<FirstLevelField>,
        first_level_key_switching_key: NonPowOf2LweKeySwitchingKey<
            <FirstLevelField as Field>::ValueT,
        >,
        second_level_blind_rotation_key: BlindRotationKey<SecondLevelField>,
        second_level_ring_dimension_inv: ShoupFactor<<SecondLevelField as Field>::ValueT>,
        trace_key: TraceKey<SecondLevelField>,
        params: OmrParameters,
    ) -> Self {
        Self {
            first_level_blind_rotation_key,
            first_level_key_switching_key,
            second_level_blind_rotation_key,
            second_level_ring_dimension_inv,
            trace_key,
            params,
        }
    }

    /// Returns the clue modulus of this [`DetectionKey`].
    pub fn clue_modulus(&self) -> ClueModulus {
        self.params.clue_params().cipher_modulus
    }

    /// Returns a reference to the first level blind rotation key of this [`DetectionKey`].
    pub fn first_level_blind_rotation_key(&self) -> &BlindRotationKey<FirstLevelField> {
        &self.first_level_blind_rotation_key
    }

    /// Returns a reference to the first level key switching key of this [`DetectionKey`].
    pub fn first_level_key_switching_key(
        &self,
    ) -> &NonPowOf2LweKeySwitchingKey<<FirstLevelField as Field>::ValueT> {
        &self.first_level_key_switching_key
    }

    /// Returns a reference to the second level blind rotation key of this [`DetectionKey`].
    pub fn second_level_blind_rotation_key(&self) -> &BlindRotationKey<SecondLevelField> {
        &self.second_level_blind_rotation_key
    }

    /// Returns a reference to the trace key of this [`DetectionKey`].
    pub fn trace_key(&self) -> &TraceKey<SecondLevelField> {
        &self.trace_key
    }

    /// Returns a reference to the params of this [`DetectionKey`].
    pub fn params(&self) -> &OmrParameters {
        &self.params
    }

    /// Returns the second level ring dimension inv of this [`DetectionKey`].
    pub fn second_level_ring_dimension_inv(
        &self,
    ) -> ShoupFactor<<SecondLevelField as Field>::ValueT> {
        self.second_level_ring_dimension_inv
    }
}
