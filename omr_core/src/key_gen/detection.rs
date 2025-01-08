use algebra::{modulus::ShoupFactor, Field};
use fhe_core::{BlindRotationKey, LweKeySwitchingKeyRlweMode, TraceKey};

use crate::{FirstLevelField, LweModulus, OmrParameters, SecondLevelField};

pub struct DetectionKey {
    first_level_blind_rotation_key: BlindRotationKey<FirstLevelField>,
    first_level_key_switching_key: LweKeySwitchingKeyRlweMode<FirstLevelField>,
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
        first_level_key_switching_key: LweKeySwitchingKeyRlweMode<FirstLevelField>,
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

    pub fn clue_modulus(&self) -> LweModulus {
        self.params.clue_params().cipher_modulus
    }

    pub fn first_level_blind_rotation_key(&self) -> &BlindRotationKey<FirstLevelField> {
        &self.first_level_blind_rotation_key
    }

    pub fn first_level_key_switching_key(&self) -> &LweKeySwitchingKeyRlweMode<FirstLevelField> {
        &self.first_level_key_switching_key
    }

    pub fn second_level_blind_rotation_key(&self) -> &BlindRotationKey<SecondLevelField> {
        &self.second_level_blind_rotation_key
    }

    pub fn trace_key(&self) -> &TraceKey<SecondLevelField> {
        &self.trace_key
    }

    pub fn params(&self) -> &OmrParameters {
        &self.params
    }

    pub fn second_level_ring_dimension_inv(
        &self,
    ) -> ShoupFactor<<SecondLevelField as Field>::ValueT> {
        self.second_level_ring_dimension_inv
    }
}
