use fhe_core::{BlindRotationKey, LweKeySwitchingKeyRlweMode, TraceKey};

use crate::{FirstLevelField, SecondLevelField};

pub struct DetectionKey {
    first_level_blind_rotation_key: BlindRotationKey<FirstLevelField>,
    first_level_key_switching_key: LweKeySwitchingKeyRlweMode<FirstLevelField>,
    second_level_blind_rotation_key: BlindRotationKey<SecondLevelField>,
    trace_key: TraceKey<SecondLevelField>,
}

impl DetectionKey {
    /// Creates a new [`DetectionKey`].
    #[inline]
    pub fn new(
        first_level_blind_rotation_key: BlindRotationKey<FirstLevelField>,
        first_level_key_switching_key: LweKeySwitchingKeyRlweMode<FirstLevelField>,
        second_level_blind_rotation_key: BlindRotationKey<SecondLevelField>,
        trace_key: TraceKey<SecondLevelField>,
    ) -> Self {
        Self {
            first_level_blind_rotation_key,
            first_level_key_switching_key,
            second_level_blind_rotation_key,
            trace_key,
        }
    }
}
