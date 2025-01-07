use algebra::{
    decompose::NonPowOf2ApproxSignedBasis, modulus::PowOf2Modulus, random::DiscreteGaussian, Field,
    NttField, U32FieldEval, U64FieldEval,
};
use fhe_core::{GadgetRlweParameters, KeySwitchingParameters, LweParameters, RingSecretKeyType};

pub type LweValue = u16;
pub type LweModulus = PowOf2Modulus<LweValue>;
pub type FirstLevelField = U32FieldEval<134215681>;
pub type SecondLevelField = U64FieldEval<18014398509404161>;

/// Parameters for omr.
#[derive(Clone)]
pub struct OmrParameters {
    clue_params: LweParameters<LweValue, LweModulus>,
    first_level_blind_rotation_params: GadgetRlweParameters<FirstLevelField>,
    first_level_key_switching_params: KeySwitchingParameters,
    intermediate_lwe_params: LweParameters<LweValue, LweModulus>,
    second_level_blind_rotation_params: GadgetRlweParameters<SecondLevelField>,
    trace_params: GadgetRlweParameters<SecondLevelField>,
}

impl OmrParameters {
    #[inline]
    pub fn clue_params(&self) -> &LweParameters<LweValue, LweModulus> {
        &self.clue_params
    }

    #[inline]
    pub fn first_level_blind_rotation_params(&self) -> GadgetRlweParameters<FirstLevelField> {
        self.first_level_blind_rotation_params
    }

    #[inline]
    pub fn first_level_ring_dimension(&self) -> usize {
        self.first_level_blind_rotation_params.dimension
    }

    #[inline]
    pub fn first_level_ring_secret_key_type(&self) -> RingSecretKeyType {
        self.first_level_blind_rotation_params.secret_key_type
    }

    #[inline]
    pub fn first_level_noise_distribution(
        &self,
    ) -> DiscreteGaussian<<FirstLevelField as Field>::ValueT> {
        self.first_level_blind_rotation_params.noise_distribution()
    }

    #[inline]
    pub fn first_level_blind_rotation_basis(
        &self,
    ) -> &NonPowOf2ApproxSignedBasis<<FirstLevelField as Field>::ValueT> {
        self.first_level_blind_rotation_params.basis()
    }

    #[inline]
    pub fn generate_first_level_ntt_table(&self) -> <FirstLevelField as NttField>::Table {
        FirstLevelField::generate_ntt_table(
            self.first_level_blind_rotation_params
                .dimension
                .trailing_zeros(),
        )
        .unwrap()
    }

    #[inline]
    pub fn first_level_key_switching_params(&self) -> KeySwitchingParameters {
        self.first_level_key_switching_params
    }

    #[inline]
    pub fn intermediate_lwe_params(&self) -> &LweParameters<LweValue, LweModulus> {
        &self.intermediate_lwe_params
    }

    #[inline]
    pub fn second_level_blind_rotation_params(&self) -> GadgetRlweParameters<SecondLevelField> {
        self.second_level_blind_rotation_params
    }

    #[inline]
    pub fn second_level_ring_dimension(&self) -> usize {
        self.second_level_blind_rotation_params.dimension
    }

    #[inline]
    pub fn second_level_ring_secret_key_type(&self) -> RingSecretKeyType {
        self.second_level_blind_rotation_params.secret_key_type
    }

    #[inline]
    pub fn second_level_blind_rotation_basis(
        &self,
    ) -> &NonPowOf2ApproxSignedBasis<<SecondLevelField as Field>::ValueT> {
        self.second_level_blind_rotation_params.basis()
    }

    #[inline]
    pub fn second_level_ring_noise_distribution(
        &self,
    ) -> DiscreteGaussian<<SecondLevelField as Field>::ValueT> {
        DiscreteGaussian::new(
            0.0,
            self.second_level_blind_rotation_params
                .noise_standard_deviation,
            SecondLevelField::MINUS_ONE,
        )
        .unwrap()
    }

    #[inline]
    pub fn generate_second_level_ntt_table(&self) -> <SecondLevelField as NttField>::Table {
        SecondLevelField::generate_ntt_table(
            self.second_level_blind_rotation_params
                .dimension
                .trailing_zeros(),
        )
        .unwrap()
    }

    #[inline]
    pub fn trace_params(&self) -> GadgetRlweParameters<SecondLevelField> {
        self.trace_params
    }
}
