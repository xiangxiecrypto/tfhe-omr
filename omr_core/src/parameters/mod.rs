use algebra::{
    decompose::NonPowOf2ApproxSignedBasis, modulus::PowOf2Modulus, random::DiscreteGaussian, Field,
    NttField, U32FieldEval, U64FieldEval,
};
use fhe_core::{
    GadgetRlweParameters, KeySwitchingParameters, LweParameters, LweSecretKeyType,
    RingSecretKeyType,
};

pub type LweValue = u16;
pub type LweModulus = PowOf2Modulus<LweValue>;
pub type FirstLevelField = U32FieldEval<134215681>;
pub type InterLweValue = <FirstLevelField as Field>::ValueT;
pub type InterLweModulus = PowOf2Modulus<InterLweValue>;
pub type SecondLevelField = U64FieldEval<18014398509404161>;
pub type OutputValue = <SecondLevelField as Field>::ValueT;

/// Parameters for omr.
#[derive(Clone)]
pub struct OmrParameters {
    clue_params: LweParameters<LweValue, LweModulus>,
    clue_count: usize,
    first_level_blind_rotation_params: GadgetRlweParameters<FirstLevelField>,
    first_level_key_switching_params: KeySwitchingParameters,
    intermediate_lwe_params: LweParameters<InterLweValue, InterLweModulus>,
    second_level_blind_rotation_params: GadgetRlweParameters<SecondLevelField>,
    trace_params: GadgetRlweParameters<SecondLevelField>,
    output_plain_modulus_value: OutputValue,
}

impl OmrParameters {
    pub fn new() -> OmrParameters {
        let clue_params = <LweParameters<LweValue, LweModulus>>::new(
            512,
            8,
            <PowOf2Modulus<LweValue>>::new(2048),
            LweSecretKeyType::Binary,
            0.83,
        );

        let clue_count = 7;

        let first_level_blind_rotation_params = GadgetRlweParameters::<FirstLevelField> {
            dimension: 1024,
            modulus: 134215681,
            secret_key_type: RingSecretKeyType::Binary,
            noise_standard_deviation: 3.20,
            basis: NonPowOf2ApproxSignedBasis::new(134215681, 5, None),
        };

        let first_level_key_switching_params = KeySwitchingParameters {
            input_cipher_dimension: 1024,
            output_cipher_dimension: 1024,
            log_modulus: <FirstLevelField as Field>::ValueT::BITS
                - first_level_blind_rotation_params.modulus.leading_zeros(),
            log_basis: 10,
            reverse_length: None,
            noise_standard_deviation: 3.20,
        };

        let intermediate_lwe_params = <LweParameters<InterLweValue, InterLweModulus>>::new(
            1024,
            32,
            <PowOf2Modulus<InterLweValue>>::new(4096),
            LweSecretKeyType::Binary,
            9.15,
        );

        let second_level_blind_rotation_params = GadgetRlweParameters::<SecondLevelField> {
            dimension: 2048,
            modulus: 18014398509404161,
            secret_key_type: RingSecretKeyType::Ternary,
            noise_standard_deviation: 3.40,
            basis: NonPowOf2ApproxSignedBasis::new(18014398509404161, 6, None),
        };

        let trace_params = GadgetRlweParameters::<SecondLevelField> {
            dimension: 2048,
            modulus: 18014398509404161,
            secret_key_type: RingSecretKeyType::Ternary,
            noise_standard_deviation: 3.40,
            basis: NonPowOf2ApproxSignedBasis::new(18014398509404161, 2, None),
        };

        let output_plain_modulus_value = 1 << 15;

        Self {
            clue_params,
            clue_count,
            first_level_blind_rotation_params,
            first_level_key_switching_params,
            intermediate_lwe_params,
            second_level_blind_rotation_params,
            trace_params,
            output_plain_modulus_value,
        }
    }

    #[inline]
    pub fn clue_params(&self) -> &LweParameters<LweValue, LweModulus> {
        &self.clue_params
    }

    #[inline]
    pub fn clue_count(&self) -> usize {
        self.clue_count
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
    pub fn intermediate_lwe_params(&self) -> &LweParameters<InterLweValue, InterLweModulus> {
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

    pub fn output_plain_modulus_value(&self) -> <SecondLevelField as Field>::ValueT {
        self.output_plain_modulus_value
    }
}
