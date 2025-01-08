use algebra::{
    integer::AsInto,
    polynomial::FieldPolynomial,
    reduce::{ModulusValue, Reduce, ReduceAddAssign},
    Field,
};
use fhe_core::{
    lwe_modulus_switch, lwe_modulus_switch_assign, CmLweCiphertext, LweCiphertext, RlweCiphertext,
};
use rayon::prelude::*;

use crate::{
    DetectionKey, FirstLevelField, InterLweValue, LookUpTable, LweValue, SecondLevelField,
};

pub struct Detector {
    detection_key: DetectionKey,
}

impl Detector {
    #[inline]
    pub fn new(detection_key: DetectionKey) -> Self {
        Self { detection_key }
    }

    pub fn detect(&self, clues: &CmLweCiphertext<LweValue>) -> RlweCiphertext<SecondLevelField> {
        let params = self.detection_key.params();
        let clue_params = params.clue_params();
        let first_level_ring_dimension = params.first_level_ring_dimension();

        let msg_count = clues.msg_count();
        let clue_modulus = self.detection_key.clue_modulus();
        let first_level_blind_rotation_key = self.detection_key.first_level_blind_rotation_key();
        let intermediate_lwe_params = params.intermediate_lwe_params();
        let second_level_blind_rotation_key = self.detection_key.second_level_blind_rotation_key();

        // Extract clues
        let mut clues: Vec<LweCiphertext<LweValue>> = (0..msg_count)
            .map(|i| clues.extract_rlwe_mode(i, clue_modulus))
            .collect();

        // Modulus switching
        if clue_params.cipher_modulus_value
            != ModulusValue::PowerOf2(first_level_ring_dimension as LweValue * 2)
        {
            println!("Modulus switching clues");
            clues.iter_mut().for_each(|clue| {
                lwe_modulus_switch_assign(
                    clue,
                    clue_params.cipher_modulus_value,
                    first_level_ring_dimension as LweValue * 2,
                );
            });
        }

        let intermediate_plain_modulus = intermediate_lwe_params.plain_modulus_value; // Generate first level LUT
        let lut1 = first_level_lut(
            first_level_ring_dimension,
            clue_params.plain_modulus_value.as_into(),
            intermediate_plain_modulus as usize,
        );

        // First level blind rotation and sum
        let intermedia = clues
            .par_iter()
            .map(|c| first_level_blind_rotation_key.blind_rotate(lut1.clone(), c))
            .reduce(
                || <RlweCiphertext<FirstLevelField>>::zero(first_level_ring_dimension),
                |acc, c| acc.add_element_wise(&c),
            );

        // Key switching
        let intermedia = self
            .detection_key
            .first_level_key_switching_key()
            .key_switch_for_rlwe(intermedia);

        // Modulus switching
        let mut intermedia = lwe_modulus_switch(
            &intermedia,
            params.first_level_blind_rotation_params().modulus,
            intermediate_lwe_params.cipher_modulus_value,
        );

        let log_plain_modulus = intermediate_lwe_params.plain_modulus_value.trailing_zeros();

        let cipher_modulus = intermediate_lwe_params.cipher_modulus;

        // Add `msg_count`
        let scale = (msg_count as InterLweValue) * {
            match intermediate_lwe_params.cipher_modulus_value {
                ModulusValue::Native => 1 << (InterLweValue::BITS - log_plain_modulus),
                ModulusValue::PowerOf2(q) => q >> log_plain_modulus,
                ModulusValue::Prime(q) | ModulusValue::Others(q) => {
                    let temp = q >> (log_plain_modulus - 1);
                    (temp + 1) >> 1
                }
            }
        };
        cipher_modulus.reduce_add_assign(intermedia.b_mut(), cipher_modulus.reduce(scale));

        // Modulus switching
        if intermediate_lwe_params.cipher_modulus_value
            != ModulusValue::PowerOf2(params.second_level_ring_dimension() as InterLweValue * 2)
        {
            println!("Modulus switching intermediate");
            lwe_modulus_switch_assign(
                &mut intermedia,
                intermediate_lwe_params.cipher_modulus_value,
                params.second_level_ring_dimension() as InterLweValue * 2,
            );
        }

        let output_plain_modulus = params.output_plain_modulus_value();
        // Generate second level LUT
        let lut2 = second_level_lut(
            params.second_level_ring_dimension(),
            msg_count,
            intermediate_lwe_params.plain_modulus_value as usize,
            output_plain_modulus as usize,
        );

        // Second level blind rotation
        let mut second_level_result =
            second_level_blind_rotation_key.blind_rotate(lut2, &intermedia);

        // Multiply by `n_inv`
        let n_inv = self.detection_key.second_level_ring_dimension_inv();
        second_level_result.a_mut().mul_shoup_scalar_assign(n_inv);
        second_level_result.b_mut().mul_shoup_scalar_assign(n_inv);

        // Trace
        self.detection_key.trace_key().trace(&second_level_result)
    }
}

/// init lut for first level bootstrapping.
fn first_level_lut(
    rlwe_dimension: usize,
    input_plain_modulus: usize,
    output_plain_modulus: usize,
) -> FieldPolynomial<FirstLevelField> {
    let q = <FirstLevelField as Field>::MODULUS_VALUE;
    let log = output_plain_modulus.trailing_zeros() - 1;
    let scale_one = ((q >> log) + 1) >> 1;
    let scale_minus_one = q - scale_one;
    let log_plain_modulus = input_plain_modulus.trailing_zeros();

    [
        scale_one,
        FirstLevelField::ZERO,
        FirstLevelField::ZERO,
        FirstLevelField::ZERO,
        scale_minus_one,
    ]
    .negacyclic_lut(rlwe_dimension, log_plain_modulus)
}

/// init lut for second level bootstrapping.
fn second_level_lut(
    rlwe_dimension: usize,
    clue_count: usize,
    input_plain_modulus: usize,
    output_plain_modulus: usize,
) -> FieldPolynomial<SecondLevelField> {
    let q = <SecondLevelField as Field>::MODULUS_VALUE;
    let log = output_plain_modulus.trailing_zeros() - 1;
    let scale_one = ((q >> log) + 1) >> 1;
    let log_plain_modulus = input_plain_modulus.trailing_zeros();

    let mut data = vec![SecondLevelField::ZERO; input_plain_modulus];
    data[clue_count * 2] = scale_one;

    data.as_slice()
        .negacyclic_lut(rlwe_dimension, log_plain_modulus)
}
