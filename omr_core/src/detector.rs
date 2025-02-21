use algebra::{
    integer::{AsFrom, AsInto},
    ntt::{NttTable, NumberTheoryTransform},
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    reduce::{ModulusValue, Reduce, ReduceAddAssign},
    Field,
};
use fhe_core::{
    lwe_modulus_switch, lwe_modulus_switch_assign, CmLweCiphertext, LweCiphertext, RlweCiphertext,
};
use lattice::NttRlwe;
use num_traits::{ConstOne, Zero};
use rand::prelude::Distribution;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tracing::{trace, trace_span};

use crate::{
    ClueValue, DetectionKey, FirstLevelField, InterLweValue, LookUpTable, RetrievalParams,
    SecondLevelField,
};

/// The detector for OMR.
pub struct Detector {
    detection_key: DetectionKey,
}

impl Detector {
    /// Creates a new [`Detector`].
    #[inline]
    pub fn new(detection_key: DetectionKey) -> Self {
        Self { detection_key }
    }

    /// Detects the message from the given clues.
    pub fn detect(&self, clues: &CmLweCiphertext<ClueValue>) -> RlweCiphertext<SecondLevelField> {
        let span = trace_span!("detect");
        let _enter = span.enter();

        let params = self.detection_key.params();
        let clue_params = params.clue_params();
        let first_level_ring_dimension = params.first_level_ring_dimension();

        let msg_count = clues.msg_count();
        let clue_modulus = self.detection_key.clue_modulus();
        let first_level_blind_rotation_key = self.detection_key.first_level_blind_rotation_key();
        let intermediate_lwe_params = params.intermediate_lwe_params();
        let intermediate_plain_modulus = intermediate_lwe_params.plain_modulus_value;
        let second_level_blind_rotation_key = self.detection_key.second_level_blind_rotation_key();

        // Extract clues
        let mut clues: Vec<LweCiphertext<ClueValue>> = clues.extract_all(clue_modulus);

        // Modulus switching
        if clue_params.cipher_modulus_value
            != ModulusValue::PowerOf2(first_level_ring_dimension as ClueValue * 2)
        {
            trace!("Modulus switching clues to 2*N_1");
            clues.iter_mut().for_each(|clue| {
                lwe_modulus_switch_assign(
                    clue,
                    clue_params.cipher_modulus_value,
                    first_level_ring_dimension as ClueValue * 2,
                );
            });
        }

        // Generate first level LUT
        let lut1 = first_level_lut(
            first_level_ring_dimension,
            clue_params.plain_modulus_value.as_into(),
            intermediate_plain_modulus as usize,
        );

        // First level blind rotation and sum
        let intermedia = clues
            .par_iter()
            .map(|c| {
                let span = trace_span!("First level blind rotation");
                let _enter = span.enter();
                first_level_blind_rotation_key.blind_rotate(lut1.clone(), c)
            })
            .reduce(
                || <RlweCiphertext<FirstLevelField>>::zero(first_level_ring_dimension),
                |acc, c| acc.add_element_wise(&c),
            );
        // let intermedia = clues
        //     .iter()
        //     .map(|c| {
        //         let span = trace_span!("First level blind rotation");
        //         let _enter = span.enter();
        //         first_level_blind_rotation_key.blind_rotate(lut1.clone(), c)
        //     })
        //     .fold(
        //         <RlweCiphertext<FirstLevelField>>::zero(first_level_ring_dimension),
        //         |acc, c| acc.add_element_wise(&c),
        //     );

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
            trace!("Modulus switching clues to 2*N_2");
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
        let br_span = trace_span!("Second level blind rotation");
        let mut second_level_result =
            br_span.in_scope(|| second_level_blind_rotation_key.blind_rotate(lut2, &intermedia));
        // let mut second_level_result =
        //     second_level_blind_rotation_key.blind_rotate(lut2, &intermedia);

        // Multiply by `n_inv`
        let n_inv = self.detection_key.second_level_ring_dimension_inv();
        second_level_result.a_mut().mul_shoup_scalar_assign(n_inv);
        second_level_result.b_mut().mul_shoup_scalar_assign(n_inv);

        // Homomorphic Trace
        self.detection_key.trace_key().trace(&second_level_result)
    }

    pub fn generate_retrieval_ciphertext(
        &self,
        retrieval_params: RetrievalParams<SecondLevelField>,
        detect_list: &[RlweCiphertext<SecondLevelField>],
    ) -> NttRlwe<SecondLevelField> {
        let ntt_table = self
            .detection_key
            .second_level_blind_rotation_key()
            .ntt_table();
        let polynomial_size = retrieval_params.polynomial_size();
        assert_eq!(polynomial_size, ntt_table.dimension());

        let slots_per_budget = retrieval_params.slots_per_budget();
        let slots_per_retrieval = retrieval_params.slots_per_retrieval();
        let budget_distr = retrieval_params.budget_distr();

        let index_slots_per_budget = slots_per_budget - 1;
        let index_modulus = retrieval_params.index_modulus();

        let mask = index_modulus - 1;
        let shift_bits = index_modulus.trailing_zeros();

        let mut rng = rand::thread_rng();

        let mut poly: FieldPolynomial<SecondLevelField> = FieldPolynomial::zero(polynomial_size);
        let mut ntt_poly: FieldNttPolynomial<SecondLevelField> =
            FieldNttPolynomial::zero(polynomial_size);

        let mut ciphertext: NttRlwe<SecondLevelField> = NttRlwe::zero(polynomial_size);
        let mut temp: NttRlwe<SecondLevelField> = NttRlwe::zero(polynomial_size);

        detect_list.iter().enumerate().for_each(|(i, detect)| {
            poly.set_zero();

            poly.as_mut_slice()
                .chunks_exact_mut(slots_per_retrieval)
                .zip(budget_distr.sample_iter(&mut rng))
                .for_each(
                    |(chunk, budget_index): (&mut [<SecondLevelField as Field>::ValueT], usize)| {
                        let mut i: <SecondLevelField as Field>::ValueT = AsFrom::as_from(i);
                        let address = budget_index * slots_per_budget;

                        let mut k = 0;
                        while !i.is_zero() {
                            chunk[address + k] = i & mask;
                            i >>= shift_bits;
                            k += 1;
                        }

                        chunk[address + index_slots_per_budget] = ConstOne::ONE;
                    },
                );

            ntt_poly.copy_from(&poly);
            ntt_table.transform_slice(ntt_poly.as_mut_slice());

            detect.mul_ntt_polynomial_inplace(&ntt_poly, ntt_table, &mut temp);
            ciphertext.add_assign_element_wise(&temp);
        });

        ciphertext
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
