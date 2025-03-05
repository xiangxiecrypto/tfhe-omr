use std::{
    ops::Add,
    time::{Duration, Instant},
};

use algebra::{
    integer::{AsFrom, AsInto},
    modulus::ShoupFactor,
    ntt::{NttTable, NumberTheoryTransform},
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    reduce::{ModulusValue, Reduce, ReduceAddAssign},
    Field,
};
use fhe_core::{
    lwe_modulus_switch, lwe_modulus_switch_assign, BlindRotationKey, CmLweCiphertext,
    LweCiphertext, NonPowOf2LweKeySwitchingKey, RlweCiphertext, TraceKey,
};
use lattice::NttRlwe;
use num_traits::{ConstOne, Zero};
use rand::prelude::*;

use crate::{
    ClueValue, DetectionKey, FirstLevelField, InterLweValue, LookUpTable, OmrParameters,
    RetrievalParams, SecondLevelField,
};

/// The detector for OMR.
pub struct Detector {
    detection_key: DetectionKey,
    first_level_lut: FieldPolynomial<FirstLevelField>,
    second_level_lut: FieldPolynomial<SecondLevelField>,
}

/// Time information for detecting a message.
#[derive(Debug, Clone, Copy, Default)]
pub struct DetectTimeInfoPerMessage {
    pub detect_time: Duration,
    pub first_level_bootstrapping_time: Duration,
    pub second_level_bootstrapping_time: Duration,
    pub trace_time: Duration,
}

/// Time information for detecting messages.
#[derive(Debug, Clone, Copy, Default)]
pub struct DetectTimeInfo {
    pub total_detect_time: Duration,
    pub total_first_level_bootstrapping_time: Duration,
    pub total_second_level_bootstrapping_time: Duration,
    pub total_trace_time: Duration,
}

impl Add<DetectTimeInfoPerMessage> for DetectTimeInfo {
    type Output = Self;

    fn add(self, rhs: DetectTimeInfoPerMessage) -> Self::Output {
        Self {
            total_detect_time: self.total_detect_time + rhs.detect_time,
            total_first_level_bootstrapping_time: self.total_first_level_bootstrapping_time
                + rhs.first_level_bootstrapping_time,
            total_second_level_bootstrapping_time: self.total_second_level_bootstrapping_time
                + rhs.second_level_bootstrapping_time,
            total_trace_time: self.total_trace_time + rhs.trace_time,
        }
    }
}

impl DetectTimeInfoPerMessage {
    /// Creates a new [`DetectTimeInfoPerMessage`].
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }
}

impl Detector {
    /// Creates a new [`Detector`].
    #[inline]
    pub fn new(detection_key: DetectionKey) -> Self {
        let params = detection_key.params();

        let clue_count = params.clue_count();
        let clue_plain_modulus_value = params.clue_plain_modulus_value().as_into();
        let first_level_ring_dimension = params.first_level_ring_dimension();
        let intermediate_lwe_plain_modulus =
            params.intermediate_lwe_plain_modulus_value().as_into();
        let second_level_ring_dimension = params.second_level_ring_dimension();
        let output_plain_modulus_value = params.output_plain_modulus_value().as_into();

        Self {
            detection_key,
            first_level_lut: first_level_lut(
                first_level_ring_dimension,
                clue_plain_modulus_value,
                intermediate_lwe_plain_modulus,
            ),
            second_level_lut: second_level_lut(
                second_level_ring_dimension,
                clue_count,
                intermediate_lwe_plain_modulus,
                output_plain_modulus_value,
            ),
        }
    }

    /// Returns a reference to the detection key of this [`Detector`].
    #[inline]
    pub fn detection_key(&self) -> &DetectionKey {
        &self.detection_key
    }

    /// Returns a reference to the first level lut of this [`Detector`].
    #[inline]
    pub fn first_level_lut(&self) -> &FieldPolynomial<FirstLevelField> {
        &self.first_level_lut
    }

    /// Returns a reference to the second level lut of this [`Detector`].
    #[inline]
    pub fn second_level_lut(&self) -> &FieldPolynomial<SecondLevelField> {
        &self.second_level_lut
    }

    /// Detects the message from the given clues.
    pub fn detect(&self, clues: &CmLweCiphertext<ClueValue>) -> RlweCiphertext<SecondLevelField> {
        let params = self.detection_key.params();

        let clues = extract_clues_and_modulus_switch(clues, params);

        let intermediate = first_level_bootstrapping(
            &clues,
            self.detection_key.first_level_blind_rotation_key(),
            self.detection_key.first_level_key_switching_key(),
            &self.first_level_lut,
            params,
        );

        let ciphertext = second_level_bootstrapping(
            intermediate,
            self.detection_key.second_level_blind_rotation_key(),
            &self.second_level_lut,
            params,
        );

        hom_trace(
            ciphertext,
            self.detection_key.trace_key(),
            self.detection_key.second_level_ring_dimension_inv(),
        )
    }

    /// Detects the message from the given clues.
    pub fn detect_with_time_info(
        &self,
        clues: &CmLweCiphertext<ClueValue>,
    ) -> (RlweCiphertext<SecondLevelField>, DetectTimeInfoPerMessage) {
        let time_0 = Instant::now();

        let params = self.detection_key.params();
        let clues = extract_clues_and_modulus_switch(clues, params);

        let time_1 = Instant::now();

        let intermediate = first_level_bootstrapping(
            &clues,
            self.detection_key.first_level_blind_rotation_key(),
            self.detection_key.first_level_key_switching_key(),
            &self.first_level_lut,
            params,
        );

        let time_2 = Instant::now();

        let ciphertext = second_level_bootstrapping(
            intermediate,
            self.detection_key.second_level_blind_rotation_key(),
            &self.second_level_lut,
            params,
        );

        let time_3 = Instant::now();

        let result = hom_trace(
            ciphertext,
            self.detection_key.trace_key(),
            self.detection_key.second_level_ring_dimension_inv(),
        );

        let time_4 = Instant::now();

        let time_info = DetectTimeInfoPerMessage {
            detect_time: time_4 - time_0,
            first_level_bootstrapping_time: time_2 - time_1,
            second_level_bootstrapping_time: time_3 - time_2,
            trace_time: time_4 - time_3,
        };

        (result, time_info)
    }

    pub fn compress_pertivency_vector(
        &self,
        retrieval_params: RetrievalParams<SecondLevelField>,
        pertivency_vector: &[RlweCiphertext<SecondLevelField>],
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

        pertivency_vector
            .iter()
            .enumerate()
            .for_each(|(i, detect)| {
                poly.set_zero();

                poly.as_mut_slice()
                    .chunks_exact_mut(slots_per_retrieval)
                    .zip(budget_distr.sample_iter(&mut rng))
                    .for_each(
                        |(chunk, budget_index): (
                            &mut [<SecondLevelField as Field>::ValueT],
                            usize,
                        )| {
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
pub fn first_level_lut(
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
pub fn second_level_lut(
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

fn extract_clues_and_modulus_switch(
    clues: &CmLweCiphertext<ClueValue>,
    params: &OmrParameters,
) -> Vec<LweCiphertext<ClueValue>> {
    let clue_count = params.clue_count();
    assert_eq!(clue_count, clues.msg_count(), "Invalid clue count.");

    // Extract clues
    let mut clues: Vec<LweCiphertext<ClueValue>> = clues.extract_all(params.clue_cipher_modulus());

    let clue_cipher_modulus_value = params.clue_cipher_modulus_value();
    let first_level_ring_dimension = params.first_level_ring_dimension();

    // Modulus switching to `2 * N_1`
    let twice_first_level_ring_dimension = first_level_ring_dimension as ClueValue * 2;
    if clue_cipher_modulus_value != ModulusValue::PowerOf2(twice_first_level_ring_dimension) {
        clues.iter_mut().for_each(|clue| {
            lwe_modulus_switch_assign(
                clue,
                clue_cipher_modulus_value,
                twice_first_level_ring_dimension,
            );
        });
    }
    clues
}

fn first_level_bootstrapping(
    clues: &[LweCiphertext<ClueValue>],
    blind_rotation_key: &BlindRotationKey<FirstLevelField>,
    key_switching_key: &NonPowOf2LweKeySwitchingKey<<FirstLevelField as Field>::ValueT>,
    lut: &FieldPolynomial<FirstLevelField>,
    params: &OmrParameters,
) -> LweCiphertext<InterLweValue> {
    let first_level_ring_dimension = params.first_level_ring_dimension();

    // First level blind rotation and sum
    // use rayon::prelude::*;
    // let intermediate = clues
    //     .par_iter()
    //     .map(|c| blind_rotation_key.blind_rotate(lut.clone(), c))
    //     .reduce(
    //         || <RlweCiphertext<FirstLevelField>>::zero(first_level_ring_dimension),
    //         |acc, c| acc.add_element_wise(&c),
    //     );
    let intermediate = clues
        .iter()
        .map(|c| blind_rotation_key.blind_rotate(lut.clone(), c))
        .reduce(|acc, ele| acc.add_element_wise(&ele))
        .unwrap_or_else(|| <RlweCiphertext<FirstLevelField>>::zero(first_level_ring_dimension));

    // Key switching
    let intermediate = key_switching_key.key_switch(
        &intermediate.extract_lwe_locally(),
        FirstLevelField::MODULUS,
    );

    let intermediate_lwe_params = params.intermediate_lwe_params();
    let intermediate_cipher_modulus_value = intermediate_lwe_params.cipher_modulus_value;
    let intermediate_cipher_modulus = intermediate_lwe_params.cipher_modulus;
    let intermediate_plain_modulus_value = intermediate_lwe_params.plain_modulus_value;

    // Modulus switching
    let mut intermediate = lwe_modulus_switch(
        &intermediate,
        params.first_level_blind_rotation_params().modulus,
        intermediate_cipher_modulus_value,
    );

    let log_plain_modulus = intermediate_plain_modulus_value.trailing_zeros();

    // Add `clue count`
    let clue_count = params.clue_count();
    let scale = (clue_count as InterLweValue) * {
        match intermediate_cipher_modulus_value {
            ModulusValue::Native => 1 << (InterLweValue::BITS - log_plain_modulus),
            ModulusValue::PowerOf2(q) => q >> log_plain_modulus,
            ModulusValue::Prime(q) | ModulusValue::Others(q) => {
                let temp = q >> (log_plain_modulus - 1);
                (temp + 1) >> 1
            }
        }
    };
    intermediate_cipher_modulus.reduce_add_assign(
        intermediate.b_mut(),
        intermediate_cipher_modulus.reduce(scale),
    );

    intermediate
}

fn second_level_bootstrapping(
    mut intermediate: LweCiphertext<InterLweValue>,
    blind_rotation_key: &BlindRotationKey<SecondLevelField>,
    lut: &FieldPolynomial<SecondLevelField>,
    params: &OmrParameters,
) -> RlweCiphertext<SecondLevelField> {
    let intermediate_cipher_modulus_value = params.intermediate_lwe_params().cipher_modulus_value;
    let second_level_ring_dimension = params.second_level_ring_dimension();

    // Modulus switching
    let twice_second_level_ring_dimension = second_level_ring_dimension as InterLweValue * 2;
    if intermediate_cipher_modulus_value
        != ModulusValue::PowerOf2(twice_second_level_ring_dimension)
    {
        lwe_modulus_switch_assign(
            &mut intermediate,
            intermediate_cipher_modulus_value,
            twice_second_level_ring_dimension,
        );
    }

    // Second level blind rotation
    blind_rotation_key.blind_rotate(lut.clone(), &intermediate)
}

fn hom_trace(
    mut ciphertext: RlweCiphertext<SecondLevelField>,
    trace_key: &TraceKey<SecondLevelField>,
    n_inv: ShoupFactor<<SecondLevelField as Field>::ValueT>,
) -> RlweCiphertext<SecondLevelField> {
    // Multiply by `n_inv`
    ciphertext.a_mut().mul_shoup_scalar_assign(n_inv);
    ciphertext.b_mut().mul_shoup_scalar_assign(n_inv);
    // Homomorphic Trace
    trace_key.trace(&ciphertext)
}
