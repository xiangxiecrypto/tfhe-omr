//! Detector pipeline: two-layer TFHE bootstrapping + homomorphic trace.

use std::{
    ops::Add,
    time::{Duration, Instant},
};

use bigdecimal::{BigDecimal, RoundingMode};
use num_traits::{ConstOne, FromPrimitive, ToPrimitive, Zero};
use rand::prelude::*;
use rand_distr::Uniform;
use rayon::prelude::*;

use algebra::{
    integer::{AsFrom, AsInto},
    modulus::{BarrettModulus, PowOf2Modulus, ShoupFactor},
    ntt::{NttTable, NumberTheoryTransform},
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    reduce::{ModulusValue, Reduce, ReduceDotProduct, ReduceSub},
    utils::Size,
    Field, NttField,
};
use fhe_core::{
    lwe_modulus_switch, lwe_modulus_switch_assign, BlindRotationKey, CmLweCiphertext,
    LweCiphertext, NonPowOf2LweKeySwitchingKey, NttRlweCiphertext, NttRlweSecretKey,
    RlweCiphertext, TraceKey,
};
use lattice::NttRlwe;

use crate::key_gen::SecretKeyPack;
use crate::lut::negacyclic_lut_from_sparse_values;
use crate::{
    payload::PayloadByteType, ClueValue, DetectNoiseInfo, DetectionKey, FirstLevelField,
    InterLweValue, NoiseByCoefficient, NoiseStats, OmrParameters, OutputValue, Payload,
    RetrievalParams, SecondLevelField, PAYLOAD_LENGTH,
};

/// Server-side detector that turns clues into a digest via bootstrapping + RLWE encoding.
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

    pub fn detect_key_size(&self) -> usize {
        self.detection_key.size()
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
    pub fn detect(
        &self,
        clues: &CmLweCiphertext<ClueValue>,
    ) -> NttRlweCiphertext<SecondLevelField> {
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
            self.detection_key
                .second_level_blind_rotation_key()
                .ntt_table(),
        )
    }

    /// Detects the message and returns noise statistics around the trace boundary.
    pub fn detect_with_noise_info(
        &self,
        clues: &CmLweCiphertext<ClueValue>,
        secret_key_pack: &SecretKeyPack,
    ) -> (NttRlweCiphertext<SecondLevelField>, DetectNoiseInfo) {
        let params = self.detection_key.params();
        let expected_intermediate = expected_intermediate_plaintext(clues, secret_key_pack, params);
        let second_level_key = secret_key_pack.second_level_ntt_rlwe_secret_key();
        let second_level_ntt_table = secret_key_pack.second_level_ntt_table();

        let clues = extract_clues_and_modulus_switch(clues, params);

        let intermediate = first_level_bootstrapping(
            &clues,
            self.detection_key.first_level_blind_rotation_key(),
            self.detection_key.first_level_key_switching_key(),
            &self.first_level_lut,
            params,
        );

        let mut after_first_level_bootstrapping = NoiseStats::default();
        if expected_intermediate == params.clue_count() as InterLweValue {
            after_first_level_bootstrapping.record(intermediate_lwe_noise(
                &intermediate,
                expected_intermediate,
                secret_key_pack,
                params,
            ));
        }

        let ciphertext = second_level_bootstrapping(
            intermediate,
            self.detection_key.second_level_blind_rotation_key(),
            &self.second_level_lut,
            params,
        );

        let after_second_level_bootstrapping = noise_by_coefficient(
            &decrypt_second_level_rlwe(&ciphertext, second_level_key, second_level_ntt_table),
            params.output_plain_modulus_value(),
        );

        let result = hom_trace(
            ciphertext,
            self.detection_key.trace_key(),
            self.detection_key.second_level_ring_dimension_inv(),
            self.detection_key
                .second_level_blind_rotation_key()
                .ntt_table(),
        );

        let after_hom_trace = noise_by_coefficient(
            &decrypt_second_level_ntt_rlwe(&result, second_level_key, second_level_ntt_table),
            params.output_plain_modulus_value(),
        );

        (
            result,
            DetectNoiseInfo {
                after_first_level_bootstrapping,
                after_second_level_bootstrapping,
                after_hom_trace,
            },
        )
    }

    /// Detects the message from the given clues.
    pub fn detect_with_time_info(
        &self,
        clues: &CmLweCiphertext<ClueValue>,
    ) -> (
        NttRlweCiphertext<SecondLevelField>,
        DetectTimeInfoPerMessage,
    ) {
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
            self.detection_key
                .second_level_blind_rotation_key()
                .ntt_table(),
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

    pub fn encode_pertinent_indices(
        &self,
        retrieval_params: RetrievalParams<SecondLevelField>,
        pertinency_vector: &[NttRlweCiphertext<SecondLevelField>],
    ) -> NttRlwe<SecondLevelField> {
        // Step 3c: RLWE-encode the indices of pertinent messages.
        // Encode each index into slots using base-(index_modulus) digits or bit chunks.
        const CHUNK_SIZE: usize = 2048;
        let ntt_table = self
            .detection_key
            .second_level_blind_rotation_key()
            .ntt_table();
        let polynomial_size = retrieval_params.polynomial_size();
        assert_eq!(polynomial_size, ntt_table.dimension());

        let slots_per_bucket = retrieval_params.slots_per_bucket();
        let slots_per_segment = retrieval_params.slots_per_segment();
        let bucket_distr = retrieval_params.bucket_distr();

        let index_slots_per_bucket = slots_per_bucket - 1;
        let index_modulus = retrieval_params.index_modulus();

        let is_power_of_two = index_modulus.is_power_of_two();

        let mask = index_modulus - 1;
        let shift_bits = index_modulus.trailing_zeros();

        let modulus = <BarrettModulus<u64>>::new(index_modulus);

        let q = <SecondLevelField as Field>::MODULUS_VALUE;
        let p = self.detection_key().params().output_plain_modulus_value();
        let half_p = (p + 1) >> 1;

        let ciphertext = pertinency_vector
            .par_chunks(CHUNK_SIZE)
            .enumerate()
            .map_init(
                || {
                    (
                        rand::thread_rng(),
                        <FieldNttPolynomial<SecondLevelField>>::zero(polynomial_size),
                        <NttRlwe<SecondLevelField>>::zero(polynomial_size),
                    )
                },
                |(rng, poly, temp), (chunk_i, chunk)| {
                    let mut chunk_result: NttRlwe<SecondLevelField> =
                        NttRlwe::zero(polynomial_size);

                    chunk.iter().enumerate().for_each(|(j, detect)| {
                        let i = CHUNK_SIZE * chunk_i + j;

                        poly.set_zero();

                        poly.as_mut_slice()
                            .chunks_exact_mut(slots_per_segment)
                            .zip(bucket_distr.sample_iter(&mut *rng))
                            .for_each(
                                |(chunk, bucket_index): (
                                    &mut [<SecondLevelField as Field>::ValueT],
                                    usize,
                                )| {
                                    let mut i: <SecondLevelField as Field>::ValueT =
                                        AsFrom::as_from(i);
                                    let address = bucket_index * slots_per_bucket;

                                    let mut k = 0;
                                    if is_power_of_two {
                                        while !i.is_zero() {
                                            let v = i & mask;
                                            unsafe {
                                                *chunk.get_unchecked_mut(address + k) =
                                                    if v < half_p { v } else { q - p + v };
                                            }
                                            // chunk[address + k] = if v < half_p { v } else { q - p + v };
                                            i >>= shift_bits;
                                            k += 1;
                                        }
                                    } else {
                                        while !i.is_zero() {
                                            let v = if i < index_modulus {
                                                i
                                            } else {
                                                modulus.reduce(i)
                                            };
                                            unsafe {
                                                *chunk.get_unchecked_mut(address + k) =
                                                    if v < half_p { v } else { q - p + v };
                                            }
                                            i = (i - v) / index_modulus;
                                            k += 1;
                                        }
                                    }

                                    unsafe {
                                        *chunk
                                            .get_unchecked_mut(address + index_slots_per_bucket) =
                                            ConstOne::ONE;
                                    }
                                    // chunk[address + index_slots_per_budget] = ConstOne::ONE;
                                },
                            );

                        ntt_table.transform_slice(poly.as_mut_slice());

                        detect.mul_ntt_polynomial_inplace(poly, temp);
                        chunk_result.add_assign_element_wise(temp);
                    });
                    chunk_result
                },
            )
            .reduce(
                || <NttRlwe<SecondLevelField>>::zero(polynomial_size),
                |a, b| a.add_element_wise(&b),
            );

        ciphertext
    }

    pub fn encode_pertinent_payloads<R>(
        &self,
        pertinency_vector: &[NttRlweCiphertext<SecondLevelField>],
        payloads: &[Payload],
        combination_count: usize,
        cmb_count_per_cipher: usize,
        rng: &mut R,
    ) -> Vec<NttRlweCiphertext<SecondLevelField>>
    where
        R: Rng + SeedableRng + CryptoRng,
    {
        // Step 3c: RLWE-encode payloads weighted by pertinency.
        // Sample random weights and pack weighted payloads into RLWE slots.
        const CHUNK_SIZE: usize = 2048;

        let payloads_count = payloads.len();
        let ring_dimension = self.detection_key.params().second_level_ring_dimension();
        let cmb_cipher_count = combination_count.div_ceil(cmb_count_per_cipher);
        let q = <SecondLevelField as Field>::MODULUS_VALUE;
        let p = self.detection_key().params().output_plain_modulus_value();
        let is_power_of_two = p.is_power_of_two();
        let half_p = (p + 1) >> 1;

        let powof2_modulus = if is_power_of_two {
            <PowOf2Modulus<PayloadByteType>>::new(p as PayloadByteType)
        } else {
            <PowOf2Modulus<PayloadByteType>>::new(2)
        };
        let barrett_modulus = <BarrettModulus<PayloadByteType>>::new(p as PayloadByteType);

        let ntt_table = self
            .detection_key
            .second_level_blind_rotation_key()
            .ntt_table();

        let mut all_weights: Vec<PayloadByteType> =
            vec![0; cmb_cipher_count * cmb_count_per_cipher * payloads_count];

        let distr = Uniform::new(0, p as PayloadByteType);

        distr
            .sample_iter(rng)
            .zip(all_weights.iter_mut())
            .take(combination_count * payloads_count)
            .for_each(|(weight, w)| {
                *w = weight;
            });

        // rng.fill_bytes(&mut all_weights[..combination_count * payloads_count]);

        let combinations = all_weights
            .par_chunks_exact(cmb_count_per_cipher * payloads_count)
            .map(|weights_chunk| {
                pertinency_vector
                    .par_chunks(CHUNK_SIZE)
                    .zip(payloads.par_chunks(CHUNK_SIZE))
                    .enumerate()
                    .map_init(
                        || FieldNttPolynomial::<SecondLevelField>::zero(ring_dimension),
                        |payload_ntt_poly, (chunk_i, (pv_chunk, payload_chunk))| {
                            let mut temp_cmb =
                                NttRlweCiphertext::<SecondLevelField>::zero(ring_dimension);

                            pv_chunk
                                .iter()
                                .zip(payload_chunk.iter())
                                .enumerate()
                                .for_each(|(chunk_j, (pv, payload))| {
                                    let i = CHUNK_SIZE * chunk_i + chunk_j;
                                    payload_ntt_poly.set_zero();

                                    for (j, poly_chunk) in payload_ntt_poly
                                        .as_mut_slice()
                                        .chunks_exact_mut(PAYLOAD_LENGTH)
                                        .take(cmb_count_per_cipher)
                                        .enumerate()
                                    {
                                        let weight = unsafe {
                                            *weights_chunk.get_unchecked(j * payloads_count + i)
                                        };
                                        let weighted_payload = if is_power_of_two {
                                            payload.mul_scalar(weight, powof2_modulus)
                                        } else {
                                            payload.mul_scalar(weight, barrett_modulus)
                                        };
                                        poly_chunk
                                            .iter_mut()
                                            .zip(weighted_payload.0.iter())
                                            .for_each(|(a, &b)| {
                                                let b = b as <SecondLevelField as Field>::ValueT;
                                                *a = if b < half_p { b } else { q - p + b };
                                            });
                                    }

                                    ntt_table.transform_slice(payload_ntt_poly.as_mut_slice());

                                    temp_cmb.add_ntt_rlwe_mul_ntt_polynomial_assign(
                                        pv,
                                        payload_ntt_poly,
                                    );
                                });
                            temp_cmb
                        },
                    )
                    .reduce(
                        || NttRlweCiphertext::<SecondLevelField>::zero(ring_dimension),
                        |acc, x| acc.add_element_wise(&x),
                    )
            })
            .collect();

        combinations
    }

    /// Analyzes noise in ciphertexts returned by [`Self::encode_pertinent_payloads`].
    ///
    /// This only measures noise after payload encoding. It rebuilds the true expected
    /// weighted payload values from `payloads`, `pertinent_indices`, and `seed`, then
    /// compares decrypted coefficients against those known encodings.
    ///
    /// This intentionally does not round the decrypted value to the nearest plaintext
    /// first: nearest-message rounding can hide decoding failures by choosing the wrong
    /// plaintext as the reference.
    #[allow(clippy::too_many_arguments)]
    pub fn analyze_encode_pertinent_payloads_noise(
        &self,
        encoded_payloads: &[NttRlweCiphertext<SecondLevelField>],
        payloads: &[Payload],
        pertinent_indices: &[usize],
        seed: [u8; 32],
        combination_count: usize,
        cmb_count_per_cipher: usize,
        secret_key_pack: &SecretKeyPack,
    ) -> NoiseStats {
        let params = self.detection_key.params();
        let payloads_count = payloads.len();
        let expected_cipher_count = combination_count.div_ceil(cmb_count_per_cipher);
        assert_eq!(
            encoded_payloads.len(),
            expected_cipher_count,
            "Invalid encoded payload ciphertext count."
        );
        assert!(
            pertinent_indices.iter().all(|&i| i < payloads_count),
            "Invalid pertinent payload index."
        );

        let p = params.output_plain_modulus_value();
        let p_u64 = p;
        let distr = Uniform::new(0, p as PayloadByteType);
        let mut weights = vec![0; combination_count * payloads_count];

        distr
            .sample_iter(&mut rand::rngs::StdRng::from_seed(seed))
            .zip(weights.iter_mut())
            .for_each(|(weight, w)| {
                *w = weight;
            });

        let second_level_key = secret_key_pack.second_level_ntt_rlwe_secret_key();
        let second_level_ntt_table = secret_key_pack.second_level_ntt_table();
        let mut stats = NoiseStats::default();

        encoded_payloads
            .iter()
            .enumerate()
            .for_each(|(cipher_i, ciphertext)| {
                let decrypted = decrypt_second_level_ntt_rlwe(
                    ciphertext,
                    second_level_key,
                    second_level_ntt_table,
                );

                for cmb_i in 0..cmb_count_per_cipher {
                    let combination_i = cipher_i * cmb_count_per_cipher + cmb_i;
                    if combination_i >= combination_count {
                        break;
                    }

                    let slot_offset = cmb_i * PAYLOAD_LENGTH;
                    let slots = &decrypted.as_slice()[slot_offset..slot_offset + PAYLOAD_LENGTH];
                    let weights = &weights
                        [combination_i * payloads_count..(combination_i + 1) * payloads_count];

                    slots.iter().enumerate().for_each(|(byte_i, &coeff)| {
                        let expected = pertinent_indices.iter().fold(0u64, |acc, &payload_i| {
                            (acc + weights[payload_i] as u64 * payloads[payload_i].0[byte_i] as u64)
                                % p_u64
                        }) as OutputValue;
                        let expected = encode_output_value(expected, p);

                        stats.record(coefficient_noise_from_encoded(coeff, expected));
                    });
                }
            });

        stats
    }
}

/// LUT for first-layer functional bootstrapping (homomorphic decryption).
pub fn first_level_lut(
    rlwe_dimension: usize,
    input_plain_modulus: usize,
    output_plain_modulus: usize,
) -> FieldPolynomial<FirstLevelField> {
    let q = <FirstLevelField as Field>::MODULUS_VALUE;
    let scale_one =
        round_div(q as u128, output_plain_modulus as u128) as <FirstLevelField as Field>::ValueT;
    let scale_minus_one = q - scale_one;

    negacyclic_lut_from_sparse_values::<FirstLevelField>(
        rlwe_dimension,
        input_plain_modulus,
        FirstLevelField::ZERO,
        &[(0, scale_one), (input_plain_modulus / 2, scale_minus_one)],
    )
}

/// LUT for second-layer functional bootstrapping (homomorphic checking).
pub fn second_level_lut(
    rlwe_dimension: usize,
    clue_count: usize,
    input_plain_modulus: usize,
    output_plain_modulus: usize,
) -> FieldPolynomial<SecondLevelField> {
    let scale_one = output_scale_one(output_plain_modulus as OutputValue);

    negacyclic_lut_from_sparse_values::<SecondLevelField>(
        rlwe_dimension,
        input_plain_modulus,
        SecondLevelField::ZERO,
        &[(clue_count, scale_one)],
    )
}

fn decrypt_second_level_rlwe(
    ciphertext: &RlweCiphertext<SecondLevelField>,
    secret_key: &NttRlweSecretKey<SecondLevelField>,
    ntt_table: &<SecondLevelField as NttField>::Table,
) -> FieldPolynomial<SecondLevelField> {
    let a_mul_s =
        ntt_table.inverse_transform_inplace(ntt_table.transform(ciphertext.a()) * &**secret_key);

    ciphertext.b() - a_mul_s
}

fn decrypt_second_level_ntt_rlwe(
    ciphertext: &NttRlweCiphertext<SecondLevelField>,
    secret_key: &NttRlweSecretKey<SecondLevelField>,
    ntt_table: &<SecondLevelField as NttField>::Table,
) -> FieldPolynomial<SecondLevelField> {
    let decrypted_ntt = ciphertext.b() - ciphertext.a().clone() * &**secret_key;
    ntt_table.inverse_transform_inplace(decrypted_ntt)
}

fn expected_intermediate_plaintext(
    clues: &CmLweCiphertext<ClueValue>,
    secret_key_pack: &SecretKeyPack,
    params: &OmrParameters,
) -> InterLweValue {
    let clue_plain_modulus = params.clue_plain_modulus_value();
    let minus_one_message = clue_plain_modulus >> 1;

    let mut expected = 0i64;
    clues
        .extract_all(params.clue_cipher_modulus())
        .iter()
        .map(|clue| secret_key_pack.decrypt_clue(clue))
        .for_each(|message| {
            if message == 0 {
                expected += 1;
            } else if message == minus_one_message {
                expected -= 1;
            }
        });

    let plain_modulus = params.intermediate_lwe_plain_modulus_value() as i64;
    expected.rem_euclid(plain_modulus) as InterLweValue
}

fn intermediate_lwe_noise(
    ciphertext: &LweCiphertext<InterLweValue>,
    expected_plaintext: InterLweValue,
    secret_key_pack: &SecretKeyPack,
    params: &OmrParameters,
) -> f64 {
    let lwe_params = params.intermediate_lwe_params();
    let modulus = lwe_params.cipher_modulus;
    let a_mul_s = modulus.reduce_dot_product(
        ciphertext.a(),
        secret_key_pack.intermediate_lwe_secret_key(),
    );
    let decrypted_phase = modulus.reduce_sub(ciphertext.b(), a_mul_s);
    let expected_encoded = encode_lwe_plaintext(
        expected_plaintext,
        lwe_params.plain_modulus_value,
        lwe_params.cipher_modulus_value,
    );
    let cipher_modulus = modulus_value_as_u128(lwe_params.cipher_modulus_value);

    centered_noise_from_encoded(
        decrypted_phase as u128,
        expected_encoded as u128,
        cipher_modulus,
    )
}

fn noise_by_coefficient(
    decrypted: &FieldPolynomial<SecondLevelField>,
    plain_modulus: OutputValue,
) -> NoiseByCoefficient {
    let mut noise = NoiseByCoefficient::default();

    if let Some((&constant, other)) = decrypted.as_slice().split_first() {
        noise
            .constant
            .record(coefficient_noise(constant, plain_modulus));

        other.iter().for_each(|&coeff| {
            noise.other.record(coefficient_noise(coeff, plain_modulus));
        });
    }

    noise
}

#[inline]
fn coefficient_noise(coeff: OutputValue, plain_modulus: OutputValue) -> f64 {
    let q = <SecondLevelField as Field>::MODULUS_VALUE;
    let decoded =
        round_div(coeff as u128 * plain_modulus as u128, q as u128) as OutputValue % plain_modulus;
    let encoded = encode_output_value(decoded, plain_modulus);

    coefficient_noise_from_encoded(coeff, encoded)
}

#[inline]
fn coefficient_noise_from_encoded(coeff: OutputValue, encoded: OutputValue) -> f64 {
    let q = <SecondLevelField as Field>::MODULUS_VALUE;
    centered_noise_from_encoded(coeff as u128, encoded as u128, q as u128)
}

#[inline]
fn centered_noise_from_encoded(coeff: u128, encoded: u128, modulus: u128) -> f64 {
    if coeff >= encoded {
        let diff = coeff - encoded;
        if diff <= modulus / 2 {
            diff as f64
        } else {
            -((modulus - diff) as f64)
        }
    } else {
        let diff = encoded - coeff;
        if diff <= modulus / 2 {
            -(diff as f64)
        } else {
            (modulus - diff) as f64
        }
    }
}

#[inline]
fn modulus_value_as_u128(modulus: ModulusValue<InterLweValue>) -> u128 {
    match modulus {
        ModulusValue::Native => 1u128 << InterLweValue::BITS,
        ModulusValue::PowerOf2(q) | ModulusValue::Prime(q) | ModulusValue::Others(q) => q as u128,
    }
}

#[inline]
fn encode_lwe_plaintext(
    value: InterLweValue,
    plain_modulus: InterLweValue,
    cipher_modulus: ModulusValue<InterLweValue>,
) -> InterLweValue {
    debug_assert!(value < plain_modulus);

    let modulus = modulus_value_as_u128(cipher_modulus);
    let encoded = round_div(value as u128 * modulus, plain_modulus as u128);

    match cipher_modulus {
        ModulusValue::Native => encoded as InterLweValue,
        ModulusValue::PowerOf2(q) | ModulusValue::Prime(q) | ModulusValue::Others(q) => {
            (encoded % q as u128) as InterLweValue
        }
    }
}

#[inline]
fn encode_output_value(value: OutputValue, plain_modulus: OutputValue) -> OutputValue {
    debug_assert!(value < plain_modulus);

    let q = <SecondLevelField as Field>::MODULUS_VALUE;
    let half_p = (plain_modulus + 1) >> 1;
    let centered = if value < half_p {
        value
    } else {
        q - plain_modulus + value
    };

    SecondLevelField::mul(centered, output_scale_one(plain_modulus))
}

fn output_scale_one(plain_modulus: OutputValue) -> OutputValue {
    let q = <SecondLevelField as Field>::MODULUS_VALUE;

    if plain_modulus.is_power_of_two() {
        let log = plain_modulus.trailing_zeros() - 1;
        ((q >> log) + 1) >> 1
    } else {
        let delta = BigDecimal::from_u64(q).unwrap() / plain_modulus;
        delta
            .with_scale_round(0, RoundingMode::HalfUp)
            .to_u64()
            .unwrap()
    }
}

#[inline]
fn round_div(numerator: u128, denominator: u128) -> u128 {
    (numerator + denominator / 2) / denominator
}

fn extract_clues_and_modulus_switch(
    clues: &CmLweCiphertext<ClueValue>,
    params: &OmrParameters,
) -> Vec<LweCiphertext<ClueValue>> {
    // Step 3a prep: extract LWE clues and switch modulus for first-layer bootstrapping.
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
    // Step 3a: first-layer functional bootstrapping (homomorphic decryption).
    // Aggregate clue ciphertexts and switch to the intermediate LWE key.
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

    // Modulus switching
    let intermediate = lwe_modulus_switch(
        &intermediate,
        params.first_level_blind_rotation_params().modulus,
        params.intermediate_lwe_params().cipher_modulus_value,
    );

    intermediate
}

fn second_level_bootstrapping(
    mut intermediate: LweCiphertext<InterLweValue>,
    blind_rotation_key: &BlindRotationKey<SecondLevelField>,
    lut: &FieldPolynomial<SecondLevelField>,
    params: &OmrParameters,
) -> RlweCiphertext<SecondLevelField> {
    // Step 3b: second-layer functional bootstrapping (homomorphic checking).
    // Normalize modulus, then apply the second-layer blind rotation.
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
    ntt_table: &<SecondLevelField as NttField>::Table,
) -> NttRlweCiphertext<SecondLevelField> {
    // Step 3b: homomorphic trace to keep the constant term.
    // Trace returns a constant-term ciphertext used for encoding.
    // Multiply by `n_inv`
    ciphertext.a_mut().mul_shoup_scalar_assign(n_inv);
    ciphertext.b_mut().mul_shoup_scalar_assign(n_inv);
    // Homomorphic Trace
    trace_key.trace(&ciphertext).to_ntt_rlwe(ntt_table)
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::*;

    #[test]
    fn first_level_lut_matches_previous_dense_implementation() {
        let params = OmrParameters::new();
        let rlwe_dimension = params.first_level_ring_dimension();
        let input_plain_modulus = params.clue_plain_modulus_value() as usize;
        let output_plain_modulus = params.intermediate_lwe_plain_modulus_value() as usize;

        assert_eq!(
            input_plain_modulus, 8,
            "previous first_level_lut used a fixed 5-value table for clue modulus 8"
        );

        let current = first_level_lut(rlwe_dimension, input_plain_modulus, output_plain_modulus);
        let previous =
            previous_first_level_lut(rlwe_dimension, input_plain_modulus, output_plain_modulus);

        assert_eq!(current.as_slice(), previous.as_slice());
    }

    fn previous_first_level_lut(
        rlwe_dimension: usize,
        input_plain_modulus: usize,
        output_plain_modulus: usize,
    ) -> FieldPolynomial<FirstLevelField> {
        let q = <FirstLevelField as Field>::MODULUS_VALUE;
        let scale_one = round_div(q as u128, output_plain_modulus as u128)
            as <FirstLevelField as Field>::ValueT;
        let scale_minus_one = q - scale_one;
        let values = [
            scale_one,
            FirstLevelField::ZERO,
            FirstLevelField::ZERO,
            FirstLevelField::ZERO,
            scale_minus_one,
        ];

        let mut lut = <FieldPolynomial<FirstLevelField>>::zero(rlwe_dimension);

        let half_delta = rlwe_dimension >> input_plain_modulus.trailing_zeros();

        lut.as_mut_slice()
            .chunks_mut(half_delta)
            .zip(values.iter().interleave(values[1..].iter()))
            .for_each(|(chunk, &value)| {
                chunk.fill(value);
            });

        lut
    }
}
