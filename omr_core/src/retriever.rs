//! Retriever-side decoding of digests into indices and payloads.

use std::{collections::HashSet, sync::Arc};

use algebra::{
    integer::{AsInto, Bits, UnsignedInteger},
    modulus::BarrettModulus,
    ntt::{NttTable, NumberTheoryTransform},
    polynomial::FieldNttPolynomial,
    Field, NttField,
};
use bigdecimal::{BigDecimal, RoundingMode};
use fhe_core::{NttRlweCiphertext, NttRlweSecretKey};
use lattice::NttRlwe;
use num_traits::{ConstZero, FromPrimitive, One, ToPrimitive, Zero};
use rand::{rngs::StdRng, SeedableRng};
use rand_distr::{Distribution, Uniform};

use crate::{
    matrix::{solve_matrix, solve_matrix_mod_256, solve_matrix_mod_257},
    payload::PayloadByteType,
    OmrError, Payload, RetrievalParams, PAYLOAD_LENGTH,
};

/// Client-side decoder for digests produced by the detector.
#[derive(Clone)]
pub struct Retriever<F: NttField> {
    params: RetrievalParams<F>,
    ntt_table: Arc<<F as NttField>::Table>,
    key: NttRlweSecretKey<F>,
    pertinent_indices_set: HashSet<usize>,
}

impl<F: NttField> Retriever<F> {
    /// Creates a new [`Retriever<F>`].
    #[inline]
    pub fn new(
        params: RetrievalParams<F>,
        ntt_table: Arc<<F as NttField>::Table>,
        key: NttRlweSecretKey<F>,
    ) -> Self {
        Self {
            params,
            ntt_table,
            key,
            pertinent_indices_set: HashSet::with_capacity(params.pertinent_count()),
        }
    }

    /// Returns the retrieval parameters.
    #[inline]
    pub fn params(&self) -> RetrievalParams<F> {
        self.params
    }

    /// Returns a reference to the pertinent indices set of this [`Retriever<F>`].
    #[inline]
    pub fn pertinent_indices_set(&self) -> &HashSet<usize> {
        &self.pertinent_indices_set
    }

    #[allow(clippy::result_unit_err)]
    pub fn decode_pertinent_indices(&mut self, encoded_indices: &NttRlwe<F>) -> Result<usize, ()> {
        // Decode index digest into a set of pertinent indices.
        // Power-of-two moduli use bit unpacking; otherwise use base-(index_modulus).
        let slots_per_bucket = self.params.slots_per_bucket();
        let slots_per_segment = self.params.slots_per_segment();
        let index_modulus = self.params.index_modulus();

        let is_power_of_two = index_modulus.is_power_of_two();

        let shift_bits = index_modulus.trailing_zeros();

        let q: u64 = <F as Field>::MODULUS_VALUE.as_into();
        let q = BigDecimal::from(q);
        let p: u16 = index_modulus.as_into();
        let p = BigDecimal::from(p);

        let decrypted_ntt = encoded_indices.b() - encoded_indices.a().clone() * &*self.key;
        let decrypted = self.ntt_table.inverse_transform_inplace(decrypted_ntt);
        let decoded = decrypted
            .into_iter()
            .map(|c: F::ValueT| {
                let mut t = (BigDecimal::from_u64(c.as_into()).unwrap() * &p / &q)
                    .with_scale_round(0, RoundingMode::HalfUp);
                if t >= p {
                    t -= &p;
                }
                t.to_u64().unwrap().as_into()
            })
            .collect::<Vec<F::ValueT>>();

        if is_power_of_two {
            decoded.chunks_exact(slots_per_segment).for_each(|chunk| {
                chunk.chunks_exact(slots_per_bucket).for_each(|bucket| {
                    if bucket.last().unwrap().is_one() {
                        let index = bucket
                            .iter()
                            .rev()
                            .skip(1)
                            .fold(<F::ValueT as ConstZero>::ZERO, |acc, &v| {
                                (acc << shift_bits) | v
                            });
                        self.pertinent_indices_set.insert(index.as_into());
                    }
                });
            });
        } else {
            decoded.chunks_exact(slots_per_segment).for_each(|chunk| {
                chunk.chunks_exact(slots_per_bucket).for_each(|bucket| {
                    if bucket.last().unwrap().is_one() {
                        let index = bucket
                            .iter()
                            .rev()
                            .skip(1)
                            .fold(<F::ValueT as ConstZero>::ZERO, |acc, &v| {
                                acc * index_modulus + v
                            });
                        self.pertinent_indices_set.insert(index.as_into());
                    }
                });
            });
        }

        if self.pertinent_indices_set.len() == self.params.pertinent_count() {
            Ok(self.params.pertinent_count())
        } else {
            Err(())
        }
    }

    // pub fn test_combine(
    //     &self,
    //     indices: &[usize],
    //     combinations: &[NttRlweCiphertext<F>],
    //     payloads: &[Payload],
    //     seed: [u8; 32],
    // ) {
    //     let combination_count = self.params.combination_count();
    //     let all_payloads_count = self.params.all_payloads_count();

    //     let retrieval_count = indices.len();

    //     let get_matrix = || {
    //         let mut seed_rng = StdRng::from_seed(seed);
    //         let mut weights = vec![0u8; combination_count * all_payloads_count];
    //         seed_rng.fill_bytes(&mut weights);

    //         let mut matrix = vec![vec![0u8; retrieval_count]; combination_count];
    //         let mut matrix_iter = matrix.iter_mut();
    //         for weights_chunk in weights.chunks_exact(all_payloads_count) {
    //             let row = matrix_iter.next().unwrap();
    //             row.iter_mut()
    //                 .zip(indices.iter())
    //                 .for_each(|(ele, &i): (&mut u8, &usize)| {
    //                     *ele = weights_chunk[i];
    //                 })
    //         }
    //         matrix
    //     };

    //     let (matrix, combined_payloads) = rayon::join(get_matrix, || {
    //         self.decode_combined_payloads_with_noise(combinations)
    //     });

    //     for (row, &cmb) in matrix.iter().zip(combined_payloads.iter()) {
    //         let payload = row
    //             .iter()
    //             .zip(indices.iter())
    //             .fold(Payload::new(), |acc, (&weight, &i)| {
    //                 acc + (payloads[i] * weight)
    //             });
    //         if payload != cmb {
    //             let count = payload
    //                 .iter()
    //                 .zip(cmb.iter())
    //                 .enumerate()
    //                 .filter(|(_i, (a, b))| a != b)
    //                 .map(|(i, (a, b))| {
    //                     println!("Different at {}: {} != {}", i, a, b);
    //                 })
    //                 .count();
    //             panic!("Different count: {}", count);
    //         }
    //     }
    // }

    pub fn decode_digest(
        &mut self,
        encode_pertinent_indices: &[NttRlwe<F>],
        encode_pertinent_payloads: &[NttRlweCiphertext<F>],
        seed: [u8; 32],
    ) -> Result<(Vec<usize>, Vec<Payload>), OmrError> {
        // Full digest decode: indices first, then payloads.
        // Payloads are recovered by solving a small linear system per combination set.
        let combination_count = self.params.combination_count();
        let all_payloads_count = self.params.all_payloads_count();
        let p: PayloadByteType = self.params.index_modulus().as_into();

        for ciphertext in encode_pertinent_indices.iter() {
            if self.decode_pertinent_indices(ciphertext).is_ok() {
                break;
            }
        }

        let pertinent_indices_set = self.pertinent_indices_set();
        let mut indices = pertinent_indices_set
            .iter()
            .copied()
            .collect::<Vec<usize>>();
        indices.sort_unstable();

        let pertinent_count = indices.len();

        let get_matrix = || {
            let mut seed_rng = StdRng::from_seed(seed);
            let mut weights: Vec<PayloadByteType> = vec![0; combination_count * all_payloads_count];

            let distr: Uniform<PayloadByteType> = Uniform::new(0, p);

            distr
                .sample_iter(&mut seed_rng)
                .zip(weights.iter_mut())
                .for_each(|(weight, w): (PayloadByteType, &mut PayloadByteType)| {
                    *w = weight;
                });

            let mut matrix: Vec<Vec<PayloadByteType>> =
                vec![vec![0; pertinent_count]; combination_count];
            let mut matrix_iter = matrix.iter_mut();
            for weights_chunk in weights.chunks_exact(all_payloads_count) {
                let row = matrix_iter.next().unwrap();
                row.iter_mut().zip(indices.iter()).for_each(
                    |(ele, &i): (&mut PayloadByteType, &usize)| {
                        *ele = weights_chunk[i];
                    },
                )
            }
            matrix
        };

        let (mut matrix, mut combined_payloads) = rayon::join(get_matrix, || {
            self.decode_combined_payloads(encode_pertinent_payloads)
        });

        let payloads = if p == 256 {
            solve_matrix_mod_256(&mut matrix, &mut combined_payloads)?
        } else if p == 257 {
            solve_matrix_mod_257(&mut matrix, &mut combined_payloads)?
        } else {
            solve_matrix(
                &mut matrix,
                &mut combined_payloads,
                <BarrettModulus<PayloadByteType>>::new(p),
                p,
            )?
        };

        Ok((indices, payloads))
    }

    // pub fn decode_combined_payloads_with_noise(
    //     &self,
    //     combinations: &[NttRlweCiphertext<F>],
    // ) -> Vec<Payload> {
    //     let combination_count = self.params.combination_count();
    //     let cmb_count_per_cipher = self.params.cmb_count_per_cipher();
    //     let all_count = self.params.combination_count() * 612;

    //     let q: <F as Field>::ValueT = <F as Field>::MODULUS_VALUE;
    //     let delta: <F as Field>::ValueT = q / 256u16.as_into();
    //     let sigma = 349228353888.975f64;
    //     let mut noise_sigma_info = NoiseSigmaInfo::<F>::new(sigma, q, all_count);

    //     let q_d = BigDecimal::from_u64(<F as Field>::MODULUS_VALUE.as_into()).unwrap();
    //     let p = BigDecimal::from_u16(256).unwrap();

    //     let mut payloads = vec![Payload::new(); combination_count];
    //     let mut temp = <FieldNttPolynomial<F>>::zero(self.ntt_table.dimension());

    //     payloads
    //         .chunks_mut(cmb_count_per_cipher)
    //         .zip(combinations.iter())
    //         .for_each(
    //             |(payload_chunk, cipher): (&mut [Payload], &NttRlweCiphertext<F>)| {
    //                 sub_mul(cipher.b(), cipher.a(), &self.key, &mut temp);
    //                 self.ntt_table.inverse_transform_slice(temp.as_mut_slice());
    //                 payload_chunk
    //                     .iter_mut()
    //                     .zip(temp.as_slice().chunks_exact(PAYLOAD_LENGTH))
    //                     .for_each(|(payload, dec_chunk)| {
    //                         payload
    //                             .iter_mut()
    //                             .zip(dec_chunk.iter())
    //                             .for_each(|(byte, &coeff)| {
    //                                 let mut t = (BigDecimal::from_u64(coeff.as_into()).unwrap()
    //                                     * &p
    //                                     / &q_d)
    //                                     .with_scale_round(0, RoundingMode::HalfUp);
    //                                 if t >= p {
    //                                     t -= &p;
    //                                 }
    //                                 *byte = t.to_u64().unwrap() as u8;
    //                                 let value = F::mul(<F as Field>::ValueT::as_from(*byte), delta);
    //                                 let x = F::sub(coeff, value);

    //                                 noise_sigma_info.check_noise_sigma(x);
    //                             });
    //                     });
    //             },
    //         );

    //     noise_sigma_info.print();

    //     payloads
    // }

    pub fn decode_combined_payloads(&self, combinations: &[NttRlweCiphertext<F>]) -> Vec<Payload> {
        // Decode linearly combined payloads into raw payloads.
        // Inverse NTT + modulus rounding yields payload bytes.
        let combination_count = self.params.combination_count();
        let cmb_count_per_cipher = self.params.cmb_count_per_cipher();

        let index_modulus = self.params.index_modulus();

        let q: u64 = <F as Field>::MODULUS_VALUE.as_into();
        let q = BigDecimal::from(q);
        let p: u16 = index_modulus.as_into();
        let p = BigDecimal::from(p);

        let mut payloads = vec![Payload::new(); combination_count];
        let mut temp = <FieldNttPolynomial<F>>::zero(self.ntt_table.dimension());

        payloads
            .chunks_mut(cmb_count_per_cipher)
            .zip(combinations.iter())
            .for_each(
                |(payload_chunk, cipher): (&mut [Payload], &NttRlweCiphertext<F>)| {
                    sub_mul(cipher.b(), cipher.a(), &self.key, &mut temp);
                    self.ntt_table.inverse_transform_slice(temp.as_mut_slice());
                    payload_chunk
                        .iter_mut()
                        .zip(temp.as_slice().chunks_exact(PAYLOAD_LENGTH))
                        .for_each(|(payload, dec_chunk)| {
                            payload
                                .iter_mut()
                                .zip(dec_chunk.iter())
                                .for_each(|(byte, &coeff)| {
                                    let mut t =
                                        (BigDecimal::from_u64(coeff.as_into()).unwrap() * &p / &q)
                                            .with_scale_round(0, RoundingMode::HalfUp);
                                    if t >= p {
                                        t -= &p;
                                    }
                                    *byte = t.to_u64().unwrap() as PayloadByteType;
                                });
                        })
                },
            );

        payloads
    }
}

pub fn sub_mul<F: NttField>(
    cb: &FieldNttPolynomial<F>,
    ca: &FieldNttPolynomial<F>,
    sk: &NttRlweSecretKey<F>,
    dest: &mut FieldNttPolynomial<F>,
) {
    dest.iter_mut()
        .zip(cb.iter())
        .zip(ca.iter())
        .zip(sk.iter())
        .for_each(
            #[allow(clippy::type_complexity)]
            |(((d, &b), &a), &s): (
                (
                    (&mut <F as Field>::ValueT, &<F as Field>::ValueT),
                    &<F as Field>::ValueT,
                ),
                &<F as Field>::ValueT,
            )| {
                *d = F::sub(b, F::mul(a, s));
            },
        );
}

/// Tracks decoded-noise statistics for evaluation/debugging.
pub struct NoiseSigmaInfo<F: Field> {
    sigma: f64,
    one_sigma: <F as Field>::ValueT,
    two_sigma: <F as Field>::ValueT,
    three_sigma: <F as Field>::ValueT,
    four_sigma: <F as Field>::ValueT,
    five_sigma: <F as Field>::ValueT,
    six_sigma: <F as Field>::ValueT,
    one_sigma_count: usize,
    two_sigma_count: usize,
    three_sigma_count: usize,
    four_sigma_count: usize,
    five_sigma_count: usize,
    six_sigma_count: usize,
    all_count: usize,
    sum: BigDecimal,
    sq_sum: BigDecimal,
    q: <F as Field>::ValueT,
    half_q: <F as Field>::ValueT,
}

impl<F: Field> NoiseSigmaInfo<F> {
    pub fn new(sigma: f64, modulus: <F as Field>::ValueT, all_count: usize) -> Self {
        let one_sigma = sigma.trunc().as_into();
        let two_sigma = (sigma * 2.0).trunc().as_into();
        let three_sigma = (sigma * 3.0).trunc().as_into();
        let four_sigma = (sigma * 4.0).trunc().as_into();
        let five_sigma = (sigma * 5.0).trunc().as_into();
        let six_sigma = (sigma * 6.0).trunc().as_into();

        Self {
            sigma,
            one_sigma,
            two_sigma,
            three_sigma,
            four_sigma,
            five_sigma,
            six_sigma,
            one_sigma_count: 0,
            two_sigma_count: 0,
            three_sigma_count: 0,
            four_sigma_count: 0,
            five_sigma_count: 0,
            six_sigma_count: 0,
            all_count,
            sum: BigDecimal::zero(),
            sq_sum: BigDecimal::zero(),
            q: modulus,
            half_q: modulus >> 1u32,
        }
    }

    pub fn check_noise_sigma(&mut self, value: <F as Field>::ValueT) {
        if value <= self.half_q {
            if value <= self.one_sigma {
                self.one_sigma_count += 1;
                self.two_sigma_count += 1;
                self.three_sigma_count += 1;
                self.four_sigma_count += 1;
                self.five_sigma_count += 1;
                self.six_sigma_count += 1;
            } else if value <= self.two_sigma {
                self.two_sigma_count += 1;
                self.three_sigma_count += 1;
                self.four_sigma_count += 1;
                self.five_sigma_count += 1;
                self.six_sigma_count += 1;
            } else if value <= self.three_sigma {
                self.three_sigma_count += 1;
                self.four_sigma_count += 1;
                self.five_sigma_count += 1;
                self.six_sigma_count += 1;
            } else if value <= self.four_sigma {
                self.four_sigma_count += 1;
                self.five_sigma_count += 1;
                self.six_sigma_count += 1;
            } else if value <= self.five_sigma {
                self.five_sigma_count += 1;
                self.six_sigma_count += 1;
            } else if value <= self.six_sigma {
                self.six_sigma_count += 1;
            }

            let x: u64 = value.as_into();
            self.sum += x;
            self.sq_sum += BigDecimal::from(x).square();
        } else if value < self.q {
            let t = self.q - value;

            if t <= self.one_sigma {
                self.one_sigma_count += 1;
                self.two_sigma_count += 1;
                self.three_sigma_count += 1;
                self.four_sigma_count += 1;
                self.five_sigma_count += 1;
                self.six_sigma_count += 1;
            } else if t <= self.two_sigma {
                self.two_sigma_count += 1;
                self.three_sigma_count += 1;
                self.four_sigma_count += 1;
                self.five_sigma_count += 1;
                self.six_sigma_count += 1;
            } else if t <= self.three_sigma {
                self.three_sigma_count += 1;
                self.four_sigma_count += 1;
                self.five_sigma_count += 1;
                self.six_sigma_count += 1;
            } else if t <= self.four_sigma {
                self.four_sigma_count += 1;
                self.five_sigma_count += 1;
                self.six_sigma_count += 1;
            } else if t <= self.five_sigma {
                self.five_sigma_count += 1;
                self.six_sigma_count += 1;
            } else if t <= self.six_sigma {
                self.six_sigma_count += 1;
            }

            let t: u64 = t.as_into();
            self.sum -= t;
            self.sq_sum += BigDecimal::from(t).square();
        } else {
            panic!("Err value:{}", value);
        }
    }

    pub fn print(self) {
        println!("-------------------------------------------------");
        println!("expect standard deviation:{}", self.sigma);
        let mean = self.sum / self.all_count as u64;
        let variance = (self.sq_sum / self.all_count as u64) - mean.square();
        println!("real standard deviation:{}", variance.sqrt().unwrap());
        println!("real mean:{}", mean);
        println!("one sigma count:{}", self.one_sigma_count);
        println!("two sigma count:{}", self.two_sigma_count);
        println!("three sigma count:{}", self.three_sigma_count);
        println!("four sigma count:{}", self.four_sigma_count);
        println!("five sigma count:{}", self.five_sigma_count);
        println!("six sigma count:{}", self.six_sigma_count);
        println!("all count:{}", self.all_count);
        println!(
            "one sigma ratio:{}",
            self.one_sigma_count as f64 / self.all_count as f64
        );
        println!(
            "two sigma ratio:{}",
            self.two_sigma_count as f64 / self.all_count as f64
        );
        println!(
            "three sigma ratio:{}",
            self.three_sigma_count as f64 / self.all_count as f64
        );
        println!(
            "four sigma ratio:{}",
            self.four_sigma_count as f64 / self.all_count as f64
        );
        println!(
            "five sigma ratio:{}",
            self.five_sigma_count as f64 / self.all_count as f64
        );
        println!(
            "six sigma ratio:{}",
            self.six_sigma_count as f64 / self.all_count as f64
        );
        println!(
            "more than six sigma ratio:{}",
            1.0 - self.six_sigma_count as f64 / self.all_count as f64
        );
        println!("-------------------------------------------------");
    }
}
