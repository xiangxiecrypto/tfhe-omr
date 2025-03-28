use std::{collections::HashSet, sync::Arc};

use algebra::{
    integer::{AsInto, Bits},
    ntt::{NttTable, NumberTheoryTransform},
    polynomial::FieldNttPolynomial,
    Field, NttField,
};
use bigdecimal::{BigDecimal, RoundingMode};
use fhe_core::{NttRlweCiphertext, NttRlweSecretKey};
use lattice::NttRlwe;
use num_traits::{ConstZero, FromPrimitive, One, ToPrimitive};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{matrix::solve_matrix_mod_256, OmrError, Payload, RetrievalParams, PAYLOAD_LENGTH};

#[derive(Clone)]
pub struct Retriever<F: NttField> {
    params: RetrievalParams<F>,
    ntt_table: Arc<<F as NttField>::Table>,
    key: NttRlweSecretKey<F>,
    retrieval_set: HashSet<usize>,
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
            retrieval_set: HashSet::with_capacity(params.pertinent_count()),
        }
    }

    /// Returns the retrieval parameters.
    #[inline]
    pub fn params(&self) -> RetrievalParams<F> {
        self.params
    }

    /// Returns a reference to the retrieval set of this [`Retriever<F>`].
    #[inline]
    pub fn retrieval_set(&self) -> &HashSet<usize> {
        &self.retrieval_set
    }

    pub fn retrieve_indices(&mut self, compress_indices: &NttRlwe<F>) -> Result<usize, ()> {
        let slots_per_budget = self.params.slots_per_budget();
        let slots_per_retrieval = self.params.slots_per_retrieval();
        let index_modulus = self.params.index_modulus();

        let shift_bits = index_modulus.trailing_zeros();

        let q = BigDecimal::from_u64(<F as Field>::MODULUS_VALUE.as_into()).unwrap();
        let p = BigDecimal::from_u64(index_modulus.as_into()).unwrap();

        let decrypted_ntt = compress_indices.b() - compress_indices.a().clone() * &*self.key;
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

        decoded.chunks_exact(slots_per_retrieval).for_each(|chunk| {
            chunk.chunks_exact(slots_per_budget).for_each(|budget| {
                if budget.last().unwrap().is_one() {
                    let index = budget
                        .iter()
                        .rev()
                        .skip(1)
                        .fold(<F::ValueT as ConstZero>::ZERO, |acc, &v| {
                            (acc << shift_bits) | v
                        });
                    self.retrieval_set.insert(index.as_into());
                }
            });
        });

        if self.retrieval_set.len() == self.params.pertinent_count() {
            Ok(self.params.pertinent_count())
        } else {
            Err(())
        }
    }

    pub fn retrieve(
        &mut self,
        compress_indices: &[NttRlwe<F>],
        combinations: &[NttRlweCiphertext<F>],
        seed: [u8; 32],
    ) -> Result<(Vec<usize>, Vec<Payload>), OmrError> {
        let combination_count = self.params.combination_count();
        let all_payloads_count = self.params.all_payloads_count();

        for ciphertext in compress_indices.iter() {
            if self.retrieve_indices(ciphertext).is_ok() {
                break;
            }
        }

        let retrieval_set = self.retrieval_set();
        let mut indices = retrieval_set.iter().copied().collect::<Vec<usize>>();
        indices.sort_unstable();

        let retrieval_count = indices.len();

        let get_matrix = || {
            let mut seed_rng = StdRng::from_seed(seed);
            let mut weights = vec![0u8; combination_count * all_payloads_count];
            seed_rng.fill_bytes(&mut weights);

            let mut matrix = vec![vec![0u8; retrieval_count]; combination_count];
            let mut matrix_iter = matrix.iter_mut();
            for weights_chunk in weights.chunks_exact(all_payloads_count) {
                let row = matrix_iter.next().unwrap();
                row.iter_mut()
                    .zip(indices.iter())
                    .for_each(|(ele, &i): (&mut u8, &usize)| {
                        *ele = weights_chunk[i];
                    })
            }
            matrix
        };

        let (mut matrix, mut combined_payloads) = rayon::join(
            || get_matrix(),
            || self.decode_combined_payloads(combinations),
        );

        let payloads = solve_matrix_mod_256(&mut matrix, &mut combined_payloads)?;

        Ok((indices, payloads))
    }

    pub fn decode_combined_payloads(&self, combinations: &[NttRlweCiphertext<F>]) -> Vec<Payload> {
        let combination_count = self.params.combination_count();
        let cmb_count_per_cipher = self.params.cmb_count_per_cipher();

        let q = BigDecimal::from_u64(<F as Field>::MODULUS_VALUE.as_into()).unwrap();
        let p = BigDecimal::from_u16(256).unwrap();

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
                                    *byte = t.to_u64().unwrap() as u8;
                                });
                        })
                },
            );

        // payloads.iter_mut().zip(combinations.iter()).for_each(
        //     |(payload, cipher): (&mut Payload, &NttRlweCiphertext<F>)| {
        //         sub_mul(cipher.b(), cipher.a(), &self.key, &mut temp);
        //         self.ntt_table.inverse_transform_slice(temp.as_mut_slice());

        //         payload
        //             .iter_mut()
        //             .zip(temp.iter())
        //             .for_each(|(byte, &coeff)| {
        //                 let mut t = (BigDecimal::from_u64(coeff.as_into()).unwrap() * &p / &q)
        //                     .with_scale_round(0, RoundingMode::HalfUp);
        //                 if t >= q {
        //                     t -= &q;
        //                 }
        //                 *byte = t.to_u64().unwrap() as u8;
        //             });
        //     },
        // );
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
