use std::{collections::HashSet, sync::Arc, time::Instant};

use algebra::{
    integer::{AsInto, Bits},
    ntt::NumberTheoryTransform,
    Field, NttField,
};
use fhe_core::NttRlweSecretKey;
use lattice::NttRlwe;
use num_traits::{ConstZero, One};
use rand::distributions::Uniform;

#[derive(Clone, Copy)]
pub struct RetrievalParams<F: NttField> {
    /// Output message modulus and the index modulus.
    index_modulus: F::ValueT,

    /// The number of slots in Rlwe Ciphertext.
    polynomial_size: usize,
    /// The number of budgets of one retrieval.
    budget_count_per_retrieval: usize,
    /// The number of slots per budget.
    slots_per_budget: usize,
    /// The number of slots per retrieval.
    slots_per_retrieval: usize,

    /// The distribution of budget index.
    budget_distr: Uniform<usize>,

    /// The number of retrievals for omr.
    retrieve_count: usize,
    /// The number of retrieval result can be stored in one cipher.
    retrieval_per_cipher: usize,

    /// The maximum number of retrieval times.
    max_retrieve_cipher_count: usize,

    /// The number of pertinent payloads.
    pertinent_count: usize,
}

impl<F: NttField> RetrievalParams<F> {
    pub fn new(
        index_modulus: F::ValueT,
        polynomial_size: usize,
        all_payloads_count: usize,
        pertinent_count: usize,
        budget_count_per_retrieval: usize,
        retrieve_count: usize,
    ) -> Self {
        let index_slots_per_budget = all_payloads_count
            .next_power_of_two()
            .trailing_zeros()
            .div_ceil(index_modulus.trailing_zeros()) as usize;

        let slots_per_budget = index_slots_per_budget + 1;
        let slots_per_retrieval = slots_per_budget * budget_count_per_retrieval;

        let retrieval_per_cipher = polynomial_size / slots_per_retrieval;
        let max_retrieve_cipher_count = retrieve_count / retrieval_per_cipher;

        let budget_distr = Uniform::new(0, budget_count_per_retrieval);

        Self {
            index_modulus,
            polynomial_size,
            budget_count_per_retrieval,
            slots_per_budget,
            slots_per_retrieval,
            budget_distr,
            retrieve_count,
            retrieval_per_cipher,
            max_retrieve_cipher_count,
            pertinent_count,
        }
    }

    pub fn index_modulus(&self) -> <F as Field>::ValueT {
        self.index_modulus
    }

    pub fn polynomial_size(&self) -> usize {
        self.polynomial_size
    }

    pub fn budget_count_per_retrieval(&self) -> usize {
        self.budget_count_per_retrieval
    }

    pub fn slots_per_budget(&self) -> usize {
        self.slots_per_budget
    }

    pub fn slots_per_retrieval(&self) -> usize {
        self.slots_per_retrieval
    }

    pub fn budget_distr(&self) -> Uniform<usize> {
        self.budget_distr
    }

    pub fn retrieve_count(&self) -> usize {
        self.retrieve_count
    }

    pub fn retrieval_per_cipher(&self) -> usize {
        self.retrieval_per_cipher
    }

    pub fn max_retrieve_cipher_count(&self) -> usize {
        self.max_retrieve_cipher_count
    }

    pub fn pertinent_count(&self) -> usize {
        self.pertinent_count
    }
}

pub struct Retriever<F: NttField> {
    params: RetrievalParams<F>,
    ntt_table: Arc<<F as NttField>::Table>,
    key: NttRlweSecretKey<F>,
    retrieval_set: HashSet<usize>,
}

impl<F: NttField> Retriever<F> {
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

    pub fn retrieve(&mut self, retrieval_ciphertext: &NttRlwe<F>) -> Result<HashSet<usize>, ()> {
        let slots_per_budget = self.params.slots_per_budget;
        let slots_per_retrieval = self.params.slots_per_retrieval;
        let index_modulus = self.params.index_modulus;

        let shift_bits = index_modulus.trailing_zeros();

        let fp: f64 = <F as Field>::MODULUS_VALUE.as_into();
        let ft: f64 = index_modulus.as_into();

        let decode = |c: F::ValueT| {
            let t: F::ValueT = (AsInto::<f64>::as_into(c) * ft / fp).round().as_into();
            t % index_modulus
        };

        let per_retrieval_start = Instant::now();

        let decrypted_ntt =
            retrieval_ciphertext.b() - retrieval_ciphertext.a().clone() * &*self.key;
        let decrypted = self.ntt_table.inverse_transform_inplace(decrypted_ntt);
        let decoded = decrypted
            .into_iter()
            .map(decode)
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

        let per_retrieval_end = Instant::now();
        tracing::debug!(
            "Per retrieval time: {:?}",
            per_retrieval_end - per_retrieval_start
        );

        if self.retrieval_set.len() == self.params.pertinent_count {
            Ok(self.retrieval_set.clone())
        } else {
            Err(())
        }
    }
}
