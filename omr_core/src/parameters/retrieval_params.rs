use algebra::{integer::Bits, Field, NttField};
use rand_distr::Uniform;

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

    /// The number of combinations of pertinent payloads.
    combination_count: usize,

    /// The number of combinations of pertinent payloads per ciphertext.
    cmb_count_per_cipher: usize,

    /// The number of all payloads count on the board.
    all_payloads_count: usize,
}

impl<F: NttField> RetrievalParams<F> {
    /// Creates a new [`RetrievalParams<F>`].
    pub fn new(
        index_modulus: F::ValueT,
        polynomial_size: usize,
        all_payloads_count: usize,
        pertinent_count: usize,
        budget_count_per_retrieval: usize,
        retrieve_count: usize,
        cmb_count_per_cipher: usize,
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
            combination_count: pertinent_count + 10,
            all_payloads_count,
            cmb_count_per_cipher,
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

    pub fn combination_count(&self) -> usize {
        self.combination_count
    }

    pub fn all_payloads_count(&self) -> usize {
        self.all_payloads_count
    }

    pub fn cmb_count_per_cipher(&self) -> usize {
        self.cmb_count_per_cipher
    }
}
