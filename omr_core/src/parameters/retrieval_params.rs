use algebra::{
    integer::{AsInto, Bits, UnsignedInteger},
    Field, NttField,
};
use rand_distr::Uniform;

#[derive(Clone, Copy)]
pub struct RetrievalParams<F: NttField> {
    /// Output message modulus and the index modulus.
    index_modulus: F::ValueT,

    /// The number of slots in Rlwe Ciphertext.
    polynomial_size: usize,
    /// The number of buckets of one segment.
    bucket_count_per_segment: usize,
    /// The number of slots per bucket.
    slots_per_bucket: usize,
    /// The number of slots per segment.
    slots_per_segment: usize,

    /// The distribution of bucket index.
    bucket_distr: Uniform<usize>,

    /// The number of segments for omr.
    segment_count: usize,
    /// The number of segment can be stored in one cipher.
    segment_per_cipher: usize,

    /// The maximum number of encode_indices_cipher.
    max_encode_indices_cipher_count: usize,

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
        bucket_count_per_segment: usize,
        segment_count: usize,
        cmb_count_per_cipher: usize,
    ) -> Self {
        let index_slots_per_bucket = if index_modulus.is_power_of_two() {
            all_payloads_count
                .next_power_of_two()
                .trailing_zeros()
                .div_ceil(index_modulus.trailing_zeros()) as usize
        } else {
            let index_modulus: usize = index_modulus.as_into();
            let mut pow = all_payloads_count.ilog(index_modulus);
            if index_modulus.pow(pow) < all_payloads_count {
                pow += 1;
            }
            if pow == 0 {
                pow = 1;
            }
            assert!(index_modulus.pow(pow) >= all_payloads_count);
            pow as usize
        };

        let slots_per_bucket = index_slots_per_bucket + 1;
        let slots_per_segment = slots_per_bucket * bucket_count_per_segment;

        let segment_per_cipher = polynomial_size / slots_per_segment;
        let max_encode_indices_cipher_count = segment_count / segment_per_cipher;

        let bucket_distr = Uniform::new(0, bucket_count_per_segment);

        let combination_count = if index_modulus.is_power_of_two() {
            pertinent_count + 10
        } else {
            pertinent_count + 5
        };

        Self {
            index_modulus,
            polynomial_size,
            bucket_count_per_segment,
            slots_per_bucket,
            slots_per_segment,
            bucket_distr,
            segment_count,
            segment_per_cipher,
            max_encode_indices_cipher_count,
            pertinent_count,
            combination_count,
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

    pub fn bucket_count_per_segment(&self) -> usize {
        self.bucket_count_per_segment
    }

    pub fn slots_per_bucket(&self) -> usize {
        self.slots_per_bucket
    }

    pub fn slots_per_segment(&self) -> usize {
        self.slots_per_segment
    }

    pub fn bucket_distr(&self) -> Uniform<usize> {
        self.bucket_distr
    }

    pub fn segment_count(&self) -> usize {
        self.segment_count
    }

    pub fn segment_per_cipher(&self) -> usize {
        self.segment_per_cipher
    }

    pub fn max_encode_indices_cipher_count(&self) -> usize {
        self.max_encode_indices_cipher_count
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
