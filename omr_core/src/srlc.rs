use algebra::integer::UnsignedInteger;
use rand::{distributions::Uniform, prelude::*, seq::IteratorRandom, CryptoRng, Rng};
use rand_distr::Binomial;

pub struct SrlcParams<T: UnsignedInteger> {
    security: u32,
    num_cols: usize,
    expect_rank: usize,
    num_nonzeros: usize,
    defective_rate: f64,
    modulus: T,
    distr: Uniform<T>,
    binomial_distr: Binomial,
}

impl<T: UnsignedInteger + std::fmt::Debug> std::fmt::Debug for SrlcParams<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrlcParams")
            .field("security", &self.security)
            .field("num_cols", &self.num_cols)
            .field("expect_rank", &self.expect_rank)
            .field("num_nonzeros", &self.num_nonzeros)
            .field("defective_rate", &self.defective_rate)
            .field("modulus", &self.modulus)
            .finish()
    }
}

impl<T: UnsignedInteger> SrlcParams<T> {
    /// Creates a new [`SrlcParams<T>`].
    #[inline]
    pub fn new(
        security: u32,
        expect_rank: usize,
        defective_rate: f64,
        modulus: T,
    ) -> SrlcParams<T> {
        let mut num_cols = 6;

        let t = 1.0f64 - (3.0f64 / (expect_rank as f64));
        loop {
            let mut acc = 1.0f64;
            for i in 1..expect_rank {
                acc *= 1.0f64 - t.powi(num_cols - i as i32 + 1);
            }
            if 1.0f64 - acc < defective_rate {
                break;
            }
            num_cols += 1;
        }

        let num_nonzeros = num_cols as usize * 3 / expect_rank;

        SrlcParams {
            security,
            num_cols: num_cols as usize,
            expect_rank,
            num_nonzeros,
            defective_rate,
            modulus,
            distr: Uniform::new_inclusive(T::ZERO, modulus - T::ONE),
            binomial_distr: Binomial::new(num_cols as u64, num_nonzeros as f64 / num_cols as f64)
                .unwrap(),
        }
    }

    pub fn gen_weights<R>(&self, rng: &mut R) -> (Vec<usize>, Vec<T>)
    where
        R: Rng + SeedableRng + CryptoRng,
    {
        let real_num_nonzeros = self.binomial_distr.sample(rng) as usize;

        let mut index = (0..self.num_cols).choose_multiple(rng, real_num_nonzeros);
        index.sort_unstable();
        let weights = self
            .distr
            .sample_iter(&mut *rng)
            .take(real_num_nonzeros)
            .collect::<Vec<_>>();

        (index, weights)
    }

    pub fn num_cols(&self) -> usize {
        self.num_cols
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srlc() {
        let slrc_params = SrlcParams::new(128, 50, 2.0f64.powi(-50), 256u64);
        println!("{:?}", slrc_params);

        let mut rng = StdRng::seed_from_u64(0u64);
        let (index, weights) = slrc_params.gen_weights(&mut rng);
        println!("{:?}", index);
        println!("{:?}", weights);
    }
}
