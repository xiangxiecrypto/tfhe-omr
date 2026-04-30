//! LUT construction helpers for TFHE functional bootstrapping.

use algebra::{polynomial::FieldPolynomial, Field};

/// A helper trait for creating look-up tables.
pub trait LookUpTable<Q: Field> {
    /// Generates the negacyclic look-up table.
    fn negacyclic_lut(&self, coeff_count: usize, log_t: u32) -> FieldPolynomial<Q>;

    /// Generates the negacyclic look-up table for a possibly non-power-of-two
    /// plaintext modulus.
    fn negacyclic_lut_for_plain_modulus(
        &self,
        coeff_count: usize,
        plain_modulus: usize,
    ) -> FieldPolynomial<Q>;
}

impl<Q: Field, const N: usize> LookUpTable<Q> for [<Q as Field>::ValueT; N] {
    #[inline]
    fn negacyclic_lut(&self, coeff_count: usize, log_t: u32) -> FieldPolynomial<Q> {
        self.negacyclic_lut_for_plain_modulus(coeff_count, 1usize << log_t)
    }

    fn negacyclic_lut_for_plain_modulus(
        &self,
        coeff_count: usize,
        plain_modulus: usize,
    ) -> FieldPolynomial<Q> {
        let mut lut = <FieldPolynomial<Q>>::zero(coeff_count);
        let twice_coeff_count = coeff_count * 2;

        lut.as_mut_slice()
            .iter_mut()
            .enumerate()
            .for_each(|(i, coeff)| {
                let message = (i * plain_modulus + coeff_count) / twice_coeff_count;
                *coeff = self[message];
            });

        lut
    }
}

impl<Q: Field> LookUpTable<Q> for &[<Q as Field>::ValueT] {
    #[inline]
    fn negacyclic_lut(&self, coeff_count: usize, log_t: u32) -> FieldPolynomial<Q> {
        self.negacyclic_lut_for_plain_modulus(coeff_count, 1usize << log_t)
    }

    fn negacyclic_lut_for_plain_modulus(
        &self,
        coeff_count: usize,
        plain_modulus: usize,
    ) -> FieldPolynomial<Q> {
        let mut lut = <FieldPolynomial<Q>>::zero(coeff_count);
        let twice_coeff_count = coeff_count * 2;

        lut.as_mut_slice()
            .iter_mut()
            .enumerate()
            .for_each(|(i, coeff)| {
                let message = (i * plain_modulus + coeff_count) / twice_coeff_count;
                *coeff = self[message];
            });

        lut
    }
}

impl<Q: Field, LutFn> LookUpTable<Q> for LutFn
where
    LutFn: Fn(usize) -> <Q as Field>::ValueT,
{
    #[inline]
    fn negacyclic_lut(&self, coeff_count: usize, log_t: u32) -> FieldPolynomial<Q> {
        self.negacyclic_lut_for_plain_modulus(coeff_count, 1usize << log_t)
    }

    fn negacyclic_lut_for_plain_modulus(
        &self,
        coeff_count: usize,
        plain_modulus: usize,
    ) -> FieldPolynomial<Q> {
        let mut lut = <FieldPolynomial<Q>>::zero(coeff_count);
        let twice_coeff_count = coeff_count * 2;

        lut.as_mut_slice()
            .iter_mut()
            .enumerate()
            .for_each(|(i, coeff)| {
                let message = (i * plain_modulus + coeff_count) / twice_coeff_count;
                *coeff = self(message);
            });

        lut
    }
}

#[cfg(test)]
mod tests {
    use super::LookUpTable;
    use algebra::polynomial::FieldPolynomial;

    use crate::FirstLevelField;

    #[test]
    fn plain_modulus_lut_matches_log_lut_for_power_of_two() {
        let values = [1, 2, 3, 4, 5];
        let via_log: FieldPolynomial<FirstLevelField> = values.negacyclic_lut(16, 3);
        let via_plain: FieldPolynomial<FirstLevelField> =
            values.negacyclic_lut_for_plain_modulus(16, 8);

        assert_eq!(via_log.as_slice(), via_plain.as_slice());
        assert_eq!(
            via_plain.as_slice(),
            &[1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5]
        );
    }

    #[test]
    fn custom_fn() {
        let mut values = [0; 30];
        values[14] = 1;
        let via_log: FieldPolynomial<FirstLevelField> =
            values.negacyclic_lut_for_plain_modulus(2048, 30);

        let s = via_log.as_slice();
        let l = s.iter().position(|v| *v == 1).unwrap_or_default();
        let r = s.iter().rposition(|v| *v == 1).unwrap_or_default();

        assert_eq!(l, 1844);
        assert_eq!(r, 1979);
    }
}
