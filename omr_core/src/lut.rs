//! LUT construction helpers for TFHE functional bootstrapping.

use std::ops::Range;

use algebra::{polynomial::FieldPolynomial, Field};

/// Generates a negacyclic LUT from explicit message values.
///
/// `values` only has to cover the message indices read by the LUT front half.
/// For the usual TFHE negacyclic layout, this means `0..=plain_modulus / 2`
/// when `coeff_count` is divisible by `plain_modulus`.
pub fn negacyclic_lut_from_values<Q>(
    values: &[Q::ValueT],
    coeff_count: usize,
    plain_modulus: usize,
) -> FieldPolynomial<Q>
where
    Q: Field,
{
    let max_message = max_message_index(coeff_count, plain_modulus);
    assert!(
        max_message < values.len(),
        "negacyclic LUT values must cover message index {max_message}, but len is {}",
        values.len()
    );

    negacyclic_lut_from_fn::<Q, _>(coeff_count, plain_modulus, |message| values[message])
}

/// Generates a negacyclic LUT from a message-indexed function.
pub fn negacyclic_lut_from_fn<Q, F>(
    coeff_count: usize,
    plain_modulus: usize,
    mut f: F,
) -> FieldPolynomial<Q>
where
    Q: Field,
    F: Fn(usize) -> Q::ValueT,
{
    let mut lut = <FieldPolynomial<Q>>::zero(coeff_count);

    if plain_modulus.is_power_of_two() {
        let max_message = plain_modulus / 2;
        fill_power_of_two_lut::<Q, F>(lut.as_mut_slice(), plain_modulus, max_message, &mut f);
    } else {
        let max_message = max_message_index(coeff_count, plain_modulus);
        fill_interval_lut::<Q, F>(lut.as_mut_slice(), plain_modulus, max_message, &mut f);
    }

    lut
}

/// Generates a sparse negacyclic LUT.
///
/// Messages not listed in `entries` keep `default`. Entries whose message
/// interval is outside the LUT front half are treated as no-ops.
pub fn negacyclic_lut_from_sparse_values<Q>(
    coeff_count: usize,
    plain_modulus: usize,
    default: Q::ValueT,
    entries: &[(usize, Q::ValueT)],
) -> FieldPolynomial<Q>
where
    Q: Field,
{
    let mut lut = <FieldPolynomial<Q>>::zero(coeff_count);
    lut.as_mut_slice().fill(default);

    for &(message, value) in entries {
        let range = message_interval(coeff_count, plain_modulus, message);
        if !range.is_empty() {
            lut.as_mut_slice()[range].fill(value);
        }
    }

    lut
}

fn fill_power_of_two_lut<Q, F>(
    coefficients: &mut [Q::ValueT],
    plain_modulus: usize,
    max_message: usize,
    f: &mut F,
) where
    Q: Field,
    F: FnMut(usize) -> Q::ValueT,
{
    let coeff_count = coefficients.len();
    let half_delta = coeff_count >> plain_modulus.trailing_zeros();
    let delta = half_delta * 2;

    let mut start = 0;
    let mut end = half_delta;
    for message in 0..=max_message {
        coefficients[start..end].fill(f(message));

        start = end;
        end = (end + delta).min(coeff_count)
    }
}

fn fill_interval_lut<Q, F>(
    coefficients: &mut [Q::ValueT],
    plain_modulus: usize,
    max_message: usize,
    f: &mut F,
) where
    Q: Field,
    F: FnMut(usize) -> Q::ValueT,
{
    let coeff_count = coefficients.len();
    let twice_coeff_count = coeff_count * 2;

    let mut start = 0;
    for message in 0..=max_message {
        let end =
            message_interval_bound(twice_coeff_count, coeff_count, plain_modulus, message + 1)
                .min(coeff_count);
        if start < end {
            coefficients[start..end].fill(f(message));
        }

        start = end;
    }
}

fn max_message_index(coeff_count: usize, plain_modulus: usize) -> usize {
    let last_coeff = coeff_count - 1;
    let numerator = last_coeff * plain_modulus + coeff_count;
    let denominator = coeff_count * 2;

    numerator / denominator
}

fn message_interval(coeff_count: usize, plain_modulus: usize, message: usize) -> Range<usize> {
    let twice_coeff_count = coeff_count * 2;

    let start = message_interval_bound(twice_coeff_count, coeff_count, plain_modulus, message);
    let end = message_interval_bound(twice_coeff_count, coeff_count, plain_modulus, message + 1);

    start.min(coeff_count)..end.min(coeff_count)
}

fn message_interval_bound(
    twice_coeff_count: usize,
    coeff_count: usize,
    plain_modulus: usize,
    message: usize,
) -> usize {
    if message == 0 {
        0
    } else {
        (twice_coeff_count * message - coeff_count).div_ceil(plain_modulus)
    }
}

#[cfg(test)]
mod tests {
    use algebra::polynomial::FieldPolynomial;

    use super::*;

    use crate::FirstLevelField;

    #[test]
    fn power_of_two_lut_matches_bucket_layout() {
        let values = [1, 2, 3, 4, 5];
        let lut: FieldPolynomial<FirstLevelField> = negacyclic_lut_from_values(&values, 16, 8);

        assert_eq!(
            lut.as_slice(),
            &[1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5]
        );
    }

    #[test]
    fn non_power_of_two_lut_matches_existing_interval() {
        let mut values = [0; 30];
        values[14] = 1;
        let lut: FieldPolynomial<FirstLevelField> = negacyclic_lut_from_values(&values, 2048, 30);

        let s = lut.as_slice();
        let l = s.iter().position(|v| *v == 1).unwrap_or_default();
        let r = s.iter().rposition(|v| *v == 1).unwrap_or_default();

        assert_eq!(l, 1844);
        assert_eq!(r, 1979);
    }

    #[test]
    fn sparse_lut_matches_dense_lut() {
        let mut values = vec![0; 30];
        values[0] = 7;
        values[15] = 11;

        let dense: FieldPolynomial<FirstLevelField> = negacyclic_lut_from_values(&values, 2048, 30);
        let sparse: FieldPolynomial<FirstLevelField> =
            negacyclic_lut_from_sparse_values(2048, 30, 0, &[(0, 7), (15, 11)]);

        assert_eq!(dense.as_slice(), sparse.as_slice());
    }

    #[test]
    fn function_lut_matches_dense_lut() {
        let values = vec![3, 5, 8, 13, 21, 34, 55, 89];

        let dense: FieldPolynomial<FirstLevelField> = negacyclic_lut_from_values(&values, 32, 14);
        let from_fn: FieldPolynomial<FirstLevelField> =
            negacyclic_lut_from_fn(32, 14, |message| values[message]);

        assert_eq!(dense.as_slice(), from_fn.as_slice());
    }
}
