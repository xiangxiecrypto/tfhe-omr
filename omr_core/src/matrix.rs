use algebra::arith::Xgcd;

use crate::{OmrError, Payload};

/// Solves a matrix modulo 256.
pub fn solve_matrix_mod_256(
    matrix: &mut [Vec<u8>],
    payloads: &mut [Payload],
) -> Result<Vec<Payload>, OmrError> {
    let num_rows = matrix.len();
    let num_cols = matrix[0].len();

    assert!(num_rows >= num_cols);

    // Gaussian elimination
    for i in 0..num_cols {
        // Find the first row with an odd value in the i-th column
        let mut odd_index = None;
        for (j, row) in matrix.iter().enumerate().take(num_rows).skip(i) {
            if row[i] % 2 == 1 {
                odd_index = Some(j);
                break;
            }
        }

        // If no such row exists, the matrix is not invertible
        if odd_index.is_none() {
            return Err(OmrError::InvertibleMatrix);
        }

        // Swap the rows
        let odd_index = odd_index.unwrap();
        if i != odd_index {
            matrix.swap(i, odd_index);
            payloads.swap(i, odd_index);
        }

        // Normalize the i-th row, so that the (i, i)-th element is 1
        let value = matrix[i][i];
        if value != 1 {
            let (inv, gcd) = Xgcd::gcdinv(value as u16, 256);
            assert_eq!(gcd, 1, "value: {}", value);
            let inv = inv as u8;

            matrix[i][i..].iter_mut().for_each(|w| {
                *w = w.wrapping_mul(inv);
            });
            payloads[i] *= inv;
        }

        // If the i-th column is the last column, we are done
        if i == num_cols - 1 {
            break;
        }

        // Eliminate the rows after the i-th row and update the payloads
        for i_rows in i + 1..num_rows {
            let c = matrix[i_rows][i];
            if c != 0 {
                for i_cols in i..num_cols {
                    matrix[i_rows][i_cols] =
                        matrix[i_rows][i_cols].wrapping_sub(matrix[i][i_cols].wrapping_mul(c));
                }
                payloads[i_rows] -= payloads[i] * c;
            }
        }
    }

    // Backward substitution
    for i_cols in (0..num_cols).rev() {
        if i_cols > 0 {
            for i_rows in 0..i_cols {
                let c = matrix[i_rows][i_cols];
                if c != 0 {
                    payloads[i_rows] -= payloads[i_cols] * c;
                    matrix[i_rows][i_cols] = 0;
                }
            }
        }
    }

    Ok(payloads.iter().copied().take(num_cols).collect())
}
