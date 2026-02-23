//! Matrix solvers (Gaussian elimination) for decoding combined payloads.

use algebra::{
    arith::Xgcd,
    modulus::{BarrettModulus, PowOf2Modulus},
    reduce::{ReduceMul, ReduceMulAssign, ReduceSubAssign, RingReduce},
};

use crate::{payload::PayloadByteType, OmrError, Payload};

const MODULUS256: PowOf2Modulus<PayloadByteType> = <PowOf2Modulus<PayloadByteType>>::new(256);

const INV_MOD_256: [u16; 256] = [
    0, 1, 0, 171, 0, 205, 0, 183, 0, 57, 0, 163, 0, 197, 0, 239, 0, 241, 0, 27, 0, 61, 0, 167, 0,
    41, 0, 19, 0, 53, 0, 223, 0, 225, 0, 139, 0, 173, 0, 151, 0, 25, 0, 131, 0, 165, 0, 207, 0,
    209, 0, 251, 0, 29, 0, 135, 0, 9, 0, 243, 0, 21, 0, 191, 0, 193, 0, 107, 0, 141, 0, 119, 0,
    249, 0, 99, 0, 133, 0, 175, 0, 177, 0, 219, 0, 253, 0, 103, 0, 233, 0, 211, 0, 245, 0, 159, 0,
    161, 0, 75, 0, 109, 0, 87, 0, 217, 0, 67, 0, 101, 0, 143, 0, 145, 0, 187, 0, 221, 0, 71, 0,
    201, 0, 179, 0, 213, 0, 127, 0, 129, 0, 43, 0, 77, 0, 55, 0, 185, 0, 35, 0, 69, 0, 111, 0, 113,
    0, 155, 0, 189, 0, 39, 0, 169, 0, 147, 0, 181, 0, 95, 0, 97, 0, 11, 0, 45, 0, 23, 0, 153, 0, 3,
    0, 37, 0, 79, 0, 81, 0, 123, 0, 157, 0, 7, 0, 137, 0, 115, 0, 149, 0, 63, 0, 65, 0, 235, 0, 13,
    0, 247, 0, 121, 0, 227, 0, 5, 0, 47, 0, 49, 0, 91, 0, 125, 0, 231, 0, 105, 0, 83, 0, 117, 0,
    31, 0, 33, 0, 203, 0, 237, 0, 215, 0, 89, 0, 195, 0, 229, 0, 15, 0, 17, 0, 59, 0, 93, 0, 199,
    0, 73, 0, 51, 0, 85, 0, 255,
];

const INV_MOD_257: [u16; 257] = [
    0, 1, 129, 86, 193, 103, 43, 147, 225, 200, 180, 187, 150, 178, 202, 120, 241, 121, 100, 230,
    90, 49, 222, 190, 75, 72, 89, 238, 101, 195, 60, 199, 249, 148, 189, 235, 50, 132, 115, 145,
    45, 163, 153, 6, 111, 40, 95, 175, 166, 21, 36, 126, 173, 97, 119, 243, 179, 248, 226, 61, 30,
    59, 228, 102, 253, 87, 74, 234, 223, 149, 246, 181, 25, 169, 66, 24, 186, 247, 201, 244, 151,
    165, 210, 96, 205, 127, 3, 65, 184, 26, 20, 209, 176, 152, 216, 46, 83, 53, 139, 135, 18, 28,
    63, 5, 215, 164, 177, 245, 188, 224, 250, 44, 218, 116, 124, 38, 113, 134, 159, 54, 15, 17,
    158, 140, 114, 220, 51, 85, 255, 2, 172, 206, 37, 143, 117, 99, 240, 242, 203, 98, 123, 144,
    219, 133, 141, 39, 213, 7, 33, 69, 12, 80, 93, 42, 252, 194, 229, 239, 122, 118, 204, 174, 211,
    41, 105, 81, 48, 237, 231, 73, 192, 254, 130, 52, 161, 47, 92, 106, 13, 56, 10, 71, 233, 191,
    88, 232, 76, 11, 108, 34, 23, 183, 170, 4, 155, 29, 198, 227, 196, 31, 9, 78, 14, 138, 160, 84,
    131, 221, 236, 91, 82, 162, 217, 146, 251, 104, 94, 212, 112, 142, 125, 207, 22, 68, 109, 8,
    58, 197, 62, 156, 19, 168, 185, 182, 67, 35, 208, 167, 27, 157, 136, 16, 137, 55, 79, 107, 70,
    77, 57, 32, 110, 214, 154, 64, 171, 128, 256,
];

#[inline]
fn mat_get(matrix: &[Vec<PayloadByteType>], row: usize, col: usize) -> PayloadByteType {
    unsafe { *matrix.get_unchecked(row).get_unchecked(col) }
}

#[inline]
fn mat_get_mut(
    matrix: &mut [Vec<PayloadByteType>],
    row: usize,
    col: usize,
) -> &mut PayloadByteType {
    unsafe { matrix.get_unchecked_mut(row).get_unchecked_mut(col) }
}

#[inline]
fn mat_set(matrix: &mut [Vec<PayloadByteType>], row: usize, col: usize, value: PayloadByteType) {
    unsafe { *matrix.get_unchecked_mut(row).get_unchecked_mut(col) = value }
}

#[inline]
fn mat_row_get_mut(matrix: &mut [Vec<PayloadByteType>], row: usize) -> &mut [PayloadByteType] {
    unsafe { matrix.get_unchecked_mut(row) }
}

#[inline]
fn arr_get(payloads: &[Payload], index: usize) -> Payload {
    unsafe { *payloads.get_unchecked(index) }
}

#[inline]
fn arr_get_mut(payloads: &mut [Payload], index: usize) -> &mut Payload {
    unsafe { payloads.get_unchecked_mut(index) }
}

/// Solves a matrix modulo 256.
pub fn solve_matrix_mod_256(
    matrix: &mut [Vec<PayloadByteType>],
    payloads: &mut [Payload],
) -> Result<Vec<Payload>, OmrError> {
    // Gaussian elimination (forward) + back substitution (mod 256).
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
        let value = mat_get(matrix, i, i);
        if value != 1 {
            let inv = unsafe { *INV_MOD_256.get_unchecked(value as usize) };
            mat_set(matrix, i, i, 1);
            mat_row_get_mut(matrix, i)[i + 1..]
                .iter_mut()
                .for_each(|w| {
                    MODULUS256.reduce_mul_assign(w, inv);
                });

            arr_get_mut(payloads, i).mul_scalar_assign(inv, MODULUS256);
        }

        // If the i-th column is the last column, we are done
        if i == num_cols - 1 {
            break;
        }

        // Eliminate the rows after the i-th row and update the payloads
        for i_rows in i + 1..num_rows {
            let c = mat_get(matrix, i_rows, i);
            if c != 0 {
                for i_cols in i..num_cols {
                    let temp = MODULUS256.reduce_mul(mat_get(matrix, i, i_cols), c);
                    MODULUS256.reduce_sub_assign(mat_get_mut(matrix, i_rows, i_cols), temp);
                }

                let temp = arr_get(payloads, i).mul_scalar(c, MODULUS256);
                arr_get_mut(payloads, i_rows).sub_assign(&temp, MODULUS256);
            }
        }
    }

    // Backward substitution
    for i_cols in (1..num_cols).rev() {
        for i_rows in 0..i_cols {
            let c = mat_get(matrix, i_rows, i_cols);
            if c != 0 {
                // payloads[i_rows] -= payloads[i_cols] * c;
                let temp = arr_get(payloads, i_cols).mul_scalar(c, MODULUS256);
                arr_get_mut(payloads, i_rows).sub_assign(&temp, MODULUS256);
                mat_set(matrix, i_rows, i_cols, 0);
            }
        }
    }

    Ok(payloads.iter().copied().take(num_cols).collect())
}

const MODULUS_257: BarrettModulus<PayloadByteType> = <BarrettModulus<PayloadByteType>>::new(257);

/// Solves a matrix modulo 257.
pub fn solve_matrix_mod_257(
    matrix: &mut [Vec<PayloadByteType>],
    payloads: &mut [Payload],
) -> Result<Vec<Payload>, OmrError> {
    // Gaussian elimination (forward) + back substitution (mod 257).
    let num_rows = matrix.len();
    let num_cols = matrix[0].len();

    assert!(num_rows >= num_cols);

    // Gaussian elimination
    for i in 0..num_cols {
        // Find the first row with non-zero value in the i-th column
        let mut pick_index = None;
        for (j, row) in matrix.iter().enumerate().take(num_rows).skip(i) {
            if row[i] != 0 {
                pick_index = Some(j);
                break;
            }
        }

        // If no such row exists, the matrix is not invertible
        if pick_index.is_none() {
            return Err(OmrError::InvertibleMatrix);
        }

        // Swap the rows
        let pick_index = pick_index.unwrap();
        if i != pick_index {
            matrix.swap(i, pick_index);
            payloads.swap(i, pick_index);
        }

        // Normalize the i-th row, so that the (i, i)-th element is 1
        let value = mat_get(matrix, i, i);
        if value != 1 {
            let inv = unsafe { *INV_MOD_257.get_unchecked(value as usize) };

            mat_set(matrix, i, i, 1);
            mat_row_get_mut(matrix, i)[i + 1..]
                .iter_mut()
                .for_each(|w| {
                    MODULUS_257.reduce_mul_assign(w, inv);
                });

            arr_get_mut(payloads, i).mul_scalar_assign(inv, MODULUS_257);
        }

        // If the i-th column is the last column, we are done
        if i == num_cols - 1 {
            break;
        }

        // Eliminate the rows after the i-th row and update the payloads
        for i_rows in i + 1..num_rows {
            let c = mat_get(matrix, i_rows, i);

            if c != 0 {
                for i_cols in i..num_cols {
                    let temp = MODULUS_257.reduce_mul(mat_get(matrix, i, i_cols), c);
                    MODULUS_257.reduce_sub_assign(mat_get_mut(matrix, i_rows, i_cols), temp);
                }

                let temp = arr_get(payloads, i).mul_scalar(c, MODULUS_257);
                arr_get_mut(payloads, i_rows).sub_assign(&temp, MODULUS_257);
            }
        }
    }

    // Backward substitution
    for i_cols in (1..num_cols).rev() {
        for i_rows in 0..i_cols {
            let c = mat_get(matrix, i_rows, i_cols);

            if c != 0 {
                let temp = arr_get(payloads, i_cols).mul_scalar(c, MODULUS_257);
                arr_get_mut(payloads, i_rows).sub_assign(&temp, MODULUS_257);
                mat_set(matrix, i_rows, i_cols, 0);
            }
        }
    }

    Ok(payloads.iter().copied().take(num_cols).collect())
}

/// Solves a matrix modulo `modulus`.
pub fn solve_matrix<M: RingReduce<PayloadByteType>>(
    matrix: &mut [Vec<PayloadByteType>],
    payloads: &mut [Payload],
    modulus: M,
    modulus_value: PayloadByteType,
) -> Result<Vec<Payload>, OmrError> {
    // Gaussian elimination (forward) + back substitution (mod p).
    let num_rows = matrix.len();
    let num_cols = matrix[0].len();

    assert!(num_rows >= num_cols);

    // Gaussian elimination
    for i in 0..num_cols {
        // Find the first row with non-zero value in the i-th column
        let mut pick_index = None;
        for (j, row) in matrix.iter().enumerate().take(num_rows).skip(i) {
            if row[i] != 0 {
                pick_index = Some(j);
                break;
            }
        }

        // If no such row exists, the matrix is not invertible
        if pick_index.is_none() {
            return Err(OmrError::InvertibleMatrix);
        }

        // Swap the rows
        let pick_index = pick_index.unwrap();
        if i != pick_index {
            matrix.swap(i, pick_index);
            payloads.swap(i, pick_index);
        }

        // Normalize the i-th row, so that the (i, i)-th element is 1
        let value = mat_get(matrix, i, i);
        if value != 1 {
            let (inv, gcd) = Xgcd::gcdinv(value, modulus_value);
            assert_eq!(gcd, 1, "value: {}", value);

            mat_set(matrix, i, i, 1);
            mat_row_get_mut(matrix, i)[i + 1..]
                .iter_mut()
                .for_each(|w| {
                    modulus.reduce_mul_assign(w, inv);
                });

            arr_get_mut(payloads, i).mul_scalar_assign(inv, modulus);
        }

        // If the i-th column is the last column, we are done
        if i == num_cols - 1 {
            break;
        }

        // Eliminate the rows after the i-th row and update the payloads
        for i_rows in i + 1..num_rows {
            let c = mat_get(matrix, i_rows, i);

            if c != 0 {
                for i_cols in i..num_cols {
                    let temp = modulus.reduce_mul(mat_get(matrix, i, i_cols), c);
                    modulus.reduce_sub_assign(mat_get_mut(matrix, i_rows, i_cols), temp);
                }

                let temp = arr_get(payloads, i).mul_scalar(c, modulus);
                arr_get_mut(payloads, i_rows).sub_assign(&temp, modulus);
            }
        }
    }

    // Backward substitution
    for i_cols in (1..num_cols).rev() {
        for i_rows in 0..i_cols {
            let c = mat_get(matrix, i_rows, i_cols);

            if c != 0 {
                let temp = arr_get(payloads, i_cols).mul_scalar(c, modulus);
                arr_get_mut(payloads, i_rows).sub_assign(&temp, modulus);
                mat_set(matrix, i_rows, i_cols, 0);
            }
        }
    }

    Ok(payloads.iter().copied().take(num_cols).collect())
}

#[test]
fn feature() {
    let p: u16 = 256;
    let mut inv = vec![0; p as usize];

    inv[0] = 0;
    inv[1] = 1;
    inv.iter_mut().enumerate().skip(2).for_each(|(i, w)| {
        let (v, gcd) = Xgcd::gcdinv(i as u16, p);
        if gcd == 1 {
            *w = v;
        }
    });

    println!("{:?}", inv);
}
