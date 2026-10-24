//! Packed witness-matrix layout (FR25b §2.1, §6.3).
//!
//! The LPPC extended witness `w ∈ F^(ns)` is arranged as `n` packs (rows) of
//! `s` coordinates (columns):
//!
//! ```text
//!             col 0 .. col s-1
//! row 0:      w_0 .. w_{s-1}            (pack 0)
//! row 1:      w_s .. w_{2s-1}          (pack 1)
//! ...
//! ```
//!
//! Each row becomes one packed Shamir sharing; each row is one Merkle leaf.
//! Column tuples `w^(k)` (FR25b §6.3) are the parallel-constraint lanes. This
//! module owns dimensions, row/column indexing, and pack/unpack only — the
//! circuit-to-matrix compiler is Phase 2.

use crate::v3::params::V3Params;
use crate::{MpcithError, Result};

/// Witness-matrix dimensions derived from a parameter set and a witness
/// length: `n = ⌈len / s⌉` packs (FR25b §6.3–6.4, `|w| = 3|C|` for ΠLigero).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatrixDims {
    /// Number of packs (rows), `n`.
    pub num_rows: usize,
    /// Packing width (columns), `s`.
    pub num_cols: usize,
    /// Padded witness length `n · s`.
    pub padded_len: usize,
}

impl MatrixDims {
    /// Derive dimensions for `witness_len` field elements under `params`.
    pub fn new(params: &V3Params, witness_len: usize) -> Result<Self> {
        params.validate()?;
        if witness_len == 0 {
            return Err(MpcithError::InvalidParams(
                "v3 witness matrix requires a non-empty witness".into(),
            ));
        }
        let s = params.packing_width as usize;
        let num_rows = witness_len.div_ceil(s);
        Ok(Self {
            num_rows,
            num_cols: s,
            padded_len: num_rows * s,
        })
    }

    /// Row-major index of `(row, col)`.
    pub fn index(&self, row: usize, col: usize) -> Result<usize> {
        if row >= self.num_rows || col >= self.num_cols {
            return Err(MpcithError::InvalidParams(format!(
                "v3 matrix index ({row}, {col}) out of {}x{}",
                self.num_rows, self.num_cols
            )));
        }
        Ok(row * self.num_cols + col)
    }
}

/// Arrange a flat witness into a padded row-major matrix.
pub fn pack_witness<F: Clone + Default>(
    dims: &MatrixDims,
    witness: &[F],
) -> Result<Vec<Vec<F>>> {
    if witness.len() > dims.padded_len {
        return Err(MpcithError::InvalidParams(format!(
            "v3 witness len {} exceeds padded matrix len {}",
            witness.len(),
            dims.padded_len
        )));
    }
    let mut rows = Vec::with_capacity(dims.num_rows);
    for r in 0..dims.num_rows {
        let mut row = vec![F::default(); dims.num_cols];
        for c in 0..dims.num_cols {
            let flat = r * dims.num_cols + c;
            if flat < witness.len() {
                row[c] = witness[flat].clone();
            }
        }
        rows.push(row);
    }
    Ok(rows)
}

/// Flatten a matrix back to its padded row-major witness (length `n·s`).
pub fn unpack_matrix<F: Clone>(rows: &[Vec<F>], dims: &MatrixDims) -> Result<Vec<F>> {
    if rows.len() != dims.num_rows {
        return Err(MpcithError::InvalidParams(format!(
            "v3 matrix has {} rows, expected {}",
            rows.len(),
            dims.num_rows
        )));
    }
    let mut flat = Vec::with_capacity(dims.padded_len);
    for (r, row) in rows.iter().enumerate() {
        if row.len() != dims.num_cols {
            return Err(MpcithError::InvalidParams(format!(
                "v3 matrix row {r} has {} cols, expected {}",
                row.len(),
                dims.num_cols
            )));
        }
        flat.extend(row.iter().cloned());
    }
    Ok(flat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    #[test]
    fn dims_match_phase0_model_values() {
        // 32-member combined: |w| = 3*1774 + pad allowance; Phase 0 used
        // n = ceil((3C + x)/s) with C=1774, x=95.
        let proto = V3Params::prototype_tau2();
        let dims = MatrixDims::new(&proto, 3 * 1774 + 95).unwrap();
        assert_eq!((dims.num_rows, dims.num_cols), (46, 120));
        let publ = V3Params::published_reference_tau1();
        let dims = MatrixDims::new(&publ, 3 * 1774 + 95).unwrap();
        assert_eq!((dims.num_rows, dims.num_cols), (41, 133));
    }

    #[test]
    fn pack_unpack_round_trip_with_zero_padding() {
        let params = V3Params::fast_insecure_test(); // s = 8
        let dims = MatrixDims::new(&params, 10).unwrap();
        assert_eq!((dims.num_rows, dims.num_cols, dims.padded_len), (2, 8, 16));
        let witness: Vec<Fr> = (0..10u64).map(Fr::from).collect();
        let rows = pack_witness(&dims, &witness).unwrap();
        assert_eq!(rows.len(), 2);
        // Tail of the last row is zero padding.
        for c in 2..8 {
            assert_eq!(rows[1][c], Fr::from(0u64));
        }
        let flat = unpack_matrix(&rows, &dims).unwrap();
        assert_eq!(flat.len(), 16);
        assert_eq!(&flat[..10], &witness[..]);
        assert!(flat[10..].iter().all(|v| *v == Fr::from(0u64)));
    }

    #[test]
    fn bad_dimensions_and_shapes_are_rejected() {
        let params = V3Params::fast_insecure_test();
        assert!(MatrixDims::new(&params, 0).is_err());
        let dims = MatrixDims::new(&params, 8).unwrap();
        assert!(dims.index(0, 8).is_err());
        assert!(dims.index(1, 0).is_err());
        let witness = vec![Fr::from(1u64); 17];
        assert!(pack_witness(&dims, &witness).is_err());
        let rows = vec![vec![Fr::from(0u64); 8]];
        assert!(unpack_matrix(&rows, &dims).is_ok());
        assert!(unpack_matrix::<Fr>(&[], &dims).is_err());
    }
}
