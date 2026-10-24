//! Packed Shamir sharing over BN254 `Fr` (FR25b Def. 1, Fig. 3 TCitH-MT side).
//!
//! An `(s, ℓ, N)`-packed sharing of `v ∈ F^s` is the `N`-evaluation of the
//! degree-`d` polynomial `P(X) = I_v(X) + F(X)·R(X)` with `d = s + ℓ − 1`,
//! where `I_v` interpolates `(ω_k, v_k)`, `F(X) = ∏_{k=1..s}(X − ω_k)`, and `R`
//! is a uniform degree-`(ℓ−1)` polynomial from the randomness.
//!
//! Evaluation points are fixed protocol constants, distinct and disjoint:
//! secret coordinates `ω_k = k` (`1..=s`), party points `e_i = s + i`
//! (`1..=N`). All are tiny relative to `|Fr|`, so discussion of wrap or
//! collision does not arise.

use ark_bn254::Fr;
use ark_ff::{Field, One, UniformRand, Zero};
use rand::RngCore;

use crate::{MpcithError, Result};

/// Secret-coordinate point `ω_k = k` (1-based, `k ≤ s`).
pub fn coord_point(k: usize) -> Fr {
    Fr::from((k + 1) as u64)
}

/// Party evaluation point `e_i = s + i` (1-based, `i ≤ N`).
pub fn party_point(s: usize, i: usize) -> Fr {
    Fr::from((s + i + 1) as u64)
}

/// Evaluate a coefficient-form polynomial at `x` (Horner).
pub(crate) fn eval_poly(coeffs: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::zero();
    for c in coeffs.iter().rev() {
        acc *= x;
        acc += c;
    }
    acc
}

/// Lagrange-interpolate `values` at `points`, evaluated at `x`.
/// Points must be pairwise distinct; fails otherwise or on empty input.
pub fn interpolate_at(points: &[Fr], values: &[Fr], x: Fr) -> Result<Fr> {
    if points.len() != values.len() || points.is_empty() {
        return Err(MpcithError::InvalidParams(
            "v3 interpolation needs non-empty equal-length points/values".into(),
        ));
    }
    let n = points.len();
    for i in 0..n {
        for j in (i + 1)..n {
            if points[i] == points[j] {
                return Err(MpcithError::InvalidParams(
                    "v3 interpolation points must be distinct".into(),
                ));
            }
        }
    }
    let mut out = Fr::zero();
    for i in 0..n {
        let mut num = Fr::one();
        let mut den = Fr::one();
        for j in 0..n {
            if i == j {
                continue;
            }
            num *= x - points[j];
            den *= points[i] - points[j];
        }
        let den_inv = den.inverse().ok_or_else(|| {
            MpcithError::InvalidParams("v3 interpolation hit zero denominator".into())
        })?;
        out += values[i] * num * den_inv;
    }
    Ok(out)
}

/// Interpolate the coefficient form of the unique degree-`<n` polynomial
/// through `(points, values)` via Gaussian elimination (test/small sizes).
pub fn interpolate_coeffs(points: &[Fr], values: &[Fr]) -> Result<Vec<Fr>> {
    if points.len() != values.len() || points.is_empty() {
        return Err(MpcithError::InvalidParams(
            "v3 interpolation needs non-empty equal-length points/values".into(),
        ));
    }
    let n = points.len();
    // Augmented Vandermonde matrix: row i is [1, x_i, x_i^2, ... | y_i].
    let mut mat = vec![vec![Fr::zero(); n + 1]; n];
    for (i, (x, y)) in points.iter().zip(values.iter()).enumerate() {
        let mut pow = Fr::one();
        for j in 0..n {
            mat[i][j] = pow;
            pow *= x;
        }
        mat[i][n] = *y;
    }
    for col in 0..n {
        let mut pivot = None;
        for row in col..n {
            if !mat[row][col].is_zero() {
                pivot = Some(row);
                break;
            }
        }
        let pivot = pivot.ok_or_else(|| {
            MpcithError::InvalidParams("v3 interpolation matrix is singular".into())
        })?;
        mat.swap(col, pivot);
        let inv = mat[col][col].inverse().ok_or_else(|| {
            MpcithError::InvalidParams("v3 interpolation hit zero pivot".into())
        })?;
        for j in col..=n {
            mat[col][j] *= inv;
        }
        for row in 0..n {
            if row != col && !mat[row][col].is_zero() {
                let factor = mat[row][col];
                let pivot_row = mat[col].clone();
                for j in col..=n {
                    mat[row][j] -= factor * pivot_row[j];
                }
            }
        }
    }
    Ok((0..n).map(|i| mat[i][n]).collect())
}

/// Check `deg P ≤ max_degree` for the polynomial through `(points, values)`.
/// Needs at least `max_degree + 2` points to detect excess degree.
pub fn degree_within_bound(points: &[Fr], values: &[Fr], max_degree: usize) -> Result<bool> {
    if points.len() < max_degree + 2 {
        return Err(MpcithError::InvalidParams(format!(
            "v3 degree check needs at least {} points, got {}",
            max_degree + 2,
            points.len()
        )));
    }
    let coeffs = interpolate_coeffs(points, values)?;
    Ok(coeffs.iter().skip(max_degree + 1).all(|c| c.is_zero()))
}

/// Build a packed sharing of `secret` (`s` values) with `randomness` (`ℓ`
/// values) for `num_parties` parties. Returns one field element per party.
pub fn share(s: usize, ell: usize, num_parties: usize, secret: &[Fr], randomness: &[Fr]) -> Result<Vec<Fr>> {
    if secret.len() != s || s == 0 {
        return Err(MpcithError::InvalidParams(format!(
            "v3 share needs exactly s={s} secret values"
        )));
    }
    if randomness.len() != ell || ell == 0 {
        return Err(MpcithError::InvalidParams(format!(
            "v3 share needs exactly ell={ell} randomness values"
        )));
    }
    if num_parties < 2 {
        return Err(MpcithError::InvalidParams(
            "v3 share needs at least 2 parties".into(),
        ));
    }
    let omega: Vec<Fr> = (0..s).map(coord_point).collect();
    // I_v: degree-(s-1) interpolation of the secret at the coordinates.
    let iv = interpolate_coeffs(&omega, secret)?;
    // F(X) = prod (X - w_k), degree s.
    let mut f = vec![Fr::one()];
    for w in &omega {
        let mut next = vec![Fr::zero(); f.len() + 1];
        for (j, c) in f.iter().enumerate() {
            next[j] += *c * (-*w);
            next[j + 1] += *c;
        }
        f = next;
    }
    // R(X) from randomness (degree ell - 1).
    let r = randomness.to_vec();
    // F*R has degree s + ell - 1; P = I_v + F*R (pad I_v with zeros).
    let deg = s + ell - 1;
    let mut p = vec![Fr::zero(); deg + 1];
    for (j, c) in iv.iter().enumerate() {
        p[j] += c;
    }
    for (i, fc) in f.iter().enumerate() {
        for (j, rc) in r.iter().enumerate() {
            p[i + j] += *fc * *rc;
        }
    }
    Ok((0..num_parties)
        .map(|i| eval_poly(&p, party_point(s, i)))
        .collect())
}

/// Sample uniform random polynomial coefficients of exact `degree`
/// (leading coefficient forced nonzero).
pub fn random_poly(degree: usize, rng: &mut impl RngCore) -> Vec<Fr> {
    let mut coeffs: Vec<Fr> = (0..degree).map(|_| Fr::rand(rng)).collect();
    let mut leading = Fr::rand(rng);
    while leading.is_zero() {
        leading = Fr::rand(rng);
    }
    coeffs.push(leading);
    coeffs
}

/// Evaluate `poly` at all `N` party points.
pub fn eval_poly_all(poly: &[Fr], s: usize, num_parties: usize) -> Vec<Fr> {
    (0..num_parties)
        .map(|i| eval_poly(poly, party_point(s, i)))
        .collect()
}

/// Sample a uniformly random polynomial of exact `degree` and return its
/// evaluations at the `N` party points. Used for hint-oracle-style sharings
/// that carry no prescribed secret (FR25b §6.1 Π$/Π0/ΠΣ0 pre-correction
/// outputs). Exact (not at-most) degree keeps degenerate inputs out of
/// tests; the 1/|F| distribution difference is immaterial for a prototype
/// that makes no zero-knowledge claim.
pub fn random_poly_shares(
    s: usize,
    degree: usize,
    num_parties: usize,
    rng: &mut impl RngCore,
) -> Result<Vec<Fr>> {
    if num_parties < 2 {
        return Err(MpcithError::InvalidParams(
            "v3 random sharing needs at least 2 parties".into(),
        ));
    }
    Ok(eval_poly_all(&random_poly(degree, rng), s, num_parties))
}
/// Recover the packed secret from at least `s + ℓ` shares.
pub fn reconstruct(
    s: usize,
    ell: usize,
    shares: &[(Fr, Fr)],
) -> Result<Vec<Fr>> {
    if shares.len() < s + ell {
        return Err(MpcithError::InvalidParams(format!(
            "v3 reconstruct needs at least {} shares, got {}",
            s + ell,
            shares.len()
        )));
    }
    let (points, values): (Vec<Fr>, Vec<Fr>) = shares.iter().cloned().unzip();
    (0..s)
        .map(|k| interpolate_at(&points, &values, coord_point(k)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0x7633_5F33)
    }

    #[test]
    fn share_reconstruct_round_trip() {
        use ark_ff::UniformRand;
        let mut rng = test_rng();
        let (s, ell, n) = (8usize, 3usize, 32usize);
        let secret: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();
        let rand: Vec<Fr> = (0..ell).map(|_| Fr::rand(&mut rng)).collect();
        let shares = share(s, ell, n, &secret, &rand).unwrap();
        assert_eq!(shares.len(), n);
        let points: Vec<(Fr, Fr)> = (0..n).map(|i| (party_point(s, i), shares[i])).collect();
        // Exactly threshold shares suffice.
        let recovered = reconstruct(s, ell, &points[..s + ell]).unwrap();
        assert_eq!(recovered, secret);
        // All shares also work.
        let recovered = reconstruct(s, ell, &points).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn committed_shares_have_expected_degree() {
        use ark_ff::UniformRand;
        let mut rng = test_rng();
        let (s, ell, n) = (8usize, 3usize, 32usize);
        let secret: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();
        let rand: Vec<Fr> = (0..ell).map(|_| Fr::rand(&mut rng)).collect();
        let shares = share(s, ell, n, &secret, &rand).unwrap();
        let points: Vec<Fr> = (0..n).map(|i| party_point(s, i)).collect();
        assert!(degree_within_bound(&points, &shares, s + ell - 1).unwrap());
        assert!(!degree_within_bound(&points, &shares, s + ell - 2).unwrap_or(true)
            || s + ell - 2 >= n - 1);
    }

    #[test]
    fn tampered_share_breaks_reconstruction() {
        use ark_ff::UniformRand;
        let mut rng = test_rng();
        let (s, ell, n) = (8usize, 3usize, 32usize);
        let secret: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();
        let rand: Vec<Fr> = (0..ell).map(|_| Fr::rand(&mut rng)).collect();
        let mut shares = share(s, ell, n, &secret, &rand).unwrap();
        shares[0] += Fr::one();
        let points: Vec<(Fr, Fr)> = (0..n).map(|i| (party_point(s, i), shares[i])).collect();
        let recovered = reconstruct(s, ell, &points).unwrap();
        assert_ne!(recovered, secret);
    }

    #[test]
    fn bad_inputs_are_rejected() {
        let good = vec![Fr::one(); 8];
        let rand = vec![Fr::one(); 3];
        assert!(share(8, 3, 32, &good[..7], &rand).is_err());
        assert!(share(8, 3, 32, &good, &rand[..2]).is_err());
        assert!(share(8, 3, 1, &good, &rand).is_err());
        let pts = vec![(Fr::one(), Fr::one()); 4];
        assert!(reconstruct(8, 3, &pts).is_err());
        // Duplicate points are rejected.
        let dup = vec![Fr::one(), Fr::one()];
        let vals = vec![Fr::one(), Fr::one()];
        assert!(interpolate_at(&dup, &vals, Fr::one()).is_err());
    }
}
