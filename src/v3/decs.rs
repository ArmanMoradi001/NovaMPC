//! Degree-enforcing round (FR25b §4.2, §5, Protocol 5 steps 1–1b, 7–8).
//!
//! Paper protocol (TCitH-MT): after the prover commits all sharings
//! (`JwK`, mask `JuK`, hints) under Merkle root `h1`, the verifier samples
//! `Γ ∈ F^{η×|Q|}` where `Q` is the degree-aligned concatenation of every
//! committed polynomial (Eq. 13: each shifted by `X^{dβ−deg}` to degree
//! `dβ`, plus mask `Pu`). The prover answers `Pξ = Γ·Q + Pu` (Eq. 14) with
//! `h1' = Hash(Pξ)` — BEFORE seeing MPC randomness or the opening set `I`.
//! At opening the prover reveals `Pξ(e_i)` for `i ∈ S`, `|S| = dβ+1−ℓ`,
//! `S ∩ I = ∅`; the verifier recomputes `Pξ(e_i)` for `i ∈ I` from opened
//! shares, interpolates over `S ∪ I` (`dβ+1` points), and checks
//! hash-equality against `h1'`. Detection comes from that hash binding
//! (Theorem 1: `C(N,dβ+2)/|F|^η`), NOT from a degree test on the
//! interpolant — any `dβ+1` values interpolate to degree `≤ dβ`, so such a
//! test would be vacuous at the protocol's point count.
//!
//! The helpers below implement the checkable unit used by tests:
//! combination, response evaluation, and verification from opened
//! evaluations. `verify_responses` additionally enforces a `d+2`-point
//! degree check, which is a STRICTER-THAN-PROTOCOL harness check (the P3.0
//! fix): it catches inconsistent high-degree responses with fewer moving
//! parts, but it is not the paper's verifier equation. The Phase-3 prover
//! must implement `h1'` pre-commitment plus reconstruction-equality, the
//! `X`-shift alignment, and the mask sharing `JuK`. Challenge sampling
//! (`Γ`) moves to the transcript in Phase 3.
//!
//! Size accounting (Phase-0 model, Eq. 16): the DECS term
//! `(dβ+1)·η·log|F|` is `(dβ+1−ℓ)·η` S-response elements plus `ℓ·η` opened
//! mask shares per repetition — exactly the messages above. Verified
//! against the Protocol 5 transcript list, not just the helper.

use ark_bn254::Fr;
use ark_ff::Zero;

use crate::v3::sharing::{eval_poly, interpolate_coeffs};
use crate::{MpcithError, Result};

/// Compute `R = Σ_i coeffs[i] · polys[i]` in coefficient form. Row
/// polynomials of different lengths are zero-padded (polynomial addition).
pub fn combine_rows(polys: &[Vec<Fr>], coeffs: &[Fr]) -> Result<Vec<Fr>> {
    if polys.is_empty() || coeffs.len() != polys.len() {
        return Err(MpcithError::InvalidParams(format!(
            "v3 DECS needs equal non-empty poly/coeff counts, got {}/{}",
            polys.len(),
            coeffs.len()
        )));
    }
    let len = polys.iter().map(|p| p.len()).max().unwrap_or(0);
    let mut out = vec![Fr::zero(); len];
    for (poly, c) in polys.iter().zip(coeffs.iter()) {
        if c.is_zero() {
            continue;
        }
        for (j, v) in poly.iter().enumerate() {
            out[j] += *v * *c;
        }
    }
    Ok(out)
}

/// Exact degree of a coefficient-form polynomial (`None` for the zero poly).
pub fn poly_degree(coeffs: &[Fr]) -> Option<usize> {
    coeffs.iter().rposition(|c| !c.is_zero())
}

/// Check `deg P ≤ max_degree` in coefficient form.
pub fn meets_degree(coeffs: &[Fr], max_degree: usize) -> bool {
    match poly_degree(coeffs) {
        None => true,
        Some(d) => d <= max_degree,
    }
}

/// Evaluate every combination response at the given points (prover side).
pub fn evaluate_responses(combinations: &[Vec<Fr>], points: &[Fr]) -> Vec<Vec<Fr>> {
    combinations
        .iter()
        .map(|r| points.iter().map(|x| eval_poly(r, *x)).collect())
        .collect()
}

/// Verify DECS responses (verifier side): for each combination `k`, the
/// claimed evaluations at `points` must interpolate to degree `≤ max_degree`
/// and must equal the `Γ`-combination of the opened row evaluations.
///
/// - `row_evals[i][j]`: opened evaluation of row polynomial `i` at
///   `points[j]`.
/// - `gamma[k][i]`: challenge coefficient for combination `k`, row `i`.
/// - `responses[k][j]`: prover-claimed `R_k(points[j])`.
pub fn verify_responses(
    row_evals: &[Vec<Fr>],
    gamma: &[Vec<Fr>],
    responses: &[Vec<Fr>],
    points: &[Fr],
    max_degree: usize,
) -> Result<bool> {
    if gamma.len() != responses.len() {
        return Err(MpcithError::InvalidParams(format!(
            "v3 DECS needs one response per gamma row, got {}/{}",
            responses.len(),
            gamma.len()
        )));
    }
    // `d+1` evaluations always interpolate to some degree-`d` polynomial, so
    // they cannot detect a malicious degree-`d+1` response. Require one more
    // evaluation before checking the claimed degree bound.
    if points.len() < max_degree + 2 {
        return Err(MpcithError::InvalidParams(format!(
            "v3 DECS needs at least {} opened points for degree testing, got {}",
            max_degree + 2,
            points.len()
        )));
    }
    for (row, evals) in row_evals.iter().enumerate() {
        if evals.len() != points.len() {
            return Err(MpcithError::InvalidParams(format!(
                "v3 DECS row {row} has {} evals for {} points",
                evals.len(),
                points.len()
            )));
        }
    }
    for (k, (g_row, resp)) in gamma.iter().zip(responses.iter()).enumerate() {
        if g_row.len() != row_evals.len() {
            return Err(MpcithError::InvalidParams(format!(
                "v3 DECS gamma row {k} has {} coeffs for {} rows",
                g_row.len(),
                row_evals.len()
            )));
        }
        if resp.len() != points.len() {
            return Err(MpcithError::InvalidParams(format!(
                "v3 DECS response {k} has {} evals for {} points",
                resp.len(),
                points.len()
            )));
        }
        // Consistency: resp[j] == Σ_i γ[k][i] · row_evals[i][j].
        for j in 0..points.len() {
            let mut expected = Fr::zero();
            for (i, row) in row_evals.iter().enumerate() {
                expected += g_row[i] * row[j];
            }
            if resp[j] != expected {
                return Ok(false);
            }
        }
        // Degree: interpolated R_k must satisfy deg ≤ d.
        let coeffs = interpolate_coeffs(points, resp)?;
        if !meets_degree(&coeffs, max_degree) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::params::V3Params;
    use crate::v3::sharing::{party_point, share};
    use ark_ff::One;
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xDE05_FD)
    }

    /// Committed row polynomials of degree `d_beta` from real sharings.
    fn honest_rows(s: usize, ell: usize, n_rows: usize, n: usize) -> Vec<Vec<Fr>> {
        let mut r = rng();
        (0..n_rows)
            .map(|_| {
                let secret: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut r)).collect();
                let rand: Vec<Fr> = (0..ell).map(|_| Fr::rand(&mut r)).collect();
                let shares = share(s, ell, n, &secret, &rand).unwrap();
                let pts: Vec<Fr> = (0..n).map(|i| party_point(s, i)).collect();
                interpolate_coeffs(&pts, &shares).unwrap()
            })
            .collect()
    }

    #[test]
    fn honest_combinations_pass_degree_and_consistency() {
        let (s, ell, n) = (8usize, 3usize, 32usize);
        let d_beta = s + ell - 1;
        let rows = honest_rows(s, ell, 4, n);
        let mut r = rng();
        let gamma: Vec<Vec<Fr>> = (0..2)
            .map(|_| (0..4).map(|_| Fr::rand(&mut r)).collect())
            .collect();
        let points: Vec<Fr> = (0..d_beta + 2).map(|i| party_point(s, i)).collect();
        let combos: Vec<Vec<Fr>> = gamma
            .iter()
            .map(|g| combine_rows(&rows, g).unwrap())
            .collect();
        assert!(combos.iter().all(|c| meets_degree(c, d_beta)));
        let row_evals: Vec<Vec<Fr>> = rows
            .iter()
            .map(|p| points.iter().map(|x| eval_poly(p, *x)).collect())
            .collect();
        let responses = evaluate_responses(&combos, &points);
        assert!(verify_responses(&row_evals, &gamma, &responses, &points, d_beta).unwrap());

        // A d+1-point view is not enough to check a degree-d bound: every such
        // vector interpolates to some polynomial of degree at most d.
        let short_points = &points[..d_beta + 1];
        let short_rows: Vec<Vec<Fr>> = rows
            .iter()
            .map(|poly| short_points.iter().map(|x| eval_poly(poly, *x)).collect())
            .collect();
        let short_responses = evaluate_responses(&combos, short_points);
        assert!(
            verify_responses(&short_rows, &gamma, &short_responses, short_points, d_beta).is_err()
        );
    }

    #[test]
    fn high_degree_row_is_detected() {
        let (s, ell, n) = (8usize, 3usize, 32usize);
        let d_beta = s + ell - 1;
        let mut rows = honest_rows(s, ell, 3, n);
        // Append an over-degree row polynomial (degree d_beta + 1).
        let mut bad = vec![Fr::zero(); d_beta + 2];
        bad[d_beta + 1] = Fr::from(1u64);
        rows.push(bad);
        // Nonzero challenge weight on the bad row forces the combination over
        // degree with probability 1 - 1/|F|; use weight 1 deterministically.
        let gamma = vec![vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(1u64),
        ]];
        let points: Vec<Fr> = (0..d_beta + 2).map(|i| party_point(s, i)).collect();
        let combos: Vec<Vec<Fr>> = gamma
            .iter()
            .map(|g| combine_rows(&rows, g).unwrap())
            .collect();
        assert!(!meets_degree(&combos[0], d_beta));
        let row_evals: Vec<Vec<Fr>> = rows
            .iter()
            .map(|p| points.iter().map(|x| eval_poly(p, *x)).collect())
            .collect();
        let responses = evaluate_responses(&combos, &points);
        assert!(!verify_responses(&row_evals, &gamma, &responses, &points, d_beta).unwrap());
    }

    #[test]
    fn inconsistent_responses_are_rejected() {
        let (s, ell, n) = (8usize, 3usize, 32usize);
        let d_beta = s + ell - 1;
        let rows = honest_rows(s, ell, 2, n);
        let gamma = vec![vec![Fr::from(1u64), Fr::from(1u64)]];
        let points: Vec<Fr> = (0..d_beta + 2).map(|i| party_point(s, i)).collect();
        let row_evals: Vec<Vec<Fr>> = rows
            .iter()
            .map(|p| points.iter().map(|x| eval_poly(p, *x)).collect())
            .collect();
        let mut responses = evaluate_responses(&[combine_rows(&rows, &gamma[0]).unwrap()], &points);
        responses[0][0] += Fr::from(1u64);
        assert!(!verify_responses(&row_evals, &gamma, &responses, &points, d_beta).unwrap());
    }

    #[test]
    fn bad_shapes_are_rejected() {
        let p = V3Params::fast_insecure_test();
        p.validate().unwrap();
        assert!(combine_rows(&[], &[Fr::one()]).is_err());
        assert!(combine_rows(&[vec![Fr::one()]], &[Fr::one(), Fr::one()]).is_err());
        // Mixed lengths are zero-padded, not rejected.
        assert_eq!(
            combine_rows(
                &[vec![Fr::one()], vec![Fr::one(), Fr::one()]],
                &[Fr::one(), Fr::one()]
            )
            .unwrap(),
            vec![Fr::from(2u64), Fr::one()]
        );
        assert!(verify_responses(&[], &[], &[], &[], 0).is_err());
        // poly_degree of the zero polynomial.
        assert_eq!(poly_degree(&[Fr::zero(), Fr::zero()]), None);
        assert!(meets_degree(&[Fr::zero()], 0));
    }
}
