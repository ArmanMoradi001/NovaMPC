//! Hint generation Π$/Π0/ΠΣ0 (FR25b §6.1, Lemma 1).
//!
//! High-degree masking sharings (`JvK` of degree `2(s+ℓ−1)` with zero
//! secret, `Jv′K` of degree `2s+ℓ−2` with sum-zero secret) are derived from
//! committed low-degree hint sharings so the DECS cap `dβ` stays small.
//! Both prover and verifier run the same deterministic derivation from the
//! opened hint shares; only the prover samples the hint polynomials and
//! computes the ΠΣ0 correction `Δu1` (sent in the proof, added by the
//! verifier exactly as in Protocol 5 step 4a).

use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use rand::RngCore;

use crate::v3::sharing::{coord_point, eval_poly, eval_poly_all, party_point, random_poly};
use crate::{MpcithError, Result};

/// One Π$ derivation: `n` low-degree hints build a degree-`target` sharing.
/// Lemma 1: `δ = dβ−ℓ+1`, `n = ⌈(target+1−ℓ)/δ⌉`, last hint degree
/// `target−(n−1)·δ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PiDollarV3 {
    pub num_hints: usize,
    pub delta: usize,
    pub last_degree: usize,
    pub target_degree: usize,
}

impl PiDollarV3 {
    /// `s` is unused in the parameter formula (Lemma 1 needs only
    /// `target`, `ell`, `dβ`) but kept for call-site readability.
    pub fn for_target(_s: usize, ell: usize, d_beta: usize, target_degree: usize) -> Result<Self> {
        if d_beta < ell {
            return Err(MpcithError::InvalidParams(format!(
                "v3 Pi$ needs d_beta {d_beta} >= ell {ell}"
            )));
        }
        let delta = d_beta - ell + 1;
        let num_hints = (target_degree + 1 - ell).div_ceil(delta).max(1);
        let last_degree = target_degree - (num_hints - 1) * delta;
        Ok(Self {
            num_hints,
            delta,
            last_degree,
            target_degree,
        })
    }

    /// Hint degrees: `dβ` for the first `n−1`, `last_degree` for the final.
    pub fn hint_degrees(&self, d_beta: usize) -> Vec<usize> {
        let mut out = vec![d_beta; self.num_hints];
        if let Some(last) = out.last_mut() {
            *last = self.last_degree;
        }
        out
    }

    /// Derive per-party shares: `Σ_j h_j,i · e_i^{(j−1)·δ}`.
    pub fn derive(&self, s: usize, hint_shares: &[Vec<Fr>]) -> Result<Vec<Fr>> {
        if hint_shares.len() != self.num_hints {
            return Err(MpcithError::InvalidParams(format!(
                "v3 Pi$ needs {} hint sharings, got {}",
                self.num_hints,
                hint_shares.len()
            )));
        }
        let n = hint_shares[0].len();
        if hint_shares.iter().any(|h| h.len() != n) {
            return Err(MpcithError::InvalidParams(
                "v3 Pi$ hint sharings have mismatched lengths".into(),
            ));
        }
        Ok((0..n)
            .map(|i| {
                let e = party_point(s, i);
                let mut power = Fr::one();
                let mut acc = Fr::zero();
                for h in hint_shares {
                    acc += h[i] * power;
                    power *= e.pow([self.delta as u64]);
                }
                acc
            })
            .collect())
    }
}

/// `P0(X) = ∏_{k=1..s}(X − ω_k)` evaluated at a party point (public).
pub fn zero_mask_eval(s: usize, party: usize) -> Fr {
    let e = party_point(s, party);
    (0..s).fold(Fr::one(), |acc, k| acc * (e - coord_point(k)))
}

/// Lagrange basis `L` with `L(ω_1) = 1`, `L(ω_k) = 0` else, at `x`.
pub fn correction_basis_eval(s: usize, x: Fr) -> Fr {
    let mut num = Fr::one();
    let mut den = Fr::one();
    let w1 = coord_point(0);
    for k in 1..s {
        let wk = coord_point(k);
        num *= x - wk;
        den *= w1 - wk;
    }
    num * den.inverse().unwrap_or(Fr::zero())
}

/// Prover-side ΠΣ0 correction: `Δu1 = −Σ_k Pv(ω_k)` from the hint
/// polynomials, where `Pv(ω_k) = Σ_j P_j(ω_k)·ω_k^{(j−1)·δ}`.
pub fn sigma_correction(s: usize, delta: usize, hint_polys: &[Vec<Fr>]) -> Fr {
    let mut sum = Fr::zero();
    for k in 0..s {
        let w = coord_point(k);
        let mut power = Fr::one();
        let mut acc = Fr::zero();
        for p in hint_polys {
            acc += eval_poly(p, w) * power;
            power *= w.pow([delta as u64]);
        }
        sum += acc;
    }
    -sum
}

/// Sample the `n` hint polynomials for one Π$ derivation (prover only).
pub fn sample_hint_polys(
    degrees: &[usize],
    rng: &mut impl RngCore,
) -> Vec<Vec<Fr>> {
    degrees.iter().map(|d| random_poly(*d, rng)).collect()
}

/// Evaluate hint polynomials at all party points (prover commit inputs).
pub fn eval_hint_polys(polys: &[Vec<Fr>], s: usize, num_parties: usize) -> Vec<Vec<Fr>> {
    polys
        .iter()
        .map(|p| eval_poly_all(p, s, num_parties))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::decs::meets_degree;
    use crate::v3::sharing::{interpolate_coeffs, reconstruct};
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0x1F50)
    }

    #[test]
    fn pi_dollar_parameters_match_lemma1() {
        // Prototype point: s=120, l=30, d_beta=149.
        let p = PiDollarV3::for_target(120, 30, 149, 2 * (120 + 30 - 1) - 120).unwrap();
        assert_eq!((p.num_hints, p.delta, p.last_degree), (2, 120, 58));
        let q = PiDollarV3::for_target(120, 30, 149, 2 * 120 + 30 - 2).unwrap();
        assert_eq!((q.num_hints, q.delta, q.last_degree), (2, 120, 148));
        // Fast point: s=8, l=3, d_beta=10.
        let r = PiDollarV3::for_target(8, 3, 10, 2 * (8 + 3 - 1) - 8).unwrap();
        assert_eq!((r.num_hints, r.delta, r.last_degree), (2, 8, 4));
    }

    #[test]
    fn pi0_derivation_yields_zero_secret_at_target_degree() {
        let (s, ell, n, d_beta) = (8usize, 3usize, 32usize, 10usize);
        let target = 2 * (s + ell - 1);
        let setup = PiDollarV3::for_target(s, ell, d_beta, target - s).unwrap();
        let mut r = rng();
        let polys = sample_hint_polys(&setup.hint_degrees(d_beta), &mut r);
        let hints = eval_hint_polys(&polys, s, n);
        let base = setup.derive(s, &hints).unwrap();
        let masked: Vec<Fr> = base
            .iter()
            .enumerate()
            .map(|(i, v)| *v * zero_mask_eval(s, i))
            .collect();
        // Degree check over target+1 points.
        let pts: Vec<Fr> = (0..target + 1).map(|i| party_point(s, i)).collect();
        let coeffs = interpolate_coeffs(&pts, &masked[..target + 1]).unwrap();
        assert!(meets_degree(&coeffs, target));
        // Secret recovers to zeros.
        let pairs: Vec<(Fr, Fr)> = pts.into_iter().zip(masked).collect();
        let secret = reconstruct(s, target + 1 - s, &pairs).unwrap();
        assert!(secret.iter().all(|v| v.is_zero()));
    }

    #[test]
    fn pi_sigma0_derivation_yields_sum_zero_secret() {
        let (s, ell, n, d_beta) = (8usize, 3usize, 32usize, 10usize);
        let target = 2 * s + ell - 2;
        let setup = PiDollarV3::for_target(s, ell, d_beta, target).unwrap();
        let mut r = rng();
        let polys = sample_hint_polys(&setup.hint_degrees(d_beta), &mut r);
        let delta = sigma_correction(s, setup.delta, &polys);
        // Corrected first-hint shares: h + Δ·L(e_i).
        let mut hints = eval_hint_polys(&polys, s, n);
        for i in 0..n {
            hints[0][i] += delta * correction_basis_eval(s, party_point(s, i));
        }
        let derived = setup.derive(s, &hints).unwrap();
        let pts: Vec<Fr> = (0..target + 1).map(|i| party_point(s, i)).collect();
        let coeffs = interpolate_coeffs(&pts, &derived[..target + 1]).unwrap();
        assert!(meets_degree(&coeffs, target));
        let pairs: Vec<(Fr, Fr)> = pts.into_iter().zip(derived).collect();
        let secret = reconstruct(s, target + 1 - s, &pairs).unwrap();
        assert_eq!(secret.iter().sum::<Fr>(), Fr::zero());
        // Sanity: an uncorrected derivation is overwhelmingly unlikely to
        // sum to zero (would require the random polys to hit the condition).
        let raw = setup.derive(s, &eval_hint_polys(&polys, s, n)).unwrap();
        let pairs: Vec<(Fr, Fr)> = (0..target + 1)
            .map(|i| (party_point(s, i), raw[i]))
            .collect();
        let raw_secret = reconstruct(s, target + 1 - s, &pairs).unwrap();
        assert_ne!(raw_secret.iter().sum::<Fr>(), Fr::zero());
    }
}
