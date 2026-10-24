//! Experimental v3 parameters and structural validation (FR25b §5, Thm 2).
//!
//! Names map to `V3_PHASE0.md` §1: `N` parties/Merkle leaves, `ℓ` privacy
//! threshold (`(ℓ+1, N)` sharing), `s` packing width, `η` DECS repetitions,
//! `ρ` MPC parallel repetitions, `τ` outer PoK repetitions.
//!
//! Validation here is structural (ranges, `N < |F|`, degree feasibility), not a
//! security argument. Nothing here labels a parameter set secure.

use crate::{MpcithError, Result};

/// Maximum accepted party count (resource bound; also far below `|Fr|`).
pub const MAX_V3_PARTIES: u32 = 65_536;

/// Maximum packing width (resource bound for matrix allocation).
pub const MAX_V3_PACKING_WIDTH: u32 = 4_096;

/// Maximum parallel repetitions for any single dimension.
pub const MAX_V3_REPETITIONS: u32 = 16;

/// Maximum DECS repetitions (resource bound).
pub const MAX_V3_DECS_REPS: u32 = 64;

/// Experimental v3 parameter set. All presets are insecure-test only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3Params {
    /// Number of virtual parties / Merkle leaves (`N`).
    pub num_parties: u32,
    /// Privacy/opening parameter (`ℓ`); sharing threshold is `ℓ + 1`.
    pub privacy_threshold: u32,
    /// Packing width: witness-matrix columns (`s`).
    pub packing_width: u32,
    /// Degree-enforcement repetitions (`η`).
    pub decs_reps: u32,
    /// MPC parallel repetitions (`ρ`).
    pub mpc_reps: u32,
    /// Outer proof-of-knowledge repetitions (`τ`).
    pub pok_reps: u32,
}

impl V3Params {
    pub fn new(
        num_parties: u32,
        privacy_threshold: u32,
        packing_width: u32,
        decs_reps: u32,
        mpc_reps: u32,
        pok_reps: u32,
    ) -> Self {
        Self {
            num_parties,
            privacy_threshold,
            packing_width,
            decs_reps,
            mpc_reps,
            pok_reps,
        }
    }

    /// Reference point reproduced from the literature (SmallWood Table 2 /
    /// FR25b): `N=8192, ℓ=27, s=133, η=5, ρ=1, τ=1`.
    ///
    /// Experimental only. Per `V3_PHASE0.md` §0/§2 this point has no
    /// Fiat–Shamir/query margin and must not be used for security-facing tests.
    pub fn published_reference_tau1() -> Self {
        Self::new(8192, 27, 133, 5, 1, 1)
    }

    /// Recommended Phase-0 prototype point: `N=8192, ℓ=30, s=120, η=6, ρ=1,
    /// τ=2` (~197 KiB modeled). Experimental; security unreviewed.
    pub fn prototype_tau2() -> Self {
        Self::new(8192, 30, 120, 6, 1, 2)
    }

    /// Tiny, explicitly insecure preset for fast unit tests only.
    pub fn fast_insecure_test() -> Self {
        Self::new(32, 3, 8, 2, 1, 1)
    }

    /// Sharing threshold `ℓ + 1`.
    pub fn threshold(&self) -> u32 {
        self.privacy_threshold + 1
    }

    /// Default maximum hint degree `d_β = s + ℓ − 1` (FR25b §6.1).
    pub fn hint_degree(&self) -> u32 {
        self.packing_width + self.privacy_threshold - 1
    }

    /// Maximum broadcast-sharing degree `d_α = 2·(s + ℓ − 1)` for the
    /// degree-2 LPPC instantiation (FR25b §6.3, Thm 2).
    pub fn broadcast_degree(&self) -> u32 {
        2 * (self.packing_width + self.privacy_threshold - 1)
    }

    /// Structural validation only. Rejects ranges that cannot satisfy the
    /// paper's degree feasibility (`d_β + 2 ≤ N`, i.e. the DECS binomial term
    /// is well-defined) and the resource bounds above.
    pub fn validate(&self) -> Result<()> {
        if self.num_parties < 2 {
            return Err(MpcithError::InvalidParams(format!(
                "v3 requires at least 2 parties, got {}",
                self.num_parties
            )));
        }
        if self.num_parties > MAX_V3_PARTIES {
            return Err(MpcithError::InvalidParams(format!(
                "v3 party count {} exceeds maximum {MAX_V3_PARTIES}",
                self.num_parties
            )));
        }
        if self.privacy_threshold == 0 {
            return Err(MpcithError::InvalidParams(
                "v3 requires privacy threshold >= 1".into(),
            ));
        }
        if self.privacy_threshold >= self.num_parties {
            return Err(MpcithError::InvalidParams(format!(
                "v3 requires privacy threshold {} < parties {}",
                self.privacy_threshold, self.num_parties
            )));
        }
        if self.packing_width == 0 || self.packing_width > MAX_V3_PACKING_WIDTH {
            return Err(MpcithError::InvalidParams(format!(
                "v3 packing width {} out of range [1, {MAX_V3_PACKING_WIDTH}]",
                self.packing_width
            )));
        }
        if self.decs_reps == 0 || self.decs_reps > MAX_V3_DECS_REPS {
            return Err(MpcithError::InvalidParams(format!(
                "v3 decs reps {} out of range [1, {MAX_V3_DECS_REPS}]",
                self.decs_reps
            )));
        }
        if self.mpc_reps == 0 || self.mpc_reps > MAX_V3_REPETITIONS {
            return Err(MpcithError::InvalidParams(format!(
                "v3 mpc reps {} out of range [1, {MAX_V3_REPETITIONS}]",
                self.mpc_reps
            )));
        }
        if self.pok_reps == 0 || self.pok_reps > MAX_V3_REPETITIONS {
            return Err(MpcithError::InvalidParams(format!(
                "v3 pok reps {} out of range [1, {MAX_V3_REPETITIONS}]",
                self.pok_reps
            )));
        }
        // DECS soundness term C(N, d_β+2) requires d_β + 2 <= N.
        if self.hint_degree() + 2 > self.num_parties {
            return Err(MpcithError::InvalidParams(format!(
                "v3 degree infeasible: d_beta + 2 = {} exceeds N = {}",
                self.hint_degree() + 2,
                self.num_parties
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_presets_pass_structural_validation() {
        V3Params::published_reference_tau1().validate().unwrap();
        V3Params::prototype_tau2().validate().unwrap();
        V3Params::fast_insecure_test().validate().unwrap();
    }

    #[test]
    fn derived_degrees_match_phase0_definitions() {
        // d_beta = s + l - 1, d_alpha = 2 (s + l - 1) for the deg-2 LPPC.
        let p = V3Params::prototype_tau2();
        assert_eq!(p.threshold(), 31);
        assert_eq!(p.hint_degree(), 120 + 30 - 1);
        assert_eq!(p.broadcast_degree(), 2 * (120 + 30 - 1));
        let r = V3Params::published_reference_tau1();
        assert_eq!(r.hint_degree(), 133 + 27 - 1);
        assert_eq!(r.broadcast_degree(), 318);
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        // Zero / out-of-range fields.
        assert!(V3Params::new(1, 1, 8, 2, 1, 1).validate().is_err());
        assert!(V3Params::new(32, 0, 8, 2, 1, 1).validate().is_err());
        assert!(V3Params::new(32, 32, 8, 2, 1, 1).validate().is_err());
        assert!(V3Params::new(32, 3, 0, 2, 1, 1).validate().is_err());
        assert!(V3Params::new(32, 3, 8, 0, 1, 1).validate().is_err());
        assert!(V3Params::new(32, 3, 8, 2, 0, 1).validate().is_err());
        assert!(V3Params::new(32, 3, 8, 2, 1, 0).validate().is_err());
        assert!(V3Params::new(MAX_V3_PARTIES + 1, 3, 8, 2, 1, 1)
            .validate()
            .is_err());
        // Degree infeasible: d_beta + 2 = s + l + 1 > N.
        assert!(V3Params::new(16, 8, 16, 2, 1, 1).validate().is_err());
    }
}
