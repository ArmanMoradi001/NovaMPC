//! Versioned suite identifiers and parameter validation for the v2 proof path.
//!
//! These identifiers are absorbed by the v2 transcript. Changing any of them
//! changes every v2 challenge and is therefore a protocol version bump, not a
//! local implementation detail.

use crate::{MpcithError, Result};

/// Current v2 proof-format version. V1 proofs never carry this value.
///
/// Version 3 binds a 32-byte context hash into the proof and transcript.
pub const V2_PROOF_VERSION: u16 = 3;

/// The v2 protocol family identifier.
pub const V2_PROTOCOL_ID: &[u8] = b"NovaMPC-v2/proof/v1";

/// Scalar field identifier. V2 is BN254 `Fr` only.
pub const V2_FIELD_ID: &[u8] = b"BN254-Fr";

/// Pinned Horizen Labs Poseidon2 instance identifier.
pub const V2_POSEIDON2_ID: &[u8] =
    b"HorizenLabs-poseidon2-bn254-t3-d5-rf8-rp56@055bde3f4782731ba5f5ce5888a440a94327eaf3";

/// Tagged-compression framing used by the v2 set hash.
pub const V2_FRAMING_ID: &[u8] = b"NovaMPC-v2/tagged-compress/v1";

/// Fixed v2 party count. The multiplication protocol is the existing 3-party
/// ZKBoo schedule; changing this value requires a different multiplication
/// protocol, not just a parameter update.
pub const V2_NUM_PARTIES: u32 = 3;

/// Upper bound on repetitions accepted from a v2 proof or parameter set.
///
/// This is a resource bound, not a security parameter. It keeps malformed
/// proofs from requesting unbounded verification work.
pub const MAX_V2_REPETITIONS: u32 = 1 << 16;

/// Target overall security level for the v2 hardening work.
///
/// This is **not** a 128-bit claim. BN254 `Fr` roots have a generic collision
/// ceiling of approximately 127 bits, so the proof-soundness repetitions below
/// cannot raise the end-to-end claim above that ceiling.
pub const SECURE_127_TARGET_BITS: u32 = 127;

/// Bare minimum repetitions for the conditional `q * (2/3)^M` bound at `q = 1`.
///
/// `218 * log2(3/2) ~= 127.52` bits before the ~127-bit BN254 field/hash
/// ceiling and before implementation/audit losses. This is a minimum, not a
/// recommended setting; [`V2Params::secure_127`] adds repetition margin.
pub const SECURE_127_Q1_MIN_REPETITIONS: u32 = 218;

/// Bare minimum repetitions for the conditional `q * (2/3)^M` bound at
/// `q = 2^32`.
///
/// `272 * log2(3/2) - 32 ~= 127.11` bits before the ~127-bit BN254 field/hash
/// ceiling and before implementation/audit losses. This is a minimum, not a
/// recommended setting; [`V2Params::secure_127_grinding_2_32`] adds margin.
pub const SECURE_127_Q32_MIN_REPETITIONS: u32 = 272;

/// Suite identifiers bound by the v2 transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2Suite {
    pub version: u16,
    pub protocol_id: &'static [u8],
    pub field_id: &'static [u8],
    pub poseidon2_id: &'static [u8],
    pub framing_id: &'static [u8],
}

/// The only suite accepted by the public v2 verifier.
pub const V2_SUITE: V2Suite = V2Suite {
    version: V2_PROOF_VERSION,
    protocol_id: V2_PROTOCOL_ID,
    field_id: V2_FIELD_ID,
    poseidon2_id: V2_POSEIDON2_ID,
    framing_id: V2_FRAMING_ID,
};

/// V2 proof parameters. `num_parties` is fixed at three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Params {
    /// Number of virtual parties (N).
    pub num_parties: u32,
    /// Number of cut-and-choose repetitions (M).
    pub num_repetitions: u32,
}

impl V2Params {
    pub fn new(num_parties: u32, num_repetitions: u32) -> Self {
        Self {
            num_parties,
            num_repetitions,
        }
    }

    /// Historical prototype sizing preset matching v1 `balanced()`: N=3, M=96.
    ///
    /// **Not secure.** This is a format/benchmark preset only. At `M=96` the
    /// conditional 2/3 bound is about 56.16 bits, far below the 127-bit target.
    /// Use [`Self::secure_127`] or [`Self::secure_127_grinding_2_32`] for a
    /// deployment-review parameter choice.
    pub fn balanced() -> Self {
        Self::new(V2_NUM_PARTIES, 96)
    }

    /// Fast, explicitly insecure preset for tests and local experiments.
    pub fn fast_insecure() -> Self {
        Self::new(V2_NUM_PARTIES, 4)
    }

    /// Recommended `q = 1` preset: N=3, M=223.
    ///
    /// The conditional `(2/3)^M` proof-soundness estimate is about 130.45 bits,
    /// leaving roughly three bits of repetition margin above the 218-repetition
    /// bare minimum. The overall claim remains capped at approximately 127 bits
    /// by the BN254 `Fr` root/commitment collision ceiling; this preset does not
    /// create a 128-bit claim.
    pub fn secure_127() -> Self {
        Self::new(V2_NUM_PARTIES, 223)
    }

    /// Recommended grinding-aware preset for `q = 2^32`: N=3, M=277.
    ///
    /// The conditional `(2/3)^M` estimate is about 130.03 bits after subtracting
    /// the 32-bit query loss, leaving roughly three bits of repetition margin
    /// above the 272-repetition bare minimum. The overall claim remains capped at
    /// approximately 127 bits by the BN254 `Fr` root/commitment collision
    /// ceiling.
    pub fn secure_127_grinding_2_32() -> Self {
        Self::new(V2_NUM_PARTIES, 277)
    }

    /// Validate structural bounds before any proof work.
    pub fn validate(&self) -> Result<()> {
        if self.num_parties != V2_NUM_PARTIES {
            return Err(MpcithError::InvalidParams(format!(
                "v2 requires exactly {V2_NUM_PARTIES} parties, got {}",
                self.num_parties
            )));
        }
        if self.num_repetitions == 0 {
            return Err(MpcithError::InvalidParams(
                "v2 requires at least one repetition".into(),
            ));
        }
        if self.num_repetitions > MAX_V2_REPETITIONS {
            return Err(MpcithError::InvalidParams(format!(
                "v2 repetition count {} exceeds maximum {MAX_V2_REPETITIONS}",
                self.num_repetitions
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_parameters_are_accepted() {
        assert!(V2Params::new(3, 1).validate().is_ok());
        assert!(V2Params::balanced().validate().is_ok());
        assert!(V2Params::fast_insecure().validate().is_ok());
        assert!(V2Params::secure_127().validate().is_ok());
        assert!(V2Params::secure_127_grinding_2_32().validate().is_ok());
    }

    #[test]
    fn secure_127_presets_are_explicit_and_not_the_legacy_96() {
        assert_eq!(SECURE_127_TARGET_BITS, 127);
        assert_eq!(SECURE_127_Q1_MIN_REPETITIONS, 218);
        assert_eq!(SECURE_127_Q32_MIN_REPETITIONS, 272);

        let q1 = V2Params::secure_127();
        assert_eq!(q1.num_parties, 3);
        assert_eq!(q1.num_repetitions, 223);
        assert!(q1.num_repetitions > SECURE_127_Q1_MIN_REPETITIONS);

        let q32 = V2Params::secure_127_grinding_2_32();
        assert_eq!(q32.num_parties, 3);
        assert_eq!(q32.num_repetitions, 277);
        assert!(q32.num_repetitions > SECURE_127_Q32_MIN_REPETITIONS);

        assert_eq!(V2Params::balanced().num_repetitions, 96);
        assert_eq!(V2Params::fast_insecure().num_repetitions, 4);
    }

    #[test]
    fn wrong_party_count_and_empty_repetitions_are_rejected() {
        for parties in [0u32, 1, 2, 4, 5] {
            assert!(V2Params::new(parties, 4).validate().is_err());
        }
        assert!(V2Params::new(3, 0).validate().is_err());
        assert!(V2Params::new(3, MAX_V2_REPETITIONS + 1).validate().is_err());
    }

    #[test]
    fn suite_identifier_is_versioned() {
        assert_eq!(V2_SUITE.version, V2_PROOF_VERSION);
        assert_eq!(V2_SUITE.protocol_id, V2_PROTOCOL_ID);
        assert_eq!(V2_SUITE.field_id, V2_FIELD_ID);
        assert_eq!(V2_SUITE.poseidon2_id, V2_POSEIDON2_ID);
        assert_eq!(V2_SUITE.framing_id, V2_FRAMING_ID);
    }
}
