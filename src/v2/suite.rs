//! Versioned suite identifiers and parameter validation for the v2 proof path.
//!
//! These identifiers are absorbed by the v2 transcript. Changing any of them
//! changes every v2 challenge and is therefore a protocol version bump, not a
//! local implementation detail.

use crate::{MpcithError, Result};

/// Current v2 proof-format version. V1 proofs never carry this value.
pub const V2_PROOF_VERSION: u16 = 2;

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

    /// Prototype sizing preset matching v1 `balanced()`: N=3, M=96.
    ///
    /// This is a repetition-count preset only. It is not a security claim for
    /// the v2 protocol.
    pub fn balanced() -> Self {
        Self::new(V2_NUM_PARTIES, 96)
    }

    /// Fast, explicitly insecure preset for tests and local experiments.
    pub fn fast_insecure() -> Self {
        Self::new(V2_NUM_PARTIES, 4)
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
        assert_eq!(V2_SUITE.version, 2);
        assert_eq!(V2_SUITE.protocol_id, V2_PROTOCOL_ID);
        assert_eq!(V2_SUITE.field_id, V2_FIELD_ID);
        assert_eq!(V2_SUITE.poseidon2_id, V2_POSEIDON2_ID);
        assert_eq!(V2_SUITE.framing_id, V2_FRAMING_ID);
    }
}
