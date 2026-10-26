//! Versioned suite identifiers for the experimental v3 proof path.
//!
//! These identifiers are absorbed by the v3 transcript (Phase 3). Changing any
//! of them changes every v3 challenge and is therefore a protocol version bump.
//! They are provisional and carry no security claim.

/// V3 proof-format magic. Distinct from every v2 magic/version value.
pub const V3_PROOF_MAGIC: &[u8; 8] = b"NMPCV3T\0";

/// V3 proof-format version. Version 2 binds the per-repetition transcript
/// index (Phase 8.1); version-1 proofs derive different challenges and are
/// rejected at parse, never silently re-evaluated.
pub const V3_PROOF_FORMAT_VERSION: u16 = 2;

/// V3 protocol family identifier (TCitH-MT over the ΠLigero LPPC protocol).
pub const V3_PROTOCOL_ID: &[u8] = b"NovaMPC-v3/tcith-mt/pi-ligero/v1";

/// Scalar field identifier. V3 is BN254 `Fr` only, like v2.
pub const V3_FIELD_ID: &[u8] = b"BN254-Fr";

/// Pinned Poseidon2 instance: same instance as v2 (`V2_POSEIDON2_ID`).
pub const V3_POSEIDON2_ID: &[u8] =
    b"HorizenLabs-poseidon2-bn254-t3-d5-rf8-rp56@055bde3f4782731ba5f5ce5888a440a94327eaf3";

/// Tagged-compression framing: same framing as v2 (`V2_FRAMING_ID`).
pub const V3_FRAMING_ID: &[u8] = b"NovaMPC-v2/tagged-compress/v1";

/// Suite identifiers bound by the v3 transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3Suite {
    pub version: u16,
    pub protocol_id: &'static [u8],
    pub field_id: &'static [u8],
    pub poseidon2_id: &'static [u8],
    pub framing_id: &'static [u8],
}

/// The only suite accepted by the (future) v3 verifier.
pub const V3_SUITE: V3Suite = V3Suite {
    version: V3_PROOF_FORMAT_VERSION,
    protocol_id: V3_PROTOCOL_ID,
    field_id: V3_FIELD_ID,
    poseidon2_id: V3_POSEIDON2_ID,
    framing_id: V3_FRAMING_ID,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_identifiers_are_versioned_and_distinct_from_v2() {
        assert_eq!(V3_SUITE.version, V3_PROOF_FORMAT_VERSION);
        assert_eq!(V3_SUITE.version, 2);
        // Magic length is fixed at 8 bytes including the NUL terminator.
        assert_eq!(V3_PROOF_MAGIC.len(), 8);
        assert_eq!(V3_PROOF_MAGIC, b"NMPCV3T\0");
        // Protocol id names the exact construction under study.
        assert_eq!(V3_SUITE.protocol_id, b"NovaMPC-v3/tcith-mt/pi-ligero/v1");
        // Field, Poseidon2, and framing match v2 (same relation being proven).
        assert_eq!(V3_SUITE.field_id, crate::v2::suite::V2_FIELD_ID);
        assert_eq!(
            V3_SUITE.poseidon2_id,
            crate::v2::suite::V2_POSEIDON2_ID
        );
        assert_eq!(V3_SUITE.framing_id, crate::v2::suite::V2_FRAMING_ID);
        // But the protocol id and version must never equal v2's.
        assert_ne!(V3_SUITE.protocol_id, crate::v2::suite::V2_PROTOCOL_ID);
        assert_ne!(
            V3_SUITE.version,
            crate::v2::suite::V2_PROOF_VERSION
        );
    }
}
