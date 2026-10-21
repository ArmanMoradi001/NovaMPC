//! V2 per-view BLAKE3 commitments.
//!
//! A view commitment binds the reconstructed party seed, the party's claimed
//! multiplication shares, and the residual party's transmitted input shares.
//! Repetition and party indices are domain-separated, and all lengths are
//! explicit. This is not the v1 `mpcith-zk commitment v1` construction.

use crate::v2::suite::V2_SUITE;

const VIEW_COMMITMENT_CONTEXT: &str = "NovaMPC-v2/view-commitment/v1";

fn absorb(hasher: &mut blake3::Hasher, label: &[u8], bytes: &[u8]) {
    hasher.update(&(label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn absorb_u32(hasher: &mut blake3::Hasher, label: &[u8], value: u32) {
    absorb(hasher, label, &value.to_be_bytes());
}

/// Commit to one party's view for one repetition.
pub fn commit_view_v2(
    repetition: u32,
    party: u32,
    seed: &[u8; 32],
    view_bytes: &[u8],
    randomness: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(VIEW_COMMITMENT_CONTEXT);
    absorb(&mut hasher, b"protocol", V2_SUITE.protocol_id);
    absorb(&mut hasher, b"version", &V2_SUITE.version.to_be_bytes());
    absorb(&mut hasher, b"field", V2_SUITE.field_id);
    absorb_u32(&mut hasher, b"repetition", repetition);
    absorb_u32(&mut hasher, b"party", party);
    absorb(&mut hasher, b"seed", seed);
    absorb(&mut hasher, b"view", view_bytes);
    absorb(&mut hasher, b"randomness", randomness);
    *hasher.finalize().as_bytes()
}

/// Recompute a commitment and compare with an expected value.
pub fn verify_view_commitment_v2(
    expected: &[u8; 32],
    repetition: u32,
    party: u32,
    seed: &[u8; 32],
    view_bytes: &[u8],
    randomness: &[u8; 32],
) -> bool {
    commit_view_v2(repetition, party, seed, view_bytes, randomness) == *expected
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [1u8; 32];
    const RAND: [u8; 32] = [2u8; 32];

    #[test]
    fn commitment_is_deterministic_and_verifiable() {
        let commitment = commit_view_v2(4, 2, &SEED, b"view", &RAND);
        assert_eq!(commitment, commit_view_v2(4, 2, &SEED, b"view", &RAND));
        assert!(verify_view_commitment_v2(
            &commitment,
            4,
            2,
            &SEED,
            b"view",
            &RAND
        ));
    }

    #[test]
    fn repetition_party_seed_view_and_randomness_are_bound() {
        let base = commit_view_v2(4, 2, &SEED, b"view", &RAND);
        assert_ne!(base, commit_view_v2(5, 2, &SEED, b"view", &RAND));
        assert_ne!(base, commit_view_v2(4, 1, &SEED, b"view", &RAND));
        assert_ne!(base, commit_view_v2(4, 2, &[3u8; 32], b"view", &RAND));
        assert_ne!(base, commit_view_v2(4, 2, &SEED, b"other", &RAND));
        assert_ne!(base, commit_view_v2(4, 2, &SEED, b"view", &[3u8; 32]));
        assert!(!verify_view_commitment_v2(
            &base, 4, 2, &SEED, b"view", &[3u8; 32]
        ));
    }

    #[test]
    fn hiding_uses_fresh_randomness() {
        let a = commit_view_v2(0, 0, &SEED, b"same view", &[0u8; 32]);
        let b = commit_view_v2(0, 0, &SEED, b"same view", &[1u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn length_prefixes_separate_concatenations() {
        let a = commit_view_v2(0, 0, &SEED, b"ab", &RAND);
        let b = commit_view_v2(0, 0, &SEED, b"a", &RAND);
        assert_ne!(a, b);
    }
}
