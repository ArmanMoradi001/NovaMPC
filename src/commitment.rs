//! BLAKE3-based commitment scheme.
//!
//! Commit(value; randomness) = BLAKE3(domain || randomness || value)
//!
//! Properties:
//! - Binding: computationally infeasible to find two values with the same commitment.
//! - Hiding: commitment reveals nothing about the value.
//!
//! We commit to each party's view (seed + broadcast messages) separately,
//! giving per-party commitments that can be selectively opened.

use blake3::Hasher;
use serde::{Deserialize, Serialize};

/// A 32-byte BLAKE3 commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment(pub [u8; 32]);

/// The randomness used to open a commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentOpening {
    pub randomness: [u8; 32],
}

/// Commit to arbitrary bytes using BLAKE3 in keyed mode.
/// Domain separation prevents cross-context collisions.
pub fn commit(domain: &[u8], randomness: &[u8; 32], data: &[u8]) -> Commitment {
    let mut hasher = Hasher::new_derive_key("mpcith-zk commitment v1");
    hasher.update(domain);
    hasher.update(randomness);
    hasher.update(data);
    let hash = hasher.finalize();
    Commitment(hash.into())
}

/// Verify a commitment opening.
pub fn verify_commitment(
    domain: &[u8],
    opening: &CommitmentOpening,
    data: &[u8],
    expected: &Commitment,
) -> bool {
    let computed = commit(domain, &opening.randomness, data);
    computed == *expected
}

/// Commit to a party's view: their seed + their broadcast messages.
/// `repetition` and `party` are included in the domain for separation.
pub fn commit_view(
    repetition: usize,
    party: usize,
    seed: &[u8; 32],
    broadcast_messages: &[u8],
    randomness: &[u8; 32],
) -> Commitment {
    let domain = format!("mpcith-view:rep={repetition}:party={party}");
    let mut data = Vec::with_capacity(32 + broadcast_messages.len());
    data.extend_from_slice(seed);
    data.extend_from_slice(broadcast_messages);
    commit(domain.as_bytes(), randomness, &data)
}

/// A vector of commitments — one per party per repetition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentMatrix {
    /// commitments[rep][party]
    pub commitments: Vec<Vec<Commitment>>,
    pub num_repetitions: usize,
    pub num_parties: usize,
}

impl CommitmentMatrix {
    pub fn new(num_repetitions: usize, num_parties: usize) -> Self {
        Self {
            commitments: vec![
                vec![Commitment([0u8; 32]); num_parties];
                num_repetitions
            ],
            num_repetitions,
            num_parties,
        }
    }

    pub fn get(&self, rep: usize, party: usize) -> &Commitment {
        &self.commitments[rep][party]
    }

    pub fn set(&mut self, rep: usize, party: usize, commitment: Commitment) {
        self.commitments[rep][party] = commitment;
    }

    /// Serialize the entire matrix for Fiat-Shamir hashing.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.commitments
            .iter()
            .flat_map(|row| row.iter().flat_map(|c| c.0))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_verify() {
        let randomness = [0xABu8; 32];
        let data = b"hello world";
        let domain = b"test";

        let commitment = commit(domain, &randomness, data);
        let opening = CommitmentOpening { randomness };

        assert!(verify_commitment(domain, &opening, data, &commitment));
        assert!(!verify_commitment(domain, &opening, b"wrong data", &commitment));
    }

    #[test]
    fn test_commit_binding() {
        let randomness = [0u8; 32];
        let c1 = commit(b"d", &randomness, b"value1");
        let c2 = commit(b"d", &randomness, b"value2");
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_commit_hiding() {
        // Same data, different randomness → different commitments.
        let c1 = commit(b"d", &[0u8; 32], b"secret");
        let c2 = commit(b"d", &[1u8; 32], b"secret");
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_domain_separation() {
        let randomness = [0u8; 32];
        let data = b"same data";
        let c1 = commit(b"domain1", &randomness, data);
        let c2 = commit(b"domain2", &randomness, data);
        assert_ne!(c1, c2);
    }
}
