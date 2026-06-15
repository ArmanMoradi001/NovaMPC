//! Fiat-Shamir transform: makes the interactive cut-and-choose non-interactive.
//!
//! The verifier's challenge (which N-1 parties to open) is derived as:
//!   challenge = SHA3-256(commitment_matrix || public_inputs || circuit_description)
//!
//! This binds the challenge to the commitments so the prover cannot choose
//! challenges adaptively.

use sha3::{Digest, Sha3_256};

/// Derive verifier challenges (which party to hide) for each repetition.
///
/// Returns a vector of length `num_repetitions`, where each entry is the
/// index of the party whose view will NOT be revealed (0..num_parties).
///
/// The challenge derivation follows the Fiat-Shamir heuristic:
/// `challenges = SHAKE(commitment_bytes || public_input_bytes || circuit_hash)[0..num_reps]`
pub fn derive_challenges(
    commitment_bytes: &[u8],
    public_inputs: &[u32],
    circuit_hash: &[u8],
    num_repetitions: usize,
    num_parties: usize,
) -> Vec<usize> {
    // Serialize public inputs.
    let mut pub_bytes = Vec::with_capacity(public_inputs.len() * 4);
    for &v in public_inputs {
        pub_bytes.extend_from_slice(&v.to_le_bytes());
    }

    // Hash everything together.
    let mut hasher = Sha3_256::new();
    hasher.update(b"mpcith-zk:fiat-shamir:v1");
    hasher.update(commitment_bytes);
    hasher.update(&pub_bytes);
    hasher.update(circuit_hash);
    hasher.update(&num_repetitions.to_le_bytes());
    hasher.update(&num_parties.to_le_bytes());
    let seed: [u8; 32] = hasher.finalize().into();

    // Expand the seed into `num_repetitions` challenges using a PRNG.
    // We use ChaCha20 seeded from the hash.
    use rand::{RngCore, SeedableRng};
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

    (0..num_repetitions)
        .map(|_| (rng.next_u64() as usize) % num_parties)
        .collect()
}

/// Hash a circuit description for Fiat-Shamir binding.
/// We use the gate sequence and wire count.
pub fn hash_circuit(circuit: &crate::circuit::Circuit) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"mpcith-zk:circuit:v1");
    hasher.update(&circuit.num_wires.to_le_bytes());
    hasher.update(&circuit.num_inputs.to_le_bytes());
    hasher.update(&circuit.num_outputs.to_le_bytes());
    hasher.update(&circuit.gates.len().to_le_bytes());

    // Hash each gate's type and wire indices.
    for gate in &circuit.gates {
        match gate {
            crate::circuit::Gate::Add { left, right, output } => {
                hasher.update(b"ADD");
                hasher.update(&left.to_le_bytes());
                hasher.update(&right.to_le_bytes());
                hasher.update(&output.to_le_bytes());
            }
            crate::circuit::Gate::Mul { left, right, output } => {
                hasher.update(b"MUL");
                hasher.update(&left.to_le_bytes());
                hasher.update(&right.to_le_bytes());
                hasher.update(&output.to_le_bytes());
            }
            crate::circuit::Gate::Xor { left, right, output } => {
                hasher.update(b"XOR");
                hasher.update(&left.to_le_bytes());
                hasher.update(&right.to_le_bytes());
                hasher.update(&output.to_le_bytes());
            }
            crate::circuit::Gate::AddConst { input, constant, output } => {
                hasher.update(b"ADDC");
                hasher.update(&input.to_le_bytes());
                hasher.update(&constant.to_le_bytes());
                hasher.update(&output.to_le_bytes());
            }
            crate::circuit::Gate::MulConst { input, constant, output } => {
                hasher.update(b"MULC");
                hasher.update(&input.to_le_bytes());
                hasher.update(&constant.to_le_bytes());
                hasher.update(&output.to_le_bytes());
            }
            crate::circuit::Gate::AssertEq { input, expected, output } => {
                hasher.update(b"AEQC");
                hasher.update(&input.to_le_bytes());
                hasher.update(&expected.to_le_bytes());
                hasher.update(&output.to_le_bytes());
            }
        }
    }

    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenges_deterministic() {
        let commitments = vec![0u8; 64];
        let public_inputs = [7u32, 42u32];
        let circuit_hash = vec![1u8; 32];

        let c1 = derive_challenges(&commitments, &public_inputs, &circuit_hash, 10, 3);
        let c2 = derive_challenges(&commitments, &public_inputs, &circuit_hash, 10, 3);

        assert_eq!(c1, c2, "Challenges must be deterministic");
        assert_eq!(c1.len(), 10);
        assert!(c1.iter().all(|&c| c < 3), "Challenges must be in [0, N)");
    }

    #[test]
    fn test_challenges_differ_on_different_commitments() {
        let c1 = vec![0u8; 64];
        let c2 = vec![1u8; 64];
        let pub_in = [7u32];
        let ch = vec![0u8; 32];

        let ch1 = derive_challenges(&c1, &pub_in, &ch, 10, 3);
        let ch2 = derive_challenges(&c2, &pub_in, &ch, 10, 3);

        // With high probability these will differ (not a strict test but catches bugs).
        assert_ne!(ch1, ch2);
    }
}
