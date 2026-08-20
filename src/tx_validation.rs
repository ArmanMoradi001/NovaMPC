//! High-level transaction validation API for Hyperledger Fabric integration.
//!
//! This module bridges the ZK proof library with Fabric chaincode by expressing
//! proof construction and verification in terms of transaction validation
//! concepts: authorized ranges, Merkle-authenticated account sets, and
//! block-binding context.
//!
//! # Replay protection
//!
//! The `context` field (e.g. block hash, channel ID) is hashed into a `u32`
//! and appended to the public-inputs vector. Since public inputs are fed into
//! the Fiat-Shamir transcript, a proof generated for block N cannot be replayed
//! at block N+1 — the verifier would hash a different context, derive different
//! challenges, and reject the proof.

use sha3::{Digest, Sha3_256};

use crate::fiat_shamir::hash_circuit;
use crate::merkle::MerkleProof;
use crate::params::ProofParams;
use crate::predicate::CompoundPredicate;
use crate::proof::{self, Proof};
use crate::{MpcithError, Result};

// ─── Data structures ──────────────────────────────────────────────────────────

/// Complete public statement for a transaction validation proof.
///
/// All fields are public and available to both prover and verifier.
/// The statement encodes: "the secret value lies in `amount_range` AND
/// belongs to the Merkle-authenticated set with root `authorized_set_root`,
/// bound to `context`."
#[derive(Debug, Clone)]
pub struct TransactionStatement {
    /// The authorized transfer range `(lo, hi)` inclusive.
    /// Proves: `lo <= secret_value <= hi`.
    pub amount_range: (u32, u32),
    /// Merkle root of the authorized account / product set.
    /// Proves: `secret_value ∈ set` where `Merkle(set) = authorized_set_root`.
    pub authorized_set_root: u32,
    /// Depth of the Merkle tree (log₂ of the padded leaf count).
    /// Needed to reconstruct witness layout for the verifier.
    pub merkle_depth: usize,
    /// Additional public context bound into the Fiat-Shamir transcript
    /// to prevent cross-transaction proof replay.  Typical values: block
    /// hash, channel ID, chaincode invocation ID.
    pub context: Vec<u8>,
    /// The full authorized member set.  Required at proving time to
    /// compile the SetMembership circuit.  The verifier does NOT need
    /// this — the root is embedded in the proof's circuit.
    pub members: Vec<u32>,
}

/// Private witness for a transaction proof.
///
/// Contains exactly the secret data that the prover must supply and that
/// the verifier never sees.
#[derive(Debug, Clone)]
pub struct TransactionWitness {
    /// The actual private transfer amount or asset ID.
    pub secret_value: u32,
    /// Merkle authentication path for `secret_value` inside the authorized set.
    /// The `leaf` field of this proof must equal `secret_value`.
    pub merkle_proof: MerkleProof,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Hash arbitrary context bytes into a single `u32` for public-input binding.
///
/// Uses SHA3-256 and takes the first four bytes (little-endian) as a `u32`.
fn hash_context_to_u32(context: &[u8]) -> u32 {
    if context.is_empty() {
        return 0;
    }
    let hash: [u8; 32] = Sha3_256::digest(context).into();
    u32::from_le_bytes(hash[..4].try_into().unwrap())
}

/// Build the public-inputs vector from a transaction statement.
///
/// Encoding: `[lo, hi, authorized_set_root, context_hash]`.
///
/// This encoding is fed into `derive_challenges` inside the Fiat-Shamir
/// transform, so all four values are cryptographically bound to the proof.
fn encode_public_inputs(statement: &TransactionStatement) -> Vec<u32> {
    let (lo, hi) = statement.amount_range;
    vec![
        lo,
        hi,
        statement.authorized_set_root,
        hash_context_to_u32(&statement.context),
    ]
}

// ─── Core API ─────────────────────────────────────────────────────────────────

/// Create a zero-knowledge proof for a transaction statement.
///
/// Builds a compound `RangeCheck ∧ SetMembership` circuit from the statement,
/// generates the witness from `witness.secret_value` and `witness.merkle_proof`,
/// and runs the MPC-in-the-Head protocol.
///
/// # Errors
/// - Returns `Err` if the secret value is outside the authorized range.
/// - Returns `Err` if the Merkle proof does not verify against the statement's
///   root (i.e. the value is not in the authorized set).
/// - Returns `Err` if the members list is empty.
pub fn create_transaction_proof(
    statement: &TransactionStatement,
    witness: &TransactionWitness,
    params: &ProofParams,
) -> Result<Proof> {
    let (lo, hi) = statement.amount_range;

    // Build the compound predicate.
    let predicate = CompoundPredicate::range_and_membership(lo, hi, statement.members.clone());

    // Generate the full witness vector: range_witness ++ membership_witness.
    let full_witness = predicate.generate_witness(witness.secret_value)?;

    // Encode public inputs with context binding.
    let public_inputs = encode_public_inputs(statement);

    proof::prove_compound(predicate, &full_witness, &public_inputs, params)
}

/// Verify a transaction proof against a statement.
///
/// Reconstructs the public-inputs encoding from the statement (including the
/// context hash), independently recompiles the expected
/// `RangeCheck ∧ SetMembership` circuit from the statement's public fields
/// (`amount_range`, `authorized_set_root`, `merkle_depth`) and checks that
/// the proof's circuit hash matches before delegating to `proof::verify()`.
///
/// This check is critical: without it a malicious prover can submit a trivial
/// always-true circuit while claiming the correct `public_inputs`, bypassing
/// the range and membership constraints entirely.
///
/// The `members` field of the statement is NOT used here — the verifier only
/// needs the Merkle root and tree depth, both of which are already part of
/// the public statement.
pub fn verify_transaction_proof(
    proof: &Proof,
    statement: &TransactionStatement,
    params: &ProofParams,
) -> Result<bool> {
    let (lo, hi) = statement.amount_range;

    // Independently compile the expected circuit from the public statement
    // (no member list needed — only the root and depth are required).
    let expected_compiled = CompoundPredicate::range_and_membership_for_verify(
        lo,
        hi,
        statement.authorized_set_root,
        statement.merkle_depth,
    )?;
    let expected_hash = hash_circuit(&expected_compiled.circuit);

    // Reject the proof if its circuit does not match the one implied by the
    // public statement.  Without this check a prover could substitute any
    // trivially-satisfiable circuit while keeping public_inputs correct.
    if proof.circuit_hash != expected_hash {
        return Err(MpcithError::VerificationFailed(
            "Proof circuit does not match the circuit implied by the transaction statement. \
             Possible circuit-substitution attack."
                .into(),
        ));
    }

    let public_inputs = encode_public_inputs(statement);
    proof::verify(proof, &public_inputs, params)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use crate::params::ProofParams;

    /// Helper: build a 4-leaf authorized set and statement for range [1, 1000].
    fn setup() -> (TransactionStatement, TransactionWitness, Vec<u32>) {
        let members = vec![10u32, 20, 500, 999];
        let tree = MerkleTree::build(&members);
        let root = tree.root();
        let depth = members.len().next_power_of_two().trailing_zeros() as usize;

        let statement = TransactionStatement {
            amount_range: (1, 1000),
            authorized_set_root: root,
            merkle_depth: depth,
            context: b"block-42-channel-myorg".to_vec(),
            members: members.clone(),
        };

        // Build witness for secret_value = 500 (leaf_index = 2).
        let merkle_proof = tree.prove_membership(2);
        let witness = TransactionWitness {
            secret_value: 500,
            merkle_proof,
        };

        (statement, witness, members)
    }

    #[test]
    fn test_transaction_proof_valid() {
        let params = ProofParams::fast_insecure();
        let (statement, witness, _members) = setup();

        let proof = create_transaction_proof(&statement, &witness, &params).unwrap();
        let ok = verify_transaction_proof(&proof, &statement, &params).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_transaction_proof_wrong_context() {
        let params = ProofParams::fast_insecure();
        let (statement, witness, _members) = setup();

        let proof = create_transaction_proof(&statement, &witness, &params).unwrap();

        // Verify with a different context (simulating a different block).
        let mut wrong_statement = statement.clone();
        wrong_statement.context = b"block-43-channel-myorg".to_vec();

        let result = verify_transaction_proof(&proof, &wrong_statement, &params);
        assert!(result.is_err(), "proof should fail with wrong context");
    }

    #[test]
    fn test_transaction_proof_amount_out_of_range() {
        let params = ProofParams::fast_insecure();
        let members = vec![10u32, 20, 500, 999];
        let tree = MerkleTree::build(&members);
        let root = tree.root();
        let depth = members.len().next_power_of_two().trailing_zeros() as usize;

        let statement = TransactionStatement {
            amount_range: (1, 1000),
            authorized_set_root: root,
            merkle_depth: depth,
            context: b"block-42".to_vec(),
            members,
        };

        // secret_value = 5000 is outside [1, 1000].
        let merkle_proof = tree.prove_membership(2);
        let witness = TransactionWitness {
            secret_value: 5000,
            merkle_proof,
        };

        let result = create_transaction_proof(&statement, &witness, &params);
        assert!(result.is_err(), "should reject out-of-range amount");
    }

    #[test]
    fn test_transaction_proof_unauthorized_account() {
        let params = ProofParams::fast_insecure();
        let members = vec![10u32, 20, 500, 999];
        let tree = MerkleTree::build(&members);
        let root = tree.root();
        let depth = members.len().next_power_of_two().trailing_zeros() as usize;

        let statement = TransactionStatement {
            amount_range: (1, 1000),
            authorized_set_root: root,
            merkle_depth: depth,
            context: b"block-42".to_vec(),
            members,
        };

        // secret_value = 100 is in range [1, 1000] but NOT in the authorized set.
        // generate_witness for SetMembership will fail because 100 is not a member.
        let witness = TransactionWitness {
            secret_value: 100,
            merkle_proof: MerkleProof {
                leaf: 100,
                leaf_index: 0,
                siblings: vec![0; depth],
                root,
            },
        };

        let result = create_transaction_proof(&statement, &witness, &params);
        assert!(result.is_err(), "should reject unauthorized account");
    }
}
