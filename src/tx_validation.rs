//! High-level transaction validation API for Hyperledger Fabric integration.
//!
//! This module bridges the ZK proof library with Fabric chaincode by expressing
//! proof construction and verification in terms of transaction validation
//! concepts: authorized ranges, Merkle-authenticated account sets, and
//! block-binding context.
//!
//! # Replay protection
//!
//! The `context` field (e.g. block hash, channel ID) is hashed with SHA3-256
//! over a domain separator plus length prefix, and the full 32-byte digest
//! (as eight `u32` words) is appended to the public-inputs vector. Since
//! public inputs are fed into the Fiat-Shamir transcript, a proof generated
//! for block N cannot be replayed at block N+1 — the verifier would hash a
//! different context, derive different challenges, and reject the proof.

use sha3::{Digest, Sha3_256};

use crate::fiat_shamir::hash_circuit;
use crate::merkle::MerkleProof;
use crate::params::ProofParams;
use crate::predicate::{set_membership_witness_vec, CompoundPredicate, Predicate};
use crate::proof::{self, Proof};
use crate::{MpcithError, Result};

// ─── Data structures ──────────────────────────────────────────────────────────

/// Complete public statement for a transaction validation proof.
///
/// All fields are public and available to both prover and verifier.
/// The statement encodes: "the secret value lies in `amount_range` AND
/// belongs to the Merkle-authenticated set with root `authorized_set_root`,
/// bound to `context`."
///
/// The verifier needs only the Merkle `authorized_set_root`, `merkle_depth`,
/// and `num_members` — never the full authorized member list. `num_members`
/// is the true length of the set the root was built from; it is baked into
/// the circuit's index-bound constraint (`leaf_index < num_members`), so a
/// wrong count compiles a different circuit and fails closed.
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
    /// Number of members in the authorized set the root was built from.
    /// Must satisfy `1 <= num_members <= 2^merkle_depth`; it is a public
    /// constant inside the circuit's index-bound constraint.
    pub num_members: usize,
    /// Additional public context bound into the Fiat-Shamir transcript
    /// to prevent cross-transaction proof replay.  Typical values: block
    /// hash, channel ID, chaincode invocation ID.
    pub context: Vec<u8>,
}

/// Private witness for a transaction proof.
///
/// Contains exactly the secret data that the prover must supply and that
/// the verifier never sees.
///
/// The `merkle_proof` is the membership witness used verbatim when building
/// the proof: its leaf, index bits, and siblings become the SetMembership
/// half of the compound witness. It must be a valid authentication path for
/// `secret_value` under the statement's root (see
/// [`create_transaction_proof`] for the exact checks).
#[derive(Debug, Clone)]
pub struct TransactionWitness {
    /// The actual private transfer amount or asset ID.
    pub secret_value: u32,
    /// Merkle authentication path for `secret_value` inside the authorized set.
    /// The `leaf` field of this proof must equal `secret_value`.
    pub merkle_proof: MerkleProof,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Domain separator for transaction-context hashing (H-4).
const TX_CONTEXT_DOMAIN: &[u8] = b"mpcith-zk:tx-context:v1";

/// Hash arbitrary context bytes to a full 32-byte digest for binding.
///
/// Uses SHA3-256 over `domain || len(context) as u64-LE || context`. The
/// length prefix gives empty and non-empty contexts distinct encodings by
/// construction (H-4); colliding two contexts requires a full SHA3-256
/// collision, not a 32-bit one.
fn hash_context_to_bytes(context: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(TX_CONTEXT_DOMAIN);
    hasher.update(&(context.len() as u64).to_le_bytes());
    hasher.update(context);
    hasher.finalize().into()
}

/// Hash arbitrary context bytes into eight `u32` words (little-endian) for
/// public-input binding. Binds the full 256-bit digest (H-4).
fn hash_context_to_words(context: &[u8]) -> [u32; 8] {
    let bytes = hash_context_to_bytes(context);
    let mut words = [0u32; 8];
    for (i, w) in words.iter_mut().enumerate() {
        *w = u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
    }
    words
}

/// Build the public-inputs vector from a transaction statement.
///
/// Encoding: `[lo, hi, authorized_set_root, ctx_0, .., ctx_7]` where
/// `ctx_*` are the eight `u32` words of `SHA3-256(domain || len || context)`.
///
/// This encoding is fed into `derive_challenges` inside the Fiat-Shamir
/// transform, so all values are cryptographically bound to the proof.
fn encode_public_inputs(statement: &TransactionStatement) -> Vec<u32> {
    let (lo, hi) = statement.amount_range;
    let ctx = hash_context_to_words(&statement.context);
    let mut inputs = Vec::with_capacity(3 + ctx.len());
    inputs.push(lo);
    inputs.push(hi);
    inputs.push(statement.authorized_set_root);
    inputs.extend_from_slice(&ctx);
    inputs
}

/// Validate the public membership parameters before any proving or
/// verification work.
///
/// Rejects empty sets and `(depth, num_members)` pairs that cannot describe
/// a real Merkle tree. Runs first in both [`create_transaction_proof`] and
/// [`verify_transaction_proof`] so inconsistent statements fail fast,
/// before circuit compilation or MPC emulation. The in-circuit index bound
/// (`leaf_index < num_members`) itself is unchanged.
fn validate_membership_params(num_members: usize, depth: usize) -> Result<()> {
    if num_members == 0 {
        return Err(MpcithError::InvalidParams(
            "Transaction statement has an empty authorized set (num_members == 0)".into(),
        ));
    }
    if depth >= 32 {
        return Err(MpcithError::InvalidParams(format!(
            "Merkle depth {depth} out of supported range (must be < 32)"
        )));
    }
    if num_members > (1usize << depth) {
        return Err(MpcithError::InvalidParams(format!(
            "Member count {num_members} inconsistent with Merkle depth {depth}"
        )));
    }
    Ok(())
}

/// Create a zero-knowledge proof for a transaction statement.
///
/// Compiles the compound `RangeCheck ∧ SetMembership` circuit from the
/// statement's public `(root, depth, num_members)` — the exact same
/// compilation the verifier performs — using the **supplied**
/// `witness.merkle_proof` as the membership witness (leaf, index bits,
/// siblings) and `witness.secret_value` for the range witness, then runs
/// the MPC-in-the-Head protocol over the crate-internal compiled-circuit
/// path. No member list is needed: the authentication path in the witness
/// carries the membership evidence.
///
/// The statement and the supplied proof are validated before any proving
/// work starts. All failures return `Err`; this function never panics.
///
/// # Validation
/// - `(num_members, merkle_depth)` is a consistent pair: non-empty and
///   `num_members <= 2^merkle_depth`.
/// - `witness.merkle_proof.leaf == witness.secret_value`.
/// - `witness.merkle_proof.root == statement.authorized_set_root`.
/// - `witness.merkle_proof.siblings.len() == statement.merkle_depth`.
/// - `witness.merkle_proof.leaf_index < statement.num_members`.
/// - The supplied proof verifies natively (`MerkleProof::verify`).
///
/// # Errors
/// - Returns `Err` for an empty set or an inconsistent
///   `(depth, num_members)` pair.
/// - Returns `Err` if the supplied Merkle proof is inconsistent with the
///   secret value or the statement (wrong leaf, root, index, or path).
/// - Returns `Err` if the secret value is outside the authorized range or
///   otherwise does not satisfy the circuit.
pub fn create_transaction_proof(
    statement: &TransactionStatement,
    witness: &TransactionWitness,
    params: &ProofParams,
) -> Result<Proof> {
    let (lo, hi) = statement.amount_range;

    // Fail fast on empty sets and inconsistent (depth, count) pairs,
    // before compiling the circuit or running any MPC emulation.
    validate_membership_params(statement.num_members, statement.merkle_depth)?;

    // ── Supplied Merkle proof validation ────────────────────────────
    // The supplied proof is the membership witness; reject anything that
    // does not authenticate secret_value under the statement's root.
    let supplied = &witness.merkle_proof;
    if supplied.leaf != witness.secret_value {
        return Err(MpcithError::InvalidWitness(
            "Supplied Merkle proof leaf does not equal the secret value".into(),
        ));
    }
    if supplied.root != statement.authorized_set_root {
        return Err(MpcithError::InvalidWitness(
            "Supplied Merkle proof root does not match the statement's authorized set root".into(),
        ));
    }
    if supplied.siblings.len() != statement.merkle_depth {
        return Err(MpcithError::InvalidWitness(format!(
            "Supplied Merkle proof has path length {} but statement requires depth {}",
            supplied.siblings.len(),
            statement.merkle_depth
        )));
    }
    if supplied.leaf_index >= statement.num_members {
        return Err(MpcithError::InvalidWitness(format!(
            "Supplied Merkle proof index {} out of range for {} authorized members",
            supplied.leaf_index, statement.num_members
        )));
    }
    if !supplied.verify() {
        return Err(MpcithError::InvalidWitness(
            "Supplied Merkle proof does not verify (wrong siblings for leaf/index/root)".into(),
        ));
    }

    // Compile from the public (root, depth, num_members) — byte-identical to
    // what verify_transaction_proof recompiles — and prove over the
    // crate-internal compiled-circuit path (no unchecked or unsafe API).
    let compiled = CompoundPredicate::range_and_membership_for_verify(
        lo,
        hi,
        statement.authorized_set_root,
        statement.merkle_depth,
        statement.num_members,
    )?;

    // Membership witness comes from the supplied proof (leaf, index bits,
    // siblings); range witness comes from the secret value.
    let mut full_witness =
        Predicate::RangeCheck { lo, hi }.generate_witness(witness.secret_value)?;
    full_witness.extend_from_slice(&set_membership_witness_vec(supplied));

    // Encode public inputs with context binding.
    let public_inputs = encode_public_inputs(statement);

    proof::prove_compiled(&compiled, &full_witness, &public_inputs, params)
}

/// Verify a transaction proof against a statement.
///
/// Reconstructs the public-inputs encoding from the statement (including the
/// context hash), independently recompiles the expected
/// `RangeCheck ∧ SetMembership` circuit from the statement's public fields
/// (`amount_range`, `authorized_set_root`, `merkle_depth`, `num_members`)
/// and checks that the proof's circuit hash matches before delegating to
/// `proof::verify_unchecked()` (the crate-internal transcript verifier).
///
/// This check is critical: without it a malicious prover can submit a trivial
/// always-true circuit while claiming the correct `public_inputs`, bypassing
/// the range and membership constraints entirely.
///
/// Since audit finding F-1, the SetMembership circuit constrains
/// `leaf_index < num_members` in-circuit, so the statement must carry the
/// true member count — no member list is needed or accepted. A wrong count
/// changes the expected circuit hash and fails closed.
///
/// Empty sets and inconsistent `(depth, num_members)` pairs are rejected
/// before recompiling, so malformed statements fail fast.
pub fn verify_transaction_proof(
    proof: &Proof,
    statement: &TransactionStatement,
    params: &ProofParams,
) -> Result<bool> {
    let (lo, hi) = statement.amount_range;

    // Fail fast on malformed membership parameters, before recompiling.
    validate_membership_params(statement.num_members, statement.merkle_depth)?;

    // Independently compile the expected circuit from the public statement.
    // The member count is baked into the F-1 index-bound constraint
    // (`leaf_index < num_members`) of the SetMembership sub-circuit. A wrong
    // count changes the expected circuit hash and fails closed — it can
    // never loosen the membership constraint.
    let expected_compiled = CompoundPredicate::range_and_membership_for_verify(
        lo,
        hi,
        statement.authorized_set_root,
        statement.merkle_depth,
        statement.num_members,
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
    proof::verify_unchecked(proof, &public_inputs, params)
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
            num_members: members.len(),
            context: b"block-42-channel-myorg".to_vec(),
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
            num_members: members.len(),
            context: b"block-42".to_vec(),
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
            num_members: members.len(),
            context: b"block-42".to_vec(),
        };

        // secret_value = 100 is in range [1, 1000] but NOT in the authorized set.
        // The hand-built proof cannot authenticate leaf 100 under the set's
        // root, so supplied-proof validation rejects it.
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

    // ── Supplied-proof regression: the witness's Merkle proof is the ──
    //    membership witness (previously it was silently regenerated).

    #[test]
    fn test_supplied_proof_tampered_sibling_rejected() {
        // 500 ∈ members, but the supplied path is corrupted. The old code
        // regenerated a fresh proof from secret_value and would have
        // succeeded; the fixed code must reject the supplied path.
        let params = ProofParams::fast_insecure();
        let (statement, witness, _members) = setup();

        let mut bad = witness.clone();
        bad.merkle_proof.siblings[0] ^= 1;

        let result = create_transaction_proof(&statement, &bad, &params);
        assert!(
            result.is_err(),
            "tampered supplied sibling path must be rejected"
        );
    }

    #[test]
    fn test_supplied_proof_wrong_leaf_rejected() {
        let params = ProofParams::fast_insecure();
        let (statement, witness, _members) = setup();

        // Leaf disagrees with the secret value (secret stays 500).
        let mut bad = witness.clone();
        bad.merkle_proof.leaf = 501;

        let result = create_transaction_proof(&statement, &bad, &params);
        assert!(result.is_err(), "proof leaf != secret must be rejected");
    }

    #[test]
    fn test_supplied_proof_wrong_root_rejected() {
        let params = ProofParams::fast_insecure();
        let (statement, witness, _members) = setup();

        // Proof rooted at a different tree than the statement.
        let mut bad = witness.clone();
        bad.merkle_proof.root ^= 1;

        let result = create_transaction_proof(&statement, &bad, &params);
        assert!(result.is_err(), "proof root != statement root must be rejected");

        // Same, but with the statement root corrupted instead.
        let mut bad_statement = statement.clone();
        bad_statement.authorized_set_root ^= 1;
        let result = create_transaction_proof(&bad_statement, &witness, &params);
        assert!(result.is_err(), "statement root != proof root must be rejected");
    }

    #[test]
    fn test_supplied_proof_wrong_index_rejected() {
        let params = ProofParams::fast_insecure();
        let (statement, witness, members) = setup();

        // Out-of-range index: no such authorized member slot.
        let mut bad = witness.clone();
        bad.merkle_proof.leaf_index = members.len();
        assert!(create_transaction_proof(&statement, &bad, &params).is_err());

        // In-range but wrong index: leaf 500 opened at index 0 with
        // index 0's path cannot verify.
        let tree = MerkleTree::build(&members);
        let mut mistargeted = tree.prove_membership(0);
        mistargeted.leaf = 500;
        let bad_witness = TransactionWitness {
            secret_value: 500,
            merkle_proof: mistargeted,
        };
        assert!(
            create_transaction_proof(&statement, &bad_witness, &params).is_err(),
            "leaf opened at the wrong index must be rejected"
        );
    }

    #[test]
    fn test_supplied_proof_wrong_depth_rejected() {
        let params = ProofParams::fast_insecure();
        let (statement, witness, _members) = setup();

        // Truncated sibling path: depth mismatch with the statement.
        let mut bad = witness.clone();
        bad.merkle_proof.siblings.pop();
        assert!(
            create_transaction_proof(&statement, &bad, &params).is_err(),
            "short sibling path must be rejected"
        );
    }

    #[test]
    fn test_statement_metadata_mismatch_rejected() {
        let params = ProofParams::fast_insecure();
        let (statement, witness, _members) = setup();

        // Wrong depth for a 4-member set.
        let mut bad_depth = statement.clone();
        bad_depth.merkle_depth = statement.merkle_depth + 1;
        assert!(
            create_transaction_proof(&bad_depth, &witness, &params).is_err(),
            "wrong statement depth must be rejected"
        );

        // Empty set.
        let mut empty = statement.clone();
        empty.num_members = 0;
        assert!(
            create_transaction_proof(&empty, &witness, &params).is_err(),
            "empty authorized set must be rejected"
        );

        // Count inconsistent with depth (5 members cannot fit in depth 2).
        let mut bad_count = statement.clone();
        bad_count.num_members = 5;
        assert!(
            create_transaction_proof(&bad_count, &witness, &params).is_err(),
            "member count inconsistent with depth must be rejected"
        );
    }

    #[test]
    fn test_supplied_proof_non_power_of_two_valid() {
        // 5 members (padded to 8 leaves): an honest supplied proof must
        // still prove and verify end to end.
        let params = ProofParams::fast_insecure();
        let members = vec![11u32, 22, 33, 44, 55];
        let tree = MerkleTree::build(&members);
        let statement = TransactionStatement {
            amount_range: (1, 100),
            authorized_set_root: tree.root(),
            merkle_depth: members.len().next_power_of_two().trailing_zeros() as usize,
            num_members: members.len(),
            context: b"block-9-five-members".to_vec(),
        };
        let witness = TransactionWitness {
            secret_value: 55,
            merkle_proof: tree.prove_membership(4),
        };
        let proof = create_transaction_proof(&statement, &witness, &params)
            .expect("honest supplied proof for padded set must be provable");
        assert!(verify_transaction_proof(&proof, &statement, &params).unwrap());
    }

    // ── Count-only API: prover and verifier derive identical circuits ──

    #[test]
    fn test_prover_verifier_circuits_match() {
        // The prover compiles from (root, depth, num_members) exactly as the
        // verifier does, so the embedded circuit hash must equal an
        // independently recompiled expectation — no member list involved.
        use crate::fiat_shamir::hash_circuit;
        use crate::predicate::CompoundPredicate;

        let params = ProofParams::fast_insecure();
        let (statement, witness, _members) = setup();
        let (lo, hi) = statement.amount_range;

        let proof = create_transaction_proof(&statement, &witness, &params).unwrap();
        let expected = CompoundPredicate::range_and_membership_for_verify(
            lo,
            hi,
            statement.authorized_set_root,
            statement.merkle_depth,
            statement.num_members,
        )
        .unwrap();
        assert_eq!(
            proof.circuit_hash,
            hash_circuit(&expected.circuit),
            "prover and verifier must derive identical circuits from (root, depth, num_members)"
        );
    }

    #[test]
    fn test_verify_rejects_changed_root_depth_count() {
        // An honest proof must fail verification when any of the public
        // membership parameters changes: each yields a different expected
        // circuit (or a rejected compilation), never a looser constraint.
        let params = ProofParams::fast_insecure();
        let (statement, witness, _members) = setup();
        let proof = create_transaction_proof(&statement, &witness, &params).unwrap();
        assert!(verify_transaction_proof(&proof, &statement, &params).unwrap());

        let mut bad_root = statement.clone();
        bad_root.authorized_set_root ^= 1;
        assert!(
            verify_transaction_proof(&proof, &bad_root, &params).is_err(),
            "changed root must be rejected"
        );

        let mut bad_depth = statement.clone();
        bad_depth.merkle_depth = statement.merkle_depth + 1;
        assert!(
            verify_transaction_proof(&proof, &bad_depth, &params).is_err(),
            "changed depth must be rejected"
        );

        for bad_count in [statement.num_members - 1, statement.num_members + 1, 0] {
            let mut bad = statement.clone();
            bad.num_members = bad_count;
            assert!(
                verify_transaction_proof(&proof, &bad, &params).is_err(),
                "changed member count {bad_count} must be rejected"
            );
        }
    }

    // ── F-6 regression: single-member authorized set (depth 0) ────────────

    fn single_member_statement() -> TransactionStatement {
        let members = vec![42u32];
        let tree = MerkleTree::build(&members);
        TransactionStatement {
            amount_range: (0, 100),
            authorized_set_root: tree.root(),
            merkle_depth: 0, // single leaf: depth 0
            num_members: 1,
            context: b"block-7-single-member".to_vec(),
        }
    }

    #[test]
    fn test_transaction_proof_single_member_valid() {
        // members = [42], secret = 42 → create + verify MUST succeed.
        let params = ProofParams::fast_insecure();
        let statement = single_member_statement();

        let witness = TransactionWitness {
            secret_value: 42,
            merkle_proof: MerkleTree::build(&[42u32]).prove_membership(0),
        };

        let proof = create_transaction_proof(&statement, &witness, &params)
            .expect("single-member transaction proof must be creatable");
        let ok = verify_transaction_proof(&proof, &statement, &params)
            .expect("verification must not error on depth-0 statements");
        assert!(ok, "valid single-member proof MUST verify");
    }

    #[test]
    fn test_transaction_proof_single_member_invalid_secret() {
        // members = [42], secret = 43 → MUST fail.
        let params = ProofParams::fast_insecure();
        let statement = single_member_statement();

        let witness = TransactionWitness {
            secret_value: 43,
            merkle_proof: MerkleTree::build(&[42u32]).prove_membership(0),
        };

        let result = create_transaction_proof(&statement, &witness, &params);
        assert!(result.is_err(), "43 ∉ {{42}} must not be provable");

        // And a hand-forged claim against the true root must also be
        // unprovable end-to-end.
        let mut forged_witness = witness.clone();
        forged_witness.secret_value = 43;
        if let Ok(proof) = create_transaction_proof(&statement, &forged_witness, &params) {
            assert!(
                !matches!(verify_transaction_proof(&proof, &statement, &params), Ok(true)),
                "forged single-member proof must not verify"
            );
        }
    }

    // ── H-4 regression: full 256-bit context binding ──────────────────────

    #[test]
    fn test_h4_context_binding_is_256_bits() {
        // Public inputs must carry lo, hi, root plus all 8 context words.
        let members = vec![10u32, 20, 500, 999];
        let root = MerkleTree::build(&members).root();
        let statement = TransactionStatement {
            amount_range: (1, 1000),
            authorized_set_root: root,
            merkle_depth: 2,
            num_members: members.len(),
            context: b"block-42".to_vec(),
        };
        let inputs = encode_public_inputs(&statement);
        assert_eq!(inputs.len(), 3 + 8, "context must bind 8 words (256 bits)");
        assert_eq!(&inputs[..3], &[1, 1000, root]);
        assert_eq!(
            &inputs[3..],
            &hash_context_to_words(b"block-42")[..],
            "trailing words must be the full context digest"
        );
    }

    #[test]
    fn test_h4_empty_context_is_distinct_and_deterministic() {
        assert_eq!(
            hash_context_to_words(b""),
            hash_context_to_words(b""),
            "context hashing must be deterministic"
        );
        assert_ne!(
            hash_context_to_words(b""),
            hash_context_to_words(b"\0"),
            "empty context must not collide with a one-byte context by construction"
        );
        // Length prefix also separates values that only differ in length.
        assert_ne!(
            hash_context_to_words(b"block-4"),
            hash_context_to_words(b"block-42"),
            "different contexts must bind to different public inputs"
        );
    }

    #[test]
    fn test_h4_empty_context_proof_verifies_only_with_empty_context() {
        let params = ProofParams::fast_insecure();
        let members = vec![10u32, 20, 500, 999];
        let tree = MerkleTree::build(&members);
        let statement = TransactionStatement {
            amount_range: (1, 1000),
            authorized_set_root: tree.root(),
            merkle_depth: 2,
            num_members: members.len(),
            context: Vec::new(),
        };
        let witness = TransactionWitness {
            secret_value: 500,
            merkle_proof: tree.prove_membership(2),
        };
        let proof = create_transaction_proof(&statement, &witness, &params).unwrap();
        assert!(verify_transaction_proof(&proof, &statement, &params).unwrap());
        let mut other = statement.clone();
        other.context = b"block-42".to_vec();
        assert!(verify_transaction_proof(&proof, &other, &params).is_err());
    }
}
