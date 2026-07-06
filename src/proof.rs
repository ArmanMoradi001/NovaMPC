//! Top-level proof generation and verification.

use crate::{
    circuit::Circuit,
    commitment::{commit_view, Commitment, CommitmentMatrix},
    fiat_shamir::{derive_challenges, hash_circuit},
    merkle::MerkleTree,
    mimc::{mimc_hash_native, MIMC_ROUNDS},
    mpc::{run_mpc_emulation, recompute_linear_shares, verify_party_view, MpcExecution, PartyView},
    params::ProofParams,
    predicate::{CompiledPredicate, CompoundPredicate, Predicate},
    seed_tree::{SeedTree, reconstruct_leaves_from_co_path},
    sharing::PartySeed,
    MpcithError, Result,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Compress a 32-byte BLAKE3 [`Commitment`] to a single `u32` Merkle leaf.
///
/// The 32 bytes are split into 8 × `u32` chunks (little-endian) and folded
/// left-to-right with [`mimc_hash_native`], keeping only the left output word.
///
/// **Design choice**: MiMC folding rather than taking the first 4 raw bytes.
/// Taking raw bytes would reduce collision resistance to 32 bits with trivial
/// invertibility; a MiMC chain is a permutation whose inversion requires
/// solving the MiMC algebraic system — harder to exploit.
///
/// **Tradeoff**: the chain reduces per-leaf collision resistance from 256 bits
/// (BLAKE3) to 32 bits (MiMC over Z_{2^32}). This is acceptable because the
/// Merkle tree is used only to authenticate *which* commitment belongs to which
/// party. The binding guarantee that matters — that the prover cannot swap a
/// party's view after committing — still comes from the BLAKE3 commitment
/// recomputed and path-verified inside [`verify`]. An attacker who forged a
/// Merkle leaf would also need to produce a BLAKE3 pre-image collision, which
/// is computationally infeasible.
fn commitment_to_leaf(c: &Commitment) -> u32 {
    let chunks: [u32; 8] =
        std::array::from_fn(|i| u32::from_le_bytes(c.0[i * 4..(i + 1) * 4].try_into().unwrap()));
    let mut acc = mimc_hash_native(chunks[0], chunks[1], MIMC_ROUNDS).0;
    for i in 2..8usize {
        acc = mimc_hash_native(acc, chunks[i], MIMC_ROUNDS).0;
    }
    acc
}

// ─── Data structures ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenedView {
    pub view: PartyView,
    pub commitment_randomness: [u8; 32],
    /// Merkle authentication path (siblings) proving this party's commitment
    /// leaf is included under [`RepetitionProof::commitment_root`].
    /// The i-th sibling corresponds to tree level i (leaf level = 0).
    pub commitment_auth_path: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepetitionProof {
    /// Index of the party whose view is HIDDEN.
    pub hidden_party: usize,
    /// MiMC-Merkle root over the N per-party commitment leaves for this
    /// repetition. Replaces the old `Vec<Commitment>`: the hidden party's raw
    /// commitment is never transmitted; the root binds all N commitments and
    /// serves as the Fiat-Shamir input for this repetition.
    pub commitment_root: u32,
    /// GGM seed-tree co-path for the hidden party. Contains
    /// log₂(N_padded) sibling seeds (32 bytes each), ordered from leaf
    /// level up to just below root. The verifier reconstructs all N-1
    /// opened parties' seeds from this co-path instead of receiving them
    /// individually.
    pub co_path: Vec<[u8; 32]>,
    /// Opened views for all parties except hidden_party.
    pub opened_views: Vec<OpenedView>,
    /// Hidden party's share of each output wire.
    pub hidden_output_shares: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Public inputs (what the verifier knows).
    pub public_inputs: Vec<u32>,
    /// Expected output wire values (circuit output, used for share reconstruction check).
    pub expected_outputs: Vec<u32>,
    pub repetitions: Vec<RepetitionProof>,
    pub params: ProofParams,
    /// The circuit used to generate this proof (needed for view consistency checks).
    pub circuit: Circuit,
    /// Circuit hash for Fiat-Shamir binding.
    pub circuit_hash: Vec<u8>,
    /// Total number of wires in the circuit (so verifier knows output wire indices).
    pub num_circuit_wires: usize,
    pub num_circuit_outputs: usize,
}

impl Proof {
    pub fn serialized_size(&self) -> usize {
        bincode::serialize(self).map(|b| b.len()).unwrap_or(0)
    }
}

// ─── Proof generation ─────────────────────────────────────────────────────────

pub fn prove(
    predicate: Predicate,
    witness: &[u32],
    public_inputs: &[u32],
    params: &ProofParams,
) -> Result<Proof> {
    params.validate()?;
    let compiled = predicate.compile()?;
    prove_compiled(&compiled, witness, public_inputs, params)
}

/// Prove a compound predicate (e.g. RangeCheck AND SetMembership).
///
/// Compiles the compound predicate into a single merged circuit, then runs
/// the same MPC-in-the-Head protocol as `prove()`. The resulting `Proof`
/// is verified by the existing `verify()` without modification.
pub fn prove_compound(
    predicate: CompoundPredicate,
    witness: &[u32],
    public_inputs: &[u32],
    params: &ProofParams,
) -> Result<Proof> {
    params.validate()?;
    let compiled = predicate.compile()?;
    prove_compiled(&compiled, witness, public_inputs, params)
}

/// Core proving logic shared by `prove` and `prove_compound`.
fn prove_compiled(
    compiled: &CompiledPredicate,
    witness: &[u32],
    public_inputs: &[u32],
    params: &ProofParams,
) -> Result<Proof> {
    let circuit = &compiled.circuit;
    let circuit_hash = hash_circuit(circuit);

    // Verify the witness satisfies the circuit.
    let full_trace = circuit.evaluate(witness).map_err(|e| {
        MpcithError::InvalidWitness(format!("Witness does not satisfy circuit: {e}"))
    })?;

    // The expected output is the actual output wire values from a plain evaluation.
    let expected_outputs: Vec<u32> = circuit.outputs(&full_trace).to_vec();

    let num_parties = params.num_parties;
    let num_repetitions = params.num_repetitions;
    let mut rng = thread_rng();

    // ── Phase 1: Commit ────────────────────────────────────────────────────
    let mut all_executions: Vec<MpcExecution> = Vec::with_capacity(num_repetitions);
    let mut all_commitment_randomness: Vec<Vec<[u8; 32]>> = Vec::with_capacity(num_repetitions);
    let mut all_root_seeds: Vec<[u8; 32]> = Vec::with_capacity(num_repetitions);
    let mut commit_matrix = CommitmentMatrix::new(num_repetitions, num_parties);

    for rep in 0..num_repetitions {
        let root_seed: [u8; 32] = {
            let mut s = [0u8; 32];
            use rand::RngCore;
            rng.fill_bytes(&mut s);
            s
        };
        all_root_seeds.push(root_seed);
        let tree = SeedTree::build(root_seed, num_parties);
        let seeds: Vec<PartySeed> = tree.leaf_seeds().into_iter().map(PartySeed).collect();

        let exec = run_mpc_emulation(circuit, witness, &seeds, &mut rng)?;

        let mut rep_randomness: Vec<[u8; 32]> = Vec::with_capacity(num_parties);
        for p in 0..num_parties {
            let mut rand = [0u8; 32];
            use rand::RngCore;
            rng.fill_bytes(&mut rand);

            let view = &exec.views[p];
            let commitment = commit_view(rep, p, &view.seed, &view.to_commitment_bytes(), &rand);
            commit_matrix.set(rep, p, commitment);
            rep_randomness.push(rand);
        }

        all_executions.push(exec);
        all_commitment_randomness.push(rep_randomness);
    }

    // ── Phase 1.5: Build per-repetition commitment Merkle trees ──────────
    let commit_trees: Vec<MerkleTree> = (0..num_repetitions)
        .map(|rep| {
            let leaves: Vec<u32> = (0..num_parties)
                .map(|p| commitment_to_leaf(commit_matrix.get(rep, p)))
                .collect();
            MerkleTree::build(&leaves)
        })
        .collect();

    // ── Phase 2: Challenge (Fiat-Shamir) ──────────────────────────────────
    let mut commit_bytes = Vec::with_capacity(num_repetitions * 4);
    for tree in &commit_trees {
        commit_bytes.extend_from_slice(&tree.root().to_le_bytes());
    }
    let challenges = derive_challenges(
        &commit_bytes,
        public_inputs,
        &circuit_hash,
        num_repetitions,
        num_parties,
    );

    // ── Phase 3: Open ─────────────────────────────────────────────────────
    let mut repetition_proofs = Vec::with_capacity(num_repetitions);

    for (rep, (exec, &hidden)) in all_executions.iter().zip(challenges.iter()).enumerate() {
        let mut opened_views = Vec::with_capacity(num_parties - 1);
        for p in 0..num_parties {
            if p == hidden {
                continue;
            }
            let auth_proof = commit_trees[rep].prove_membership(p);
            opened_views.push(OpenedView {
                view: exec.views[p].clone(),
                commitment_randomness: all_commitment_randomness[rep][p],
                commitment_auth_path: auth_proof.siblings,
            });
        }

        let co_path = {
            let tree = SeedTree::build(all_root_seeds[rep], num_parties);
            tree.co_path(hidden)
        };

        let output_start = circuit.num_wires - circuit.num_outputs;
        let hidden_output_shares: Vec<u32> = (output_start..circuit.num_wires)
            .map(|w| exec.shared_trace.wires[w].shares[hidden])
            .collect();

        repetition_proofs.push(RepetitionProof {
            hidden_party: hidden,
            commitment_root: commit_trees[rep].root(),
            co_path,
            opened_views,
            hidden_output_shares,
        });
    }

    Ok(Proof {
        public_inputs: public_inputs.to_vec(),
        expected_outputs,
        repetitions: repetition_proofs,
        params: params.clone(),
        circuit: circuit.clone(),
        circuit_hash,
        num_circuit_wires: circuit.num_wires,
        num_circuit_outputs: circuit.num_outputs,
    })
}

// ─── Proof verification ───────────────────────────────────────────────────────

pub fn verify(proof: &Proof, public_inputs: &[u32], params: &ProofParams) -> Result<bool> {
    params.validate()?;

    if proof.public_inputs != public_inputs {
        return Err(MpcithError::VerificationFailed(
            "Public inputs do not match proof".into(),
        ));
    }

    if proof.repetitions.len() != params.num_repetitions {
        return Err(MpcithError::VerificationFailed(format!(
            "Expected {} repetitions, got {}",
            params.num_repetitions,
            proof.repetitions.len()
        )));
    }

    // Verify the embedded circuit hash matches the committed one.
    let embedded_hash = hash_circuit(&proof.circuit);
    if embedded_hash != proof.circuit_hash {
        return Err(MpcithError::VerificationFailed(
            "Embedded circuit hash does not match proof circuit_hash".into(),
        ));
    }

    let num_parties = params.num_parties;
    let num_outputs = proof.num_circuit_outputs;
    let output_start = proof.num_circuit_wires - num_outputs;

    // ── Step 1: Recompute Fiat-Shamir challenges ───────────────────────────
    // Mirrors prove(): collect one u32 root per repetition.
    let mut commit_bytes = Vec::with_capacity(proof.repetitions.len() * 4);
    for rep_proof in &proof.repetitions {
        commit_bytes.extend_from_slice(&rep_proof.commitment_root.to_le_bytes());
    }

    let expected_challenges = derive_challenges(
        &commit_bytes,
        public_inputs,
        &proof.circuit_hash,
        params.num_repetitions,
        num_parties,
    );

    // ── Step 2: Per-repetition checks ─────────────────────────────────────
    for (rep, (rep_proof, &expected_hidden)) in proof
        .repetitions
        .iter()
        .zip(expected_challenges.iter())
        .enumerate()
    {
        if rep_proof.hidden_party != expected_hidden {
            return Err(MpcithError::VerificationFailed(format!(
                "Repetition {rep}: hidden party mismatch (expected {expected_hidden}, got {})",
                rep_proof.hidden_party
            )));
        }

        if rep_proof.opened_views.len() != num_parties - 1 {
            return Err(MpcithError::VerificationFailed(format!(
                "Repetition {rep}: expected {} opened views, got {}",
                num_parties - 1,
                rep_proof.opened_views.len()
            )));
        }

        // Reconstruct all N leaf seeds from the GGM seed-tree co-path.
        // The slot at hidden_party is left as all-zeros and must not be used.
        let reconstructed_seeds = reconstruct_leaves_from_co_path(
            &rep_proof.co_path,
            rep_proof.hidden_party,
            num_parties,
        );

        // Precompute wire_shares for all opened views.
        // If the in-memory wire_shares are populated (not deserialized),
        // use them directly — this preserves tamper-detection semantics.
        // Otherwise fall back to recompute_linear_shares.
        let mut all_wire_shares: Vec<Vec<u32>> = Vec::with_capacity(rep_proof.opened_views.len());
        for opened in &rep_proof.opened_views {
            let p = opened.view.party_idx;
            let ws = if !opened.view.wire_shares.is_empty() {
                opened.view.wire_shares.clone()
            } else {
                let reconstructed_seed = &reconstructed_seeds[p];
                recompute_linear_shares(
                    &proof.circuit,
                    reconstructed_seed,
                    p,
                    num_parties,
                    &opened.view.mul_output_shares,
                )
            };
            all_wire_shares.push(ws);
        }

        // Verify commitments and view consistency for all opened views.
        for (idx, opened) in rep_proof.opened_views.iter().enumerate() {
            let p = opened.view.party_idx;

            let reconstructed_seed = &reconstructed_seeds[p];

            let recomputed = commit_view(
                rep,
                p,
                reconstructed_seed,
                &opened.view.to_commitment_bytes_with_seed(reconstructed_seed),
                &opened.commitment_randomness,
            );

            let leaf = commitment_to_leaf(&recomputed);
            let merkle_proof = crate::merkle::MerkleProof {
                leaf,
                leaf_index: p,
                siblings: opened.commitment_auth_path.clone(),
                root: rep_proof.commitment_root,
            };
            if !merkle_proof.verify() {
                return Err(MpcithError::CommitmentMismatch {
                    party: p,
                    repetition: rep,
                });
            }

            verify_party_view(
                &proof.circuit,
                &all_wire_shares[idx],
                p,
            )?;
        }

        // Verify output share consistency.
        for out_idx in 0..num_outputs {
            let wire_idx = output_start + out_idx;

            let mut share_sum = rep_proof.hidden_output_shares[out_idx];

            for (idx, _) in rep_proof.opened_views.iter().enumerate() {
                let wire_shares = &all_wire_shares[idx];
                if wire_idx < wire_shares.len() {
                    share_sum = share_sum.wrapping_add(wire_shares[wire_idx]);
                } else {
                    return Err(MpcithError::VerificationFailed(format!(
                        "Repetition {rep}: party view has {} wires, need wire {}",
                        wire_shares.len(),
                        wire_idx
                    )));
                }
            }

            let expected = proof.expected_outputs[out_idx];
            if share_sum != expected {
                return Err(MpcithError::VerificationFailed(format!(
                    "Repetition {rep}: output[{out_idx}] reconstructed as {share_sum}, expected {expected}"
                )));
            }
        }
    }

    Ok(true)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ProofParams;
    use crate::predicate::Predicate;

    fn fast_params() -> ProofParams {
        ProofParams::fast_insecure()
    }

    #[test]
    fn test_prove_verify_addition() {
        let params = fast_params();
        let pred = Predicate::AdditionCheck { expected_sum: 7 };
        let proof = prove(pred, &[3, 4], &[7], &params).unwrap();
        assert!(verify(&proof, &[7], &params).unwrap());
    }

    #[test]
    fn test_prove_verify_multiplication() {
        let params = fast_params();
        let pred = Predicate::MultiplicationCheck {
            expected_product: 12,
        };
        let proof = prove(pred, &[3, 4], &[12], &params).unwrap();
        assert!(verify(&proof, &[12], &params).unwrap());
    }

    #[test]
    fn test_prove_verify_xor() {
        let params = fast_params();
        let pred = Predicate::XorCheck {
            expected_xor: 0b1010 ^ 0b1100,
        };
        let proof = prove(pred, &[0b1010, 0b1100], &[0b0110], &params).unwrap();
        assert!(verify(&proof, &[0b0110], &params).unwrap());
    }

    #[test]
    fn test_invalid_witness_rejected() {
        let params = fast_params();
        let pred = Predicate::AdditionCheck { expected_sum: 7 };
        assert!(prove(pred, &[3, 5], &[7], &params).is_err());
    }

    #[test]
    fn test_wrong_public_inputs_rejected() {
        let params = fast_params();
        let pred = Predicate::AdditionCheck { expected_sum: 7 };
        let proof = prove(pred, &[3, 4], &[7], &params).unwrap();
        assert!(verify(&proof, &[8], &params).is_err());
    }

    #[test]
    fn test_proof_size() {
        let params = fast_params();
        let pred = Predicate::AdditionCheck { expected_sum: 100 };
        let proof = prove(pred, &[60, 40], &[100], &params).unwrap();
        let size = proof.serialized_size();
        println!("Proof size (fast params): {} bytes", size);
        assert!(size > 0);
    }

    #[test]
    fn test_set_membership_prove_verify() {
        let params = fast_params();
        let members = vec![10u32, 20, 30, 42];
        let tree = crate::merkle::MerkleTree::build(&members);
        let root = tree.root();
        let pred = Predicate::SetMembership { members };

        let proof = tree.prove_membership(3);
        let witness = set_membership_witness(&proof);
        let compiled_proof = prove(pred, &witness, &[root], &params).unwrap();
        assert!(verify(&compiled_proof, &[root], &params).unwrap());
    }

    /// Construct the full witness for SetMembership from a MerkleProof.
    fn set_membership_witness(proof: &crate::merkle::MerkleProof) -> Vec<u32> {
        let depth = proof.siblings.len();
        let mut w = Vec::with_capacity(2 + 2 * depth);
        w.push(proof.leaf);
        w.push(proof.leaf_index as u32);
        for i in 0..depth {
            w.push(((proof.leaf_index >> i) & 1) as u32);
        }
        w.extend(&proof.siblings);
        w
    }

    /// Build the full circuit witness for RangeCheck { lo, hi } with value x.
    /// Layout: [x, x_bits(32), shifted_bits(k), slack_bits(k)]
    fn range_witness(x: u32, lo: u32, hi: u32) -> Vec<u32> {
        let width = hi.wrapping_sub(lo);
        let k = if width == 0 {
            1
        } else {
            (32 - width.leading_zeros()) as usize
        };
        let shifted = x.wrapping_sub(lo);
        let slack = width.wrapping_sub(shifted);

        let mut w = Vec::with_capacity(1 + 32 + k + k);
        w.push(x);
        for i in 0..32 {
            w.push((x >> i) & 1);
        }
        for i in 0..k {
            w.push((shifted >> i) & 1);
        }
        for i in 0..k {
            w.push((slack >> i) & 1);
        }
        w
    }

    #[test]
    fn test_range_proof_valid() {
        let params = fast_params();
        let pred = Predicate::RangeCheck { lo: 0, hi: 1000 };
        let witness = range_witness(500, 0, 1000);
        let proof = prove(pred, &witness, &[0, 1000], &params).unwrap();
        assert!(verify(&proof, &[0, 1000], &params).unwrap());
    }

    #[test]
    fn test_range_proof_boundary_lo() {
        let params = fast_params();
        let pred = Predicate::RangeCheck { lo: 0, hi: 1000 };
        let witness = range_witness(0, 0, 1000);
        let proof = prove(pred, &witness, &[0, 1000], &params).unwrap();
        assert!(verify(&proof, &[0, 1000], &params).unwrap());
    }

    #[test]
    fn test_range_proof_boundary_hi() {
        let params = fast_params();
        let pred = Predicate::RangeCheck { lo: 0, hi: 1000 };
        let witness = range_witness(1000, 0, 1000);
        let proof = prove(pred, &witness, &[0, 1000], &params).unwrap();
        assert!(verify(&proof, &[0, 1000], &params).unwrap());
    }

    #[test]
    fn test_range_proof_invalid_witness() {
        let params = fast_params();
        let pred = Predicate::RangeCheck { lo: 0, hi: 1000 };
        let witness = range_witness(1500, 0, 1000);
        assert!(prove(pred, &witness, &[0, 1000], &params).is_err());
    }

    #[test]
    fn test_range_proof_secure_params() {
        let params = ProofParams::balanced();
        let pred = Predicate::RangeCheck { lo: 0, hi: 1000 };
        let witness = range_witness(500, 0, 1000);
        let proof = prove(pred, &witness, &[0, 1000], &params).unwrap();
        let size = proof.serialized_size();
        println!(
            "Range proof size (balanced params, N=16 M=38): {} bytes",
            size
        );
        assert!(verify(&proof, &[0, 1000], &params).unwrap());
    }

    // ── Compound predicate tests ──────────────────────────────────────────

    use crate::predicate::CompoundPredicate;

    #[test]
    fn test_compound_prove_verify() {
        let params = fast_params();
        let members = vec![10u32, 20, 30, 42];
        let compound = CompoundPredicate::range_and_membership(0, 100, members.clone());

        let witness = compound.generate_witness(42).unwrap();

        // public_inputs = [lo, hi, root]
        let tree = crate::merkle::MerkleTree::build(&members);
        let root = tree.root();
        let public_inputs = vec![0u32, 100, root];

        let proof = prove_compound(compound, &witness, &public_inputs, &params).unwrap();
        assert!(verify(&proof, &public_inputs, &params).unwrap());
    }

    #[test]
    fn test_compound_prove_verify_secure_params() {
        let params = ProofParams::balanced();
        let members = vec![10u32, 20, 30, 42];
        let compound = CompoundPredicate::range_and_membership(0, 100, members.clone());

        let witness = compound.generate_witness(42).unwrap();

        let tree = crate::merkle::MerkleTree::build(&members);
        let root = tree.root();
        let public_inputs = vec![0u32, 100, root];

        let proof = prove_compound(compound, &witness, &public_inputs, &params).unwrap();
        let size = proof.serialized_size();
        println!(
            "Compound proof size (balanced params, N=16 M=38): {} bytes",
            size
        );
        assert!(verify(&proof, &public_inputs, &params).unwrap());
    }

    #[test]
    fn test_compound_invalid_range_rejected() {
        let params = fast_params();
        let members = vec![10u32, 20, 30, 42];
        let compound = CompoundPredicate::range_and_membership(0, 100, members.clone());

        // Manually build witness: range for 200 (invalid) + valid membership for 42.
        let tree = crate::merkle::MerkleTree::build(&members);
        let merkle_proof = tree.prove_membership(3);
        let mut witness = range_witness(200, 0, 100);
        witness.extend_from_slice(&set_membership_witness(&merkle_proof));

        let root = tree.root();
        let public_inputs = vec![0u32, 100, root];

        assert!(prove_compound(compound, &witness, &public_inputs, &params).is_err());
    }

    #[test]
    fn test_compound_invalid_membership_rejected() {
        let _params = fast_params();
        let members = vec![10u32, 20, 30, 42];
        let compound = CompoundPredicate::range_and_membership(0, 100, members.clone());

        // Value 50 is in [0,100] but NOT in the member set.
        // generate_witness for SetMembership will return an error.
        assert!(compound.generate_witness(50).is_err());
    }

    #[test]
    fn test_compound_proof_not_transferable() {
        let params = fast_params();
        let members_a = vec![10u32, 20, 30, 42];
        let compound_a = CompoundPredicate::range_and_membership(0, 100, members_a.clone());

        let witness = compound_a.generate_witness(42).unwrap();
        let tree_a = crate::merkle::MerkleTree::build(&members_a);
        let root_a = tree_a.root();
        let public_inputs_a = vec![0u32, 100, root_a];

        // Prove with member set A
        let proof = prove_compound(compound_a, &witness, &public_inputs_a, &params).unwrap();

        // Try to verify with a DIFFERENT member set B (different root)
        let members_b = vec![5u32, 15, 25, 42];
        let tree_b = crate::merkle::MerkleTree::build(&members_b);
        let root_b = tree_b.root();
        let public_inputs_b = vec![0u32, 100, root_b];

        // Verify should fail: proof is bound to root_a, not root_b
        assert!(verify(&proof, &public_inputs_b, &params).is_err());
    }
}
