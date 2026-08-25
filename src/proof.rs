//! Top-level proof generation and verification.

use crate::{
    circuit::Circuit,
    commit_merkle::{CommitMerkleProof, CommitTree},
    commitment::{commit_view, CommitmentMatrix},
    fiat_shamir::{derive_challenges, hash_circuit},
    mpc::{
        recompute_linear_shares, run_mpc_emulation, verify_party_view, MpcExecution,
        OpenedNeighbor, PartyView,
    },
    params::ProofParams,
    predicate::{CompiledPredicate, CompoundPredicate, Predicate},
    seed_tree::{reconstruct_leaves_from_co_path, SeedTree},
    sharing::PartySeed,
    MpcithError, Result,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

// ─── Data structures ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenedView {
    pub view: PartyView,
    pub commitment_randomness: [u8; 32],
    /// Merkle authentication path (siblings) proving this party's commitment
    /// leaf is included under [`RepetitionProof::commitment_root`].
    /// The i-th sibling corresponds to tree level i (leaf level = 0).
    pub commitment_auth_path: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepetitionProof {
    /// Index of the party whose view is HIDDEN.
    pub hidden_party: usize,
    /// BLAKE3-Merkle root over the N per-party commitment leaves for this
    /// repetition. Replaces the old `Vec<Commitment>`: the hidden party's raw
    /// commitment is never transmitted; the root binds all N commitments and
    /// serves as the Fiat-Shamir input for this repetition.
    pub commitment_root: [u8; 32],
    /// GGM seed-tree co-path for the hidden party. Contains
    /// log₂(N_padded) sibling seeds (32 bytes each), ordered from leaf
    /// level up to just below root. The verifier reconstructs all N-1
    /// opened parties' seeds from this co-path instead of receiving them
    /// individually.
    pub co_path: Vec<[u8; 32]>,
    /// Opened views for all parties except hidden_party.
    pub opened_views: Vec<OpenedView>,
    /// Every party's share of each circuit output wire, indexed
    /// `[output_idx][party]`. Published for ALL parties, including the
    /// hidden one — revealing an additive share of a publicly-checked value
    /// leaks nothing about the witness. These shares (together with
    /// `assert_shares`) are hashed into the Fiat-Shamir transcript BEFORE
    /// the hidden party is chosen, so a prover cannot bias them after
    /// learning which party will stay hidden.
    pub output_shares: Vec<Vec<u32>>,
    /// Every party's share of each `AssertEq` gate's input wire, indexed
    /// `[gate_idx][party]`, bound into the transcript the same way as
    /// `output_shares`. Lets the verifier check
    /// `Σ_p assert_shares[gate][p] == circuit.gates[gate].expected` for
    /// every assertion in the circuit (not just the declared output),
    /// closing the gap where `AssertEq` gates — including the boolean and
    /// reconstruction checks inside `bit_decompose`, and hence RangeCheck /
    /// SetMembership correctness — were never actually enforced in the MPC
    /// verification path.
    pub assert_shares: Vec<Vec<u32>>,
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

/// Serialize per-party `AssertEq`/output shares in a canonical order for
/// binding into the Fiat-Shamir transcript. Must match exactly between
/// `prove_compiled` and `verify`.
fn encode_public_shares(assert_shares: &[Vec<u32>], output_shares: &[Vec<u32>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for shares in assert_shares {
        for &s in shares {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
    }
    for shares in output_shares {
        for &s in shares {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
    }
    bytes
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
    // Every `AssertEq` gate in the circuit, as (input_wire, expected constant).
    // Used to bind and independently check every assertion — not just the
    // final declared output — against the actual MPC shares.
    let assert_constraints = circuit.assert_constraints();
    let output_start = circuit.num_wires - circuit.num_outputs;

    let num_parties = params.num_parties;
    let num_repetitions = params.num_repetitions;
    let mut rng = thread_rng();

    // ── Phase 1: Commit ────────────────────────────────────────────────────
    let mut all_executions: Vec<MpcExecution> = Vec::with_capacity(num_repetitions);
    let mut all_commitment_randomness: Vec<Vec<[u8; 32]>> = Vec::with_capacity(num_repetitions);
    let mut all_root_seeds: Vec<[u8; 32]> = Vec::with_capacity(num_repetitions);
    // Per-repetition, every party's share of every output wire / AssertEq
    // input wire — see `RepetitionProof::output_shares`/`assert_shares`.
    let mut all_output_shares: Vec<Vec<Vec<u32>>> = Vec::with_capacity(num_repetitions);
    let mut all_assert_shares: Vec<Vec<Vec<u32>>> = Vec::with_capacity(num_repetitions);
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

        let output_shares: Vec<Vec<u32>> = (output_start..circuit.num_wires)
            .map(|w| {
                (0..num_parties)
                    .map(|p| exec.shared_trace.wires[w].shares[p])
                    .collect()
            })
            .collect();
        let assert_shares: Vec<Vec<u32>> = assert_constraints
            .iter()
            .map(|&(wire, _)| {
                (0..num_parties)
                    .map(|p| exec.shared_trace.wires[wire].shares[p])
                    .collect()
            })
            .collect();

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

        all_output_shares.push(output_shares);
        all_assert_shares.push(assert_shares);
        all_executions.push(exec);
        all_commitment_randomness.push(rep_randomness);
    }

    // ── Phase 1.5: Build per-repetition commitment Merkle trees ──────────
    let commit_trees: Vec<CommitTree> = (0..num_repetitions)
        .map(|rep| {
            let leaves: Vec<[u8; 32]> = (0..num_parties)
                .map(|p| commit_matrix.get(rep, p).0)
                .collect();
            CommitTree::build(&leaves)
        })
        .collect();

    // ── Phase 2: Challenge (Fiat-Shamir) ──────────────────────────────────
    // Bind each repetition's commitment root AND its (public, per-party)
    // output/assert shares into the transcript BEFORE the hidden party is
    // chosen, so the prover cannot pick those shares adaptively afterwards.
    let mut commit_bytes = Vec::with_capacity(num_repetitions * 32);
    for (rep, tree) in commit_trees.iter().enumerate() {
        commit_bytes.extend_from_slice(&tree.root());
        commit_bytes.extend_from_slice(&encode_public_shares(
            &all_assert_shares[rep],
            &all_output_shares[rep],
        ));
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

        repetition_proofs.push(RepetitionProof {
            hidden_party: hidden,
            commitment_root: commit_trees[rep].root(),
            co_path,
            opened_views,
            output_shares: all_output_shares[rep].clone(),
            assert_shares: all_assert_shares[rep].clone(),
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

/// Verify a proof against the given public inputs.
///
/// **Warning:** this function does **not** verify that `proof.circuit` matches
/// any particular predicate — it only checks that `proof.circuit_hash` matches
/// the circuit embedded in the proof.  A malicious prover can embed a
/// trivially-satisfiable circuit in `Proof.circuit` and this function will
/// accept it, since nothing ties the circuit back to the predicate the caller
/// actually intended to check.
///
/// Prefer [`verify_predicate`] or [`verify_compound`] for application-level
/// verification, or perform your own circuit-hash check against the expected
/// compiled circuit (as `tx_validation::verify_transaction_proof` does) before
/// calling this function.
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
    let assert_constraints = proof.circuit.assert_constraints();

    // ── Step 1: Recompute Fiat-Shamir challenges ───────────────────────────
    // Mirrors prove(): collect the commitment root AND the (public,
    // per-party) output/assert shares for each repetition, in the same
    // order used by `prove_compiled`.
    let mut commit_bytes = Vec::with_capacity(proof.repetitions.len() * 32);
    for rep_proof in &proof.repetitions {
        if rep_proof.assert_shares.len() != assert_constraints.len() {
            return Err(MpcithError::VerificationFailed(format!(
                "Expected {} AssertEq share rows, got {}",
                assert_constraints.len(),
                rep_proof.assert_shares.len()
            )));
        }
        if rep_proof.output_shares.len() != num_outputs {
            return Err(MpcithError::VerificationFailed(format!(
                "Expected {num_outputs} output share rows, got {}",
                rep_proof.output_shares.len()
            )));
        }
        for row in rep_proof
            .assert_shares
            .iter()
            .chain(rep_proof.output_shares.iter())
        {
            if row.len() != num_parties {
                return Err(MpcithError::VerificationFailed(
                    "Malformed per-party share row (wrong party count)".into(),
                ));
            }
        }

        commit_bytes.extend_from_slice(&rep_proof.commitment_root);
        commit_bytes.extend_from_slice(&encode_public_shares(
            &rep_proof.assert_shares,
            &rep_proof.output_shares,
        ));
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

        // The opened party indices must be exactly {0..num_parties} \ 
        // {hidden_party}. Without these checks a prover could submit
        // duplicate indices (e.g. {(h+2) % N} twice), leaving one party
        // entirely unverified — its assert/output share entries would then
        // be free parameters that absorb any sum-check discrepancy, breaking
        // soundness completely. Out-of-range indices would additionally
        // panic on `reconstructed_seeds[p]` below.
        let mut opened_seen = vec![false; num_parties];
        for opened in &rep_proof.opened_views {
            let p = opened.view.party_idx;
            if p >= num_parties {
                return Err(MpcithError::VerificationFailed(format!(
                    "Repetition {rep}: opened party index {p} out of range (num_parties = {num_parties})"
                )));
            }
            if p == rep_proof.hidden_party {
                return Err(MpcithError::VerificationFailed(format!(
                    "Repetition {rep}: opened view claims hidden party {p}"
                )));
            }
            if opened_seen[p] {
                return Err(MpcithError::VerificationFailed(format!(
                    "Repetition {rep}: duplicate opened party index {p}"
                )));
            }
            opened_seen[p] = true;
        }
        for (p, &seen) in opened_seen.iter().enumerate() {
            if !seen && p != rep_proof.hidden_party {
                return Err(MpcithError::VerificationFailed(format!(
                    "Repetition {rep}: non-hidden party {p} missing from opened views"
                )));
            }
        }

        // Reconstruct all N leaf seeds from the GGM seed-tree co-path.
        // The slot at hidden_party is left as all-zeros and must not be used.
        let reconstructed_seeds = reconstruct_leaves_from_co_path(
            &rep_proof.co_path,
            rep_proof.hidden_party,
            num_parties,
        )?;

        // Precompute wire_shares for all opened views, always derived from the
        // reconstructed seed.  `wire_shares` is not part of any commitment, so
        // a pre-populated value can never be trusted here.
        let mut all_wire_shares: Vec<Vec<u32>> = Vec::with_capacity(rep_proof.opened_views.len());
        for opened in &rep_proof.opened_views {
            let p = opened.view.party_idx;
            let reconstructed_seed = &reconstructed_seeds[p];
            let ws = recompute_linear_shares(
                &proof.circuit,
                reconstructed_seed,
                p,
                num_parties,
                &opened.view.mul_output_shares,
                &opened.view.residual_input_shares,
            )?;
            all_wire_shares.push(ws);
        }

        // Verify commitments and view consistency for all opened views.
        // Map each opened party index to its position in `all_wire_shares` so
        // we can hand the verifier a party's right neighbour's data when it is
        // also opened (required for the ZKBoo Mul share check).
        let mut opened_index_of: Vec<usize> = vec![usize::MAX; num_parties];
        for (i, op) in rep_proof.opened_views.iter().enumerate() {
            opened_index_of[op.view.party_idx] = i;
        }

        for (idx, opened) in rep_proof.opened_views.iter().enumerate() {
            let p = opened.view.party_idx;

            let reconstructed_seed = &reconstructed_seeds[p];

            let recomputed = commit_view(
                rep,
                p,
                reconstructed_seed,
                &opened
                    .view
                    .to_commitment_bytes_with_seed(reconstructed_seed),
                &opened.commitment_randomness,
            );

            let leaf = recomputed.0;
            let merkle_proof = CommitMerkleProof {
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

            // Right neighbour ((p+1) % 3) data — only available if that party
            // is also opened.  If it is the hidden party, its Mul/Xor share is
            // structurally unverifiable and skipped by the 2-of-3 scheme.
            let next = (p + 1) % num_parties;
            let next_opened = if next != rep_proof.hidden_party {
                let next_idx = opened_index_of[next];
                if next_idx == usize::MAX {
                    return Err(MpcithError::VerificationFailed(format!(
                        "Repetition {rep}: opened party {next} missing from opened views"
                    )));
                }
                Some(OpenedNeighbor {
                    seed: &reconstructed_seeds[next],
                    wire_shares: all_wire_shares[next_idx].as_slice(),
                })
            } else {
                None
            };

            verify_party_view(
                &proof.circuit,
                &all_wire_shares[idx],
                p,
                reconstructed_seed,
                next_opened,
            )?;

            // Cross-check the publicly-revealed per-party assert/output
            // shares against this opened party's own (committed) view. A
            // cheating prover cannot reveal one set of shares for the
            // Σ==expected checks below while using different, inconsistent
            // shares in the committed view used for the Mul/Xor/AssertEq
            // checks above.
            for (gate_idx, &(wire, _)) in assert_constraints.iter().enumerate() {
                if rep_proof.assert_shares[gate_idx][p] != all_wire_shares[idx][wire] {
                    return Err(MpcithError::VerificationFailed(format!(
                        "Repetition {rep}: party {p} assert-share mismatch for gate {gate_idx}"
                    )));
                }
            }
            for out_idx in 0..num_outputs {
                let wire_idx = output_start + out_idx;
                if rep_proof.output_shares[out_idx][p] != all_wire_shares[idx][wire_idx] {
                    return Err(MpcithError::VerificationFailed(format!(
                        "Repetition {rep}: party {p} output-share mismatch for output {out_idx}"
                    )));
                }
            }
        }

        // Verify every AssertEq gate's constraint: the sum of ALL N parties'
        // shares (opened AND hidden) of the gate's input wire must equal the
        // gate's public `expected` constant embedded in the circuit. This is
        // what actually enforces AssertEq — previously this was a no-op in
        // the MPC verification path, so boolean/range/membership checks
        // (and any other assertion) were never verified at all.
        for (gate_idx, &(_, expected)) in assert_constraints.iter().enumerate() {
            let sum = rep_proof.assert_shares[gate_idx]
                .iter()
                .fold(0u32, |acc, &s| acc.wrapping_add(s));
            if sum != expected {
                return Err(MpcithError::VerificationFailed(format!(
                    "Repetition {rep}: AssertEq gate {gate_idx} failed (reconstructed {sum}, expected {expected})"
                )));
            }
        }

        // Verify output share consistency: the sum of ALL N parties' shares
        // of each output wire must equal the expected output value. Prefer
        // the value derived directly from the circuit's own AssertEq gate (a
        // public constant bound into circuit_hash) over the prover-supplied
        // `expected_outputs` field whenever the output wire is the target of
        // such a gate — which is the case for every predicate in this crate.
        for out_idx in 0..num_outputs {
            let wire_idx = output_start + out_idx;
            let sum = rep_proof.output_shares[out_idx]
                .iter()
                .fold(0u32, |acc, &s| acc.wrapping_add(s));

            let expected = proof
                .circuit
                .assert_expected_for_output(wire_idx)
                .unwrap_or(proof.expected_outputs[out_idx]);

            if sum != expected {
                return Err(MpcithError::VerificationFailed(format!(
                    "Repetition {rep}: output[{out_idx}] reconstructed as {sum}, expected {expected}"
                )));
            }
        }
    }

    Ok(true)
}

/// Verify a proof against a specific predicate, guarding against
/// circuit-substitution attacks.
///
/// Independently recompiles `predicate` to obtain the expected circuit,
/// hashes it (using the same `hash_circuit` used by [`verify`] internally),
/// and compares against `proof.circuit_hash`.  If they differ, returns a
/// [`MpcithError::VerificationFailed`] indicating a possible
/// circuit-substitution attack, mirroring
/// `tx_validation::verify_transaction_proof`.  Only delegates to [`verify`]
/// when the hashes match.
pub fn verify_predicate(
    predicate: &Predicate,
    proof: &Proof,
    public_inputs: &[u32],
    params: &ProofParams,
) -> Result<bool> {
    let compiled = predicate.compile()?;
    let expected_hash = hash_circuit(&compiled.circuit);

    if proof.circuit_hash != expected_hash {
        return Err(MpcithError::VerificationFailed(
            "Proof circuit does not match the predicate — possible circuit-substitution attack"
                .into(),
        ));
    }

    verify(proof, public_inputs, params)
}

/// Verify a proof against a specific compound predicate, guarding against
/// circuit-substitution attacks.
///
/// Independently recompiles `compound` to obtain the expected circuit,
/// hashes it (using the same `hash_circuit` used by [`verify`] internally),
/// and compares against `proof.circuit_hash`.  If they differ, returns a
/// [`MpcithError::VerificationFailed`] indicating a possible
/// circuit-substitution attack, mirroring
/// `tx_validation::verify_transaction_proof`.  Only delegates to [`verify`]
/// when the hashes match.
pub fn verify_compound(
    compound: &CompoundPredicate,
    proof: &Proof,
    public_inputs: &[u32],
    params: &ProofParams,
) -> Result<bool> {
    let compiled = compound.compile()?;
    let expected_hash = hash_circuit(&compiled.circuit);

    if proof.circuit_hash != expected_hash {
        return Err(MpcithError::VerificationFailed(
            "Proof circuit does not match the compound predicate — possible circuit-substitution attack"
                .into(),
        ));
    }

    verify(proof, public_inputs, params)
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
    fn test_verify_predicate_roundtrip() {
        let params = fast_params();
        let pred = Predicate::AdditionCheck { expected_sum: 7 };
        let proof = prove(pred.clone(), &[3, 4], &[7], &params).unwrap();
        assert!(verify_predicate(&pred, &proof, &[7], &params).unwrap());
    }

    #[test]
    fn test_verify_predicate_rejects_circuit_substitution() {
        let params = fast_params();
        let pred = Predicate::AdditionCheck { expected_sum: 7 };
        let proof = prove(pred.clone(), &[3, 4], &[7], &params).unwrap();

        // Malicious prover swaps in a different, trivially-true circuit and
        // rebinds circuit_hash to it so `verify` would accept it; only
        // verify_predicate's predicate-binding check can catch this.
        let mut builder = crate::circuit::CircuitBuilder::new(2);
        builder.assert_eq(0, 0);
        let trivial_circuit = builder.build(1);

        let mut forged = proof;
        forged.circuit = trivial_circuit.clone();
        forged.circuit_hash = crate::fiat_shamir::hash_circuit(&trivial_circuit);
        forged.num_circuit_wires = trivial_circuit.num_wires;
        forged.num_circuit_outputs = trivial_circuit.num_outputs;

        let result = verify_predicate(&pred, &forged, &[7], &params);
        assert!(result.is_err(), "substituted circuit must be rejected");
        let err = result.unwrap_err();
        match err {
            crate::MpcithError::VerificationFailed(msg) => {
                assert!(
                    msg.contains("circuit-substitution"),
                    "error should mention circuit-substitution, got: {msg}"
                );
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_forged_expected_outputs_field_is_inert() {
        // Proof::expected_outputs used to be the *sole* value the verifier
        // checked reconstructed output shares against, with nothing tying
        // it to the real, publicly-known target. Tampering it should now
        // have NO effect: the verifier derives the true expected value from
        // the circuit's own AssertEq gate instead.
        let params = fast_params();
        let pred = Predicate::AdditionCheck { expected_sum: 7 };
        let mut proof = prove(pred, &[3, 4], &[7], &params).unwrap();
        proof.expected_outputs[0] = 999;
        assert!(
            verify(&proof, &[7], &params).unwrap(),
            "tampering the prover-supplied expected_outputs field must not affect verification"
        );
    }

    #[test]
    fn test_forged_assert_share_sum_rejected() {
        // Before this fix, AssertEq gates (including the boolean and
        // reconstruction checks generated by bit_decompose for RangeCheck)
        // were never checked in the MPC verification path. Breaking the
        // additive sum of any AssertEq gate's per-party shares must now be
        // rejected.
        let params = fast_params();
        let pred = Predicate::RangeCheck { lo: 1, hi: 1000 };
        let witness = range_witness(500, 1, 1000);
        let mut proof = prove(pred, &witness, &[1, 1000], &params).unwrap();
        assert!(verify(&proof, &[1, 1000], &params).unwrap());

        // Tamper party 0's share of the very first AssertEq gate (a boolean
        // check b*(b-1)==0 from bit_decompose). This breaks the sum, so it
        // must be rejected regardless of which party ends up hidden.
        proof.repetitions[0].assert_shares[0][0] =
            proof.repetitions[0].assert_shares[0][0].wrapping_add(1);
        let result = verify(&proof, &[1, 1000], &params);
        assert!(result.is_err(), "forged AssertEq share sum must cause Err");
    }

    #[test]
    fn test_forged_assert_share_shift_rejected() {
        // Shifting a value between two parties' shares of the same AssertEq
        // gate preserves the additive sum, but must still be rejected
        // because opened parties' revealed shares are cross-checked against
        // their own committed view.
        let params = fast_params();
        let pred = Predicate::RangeCheck { lo: 1, hi: 1000 };
        let witness = range_witness(500, 1, 1000);
        let mut proof = prove(pred, &witness, &[1, 1000], &params).unwrap();
        assert!(verify(&proof, &[1, 1000], &params).unwrap());

        proof.repetitions[0].assert_shares[0][0] =
            proof.repetitions[0].assert_shares[0][0].wrapping_add(1);
        proof.repetitions[0].assert_shares[0][1] =
            proof.repetitions[0].assert_shares[0][1].wrapping_sub(1);
        let result = verify(&proof, &[1, 1000], &params);
        assert!(
            result.is_err(),
            "sum-preserving shift between parties' AssertEq shares must still be rejected"
        );
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
        let x = 0b1010u32;
        let y = 0b1100u32;
        let pred = Predicate::XorCheck { expected_xor: x ^ y };
        // CircuitBuilder::xor() expands XOR into bit-decomposition gates, so the
        // witness must be [x, y] followed by the 32 bits of x and the 32 bits of y.
        let mut witness = vec![x, y];
        for i in 0..32 {
            witness.push((x >> i) & 1);
        }
        for i in 0..32 {
            witness.push((y >> i) & 1);
        }
        let proof = prove(pred, &witness, &[x ^ y], &params).unwrap();
        assert!(verify(&proof, &[x ^ y], &params).unwrap());
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
    fn test_serialized_proof_roundtrip() {
        // Prove, then serialize/deserialize so the verifier must rebuild
        // every opened party's shares from the seed tree co-path, the
        // transmitted residual-input shares (last party) and the committed
        // Mul output shares.  This exercises the real
        // networked-verification path, including the ZKBoo Mul check.
        let params = fast_params();

        let mul_pred = Predicate::MultiplicationCheck {
            expected_product: 12,
        };
        let mul_proof = prove(mul_pred, &[3, 4], &[12], &params).unwrap();
        let mul_bytes = bincode::serialize(&mul_proof).unwrap();
        let mul_roundtrip: Proof = bincode::deserialize(&mul_bytes).unwrap();
        assert!(
            verify(&mul_roundtrip, &[12], &params).unwrap(),
            "deserialized MultiplicationCheck proof must verify"
        );

        let add_pred = Predicate::AdditionCheck { expected_sum: 7 };
        let add_proof = prove(add_pred, &[3, 4], &[7], &params).unwrap();
        let add_bytes = bincode::serialize(&add_proof).unwrap();
        let add_roundtrip: Proof = bincode::deserialize(&add_bytes).unwrap();
        assert!(
            verify(&add_roundtrip, &[7], &params).unwrap(),
            "deserialized AdditionCheck proof must verify"
        );
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
            "Range proof size (balanced params, N=3 M=96): {} bytes",
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
            "Compound proof size (balanced params, N=3 M=96): {} bytes",
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

    // ── C-1 regression: opened-party multiset must be exactly {0..N}\{h} ──

    /// Prove AdditionCheck repeatedly until one proof per hidden-party value
    /// has been observed (bounded attempts).
    fn proofs_for_every_hidden(
        params: &ProofParams,
    ) -> Vec<Proof> {
        let mut per_hidden: Vec<Option<Proof>> = vec![None; params.num_parties];
        for _ in 0..500 {
            let proof = prove(
                Predicate::AdditionCheck { expected_sum: 7 },
                &[3, 4],
                &[7],
                params,
            )
            .unwrap();
            let h = proof.repetitions[0].hidden_party;
            if per_hidden[h].is_none() {
                per_hidden[h] = Some(proof);
            }
            if per_hidden.iter().all(|p| p.is_some()) {
                break;
            }
        }
        assert!(
            per_hidden.iter().all(|p| p.is_some()),
            "expected to observe every hidden-party value across repetitions"
        );
        per_hidden.into_iter().map(|p| p.unwrap()).collect()
    }

    #[test]
    fn test_c1_duplicate_opened_party_rejected() {
        let params = fast_params();
        for proof in proofs_for_every_hidden(&params) {
            let hidden = proof.repetitions[0].hidden_party;
            let orig = proof.repetitions[0].opened_views.clone();
            assert_eq!(orig.len(), params.num_parties - 1);

            let mut forged = proof;
            forged.repetitions[0].opened_views =
                vec![orig[0].clone(), orig[0].clone()];
            let result = verify(&forged, &[7], &params);
            assert!(
                result.is_err(),
                "A: duplicated opened party must be rejected (hidden = {hidden})"
            );
        }
    }

    #[test]
    fn test_c1_omitted_nonhidden_party_rejected() {
        let params = fast_params();
        for proof in proofs_for_every_hidden(&params) {
            let hidden = proof.repetitions[0].hidden_party;
            let orig = proof.repetitions[0].opened_views.clone();

            // Relabel the second opened view so both claim the same party:
            // one non-hidden party is silently missing from verification.
            let mut relabeled = orig[1].clone();
            relabeled.view.party_idx = orig[0].view.party_idx;

            let mut forged = proof;
            forged.repetitions[0].opened_views = vec![orig[0].clone(), relabeled];
            let result = verify(&forged, &[7], &params);
            assert!(
                result.is_err(),
                "B: omitted non-hidden party must be rejected (hidden = {hidden})"
            );
        }
    }

    #[test]
    fn test_c1_out_of_range_opened_party_rejected_no_panic() {
        let params = fast_params();
        for proof in proofs_for_every_hidden(&params) {
            let hidden = proof.repetitions[0].hidden_party;
            let orig = proof.repetitions[0].opened_views.clone();

            let mut oor = orig[1].clone();
            oor.view.party_idx = params.num_parties; // 3 for N=3

            let mut forged = proof;
            forged.repetitions[0].opened_views = vec![orig[0].clone(), oor];
            let result = verify(&forged, &[7], &params);
            assert!(
                result.is_err(),
                "C: out-of-range opened party must be rejected (hidden = {hidden})"
            );
        }
    }

    #[test]
    fn test_c1_hidden_party_in_opened_views_rejected() {
        let params = fast_params();
        for proof in proofs_for_every_hidden(&params) {
            let hidden = proof.repetitions[0].hidden_party;
            let orig = proof.repetitions[0].opened_views.clone();

            let mut as_opened = orig[1].clone();
            as_opened.view.party_idx = hidden;

            let mut forged = proof;
            forged.repetitions[0].opened_views = vec![orig[0].clone(), as_opened];
            let result = verify(&forged, &[7], &params);
            assert!(
                result.is_err(),
                "D: hidden party claimed as opened must be rejected (hidden = {hidden})"
            );
        }
    }

    #[test]
    fn test_c1_valid_permutation_of_opened_set_still_verifies() {
        let params = fast_params();
        for proof in proofs_for_every_hidden(&params) {
            let orig = proof.repetitions[0].opened_views.clone();

            // Sanity: unmodified proof verifies.
            assert!(verify(&proof, &[7], &params).unwrap());

            // E: same set, different order — verification is order-independent.
            let mut reordered = proof;
            reordered.repetitions[0].opened_views =
                vec![orig[1].clone(), orig[0].clone()];
            assert!(
                verify(&reordered, &[7], &params).unwrap(),
                "E: valid permutation of the opened set must still verify"
            );
        }
    }

    // ── C-2 regression: RangeCheck unsound for width >= 2^31 ──────────────

    #[test]
    fn test_c2_adversarial_large_width_cannot_prove() {
        // The pre-fix unsoundness: with lo = 0, hi = 2^31 (width = 2^31,
        // k = 32) the bit decompositions are vacuous and x = 3_000_000_000
        // (far above hi) could produce a VALID proof. The fix must reject
        // at compile time — before any proof exists.
        let params = fast_params();
        let pred = Predicate::RangeCheck {
            lo: 0,
            hi: 2_147_483_648u32, // 2^31
        };

        // Compile-level: InvalidParams, not a circuit.
        let compiled = pred.compile();
        assert!(
            matches!(compiled, Err(crate::MpcithError::InvalidParams(_))),
            "RangeCheck with width 2^31 must be rejected as InvalidParams"
        );

        // End-to-end: prove() must fail for the out-of-range value; no
        // valid proof can be produced, so there is nothing to verify.
        let witness = range_witness(3_000_000_000u32, 0, 2_147_483_648);
        let result = prove(pred, &witness, &[0, 2_147_483_648], &params);
        assert!(
            result.is_err(),
            "x = 3_000_000_000 must not be provable in [0, 2^31]"
        );
    }

    #[test]
    fn test_c2_max_supported_width_end_to_end() {
        // Largest supported width (2^31 - 1) still proves and verifies
        // end-to-end through the full MPCitH pipeline.
        let params = fast_params();
        let lo = 0u32;
        let hi = (1u32 << 31) - 1;
        let x = 1u32 << 30;
        let pred = Predicate::RangeCheck { lo, hi };
        let witness = range_witness(x, lo, hi);
        let proof = prove(pred, &witness, &[lo, hi], &params).unwrap();
        assert!(verify(&proof, &[lo, hi], &params).unwrap());
    }

    // ── C-3 regression: And binds both sub-predicates to the same value ───

    /// Members {10,20,30,42} with Merkle root; 42 sits at index 3.
    fn c3_setup() -> (crate::merkle::MerkleTree, Vec<u32>, Vec<u32>) {
        let members = vec![10u32, 20, 30, 42];
        let tree = crate::merkle::MerkleTree::build(&members);
        let root = tree.root();
        let public_inputs = vec![0u32, 100, root]; // [lo, hi, root]
        (tree, members, public_inputs)
    }

    #[test]
    fn test_c3_different_values_must_not_be_provable() {
        let params = fast_params();
        let (tree, members, public_inputs) = c3_setup();

        // Adversarial decoupled witness: RangeCheck proves 50 (∈ [0,100])
        // while SetMembership proves 42 (∈ set). Pre-fix this verified.
        let compound = CompoundPredicate::range_and_membership(0, 100, members.clone());
        let mut witness = range_witness(50, 0, 100);
        witness.extend(set_membership_witness(&tree.prove_membership(3)));

        // Circuit-level: the equality link must make evaluation fail...
        let compiled = compound.compile().unwrap();
        assert!(
            compiled.circuit.evaluate(&witness).is_err(),
            "decoupled witness (x=50 vs leaf=42) must violate the merged circuit"
        );

        // ...and end-to-end: no valid proof may exist.
        let result = prove_compound(compound, &witness, &public_inputs, &params);
        assert!(
            result.is_err(),
            "RangeCheck(50) AND SetMembership(42) must not be provable"
        );
    }

    #[test]
    fn test_c3_same_value_proves_and_verifies() {
        let params = fast_params();
        let (_tree, members, public_inputs) = c3_setup();

        let compound = CompoundPredicate::range_and_membership(0, 100, members.clone());
        let witness = compound.generate_witness(42).unwrap();
        let proof = prove_compound(compound, &witness, &public_inputs, &params).unwrap();

        // Verify through the predicate-bound path too (circuit-hash check).
        let compound_v = CompoundPredicate::range_and_membership(0, 100, members);
        assert!(verify_compound(&compound_v, &proof, &public_inputs, &params).unwrap());
    }

    #[test]
    fn test_c3_nested_and_binds_all_subpredicates() {
        let params = fast_params();
        let (tree, members, _pi) = c3_setup();
        let tree_root = tree.root();

        // Nested: RangeCheck[0,100] AND (SetMembership AND RangeCheck[40,44]).
        let compound = CompoundPredicate::And(
            Box::new(CompoundPredicate::Single(Predicate::RangeCheck {
                lo: 0,
                hi: 100,
            })),
            Box::new(CompoundPredicate::And(
                Box::new(CompoundPredicate::Single(Predicate::SetMembership {
                    members: members.clone(),
                })),
                Box::new(CompoundPredicate::Single(Predicate::RangeCheck {
                    lo: 40,
                    hi: 44,
                })),
            )),
        );
        // Public inputs concatenate in evaluation order: [0,100] ++ [root] ++ [40,44].
        let public_inputs = vec![0u32, 100, tree_root, 40, 44];

        // Honest witness: 42 satisfies all three sub-predicates → provable.
        let mut honest = range_witness(42, 0, 100);
        honest.extend(set_membership_witness(&tree.prove_membership(3)));
        honest.extend(range_witness(42, 40, 44));
        let proof = prove_compound(compound.clone(), &honest, &public_inputs, &params).unwrap();
        assert!(verify(&proof, &public_inputs, &params).unwrap());

        // Decoupled variants must all be unprovable:
        //   range=50 vs membership=42 vs tail-range=42
        let mut mixed1 = range_witness(50, 0, 100);
        mixed1.extend(set_membership_witness(&tree.prove_membership(3)));
        mixed1.extend(range_witness(42, 40, 44));
        assert!(prove_compound(compound.clone(), &mixed1, &public_inputs, &params).is_err());

        //   range=42, membership=10, tail-range=42 — every individual
        //   sub-predicate is TRUE for its own value, but the values differ.
        let mut mixed2 = range_witness(42, 0, 100);
        mixed2.extend(set_membership_witness(&tree.prove_membership(0))); // leaf 10
        mixed2.extend(range_witness(42, 40, 44));
        assert!(
            prove_compound(compound, &mixed2, &public_inputs, &params).is_err(),
            "nested And must reject witnesses whose sub-values differ"
        );
    }

    // ── F-1 regression: padded Merkle slots are not provable positions ────

    fn f1_members() -> Vec<u32> {
        vec![7u32, 8, 9] // pads to [7, 8, 9, 0]
    }

    #[test]
    fn test_f1_end_to_end_small_set_prove_verify() {
        let params = fast_params();
        let members = f1_members();
        let pred = Predicate::SetMembership { members: members.clone() };
        let tree = crate::merkle::MerkleTree::build(&members);
        let root = tree.root();
        for idx in 0..members.len() {
            let w = set_membership_witness(&tree.prove_membership(idx));
            let proof = prove(pred.clone(), &w, &[root], &params)
                .unwrap_or_else(|e| panic!("member {} must be provable: {e}", members[idx]));
            assert!(
                verify_predicate(&pred, &proof, &[root], &params).unwrap(),
                "member {} (index {idx}) must verify end-to-end",
                members[idx]
            );
        }
    }

    #[test]
    fn test_f1_end_to_end_padded_zero_prove_rejected() {
        let params = fast_params();
        let members = f1_members();
        let tree = crate::merkle::MerkleTree::build(&members);
        let root = tree.root();
        let pred = Predicate::SetMembership { members };

        // THE attack witness: the padded zero leaf at index 3.
        let mp = tree.prove_membership(3);
        assert_eq!(mp.leaf, 0, "padded slot of {{7,8,9}} must hold zero");
        let w = set_membership_witness(&mp);
        assert!(
            prove(pred, &w, &[root], &params).is_err(),
            "proving 0 ∈ {{7,8,9}} via the padded slot must fail"
        );
    }

    /// Manually forge a proof for the padded-index membership witness
    /// (leaf = 0 at index 3 of {7,8,9}), bypassing `prove()`'s witness
    /// validation exactly like a malicious prover would:
    ///
    /// 1. run the MPC emulation honestly on the *invalid* witness,
    /// 2. commit to every party's view,
    /// 3. BEFORE deriving challenges, rewrite one fixed party `j`'s public
    ///    assert/output share entries so the Σ-checks would pass IF j is
    ///    hidden,
    /// 4. derive challenges and open accordingly.
    ///
    /// Acceptance requires EVERY repetition to hide party j — probability
    /// 3^{-M} — so verification MUST reject.
    fn forge_padded_index_proof(params: &ProofParams) -> Proof {
        use rand::RngCore;

        let members = f1_members();
        let tree = crate::merkle::MerkleTree::build(&members);
        let root = tree.root();
        let pred = Predicate::SetMembership { members };
        let compiled = pred.compile().unwrap(); // includes the F-1 index bound
        let circuit_hash = hash_circuit(&compiled.circuit);
        let num_outputs = compiled.circuit.num_outputs;
        let num_wires = compiled.circuit.num_wires;
        let circuit = compiled.circuit;

        // Padded-slot witness: leaf 0 at index 3.
        let mp = tree.prove_membership(3);
        assert_eq!(mp.leaf, 0);
        let witness = set_membership_witness(&mp);

        let assert_constraints = circuit.assert_constraints();
        let output_start = num_wires - num_outputs;
        let num_parties = params.num_parties;
        let num_repetitions = params.num_repetitions;
        let mut rng = thread_rng();

        // ── Phase 1: honest emulation of the invalid witness + commitments ──
        let mut execs = Vec::with_capacity(num_repetitions);
        let mut root_seeds = Vec::with_capacity(num_repetitions);
        let mut output_shares: Vec<Vec<Vec<u32>>> = Vec::with_capacity(num_repetitions);
        let mut assert_shares: Vec<Vec<Vec<u32>>> = Vec::with_capacity(num_repetitions);
        for _ in 0..num_repetitions {
            let mut rs = [0u8; 32];
            rng.fill_bytes(&mut rs);
            root_seeds.push(rs);
            let st = SeedTree::build(rs, num_parties);
            let seeds: Vec<PartySeed> = st.leaf_seeds().into_iter().map(PartySeed).collect();
            let exec = run_mpc_emulation(&circuit, &witness, &seeds, &mut rng).unwrap();
            output_shares.push(
                (output_start..num_wires)
                    .map(|w| (0..num_parties).map(|p| exec.shared_trace.wires[w].shares[p]).collect())
                    .collect(),
            );
            assert_shares.push(
                assert_constraints
                    .iter()
                    .map(|&(w, _)| (0..num_parties).map(|p| exec.shared_trace.wires[w].shares[p]).collect())
                    .collect(),
            );
            execs.push(exec);
        }

        let mut trees = Vec::with_capacity(num_repetitions);
        let mut randomness = Vec::with_capacity(num_repetitions);
        for rep in 0..num_repetitions {
            let mut rep_rand = Vec::with_capacity(num_parties);
            let leaves: Vec<[u8; 32]> = (0..num_parties)
                .map(|p| {
                    let mut r = [0u8; 32];
                    rng.fill_bytes(&mut r);
                    rep_rand.push(r);
                    let view = &execs[rep].views[p];
                    commit_view(rep, p, &view.seed, &view.to_commitment_bytes(), &r).0
                })
                .collect();
            randomness.push(rep_rand);
            trees.push(CommitTree::build(&leaves));
        }

        // ── Malicious adjustment: fix party j's public entries pre-challenge ──
        let j = 0usize;
        for rep in 0..num_repetitions {
            for (g, &(_, expected)) in assert_constraints.iter().enumerate() {
                let others: u32 = (0..num_parties)
                    .filter(|&p| p != j)
                    .fold(0u32, |acc, p| acc.wrapping_add(assert_shares[rep][g][p]));
                assert_shares[rep][g][j] = expected.wrapping_sub(others);
            }
            for o in 0..num_outputs {
                let wire = output_start + o;
                let expected = circuit
                    .assert_expected_for_output(wire)
                    .expect("membership circuit output is AssertEq-covered");
                let others: u32 = (0..num_parties)
                    .filter(|&p| p != j)
                    .fold(0u32, |acc, p| acc.wrapping_add(output_shares[rep][o][p]));
                output_shares[rep][o][j] = expected.wrapping_sub(others);
            }
        }

        // ── Phase 2: Fiat-Shamir over roots + adjusted public shares ──
        let mut commit_bytes = Vec::with_capacity(num_repetitions * 32);
        for rep in 0..num_repetitions {
            commit_bytes.extend_from_slice(&trees[rep].root());
            commit_bytes.extend_from_slice(&encode_public_shares(
                &assert_shares[rep],
                &output_shares[rep],
            ));
        }
        let public_inputs = vec![root];
        let challenges = derive_challenges(
            &commit_bytes,
            &public_inputs,
            &circuit_hash,
            num_repetitions,
            num_parties,
        );

        // ── Phase 3: open all parties except the challenged hidden one ──
        let mut repetitions = Vec::with_capacity(num_repetitions);
        for (rep, &hidden) in challenges.iter().enumerate() {
            let mut opened_views = Vec::with_capacity(num_parties - 1);
            for p in 0..num_parties {
                if p == hidden {
                    continue;
                }
                let auth = trees[rep].prove_membership(p);
                opened_views.push(OpenedView {
                    view: execs[rep].views[p].clone(),
                    commitment_randomness: randomness[rep][p],
                    commitment_auth_path: auth.siblings,
                });
            }
            let co_path = SeedTree::build(root_seeds[rep], num_parties).co_path(hidden);
            repetitions.push(RepetitionProof {
                hidden_party: hidden,
                commitment_root: trees[rep].root(),
                co_path,
                opened_views,
                output_shares: output_shares[rep].clone(),
                assert_shares: assert_shares[rep].clone(),
            });
        }

        Proof {
            public_inputs,
            expected_outputs: vec![0], // inert: output wire is AssertEq-covered
            repetitions,
            params: params.clone(),
            circuit,
            circuit_hash,
            num_circuit_wires: num_wires,
            num_circuit_outputs: num_outputs,
        }
    }

    #[test]
    fn test_f1_manual_forged_padded_index_proof_rejected() {
        let members = f1_members();
        let root = crate::merkle::MerkleTree::build(&members).root();

        // Balanced params: per-proof acceptance probability 3^{-96} ≈ 4.6e-46.
        let balanced = ProofParams::balanced();
        let forged = forge_padded_index_proof(&balanced);
        let result = verify(&forged, &[root], &balanced);
        assert!(
            !matches!(result, Ok(true)),
            "manually forged padded-index proof must not verify (balanced params)"
        );

        // Fast params: per-attempt forgery probability 3^{-10} ≈ 1.7e-5;
        // a handful of attempts must all be rejected.
        let fast = fast_params();
        for attempt in 0..5 {
            let f = forge_padded_index_proof(&fast);
            assert!(
                !matches!(verify(&f, &[root], &fast), Ok(true)),
                "forged attempt {attempt} must not verify"
            );
        }
    }

    #[test]
    fn test_f1_tampered_index_share_rejected() {
        let params = fast_params();
        let members = f1_members();
        let pred = Predicate::SetMembership { members };
        let tree = crate::merkle::MerkleTree::build(&f1_members());
        let root = tree.root();

        // Honest proof for real member 8 (index 1).
        let w = set_membership_witness(&tree.prove_membership(1));
        let mut proof = prove(pred, &w, &[root], &params).unwrap();

        // leaf_index lives at input wire 1. Flip the residual party's share
        // of that wire wherever that party is opened: the tampered value no
        // longer matches the committed view, so verification must reject.
        let n = params.num_parties;
        let mut touched = false;
        for rep in proof.repetitions.iter_mut() {
            for ov in rep.opened_views.iter_mut() {
                if ov.view.party_idx == n - 1 && ov.view.residual_input_shares.len() > 1 {
                    ov.view.residual_input_shares[1] ^= 0xFF;
                    touched = true;
                }
            }
        }
        assert!(
            touched,
            "expected the residual party to be opened in at least one repetition"
        );
        let result = verify(&proof, &[root], &params);
        assert!(result.is_err(), "tampered leaf_index share must cause rejection");
    }
}
