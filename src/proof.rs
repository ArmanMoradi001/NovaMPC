//! Top-level proof generation and verification.

use crate::{
    commitment::{commit_view, CommitmentMatrix},
    fiat_shamir::{derive_challenges, hash_circuit},
    mpc::{run_mpc_emulation, MpcExecution, PartyView},
    params::ProofParams,
    predicate::Predicate,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepetitionProof {
    /// Index of the party whose view is HIDDEN.
    pub hidden_party: usize,
    /// All N commitments for this repetition.
    pub commitments: Vec<crate::commitment::Commitment>,
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
    let mut commit_matrix = CommitmentMatrix::new(num_repetitions, num_parties);

    for rep in 0..num_repetitions {
        let seeds: Vec<PartySeed> = (0..num_parties)
            .map(|_| PartySeed::random(&mut rng))
            .collect();

        let exec = run_mpc_emulation(circuit, witness, &seeds, &mut rng)?;

        let mut rep_randomness: Vec<[u8; 32]> = Vec::with_capacity(num_parties);
        for p in 0..num_parties {
            let mut rand = [0u8; 32];
            use rand::RngCore;
            rng.fill_bytes(&mut rand);

            let view = &exec.views[p];
            let commitment = commit_view(
                rep,
                p,
                &view.seed,
                &view.to_commitment_bytes(),
                &rand,
            );
            commit_matrix.set(rep, p, commitment);
            rep_randomness.push(rand);
        }

        all_executions.push(exec);
        all_commitment_randomness.push(rep_randomness);
    }

    // ── Phase 2: Challenge (Fiat-Shamir) ──────────────────────────────────
    let challenges = derive_challenges(
        &commit_matrix.to_bytes(),
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
            if p == hidden { continue; }
            opened_views.push(OpenedView {
                view: exec.views[p].clone(),
                commitment_randomness: all_commitment_randomness[rep][p],
            });
        }

        // Reveal only the hidden party's output wire shares.
        let output_start = circuit.num_wires - circuit.num_outputs;
        let hidden_output_shares: Vec<u32> = (output_start..circuit.num_wires)
            .map(|w| exec.shared_trace.wires[w].shares[hidden])
            .collect();

        repetition_proofs.push(RepetitionProof {
            hidden_party: hidden,
            commitments: commit_matrix.commitments[rep].clone(),
            opened_views,
            hidden_output_shares,
        });
    }

    Ok(Proof {
        public_inputs: public_inputs.to_vec(),
        expected_outputs,
        repetitions: repetition_proofs,
        params: params.clone(),
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

    let num_parties = params.num_parties;
    let num_outputs = proof.num_circuit_outputs;
    let output_start = proof.num_circuit_wires - num_outputs;

    // ── Step 1: Recompute Fiat-Shamir challenges ───────────────────────────
    let mut commit_bytes: Vec<u8> = Vec::new();
    for rep_proof in &proof.repetitions {
        for c in &rep_proof.commitments {
            commit_bytes.extend_from_slice(&c.0);
        }
    }

    let expected_challenges = derive_challenges(
        &commit_bytes,
        public_inputs,
        &proof.circuit_hash,
        params.num_repetitions,
        num_parties,
    );

    // ── Step 2: Per-repetition checks ─────────────────────────────────────
    for (rep, (rep_proof, &expected_hidden)) in
        proof.repetitions.iter().zip(expected_challenges.iter()).enumerate()
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

        // Verify commitments for all opened views.
        for opened in &rep_proof.opened_views {
            let p = opened.view.party_idx;
            let recomputed = commit_view(
                rep,
                p,
                &opened.view.seed,
                &opened.view.to_commitment_bytes(),
                &opened.commitment_randomness,
            );
            if recomputed != rep_proof.commitments[p] {
                return Err(MpcithError::CommitmentMismatch { party: p, repetition: rep });
            }
        }

        // Verify output share consistency.
        // All N parties' shares of each output wire must reconstruct to expected_outputs[i].
        for out_idx in 0..num_outputs {
            let wire_idx = output_start + out_idx;

            // Start with the hidden party's share.
            let mut share_sum = rep_proof.hidden_output_shares[out_idx];

            // Add each opened party's share of this output wire.
            for opened in &rep_proof.opened_views {
                let wire_shares = &opened.view.wire_shares;
                if wire_idx < wire_shares.len() {
                    share_sum = share_sum.wrapping_add(wire_shares[wire_idx]);
                } else {
                    return Err(MpcithError::VerificationFailed(format!(
                        "Repetition {rep}: party {} view has {} wires, need wire {}",
                        opened.view.party_idx,
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
        let pred = Predicate::MultiplicationCheck { expected_product: 12 };
        let proof = prove(pred, &[3, 4], &[12], &params).unwrap();
        assert!(verify(&proof, &[12], &params).unwrap());
    }

    #[test]
    fn test_prove_verify_xor() {
        let params = fast_params();
        let pred = Predicate::XorCheck { expected_xor: 0b1010 ^ 0b1100 };
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
        let pred = Predicate::SetMembership { members };
        let proof = prove(pred, &[42], &[0u32], &params).unwrap();
        assert!(verify(&proof, &[0u32], &params).unwrap());
    }
}
