//! Comprehensive integration tests for mpcith-zk Phase 2.
//!
//! These tests exercise the full prove/verify pipeline across all predicate
//! types and parameter sets, and produce a proof-size / timing table.

use mpcith_zk::merkle::MerkleTree;
use mpcith_zk::params::ProofParams;
use mpcith_zk::predicate::Predicate;
use mpcith_zk::proof::Proof;
use mpcith_zk::{prove, verify};
use std::time::Instant;

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Build the RangeCheck witness.  Layout: [x, x_bits(32), shifted_bits(k), slack_bits(k)]
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

/// Build the SetMembership witness from a MerkleProof.
/// Layout: [leaf, index, b0..b_{d-1}, sib0..sib_{d-1}]
fn membership_witness(proof: &mpcith_zk::merkle::MerkleProof) -> Vec<u32> {
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

// ─── tests ───────────────────────────────────────────────────────────────────

#[test]
fn test_range_and_membership_composition() {
    let params = ProofParams::fast_insecure();

    // ── RangeCheck: 1 ≤ 42 ≤ 100 ──────────────────────────────────────────
    let lo = 1u32;
    let hi = 100u32;
    let x = 42u32;
    let range_pred = Predicate::RangeCheck { lo, hi };
    let r_witness = range_witness(x, lo, hi);
    let range_proof =
        prove(range_pred, &r_witness, &[lo, hi], &params).expect("range prove should succeed");
    assert!(
        verify(&range_proof, &[lo, hi], &params).unwrap(),
        "range verify should pass"
    );

    // ── SetMembership: 42 ∈ {10,20,30,42,50,60,70,80} ─────────────────────
    let members: Vec<u32> = vec![10, 20, 30, 42, 50, 60, 70, 80];
    let tree = MerkleTree::build(&members);
    let root = tree.root();
    let leaf_idx = members.iter().position(|&v| v == x).unwrap();
    let merkle_proof = tree.prove_membership(leaf_idx);
    let m_witness = membership_witness(&merkle_proof);
    let mem_pred = Predicate::SetMembership { members };
    let mem_proof =
        prove(mem_pred, &m_witness, &[root], &params).expect("membership prove should succeed");
    assert!(
        verify(&mem_proof, &[root], &params).unwrap(),
        "membership verify should pass"
    );
}

#[test]
fn test_proof_sizes_table() {
    let fast = ProofParams::fast_insecure();
    let balanced = ProofParams::balanced();

    // Predicate descriptions and (predicate, witness_builder, public_inputs) tuples
    struct Case {
        name: &'static str,
        pred: Predicate,
        witness: Vec<u32>,
        public: Vec<u32>,
    }

    let addition = Case {
        name: "AdditionCheck",
        pred: Predicate::AdditionCheck { expected_sum: 7 },
        witness: vec![3, 4],
        public: vec![7],
    };

    let multiplication = Case {
        name: "MultiplicationCheck",
        pred: Predicate::MultiplicationCheck {
            expected_product: 12,
        },
        witness: vec![3, 4],
        public: vec![12],
    };

    let range_half = Case {
        name: "RangeCheck(0..MAX/2)",
        pred: Predicate::RangeCheck {
            lo: 0,
            hi: u32::MAX / 2,
        },
        witness: range_witness(u32::MAX / 4, 0, u32::MAX / 2),
        public: vec![0, u32::MAX / 2],
    };

    let members8: Vec<u32> = vec![10, 20, 30, 42, 50, 60, 70, 80];
    let tree8 = MerkleTree::build(&members8);
    let root8 = tree8.root();
    let mp8 = tree8.prove_membership(3);
    let membership = Case {
        name: "SetMembership(8)",
        pred: Predicate::SetMembership {
            members: members8.clone(),
        },
        witness: membership_witness(&mp8),
        public: vec![root8],
    };

    let cases: &[Case] = &[addition, multiplication, range_half, membership];

    println!();
    println!(
        "{:<24} {:<18} {:>12} {:>12} {:>12}",
        "Predicate", "Params", "proof_bytes", "prove_ms", "verify_ms"
    );
    println!("{}", "-".repeat(80));

    for case in cases {
        for (label, params) in &[("N=3 M=10", fast.clone()), ("N=16 M=38", balanced.clone())] {
            let t0 = Instant::now();
            let proof = prove(case.pred.clone(), &case.witness, &case.public, params).unwrap();
            let prove_ms = t0.elapsed().as_millis();

            let t1 = Instant::now();
            assert!(verify(&proof, &case.public, params).unwrap());
            let verify_ms = t1.elapsed().as_millis();

            let size = proof.serialized_size();
            println!(
                "{:<24} {:<18} {:>12} {:>12} {:>12}",
                case.name, label, size, prove_ms, verify_ms
            );
        }
    }
}

#[test]
fn test_membership_non_member_rejected() {
    let params = ProofParams::fast_insecure();
    let members: Vec<u32> = vec![10, 20, 30, 42];
    let tree = MerkleTree::build(&members);
    let root = tree.root();

    // Attempt to prove membership of 99, which is NOT in the set.
    // We can still build a "proof" for index 0 but with a wrong leaf value.
    let mut fake_proof = tree.prove_membership(0);
    fake_proof.leaf = 99;
    let witness = membership_witness(&fake_proof);
    let pred = Predicate::SetMembership { members };

    let result = prove(pred, &witness, &[root], &params);
    assert!(result.is_err(), "prove() should reject a non-member leaf");
}

#[test]
fn test_range_proof_large_range() {
    let params = ProofParams::balanced();
    let lo = 0u32;
    let hi = u32::MAX / 2;
    let x = u32::MAX / 4;

    let pred = Predicate::RangeCheck { lo, hi };
    let witness = range_witness(x, lo, hi);
    let proof = prove(pred, &witness, &[lo, hi], &params).unwrap();
    assert!(verify(&proof, &[lo, hi], &params).unwrap());
}

#[test]
fn test_soundness_parameter_sweep() {
    println!();
    println!("{:<6} {:<6} {:>12}", "N", "M", "sound_bits");
    println!("{}", "-".repeat(28));

    let party_counts = [3, 5, 16];
    let rep_counts = [10, 20, 38];

    for &n in &party_counts {
        for &m in &rep_counts {
            // soundness ≈ (1/N)^M  →  bits = M * log2(N)
            let bits = (m as f64) * ((n as f64).log2());
            assert!(bits > 0.0, "soundness bits must be positive");
            println!("{:<6} {:<6} {:>12.2}", n, m, bits);
        }
    }
}

// ─── tamper-resistance smoke tests ───────────────────────────────────────────

fn make_addition_proof() -> Proof {
    let params = ProofParams::fast_insecure();
    let pred = Predicate::AdditionCheck { expected_sum: 7 };
    prove(pred, &[3, 4], &[7], &params).unwrap()
}

#[test]
fn test_tampered_commitment_rejected() {
    // Previously tampered with `commitments[0]` directly; that field is gone.
    // The equivalent under the Merkle-commitment scheme is to corrupt the
    // `commitment_randomness` of an opened view: the verifier recomputes the
    // BLAKE3 commitment from (view + randomness), converts it to a Merkle leaf,
    // and verifies the auth path against `commitment_root`.  Wrong randomness
    // produces a different leaf, causing MerkleProof::verify() to return false.
    let mut proof = make_addition_proof();
    proof.repetitions[0].opened_views[0].commitment_randomness[0] ^= 0x01;
    let result = verify(&proof, &[7], &ProofParams::fast_insecure());
    assert!(
        result.is_err(),
        "tampered commitment randomness must cause Err"
    );
}

#[test]
fn test_tampered_commitment_root_rejected() {
    // Flip a bit in the Merkle root stored in the proof. The verifier uses
    // commitment_root for Fiat-Shamir re-derivation (so challenges change,
    // causing hidden_party mismatches) AND as the expected root in every
    // auth-path check for that repetition (so any path that was valid under
    // the original root now fails). Either path leads to Err.
    let mut proof = make_addition_proof();
    proof.repetitions[0].commitment_root ^= 0x01;
    let result = verify(&proof, &[7], &ProofParams::fast_insecure());
    assert!(result.is_err(), "tampered commitment_root must cause Err");
}

#[test]
fn test_tampered_auth_path_rejected() {
    // Flip a bit in the first sibling of the first opened view's auth path.
    // MerkleProof::verify() recomputes the root from leaf + siblings; a wrong
    // sibling produces a root that does not match commitment_root -> Err.
    let mut proof = make_addition_proof();
    proof.repetitions[0].opened_views[0].commitment_auth_path[0] ^= 0x01;
    let result = verify(&proof, &[7], &ProofParams::fast_insecure());
    assert!(result.is_err(), "tampered auth path must cause Err");
}

#[test]
fn test_tampered_opened_view_rejected() {
    let mut proof = make_addition_proof();
    // Flip the output wire share — this is checked during reconstruction.
    // AdditionCheck: num_wires=4, num_outputs=1, output_start=3.
    let output_wire = proof.num_circuit_wires - proof.num_circuit_outputs;
    proof.repetitions[0].opened_views[0].view.wire_shares[output_wire] ^= 0xFF;
    let result = verify(&proof, &[7], &ProofParams::fast_insecure());
    assert!(
        result.is_err(),
        "tampered output wire share must cause Err, not Ok(false)"
    );
}

#[test]
fn test_tampered_hidden_party_rejected() {
    let mut proof = make_addition_proof();
    let original = proof.repetitions[0].hidden_party;
    // Change to a different valid party index.
    let alternative = if original == 0 { 1 } else { 0 };
    proof.repetitions[0].hidden_party = alternative;
    let result = verify(&proof, &[7], &ProofParams::fast_insecure());
    assert!(
        result.is_err(),
        "tampered hidden_party must cause Err, not Ok(false)"
    );
}

#[test]
fn test_tampered_intermediate_wire_rejected() {
    let mut proof = make_addition_proof();
    // Flip a NON-output wire share (wire 0 = witness input x).
    // AdditionCheck: num_wires=4, num_outputs=1, output_start=3.
    // Wire 0 is an input wire — not an output, so this was previously undetected.
    proof.repetitions[0].opened_views[0].view.wire_shares[0] ^= 0xFF;
    let result = verify(&proof, &[7], &ProofParams::fast_insecure());
    assert!(
        result.is_err(),
        "tampered intermediate wire must now cause Err via verify_party_view"
    );
}

#[test]
fn test_hidden_party_view_not_leaked() {
    let proof = make_addition_proof();
    for (rep_idx, rep) in proof.repetitions.iter().enumerate() {
        for opened in &rep.opened_views {
            assert_ne!(
                opened.view.party_idx, rep.hidden_party,
                "repetition {rep_idx}: opened view contains hidden party {} — ZK leak",
                rep.hidden_party
            );
        }
        assert_eq!(
            rep.opened_views.len(),
            ProofParams::fast_insecure().num_parties - 1,
            "repetition {rep_idx}: expected N-1 opened views"
        );
    }
}

#[test]
fn test_tampered_co_path_rejected() {
    let mut proof = make_addition_proof();
    // Flip one byte in the last (highest-level) co-path node. This node
    // covers at least half the tree, so it always affects at least one
    // real party's reconstructed seed, causing commitment verification
    // to fail.
    let last = proof.repetitions[0].co_path.len() - 1;
    proof.repetitions[0].co_path[last][0] ^= 0x01;
    let result = verify(&proof, &[7], &ProofParams::fast_insecure());
    assert!(
        result.is_err(),
        "tampered co_path must cause Err — seed reconstruction produces wrong commitments"
    );
}

// Note: test_forged_membership_leaf_rejected is already covered by
// test_membership_non_member_rejected (line ~178) which sets leaf=99.

// ─── proof size blowup diagnostic ────────────────────────────────────────────

#[test]
fn test_proof_size_blowup_diagnostic() {
    let params = ProofParams::balanced();
    let n = params.num_parties;
    let m = params.num_repetitions;

    println!("\n=== Proof Size Blowup Diagnostic ===\n");

    // ── RangeCheck(0, MAX/2) ──────────────────────────────────────────────
    {
        let lo = 0u32;
        let hi = u32::MAX / 2;
        let x = u32::MAX / 4;
        let pred = Predicate::RangeCheck { lo, hi };
        let compiled = pred.compile().unwrap();
        let witness = range_witness(x, lo, hi);
        let circuit = &compiled.circuit;
        let mul_gates = circuit.num_mul_gates();
        let total_gates = circuit.gates.len();
        let num_wires = circuit.num_wires;

        let proof = prove(pred, &witness, &[lo, hi], &params).unwrap();
        let proof_bytes = proof.serialized_size();

        let sample_view = &proof.repetitions[0].opened_views[0].view;
        let mul_shares_ser = bincode::serialize(&sample_view.mul_output_shares).unwrap();

        println!("--- RangeCheck(0, MAX/2) ---");
        println!("  gates: {total_gates}  (mul: {mul_gates})  wires: {num_wires}");
        println!("  single PartyView:");
        println!(
            "    mul_output_shares: {} shares, {} bytes",
            sample_view.mul_output_shares.len(),
            mul_shares_ser.len()
        );

        let avg = proof_bytes as f64 / (m as f64 * n as f64);
        println!("  proof_bytes: {proof_bytes}");
        println!("  avg bytes/party/rep: {avg:.0}");
        println!();
    }

    // ── SetMembership(8) ──────────────────────────────────────────────────
    {
        let members: Vec<u32> = vec![10, 20, 30, 42, 50, 60, 70, 80];
        let tree = MerkleTree::build(&members);
        let root = tree.root();
        let pred = Predicate::SetMembership { members };
        let compiled = pred.compile().unwrap();
        let mp = tree.prove_membership(0);
        let witness = membership_witness(&mp);
        let circuit = &compiled.circuit;
        let mul_gates = circuit.num_mul_gates();
        let total_gates = circuit.gates.len();
        let num_wires = circuit.num_wires;

        let proof = prove(pred, &witness, &[root], &params).unwrap();
        let proof_bytes = proof.serialized_size();

        let sample_view = &proof.repetitions[0].opened_views[0].view;
        let mul_shares_ser = bincode::serialize(&sample_view.mul_output_shares).unwrap();

        println!("--- SetMembership(8) ---");
        println!("  gates: {total_gates}  (mul: {mul_gates})  wires: {num_wires}");
        println!("  single PartyView:");
        println!(
            "    mul_output_shares: {} shares, {} bytes",
            sample_view.mul_output_shares.len(),
            mul_shares_ser.len()
        );

        let avg = proof_bytes as f64 / (m as f64 * n as f64);
        println!("  proof_bytes: {proof_bytes}");
        println!("  avg bytes/party/rep: {avg:.0}");
        println!();
    }
}
