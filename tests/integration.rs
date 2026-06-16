//! Comprehensive integration tests for mpcith-zk Phase 2.
//!
//! These tests exercise the full prove/verify pipeline across all predicate
//! types and parameter sets, and produce a proof-size / timing table.

use mpcith_zk::merkle::MerkleTree;
use mpcith_zk::params::ProofParams;
use mpcith_zk::predicate::Predicate;
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
    let range_proof = prove(range_pred, &r_witness, &[lo, hi], &params)
        .expect("range prove should succeed");
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
    let mem_proof = prove(mem_pred, &m_witness, &[root], &params)
        .expect("membership prove should succeed");
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
        for (label, params) in &[
            ("N=3 M=10", fast.clone()),
            ("N=16 M=38", balanced.clone()),
        ] {
            let t0 = Instant::now();
            let proof = prove(
                case.pred.clone(),
                &case.witness,
                &case.public,
                params,
            )
            .unwrap();
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
    assert!(
        result.is_err(),
        "prove() should reject a non-member leaf"
    );
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
    println!(
        "{:<6} {:<6} {:>12}",
        "N", "M", "sound_bits"
    );
    println!("{}", "-".repeat(28));

    let party_counts = [3, 5, 16];
    let rep_counts = [10, 20, 38];

    for &n in &party_counts {
        for &m in &rep_counts {
            // soundness ≈ (N/(N-1))^M  →  bits = M * log2(N/(N-1))
            let ratio = (n as f64) / ((n - 1) as f64);
            let bits = (m as f64) * ratio.log2();
            assert!(bits > 0.0, "soundness bits must be positive");
            println!("{:<6} {:<6} {:>12.2}", n, m, bits);
        }
    }
}
