//! End-to-end v2 tests through the public API.
//!
//! These tests deliberately use the fast, explicitly insecure repetition
//! preset. They exercise format and API behavior, not security.

use ark_bn254::Fr;
use mpcith_zk::v2::merkle::MerkleTreeV2;
use mpcith_zk::v2::predicate::{MembershipStatementV2, RangeStatementV2, StatementV2};
use mpcith_zk::v2::proof::{
    hash_context_v2, prove_combined, prove_membership, prove_range, verify_bytes_statement,
    verify_statement, V2Proof,
};
use mpcith_zk::v2::suite::V2Params;
use mpcith_zk::{prove, Predicate, ProofParams};

fn params() -> V2Params {
    V2Params::fast_insecure()
}

fn context() -> [u8; 32] {
    hash_context_v2(b"v2-integration")
}

fn fixture() -> (MerkleTreeV2, mpcith_zk::v2::merkle::MerkleProofV2) {
    let tree = MerkleTreeV2::build(&[10, 20, 30, 42]).unwrap();
    let member = tree.prove_membership(2).unwrap();
    (tree, member)
}

fn membership_statement(tree: &MerkleTreeV2) -> StatementV2 {
    StatementV2::Membership(
        MembershipStatementV2::new(tree.root(), tree.num_members(), tree.depth()).unwrap(),
    )
}

#[test]
fn range_only_proof_round_trips_through_the_public_api() {
    let params = params();
    let statement = StatementV2::Range(RangeStatementV2::new(10, 50).unwrap());

    let proof = prove_range(10, 50, 30, context(), &params).unwrap();
    verify_statement(&proof, &statement, context(), &params).unwrap();

    let bytes = proof.to_bytes().unwrap();
    let decoded = V2Proof::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, proof);
    verify_bytes_statement(&bytes, &statement, context(), &params).unwrap();

    assert!(prove_range(10, 50, 51, context(), &params).is_err());
    assert!(verify_statement(
        &proof,
        &StatementV2::Range(RangeStatementV2::new(10, 49).unwrap()),
        context(),
        &params
    )
    .is_err());
    assert!(verify_statement(
        &proof,
        &statement,
        hash_context_v2(b"different-context"),
        &params
    )
    .is_err());
}

#[test]
fn membership_only_proof_round_trips_through_the_public_api() {
    let params = params();
    let (tree, member) = fixture();
    let statement = membership_statement(&tree);

    let proof = prove_membership(
        tree.root(),
        tree.num_members(),
        tree.depth(),
        30,
        &member,
        context(),
        &params,
    )
    .unwrap();
    verify_statement(&proof, &statement, context(), &params).unwrap();

    let bytes = proof.to_bytes().unwrap();
    verify_bytes_statement(&bytes, &statement, context(), &params).unwrap();

    // The membership path is for 30, not for another member.
    assert!(prove_membership(
        tree.root(),
        tree.num_members(),
        tree.depth(),
        42,
        &member,
        context(),
        &params
    )
    .is_err());
}

#[test]
fn combined_proof_uses_one_value_for_both_relations() {
    let params = params();
    let (tree, member) = fixture();

    let proof = prove_combined(
        10,
        50,
        tree.root(),
        tree.num_members(),
        tree.depth(),
        30,
        &member,
        context(),
        &params,
    )
    .unwrap();
    let expected = StatementV2::Combined {
        range: RangeStatementV2::new(10, 50).unwrap(),
        membership: MembershipStatementV2::new(tree.root(), tree.num_members(), tree.depth())
            .unwrap(),
    };
    verify_statement(&proof, &expected, context(), &params).unwrap();

    // A range-only or membership-only statement is not the combined statement.
    assert!(verify_statement(
        &proof,
        &StatementV2::Range(RangeStatementV2::new(10, 50).unwrap()),
        context(),
        &params
    )
    .is_err());

    // The supplied authentication path is for 30. Reusing it with a different
    // private value must be rejected before proving.
    assert!(prove_combined(
        10,
        50,
        tree.root(),
        tree.num_members(),
        tree.depth(),
        42,
        &member,
        context(),
        &params
    )
    .is_err());
}

#[test]
fn statement_and_proof_tampering_is_rejected_end_to_end() {
    let params = params();
    let (tree, member) = fixture();
    let proof = prove_combined(
        10,
        50,
        tree.root(),
        tree.num_members(),
        tree.depth(),
        30,
        &member,
        context(),
        &params,
    )
    .unwrap();
    let expected = StatementV2::Combined {
        range: RangeStatementV2::new(10, 50).unwrap(),
        membership: MembershipStatementV2::new(tree.root(), tree.num_members(), tree.depth())
            .unwrap(),
    };
    verify_statement(&proof, &expected, context(), &params).unwrap();

    let mut tampered = proof.clone();
    tampered.statement = StatementV2::Combined {
        range: RangeStatementV2::new(10, 49).unwrap(),
        membership: MembershipStatementV2::new(tree.root(), tree.num_members(), tree.depth())
            .unwrap(),
    };
    assert!(verify_statement(&tampered, &expected, context(), &params).is_err());

    let mut tampered = proof.clone();
    if let StatementV2::Combined { membership, .. } = &mut tampered.statement {
        membership.root += Fr::from(1u64);
    }
    assert!(verify_statement(&tampered, &expected, context(), &params).is_err());

    let mut tampered = proof.clone();
    if let StatementV2::Combined { membership, .. } = &mut tampered.statement {
        membership.num_members = 3;
        membership.depth = 2;
    }
    assert!(verify_statement(&tampered, &expected, context(), &params).is_err());

    let mut tampered = proof.clone();
    tampered.repetitions[0].commitment_root[0] ^= 1;
    assert!(verify_statement(&tampered, &expected, context(), &params).is_err());

    let mut tampered = proof.clone();
    tampered.repetitions[0].hidden_party = (tampered.repetitions[0].hidden_party + 1) % 3;
    assert!(verify_statement(&tampered, &expected, context(), &params).is_err());

    let mut tampered = proof.clone();
    tampered.repetitions[0].assert_shares[0][0] += Fr::from(1u64);
    assert!(verify_statement(&tampered, &expected, context(), &params).is_err());

    let mut tampered = proof.clone();
    tampered.repetitions[0].opened_views[0].mul_output_shares[0] += Fr::from(1u64);
    assert!(verify_statement(&tampered, &expected, context(), &params).is_err());

    let mut tampered = proof.clone();
    tampered.repetitions[0].opened_views[0].commitment_randomness[0] ^= 1;
    assert!(verify_statement(&tampered, &expected, context(), &params).is_err());

    let mut tampered = proof;
    tampered.context = hash_context_v2(b"different-context");
    assert!(verify_statement(&tampered, &expected, context(), &params).is_err());
}

#[test]
fn malformed_serialized_proofs_are_rejected_without_panicking() {
    let params = params();
    let statement = StatementV2::Range(RangeStatementV2::new(10, 50).unwrap());
    let proof = prove_range(10, 50, 30, context(), &params).unwrap();
    let bytes = proof.to_bytes().unwrap();

    assert!(V2Proof::from_bytes(&[]).is_err());
    assert!(verify_bytes_statement(&[], &statement, context(), &params).is_err());

    let mut bad = bytes.clone();
    bad[0] ^= 1;
    assert!(V2Proof::from_bytes(&bad).is_err());
    assert!(verify_bytes_statement(&bad, &statement, context(), &params).is_err());

    let mut bad = bytes.clone();
    bad[8] ^= 1; // high byte of the version field
    assert!(V2Proof::from_bytes(&bad).is_err());

    let mut bad = bytes.clone();
    bad.pop();
    assert!(V2Proof::from_bytes(&bad).is_err());

    let mut bad = bytes;
    bad.push(0);
    assert!(V2Proof::from_bytes(&bad).is_err());
}

#[test]
fn v1_proof_bytes_are_not_accepted_as_v2() {
    let v1 = prove(
        Predicate::AdditionCheck { expected_sum: 7 },
        &[3, 4],
        &[7],
        &ProofParams::fast_insecure(),
    )
    .unwrap();
    let v1_bytes = bincode::serialize(&v1).unwrap();
    assert!(V2Proof::from_bytes(&v1_bytes).is_err());
}
