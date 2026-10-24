//! Adversarial and serialization regression tests for the v2 public API.
//!
//! These tests use the fast, explicitly insecure repetition preset. They check
//! fail-closed API behavior, not the security level or the 2/3 proof.

use ark_bn254::Fr;
use mpcith_zk::v2::field::encode_fr;
use mpcith_zk::v2::merkle::MerkleTreeV2;
use mpcith_zk::v2::predicate::{MembershipStatementV2, RangeStatementV2, StatementV2};
use mpcith_zk::v2::proof::{
    hash_context_v2, prove_membership, prove_range, verify_bytes_statement, verify_statement,
    V2Proof,
};
use mpcith_zk::v2::suite::V2Params;
use mpcith_zk::v2::transaction::{
    create_transaction_proof_v2, verify_transaction_proof_v2, TransactionStatementV2,
    TransactionWitnessV2,
};
use mpcith_zk::{prove, Predicate, ProofParams};

fn params() -> V2Params {
    V2Params::fast_insecure()
}

fn context(label: &[u8]) -> [u8; 32] {
    hash_context_v2(label)
}

fn range_statement(lo: u32, hi: u32) -> StatementV2 {
    StatementV2::Range(RangeStatementV2::new(lo, hi).unwrap())
}

fn membership_statement(tree: &MerkleTreeV2) -> StatementV2 {
    StatementV2::Membership(
        MembershipStatementV2::new(tree.root(), tree.num_members(), tree.depth()).unwrap(),
    )
}

#[test]
fn statement_substitution_and_cross_type_reuse_are_rejected() {
    let ctx = context(b"adversarial-statement");
    let proof = prove_range(10, 50, 30, ctx, &params()).unwrap();
    let expected = range_statement(10, 50);
    verify_statement(&proof, &expected, ctx, &params()).unwrap();

    // A valid proof for statement A is not a proof for statement B.
    assert!(verify_statement(&proof, &range_statement(10, 49), ctx, &params()).is_err());

    // A range-only proof cannot be relabelled as a combined statement.
    let tree = MerkleTreeV2::build(&[10, 20, 30, 42]).unwrap();
    let combined = StatementV2::Combined {
        range: RangeStatementV2::new(10, 50).unwrap(),
        membership: MembershipStatementV2::new(tree.root(), tree.num_members(), tree.depth())
            .unwrap(),
    };
    assert!(verify_statement(&proof, &combined, ctx, &params()).is_err());

    // Conversely, a membership-only proof cannot be relabelled as combined.
    let member = tree.prove_membership(2).unwrap();
    let membership_proof = prove_membership(
        tree.root(),
        tree.num_members(),
        tree.depth(),
        30,
        &member,
        ctx,
        &params(),
    )
    .unwrap();
    assert!(verify_statement(&membership_proof, &combined, ctx, &params()).is_err());

    // The existing 2/3 forgery is circuit-specific. This test only checks that
    // a range proof cannot be relabelled as combined; it does not establish
    // combined soundness. The hidden-share gap is still a known protocol issue.
    let mut relabelled = proof;
    relabelled.statement = combined.clone();
    assert!(verify_statement(&relabelled, &combined, ctx, &params()).is_err());
}

#[test]
fn transaction_root_substitution_uses_the_ledger_statement() {
    let ledger_tree = MerkleTreeV2::build(&[10, 20, 30, 42]).unwrap();
    let attacker_tree = MerkleTreeV2::build(&[42]).unwrap();
    let ctx = context(b"adversarial-ledger");
    let ledger = TransactionStatementV2 {
        amount_range: (10, 50),
        authorized_set_root: ledger_tree.root(),
        merkle_depth: ledger_tree.depth(),
        num_members: ledger_tree.num_members(),
        context: ctx.to_vec(),
    };
    let attacker = TransactionStatementV2 {
        amount_range: (10, 50),
        authorized_set_root: attacker_tree.root(),
        merkle_depth: attacker_tree.depth(),
        num_members: attacker_tree.num_members(),
        context: ctx.to_vec(),
    };
    let witness = TransactionWitnessV2 {
        secret_value: 42,
        merkle_proof: attacker_tree.prove_membership(0).unwrap(),
    };

    let proof = create_transaction_proof_v2(&attacker, &witness, &params()).unwrap();
    assert!(verify_transaction_proof_v2(&proof, &ledger, &params()).is_err());
    verify_transaction_proof_v2(&proof, &attacker, &params()).unwrap();
}

#[test]
fn membership_path_count_depth_and_root_tampering_fail_closed() {
    let tree = MerkleTreeV2::build(&[10, 20, 30, 42]).unwrap();
    let member = tree.prove_membership(2).unwrap();
    let ctx = context(b"adversarial-membership");
    let expected = membership_statement(&tree);
    let proof = prove_membership(
        tree.root(),
        tree.num_members(),
        tree.depth(),
        30,
        &member,
        ctx,
        &params(),
    )
    .unwrap();
    verify_statement(&proof, &expected, ctx, &params()).unwrap();

    // Wrong root, count, depth, and range are statement mismatches.
    let wrong_root = StatementV2::Membership(
        MembershipStatementV2::new(
            tree.root() + Fr::from(1u64),
            tree.num_members(),
            tree.depth(),
        )
        .unwrap(),
    );
    assert!(verify_statement(&proof, &wrong_root, ctx, &params()).is_err());

    let wrong_count =
        StatementV2::Membership(MembershipStatementV2::new(tree.root(), 3, 2).unwrap());
    assert!(verify_statement(&proof, &wrong_count, ctx, &params()).is_err());

    // A non-canonical depth is rejected while constructing the statement.
    assert!(MembershipStatementV2::new(tree.root(), 4, 1).is_err());
    assert!(MembershipStatementV2::new(tree.root(), 5, 2).is_err());

    // The prover refuses a wrong private value against a valid path.
    assert!(prove_membership(
        tree.root(),
        tree.num_members(),
        tree.depth(),
        42,
        &member,
        ctx,
        &params()
    )
    .is_err());

    // Wrong index, sibling, root, count, or depth is rejected before proving.
    let mut wrong_index = member.clone();
    wrong_index.leaf_index = 0;
    assert!(prove_membership(
        tree.root(),
        tree.num_members(),
        tree.depth(),
        30,
        &wrong_index,
        ctx,
        &params()
    )
    .is_err());

    let mut wrong_sibling = member.clone();
    wrong_sibling.siblings[0] += Fr::from(1u64);
    assert!(prove_membership(
        tree.root(),
        tree.num_members(),
        tree.depth(),
        30,
        &wrong_sibling,
        ctx,
        &params()
    )
    .is_err());

    assert!(prove_membership(
        tree.root() + Fr::from(1u64),
        tree.num_members(),
        tree.depth(),
        30,
        &member,
        ctx,
        &params()
    )
    .is_err());

    assert!(prove_membership(tree.root(), 3, 2, 30, &member, ctx, &params()).is_err());

    assert!(prove_membership(tree.root(), 4, 1, 30, &member, ctx, &params()).is_err());
}

#[test]
fn context_binding_prevents_cross_context_replay() {
    let ctx_a = context(b"session-A");
    let ctx_b = context(b"session-B");
    let statement = range_statement(10, 50);
    let proof = prove_range(10, 50, 30, ctx_a, &params()).unwrap();
    verify_statement(&proof, &statement, ctx_a, &params()).unwrap();
    assert!(verify_statement(&proof, &statement, ctx_b, &params()).is_err());

    let bytes = proof.to_bytes().unwrap();
    verify_bytes_statement(&bytes, &statement, ctx_a, &params()).unwrap();
    assert!(verify_bytes_statement(&bytes, &statement, ctx_b, &params()).is_err());

    let mut tampered = proof;
    tampered.context[0] ^= 1;
    assert!(verify_statement(&tampered, &statement, ctx_a, &params()).is_err());

    // Context binding is not an outer transaction nonce. A real ledger still
    // needs its own replay control; this test only checks the bound context.
}

#[test]
fn serialization_rejects_magic_version_params_tag_and_trailing_bytes() {
    let ctx = context(b"adversarial-serialization");
    let statement = range_statement(10, 50);
    let proof = prove_range(10, 50, 30, ctx, &params()).unwrap();
    let bytes = proof.to_bytes().unwrap();
    verify_bytes_statement(&bytes, &statement, ctx, &params()).unwrap();

    let mut bad_magic = bytes.clone();
    bad_magic[0] ^= 1;
    assert!(V2Proof::from_bytes(&bad_magic).is_err());
    assert!(verify_bytes_statement(&bad_magic, &statement, ctx, &params()).is_err());

    let mut old_version = bytes.clone();
    old_version[8..10].copy_from_slice(&2u16.to_be_bytes());
    assert!(V2Proof::from_bytes(&old_version).is_err());

    let mut bad_params = bytes.clone();
    bad_params[10..14].copy_from_slice(&4u32.to_be_bytes());
    assert!(V2Proof::from_bytes(&bad_params).is_err());

    let mut unknown_tag = bytes.clone();
    unknown_tag[18] = 9;
    assert!(V2Proof::from_bytes(&unknown_tag).is_err());

    let mut truncated = bytes.clone();
    truncated.pop();
    assert!(V2Proof::from_bytes(&truncated).is_err());
    assert!(verify_bytes_statement(&truncated, &statement, ctx, &params()).is_err());

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(V2Proof::from_bytes(&trailing).is_err());

    // Replace one serialized Mul share with an all-ones 32-byte value, which is
    // above the BN254 modulus. The strict decoder must reject it.
    let target = encode_fr(&proof.repetitions[0].opened_views[0].mul_output_shares[0]);
    let offset = bytes
        .windows(32)
        .position(|window| window == target)
        .expect("serialized Mul share must be present");
    let mut noncanonical = bytes.clone();
    noncanonical[offset..offset + 32].copy_from_slice(&[0xff; 32]);
    assert!(V2Proof::from_bytes(&noncanonical).is_err());

    // Truncation at several structural boundaries must be an error, not a panic.
    for cut in [0, 1, 8, 9, 10, 17, 18, 19, bytes.len() - 1] {
        let prefix = &bytes[..cut];
        assert!(V2Proof::from_bytes(prefix).is_err(), "cut {cut} must fail");
    }
}

#[test]
fn oversized_length_fields_are_rejected_before_allocation() {
    let ctx = context(b"adversarial-lengths");
    let statement = range_statement(10, 50);
    let proof = prove_range(10, 50, 30, ctx, &params()).unwrap();
    let bytes = proof.to_bytes().unwrap();

    // Header layout: magic(8) || version(2) || N(4) || M(4).
    // Range statement: tag(1) || lo(4) || hi(4). Then context(32).
    let repetition_count_offset = 8 + 2 + 4 + 4 + 1 + 4 + 4 + 32;
    let mut huge_rep_count = bytes.clone();
    huge_rep_count[repetition_count_offset..repetition_count_offset + 4]
        .copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(V2Proof::from_bytes(&huge_rep_count).is_err());
    assert!(verify_bytes_statement(&huge_rep_count, &statement, ctx, &params()).is_err());

    // First repetition: hidden(4) || root(32) || co-path length(4).
    let co_path_len_offset = repetition_count_offset + 4 + 4 + 32;
    let mut huge_co_path = bytes.clone();
    huge_co_path[co_path_len_offset..co_path_len_offset + 4]
        .copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(V2Proof::from_bytes(&huge_co_path).is_err());

    // co-path is depth 2: two 32-byte nodes. Then opened-view count(4).
    let opened_count_offset = co_path_len_offset + 4 + 2 * 32;
    let mut too_many_views = bytes.clone();
    too_many_views[opened_count_offset..opened_count_offset + 4]
        .copy_from_slice(&3u32.to_be_bytes());
    assert!(V2Proof::from_bytes(&too_many_views).is_err());

    // party(4) || Mul-share count(4).
    let mul_len_offset = opened_count_offset + 4 + 4;
    let mut huge_mul_len = bytes.clone();
    huge_mul_len[mul_len_offset..mul_len_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(V2Proof::from_bytes(&huge_mul_len).is_err());

    // The first opened view is party 0. Its residual count is immediately
    // after the Mul shares; a non-zero value is structurally invalid.
    let mul_len = u32::from_be_bytes(
        bytes[mul_len_offset..mul_len_offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let residual_len_offset = mul_len_offset + 4 + mul_len * 32;
    let mut bad_residual = bytes.clone();
    bad_residual[residual_len_offset..residual_len_offset + 4].copy_from_slice(&1u32.to_be_bytes());
    assert!(V2Proof::from_bytes(&bad_residual).is_err());
}

#[test]
fn v1_and_v2_serialized_proofs_cannot_be_confused() {
    let v1 = prove(
        Predicate::AdditionCheck { expected_sum: 7 },
        &[3, 4],
        &[7],
        &ProofParams::fast_insecure(),
    )
    .unwrap();
    let v1_bytes = bincode::serialize(&v1).unwrap();
    assert!(V2Proof::from_bytes(&v1_bytes).is_err());

    let ctx = context(b"adversarial-v1-separation");
    let v2_bytes = prove_range(10, 50, 30, ctx, &params())
        .unwrap()
        .to_bytes()
        .unwrap();
    assert!(V2Proof::from_bytes(&v2_bytes).is_ok());
    assert!(
        bincode::deserialize::<mpcith_zk::Proof>(&v2_bytes).is_err(),
        "v2 canonical bytes must not decode as a v1 bincode proof"
    );
}

#[test]
fn transaction_statement_never_contains_a_u32_root() {
    // This is a compile-time/type-level check: the transaction root is Fr, not
    // u32. The expression must not need a `u32` root conversion.
    let tree = MerkleTreeV2::build(&[10, 20, 30, 42]).unwrap();
    let statement = TransactionStatementV2 {
        amount_range: (10, 50),
        authorized_set_root: tree.root(),
        merkle_depth: tree.depth(),
        num_members: tree.num_members(),
        context: b"adversarial-types".to_vec(),
    };
    let _root: Fr = statement.authorized_set_root;
    assert_eq!(
        statement
            .to_statement_v2()
            .unwrap()
            .membership()
            .map(|m| m.root),
        Some(tree.root())
    );
}
