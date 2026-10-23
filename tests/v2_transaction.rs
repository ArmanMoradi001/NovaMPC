//! Transaction-facing v2 API tests.
//!
//! These tests use the fast, explicitly insecure repetition preset. They test
//! the trust boundary and statement pinning, not the security level.

use mpcith_zk::v2::merkle::{MerkleProofV2, MerkleTreeV2};
use mpcith_zk::v2::predicate::{MembershipStatementV2, RangeStatementV2, StatementV2};
use mpcith_zk::v2::suite::V2Params;
use mpcith_zk::v2::transaction::{
    create_transaction_proof_v2, verify_transaction_proof_v2, TransactionStatementV2,
    TransactionWitnessV2,
};

fn params() -> V2Params {
    V2Params::fast_insecure()
}

fn tree(members: &[u32]) -> MerkleTreeV2 {
    MerkleTreeV2::build(members).unwrap()
}

fn member(tree: &MerkleTreeV2, index: u32) -> MerkleProofV2 {
    tree.prove_membership(index).unwrap()
}

fn statement(
    tree: &MerkleTreeV2,
    amount_range: (u32, u32),
    context: &[u8],
) -> TransactionStatementV2 {
    TransactionStatementV2 {
        amount_range,
        authorized_set_root: tree.root(),
        merkle_depth: tree.depth(),
        num_members: tree.num_members(),
        context: context.to_vec(),
    }
}

#[test]
fn honest_transaction_proof_round_trips() {
    let tree = tree(&[10, 20, 30, 42]);
    let expected = statement(&tree, (10, 50), b"channel-a/transaction-1");
    let witness = TransactionWitnessV2 {
        secret_value: 30,
        merkle_proof: member(&tree, 2),
    };

    let proof = create_transaction_proof_v2(&expected, &witness, &params()).unwrap();
    verify_transaction_proof_v2(&proof, &expected, &params()).unwrap();

    let expected_v2 = expected.to_statement_v2().unwrap();
    assert_eq!(
        expected_v2,
        StatementV2::Combined {
            range: RangeStatementV2::new(10, 50).unwrap(),
            membership: MembershipStatementV2::new(tree.root(), tree.num_members(), tree.depth())
                .unwrap(),
        }
    );
    assert_eq!(proof.context, expected.context_hash().unwrap());
}

#[test]
fn attacker_chosen_root_is_rejected_by_the_ledger_statement() {
    let ledger_tree = tree(&[10, 20, 30, 42]);
    let attacker_tree = tree(&[42]);
    let ledger_statement = statement(&ledger_tree, (10, 50), b"channel-a/transaction-2");
    let attacker_statement = statement(&attacker_tree, (10, 50), b"channel-a/transaction-2");
    let witness = TransactionWitnessV2 {
        secret_value: 42,
        merkle_proof: member(&attacker_tree, 0),
    };

    let attacker_proof =
        create_transaction_proof_v2(&attacker_statement, &witness, &params()).unwrap();

    // The proof is internally valid for the attacker's statement...
    verify_transaction_proof_v2(&attacker_proof, &attacker_statement, &params()).unwrap();

    // ...but the ledger statement pins the root, count, depth, and context.
    assert!(verify_transaction_proof_v2(&attacker_proof, &ledger_statement, &params()).is_err());
}

#[test]
fn wrong_range_context_count_or_depth_is_rejected() {
    let tree = tree(&[10, 20, 30, 42]);
    let expected = statement(&tree, (10, 50), b"channel-a/transaction-3");
    let witness = TransactionWitnessV2 {
        secret_value: 30,
        merkle_proof: member(&tree, 2),
    };
    let proof = create_transaction_proof_v2(&expected, &witness, &params()).unwrap();

    let wrong_range = statement(&tree, (10, 49), b"channel-a/transaction-3");
    assert!(verify_transaction_proof_v2(&proof, &wrong_range, &params()).is_err());

    let wrong_context = statement(&tree, (10, 50), b"channel-a/transaction-4");
    assert!(verify_transaction_proof_v2(&proof, &wrong_context, &params()).is_err());

    // Reusing the proof with a different count but a canonical depth for that
    // count must also fail the statement comparison.
    let wrong_count = TransactionStatementV2 {
        amount_range: (10, 50),
        authorized_set_root: tree.root(),
        merkle_depth: 2,
        num_members: 3,
        context: b"channel-a/transaction-3".to_vec(),
    };
    assert!(verify_transaction_proof_v2(&proof, &wrong_count, &params()).is_err());

    // A non-canonical depth is rejected before proof verification.
    let wrong_depth = TransactionStatementV2 {
        amount_range: (10, 50),
        authorized_set_root: tree.root(),
        merkle_depth: 1,
        num_members: 4,
        context: b"channel-a/transaction-3".to_vec(),
    };
    assert!(verify_transaction_proof_v2(&proof, &wrong_depth, &params()).is_err());
}

#[test]
fn empty_context_and_tampered_proof_context_fail_closed() {
    let tree = tree(&[10, 20, 30, 42]);
    let witness = TransactionWitnessV2 {
        secret_value: 30,
        merkle_proof: member(&tree, 2),
    };
    let empty_context = statement(&tree, (10, 50), b"");
    assert!(create_transaction_proof_v2(&empty_context, &witness, &params()).is_err());
    assert!(empty_context.context_hash().is_err());

    let expected = statement(&tree, (10, 50), b"channel-a/transaction-5");
    let proof = create_transaction_proof_v2(&expected, &witness, &params()).unwrap();
    let mut tampered = proof;
    tampered.context[0] ^= 1;
    assert!(verify_transaction_proof_v2(&tampered, &expected, &params()).is_err());
}

#[test]
fn transaction_statement_uses_fr_root_and_validates_bounds() {
    let tree = tree(&[42]);
    let expected = statement(&tree, (10, 50), b"channel-a/transaction-6");
    let v2 = expected.to_statement_v2().unwrap();
    assert_eq!(v2.membership().map(|m| m.root), Some(tree.root()));

    let invalid = statement(&tree, (50, 10), b"channel-a/transaction-6");
    assert!(invalid.to_statement_v2().is_err());
}
