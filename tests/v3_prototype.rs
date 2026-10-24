//! Experimental V3 prototype tests: honest paths, negative paths, tampering.
//! No security claim. Uses only insecure test parameters.

use ark_bn254::Fr;
use mpcith_zk::v2::merkle::MerkleTreeV2;
use mpcith_zk::v3::params::V3Params;
use mpcith_zk::v3::proof::V3Proof;
use mpcith_zk::v3::prover::prove_combined_v3;
use mpcith_zk::v3::verifier::verify_combined_v3;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(0x7331_5033)
}

fn small_tree() -> MerkleTreeV2 {
    MerkleTreeV2::build(&[10u32, 20, 30, 40]).unwrap()
}

#[test]
fn honest_combined_proof_verifies_and_round_trips() {
    let tree = small_tree();
    let params = V3Params::fast_insecure_test();
    let proof_tx = tree.prove_membership(1).unwrap();
    let context = [7u8; 32];
    let proof = prove_combined_v3(
        10, 40, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx, context, &params,
        &mut rng(),
    )
    .unwrap();
    let statement = mpcith_zk::v2::predicate::StatementV2::Combined {
        range: mpcith_zk::v2::predicate::RangeStatementV2::new(10, 40).unwrap(),
        membership: mpcith_zk::v2::predicate::MembershipStatementV2::new(
            tree.root(),
            tree.num_members(),
            tree.depth(),
        )
        .unwrap(),
    };
    verify_combined_v3(&proof, &statement, context, &params).unwrap();
    let bytes = proof.to_bytes().unwrap();
    println!("v3 fast-params 4-member combined proof size: {} bytes", bytes.len());
    assert_eq!(V3Proof::from_bytes(&bytes).unwrap(), proof);
    verify_combined_v3(&V3Proof::from_bytes(&bytes).unwrap(), &statement, context, &params)
        .unwrap();
}

#[test]
fn deterministic_under_seeded_rng() {
    let tree = small_tree();
    let params = V3Params::fast_insecure_test();
    let proof_tx = tree.prove_membership(1).unwrap();
    let context = [7u8; 32];
    let mk = || {
        prove_combined_v3(
            10, 40, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx, context,
            &params, &mut rng(),
        )
        .unwrap()
        .to_bytes()
        .unwrap()
    };
    assert_eq!(mk(), mk());
}

#[test]
fn false_statements_cannot_prove() {
    let tree = small_tree();
    let params = V3Params::fast_insecure_test();
    let proof_tx = tree.prove_membership(1).unwrap();
    let context = [7u8; 32];
    // Out of range.
    assert!(prove_combined_v3(
        21, 40, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx, context, &params,
        &mut rng(),
    )
    .is_err());
    // Non-member value with a mismatched path.
    assert!(prove_combined_v3(
        10, 40, tree.root(), tree.num_members(), tree.depth(), 99, &proof_tx, context, &params,
        &mut rng(),
    )
    .is_err());
}

#[test]
fn wrong_expected_statement_context_or_params_reject() {
    let tree = small_tree();
    let params = V3Params::fast_insecure_test();
    let proof_tx = tree.prove_membership(1).unwrap();
    let context = [7u8; 32];
    let proof = prove_combined_v3(
        10, 40, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx, context, &params,
        &mut rng(),
    )
    .unwrap();
    let statement = mpcith_zk::v2::predicate::StatementV2::Combined {
        range: mpcith_zk::v2::predicate::RangeStatementV2::new(10, 40).unwrap(),
        membership: mpcith_zk::v2::predicate::MembershipStatementV2::new(
            tree.root(),
            tree.num_members(),
            tree.depth(),
        )
        .unwrap(),
    };
    // Wrong root.
    let bad_root_stmt = mpcith_zk::v2::predicate::StatementV2::Combined {
        range: mpcith_zk::v2::predicate::RangeStatementV2::new(10, 40).unwrap(),
        membership: mpcith_zk::v2::predicate::MembershipStatementV2::new(
            tree.root() + Fr::from(1u64),
            tree.num_members(),
            tree.depth(),
        )
        .unwrap(),
    };
    assert!(verify_combined_v3(&proof, &bad_root_stmt, context, &params).is_err());
    // Wrong context.
    assert!(verify_combined_v3(&proof, &statement, [8u8; 32], &params).is_err());
    // Wrong params.
    let mut bad_params = params;
    bad_params.pok_reps = 2;
    assert!(verify_combined_v3(&proof, &statement, context, &bad_params).is_err());
}

#[test]
fn tampered_proof_bytes_reject() {
    let tree = small_tree();
    let params = V3Params::fast_insecure_test();
    let proof_tx = tree.prove_membership(1).unwrap();
    let context = [7u8; 32];
    let proof = prove_combined_v3(
        10, 40, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx, context, &params,
        &mut rng(),
    )
    .unwrap();
    let statement = mpcith_zk::v2::predicate::StatementV2::Combined {
        range: mpcith_zk::v2::predicate::RangeStatementV2::new(10, 40).unwrap(),
        membership: mpcith_zk::v2::predicate::MembershipStatementV2::new(
            tree.root(),
            tree.num_members(),
            tree.depth(),
        )
        .unwrap(),
    };
    let bytes = proof.to_bytes().unwrap();
    // Flip each of a sample of byte positions: parse must fail or verify
    // must fail. (Full sweep is slow in debug; sample the header, a share,
    // and the tail.)
    let positions: Vec<usize> = [8, 40, 100, bytes.len() / 2, bytes.len() - 1]
        .into_iter()
        .filter(|p| *p < bytes.len())
        .collect();
    for p in positions {
        let mut bad = bytes.clone();
        bad[p] ^= 0x01;
        match V3Proof::from_bytes(&bad) {
            Err(_) => {}
            Ok(parsed) => {
                assert!(
                    verify_combined_v3(&parsed, &statement, context, &params).is_err(),
                    "tampered byte {p} accepted"
                );
            }
        }
    }
    // Tamper an opened share value structurally (parse ok, verify must fail).
    let mut parsed = V3Proof::from_bytes(&bytes).unwrap();
    parsed.reps[0].opened[0].shares[0] += Fr::from(1u64);
    assert!(verify_combined_v3(&parsed, &statement, context, &params).is_err());
    // Tamper a DECS response.
    let mut parsed = V3Proof::from_bytes(&bytes).unwrap();
    parsed.reps[0].decs_responses[0][0] += Fr::from(1u64);
    assert!(verify_combined_v3(&parsed, &statement, context, &params).is_err());
    // Tamper the commitment root.
    let mut parsed = V3Proof::from_bytes(&bytes).unwrap();
    parsed.reps[0].commitment_root[0] ^= 1;
    assert!(verify_combined_v3(&parsed, &statement, context, &params).is_err());
    // Tamper the broadcast hash.
    let mut parsed = V3Proof::from_bytes(&bytes).unwrap();
    parsed.reps[0].broadcast_hash[1] ^= 1;
    assert!(verify_combined_v3(&parsed, &statement, context, &params).is_err());
}
