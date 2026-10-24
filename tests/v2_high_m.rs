//! Expensive high-repetition proof checks.
//!
//! Run in release mode only:
//!
//! ```text
//! cargo test --release --test v2_high_m -- --ignored --nocapture
//! ```
//!
//! These tests use the recommended `q=1` and `q=2^32` presets. They are ignored
//! by default because a full proof is intentionally large and slow.

use std::time::Instant;

use mpcith_zk::v2::predicate::RangeStatementV2;
use mpcith_zk::v2::proof::{hash_context_v2, prove_range, verify_bytes_statement};
use mpcith_zk::v2::suite::V2Params;

fn run_case(label: &str, params: V2Params) {
    let context = hash_context_v2(label.as_bytes());
    let statement = RangeStatementV2::new(10, 1000).unwrap();

    let prove_start = Instant::now();
    let proof = prove_range(10, 1000, 42, context, &params).unwrap();
    let prove_elapsed = prove_start.elapsed();

    let bytes = proof.to_bytes().unwrap();
    let verify_start = Instant::now();
    verify_bytes_statement(
        &bytes,
        &mpcith_zk::v2::predicate::StatementV2::Range(statement),
        context,
        &params,
    )
    .unwrap();
    let verify_elapsed = verify_start.elapsed();

    println!(
        "{label}: M={} proof_bytes={} prove_ms={} verify_ms={}",
        params.num_repetitions,
        bytes.len(),
        prove_elapsed.as_millis(),
        verify_elapsed.as_millis()
    );
    assert_eq!(proof.params.num_repetitions, params.num_repetitions);
    assert_eq!(proof.serialized_size().unwrap(), bytes.len());
}

#[test]
#[ignore = "expensive high-M proof; run with --release --ignored --nocapture"]
fn secure_127_q1_range_proof_round_trips() {
    run_case("secure_127", V2Params::secure_127());
}

#[test]
#[ignore = "expensive high-M proof; run with --release --ignored --nocapture"]
fn secure_127_q32_range_proof_round_trips() {
    run_case(
        "secure_127_grinding_2_32",
        V2Params::secure_127_grinding_2_32(),
    );
}
