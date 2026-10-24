//! Reproducible v2 membership/combined proof measurements.
//!
//! Run with:
//!
//! ```text
//! cargo bench --bench v2_bench
//! ```
//!
//! Optional environment variables:
//! - `V2_BENCH_ITERS` (default 3): timed prove/verify iterations per row.
//! - `V2_BENCH_SIZES` (default `4,8,16,32`): comma-separated set sizes.
//! - `V2_BENCH_M` (default `96,219`): comma-separated repetition counts.
//! - `V2_BENCH_MODE` (default `both`): `membership`, `combined`, or `both`.
//!
//! This is a manual harness rather than Criterion because the M=219 cases are
//! intentionally expensive and the report needs exact serialized-byte counts
//! alongside medians. It measures the actual public API, including canonical
//! proof serialization.

#![allow(deprecated)] // the v1 reference row is intentionally legacy.

use std::time::{Duration, Instant};

use ark_bn254::Fr;
use mpcith_zk::merkle::MerkleTree;
use mpcith_zk::tx_validation::{
    create_transaction_proof, verify_transaction_proof, TransactionStatement, TransactionWitness,
};
use mpcith_zk::v2::circuit::GateV2;
use mpcith_zk::v2::merkle::MerkleTreeV2;
use mpcith_zk::v2::predicate::{
    compile_from_statement, CompiledV2, MembershipStatementV2, RangeStatementV2, StatementV2,
};
use mpcith_zk::v2::proof::{
    hash_context_v2, prove_combined, prove_membership, verify_statement, V2Proof,
};
use mpcith_zk::v2::suite::V2Params;
use mpcith_zk::{MpcithError, ProofParams, Result};

const RANGE_LO: u32 = 1;
const RANGE_HI: u32 = 1_000;
const DEFAULT_ITERS: usize = 3;
const DEFAULT_SIZES: &[u32] = &[4, 8, 16, 32];
const DEFAULT_M: &[u32] = &[96, 219];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Membership,
    Combined,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Membership => "membership",
            Mode::Combined => "combined",
        }
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_u32_list(name: &str, default: &[u32]) -> Vec<u32> {
    match std::env::var(name) {
        Ok(value) => value
            .split(',')
            .filter_map(|part| {
                let part = part.trim();
                if part.is_empty() {
                    None
                } else {
                    part.parse::<u32>().ok()
                }
            })
            .filter(|value| *value > 0)
            .collect(),
        Err(_) => default.to_vec(),
    }
}

fn env_modes() -> Vec<Mode> {
    match std::env::var("V2_BENCH_MODE").as_deref() {
        Ok("membership") => vec![Mode::Membership],
        Ok("combined") => vec![Mode::Combined],
        _ => vec![Mode::Membership, Mode::Combined],
    }
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

fn count_gates(compiled: &CompiledV2) -> (usize, usize) {
    let gates = compiled.circuit().gates();
    let mul = gates
        .iter()
        .filter(|gate| matches!(gate, GateV2::Mul { .. }))
        .count();
    (gates.len(), mul)
}

fn build_case(size: u32) -> Result<(u32, u32, u32, Fr, u32, mpcith_zk::v2::merkle::MerkleProofV2)> {
    let members: Vec<u32> = (0..size).map(|i| 100 + i * 10).collect();
    let tree = MerkleTreeV2::build(&members)
        .map_err(|err| MpcithError::InvalidWitness(format!("v2 benchmark tree failed: {err}")))?;
    let index = size / 2;
    let value = members[index as usize];
    let member_proof = tree.prove_membership(index).map_err(|err| {
        MpcithError::InvalidWitness(format!("v2 benchmark membership path failed: {err}"))
    })?;
    Ok((
        tree.num_members(),
        tree.depth(),
        value,
        tree.root(),
        index,
        member_proof,
    ))
}

fn statement_for(mode: Mode, root: Fr, num_members: u32, depth: u32) -> Result<StatementV2> {
    let membership = MembershipStatementV2::new(root, num_members, depth)?;
    match mode {
        Mode::Membership => Ok(StatementV2::Membership(membership)),
        Mode::Combined => Ok(StatementV2::Combined {
            range: RangeStatementV2::new(RANGE_LO, RANGE_HI)?,
            membership,
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn prove_for(
    mode: Mode,
    root: Fr,
    num_members: u32,
    depth: u32,
    value: u32,
    member_proof: &mpcith_zk::v2::merkle::MerkleProofV2,
    context: [u8; 32],
    params: &V2Params,
) -> Result<V2Proof> {
    match mode {
        Mode::Membership => prove_membership(
            root,
            num_members,
            depth,
            value,
            member_proof,
            context,
            params,
        ),
        Mode::Combined => prove_combined(
            RANGE_LO,
            RANGE_HI,
            root,
            num_members,
            depth,
            value,
            member_proof,
            context,
            params,
        ),
    }
}

fn run_case(mode: Mode, params: &V2Params, size: u32, iters: usize) -> Result<()> {
    let (num_members, depth, value, root, index, member_proof) = build_case(size)?;
    let statement = statement_for(mode, root, num_members, depth)?;
    let context = hash_context_v2(b"v2-bench");
    let compiled = compile_from_statement(&statement)?;
    let (gate_count, mul_count) = count_gates(&compiled);

    let mut prove_times = Vec::with_capacity(iters);
    let mut verify_times = Vec::with_capacity(iters);
    let mut proof_sizes = Vec::with_capacity(iters);

    for _ in 0..iters {
        let start = Instant::now();
        let proof = prove_for(
            mode,
            root,
            num_members,
            depth,
            value,
            &member_proof,
            context,
            params,
        )?;
        prove_times.push(start.elapsed());

        let bytes = proof.to_bytes()?;
        assert_eq!(V2Proof::from_bytes(&bytes)?, proof);
        proof_sizes.push(bytes.len());

        let start = Instant::now();
        verify_statement(&proof, &statement, context, params)?;
        verify_times.push(start.elapsed());
    }

    let prove = median(prove_times);
    let verify = median(verify_times);
    let min_bytes = *proof_sizes.iter().min().unwrap();
    let max_bytes = *proof_sizes.iter().max().unwrap();
    let mean_bytes = proof_sizes.iter().sum::<usize>() as f64 / proof_sizes.len() as f64;
    println!(
        "{:<10} | {:>7} | {:>5} | {:>4} | {:>8} | {:>8} | {:>10.3} | {:>10.3} | {:>12} | {:>12} | {:>10.1} | {:>8.3}",
        mode.label(),
        size,
        depth,
        params.num_repetitions,
        gate_count,
        mul_count,
        prove.as_secs_f64() * 1000.0,
        verify.as_secs_f64() * 1000.0,
        min_bytes,
        max_bytes,
        mean_bytes / 1024.0,
        max_bytes as f64 / (1024.0 * 1024.0),
    );
    println!(
        "           |         |       |      |          |          |            |            | index={index}; witness_inputs={}",
        compiled.witness_size()
    );
    Ok(())
}

fn run_v1_reference(iters: usize) -> Result<()> {
    let members = vec![100u32, 110, 120, 130];
    let tree = MerkleTree::build(&members).map_err(|err| {
        mpcith_zk::MpcithError::InvalidWitness(format!("v1 benchmark tree failed: {err}"))
    })?;
    let statement = TransactionStatement {
        amount_range: (RANGE_LO, RANGE_HI),
        authorized_set_root: tree.root(),
        merkle_depth: members.len().next_power_of_two().trailing_zeros() as usize,
        num_members: members.len(),
        context: b"v2-benchmark-v1-reference".to_vec(),
    };
    let witness = TransactionWitness {
        secret_value: members[2],
        merkle_proof: tree.prove_membership(2),
    };
    let params = ProofParams::balanced();

    let mut prove_times = Vec::with_capacity(iters);
    let mut verify_times = Vec::with_capacity(iters);
    let mut proof_sizes = Vec::with_capacity(iters);

    for _ in 0..iters {
        let start = Instant::now();
        let proof = create_transaction_proof(&statement, &witness, &params)?;
        prove_times.push(start.elapsed());
        proof_sizes.push(proof.serialized_size());

        let start = Instant::now();
        let valid = verify_transaction_proof(&proof, &statement, &params)?;
        verify_times.push(start.elapsed());
        assert!(valid, "v1 reference proof must verify");
    }

    let prove = median(prove_times);
    let verify = median(verify_times);
    let min_bytes = *proof_sizes.iter().min().unwrap();
    let max_bytes = *proof_sizes.iter().max().unwrap();
    let mean_bytes = proof_sizes.iter().sum::<usize>() as f64 / proof_sizes.len() as f64;
    println!(
        "{:<10} | {:>7} | {:>5} | {:>4} | {:>8} | {:>8} | {:>10.3} | {:>10.3} | {:>12} | {:>12} | {:>10.1} | {:>8.3}",
        "v1-ref",
        4,
        2,
        params.num_repetitions,
        "-",
        "-",
        prove.as_secs_f64() * 1000.0,
        verify.as_secs_f64() * 1000.0,
        min_bytes,
        max_bytes,
        mean_bytes / 1024.0,
        max_bytes as f64 / (1024.0 * 1024.0),
    );
    println!(
        "           |         |       |      |          |          |            |            | 32-bit MiMC root; v1 range+membership+context",
    );
    Ok(())
}

fn main() -> Result<()> {
    let iters = env_usize("V2_BENCH_ITERS", DEFAULT_ITERS);
    let sizes = env_u32_list("V2_BENCH_SIZES", DEFAULT_SIZES);
    let m_values = env_u32_list("V2_BENCH_M", DEFAULT_M);
    let modes = env_modes();

    println!(
        "v2 benchmark: iters={iters}, sizes={sizes:?}, M={m_values:?}, modes={:?}",
        modes.iter().map(|mode| mode.label()).collect::<Vec<_>>()
    );
    println!();
    println!(
        "{:<10} | {:>7} | {:>5} | {:>4} | {:>8} | {:>8} | {:>10} | {:>10} | {:>12} | {:>12} | {:>10} | {:>8}",
        "mode", "members", "depth", "M", "gates", "mul", "prove_ms", "verify_ms",
        "bytes_min", "bytes_max", "mean_KiB", "max_MiB"
    );
    println!("{}", "-".repeat(145));

    for mode in modes {
        for &m in &m_values {
            let params = V2Params::new(3, m);
            params.validate()?;
            for &size in &sizes {
                run_case(mode, &params, size, iters)?;
            }
        }
    }

    if !sizes.is_empty() {
        run_v1_reference(iters.max(1))?;
    }
    Ok(())
}
