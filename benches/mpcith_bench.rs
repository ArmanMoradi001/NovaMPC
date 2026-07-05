//! Criterion benchmarks for mpcith-zk.
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mpcith_zk::merkle::MerkleTree;
use mpcith_zk::{
    prove, prove_compound, verify, CompoundPredicate, Predicate, ProofParams,
};

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("prove");

    for (label, params) in [
        ("fast_n3_m10", ProofParams::fast_insecure()),
        ("low_n3_m64", ProofParams::low_n()),
        ("balanced_n16_m38", ProofParams::balanced()),
    ] {
        group.bench_with_input(
            BenchmarkId::new("addition", label),
            &params,
            |b, params| {
                b.iter(|| {
                    prove(
                        black_box(Predicate::AdditionCheck { expected_sum: 7 }),
                        black_box(&[3u32, 4u32]),
                        black_box(&[7u32]),
                        params,
                    )
                    .unwrap()
                });
            },
        );
    }

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");

    for (label, params) in [
        ("fast_n3_m10", ProofParams::fast_insecure()),
        ("balanced_n16_m38", ProofParams::balanced()),
    ] {
        let proof = prove(
            Predicate::AdditionCheck { expected_sum: 7 },
            &[3u32, 4u32],
            &[7u32],
            &params,
        )
        .unwrap();

        group.bench_with_input(
            BenchmarkId::new("addition", label),
            &(proof, params.clone()),
            |b, (proof, params)| {
                b.iter(|| verify(black_box(proof), black_box(&[7u32]), params).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_set_membership(c: &mut Criterion) {
    let mut group = c.benchmark_group("set_membership");
    let params = ProofParams::fast_insecure();

    for set_size in [4usize, 8, 16, 32] {
        let members: Vec<u32> = (0..set_size as u32).map(|i| i * 10 + 1).collect();
        let tree = MerkleTree::build(&members);
        let leaf_idx = set_size / 2;
        let proof_merkle = tree.prove_membership(leaf_idx);

        let depth = members.len().next_power_of_two().trailing_zeros() as usize;
        let mut witness = Vec::with_capacity(2 + 2 * depth);
        witness.push(proof_merkle.leaf);
        witness.push(proof_merkle.leaf_index as u32);
        for i in 0..depth {
            witness.push(((proof_merkle.leaf_index >> i) & 1) as u32);
        }
        witness.extend(&proof_merkle.siblings);

        group.bench_with_input(
            BenchmarkId::new("prove", set_size),
            &(members.clone(), witness, tree.root()),
            |b, (members, witness, root)| {
                b.iter(|| {
                    prove(
                        black_box(Predicate::SetMembership {
                            members: members.clone(),
                        }),
                        black_box(witness),
                        black_box(&[*root]),
                        &params,
                    )
                    .unwrap()
                });
            },
        );
    }

    group.finish();
}

fn bench_transaction_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_proof");
    let params = ProofParams::balanced();

    let members: Vec<u32> = vec![10, 20, 500, 999];
    let tree = MerkleTree::build(&members);
    let root = tree.root();
    let merkle_proof = tree.prove_membership(2);

    group.bench_function("prove", |b| {
        b.iter(|| {
            mpcith_zk::tx_validation::create_transaction_proof(
                black_box(&mpcith_zk::tx_validation::TransactionStatement {
                    amount_range: (1, 1000),
                    authorized_set_root: root,
                    merkle_depth: 2,
                    context: b"bench-block-42".to_vec(),
                    members: members.clone(),
                }),
                black_box(&mpcith_zk::tx_validation::TransactionWitness {
                    secret_value: 500,
                    merkle_proof: merkle_proof.clone(),
                }),
                &params,
            )
            .unwrap()
        });
    });

    let proof = mpcith_zk::tx_validation::create_transaction_proof(
        &mpcith_zk::tx_validation::TransactionStatement {
            amount_range: (1, 1000),
            authorized_set_root: root,
            merkle_depth: 2,
            context: b"bench-block-42".to_vec(),
            members: members.clone(),
        },
        &mpcith_zk::tx_validation::TransactionWitness {
            secret_value: 500,
            merkle_proof: merkle_proof.clone(),
        },
        &params,
    )
    .unwrap();

    let statement = mpcith_zk::tx_validation::TransactionStatement {
        amount_range: (1, 1000),
        authorized_set_root: root,
        merkle_depth: 2,
        context: b"bench-block-42".to_vec(),
        members,
    };

    group.bench_function("verify", |b| {
        b.iter(|| {
            mpcith_zk::tx_validation::verify_transaction_proof(
                black_box(&proof),
                black_box(&statement),
                &params,
            )
            .unwrap();
        });
    });

    println!(
        "  transaction_proof proof_size: {} bytes ({:.2} KB)",
        proof.serialized_size(),
        proof.serialized_size() as f64 / 1024.0
    );

    group.finish();
}

fn bench_compound_predicate(c: &mut Criterion) {
    let mut group = c.benchmark_group("compound_predicate");
    let params = ProofParams::balanced();

    let members: Vec<u32> = (0..8u32).map(|i| i * 10 + 1).collect();
    let tree = MerkleTree::build(&members);
    let root = tree.root();
    let merkle_proof = tree.prove_membership(3);

    let _predicate = CompoundPredicate::range_and_membership(0, 1000, members.clone());

    let mut witness = Vec::new();
    let range_w = range_witness(31, 0, 1000);
    witness.extend_from_slice(&range_w);
    let depth = members.len().next_power_of_two().trailing_zeros() as usize;
    witness.push(merkle_proof.leaf);
    witness.push(merkle_proof.leaf_index as u32);
    for i in 0..depth {
        witness.push(((merkle_proof.leaf_index >> i) & 1) as u32);
    }
    witness.extend(&merkle_proof.siblings);

    let public_inputs = vec![0u32, 1000, root];

    group.bench_function("prove", |b| {
        b.iter(|| {
            prove_compound(
                black_box(CompoundPredicate::range_and_membership(
                    0,
                    1000,
                    members.clone(),
                )),
                black_box(&witness),
                black_box(&public_inputs),
                &params,
            )
            .unwrap()
        });
    });

    let proof = prove_compound(
        CompoundPredicate::range_and_membership(0, 1000, members.clone()),
        &witness,
        &public_inputs,
        &params,
    )
    .unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            verify(black_box(&proof), black_box(&public_inputs), &params).unwrap();
        });
    });

    println!(
        "  compound_predicate proof_size: {} bytes ({:.2} KB)",
        proof.serialized_size(),
        proof.serialized_size() as f64 / 1024.0
    );

    group.finish();
}

fn bench_by_param_set(c: &mut Criterion) {
    let mut group = c.benchmark_group("by_param_set");

    let param_sets: Vec<(&str, ProofParams)> = vec![
        ("fast_insecure", ProofParams::fast_insecure()),
        ("low_n", ProofParams::low_n()),
        ("balanced", ProofParams::balanced()),
    ];

    println!();
    println!(
        "{:<30} | {:<18} | {:>10} | {:>10} | {:>10} | {:>15}",
        "predicate", "params", "prove_ms", "verify_ms", "proof_kb", "soundness_bits"
    );
    println!("{}", "-".repeat(100));

    for (param_label, params) in &param_sets {
        // -- AdditionCheck --
        let _pred_add = Predicate::AdditionCheck { expected_sum: 7 };
        let witness_add = [3u32, 4];
        let public_add = [7u32];

        let mut prove_time_add = std::time::Duration::ZERO;
        let mut verify_time_add = std::time::Duration::ZERO;
        let mut proof_size_add = 0usize;

        group.bench_function(format!("addition_prove/{}", param_label), |b| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let start = std::time::Instant::now();
                    let p = prove(
                        black_box(Predicate::AdditionCheck { expected_sum: 7 }),
                        black_box(&witness_add),
                        black_box(&public_add),
                        params,
                    )
                    .unwrap();
                    total += start.elapsed();
                    proof_size_add = p.serialized_size();
                    let vstart = std::time::Instant::now();
                    verify(black_box(&p), black_box(&public_add), params).unwrap();
                    verify_time_add = vstart.elapsed();
                    prove_time_add = total / (iters as u32);
                }
                total
            });
        });

        let prove_ms = prove_time_add.as_secs_f64() * 1000.0;
        let verify_ms = verify_time_add.as_secs_f64() * 1000.0;
        let proof_kb = proof_size_add as f64 / 1024.0;
        let soundness = params.soundness_bits();

        println!(
            "{:<30} | {:<18} | {:>9.2}ms | {:>9.2}ms | {:>9.2}KB | {:>15.1}",
            "AdditionCheck", param_label, prove_ms, verify_ms, proof_kb, soundness
        );

        // -- Compound Range+Membership --
        let members: Vec<u32> = (0..8u32).map(|i| i * 10 + 1).collect();
        let tree = MerkleTree::build(&members);
        let root = tree.root();
        let merkle_proof = tree.prove_membership(3);

        let mut witness = Vec::new();
        let range_w = range_witness(31, 0, 1000);
        witness.extend_from_slice(&range_w);
        let depth = members.len().next_power_of_two().trailing_zeros() as usize;
        witness.push(merkle_proof.leaf);
        witness.push(merkle_proof.leaf_index as u32);
        for i in 0..depth {
            witness.push(((merkle_proof.leaf_index >> i) & 1) as u32);
        }
        witness.extend(&merkle_proof.siblings);

        let public_inputs = vec![0u32, 1000, root];

        let mut prove_time_cmp = std::time::Duration::ZERO;
        let mut verify_time_cmp = std::time::Duration::ZERO;
        let mut proof_size_cmp = 0usize;

        group.bench_function(format!("compound_prove/{}", param_label), |b| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let start = std::time::Instant::now();
                    let p = prove_compound(
                        black_box(CompoundPredicate::range_and_membership(
                            0,
                            1000,
                            members.clone(),
                        )),
                        black_box(&witness),
                        black_box(&public_inputs),
                        params,
                    )
                    .unwrap();
                    total += start.elapsed();
                    proof_size_cmp = p.serialized_size();
                    let vstart = std::time::Instant::now();
                    verify(black_box(&p), black_box(&public_inputs), params).unwrap();
                    verify_time_cmp = vstart.elapsed();
                    prove_time_cmp = total / (iters as u32);
                }
                total
            });
        });

        let prove_ms = prove_time_cmp.as_secs_f64() * 1000.0;
        let verify_ms = verify_time_cmp.as_secs_f64() * 1000.0;
        let proof_kb = proof_size_cmp as f64 / 1024.0;
        let soundness = params.soundness_bits();

        println!(
            "{:<30} | {:<18} | {:>9.2}ms | {:>9.2}ms | {:>9.2}KB | {:>15.1}",
            "RangeCheck ∧ SetMembership",
            param_label,
            prove_ms,
            verify_ms,
            proof_kb,
            soundness
        );
    }

    println!();
    group.finish();
}

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

criterion_group!(
    benches,
    bench_prove,
    bench_verify,
    bench_set_membership,
    bench_transaction_proof,
    bench_compound_predicate,
    bench_by_param_set
);
criterion_main!(benches);
