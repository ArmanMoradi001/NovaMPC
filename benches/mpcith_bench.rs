//! Criterion benchmarks for mpcith-zk.
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mpcith_zk::{prove, verify, Predicate, ProofParams};

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("prove");

    for (label, params) in [
        ("fast_n3_m10", ProofParams::fast_insecure()),
        ("low_n3_m64", ProofParams::low_n()),
        ("balanced_n16_m38", ProofParams::balanced()),
    ] {
        group.bench_with_input(BenchmarkId::new("addition", label), &params, |b, params| {
            b.iter(|| {
                prove(
                    black_box(Predicate::AdditionCheck { expected_sum: 7 }),
                    black_box(&[3u32, 4u32]),
                    black_box(&[7u32]),
                    params,
                )
                .unwrap()
            });
        });
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

        group.bench_with_input(BenchmarkId::new("addition", label), &(proof, params.clone()), |b, (proof, params)| {
            b.iter(|| verify(black_box(proof), black_box(&[7u32]), params).unwrap());
        });
    }

    group.finish();
}

fn bench_set_membership(c: &mut Criterion) {
    let mut group = c.benchmark_group("set_membership");
    let params = ProofParams::fast_insecure();

    for set_size in [4usize, 8, 16, 32] {
        let members: Vec<u32> = (0..set_size as u32).map(|i| i * 10).collect();
        let witness = [members[set_size / 2]];

        group.bench_with_input(
            BenchmarkId::new("prove", set_size),
            &(members.clone(), witness),
            |b, (members, witness)| {
                b.iter(|| {
                    prove(
                        black_box(Predicate::SetMembership { members: members.clone() }),
                        black_box(witness),
                        black_box(members),
                        &params,
                    )
                    .unwrap()
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_prove, bench_verify, bench_set_membership);
criterion_main!(benches);
