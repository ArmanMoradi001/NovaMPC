//! Demo binary: exercises all predicates and prints proof statistics.

use mpcith_zk::{prove, verify, Predicate, ProofParams};

fn separator(title: &str) {
    println!("\n{}", "═".repeat(60));
    println!("  {}", title);
    println!("{}", "═".repeat(60));
}

fn run_demo(label: &str, predicate: Predicate, witness: &[u32], public_inputs: &[u32], params: &ProofParams) {
    use std::time::Instant;

    println!("\n▶ {}", label);
    println!("  Witness:       {:?}", witness);
    println!("  Public inputs: {:?}", public_inputs);
    println!("  Params:        N={}, M={}", params.num_parties, params.num_repetitions);

    let t_prove = Instant::now();
    let proof = match prove(predicate, witness, public_inputs, params) {
        Ok(p) => p,
        Err(e) => {
            println!("  ✗ Prove failed: {}", e);
            return;
        }
    };
    let prove_ms = t_prove.elapsed().as_millis();

    let proof_bytes = proof.serialized_size();

    let t_verify = Instant::now();
    let valid = verify(&proof, public_inputs, params).unwrap_or(false);
    let verify_ms = t_verify.elapsed().as_millis();

    println!("  Proof size:    {} bytes ({:.1} KB)", proof_bytes, proof_bytes as f64 / 1024.0);
    println!("  Prove time:    {} ms", prove_ms);
    println!("  Verify time:   {} ms", verify_ms);
    println!("  Valid:         {}", if valid { "✓ YES" } else { "✗ NO" });
}

fn main() {
    separator("MPC-in-the-Head ZK Proof Demo");
    println!("  Library: mpcith-zk v0.1.0");
    println!("  Field:   Z_{{2^32}}");

    // ── Fast (insecure) parameters for demo speed ─────────────────────────
    let fast = ProofParams::fast_insecure();

    separator("Predicate 1: Addition Check (x + y == z)");
    run_demo(
        "Prove: 3 + 4 == 7",
        Predicate::AdditionCheck { expected_sum: 7 },
        &[3, 4],
        &[7],
        &fast,
    );

    separator("Predicate 2: Multiplication Check (x * y == z)");
    run_demo(
        "Prove: 6 * 7 == 42",
        Predicate::MultiplicationCheck { expected_product: 42 },
        &[6, 7],
        &[42],
        &fast,
    );

    separator("Predicate 3: XOR Check (x XOR y == z)");
    run_demo(
        "Prove: 0b1010 XOR 0b1100 == 0b0110",
        Predicate::XorCheck { expected_xor: 0b0110 },
        &[0b1010, 0b1100],
        &[0b0110],
        &fast,
    );

    separator("Predicate 4: Set Membership (x ∈ S)");
    let members = vec![10u32, 20, 30, 42, 100];
    run_demo(
        "Prove: 42 ∈ {10, 20, 30, 42, 100}",
        Predicate::SetMembership { members: members.clone() },
        &[42],
        &members,
        &fast,
    );

    // ── Balanced (secure) parameters — for one predicate ─────────────────
    separator("Secure Parameters (N=16, M=38, soundness ≈ 2^{-40})");
    let balanced = ProofParams::balanced();
    run_demo(
        "Prove: 1000 + 337 == 1337  [SECURE PARAMS]",
        Predicate::AdditionCheck { expected_sum: 1337 },
        &[1000, 337],
        &[1337],
        &balanced,
    );

    // ── Soundness error estimate ──────────────────────────────────────────
    separator("Parameter Analysis");
    for (label, params) in [
        ("fast_insecure (N=3, M=10)", ProofParams::fast_insecure()),
        ("low_n        (N=3, M=64)", ProofParams::low_n()),
        ("balanced     (N=16, M=38)", ProofParams::balanced()),
    ] {
        let n = params.num_parties as f64;
        let m = params.num_repetitions as f64;
        let soundness_bits = m * (n / (n - 1.0)).log2();
        let estimated = params.estimated_proof_bytes(2, 10);
        println!(
            "  {:30} soundness ≈ 2^{{-{:.1}}}  est. size ≈ {} KB",
            label,
            soundness_bits,
            estimated / 1024
        );
    }

    println!("\n{}", "═".repeat(60));
    println!("  Demo complete.");
    println!("{}\n", "═".repeat(60));
}
