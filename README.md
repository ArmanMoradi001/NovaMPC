# mpcith-zk

A Rust library implementing the **MPC-in-the-Head (MPCitH)** paradigm for constructing non-interactive zero-knowledge proofs from symmetric-key primitives.

This library proves statements of the form:

> *"I know a secret witness `w` such that `Circuit(w) = public_output`"*

without revealing `w`, using the cut-and-choose technique of Ishai et al. (STOC 2007) with the Picnic/KKW signature scheme family as reference.

## Features

- **Arithmetic circuits over Z<sub>2<sup>32</sup></sub>** with Add, Mul, Xor, AddConst, MulConst, and AssertEq gates
- **Additive secret sharing** with information-theoretic privacy (any N-1 shares reveal nothing)
- **BLAKE3 commitment scheme** with domain separation and per-party view commitments
- **Fiat-Shamir transformation** using SHA3-256 for non-interactive challenge derivation
- **Built-in predicates**: addition, multiplication, XOR, range proofs, and Merkle-based set membership
- **MiMC-2n/n Feistel hash** circuit — a circuit-friendly hash using only Add and Mul gates
- **Merkle tree** support for set membership proofs with MiMC as the hash function
- **Configurable parameters** with soundness from 2<sup>-16</sup> (testing) to 2<sup>-152</sup> (production)

## Architecture

```
src/
├── lib.rs            Crate root and public API re-exports
├── circuit.rs        Arithmetic circuit representation and builder
├── mimc.rs           MiMC-2n/n Feistel hash (circuit and native)
├── merkle.rs         Merkle tree with MiMC hash (prover-side)
├── mpc.rs            MPC-in-the-Head emulation engine
├── sharing.rs        Additive secret sharing over Z_{2^32}
├── commitment.rs     BLAKE3-based commitment scheme
├── fiat_shamir.rs    SHA3-256 Fiat-Shamir challenge derivation
├── predicate.rs      High-level predicates → circuit compilation
├── proof.rs          Top-level prove and verify API
├── params.rs         Proof parameter presets and validation
├── error.rs          Error types
└── bin/demo.rs       Demo binary exercising all predicates
benches/
└── mpcith_bench.rs   Criterion benchmarks
tests/
└── integration.rs    End-to-end integration and tamper-resistance tests
```

## Protocol Overview

```
PROVER                                    VERIFIER
  │                                           │
  │  1. Compile predicate → Circuit           │
  │  2. For each repetition i = 1..M:         │
  │     a. Sample N party seeds               │
  │     b. Secret-share witness               │
  │     c. Evaluate circuit in shared form    │
  │     d. Commit to each party's view        │
  │        com[i][p] = BLAKE3(seed_p ‖ msgs)  │
  │                                           │
  │  3. Fiat-Shamir challenge:                │
  │     e[i] = SHA3(all_commitments)[i] mod N │
  │                                           │
  │  4. Open N-1 views per repetition         │
  │     (hide party e[i])                     │
  │──────────── Proof ───────────────────────►│
  │                                           │  5. Recompute challenges
  │                                           │  6. Verify opened commitments
  │                                           │  7. Check view consistency
  │                                           │  8. Check output reconstruction
```

## Usage

```rust
use mpcith_zk::{prove, verify, Predicate, ProofParams};

// Prove: x + y == 7, where x=3, y=4 are private witnesses
let params = ProofParams::default(); // N=16, M=38, soundness ≈ 2^-152
let proof = prove(
    Predicate::AdditionCheck { expected_sum: 7 },
    &[3u32, 4u32],   // private witness
    &[7u32],          // public inputs
    &params,
)?;

assert!(verify(&proof, &[7u32], &params)?);
```

### Range Proof

```rust
use mpcith_zk::{prove, verify, Predicate, ProofParams};

let params = ProofParams::default();
let pred = Predicate::RangeCheck { lo: 0, hi: 1000 };
// Witness layout: [x, x_bits(32), shifted_bits(k), slack_bits(k)]
let witness = build_range_witness(500, 0, 1000);
let proof = prove(pred, &witness, &[0, 1000], &params)?;
assert!(verify(&proof, &[0, 1000], &params)?);
```

### Set Membership Proof

```rust
use mpcith_zk::{prove, verify, Predicate, ProofParams};
use mpcith_zk::merkle::MerkleTree;

let members = vec![10u32, 20, 30, 42];
let tree = MerkleTree::build(&members);
let root = tree.root();
let merkle_proof = tree.prove_membership(3); // prove 42 ∈ set

// Build witness from Merkle proof: [leaf, index, bits, siblings]
let witness = build_membership_witness(&merkle_proof);
let pred = Predicate::SetMembership { members };
let proof = prove(pred, &witness, &[root], &params)?;
assert!(verify(&proof, &[root], &params)?);
```

## Supported Predicates

| Predicate            | Statement                        | Circuit Cost               |
|----------------------|----------------------------------|----------------------------|
| `AdditionCheck`      | x + y == z                       | 1 Add + 1 AssertEq         |
| `MultiplicationCheck`| x * y == z                       | 1 Mul + 1 AssertEq         |
| `XorCheck`           | x XOR y == z                     | 1 Xor + 1 AssertEq         |
| `RangeCheck`         | lo <= x <= hi                    | 32 + 2k Mul gates (bit decomp) |
| `SetMembership`      | x ∈ {m₁, …, mₖ} via Merkle path | depth × MiMC rounds       |

## Parameters

| Preset                | N  | M  | Soundness (bits) | Use Case               |
|-----------------------|----|----|------------------|------------------------|
| `fast_insecure()`     | 3  | 10 | ~16              | Unit tests, benchmarks |
| `low_n()`             | 3  | 64 | ~101             | Larger proofs          |
| `balanced()` (default)| 16 | 38 | ~152             | Production / Picnic-style |

Soundness is computed as `M × log₂(N)`. A cheating prover fabricating one view per repetition is caught with probability `1 - (1/N)^M`.

## Getting Started

### Prerequisites

- Rust 1.70+ (edition 2021)

### Build

```bash
cargo build --release
```

### Run Tests

```bash
cargo test
```

### Run Demo

```bash
cargo run --bin demo --release
```

### Run Benchmarks

```bash
cargo bench
```

## Dependencies

| Crate       | Purpose                              |
|-------------|--------------------------------------|
| `blake3`    | Commitment scheme (view commitments) |
| `sha3`      | Fiat-Shamir challenge derivation     |
| `rand`      | Cryptographic randomness             |
| `rand_chacha` | Deterministic PRNG from seeds      |
| `serde`     | Serialization of proof structures    |
| `bincode`   | Binary serialization for proofs      |
| `thiserror` | Ergonomic error types                |
| `criterion` | Benchmarking framework (dev)         |

## References

- Ishai, Sahai, Wagner — *"Zero-Knowledge from Secure Multiparty Computation"* (STOC 2007)
- Chase, Derler, Goldfeder, Orlandi, Reager, Ribeiro, Xie — *"Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives"* (CCS 2017) — Picnic
- Katz, Kolesnikov, Wang — *"Improved Non-Interactive Zero Knowledge and Applications to Mining Pool Accountability"* (CCS 2018) — KKW

## License

MIT — see [LICENSE](LICENSE).
