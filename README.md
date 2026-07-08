# NovaMPC

MPC-in-the-Head Zero-Knowledge Proof library for privacy-preserving blockchain validation.

## Overview

NovaMPC implements the **MPC-in-the-Head (MPCitH)** paradigm for constructing zero-knowledge proofs, based on the work of Ishai et al. (STOC 2007) and the Picnic/KKW signature scheme family.

The library proves statements of the form:

> "I know a secret witness `w` such that `Circuit(w) = public_output`"

without revealing `w`. All computations operate over **Z<sub>2<sup>32</sup></sub>**.

### Key Features

- **5 predicate types**: addition, multiplication, XOR, range check, and set membership
- **Compound predicates**: logical AND composition of sub-predicates
- **Transaction validation API**: high-level interface for blockchain integration
- **Configurable security**: three parameter sets from fast/insecure to Picnic-style secure
- **No trusted setup**: relies only on symmetric-key primitives (BLAKE3, SHA3, MiMC)
- **Post-quantum**: security based on symmetric-key assumptions, not number theory

## Architecture

```
Circuit ──► MPC Emulator ──► Commitment Scheme ──► Fiat-Shamir
 (gates)    (N parties,       (BLAKE3 per view)     (SHA3-256
            additive shares)                          challenge)
```

```
NovaMPC/
├── src/
│   ├── lib.rs            — crate root, public API re-exports
│   ├── params.rs         — ProofParams (N parties, M repetitions)
│   ├── circuit.rs        — Arithmetic circuit over Z_{2^32}
│   ├── sharing.rs        — Additive secret sharing
│   ├── mpc.rs            — MPC-in-the-Head emulation
│   ├── commitment.rs     — BLAKE3 commitment scheme
│   ├── fiat_shamir.rs    — SHA3-256 Fiat-Shamir challenge derivation
│   ├── predicate.rs      — High-level predicates compiled to circuits
│   ├── proof.rs          — Prove + Verify top-level API
│   ├── seed_tree.rs      — GGM-style binary seed tree
│   ├── merkle.rs         — Merkle tree with MiMC hash
│   ├── mimc.rs           — MiMC-2n/n Feistel hash
│   ├── tx_validation.rs  — Transaction validation for Hyperledger Fabric
│   ├── error.rs          — Error types
│   └── bin/
│       └── demo.rs       — Demo binary exercising all predicates
├── tests/
│   └── integration.rs    — End-to-end integration tests
└── benches/
    └── mpcith_bench.rs   — Criterion benchmarks
```

## Protocol Overview

```
PROVER                                    VERIFIER
  │                                           │
  │  1. Compile predicate → Circuit           │
  │  2. For each repetition i=1..M:           │
  │     a. Generate N party seeds             │
  │     b. Secret-share witness               │
  │     c. Evaluate circuit in shared form    │
  │     d. Commit to each party's view        │
  │        com[i][p] = BLAKE3(seed_p || msgs) │
  │                                           │
  │  3. Fiat-Shamir challenge:                │
  │     e[i] = SHA3(all_commitments)[i] mod N │
  │                                           │
  │  4. Open N-1 views per repetition         │
  │     (hide party e[i])                     │
  │──────────── Proof ───────────────────────►│
  │                                           │  5. Recompute challenges
  │                                           │  6. Verify opened commitments
  │                                           │  7. Check output consistency
```

## Getting Started

### Prerequisites

- Rust 1.70+ (2021 edition)

### Build

```bash
cargo build --release
```

### Run Demo

```bash
cargo run --bin demo --release
```

### Run Tests

```bash
cargo test
```

### Run Benchmarks

```bash
cargo bench
```

## Usage

### Basic Proof

```rust
use mpcith_zk::{prove, verify, Predicate, ProofParams};

let params = ProofParams::default(); // N=16, M=38

// Prove: 3 + 4 == 7 (witness is private)
let proof = prove(
    Predicate::AdditionCheck { expected_sum: 7 },
    &[3u32, 4u32],   // private witness
    &[7u32],          // public inputs
    &params,
)?;

// Verify: only needs public inputs
assert!(verify(&proof, &[7u32], &params)?);
```

### Compound Predicate

```rust
use mpcith_zk::{prove_compound, verify, CompoundPredicate, Predicate, ProofParams};

let predicate = CompoundPredicate {
    sub_predicates: vec![
        Predicate::RangeCheck { lo: 0, hi: 1000 },
        Predicate::SetMembership { members: vec![10, 20, 42, 100] },
    ],
};

let params = ProofParams::default();
let proof = prove_compound(
    predicate,
    &[42u32],        // private witness
    &[0, 1000, 10, 20, 42, 100], // public inputs
    &params,
)?;

assert!(verify(&proof, &[0, 1000, 10, 20, 42, 100], &params)?);
```

### Transaction Validation

```rust
use mpcith_zk::tx_validation::{generate_transaction_proof, verify_transaction_proof, TransactionStatement};

let statement = TransactionStatement {
    amount_range: (0, 1000),
    authorized_set_root: 42,  // Merkle root of authorized accounts
    merkle_depth: 4,
    context: b"block-123".to_vec(),
    members: vec![10, 20, 42, 100],
};

let proof = generate_transaction_proof(42u32, &statement, &ProofParams::default())?;
assert!(verify_transaction_proof(&proof, &statement, &ProofParams::default())?);
```

## Predicates

| Predicate | Witness | Public | Circuit Gates |
|---|---|---|---|
| `AdditionCheck` | `x, y` | `expected_sum` | 1 Add + 1 AssertEq |
| `MultiplicationCheck` | `x, y` | `expected_product` | 1 Mul + 1 AssertEq |
| `XorCheck` | `x, y` | `expected_xor` | 1 Xor + 1 AssertEq |
| `RangeCheck` | `x` | `lo, hi` | Bit decomposition + range proof |
| `SetMembership` | `x` | `members, root` | Merkle proof via MiMC hashes |

## Soundness Parameters

| Parameter Set | N (parties) | M (repetitions) | Soundness | Proof Size (Addition) |
|---|---|---|---|---|
| `fast_insecure()` | 3 | 10 | ≈ 2<sup>-16</sup> | ≈ 3 KB |
| `low_n()` | 3 | 64 | ≈ 2<sup>-101</sup> | ≈ 18 KB |
| `balanced()` | 16 | 38 | ≈ 2<sup>-152</sup> | ≈ 60 KB |

Soundness is computed as: `M × log₂(N / (N-1))` bits of security.

## Benchmarks

Measured on a standard desktop (Rust release profile with LTO):

### Single Predicate

| Predicate | Params | Prove | Verify | Proof Size | Soundness |
|---|---|---|---|---|---|
| AdditionCheck | fast_insecure | 0.31 ms | 0.20 ms | 2.9 KB | 15.8 bits |
| AdditionCheck | low_n | 1.95 ms | 1.37 ms | 17.7 KB | 101.4 bits |
| AdditionCheck | balanced | 6.49 ms | 7.44 ms | 59.9 KB | 152.0 bits |

### Set Membership (balanced params)

| Set Size | Prove | Verify |
|---|---|---|
| 4 elements | 0.77 ms | — |
| 8 elements | 1.04 ms | — |
| 16 elements | 1.24 ms | — |
| 32 elements | 1.46 ms | — |

### Compound & Transaction

| Operation | Prove | Verify | Proof Size |
|---|---|---|---|
| Compound (RangeCheck ∧ SetMembership) | 14.5 ms | 12.5 ms | 4.5 MB |
| Transaction Proof | 13.5 ms | 11.1 ms | 3.3 MB |

## Dependencies

| Crate | Purpose |
|---|---|
| `blake3` | Commitment scheme, seed tree derivation |
| `sha3` | Fiat-Shamir challenge derivation |
| `rand_chacha` | Deterministic per-party CSPRNG |
| `serde` / `bincode` | Proof serialization |
| `mimc` (in-tree) | Circuit-friendly Feistel hash for Merkle trees |
| `criterion` (dev) | Statistical benchmarking |

## Security Considerations

- **No trusted setup**: all parameters are derived from public constants
- **Post-quantum**: security relies on symmetric-key primitives, not discrete logarithms or factoring
- **Fiat-Shamir**: non-interactive transformation via SHA3-256 hash function
- **Replay protection**: transaction proofs bind to a `context` field (e.g., block hash) hashed into the Fiat-Shamir transcript
- **Soundness tradeoff**: smaller N gives faster proofs but weaker soundness per repetition; larger M compensates

## Academic References

- Ishai, Kushilevitz, Ostrovsky, Sahai — *Zero-Knowledge from Secure MPC* (STOC 2007)
- Chase, Derler, Goldfeder, Orlandi, Ramacher, Rechberger, Slamanig, Zaverucha — *Post-Quantum Zero-Knowledge from Symmetric-Key Primitives* (CCS 2017) — Picnic
- Katz, Kolesnikov, Wang — *Improved Non-Interactive Zero-Knowledge with Applications to Post-Quantum Signatures* (CCS 2018) — KKW

## Roadmap

- [ ] Full bit-decomposition range proof
- [ ] Beaver-triple multiplication protocol
- [ ] Merkle-based set membership refinements
- [ ] Hyperledger Fabric chaincode integration

## License

MIT — see [LICENSE](LICENSE) for details.
