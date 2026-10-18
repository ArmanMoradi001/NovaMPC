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
- **Configurable prototype soundness**: parameter sets from fast/insecure (M=10) up to high-repetition presets (M=219); repetition counts are prototype soundness estimates, not end-to-end security claims (see Soundness Parameters)
- **No trusted setup**: relies only on symmetric-key primitives (BLAKE3, SHA3, MiMC)
- **Symmetric-key primitives only**: no number-theoretic hardness assumptions, but this prototype makes no end-to-end post-quantum security claim (see Security Considerations)

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
use mpcith_zk::{prove, verify_predicate, Predicate, ProofParams};

let params = ProofParams::balanced(); // N=3, M=96

// Prove: 3 + 4 == 7 (witness is private)
let proof = prove(
    Predicate::AdditionCheck { expected_sum: 7 },
    &[3u32, 4u32],   // private witness
    &[7u32],          // public inputs
    &params,
)?;

// Verify: recompiles the predicate's circuit and binds verification to it.
assert!(verify_predicate(&Predicate::AdditionCheck { expected_sum: 7 }, &proof, &[7u32], &params)?);
```

> **Security note — always use a predicate-bound verifier.** The generic
> transcript verifier (`proof::verify_unchecked`) is `pub(crate)`: it only
> checks that `proof.circuit_hash` matches the circuit *embedded in the
> proof*, so it would accept an honestly-generated proof of any trivially-true
> (tautological) circuit. It is deliberately not exported. The public
> verifiers — [`verify_predicate`](src/proof.rs), [`verify_compound`](src/proof.rs)
> and [`tx_validation::verify_transaction_proof`](src/tx_validation.rs) —
> independently recompile the intended predicate, hash the expected circuit,
> and fail closed on mismatch before running any transcript checks.

### Compound Predicate

```rust
use mpcith_zk::{prove_compound, verify_compound, CompoundPredicate, ProofParams};
use mpcith_zk::merkle::MerkleTree;

let members = vec![10u32, 20, 42, 100];
let root = MerkleTree::build(&members)?.root();

// RangeCheck[0,1000] AND SetMembership(members), sharing one witness value.
let predicate = CompoundPredicate::range_and_membership(0, 1000, members.clone());

let params = ProofParams::balanced();
let witness = predicate.generate_witness(42u32)?; // full circuit witness
let proof = prove_compound(
    predicate,
    &witness,
    &[0, 1000, root], // public inputs: lo, hi, Merkle root
    &params,
)?;

assert!(verify_compound(
    &CompoundPredicate::range_and_membership(0, 1000, members),
    &proof,
    &[0, 1000, root],
    &params,
)?);
```

### Transaction Validation

```rust
use mpcith_zk::merkle::{MerkleTree, MerkleProof};
use mpcith_zk::tx_validation::{
    create_transaction_proof, verify_transaction_proof, TransactionStatement, TransactionWitness,
};

let members = vec![10u32, 20, 42, 100];
let tree = MerkleTree::build(&members)?;
// The verifier needs only root, depth, and member count — not the list.
let statement = TransactionStatement {
    amount_range: (0, 1000),
    authorized_set_root: tree.root(),
    merkle_depth: members.len().next_power_of_two().trailing_zeros() as usize,
    num_members: members.len(),
    context: b"block-123".to_vec(),
};

let witness = TransactionWitness {
    secret_value: 42u32,
    merkle_proof: tree.prove_membership(2),
};

let proof = create_transaction_proof(&statement, &witness, &mpcith_zk::ProofParams::balanced())?;
assert!(verify_transaction_proof(&proof, &statement, &mpcith_zk::ProofParams::balanced())?);
```

## Predicates

| Predicate | Witness | Public | Circuit Gates |
|---|---|---|---|
| `AdditionCheck` | `x, y` | `expected_sum` | 1 Add + 1 AssertEq |
| `MultiplicationCheck` | `x, y` | `expected_product` | 1 Mul + 1 AssertEq |
| `XorCheck` | `x, y` | `expected_xor` | Bit decomposition + XOR expansion |
| `RangeCheck` | `x` | `lo, hi` | Bit decomposition + range proof |
| `SetMembership` | `x` | `root` | Merkle proof via MiMC hashes |

## Soundness Parameters

| Parameter Set | N (parties) | M (repetitions) | Prototype Soundness* | Proof Size (Addition, estimator upper bound) |
|---|---|---|---|---|
| `fast_insecure()` | 3 | 10 | ≈ 2<sup>-6</sup> | ≈ 4.5 KB |
| `low_n()` | 3 | 64 | ≈ 2<sup>-37</sup> | ≈ 27.7 KB |
| `balanced()` | 3 | 96 | ≈ 2<sup>-56</sup> | ≈ 41.4 KB |
| `secure_100()` / `fabric_recommended()` | 3 | 171 | ≈ 2<sup>-100</sup> | ≈ 73.7 KB |
| `secure_128()` | 3 | 219 | ≈ 2<sup>-128</sup> | ≈ 94.3 KB |

\* Prototype soundness is computed as `M × log₂(N / (N-1))` forgery-estimate bits (per-repetition error `(N-1)/N`, i.e. 2/3 at N=3 for the 2-of-3 ZKBoo opening). These repetition counts do **not** establish end-to-end cryptographic security for the custom protocol or its implementation — see Security Considerations. Proof sizes are `ProofParams::estimated_proof_bytes` upper bounds for `AdditionCheck` (measured proofs land within one residual-share block per repetition below them; e.g. ≈ 4.5 KB measured at `fast_insecure`).

## Benchmarks

Measured on a standard desktop (Rust release profile with LTO):

### Single Predicate

| Predicate | Params | Prove | Verify | Proof Size (estimator upper bound) | Soundness |
|---|---|---|---|---|---|
| AdditionCheck | fast_insecure | 0.31 ms | 0.20 ms | 4.5 KB | 5.8 bits |
| AdditionCheck | low_n | 1.95 ms | 1.37 ms | 27.7 KB | 37.4 bits |
| AdditionCheck | balanced | 6.49 ms | 7.44 ms | 41.4 KB | 56.1 bits |

### Set Membership (balanced params)

| Set Size | Prove | Verify |
|---|---|---|
| 4 elements | 0.77 ms | — |
| 8 elements | 1.04 ms | — |
| 16 elements | 1.24 ms | — |
| 32 elements | 1.46 ms | — |

### Compound & Transaction

| Operation | Prove | Verify | Proof Size (estimator upper bound) |
|---|---|---|---|
| Compound (RangeCheck ∧ SetMembership, 4-member set) | 14.5 ms | 12.5 ms | ≈ 437 KB |
| Transaction Proof (range ∧ 4-member set) | 13.5 ms | 11.1 ms | ≈ 437 KB |

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

- **Prototype, not production cryptography**: repetition counts (`M`) are prototype forgery-estimates under the per-repetition MPCitH model. They do not establish end-to-end cryptographic security for this custom protocol, its Fiat-Shamir binding, or its unaudited implementation. Do not deploy these presets on the strength of their bit labels.
- **32-bit membership root**: the set-membership Merkle root is a single 32-bit word (≈ 2<sup>16</sup> birthday collision resistance). It must not be relied on for cryptographic strength.
- **No trusted setup**: all parameters are derived from public constants
- **Symmetric-key building blocks, not a post-quantum security claim**: the protocol uses no number-theoretic assumptions (no discrete log or factoring), so its primitives are not broken by Shor's algorithm — but end-to-end security for this unaudited prototype is *not* established. In particular, the set-membership Merkle root is a single 32-bit word (≈ 2<sup>16</sup> birthday collision resistance), and the repetition-count bit labels are forgery-model estimates only.
- **Circuit-substitution protection**: verification is bound to the intended predicate — the safe APIs (`verify_predicate`, `verify_compound`, `verify_transaction_proof`) independently recompile the expected circuit and fail closed if `proof.circuit_hash` does not match; the unchecked generic verifier is crate-private (`pub(crate)`)
- **Fiat-Shamir**: non-interactive transformation via SHA3-256 hash function
- **Replay protection**: transaction proofs bind to a `context` field (e.g., block hash) hashed into the Fiat-Shamir transcript
- **Soundness tradeoff**: smaller N gives faster proofs but weaker soundness per repetition; larger M compensates

## Academic References

- Ishai, Kushilevitz, Ostrovsky, Sahai — *Zero-Knowledge from Secure MPC* (STOC 2007)
- Chase, Derler, Goldfeder, Orlandi, Ramacher, Rechberger, Slamanig, Zaverucha — *Post-Quantum Zero-Knowledge from Symmetric-Key Primitives* (CCS 2017) — Picnic
- Katz, Kolesnikov, Wang — *Improved Non-Interactive Zero-Knowledge with Applications to Post-Quantum Signatures* (CCS 2018) — KKW

## Roadmap

- [x] Full bit-decomposition range proof
- [ ] Beaver-triple multiplication protocol
- [ ] Merkle-based set membership refinements
- [ ] Hyperledger Fabric chaincode integration

## License

© 2026 Arman Moradi. All Rights Reserved.

This repository contains original research code and materials developed by Arman Moradi.

**No license is granted for the use, reproduction, modification, distribution, publication, or incorporation of this code or any substantial portion of it into other projects without prior written permission from the copyright holder.**

If you wish to use this work for academic research, education, commercial purposes, benchmarking, publication, or any other purpose beyond viewing the repository on GitHub, please contact the copyright holder and obtain written permission first.

see [LICENSE](LICENSE) for details.






