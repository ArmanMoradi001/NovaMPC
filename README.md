# mpcith-zk

MPC-in-the-Head Zero-Knowledge Proof library — Phase 1 of the MSc thesis implementation.

## What this is

An implementation of the **MPC-in-the-Head (MPCitH)** paradigm for constructing
zero-knowledge proofs, following the approach of Ishai et al. (STOC 2007) and the
Picnic/KKW signature scheme family.

This library proves statements of the form:
> "I know a secret witness `w` such that `Circuit(w) = public_output`"

without revealing `w`.

## Architecture

```
mpcith-zk/
├── src/
│   ├── lib.rs          — crate root, public API
│   ├── params.rs       — ProofParams (N parties, M repetitions)
│   ├── circuit.rs      — Arithmetic circuit over Z_{2^32}
│   ├── sharing.rs      — Additive secret sharing
│   ├── mpc.rs          — MPC-in-the-Head emulation
│   ├── commitment.rs   — BLAKE3 commitment scheme
│   ├── fiat_shamir.rs  — SHA3-256 challenge derivation
│   ├── predicate.rs    — High-level predicates → circuits
│   ├── proof.rs        — Prove + Verify top-level API
│   └── bin/demo.rs     — Demo binary
└── benches/
    └── mpcith_bench.rs — Criterion benchmarks
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

## Soundness

| Params              | N  | M  | Soundness     | Notes                  |
|---------------------|----|----|---------------|------------------------|
| `fast_insecure()`   | 3  | 10 | ≈ 2^{-16}     | Tests only             |
| `low_n()`           | 3  | 64 | ≈ 2^{-40}     | Large proofs           |
| `balanced()` (def)  | 16 | 38 | ≈ 2^{-40}     | Picnic-style           |

## Usage

```rust
use mpcith_zk::{prove, verify, Predicate, ProofParams};

// Prove: x + y == 7, where x=3, y=4 are private
let params = ProofParams::default(); // N=16, M=38
let proof = prove(
    Predicate::AdditionCheck { expected_sum: 7 },
    &[3u32, 4u32],   // private witness
    &[7u32],          // public inputs
    &params,
)?;

assert!(verify(&proof, &[7u32], &params)?);
```

## Running

```bash
# Run demo
cargo run --bin demo --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

## Predicates (Phase 1)

| Predicate            | Witness       | Public         | Gates                  |
|----------------------|---------------|----------------|------------------------|
| `AdditionCheck`      | x, y          | x+y            | 1 Add + 1 AssertEq     |
| `MultiplicationCheck`| x, y          | x*y            | 1 Mul + 1 AssertEq     |
| `XorCheck`           | x, y          | x XOR y        | 1 Xor + 1 AssertEq     |
| `SetMembership`      | x             | {m_1,...,m_k}  | k AddConst + k-1 Mul   |
| `RangeCheck`         | x             | lo, hi         | Placeholder (Phase 2)  |

## References

- Ishai et al., "Zero-Knowledge from Secure MPC" (STOC 2007)
- Chase et al., "Post-Quantum ZK from Symmetric-Key Primitives" (CCS 2017) — Picnic
- Katz, Kolesnikov, Wang, "Improved Non-Interactive ZK" (CCS 2018) — KKW

## Phase 2 (Next)

- Full bit-decomposition range proof
- Proper Beaver-triple multiplication protocol
- Merkle-based set membership
- Hyperledger Fabric integration
