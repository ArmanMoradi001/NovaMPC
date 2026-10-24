# NovaMPC v2 Audit Package

**Status:** `AWAITING AUDIT`  
**Proof status:** 2/3 soundness dossier is `DRAFT / AWAITING EXTERNAL REVIEW`;
knowledge soundness, zero knowledge, side channels, and primitive assumptions
are unresolved.  
**Code baseline:** proof format v3; Step 06 adversarial/high-M suite.  
**Companion documents:** [`V2_SOUNDNESS_2_3.md`](V2_SOUNDNESS_2_3.md),
[`V2_SECURITY_ANALYSIS.md`](V2_SECURITY_ANALYSIS.md).

This package is preparation for an independent review. It is not an audit, a
proof, or a deployment approval. An AI self-review is not an independent audit.

---

## 1. Scope and threat model

### 1.1 Assets

- The private amount/member value and its witness shares.
- The correctness of the public statement (range bounds, set root, member count,
  depth, context).
- The soundness of the range/membership/combined proof.
- Transaction authorization: a verifier must not accept a proof for a root,
  range, count, depth, or context chosen by an attacker.
- The confidentiality of the witness, to the extent zero knowledge is claimed
  (currently it is not).

### 1.2 Adversary capabilities

- Chooses a statement, context, proof bytes, Merkle path, and proof parameters
  within the documented bounds.
- May query the transcript/challenge derivation up to a stated `q` budget and
  may grind prefixes.
- May tamper with every serialized field, including magic, version, parameters,
  statement tag, lengths, field encodings, context, commitment roots, assertion
  rows, and opened views.
- May control the root or statement supplied to a transaction verifier through
  an untrusted request. The library's API must prevent the proof from becoming
  the source of that expected statement.

### 1.3 Trust boundaries

- **Caller/ledger:** the caller must reconstruct `TransactionStatementV2` from
  authenticated ledger or consensus state. The library verifies a relation
  about that statement; it does not authenticate the root.
- **Verifier entry points:** external callers use `verify_statement`,
  `verify_bytes_statement`, or `verify_transaction_proof_v2`. The raw `verify`
  is crate-private.
- **Prover:** the witness and seed-tree secrets are trusted to the prover
  process; the library does not provide a secure enclave or memory isolation.
- **No trusted setup:** all suite/field/Poseidon2 parameters are public
  constants.

### 1.4 In scope

- v2 field encoding, Poseidon2, Merkle tree, circuits/predicates, MPC emulation,
  commitments, seed tree, proof/transcript, and transaction API.
- The 2/3 soundness argument and the conditional `q * (2/3)^M` bound.
- Known API and serialization failure modes exercised by the tests.

### 1.5 Out of scope

- v1. It is legacy, uses a 32-bit MiMC root, and is not part of the v2 secure
  transaction path.
- Fabric chaincode, networking, gossip, ordering, consensus, and transaction
  envelope validation.
- Formal verification, machine-checked proofs, and side-channel measurement.
- A concrete-cryptanalysis claim for Poseidon2.
- A production-security claim.

---

## 2. Code map

| Area | Files | Review focus |
|---|---|---|
| Field encoding | `src/v2/field.rs` | Canonical 32-byte BN254 `Fr` encoding; reject modulus and non-canonical values |
| Poseidon2 native | `src/v2/poseidon2.rs`, `src/v2/poseidon2/poseidon2_constants.rs` | Pinned upstream constants; domain-separated leaf/node/root framing |
| Poseidon2 circuit | `src/v2/poseidon2_circuit.rs` | Gadget matches native framing and upstream KAT |
| Merkle tree | `src/v2/merkle.rs` | Ordered leaves, duplicate rejection, empty leaf, count/depth binding, index bounds |
| Circuit | `src/v2/circuit.rs` | Gate semantics; no `u32` wraparound; assertion checks |
| Predicates | `src/v2/predicate.rs` | Range/membership/combined relation; one shared `x` wire; canonical depth |
| MPC | `src/v2/mpc.rs` | 3-party emulation; linear recomputation; Mul edges; zero shares; residual shares |
| Sharing | `src/v2/sharing.rs` | Additive shares; rejection sampling; seed domains |
| Commitments | `src/v2/commitment.rs`, `src/v2/commit_tree.rs` | View commitment binding; tree paths; length-prefixed payload |
| Seed tree | `src/v2/seed_tree.rs` | Co-path reconstruction; party count bounds; no checked root |
| Proof/transcript | `src/v2/proof.rs` | Version 3; context hash; statement pinning; structural limits; challenge derivation; transcript framing |
| Transaction | `src/v2/transaction.rs` | `Fr` root; caller-supplied expected statement; context; no proof-derived root |
| Tests | `tests/v2_*.rs` | Integration, transaction, soundness gap, arithmetic, adversarial, high-M |

---

## 3. Cryptographic assumptions

| Assumption | Concrete dependency | Status |
|---|---|---|
| BN254 `Fr` discrete-log/field arithmetic | `ark-bn254 0.6.0`, `ark-ff 0.6` | Standard library assumption; no independent audit here |
| Poseidon2 permutation and parameters | Horizen Labs revision `055bde3f...`; constants SHA-256 `7b34cc65...` | Pinned and KAT-tested; external cryptanalysis assumed |
| BLAKE3 collision resistance | `blake3 1.8.5` (Cargo.lock) | Used for seed tree, commitments, transcript/context; generic collision ceiling ~128 bits |
| ChaCha20 PRG | `rand_chacha 0.3.1` | Used for shares and Fiat-Shamir challenge sampling; ideal-PRG assumption |
| Transcript encoding | Fixed-width integers, explicit lengths, domain strings | Design + tamper tests; no formal injectivity proof |
| Ideal challenge | BLAKE3 `derive_key` + ChaCha20 `gen_range(0..3)` | Treated as ideal in the 2/3 bound; not proven |
| No trusted setup | Public consts only | No trapdoor setup |

The ~127-bit ceiling comes from the ~254-bit BN254 `Fr` field elements used for
the root and commitment tree. It is **not** a 128-bit claim. BLAKE3's generic
collision ceiling is also about 128 bits.

---

## 4. Proof status

### 4.1 What is established

- Completeness argument for honest proofs (conditional on implementation and
  deterministic encoding).
- Conditional 2/3 per-repetition soundness: for a fixed pre-challenge prefix and
  a false statement, at most two of the three hidden choices pass.
- Tightness: a concrete false range statement is accepted for hidden choices 0
  and 1 and rejected for hidden choice 2. The same hidden-neighbour mechanism
  ports to the combined range+membership circuit.
- Conditional `q * (2/3)^M` query-loss bound.

### 4.2 What is not established

- A Fiat-Shamir knowledge-soundness theorem / extraction for the deployed
  BLAKE3/ChaCha20 transform.
- Zero knowledge.
- A concrete-security reduction for BLAKE3, ChaCha20, Poseidon2, or the
  transcript encoding.
- Side-channel or constant-time behaviour.
- Any production or 128-bit claim.

### 4.3 Parameter status

| `M` | Conditional bits at `q=1` | At `q=2^32` | Status |
|---:|---:|---:|---|
| 96 | 56.16 | 24.16 | historical/test only |
| 218 | 127.52 | 95.52 | bare minimum at `q=1` |
| 223 | 130.45 | 98.45 | recommended `q=1` preset |
| 272 | 159.11 | 127.11 | bare minimum at `q=2^32` |
| 277 | 162.03 | 130.03 | recommended `q=2^32` preset |

The overall target remains ~127 bits because of the BN254 root/field collision
ceiling. `M=219` is an old benchmark setting, not a target.

### 4.4 Review gates

- 2/3 bound: `AWAITING EXTERNAL REVIEW`; see
  [`V2_SOUNDNESS_2_3.md`](V2_SOUNDNESS_2_3.md) Section 10.
- Audit: `AWAITING AUDIT`; this package.
- No README or code comment may say "proven", "audited", "production-secure",
  or "128-bit" before sign-off.

---

## 5. Side-channel checklist

This section records what must be reviewed. It does **not** establish
constant-time behaviour or side-channel resistance.

| Area | Observation | Status |
|---|---|---|
| Secret-dependent branches | Field/MPC code contains arithmetic on secret shares; no constant-time annotation or formal analysis | **Not established** |
| Variable-time field operations | `ark-bn254`/`ark-ff` operations are not documented here as constant-time | **Not established** |
| Rejection sampling | `sample_fr` loops until a canonical draw; iteration count depends on the draw | **Not established** |
| RNG use | `thread_rng` for proof randomness; ChaCha20 streams for party shares/challenges | **Not established** |
| Memory zeroization | No `zeroize` dependency; secret shares, seeds, and witnesses are ordinary `Vec`/stack values | **Not established** |
| Proof parsing | Strict length bounds and canonical field checks; parser is not measured for timing | Implementation checks only |
| Error messages | Errors expose party indices/gate positions and structural reasons; no secret-dependent error oracle analysis | **Not established** |
| Serialization shape | Party 2 residual shares appear only when party 2 is opened; the hidden party is public in the proof | Implementation feature; privacy impact not analysed |
| Transaction API | Expected root/statement/context come from the caller; no proof-derived root | API shape tested |
| Network/chaincode timing | Out of scope | Not reviewed |

Recommended reviewer actions: measure secret-dependent branches in
`sharing.rs`, `mpc.rs`, `seed_tree.rs`, `commitment.rs`, and prover paths;
inspect allocator behaviour; assess whether witness/seed memory is exposed by
the host process; review error paths and panic behaviour.

---

## 6. Primitive pins and domain separation

### 6.1 Suite identifiers

- `V2_PROOF_VERSION = 3`
- `V2_PROTOCOL_ID = b"NovaMPC-v2/proof/v1"`
- `V2_FIELD_ID = b"BN254-Fr"`
- `V2_POSEIDON2_ID = b"HorizenLabs-poseidon2-bn254-t3-d5-rf8-rp56@055bde3f4782731ba5f5ce5888a440a94327eaf3"`
- `V2_FRAMING_ID = b"NovaMPC-v2/tagged-compress/v1"`
- `N = 3`; `M` is a parameter with `1 <= M <= 65536`

### 6.2 Domain strings

- Circuit hash: `"NovaMPC-v2/circuit-hash/v1"`
- Transcript: `"NovaMPC-v2/transcript/v1"`
- Challenge RNG: `"NovaMPC-v2/challenge-rng/v1"`
- Context hash: `"NovaMPC-v2/context/v1"`
- Poseidon2 tags: leaf `1`, node `2`, root `3`; empty-leaf marker `2^32`
- Commitment/seed-tree domain separation: see `src/v2/commitment.rs`,
  `src/v2/seed_tree.rs`, and their tests

### 6.3 Dependency pins

| Crate | Locked version | Use |
|---|---|---|
| `ark-bn254` | 0.6.0 | BN254 `Fr` arithmetic |
| `ark-ff` | 0.6.x | Field trait implementation |
| `blake3` | 1.8.5 | Commitments, transcript, context, seed tree |
| `rand_chacha` | 0.3.1 | Party RNG and challenge sampling |
| `sha3` | 0.10.9 | v1 legacy only; not part of v2 proof |
| `serde` / `bincode` | per lockfile | v1 legacy serialization; v2 uses a custom canonical codec |

The v2 proof encoding is custom, not `bincode`. Do not confuse a v1 serialized
proof with a v2 proof; the magic and version checks are tested.

---

## 7. Test evidence

### 7.1 Commands run before audit preparation

```text
cargo test --lib v2:: -- --test-threads=1
cargo test --test v2_integration --test v2_soundness_gap --test v2_transaction --test v2_parameter_arithmetic -- --test-threads=1
cargo test --test v2_adversarial --test v2_transaction --test v2_integration --test v2_soundness_gap -- --test-threads=1
cargo clippy --all-targets
```

Observed after Step 06:

- 99 v2 library tests passed.
- 6 v2 integration tests passed.
- 2 soundness-gap tests passed: the range forgery and the combined-circuit port.
- 1 parameter-arithmetic test passed.
- 5 transaction tests passed.
- 8 adversarial tests passed.
- Clippy reports style warnings in v1/v2 (manual `is_multiple_of`, loop-index
  lints, and a few simplifications); no errors. These are not security findings.

### 7.2 High-M evidence

The ignored high-M test was run in release mode:

```text
cargo test --release --test v2_high_m -- --ignored --nocapture
```

Observed on the benchmark host (range-only `10 <= x <= 1000`, `x = 42`):

| Preset | `M` | proof bytes | prove ms | verify ms |
|---|---:|---:|---:|---:|
| `secure_127()` | 223 | 2,279,379 | 114 | 43 |
| `secure_127_grinding_2_32()` | 277 | 2,853,947 | 127 | 53 |

These are local CPU-only measurements, not deployment latencies. The proof
sizes are for the range-only circuit; membership and combined proofs are much
larger (see `V2_BENCHMARKS.md`). Do not reduce `M` to make the test faster.

### 7.3 Adversarial evidence

`tests/v2_adversarial.rs` covers statement/root substitution, context replay,
membership/path tampering, serialization bounds, and v1/v2 format separation.
`tests/v2_integration.rs` and `tests/v2_transaction.rs` cover the honest public
API and the transaction trust boundary. `tests/v2_soundness_gap.rs` records both
the range forgery and its successful port to the combined circuit; that is a
known protocol gap, not a fixed regression.

### 7.4 Full-suite status

`cargo test --all-targets` is known to be slow in this repository. At the time
of this package the v2-specific suites above are green; a full all-targets run
must be recorded in Step 08, or the omitted suites listed explicitly. Do not
claim a full green run without evidence.

---

## 8. Known gaps and non-claims

1. **2/3, not 1/3.** The implemented opening schedule has a concrete 2/3
   forgery. The parameter choice pays for it with repetitions; it does not
   eliminate it. The forgery also ports to the combined range+membership
   circuit, so it is structural rather than range-specific.
2. **Knowledge soundness.** The three-opening argument is special soundness
   only; the Fiat-Shamir extractor and its losses are unresolved.
3. **Zero knowledge.** The simulator sketch lacks commitment hiding, seed-tree
   hiding, Fiat-Shamir programmability, distribution, and side-channel proofs.
4. **Side channels.** No constant-time/zeroization claim.
5. **Poseidon2.** Parameter security is an external assumption; the constants
   are pinned and KAT-tested but not independently cryptanalysed here.
6. **Field/hash ceiling.** ~127 bits for BN254 `Fr`; no 128-bit end-to-end
   claim.
7. **Trust boundary.** The caller must authenticate the root/statement; the
   library does not.
8. **Context.** Context binding prevents cross-context replay for the bound
   context; it does not replace an outer transaction nonce or ledger replay
   control.
9. **v1.** Legacy, 32-bit root, not part of the v2 secure path.
10. **Deployment.** Not production-ready; no deployment approval.

---

## 9. Reviewer sign-off

| Reviewer | Date | Scope | Findings | Verdict |
|---|---|---|---|---|
| _unassigned_ | — | 2/3 soundness and extraction | — | **AWAITING REVIEW** |
| _unassigned_ | — | Knowledge soundness / ZK | — | **AWAITING AUDIT** |
| _unassigned_ | — | Side channels / primitives | — | **AWAITING AUDIT** |
| _unassigned_ | — | API trust boundary / serialization | — | **AWAITING AUDIT** |

A reviewer must be named and the verdict recorded before any claim of
production security, proven soundness, audit completion, or 128-bit security.

---

## 10. Reproduction

```bash
cargo test --lib v2:: -- --test-threads=1
cargo test --test v2_integration --test v2_soundness_gap --test v2_transaction --test v2_parameter_arithmetic --test v2_adversarial -- --test-threads=1
cargo test --test v2_soundness_gap -- --nocapture
cargo test --test v2_parameter_arithmetic -- --nocapture
cargo test --release --test v2_high_m -- --ignored --nocapture
cargo clippy --all-targets
```

The soundness-gap test intentionally accepts a false statement for two of the
three hidden choices. It is evidence of the 2/3 event, not a security
qualification.
