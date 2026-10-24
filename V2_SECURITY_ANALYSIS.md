# NovaMPC v2 security analysis

**Status:** implementation analysis and conditional proof draft.  
**Review status:** `DRAFT / AWAITING EXTERNAL REVIEW` for the 2/3 soundness
argument; `AWAITING AUDIT` for knowledge soundness, zero knowledge, side
channels, and primitive assumptions.  
**Code baseline:** v2 proof format version 3 after `[STEP-02]` (commit
`d8840e3`).  
**Companion dossier:** [`V2_SOUNDNESS_2_3.md`](V2_SOUNDNESS_2_3.md).

This document is not a machine-checked proof, an independent audit, or a
deployment qualification. It does not establish knowledge soundness, zero
knowledge, side-channel resistance, or production security. The v2 path must
not be described as `secure`, `audited`, `128-bit`, or production-ready on the
basis of this document.

## 1. Result summary

| Property | Current result |
|---|---|
| Completeness | Honest proofs for satisfying witnesses verify, conditional on deterministic encoding and implementation correctness. |
| Soundness, one repetition | Conditional lemma: for a fixed pre-challenge prefix and a false statement, at most two of the three hidden-party choices can pass. Per-repetition error at most `2/3`. |
| Overall soundness | Conditional `q * (2/3)^M` bound, where `q` is the number of transcript/prefix queries. |
| Tightness | A concrete false range statement is accepted for two of the three hidden choices and rejected only for the third. The 2/3 bound is tight for this schedule. |
| Knowledge soundness | **Not established.** The three-opening argument is a special-soundness observation; the Fiat-Shamir extractor is unresolved. |
| Zero knowledge | **Not established.** The simulator sketch lacks commitment hiding, seed-tree hiding, Fiat-Shamir programmability, distribution, and side-channel proofs. |
| Deployment | **Do not deploy v2 as production cryptography.** The current claim is implementation plus tests plus a conditional proof draft. |
| Security cap | BN254 `Fr` roots give approximately a **127-bit** generic collision ceiling. Do not claim 128-bit end-to-end security. |

The 2/3 bound is a real limitation of the implemented 2-of-3 opening schedule,
not a heuristic that can be relabelled as 1/3. The protocol keeps the 2/3
schedule and pays for it with repetitions `M = 223` at `q = 1` or `M = 277` at
`q = 2^32`.

## 2. v3 protocol and trust boundary

### 2.1 Statement pinning and context

For a statement `st`, the verifier recompiles the canonical circuit
`C_st = compile_from_statement(st)` and hashes it. The relation is
`R_st = { w : C_st.evaluate(w) = Ok }`.

The only public authorization verifiers are:

```rust
verify_statement(proof, expected_statement, expected_context, params)
verify_bytes_statement(bytes, expected_statement, expected_context, params)
```

Both compare `proof.statement` and `proof.context` with the caller's expected
values before running the crate-private `verify`. The raw verifier is not a
public API.

Proof format version 3 stores `context: [u8; 32]`, the BLAKE3-derived
`hash_context_v2(raw_context)`. The context is in the proof, the canonical
serialization, and the Fiat-Shamir transcript. Version-2 proofs have no context
field and are rejected. There is no compatibility path.

### 2.2 Transaction API trust boundary

`v2::transaction::verify_transaction_proof_v2` builds the expected combined
statement from the caller's `TransactionStatementV2` only. It never derives the
root, range, member count, depth, or context from the proof. The expected
statement must come from authenticated ledger or consensus state. The library
verifies a relation about that statement; it does not authenticate the
statement or the root.

The transaction root is a BN254 `Fr`, not the v1 `u32` root. The v1 transaction
API remains legacy and is not used by the v2 module.

### 2.3 Transcript

For each repetition `i`, the proof commits to three party views and publishes
one assertion row per `AssertEq` gate. The pre-challenge prefix contains all
commitment roots `R_i` and assertion rows. The transcript absorbs the suite
identifiers, `N`, `M`, the context hash, the statement values, the canonical
circuit hash, every `R_i`, and every assertion row. It then derives one hidden
party per repetition:

```text
transcript = transcript_hash(st, context, params, circuit_hash, roots, rows, suite)
seed       = BLAKE3.derive_key("NovaMPC-v2/challenge-rng/v1", transcript)
H_i        = ChaCha20Rng(seed).gen_range(0..3)
```

The prover opens the two parties other than `H_i`. The verifier reconstructs the
opened seeds, recomputes each opened view, checks its commitment and path,
checks linear gates, checks one Mul edge, and checks every assertion row.

With `N = 3`, exactly one Mul edge is skipped for each hidden party: the edge
whose source is the opened party immediately before the hidden party. The
hidden party's assertion share is checked only through the row sum. These two
facts are the source of the 2/3 event.

## 3. Assumptions

The conditional bound uses these assumptions. None is a theorem about the
implementation today.

| ID | Assumption | Status |
|---|---|---|
| A1 | Canonical circuit faithfully encodes the range/membership/combined relation, including the pinned Poseidon2 gadget | Tests and code inspection; no formal refinement proof |
| A2 | BLAKE3 view commitment and `CommitTreeV2` are binding under the domain-separated encoding | Cryptographic assumption; generic collision ceiling about 128 bits for BLAKE3, about 127 bits for BN254 field elements |
| A3 | Transcript encoding is injective; for a fixed prefix the challenge vector is uniform and independent | Encoding has tamper tests; BLAKE3/ChaCha20 path is an idealisation, not proven |
| A4 | Additive sharing, zero-share telescoping, and Mul reconstruction algebra | Proved algebraically and unit-tested |
| A5 | `sample_fr` rejection sampling and canonical `Fr` decoding | Implementation plus tests; no formal uniformity/side-channel proof |
| A6 | No implementation, decoding, allocation, panic, timing, or side-channel failure | Not proven; independent audit required |

The analysis is specific to `N = 3`; the code rejects other party counts.

## 4. Soundness

### 4.1 Per-repetition lemma

Fix one repetition, one commitment root, one assertion-row tuple, and a false
statement. Suppose all three hidden choices `h in {0,1,2}` have a passing local
opening for the same prefix. For each party `p`, extract its view from an
opening where `p` is not hidden. Commitment binding makes the two appearances
of each party the same committed view. Linear gates are checked in at least one
opening. Each Mul edge `p -> p+1` is checked when the hidden party is `p+2`, so
all Mul equations hold across the three openings. Every assertion share is
checked for each party in some opening, and the row sum gives
`sum_p W_p[wire] = expected`. Summing the per-party equations reconstructs a
witness `w` with `C_st.evaluate(w) = Ok`, contradicting falsity.

Therefore, for a fixed prefix and a false statement, at most two of the three
hidden choices can pass. This is the 2/3 event.

The full argument, including the skipped-Mul edge and assertion-share cases, is
in [`V2_SOUNDNESS_2_3.md`](V2_SOUNDNESS_2_3.md), Section 5.

### 4.2 Parallel repetition and grinding

With `M` independent repetitions and `q` transcript/prefix queries, the union
bound is

```text
Pr[false proof accepted] <= q * (2/3)^M
```

and the corresponding bits are

```text
M * log2(3/2) - log2(q) = 0.584962500721... * M - log2(q).
```

`q` includes grinding attempts and every prefix the adversary can have hashed
and then use. It is not a fixed small constant.

### 4.3 Tightness attack

`tests/v2_soundness_gap.rs` constructs the false statement `10 <= x <= 100`
with `x = 101`. The private slack is `-1`, whose first slack bit is not boolean.
The forgery subtracts the failing product from party 0's Mul-output share and
publishes a matching assertion row. Hidden party 0 skips the bad edge; hidden
party 1 skips the edge from party 0 to hidden party 1; hidden party 2 checks
the bad edge and rejects. Thus two of three choices accept. The test samples 48
Fiat-Shamir challenges and observes both outcomes. This demonstrates that the
2/3 bound is tight for the implemented schedule.

The same attack ports to the combined circuit: a valid member outside the
claimed range, with only the range booleanity constraints broken, is accepted
for two hidden choices. See
`known_gap_ports_to_combined_range_and_membership` in the same test file. This
confirms the gap is structural (skipped Mul edge plus hidden assertion share),
not range-circuit-specific. It remains a known, unfixed protocol gap.

The attack uses no hash collision and no cryptanalytic break. It uses only the
hidden assertion-share gap and the skipped Mul edge.

## 5. Knowledge soundness and extraction

The three-opening lemma is a **special-soundness** observation, not a
single-proof extractor. A single accepting proof hides one view, skips one Mul
edge, and checks the hidden assertion share only through the row sum.

To obtain knowledge soundness for the deployed Fiat-Shamir transform, an
extractor would need three accepting openings for the same pre-challenge prefix
and repetition with different hidden choices. The following are unresolved:

- a forking lemma for the exact `transcript_hash -> BLAKE3 derive_key ->
  ChaCha20Rng -> gen_range(0..3)` path, including the vector challenge and PRG
  state;
- the concrete extraction loss and running time as a function of `M`, `q`, and
  the number of accepting transcripts;
- preservation of the same commitment roots and assertion rows under rewinding;
- extraction of the hidden view from a single transcript;
- a proof that the extracted witness satisfies the caller's expected statement.

Loss terms that a future proof must account for include `q`, the forking
probability, commitment binding, transcript encoding, field/hash collision
ceilings, the ideal-challenge/PRG model, the canonical relation and Poseidon2
assumptions, and implementation/side-channel failures.

**No knowledge-soundness claim is made.**

## 6. Zero knowledge

The simulator sketch is standard MPC-in-the-head: choose the hidden party per
repetition, build a seed tree and co-path, make the two opened views consistent
on their one checked Mul edge, commit an arbitrary hidden view, set the hidden
assertion share to `expected - sum(opened shares)`, and program the challenge.
It is not a proof.

Missing steps:

- commitment hiding for `commit_view_v2`;
- seed-tree hiding for the BLAKE3-derived tree and co-path;
- Fiat-Shamir programmability for the concrete primitive;
- the joint distribution of roots, rows, opened views, and hidden commitments;
- MPC privacy for the full wire trace, Mul shares, assertion rows, seed tree,
  and Poseidon2 gadgets;
- serialization-length variation, timing, allocation, and error side channels.

**No zero-knowledge claim is made.**

## 7. Parameters and the 127-bit ceiling

The BN254 `Fr` root and commitment-tree field elements have a generic collision
ceiling of approximately 127 bits. BLAKE3 has a generic collision ceiling of
approximately 128 bits. The proof-soundness margin does not raise the overall
cap above 127 bits.

| `M` | Bits at `q=1` | Bits at `q=2^20` | Bits at `q=2^32` | Role |
|---:|---:|---:|---:|---|
| 96 | 56.16 | 36.16 | 24.16 | `balanced()`; test/benchmark only |
| 218 | 127.52 | 107.52 | 95.52 | bare minimum at `q=1` |
| 223 | 130.45 | 110.45 | 98.45 | recommended `secure_127()` |
| 272 | 159.11 | 139.11 | 127.11 | bare minimum at `q=2^32` |
| 277 | 162.03 | 142.03 | 130.03 | recommended `secure_127_grinding_2_32()` |

`M = 219` is an old benchmark setting, not the target parameter. The target is
`M = 223` for `q = 1` or `M = 277` for `q = 2^32`, with the overall claim
capped at ~127 bits. These are the parameters the transaction API documents for
deployment review. They are not a licence to claim production security before
the review gates close.

## 8. Code map

| Code | Role |
|---|---|
| `src/v2/suite.rs` | `V2_PROOF_VERSION = 3`, `N = 3`, `V2Params`, version/suite identifiers, secure presets |
| `src/v2/proof.rs::hash_context_v2` | Domain-separated context hash |
| `src/v2/proof.rs::prove` | Canonical circuit check, witness check, MPC repetitions, commitments, assertion rows, context-bound transcript |
| `src/v2/proof.rs::verify` | Crate-private structural, transcript, commitment, view, and assertion checks |
| `src/v2/proof.rs::verify_statement` | Mandatory expected statement and context pinning |
| `src/v2/proof.rs::verify_bytes_statement` | Serialized safe verifier |
| `src/v2/proof.rs::transcript_hash` | Binds suite, context, statement, circuit hash, roots, rows |
| `src/v2/proof.rs::derive_challenges` | BLAKE3 seed + ChaCha20 `gen_range(0..3)` |
| `src/v2/mpc.rs::run_mpc_emulation` | Honest 3-party emulation and view generation |
| `src/v2/mpc.rs::recompute_linear_shares` | Verifier-side view recomputation |
| `src/v2/mpc.rs::verify_party_view` | Linear checks and conditional Mul-edge check |
| `src/v2/predicate.rs::constrain_bits` | Boolean bit constraints; the false slack bit exploits the hidden-share gap |
| `src/v2/commitment.rs::commit_view_v2` | View commitment |
| `src/v2/commit_tree.rs` | Commitment Merkle tree and path verification |
| `src/v2/seed_tree.rs` | Seed tree and co-path reconstruction (no checked root) |
| `src/v2/transaction.rs` | Caller-authenticated `Fr` root, statement pinning, context, safe transaction verifier |
| `tests/v2_soundness_gap.rs` | Executable false-statement forgery |
| `tests/v2_parameter_arithmetic.rs` | Deterministic M/q arithmetic checks |
| `tests/v2_transaction.rs` | Root-substitution and context-substitution regressions |

## 9. Review gate and deployment status

| Gate | Status |
|---|---|
| 2/3 bound and tightness argument | **AWAITING EXTERNAL REVIEW** |
| Fiat-Shamir knowledge-soundness extraction | **UNRESOLVED / AWAITING REVIEW** |
| Zero knowledge | **UNRESOLVED / AWAITING AUDIT** |
| Side channels and primitive assumptions | **AWAITING AUDIT** |
| Production deployment | **NOT CLAIMED** |
| 128-bit end-to-end security | **NOT CLAIMED** |

The required sign-off table is in
[`V2_SOUNDNESS_2_3.md`](V2_SOUNDNESS_2_3.md), Section 10. The audit package and
reviewer table are in [`V2_AUDIT_PACKAGE.md`](V2_AUDIT_PACKAGE.md). Until a
named external reviewer signs, the status is `DRAFT / AWAITING REVIEW` and
`AWAITING AUDIT`.

## 10. Reproduction

```bash
cargo test --test v2_soundness_gap -- --nocapture
cargo test --test v2_parameter_arithmetic -- --nocapture
cargo test --lib v2:: -- --test-threads=1
cargo test --test v2_transaction -- --test-threads=1
```

The soundness-gap test intentionally accepts a false statement for two of the
three hidden choices. It is evidence for the 2/3 event, not a security
qualification.
