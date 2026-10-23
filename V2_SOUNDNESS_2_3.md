# NovaMPC v2 2/3 Soundness and Extraction Dossier

**Status:** `DRAFT / AWAITING EXTERNAL REVIEW`  
**Scope:** v2 proof format version 3, BN254 `Fr`, `N = 3`, the implemented 2-of-3 opening schedule.  
**Code baseline:** commit `d8840e3` (`[STEP-02] Add v2 transaction API with Fr root and context`), plus the Step 03 documentation and arithmetic-test changes.

This document is a proof draft and an explicit gap report. It is not a
machine-checked proof, an independent review, or an audit. It does not claim
knowledge soundness, zero knowledge, side-channel resistance, or production
readiness. Steps 03 and 05 are review gates; an implementation agent cannot
sign them off on its own.

The broader implementation analysis is in
[`V2_SECURITY_ANALYSIS.md`](V2_SECURITY_ANALYSIS.md). The audit package is
[`V2_AUDIT_PACKAGE.md`](V2_AUDIT_PACKAGE.md).

---

## 1. Scope and non-claims

### 1.1 In scope

- The relation encoded by `compile_from_statement` for range, membership, and
  combined v2 statements.
- The proof-format-v3 transcript: suite identifiers, statement, context hash,
  canonical circuit hash, commitment roots, and assertion rows.
- The 2-of-3 opening schedule implemented by `src/v2/mpc.rs`.
- The per-repetition soundness claim and its parallel-repetition/query-loss
  accounting.
- The limits of the three-transcript extraction argument.

### 1.2 Out of scope / not claimed

- A Fiat-Shamir knowledge-soundness theorem for the concrete BLAKE3/ChaCha20
  challenge path.
- A zero-knowledge theorem or a simulation proof.
- Side-channel or constant-time behaviour.
- Concrete cryptanalysis of the pinned Poseidon2 instance.
- Authentication of the set root or transaction statement. That is the
  caller's trust boundary (see `v2::transaction`).
- v1. v1 is legacy and uses a 32-bit membership root.

### 1.3 Review status

| Gate | Status |
|---|---|
| Internal proof draft | written in this document |
| Independent cryptographic review of the 2/3 bound and extraction | **AWAITING REVIEW** |
| Independent audit of knowledge soundness, ZK, side channels, primitives | **AWAITING AUDIT** |

---

## 2. Protocol and transcript (v3)

### 2.1 Statement and relation

For a public `StatementV2 st`, the verifier recompiles the canonical circuit
`C_st = compile_from_statement(st)` and hashes it with
`hash_circuit_v2(C_st)`. The relation is

```text
R_st = { w : C_st.evaluate(w) = Ok }.
```

The public statement values (range bounds, root, member count, depth) are
circuit constants; the witness is private. The proof carries `st`, but external
callers must use `verify_statement`, which compares the proof's statement with
the caller's expected statement before doing any cryptographic check.

### 2.2 Proof version 3

`V2Proof` carries:

```text
version = 3
params  = (N, M)
statement
context : [u8; 32]          // hash_context_v2(raw context)
repetitions : [RepetitionProofV2; M]
```

`hash_context_v2` is BLAKE3 keyed by `"NovaMPC-v2/context/v1"`, with an 8-byte
big-endian length prefix before the raw context. The length prefix prevents
concatenation ambiguity. A version-2 proof has no context field and is rejected
by `from_bytes`; there is no compatibility path.

The public verifiers are:

```rust
verify_statement(proof, expected_statement, expected_context, params)
verify_bytes_statement(bytes, expected_statement, expected_context, params)
```

Both compare the expected statement and context before invoking the
crate-private `verify`. The raw verifier is not a public authorization API.

### 2.3 One repetition

For each repetition `i`:

1. The prover samples a seed tree and runs the 3-party MPC emulation.
   Party 0 and party 1 input shares are seed-derived; party 2 receives the
   residual. Multiplication outputs use

   ```text
   z_p = x_p y_p + x_p y_{p+1} + x_{p+1} y_p + r_p(g),
   r_p(g) = PRF(seed_p, g) - PRF(seed_{p+1}, g).
   ```

2. The prover publishes one assertion row per `AssertEq` gate, with one share
   per party.
3. The prover commits to each party view. The committed payload binds the party
   seed, its Mul-output shares, and (party 2 only) its residual input shares.
   The three commitments form a `CommitTreeV2` with root `R_i`.
4. The pre-challenge prefix `P` contains all `R_i` and all assertion rows. The
   transcript absorbs the suite identifiers, `N`, `M`, the context hash, the
   statement values, the canonical circuit hash, every `R_i`, and every
   assertion row. It then derives one hidden-party index per repetition:

   ```text
   transcript = transcript_hash(st, context, params, circuit_hash, roots, rows, suite)
   seed       = BLAKE3.derive_key("NovaMPC-v2/challenge-rng/v1", transcript)
   H_i        = ChaCha20Rng(seed).gen_range(0..3)
   ```

5. The proof opens the two parties other than `H_i`, with the seed-tree
   co-path, Mul-output shares, residual shares, commitment randomness, and
   commitment-tree authentication paths. The hidden view remains committed and
   is not opened.

### 2.4 What the verifier checks per repetition

1. `rep.hidden_party == H_i`.
2. The co-path reconstructs the leaves of the two opened parties.
3. Each opened view is recomputed from its seed, Mul-output shares, and (party
   2) residual shares.
4. Each opened view commitment matches its leaf and the leaf folds to `R_i`.
5. `verify_party_view` checks the opened party's linear gates. A Mul edge
   `p -> p+1` is checked only when both endpoints are opened. With `N = 3` and
   hidden party `h`, exactly one Mul edge is skipped: the edge whose source is
   the opened party immediately before `h`.
6. For every assertion, an opened party's published share must equal its
   recomputed share; the three published shares must sum to the expected
   constant.

The hidden view, its assertion share, and the skipped Mul edge are not tied
together in one proof. This is why the per-repetition error is 2/3 rather than
1/3, and why a single-proof witness extractor does not follow.

---

## 3. Assumptions

These are the same assumptions as `V2_SECURITY_ANALYSIS.md`; none is a theorem
about the implementation.

- **A1 (canonical relation).** For every accepted `StatementV2`, the recompiled
  circuit faithfully encodes the intended range/membership/combined relation,
  including the pinned Poseidon2 membership gadget. Tests are not a refinement
  proof.
- **A2 (commitment binding).** The BLAKE3 view commitment and `CommitTreeV2`
  are binding under the stated domain separation and encoding. The generic
  collision ceiling is about 128 bits for BLAKE3 and about 127 bits for the
  BN254 field elements used in the tree.
- **A3 (transcript encoding and ideal challenge).** The transcript encoding is
  injective on the bound values, and for a fixed pre-challenge prefix the
  derived challenge vector is uniform over `{0,1,2}^M` and independent of the
  prefix. The concrete BLAKE3/ChaCha20 derivation is treated as an
  idealisation, not a proven property.
- **A4 (MPC algebra).** Additive sharing reconstructs; linear gates are local;
  the three zero shares telescope to zero; the Mul formula reconstructs to
  `x*y`. These are algebraic facts and are unit-tested.
- **A5 (canonical field sampling/encoding).** `sample_fr` rejection-samples
  canonical BN254 `Fr` values, and `decode_fr` rejects non-canonical encodings.
  Uniformity is assumed, not formally proved.
- **A6 (implementation).** Structural validation, allocation bounds, decoder
  strictness, panic freedom, timing, and side channels are assumed safe. This
  is not established by the current tests or by self-review.

The argument is specific to `N = 3`; the code rejects other party counts.

---

## 4. Completeness

**Lemma 1 (honest completeness).** Let `st` be a statement and `w` a witness
with `C_st.evaluate(w) = Ok`. If `prove` and `verify_statement` run without
implementation failures, then an honest proof verifies with the same statement
and context.

**Proof sketch.** `prove` recompiles `C_st`, checks the witness length and
evaluation, and runs the honest MPC emulation. The co-path reconstructs the two
opened seeds; `recompute_linear_shares` reproduces each opened view; the
commitment and authentication path fold to `R_i`; `verify_party_view` passes
for the opened linear gates and the one checked Mul edge; assertion shares are
the actual shares and sum to the asserted constant; and the prover uses the
same derived `H_i`. All checks pass. This is a standard completeness argument
conditioned on A1, A4, A5, and deterministic encoding.

Completeness says nothing about soundness, knowledge soundness, or zero
knowledge.

---

## 5. Per-repetition soundness

### 5.1 Lemma 2 (three openings extract a witness)

Fix one repetition index `i`, one commitment root `R_i`, one assertion-row
tuple, and a statement `st`. Suppose that for each hidden value `h in {0,1,2}`
there is an opening `O_h` that passes all repetition-local verifier checks when
the hidden party is `h`. Under A1-A6, there exists a witness `w` with
`C_st.evaluate(w) = Ok`.

**Proof.**

For each party `p`, choose any `h != p` and read party `p`'s opened view from
`O_h`. Party `p` is opened for two of the three hidden values. By commitment
binding (A2), the seed, payload, and randomness extracted from those two
openings are the same committed tuple; otherwise the two openings would give a
collision in the view commitment or commitment tree.

Let `W_p` be the full wire-share vector computed by
`recompute_linear_shares` from party `p`'s extracted view. The verifier checked
the linear gates for that view in at least one opening, so all linear gates
hold for `W_p`.

For each Mul gate, consider the edge `p -> p+1`. It is checked when the hidden
party is `p+2 (mod 3)`, because then both `p` and `p+1` are opened. The three
openings cover all three values of `p`, so every Mul equation holds for the
extracted views. This is the multi-transcript replacement for the single-proof
hidden-neighbour check.

For each assertion row `A_j` and party `p`, party `p` is opened in at least one
of the three openings. In that opening, the verifier checked
`A_j[p] == W_p[wire_j]`. The row is part of the fixed prefix, so its entries are
the same in all three openings. The row-sum check gives
`sum_p A_j[p] = expected_j`, hence `sum_p W_p[wire_j] = expected_j`. Every
assertion is satisfied by the reconstructed wire values.

Define the witness `w` by summing the three extracted input-share vectors. By
induction over the canonical gate order, the summed per-party equations give
the native gate equations: linear gates sum directly, multiplication gates sum
to `(sum_p W_p[left]) * (sum_p W_p[right])` by the MPC algebra lemma, and every
`AssertEq` is satisfied by the previous paragraph. Therefore
`C_st.evaluate(w) = Ok`. QED.

### 5.2 Corollary 1 (at most two hidden choices)

Fix a pre-challenge prefix and a false statement `st`. For each repetition, at
most two of the three possible hidden values can have a passing local opening.

**Proof.** If all three passed, Lemma 2 would produce a witness for `st`,
contradicting that `st` is false. QED.

### 5.3 Theorem 1 (conditional 2/3 per-repetition bound)

Assume A1-A6. Fix a false statement and a pre-challenge prefix
`P = ((R_i, A_i))_{i=1..M}`. If the challenge vector
`H = (H_1,...,H_M)` is uniform over `{0,1,2}^M` and independent of `P`, then
the probability that a full accepting proof exists for prefix `P` is at most

```text
(2/3)^M.
```

**Proof.** By Corollary 1, for each coordinate `i` at most two of the three
values of `H_i` are admissible. A full proof can pass only if every coordinate
is admissible, so at most `2^M` of the `3^M` challenge vectors are admissible.
Under the uniform independent challenge model the probability is at most
`2^M / 3^M = (2/3)^M`. QED.

### 5.4 Tightness: the concrete forgery

The bound is not merely an upper bound. `tests/v2_soundness_gap.rs` constructs
a false range statement `10 <= x <= 100` with `x = 101`. The private slack is
`hi - x = -1`; its first slack bit is `-1` instead of a boolean, and the
boolean assertion `b(b-1) = 0` fails with value `2`.

The forgery:

1. Takes party 0's honest Mul-output share `m_0` for the failing boolean gate
   and replaces it with `m_0 - 2`, keeping `m_1` and `m_2`.
2. Recomputes party 0's view with the modified share and publishes the
   assertion row `(m_0 - 2, m_1, m_2)`, whose sum is zero.
3. Parties 1 and 2 remain honest.

For hidden `h = 0`, party 0 is hidden and its bad Mul edge is skipped; the
opened parties and the row sum pass. For hidden `h = 1`, party 0 is opened, but
its bad edge points to hidden party 1 and is skipped; the row matches party 0's
modified view. For hidden `h = 2`, party 0's edge to party 1 is checked and
fails. Therefore two of the three hidden choices accept. The test samples 48
Fiat-Shamir challenges and observes both outcomes; it is evidence for the
mechanism, not a precise probability estimate. Theorem 1 and this attack show
that `2/3` is tight for the implemented schedule.

### 5.5 Why not 1/3

A 1/3 claim would require binding the hidden party's assertion share to its
committed view and recovering the skipped Mul edge without opening the hidden
view, or a different opening schedule. Neither is implemented. The current code
therefore has a real 2/3 per-repetition error, not a heuristic that can be
relabelled as 1/3.

---

## 6. Parallel repetition and query loss

If an adversary makes `q` transcript/prefix queries, the union bound gives

```text
Pr[false proof accepted] <= q * (2/3)^M.
```

The corresponding soundness "bits" are

```text
M * log2(3/2) - log2(q) = 0.584962500721... * M - log2(q).
```

`q` is the number of distinct pre-challenge prefixes the adversary can have
hashed and then use. A grinding adversary can abandon prefixes and retry; `q`
must include those attempts. A larger `q` lowers the level linearly in bits.

| `M` | `q = 1` | `q = 2^20` | `q = 2^32` | Role |
|---:|---:|---:|---:|---|
| 96 | 56.16 | 36.16 | 24.16 | `balanced()`; test/benchmark only, not secure |
| 218 | 127.52 | 107.52 | 95.52 | bare minimum at `q=1`, no margin |
| 223 | 130.45 | 110.45 | 98.45 | recommended `secure_127()` at `q=1` |
| 272 | 159.11 | 139.11 | 127.11 | bare minimum at `q=2^32`, no margin |
| 277 | 162.03 | 142.03 | 130.03 | recommended `secure_127_grinding_2_32()` |

The overall claim is capped at approximately **127 bits**, not 128, by the
BN254 `Fr` root and commitment-tree field elements. The proof-soundness column
can exceed 127 at the recommended settings; the collision ceiling does not move.
`M = 219` is an old benchmark setting and is not the target parameter.

---

## 7. Knowledge soundness and extraction

### 7.1 What the three-opening argument gives

Lemma 2 is a **special-soundness** statement. It says that three local openings
for the same prefix and the same repetition, with hidden choices 0, 1, and 2,
extract a witness. This is enough for Corollary 1 and for the counting bound in
Theorem 1.

It is not a single-proof extractor. A single accepting proof hides one view,
skips one Mul edge, and checks the hidden assertion share only through the row
sum. There is no straight-line extraction of the hidden view from one
transcript.

### 7.2 Unresolved Fiat-Shamir forking argument

To obtain a knowledge-soundness theorem for the deployed transform, an
extractor would need three accepting openings for the same pre-challenge prefix
and repetition with different hidden choices. In the random-oracle model this
requires rewinding or programming the challenge derivation. The following are
not established:

- a forking lemma for the exact `transcript_hash -> BLAKE3 derive_key ->
  ChaCha20Rng -> gen_range(0..3)` path, including the PRG state and the
  vector-of-challenges structure;
- the concrete extraction loss and running time as a function of `M`, `q`, and
  the number of accepting transcripts;
- that rewinding preserves the same commitment roots and assertion rows rather
  than letting the prover change its prefix;
- that the extracted witness satisfies the caller's expected statement, not a
  different canonical circuit;
- any extraction of the single-proof hidden view.

A generic forking lemma could be invoked as a heuristic, but the challenge
space is `3^M`, the accepting set has size at most `2^M`, and the prefix is a
vector of commitments. No concrete theorem for this code is claimed.

### 7.3 Loss terms that a future proof must account for

1. Transcript/prefix query loss `q`.
2. The probability of obtaining a fork and the extraction running time.
3. Commitment-binding failure (BLAKE3 / tree collision).
4. Transcript encoding collision or ambiguous decoding.
5. Field/hash collision ceilings.
6. The ideal-challenge/PRG idealisation.
7. The canonical-relation and Poseidon2 assumptions.
8. Implementation, decoding, and side-channel failures.

### 7.4 Status

**No knowledge-soundness claim is made.** The implementation has a conditional
soundness bound and a special-soundness observation; it does not yet have a
deployed Fiat-Shamir extractor.

---

## 8. Zero knowledge

### 8.1 Simulator sketch

For a true statement, a simulator could choose the hidden party per repetition,
build a seed tree and co-path, choose the two opened views so their one checked
Mul edge is consistent, commit an arbitrary hidden view, set each hidden
assertion share to `expected - sum(opened shares)`, build the roots and rows,
and program the challenge derivation to select the chosen hidden parties. This
is the standard MPC-in-the-head simulation shape.

### 8.2 Missing proof steps

The sketch is not a proof. The unresolved steps are:

- **Z1 (commitment hiding).** No indistinguishability proof for
  `commit_view_v2` or its domain separation.
- **Z2 (seed-tree hiding).** No PRG/indistinguishability argument for the
  BLAKE3-derived seed tree and co-path.
- **Z3 (Fiat-Shamir programmability).** Real BLAKE3 is not programmable; the
  ROM heuristic is not a proof for the concrete primitive.
- **Z4 (assertion-row distribution).** No proof that the simulated joint
  distribution of roots, rows, opened views, and hidden commitments matches the
  real prover's.
- **Z5 (MPC privacy).** The full wire trace, Mul shares, assertion rows, seed
  tree, and Poseidon2 gadgets have not been analysed as one distribution.
- **Z6 (metadata and side channels).** Serialization length variation (party 2
  residual shares appear only when party 2 is opened), timing, allocation, and
  error behaviour are not analysed.

**No zero-knowledge claim is made.** The soundness argument does not rely on
hiding, but that is not a ZK theorem.

---

## 9. Parameter decision

- Keep BN254 `Fr`; the root/commitment field collision ceiling is approximately
  127 bits. Do not claim 128-bit end-to-end security.
- Keep the 2/3 schedule; do not redesign to 1/3.
- Bare minima: `M = 218` at `q = 1`, `M = 272` at `q = 2^32`.
- Recommended with margin: `M = 223` at `q = 1`, `M = 277` at `q = 2^32`.
- `balanced()` (`M = 96`) and `fast_insecure()` are test/benchmark presets only.
- The proof margin does not raise the BN254 collision ceiling above 127 bits.

The parameter arithmetic is checked deterministically by
`tests/v2_parameter_arithmetic.rs`.

---

## 10. Review gate

This dossier must not be marked `DONE` or cited as a completed security proof
until a named external cryptographer reviews the 2/3 extraction argument, the
Fiat-Shamir query accounting, and the stated non-claims.

| Reviewer | Date | Scope | Verdict |
|---|---|---|---|
| _unassigned_ | — | Lemma 2, Theorem 1, Attack 1, query loss, extraction gaps | **AWAITING REVIEW** |
| _unassigned_ | — | Knowledge soundness / ZK / side channels / primitives | **AWAITING AUDIT** (Step 05) |

Until sign-off, the status is `DRAFT / AWAITING REVIEW`. README and code comments
must not say the v2 proof is proven, audited, production-secure, or 128-bit.

---

## 11. Reproduction

```bash
cargo test --test v2_soundness_gap -- --nocapture
cargo test --test v2_parameter_arithmetic -- --nocapture
cargo test --lib v2:: -- --test-threads=1
```

The soundness-gap test intentionally accepts a false statement for two of the
three hidden choices. It is evidence of the 2/3 event, not a security
qualification.
