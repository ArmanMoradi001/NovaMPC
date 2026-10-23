# NovaMPC v2 security analysis (STEP-10)

Status: proof attempt and gap report for the v2 protocol at commit
`4ad0a2d` (`[STEP-09] Benchmark and document v2 membership proofs`). This is
not a machine-checked proof, not an independent audit, and not a deployment
qualification. It contains one conditional soundness bound and a concrete
forgery that attains the bound. The v2 path must not be described as
`secure`, `128-bit`, or production-ready on the basis of this document.

The executable evidence for the concrete forgery is
[`tests/v2_soundness_gap.rs`](tests/v2_soundness_gap.rs). The proof attempt and
the gaps are below.

## 1. Result summary

| Property | Result in this document |
|---|---|
| Completeness | Lemma 1: honest proofs for a satisfying witness verify, modulo deterministic hash/PRG reproduction and implementation correctness. |
| Soundness, per repetition | Lemma 2 and Theorem 1: under assumptions A1-A6, a false statement cannot pass all three possible hidden-party choices for one fixed pre-challenge prefix. At most two choices can pass, so the per-repetition error is at most `2/3`. |
| Overall soundness | Conditional Corollary 1: a `q`-query Fiat-Shamir adversary succeeds with probability at most `q * (2/3)^M`. |
| Tightness | Attack 1: a false range statement is accepted for hidden party 0 or 1 and rejected only for hidden party 2. The test samples 48 Fiat-Shamir challenges and observes 27 accepted, 21 rejected at `h = 2`. The `2/3` per-repetition bound is therefore tight for this protocol; no `1/3` claim is possible. |
| Knowledge soundness | Not established. Lemma 2 is a three-transcript special-soundness statement, not a single-proof extractor. The Fiat-Shamir forking extraction is an explicit unresolved lemma (Section 6). |
| Zero knowledge | Not established. Section 7 gives a simulator sketch and the exact missing steps; no simulation theorem is claimed. |
| Deployment | **Do not deploy v2.** At `M = 96` the conditional bound is about `2^-56.16`, not 128-bit. At `M = 219` it is about `2^-128.11` only for one transcript attempt under idealised hashing, and it is capped by the approximately 127-bit generic collision ceiling of BN254 `Fr` plus the query loss. |

The rest of this document is deliberately narrower than a security proof: it
derives the bound that the code actually supports, records the attack that
shows the bound cannot be improved for this opening schedule, and names the
lemmas that are still missing.

## 2. Code baseline and protocol

### 2.1 Baseline

The analysis follows the code in this tree, not an earlier design sketch:

- `src/v2/suite.rs`: `V2_PROOF_VERSION = 3`, `V2_NUM_PARTIES = 3`,
  `V2Params`, suite identifiers.
- `src/v2/proof.rs`: `prove`, the crate-private `verify`, the public
  `verify_statement` and `verify_bytes_statement`, proof-version-3 context
  binding, structural validation, transcript hashing, challenge derivation,
  and the commitment checks. Version 3 binds a 32-byte context hash in the
  proof and transcript; the public verifier pins the caller's expected
  statement and context.
- `src/v2/mpc.rs`: `run_mpc_emulation`, `recompute_linear_shares`,
  `verify_party_view`, `zero_share`, `mul_output_share`.
- `src/v2/predicate.rs`: canonical range, membership, and combined circuits,
  including `constrain_bits`.
- `src/v2/commitment.rs`: `commit_view_v2`.
- `src/v2/commit_tree.rs`: `CommitTreeV2`, `CommitProofV2`.
- `src/v2/seed_tree.rs`: `SeedTreeV2` and
  `reconstruct_leaves_from_co_path`.
- `src/v2/field.rs` and `src/v2/sharing.rs`: canonical field encoding and
  rejection-sampled additive shares.
- `tests/v2_soundness_gap.rs`: the concrete false-statement forgery.

### 2.2 Relation and statement

For a public statement `st`, the verifier recompiles the canonical circuit
`C_st` with `compile_from_statement(st)`, hashes it with `hash_circuit_v2`, and
uses only that circuit. The relation is

```text
R_st = { w : C_st.evaluate(w) = Ok }.
```

`C_st` has only private input wires; the public values (range bounds, set root,
member count, depth) are compiled into constants and assertion gates. The v2
proof carries `StatementV2`; `verify` verifies against the statement embedded
in the proof, while `verify_statement` additionally requires the caller's
expected statement. Applications must use `verify_statement` (or compare
`proof.statement` themselves). `verify` alone is not a statement-pinning API.

### 2.3 One repetition

For each repetition `i = 0 .. M-1`:

1. `prove` samples a seed-tree root, builds `SeedTreeV2`, and runs the 3-party
   emulation with `run_mpc_emulation`. The witness inputs are additively
   shared: parties 0 and 1 draw shares from their seed streams, and party 2
   receives the residual. Multiplication outputs use
   `z_p = x_p y_p + x_p y_{p+1} + x_{p+1} y_p + r_p(g)`, where
   `r_p(g) = PRF(seed_p, g) - PRF(seed_{p+1}, g)`.
2. The prover computes one assertion row per `AssertEq` gate. Each row has one
   share per party.
3. The prover commits to all three party views with `commit_view_v2`. The
   committed view binds the party seed, the party's Mul-output shares, and (for
   party 2 only) its residual input shares. The three commitments are leaves of
   a `CommitTreeV2`; the root is `R_i`.
4. The pre-challenge prefix `P` consists of all roots `R_i` and all assertion
   rows `A_i`. The transcript absorbs the suite identifiers, `N`, `M`, the
   statement's public values, the circuit hash, every `R_i`, and every
   assertion row. The challenge vector is derived only after all of that
   material:

   ```text
   transcript = transcript_hash(statement, params, circuit_hash, roots, rows, suite)
   seed       = BLAKE3 derive_key("NovaMPC-v2/challenge-rng/v1", transcript)
   challenges = ChaCha20Rng(seed).gen_range(0..3) for each repetition
   ```

   `derive_challenges` produces one hidden-party index per repetition. The
   proof carries `hidden_party`, and the verifier requires it to equal the
   derived challenge.
5. The prover opens the two parties other than the challenged hidden party:
   it supplies the seed-tree co-path and each opened party's Mul-output shares,
   residual input shares, commitment randomness, and commitment-tree
   authentication path. The hidden party's view remains committed but is not
   opened.

### 2.4 Verification checks

`verify` performs the following for each repetition, after checking the proof
shape and deriving the challenge vector:

1. `rep.hidden_party` equals the derived challenge.
2. `reconstruct_leaves_from_co_path` reconstructs the seed-tree leaves. The
   hidden leaf is filled with a zero placeholder and is never used as a party
   seed.
3. For each opened view, `recompute_linear_shares` reconstructs every wire
   share from the party seed, the claimed Mul-output shares, and (for party 2)
   the residual input shares.
4. The view commitment is recomputed from the seed and the length-prefixed
   payload and checked against the repetition's commitment root with the
   supplied authentication path.
5. `verify_party_view` checks the opened party's linear gates. A Mul gate is
   checked only if the party's right neighbour is also opened. With `N = 3`
   and hidden party `h`, the opened parties are the other two; exactly one
   opened party has its right neighbour hidden, so exactly one Mul edge is
   skipped per repetition.
6. For every assertion and every opened party, the published assertion share
   must equal the party's recomputed wire share. The sum of all three shares in
   each assertion row must equal the public expected value.

The hidden party's view, its assertion share, and the skipped Mul edge are not
checked against one another in a single proof. This is the source of the
concrete forgery in Section 5.3.

## 3. Security model and assumptions

### 3.1 Adversary and games

- A prover adversary is a probabilistic polynomial-time algorithm that chooses
  a statement and a v2 proof, may query the challenge hash as a random oracle,
  and succeeds if `verify_statement(proof, st, params)` accepts a false `st`.
- The Fiat-Shamir game counts the number of transcript/prefix queries. A query
  fixes a pre-challenge prefix; the challenge vector is the oracle output.
- Completeness uses an honest prover that runs `prove` with a satisfying
  witness.
- Knowledge soundness would additionally require an extractor that outputs a
  witness from a successful prover. Section 6 explains why this is not proven.
- Zero knowledge would require a simulator for the verifier's view without the
  witness. Section 7 gives only a sketch.

### 3.2 Assumptions

The conditional bound in Section 5 uses the following assumptions. None of
them is a theorem about this implementation today.

- **A1 (canonical relation).** For every statement accepted by
  `StatementV2`, the circuit recompiled by `compile_from_statement` faithfully
  encodes the intended range/membership/combined relation, and the Poseidon2
  membership gadget is correct for the pinned instance. The range and
  membership builders have positive/negative tests, but this is not a formal
  refinement proof.
- **A2 (commitment binding).** The BLAKE3 view commitment and the
  `CommitTreeV2` tree are binding: a polynomial-time adversary cannot produce
  two different openings of the same leaf at the same index under the same
  repetition root. This relies on collision resistance of BLAKE3 in the
  domain-separated constructions. The tree has 32-byte nodes; the generic
  collision ceiling is about 128 bits, not a proven 256-bit level.
- **A3 (transcript encoding and ideal challenge).** The transcript encoding is
  injective on the values it binds (fixed-width integers, explicit lengths,
  domain-separated labels), and for a fixed pre-challenge prefix the derived
  challenge vector is uniform over `{0,1,2}^M` and independent of the prefix.
  The code derives the vector from a BLAKE3 keyed hash and ChaCha20; the bound
  treats this as a random-oracle/PRG idealisation, not as a proven property of
  the concrete primitives.
- **A4 (MPC algebra).** Additive sharing reconstructs; linear gates are local;
  the three zero shares telescope to zero; and the Mul formula reconstructs to
  `x*y`. These facts are proved algebraically in Section 4 and exercised by
  unit tests. They do not depend on cryptographic assumptions.
- **A5 (field sampling and encoding).** `sample_fr` samples uniformly from
  `Fr` by rejection (a 32-byte draw is accepted only when it is below the
  modulus), and `decode_fr` rejects non-canonical encodings instead of
  reducing them. The expected number of draws is about `2^256 / p ~ 5.3` for
  BN254 `Fr`; the loop terminates with probability 1. This is an
  implementation/uniformity assumption, not a formal proof.
- **A6 (implementation and resource bounds).** Structural validation,
  decoding, allocation bounds, and the absence of memory-safety/side-channel
  bugs are assumed. The code has explicit length and size checks and tamper
  tests, but no formal verification or audit.

The model is specific to `N = 3` and the 2-of-3 opening schedule. The code
rejects all other party counts.

### 3.3 Field and hash ceilings

- BN254 `Fr` has a modulus of about 254 bits. The generic collision ceiling for
  a 254-bit group/field element is approximately `2^127`; a 219-repetition
  soundness bound of `2^-128.11` is therefore at the same order as, and cannot
  cleanly exceed, the field's generic collision ceiling.
- BLAKE3 has a 256-bit output; its generic collision ceiling is about 128
  bits. The transcript hash and view commitments are BLAKE3-based.
- Poseidon2 is the pinned Horizen Labs instance
  (`t=3`, `d=5`, `rf=8`, `rp=56`, identifier in `src/v2/suite.rs`). Its
  parameter security is an external cryptanalytic assumption; this repository
  does not establish it.
- The membership set root is a field element; it is not a 32-bit v1 MiMC root,
  but the field/hash ceilings above still apply.

## 4. Completeness

### Lemma 1 (completeness)

Let `st` be a statement and `w` a witness with `C_st.evaluate(w) = Ok`. Let
`params` be a valid `V2Params` (`N = 3`, `1 <= M <= 65536`). If `prove` and
`verify_statement` run without I/O or implementation failures, then
`verify_statement(prove(&compiled, &w, &params), st, &params)` accepts.

### Proof

`prove` first recompiles the canonical circuit from the statement, checks that
the supplied compiled circuit matches it, checks the witness length, and calls
`C_st.evaluate(w)`. Thus only a satisfying witness reaches proof generation.

For each repetition, the honest prover builds the seed tree and runs
`run_mpc_emulation`. The following facts hold by construction and by the
algebra in Section 4.1:

- The co-path for the challenged hidden party reconstructs exactly the seeds
  of the two opened parties (the hidden leaf is not used).
- For each opened party, `recompute_linear_shares` reproduces the same input
  shares, linear-gate outputs, and claimed Mul-output shares as
  `run_mpc_emulation`. The reason is that both use the same
  `PartySeedV2::to_rng(PARTY_SHARE_TAG)` stream and the same view Mul shares;
  party 2 uses the same residual input shares in both paths.
- The view commitment is deterministic in
  `(repetition, party, seed, payload, randomness)`. The prover uses the same
  tuple that the verifier reconstructs, and the authentication path for that
  leaf folds to the root. Therefore the commitment check passes.
- `verify_party_view` checks the linear gates, which hold by the induction
  just described, and checks a Mul edge only when the right neighbour is
  opened. For the one opened party whose right neighbour is opened, the
  honest Mul formula and the same zero-share derivation give equality. The
  other opened party's Mul edge is skipped by the 2-of-3 schedule.
- The assertion rows are the actual shares of the asserted input wires. For
  every opened party the published share equals the recomputed share. The sum
  of the three shares reconstructs the asserted wire; `C_st.evaluate(w) = Ok`
  ensures every `AssertEq` input equals its expected constant. Thus every row
  sum passes.
- The prover sets `hidden_party` from the same derived challenge vector, so
  the hidden-party equality check passes. All lengths and counts match the
  canonical circuit.

Every verifier check therefore passes, so `verify_statement` accepts. QED.

Completeness does not need collision resistance or hiding; it only needs
deterministic reproduction and correct encoding. It does not imply soundness
or zero knowledge.

### 4.1 Algebraic lemmas used above

**Sharing and linear gates.** If `s_0 + s_1 + s_2 = v` in `Fr`, then
`Add` preserves reconstruction, `MulConst` scales all shares, and
`AddConst` adds the constant to party 0's share so the sum increases by the
constant. These are immediate from field arithmetic and are implemented in
`SharingV2::{add, add_const, mul_const}`.

**Zero-share telescoping.** With cyclic indices and
`r_p(g) = PRF(seed_p, g) - PRF(seed_{p+1}, g)`,

```text
r_0(g) + r_1(g) + r_2(g) = 0
```

because each PRF term appears once with each sign.

**Multiplication.** For a gate with left shares `x_p` and right shares `y_p`,
the claimed outputs are

```text
z_p = x_p y_p + x_p y_{p+1} + x_{p+1} y_p + r_p(g).
```

Summing over the three parties:

```text
sum_p z_p
  = sum_p x_p y_p + sum_p x_p y_{p+1} + sum_p x_{p+1} y_p + sum_p r_p(g)
  = (sum_p x_p)(sum_p y_p)
  = x y.
```

The cross terms cover all ordered pairs exactly once modulo the cyclic index;
the zero shares vanish. This is the standard 3-party ZKBoo multiplication
identity ported to `Fr`.

## 5. Soundness

### 5.1 Lemma 2 (three-opening extraction for one repetition)

Fix one repetition index `i`, one commitment root `R_i`, one tuple of
assertion rows `A_i`, and a statement `st`. Suppose that for each hidden value
`h in {0,1,2}` there is an opening `O_h` (co-path plus the two opened views)
that passes all repetition-local verifier checks when the hidden party is `h`.
Assume A1-A6. Then there exists a witness `w` with `C_st.evaluate(w) = Ok`.

#### Proof

For each party `p in {0,1,2}`, choose any `h != p` and read party `p`'s
opened view from `O_h`. That view contains the party seed (reconstructed from
the co-path), its Mul-output shares, its residual input shares (party 2 only),
its commitment randomness, and its commitment authentication path. The
verifier checked that the recomputed view commitment equals leaf `p` and that
the path folds to `R_i`.

By A2 (commitment binding), the tuple `(seed_p, payload_p, randomness_p)` is
the unique opening of leaf `p` under `R_i`. If two of the `O_h` produced
different tuples, they would be a collision in the view commitment or in the
commitment tree. Thus all three opened appearances of party `p` refer to the
same committed view. The hidden appearances are irrelevant; each party is
opened for the other two hidden values.

Let `W_p` be the full wire-share vector computed by
`recompute_linear_shares` from party `p`'s extracted seed and view payload.
For parties 0 and 1 the input shares are seed-derived; for party 2 they are
the committed residual input shares. The verifier ran `verify_party_view` for
party `p` in at least one `O_h`, so its linear-gate checks pass for `W_p`.
(These checks are deterministic consequences of the recomputation, but the
statement is still true for the extracted vector.)

For each Mul gate, consider the edge from party `p` to party `p+1`. With
`N = 3`, that edge is checked in exactly one hidden choice:

- `p = 0`: checked when `h = 2` (parties 0 and 1 opened);
- `p = 1`: checked when `h = 0` (parties 1 and 2 opened);
- `p = 2`: checked when `h = 1` (parties 2 and 0 opened).

In that choice both endpoints are opened, so `verify_party_view` checks
`z_p` against `mul_output_share` using the two seeds and the gate index. Since
`O_h` passes, the Mul equation holds for every `p` and every Mul gate across
the three openings. This is the multi-transcript replacement for the
single-proof hidden-neighbour check.

For each assertion row `A_{i,j}` and each party `p`, party `p` is opened in at
least one `O_h`; in every such opening the verifier checks
`A_{i,j}[p] == W_p[wire_j]`. The row values are fixed by the prefix and are
the same in all three openings, so all three entries equal the corresponding
recomputed shares. The row-sum check in any `O_h` (indeed in all of them)
gives

```text
sum_p A_{i,j}[p] = expected_j,
```

hence `sum_p W_p[wire_j] = expected_j`. Every assertion is therefore satisfied
by the reconstructed wire values.

Define the reconstructed input witness `w` by summing the three input-share
vectors. For each gate, summing the per-party equations gives the native gate
equation: `Add`, `AddConst`, and `MulConst` are linear; a Mul gate sums to
`(sum_p W_p[left]) * (sum_p W_p[right])` by the multiplication lemma; an
`AssertEq` is satisfied by the previous paragraph. By induction in gate order,
the reconstructed wire vector is exactly `C_st.evaluate(w)`, and all
assertions hold. Therefore `C_st.evaluate(w) = Ok`. QED.

### 5.2 Corollary 1 and Theorem 1 (conditional soundness bound)

**Corollary 1 (at most two hidden choices per repetition).** Fix a
pre-challenge prefix and a false statement `st`. For each repetition `i`, at
most two of the three possible hidden values can have a passing local opening.

**Proof.** If all three had a passing opening, Lemma 2 would produce a witness
for `st`, contradicting that `st` is false. QED.

**Theorem 1 (conditional `2/3`-per-repetition bound).** Assume A1-A6. Fix a
false statement and a pre-challenge prefix `P = ((R_i, A_i))_{i=1..M}`. If the
challenge vector `H = (H_1, ..., H_M)` is uniform over `{0,1,2}^M` and
independent of `P`, then the probability that there exists a full accepting
proof with prefix `P` and hidden choices `H` is at most

```text
(2/3)^M.
```

**Proof.** By Corollary 1, for each `i` there are at most two admissible values
`H_i` for which repetition `i` can pass with prefix `P`. A full proof can pass
only if every coordinate is admissible. Therefore at most `2^M` of the `3^M`
challenge vectors are admissible. Under the uniform independent challenge
model, the probability is at most `2^M / 3^M = (2/3)^M`. QED.

**Corollary 2 (Fiat-Shamir query loss).** If an adversary makes `q`
transcript/prefix queries, then by the union bound its probability of
producing an accepting proof for a false statement is at most

```text
q * (2/3)^M.
```

The corresponding "bits" expression is

```text
M * log2(3/2) - log2(q) = 0.5849625... * M - log2(q),
```

before applying the field/hash collision ceilings. This is a bound on the
soundness error, not a promise that the concrete BLAKE3/ChaCha instantiation
or the implementation realises it.

**What is and is not used.** The bound uses commitment binding (A2) and the
ideal challenge model (A3), plus the canonical relation (A1) and the
implementation assumptions. It does **not** use a single-proof extraction of
the hidden view. The hidden view can be arbitrary in one proof; it is the
existence of all three openings for the same prefix that forces a witness.
This distinction is exactly why the protocol has a `2/3` error and not a
`1/3` error.

**Seed-tree note.** The seed tree has no checked root. The three co-paths used
in Lemma 2 therefore need not be consistent with one common seed-tree root.
That does not affect the soundness argument: each opened seed is bound by its
view commitment under `R_i`, and every party is opened in at least one of the
three openings. Parties 0 and 1 contribute their seed-derived input shares;
party 2 contributes its committed residual input shares. The absence of a
seed-tree root is relevant to hiding and zero knowledge, not to the `2/3`
bound.

### 5.3 Attack 1 (the bound is tight)

The following false statement is used by `tests/v2_soundness_gap.rs`:

```text
statement: 10 <= x <= 100
witness:   x = 101
```

`compile_range(10, 100)` allocates `[x, x_bits(32), shifted_bits(7),
slack_bits(7)]`. For `x = 101`:

- `shifted = x - 10 = 91`, whose 7-bit decomposition is valid;
- `slack = hi - x = -1`, encoded as the field element `-1` in the first slack
  bit and zero in the other slack bits;
- the first slack bit is not boolean: `b * (b - 1) = (-1) * (-2) = 2`, so the
  boolean constraint for that bit is the single failing assertion. The
  reconstructions of `x`, `shifted`, and `slack` are otherwise consistent.

The circuit evaluator rejects the witness, and `compiled.witness_for(101)`
returns an error. The honest MPC execution has all Mul equations valid; the
assertion row for the failing boolean check has shares summing to `2`, while
the expected value is `0`.

The forgery modifies one committed view and one published row:

1. Let `m_p` be party `p`'s honest Mul-output share for that boolean gate, with
   `m_0 + m_1 + m_2 = 2`. Set `m'_0 = m_0 - 2`; keep `m_1` and `m_2`.
2. Recompute party 0's view with `m'_0`. The published assertion row is
   `(m'_0, m_1, m_2)`, whose sum is `0`; parties 1 and 2 are honest.
3. Party 0's Mul equation for that gate now fails by `2`. All other Mul
   equations remain valid.

The verifier's behaviour for the three possible hidden parties is:

| hidden `h` | party 0 | checked Mul edge | result |
|---:|---|---|---|
| 0 | hidden; its assertion share is only used in the row sum | party 1 -> 2 (honest) | **accept** |
| 1 | opened; its published share matches its modified recomputed view | party 2 -> 0 (honest); party 0 -> 1 is skipped because party 1 is hidden | **accept** |
| 2 | opened | party 0 -> 1 is checked and fails by 2 | **reject** (`ConsistencyCheckFailed(0)`) |

Thus the false statement is accepted for hidden party 0 or 1 and rejected only
for hidden party 2. Since the challenge is uniform over the three parties, one
repetition is accepted with probability `2/3`. With `M` independent
repetitions, the adversary needs every challenge to be 0 or 1, giving
`(2/3)^M`. The same construction works with any sacrificial party `r`: hidden
`r` and `r+1` accept; hidden `r+2` checks the bad edge and rejects.

The attack uses no hash collision and no cryptanalytic break. It uses only:

- the fact that a hidden party's assertion share is not checked against its
  committed view, and
- the fact that exactly one Mul edge is skipped for each hidden party.

The test constructs all three candidate openings for the same prefix. `verify`
derives the Fiat-Shamir challenge, so only the candidate whose `hidden_party`
matches the challenge can pass the equality check; the other candidates fail
with a hidden-party mismatch. The test's sample of 48 independent prefixes
produced 27 accepted proofs (challenges 0 or 1) and 21 rejections (challenge 2,
caught at party 0's bad Mul edge). The expected count is 32 under `2/3`; the
sample is evidence for the mechanism, not a precise probability estimate.

### 5.4 Why the bound is not a `1/3` claim

The existing v2 notes sometimes described a `(2/3)^M` "heuristic". The
argument above proves the `2/3` **upper bound** for the implemented schedule
under A1-A6, and Attack 1 shows it is tight. A claim that one repetition has
error `1/3` would require the hidden party's assertion share to be bound to its
committed view and the skipped Mul edge to be recovered, or a different
opening schedule. Neither is implemented. Therefore:

- `(2/3)^M` is the correct per-repetition model for this code;
- no stronger bound follows from the current checks;
- the hidden-neighbour and hidden-assertion gaps are real, but they lower the
  bound to `2/3` rather than making the protocol unsound for all choices.

## 6. Knowledge soundness and extraction

### 6.1 What Lemma 2 gives

Lemma 2 is a **special-soundness** statement: three local openings for the same
prefix and the same repetition, with hidden choices 0, 1, and 2, extract a
witness. It is enough to count accepting challenge vectors and to prove the
soundness bound in Theorem 1.

It is not a single-proof extractor. In one accepting proof, one party is
hidden, one Mul edge is skipped, and the hidden assertion share is only checked
through the row sum. The hidden party's committed view never has to be
consistent with its assertion share or with the skipped edge. This is
intentional for zero knowledge, but it means there is no straight-line
extraction of the hidden view from one transcript.

### 6.2 Lemma K (Fiat-Shamir forking extraction): unresolved

To turn Lemma 2 into a knowledge-soundness theorem for the deployed
Fiat-Shamir transform, an extractor would need to obtain three accepting
openings for the same pre-challenge prefix and the same repetition, with
different hidden choices. In the random-oracle model this means rewinding or
programming the challenge derivation.

The following are not established:

- a forking lemma for the exact `transcript_hash` -> BLAKE3 `derive_key` ->
  ChaCha20Rng -> `gen_range(0..3)` path, including the PRG's internal state and
  the vector-of-challenges structure;
- the concrete extraction loss and running time as a function of `M`, `q`, and
  the number of accepting transcripts;
- that rewinding preserves the same commitment roots and assertion rows, as
  required by Lemma 2, rather than allowing the prover to change its prefix;
- that the extractor's witness is the same witness the statement intends
  (rather than a witness for a different circuit/statement);
- any proof that the single-proof hidden view is extractable at all.

A generic forking lemma could be invoked as a heuristic, but the challenge
space is `3^M`, the accepting set has size at most `2^M`, and the proof prefix
is a vector of commitments. No concrete theorem for this code is claimed here.
Accordingly, the protocol has a conditional **soundness** bound but no
established **knowledge soundness** for the deployed transform. This is one of
the exact unresolved lemmas of STEP-10.

### 6.3 What would be needed

A complete knowledge-soundness proof would need, at minimum:

1. a formal special-soundness/extraction lemma for the 3-party schedule
   (Lemma 2 above, with the commitment-binding reduction made explicit);
2. a forking lemma tailored to the vector challenge and the exact transcript
   encoding, with a stated loss;
3. a reduction from BLAKE3/ChaCha to the random-oracle/PRG model used by the
   forking lemma, or a concrete-security argument that does not rely on the
   idealisation;
4. an argument that the extractor's witness satisfies the canonical circuit
   relation, including the Poseidon2 membership gadget.

None of these is supplied by the current tests.

## 7. Zero knowledge

### 7.1 Simulator sketch

The proof reveals two of the three views per repetition, the commitment roots,
the assertion rows, the statement, and the challenge. A simulator for a true
statement could try the following:

1. Choose a hidden party `h` and a seed tree; produce a co-path for `h`.
2. Choose the two opened parties' seeds and views, and build their linear/Mul
   shares so that the one checked Mul edge between them holds. The hidden
   party's view can be chosen arbitrarily and committed; it is never opened.
3. For each assertion, set the opened parties' published shares to their
   recomputed wire shares. Set the hidden party's share to
   `expected - sum(opened shares)`, so the row sum passes without opening the
   hidden view.
4. Build the commitment root and assertion rows, then program the transcript
   hash/challenge derivation to select `h` (and the desired hidden party for
   every repetition).

This is the standard MPC-in-the-head simulation shape: the hidden view and the
hidden assertion share are the simulator's freedom, and the opened views are
made internally consistent.

### 7.2 Missing lemmas

The sketch is not a proof. The unresolved steps are:

- **Z1 (commitment hiding).** `commit_view_v2` uses a 32-byte random value and
  BLAKE3. No indistinguishability proof is given for the concrete construction,
  the domain separation, or the seed-and-payload commitment. The commitment is
  binding-like under collision resistance, but hiding is a separate property.
- **Z2 (seed-tree hiding).** The GGM/BLAKE3 seed tree must hide the hidden
  leaf given the co-path. The code has no root check and uses BLAKE3-derived
  children; a PRG/indistinguishability argument is missing.
- **Z3 (Fiat-Shamir programmability).** The simulator sketch assumes it can
  program the BLAKE3 transcript hash to a desired challenge vector. Real
  BLAKE3 is not programmable; the standard ROM heuristic is not a proof for
  the concrete primitive.
- **Z4 (assertion-row distribution).** The hidden party's assertion share is
  set to a value that makes the row sum correct. A proof must show that the
  joint distribution of roots, rows, opened views, and hidden commitments is
  indistinguishable from the real prover's, including the case where the
  statement's asserted wires are functions of the witness.
- **Z5 (MPC privacy).** Opening two of three additive shares should hide the
  witness because the third share is uniform (party 2's residual, or a
  seed-derived share for parties 0/1). This is plausible for the additive
  sharing, but the full wire trace, the Mul shares, the assertion rows, and the
  seed tree have not been analysed as one distribution. The membership gadget
  and the Poseidon2 circuit add more correlated values.
- **Z6 (side channels and proof metadata).** Timing, allocation, serialization
  length variation (party 2's residual shares are present only when party 2 is
  opened), and error behaviour are not analysed.

No zero-knowledge claim is made. In particular, this document does not claim
that the witness is hidden, only that the soundness argument does not depend on
hiding.

## 8. Fiat-Shamir, grinding, and parameters

### 8.1 Transcript binding

The transcript binds the suite/protocol/version/field/Poseidon2/framing
identifiers, `N`, `M`, the statement type and public values, the canonical
circuit hash, every repetition commitment root, and every assertion row. The
verifier recompiles the circuit from the statement, so a proof cannot supply a
different gate sequence. The hidden party is not absorbed before the
challenge; it is a deterministic function of the challenge and is checked for
equality. The co-path and opened views are openings, not pre-challenge
commitments, so they are not absorbed before the challenge.

`verify` accepts the statement embedded in the proof. A caller that needs a
specific statement must use `verify_statement` or compare `proof.statement`.
This is an API requirement, not a protocol-level statement-pinning guarantee.
V2 also has no transaction/context/session identifier in `StatementV2`; a
proof is bound to the statement values, not to an external context. If v2 is
used for authorization rather than pure statement verification, the
application must bind a context outside this proof format.

### 8.2 Grinding and the query loss

The prover can grind: it chooses a prefix (roots, assertion rows, views), hashes
the transcript, observes the challenge, and either opens the matching parties
or abandons the prefix and tries again. For each prefix on a false statement,
at most two of the three hidden choices per repetition are admissible
(Corollary 1). With `q` attempts, the union bound is `q * (2/3)^M`. The
"security level" expression is therefore

```text
M * log2(3/2) - log2(q).
```

`q` is not a small constant in an adversarial setting: an attacker with
`2^32` transcript attempts at `M = 219` gets about `96.1` bits, not `128.1`.
The bound also assumes the ideal challenge model; the concrete BLAKE3/ChaCha
construction is not proven to realize it.

### 8.3 Parameter table

| `M` | `(2/3)^M` | `log2((2/3)^M)` | role |
|---:|---:|---:|---|
| 4 | `2^-2.34` | 2.34 | `fast_insecure` test preset; not a security parameter |
| 96 | `2^-56.16` | 56.16 | `balanced` preset; far below 128 bits |
| 219 | `2^-128.11` | 128.11 | benchmark high-repetition setting; only `q=1` and idealised hashing |

The query loss for the same two settings:

| `q` | `M=96` bits | `M=219` bits |
|---:|---:|---:|
| 1 | 56.16 | 128.11 |
| `2^20` | 36.16 | 108.11 |
| `2^32` | 24.16 | 96.11 |

Even the `M=219`, `q=1` entry is not a clean 128-bit claim: BN254 `Fr` has a
generic collision ceiling near 127 bits, BLAKE3 has a collision ceiling near
128 bits, and the Poseidon2 instance is an external assumption. The `M=96`
setting is plainly unsuitable for a 128-bit target.

### 8.4 Field sampling and encoding

`sharing::sample_fr` draws 32 bytes from ChaCha and accepts the draw only when
`decode_fr` accepts it as a canonical value below the BN254 scalar modulus.
There is no modulo reduction of an arbitrary 32-byte string. For BN254 `Fr`,
the modulus is about `0.189 * 2^256`, so the expected number of draws is about
`5.3`; the loop terminates with probability 1. The canonical encoder rejects
values at or above the modulus, so a proof cannot silently reinterpret a
non-canonical field element. These facts support A5; they are not a formal
uniformity or side-channel proof.

## 9. Assumptions and unresolved lemmas

### 9.1 Status of the lemmas used by the bound

| ID | Lemma/assumption | Used for | Status |
|---|---|---|---|
| A1 | Canonical circuit faithfully encodes the statement | soundness, completeness | Tests and code inspection; no formal refinement proof. |
| A2 | BLAKE3 view commitment and commit tree are binding | Lemma 2 | Cryptographic assumption; generic collision ceiling about 128 bits. |
| A3 | Transcript encoding injective; challenge ideal | Theorem 1 | Encoding has tamper tests; challenge is a BLAKE3/ChaCha idealisation, not proven. |
| A4 | MPC sharing/zero-share/Mul algebra | Lemmas 1-2 | Proved algebraically and unit-tested. |
| A5 | Field sampling/encoding uniform and canonical | completeness, soundness | Implementation/tests; no formal proof. |
| A6 | No implementation/side-channel failure | all | Not proven; independent audit needed. |

### 9.2 Exact unresolved lemmas

1. **L-FS (ideal challenge).** There is no proof that the concrete
   `transcript_hash` -> BLAKE3 `derive_key` -> ChaCha20Rng -> `gen_range(0..3)`
   construction produces a challenge vector that is uniform and independent of
   the prefix in the sense required by Theorem 1. The bound is conditional on
   this idealisation.
2. **L-BIND (commitment binding).** There is no reduction from breaking the
   view commitment or the commitment tree to a standard BLAKE3 collision
   problem, and no concrete-security accounting for the domain-separated
   construction. A2 is an assumption.
3. **L-EXTRACT (single-proof hidden-view extraction).** A single accepting
   proof does not determine the hidden party's view, its assertion share, or
   the skipped Mul edge. Lemma 2 needs three openings. The Fiat-Shamir
   forking extractor that would obtain them is not proven. This is the main
   knowledge-soundness gap.
4. **L-ZK (simulation).** The simulator sketch in Section 7 lacks proofs for
   commitment hiding, seed-tree hiding, Fiat-Shamir programmability, assertion
   row distribution, and MPC privacy. No zero-knowledge claim is made.
5. **L-REL (canonical relation and Poseidon2).** The range, membership, and
   combined builders have positive/negative tests and the Poseidon2 gadget has
   KATs, but there is no formal proof that the canonical circuit exactly
   encodes the intended relation for all inputs, nor an independent
   cryptanalysis of the pinned Poseidon2 instance.
6. **L-ENC (transcript injectivity).** The `absorb` framing, fixed-width
   integers, and length prefixes are designed to be injective, and tamper
   tests cover the main fields. A formal encoding-injectivity proof is not
   supplied.
7. **L-SAMPLE (field sampling).** Rejection sampling is implemented correctly
   by inspection and tests, but no formal uniformity or side-channel analysis
   is supplied.
8. **L-IMPL (implementation).** Decoder bounds, allocation bounds, panic
   freedom, timing, and side channels are not audited. The code has explicit
   resource limits and strict decoding, which reduces obvious DoS/ambiguity
   risks but does not prove absence of bugs.

The failed single-proof lemma is **L-EXTRACT** (together with the
hidden-assertion-share and skipped-Mul-edge checks that make it fail). The
multi-transcript special-soundness lemma (Lemma 2) is what supports the
conditional `2/3` bound. The zero-knowledge lemma **L-ZK** is also unresolved.

## 10. Conclusion and next decision

### 10.1 What this analysis establishes

- **Completeness:** honest proofs for satisfying witnesses verify, subject to
  deterministic reproduction and implementation correctness (Lemma 1).
- **Soundness:** under A1-A6, a false statement has per-repetition acceptance
  probability at most `2/3`; over `M` repetitions and `q` prefix attempts, the
  bound is `q * (2/3)^M` (Theorem 1 and Corollary 2).
- **Tightness:** the bound is attained by a concrete false range proof that
  passes for hidden parties 0 and 1 and fails only for hidden party 2
  (Attack 1). The executable test confirms the mechanism.
- **No stronger per-repetition claim:** the hidden assertion row and the
  skipped Mul edge prevent a `1/3` claim. A protocol change or a different
  opening schedule is required for that.

### 10.2 What this analysis does not establish

- No knowledge-soundness theorem for the deployed Fiat-Shamir transform.
- No zero-knowledge theorem.
- No concrete-security proof for BLAKE3/ChaCha, Poseidon2, or the transcript
  encoding.
- No independent audit, no machine-checked proof, and no production-security
  claim.

### 10.3 Parameters and deployment

At `M = 96`, the conditional bound is about `2^-56.16`; this is not a 128-bit
setting and is not suitable for a deployment that needs a 128-bit forgery
target. At `M = 219`, the bound is about `2^-128.11` only for `q = 1` under the
ideal challenge model, and it is capped by the approximately 127-bit generic
collision ceiling of BN254 `Fr` and the BLAKE3 collision ceiling. With a
realistic query budget the level is lower. Neither setting is a licence to use
the words `secure`, `128-bit`, or `production-ready`.

**Do not deploy v2.** The protocol needs a protocol-level fix or a different
design, not a larger repetition count alone. The safest next decisions are:

1. Keep v2 research-only and retain the `fast_insecure`/`balanced` labels as
   parameter presets, never as security claims.
2. If the `2/3` gap matters for the target use case, change the opening
   schedule or bind the hidden party's assertion shares to its committed view
   in a way the verifier can check without opening the view. That is a new
   protocol/design step, not a STEP-10 documentation change.
3. Commission an independent cryptographic review of the Poseidon2 instance,
   the BLAKE3 domain separation, the seed/commitment trees, the transcript
   encoding, and the Fiat-Shamir conversion.
4. If a 128-bit target is required, use a protocol with a proven opening
   schedule and a concrete-security analysis that includes the query loss and
   the field/hash collision ceilings. Do not relabel `M = 219` as 128-bit.
5. Keep v1's 32-bit MiMC root and v1 proofs out of any v2 deployment; v1 is
   also a research baseline, not production cryptography.

## Appendix A. Reproduction

Run the concrete forgery:

```text
cargo test --test v2_soundness_gap -- --nocapture
```

Observed output at the baseline commit:

```text
known-gap evidence: 27/48 sampled Fiat-Shamir challenges selected h=0 or h=1 and accepted the false range proof; 21/48 selected h=2 and were rejected
test known_gap_accepts_false_range_statement_for_two_of_three_hidden_parties ... ok
```

The test is intentionally an acceptance test for a false statement. It is not a
regression test asserting that v2 is sound, and it must not be cited as a
security qualification. The sample count is not a precise estimate of `2/3`;
the protocol argument for the probability is Theorem 1 and Attack 1.

## Appendix B. Code map

| Code | Role in this analysis |
|---|---|
| `src/v2/suite.rs` | `N=3`, `V2Params`, version/suite identifiers, parameter bounds. |
| `src/v2/proof.rs::prove` | Canonical circuit check, witness evaluation, MPC repetitions, commitments, assertion rows, challenge derivation. |
| `src/v2/proof.rs::verify` | Structural checks, transcript, challenge equality, seed reconstruction, commitment checks, per-party checks, assertion rows. |
| `src/v2/proof.rs::verify_statement` | Statement pinning for callers. |
| `src/v2/proof.rs::transcript_hash` | Binds suite, statement, circuit hash, roots, and assertion rows. |
| `src/v2/proof.rs::derive_challenges` | BLAKE3 seed + ChaCha20 `gen_range(0..3)` per repetition. |
| `src/v2/mpc.rs::run_mpc_emulation` | Honest 3-party emulation and view generation. |
| `src/v2/mpc.rs::recompute_linear_shares` | Verifier-side view recomputation. |
| `src/v2/mpc.rs::verify_party_view` | Linear checks and conditional Mul-edge check. |
| `src/v2/mpc.rs::zero_share`, `mul_output_share` | ZKBoo zero-share and Mul formulas. |
| `src/v2/predicate.rs::constrain_bits` | Boolean bit constraints; the false slack bit exploits the missing hidden-share binding. |
| `src/v2/predicate.rs::compile_range` | The concrete false range circuit used by the test. |
| `src/v2/commitment.rs::commit_view_v2` | View commitment (seed + payload + randomness). |
| `src/v2/commit_tree.rs` | Commitment Merkle tree and path verification. |
| `src/v2/seed_tree.rs` | Seed tree and co-path reconstruction (no checked root). |
| `src/v2/field.rs`, `src/v2/sharing.rs` | Canonical field encoding and rejection-sampled shares. |
| `tests/v2_soundness_gap.rs` | Executable false-statement forgery. |

## Appendix C. Relation to the earlier v2 notes

`V2_PROTOCOL_NOTES.md` previously described the hidden-neighbour and hidden
assertion-row issues as a heuristic `(2/3)^M` gap. This document replaces that
heuristic with:

- a proof that the local extraction over three hidden choices yields a witness
  (Lemma 2), giving the conditional `2/3`-per-repetition upper bound;
- a concrete attack showing the bound is tight;
- explicit assumptions and unresolved knowledge-soundness/zero-knowledge
  lemmas.

The protocol is still unproven as a whole. The change is that the `2/3`
per-repetition **soundness** bound is now derived rather than assumed, while
knowledge soundness and zero knowledge remain open. No implementation or proof
format is changed by this analysis.
