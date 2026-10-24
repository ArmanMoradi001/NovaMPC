# NovaMPC v3: MPCitH proof-size redesign plan

Status: **planning document only**. No v3 code exists yet. No v3 security
claim is made. The current v2 implementation, v2 proof format, v2 tests, and
v2 security documents remain unchanged.

Working name: **NovaMPC v3 / TCitH-MT**.

## 0. Decision summary

I will build a new MPC-in-the-Head proof path under `src/v3/` that proves the
**same combined range + set-membership statement on the same private input
`x`** and targets a serialized proof size **below 1 MB**.

The chosen construction is:

> **Extended Threshold Computation in the Head, Merkle-tree variant
> (TCitH-MT), with packed Shamir sharing, a degree-enforcing commitment
> scheme, and a Ligero-style parallel/aggregated constraint check.**

It is still MPC-in-the-head:

- the prover emulates many virtual parties in its head;
- each party holds a share of the witness;
- the prover commits to the parties' views;
- the verifier opens a small verifier-chosen subset;
- the verifier checks that the opened views are consistent with one MPC
  execution and that the circuit output is the required statement.

It is **not** a SNARK, STARK, pairing proof, or trusted-setup proof.

Targets:

| Item | Target |
|---|---|
| Statement | one combined range + membership proof, same `x` |
| Proof system family | MPCitH only |
| Hard serialized-size limit | **< 1,000,000 bytes** |
| Design target | **< 250 KB** |
| Current size estimate | **about 197 KiB** for the recommended prototype parameters; still to be measured |
| Security target | approximately **127-bit** ceiling, not 128-bit |
| Old v2 proofs | remain valid and unchanged |
| New v3 proofs | new magic, new format, never accepted as v2 |

The old v2 3-party `2/3` soundness dossier does **not** apply to v3. V3 needs
its own soundness analysis and external review.

---

## 1. Why v2 cannot be patched to reach 1 MB

Measured v2 result (`V2_BENCHMARKS.md`), combined 32-member proof at
`M = 219`:

```text
27,422,239 – 27,467,839 bytes
```

The circuit has:

```text
6,186 total gates
1,774 Mul gates
```

The dominant proof cost is:

```text
2 opened parties
× 1,774 Mul shares
× 32 bytes per Fr element
× 219 repetitions
≈ 24.9 MB
```

The code that causes this is explicit:

- `src/v2/proof.rs:83-101` defines `RepetitionProofV2` with
  `opened_views` and `assert_shares`.
- `src/v2/proof.rs:127-150` serializes every opened view's
  `mul_output_shares` and residual input shares.
- `src/v2/mpc.rs:316` recomputes linear shares from a seed and the supplied
  Mul shares.
- `src/v2/mpc.rs:493` verifies a party view, but the 3-party schedule checks
  only one Mul edge per repetition.
- `src/v2/suite.rs:30` fixes `V2_NUM_PARTIES = 3`; `:135` rejects any other
  party count.

The 2/3 gap and the 27 MB size are the same design problem: opening 2 of 3
parties and sending their full Mul-share vectors. A parameter change cannot
fix it:

- lowering `M` weakens security;
- truncating `Fr` breaks canonical encoding;
- generic compression saves only about 6% (`zstd -19`) and is not a fix;
- raising `N` inside v2 is rejected by construction and would require a new
  multiplication protocol anyway.

V2 stays as the existing, documented, blocked-on-review implementation. V3 is
a separate path.

---

## 2. Goals and non-goals

### 2.1 Goals

1. Prove the **combined** relation, not two separate proofs:
   - private `x` is in `[lo, hi]`;
   - the same `x` is a member of the committed set.
2. Keep one witness, one circuit, one proof, one context binding.
3. Preserve the current public statement semantics:
   - BN254 `Fr`;
   - canonical 32-byte field encoding;
   - pinned Horizen Labs Poseidon2 instance;
   - current tagged leaf/node/root framing;
   - the existing range bounds and member-count/depth rules.
4. Use only MPC-in-the-Head and hash-based commitments.
5. Reduce the worst-case serialized proof below 1 MB.
6. Keep v2 source, tests, proof format, and claims untouched.
7. Produce measurable evidence: size, prove time, verify time, prover memory.
8. Produce a new soundness/zero-knowledge analysis and audit package.

### 2.2 Non-goals

- **No SNARK/STARK, no trusted setup, no pairings, no KZG.**
- **No KKW/Picnic3 binary-circuit port.** KKW/Picnic3 is optimized for
  Boolean circuits and small binary fields; it does not give the needed size
  over BN254 `Fr`.
- **No splitting** of range and membership into two proofs or two witnesses.
- **No weakening** of v2's `M`, soundness bound, or
  `tests/v2_soundness_gap.rs`.
- **No reuse of v2 proof bytes** as v3, and no v3 acceptance by the v2
  verifier.
- **No new Poseidon2 instance**, no truncated field elements, no non-canonical
  decoding.
- **No production, 128-bit, or post-quantum security claim.** The field is
  BN254 `Fr`; the practical ceiling remains about 127 bits. The proof is
  hash-based, but that alone is not a post-quantum claim for the whole
  deployment.
- **No silent fallback** to a smaller security parameter if the size target is
  missed. If the target cannot be met, the phase stops and reports the
  measured result.

---

## 3. The v3 relation

### 3.1 Statement

The public statement is the existing `StatementV2`:

- `Range { lo, hi }`
- `Membership { root, num_members, depth }`
- `Combined { range, membership }`

The v3 prover accepts the existing compiled circuit and witness layout from
`src/v2/predicate.rs`. The circuit is compiled once, deterministically, from
the statement. The verifier recompiles it from the expected statement and
never trusts a prover-supplied circuit.

### 3.2 Witness

One private value `x: u32` and its existing auxiliary values:

- 32-bit decomposition of `x`;
- range shifted/slack bits;
- membership index bits and slack bits;
- Merkle sibling values;
- Poseidon2 intermediate wires.

The combined builder must continue to use **one `x` wire** for both checks.
The v3 constraint compiler must not create independent range and membership
witnesses. A split-witness proof must fail the constraint system.

### 3.3 What the proof establishes

If verification accepts, then there exists a single witness `x` such that:

1. `lo <= x <= hi` as a `u32` range check encoded in `Fr`;
2. `leaf(x)` is the leaf at the proven index in the committed set;
3. the Merkle path reconstructs the public root;
4. the root metadata `(num_members, depth)` is correct;
5. every Poseidon2 permutation in the Merkle path uses the pinned constants
   and framing;
6. all multiplication gates are satisfied over `Fr`;
7. the proof is bound to the caller's expected statement and 32-byte context.

The exact semantics remain those documented in `V2_DESIGN.md` and
`V2_PROTOCOL_NOTES.md`. V3 changes the proof machinery, not the relation.

---

## 4. Chosen construction: extended TCitH-MT

### 4.1 Why TCitH-MT

V2 is a 3-party additive-sharing ZKBoo-style protocol. Its proof is linear in:

```text
(number of Mul gates) × (number of repetitions) × (opened parties)
```

TCitH-MT changes three things at once:

1. **Threshold sharing instead of 3-party additive sharing.**
   With an `(ℓ+1, N)`-threshold Shamir sharing, a cheating prover is caught
   The packed/quadratic LPPC bound is not `1 / C(N, ℓ)`. The interactive error
   includes the combinatorial term `C(d_α, ℓ) / C(N, ℓ)`, where
   `d_α = 2(s+ℓ−1)` for degree-2 constraints, plus the DECS and MPC false-
   positive terms. See `V3_PHASE0.md` for the corrected bound and assumptions.
   This can reduce the outer repetition count, but does not by itself establish
   non-interactive security.

2. **Packed sharing and a witness matrix.**
   Many witness values are packed into each committed field element. The
   extended witness is arranged as a matrix, so the proof does not contain a
   separate field element for every gate in every opened party.

3. **Merkle commitment plus a Ligero-style constraint check.**
   The prover commits to the packed witness rows with a Merkle tree. The
   verifier opens only a small number of rows/leaves and checks random linear
   combinations of all constraints. Proof size becomes sublinear in the
   witness size, rather than linear in `Mul gates × repetitions`.

The result is still MPCitH. The prover's virtual parties compute the circuit
on Shamir shares; the verifier checks a small opened portion and the
commitment/constraint consistency. There is no SNARK.

### 4.2 Required components

1. **Packed Shamir sharing over `Fr`**
   - `(ℓ+1, N)` threshold.
   - Public distinct non-zero evaluation points.
   - Share, reconstruct, and degree-check operations.
   - Packing `s` witness coordinates per share row.
   - All operations over BN254 `Fr`.

2. **Witness matrix**
   - Rows are committed Merkle leaves.
   - Columns are the packed witness coordinates / constraint lanes.
   - The layout is deterministic and bound to the circuit hash.
   - The same matrix contains range bits, membership index/path values, and
     the multiplication-gate operands/outputs.

3. **Degree-enforcing commitment scheme (DECS)**
   - Merkle commitment to the share rows.
   - Random linear-combination proximity/degree test.
   - Stops a malicious prover from committing rows that are not valid
     degree-`d` Shamir sharings.
   - The error term is part of the v3 soundness calculation; it is not
     hand-waved away.

4. **PACS/LPPC constraint system**
   - Parallel and aggregated polynomial constraints over the witness matrix.
   - Each `Mul` gate contributes a degree-2 constraint.
   - `Add`, `AddConst`, `MulConst` are folded into linear combinations.
   - `AssertEq` becomes an output/aggregated constraint.
   - Poseidon2 S-boxes remain the existing three-Mul decomposition
     (`x2 = x*x`, `x4 = x2*x2`, `x5 = x4*x`).
   - Range bit checks use `b * (b - 1) = 0`.
   - The membership mux/path uses the existing bit-select and Poseidon2 node
     gadgets.

5. **TCitH-MT prover/verifier**
   - Prover builds the packed shares, evaluates the virtual MPC, commits the
     matrix, and answers the verifier's challenges.
   - Verifier recompiles the circuit, checks the commitments/openings,
     degree-enforcement responses, PACS linear combinations, output
     assertions, and context binding.
   - Fiat-Shamir makes it non-interactive using a domain-separated BLAKE3
     transcript.

6. **New proof format and version**
   - Separate magic and format version.
   - Canonical serialization only.
   - Bounded allocation and strict trailing-byte rejection.
   - No v2 parser changes.

### 4.3 Why not KKW/Picnic3 or TCitH-GGM

- **KKW/Picnic3:** binary-oriented. Picnic3's ~12.6 KB is for a LowMC
  circuit with roughly 516–645 binary AND gates, `N=16`, `τ=36`, and `F₂`
  shares. Over BN254 `Fr`, a KKW-style proof for 1,774 Mul gates remains
  linear and is expected in the ~1–2 MB range, not comfortably below 1 MB.
  It is the wrong base.
- **TCitH-GGM:** simpler than TCitH-MT, but its proof is linear in the
  opened shares. It is useful as a research fallback, but not the primary
  plan because it does not provide enough size margin.
- **TCitH-MT:** the only MPCitH option in this plan with published
  arithmetic-circuit sizes in the tens-to-low-hundreds of KB for this
  circuit scale.

Published reference point: for a 256-bit field, degree-2 constraints, and
4,096 multiplication gates, TCitH-MT with `N = 8192` is reported at about
**130 KB** (SmallWood paper, Table 2, `TCitH-ΠLigero` row). Re-evaluating the
published size formula for NovaMPC's 1,774-Mul combined circuit and the
recommended prototype parameters gives about **197 KiB**. This is a calibrated
model, not a measurement of a V3 proof; see `V3_PHASE0.md`.

References:

- TCitH: <https://eprint.iacr.org/2023/1573>
- Threshold LSSS MPCitH: <https://eprint.iacr.org/2022/1407>
- SmallWood comparison table: <https://eprint.iacr.org/2025/1085>
- Picnic3: <https://eprint.iacr.org/2020/427>
- KKW: <https://eprint.iacr.org/2018/475>

---

## 5. Protocol flow

### 5.1 Prover

```text
input: statement, witness (x, bits, siblings), context, v3 params

1. Validate statement and parameters.
2. Compile the canonical combined circuit from the statement.
3. Compile the circuit to the v3 PACS/LPPC constraint system.
4. Hash the suite, statement, circuit, context, and parameter set.
5. Build the extended witness:
     - one x and its bit decomposition,
     - range shifted/slack bits,
     - membership index bits and siblings,
     - all Mul-gate operands and outputs.
6. Pack the witness into a matrix with s columns.
7. Sample Shamir randomness and build (ℓ+1, N)-threshold shares.
8. Emulate the virtual MPC:
     - linear gates locally on shares,
     - Mul gates via the chosen share-wise/quadratic protocol,
     - broadcast the required output shares.
9. Commit the packed share rows with a Merkle tree.
10. Run the DECS setup and absorb the commitment root into the transcript.
11. Derive verifier challenges (openings, linear combinations, proximity
    coefficients) from the transcript.
12. Compute DECS responses and PACS constraint responses.
13. Open the requested rows/leaves and build the proof.
14. Serialize with canonical lengths and bounds.
```

### 5.2 Verifier

```text
input: proof bytes, expected statement, expected context, expected params

1. Reject wrong magic, format version, protocol/suite ID, or parameter set.
2. Enforce size/resource bounds before allocation.
3. Decode canonical Fr elements and length-prefixed vectors; reject trailing
   bytes.
4. Recompile the canonical circuit and constraint system from the expected
   statement; reject any hash mismatch.
5. Absorb the statement, circuit hash, context, params, and commitment roots
   into the transcript.
6. Derive the same challenges as the prover.
7. Check Merkle authentication paths for the opened rows.
8. Check the DECS degree/proximity responses.
9. Check the PACS random linear combinations for all multiplication and
   linear constraints.
10. Check output/assertion constraints and the public statement values.
11. Reject on any mismatch. Accept only if every check passes.
```

### 5.3 Same input guarantee

The constraint compiler takes the existing `CompiledV2` circuit, which already
shares one `x` wire between the range and membership paths. It does not accept
two witnesses. Tests will include a deliberate split-witness attack:

- witness A satisfies the range but not membership;
- witness B satisfies membership but not range;
- any attempt to combine them into one proof must fail.

---

## 6. Proof format (provisional)

The final byte layout is frozen only after the parameter/prototype phase, but
the following is the required structure.

### 6.1 Header

```text
magic                 8 bytes   "NMPCV3T\0"
format_version        u16       = 1
protocol_id           fixed     "NovaMPC-v3/tcith-mt/v1"
field_id              fixed     "BN254-Fr"
poseidon2_id          fixed     pinned instance identifier
framing_id            fixed     v2-compatible tagged framing identifier
statement_type        u8
params                 fixed     N, ℓ, s, η, ρ, ℓ′, query budget
statement             canonical existing StatementV2 encoding
context               32 bytes
circuit_hash          32 bytes
```

### 6.2 Body

- Merkle root(s) for the packed witness commitment.
- DECS commitment/response data.
- Opened row indices and values.
- Merkle authentication paths.
- PACS linear-combination responses.
- Output/assertion shares or openings required by the chosen TCitH-MT
  variant.
- Any Fiat-Shamir counters/grinding values, if enabled.

### 6.3 Encoding rules

- Every `Fr` element is exactly 32-byte canonical big-endian.
- Every vector has an explicit `u32` length prefix.
- Every count is validated against the parameter set and a hard resource
  bound before allocation.
- No `usize`, `u64` memory dumps, `serde`, or `bincode` on the wire.
- No trailing bytes.
- No prover-supplied circuit or expected outputs.
- The verifier's expected statement and context are authoritative; a proof
  carrying different values is rejected.

### 6.4 Size accounting

The proof size is measured as the exact output length of
`V3Proof::to_bytes()`, not an estimate. The benchmark records:

- minimum, median, and maximum bytes;
- prove time;
- verify time;
- peak prover memory;
- parameter set and host details.

Acceptance is based on the **maximum**, not the median.

### 6.5 Version separation

V3 must use a new magic and format version. It must not reuse
`V2_PROOF_VERSION = 3` or the v2 `V2_PROOF_MAGIC`. A v2 verifier must reject a
v3 proof at the magic/version check, and a v3 verifier must reject a v2 proof.
Both negative cases are mandatory tests.

---

## 7. Parameters and security calculation

### 7.1 Parameter set

The v3 parameter structure will include at least:

| Symbol | Meaning | Initial search range |
|---|---|---|
| `N` | number of virtual parties | 1024, 2048, 4096, 8192 |
| `ℓ` | privacy/opening parameter; `(ℓ+1, N)` sharing | 8–64 |
| `s` | packing width / witness-matrix columns | 16–256 |
| `η` | degree-enforcement / proximity repetitions | 1–8 |
| `ρ` | PACS parallel repetitions | 1–4 |
| `τ` | outer proof-of-knowledge repetitions | 1–16 |

Current prototype candidate: `N=8192, ℓ=30, s=120, η=6, ρ=1, τ=2`.
Its modeled size is 197 KiB and its parameters remain experimental. Exact
definitions and estimates are in `V3_PHASE0.md`.

### 7.2 Security calculation

The written security note must derive, for the chosen parameter set:

1. The LPPC combinatorial term `C(d_α,ℓ)/C(N,ℓ)`, with exact `d_α` for the
   selected degree and packing.
2. The DECS term `C(N,d_β+2)/|F|^η`.
3. The MPC false-positive term `1/|F|^ρ`.
4. The Fiat-Shamir/random-oracle and grinding/query-loss terms.
5. The BN254 `Fr` collision ceiling (about 127 bits).
6. The final `≤ 2^-127` target with margin.

No parameter set may be labeled "secure" until that calculation is written
and reviewed. Until then, v3 presets must be named `experimental` or
`insecure_test`.

### 7.3 Size model

Planning model:

```text
proof size
  = header + statement + context
  + commitment roots
  + opened rows/leaves and Merkle paths
  + DECS responses
  + PACS responses
  + assertion/output data
```

The dominant terms should be the opened rows/leaves, not the number of Mul
gates times the number of repetitions. The current 1,774-Mul model predicts
about 197 KiB for the recommended parameters; actual proof bytes and timings
remain to be measured.

Hard acceptance:

```text
max serialized v3 proof < 1,000,000 bytes
```

Design acceptance:

```text
max serialized v3 proof < 250,000 bytes
```

If the prototype cannot meet the hard limit with a parameter set that has a
written `≤ 2^-127` soundness calculation, the project stops and reports why.
It does not silently reduce `N`, `ℓ`, `η`, or the security target.

---

## 8. Code architecture

### 8.1 New module

```text
src/v3/
  mod.rs
  suite.rs          v3 identifiers, magic, format version
  params.rs         V3Params and validation
  matrix.rs         packed witness matrix layout
  sharing.rs        packed Shamir share/reconstruct/degree checks
  merkle.rs         v3 Merkle commitment/openings (may wrap v2 primitives)
  decs.rs           degree-enforcing commitment scheme
  constraints.rs    circuit -> PACS/LPPC compiler
  witness.rs        v2 compiled witness -> v3 extended witness
  prover.rs         v3 prover
  verifier.rs       v3 verifier
  proof.rs          V3Proof and canonical serialization
  transcript.rs     Fiat-Shamir transcript and challenge derivation
  transaction.rs    transaction-facing wrapper, if needed
```

### 8.2 Reuse from v2

Reuse, without changing semantics:

- `src/v2/field.rs` — canonical `Fr` encoding/decoding.
- `src/v2/circuit.rs` — gate model and deterministic circuit evaluation.
- `src/v2/predicate.rs` — statement, layout, witness construction, combined
  circuit.
- `src/v2/poseidon2.rs` and `poseidon2_circuit.rs` — pinned permutation and
  three-Mul S-box gadget.
- `src/v2/transaction.rs` — statement/witness trust boundary.
- `src/v2/merkle.rs` / `commitment.rs` — BLAKE3 hashing and Merkle mechanics,
  if the leaf formats can be cleanly wrapped.
- Existing error types, test conventions, and serialization discipline.

Do **not** reuse:

- `src/v2/sharing.rs` (3-party additive sharing),
- `src/v2/mpc.rs` (3-party ZKBoo emulation),
- `src/v2/proof.rs` (v2 proof format/prover/verifier),
- `src/v2/seed_tree.rs` unless the chosen TCitH-MT variant needs it,
- the v2 2/3 soundness argument.

### 8.3 API

Provisional public API:

```rust
pub fn prove_statement_v3(
    statement: &StatementV2,
    witness: &WitnessV2,
    context: [u8; 32],
    params: &V3Params,
) -> Result<V3Proof>;

pub fn verify_statement_v3(
    proof: &V3Proof,
    expected_statement: &StatementV2,
    expected_context: [u8; 32],
    expected_params: &V3Params,
) -> Result<()>;
```

The exact names may change during scaffolding, but the semantics are fixed:

- the verifier takes the expected statement/context, not prover-supplied ones;
- the circuit is recompiled and hash-checked;
- no unasserted output fallback;
- v2 functions remain untouched.

### 8.4 Version identifiers

Provisional:

```text
V3_PROOF_MAGIC          = b"NMPCV3T\0"
V3_PROOF_FORMAT_VERSION = 1
V3_PROTOCOL_ID          = b"NovaMPC-v3/tcith-mt/v1"
V3_FIELD_ID             = b"BN254-Fr"
V3_POSEIDON2_ID         = same pinned instance as v2
V3_FRAMING_ID           = same tagged framing identifier as v2
```

These are not the v2 proof version. The v2 proof format version stays `3` and
is not reinterpreted.

---

## 9. Implementation phases

### Phase 0 — Design freeze and parameter model (complete; see `V3_PHASE0.md`)

Deliverables:

- this plan refined into a frozen v3 design note;
- exact PACS/LPPC constraint count for the 1,774 Mul gates;
- parameter search spreadsheet with soundness and size formulas;
- explicit go/no-go thresholds;
- no code changes.

Gate: a written parameter set with `≤ 2^-127` soundness target and a
predicted proof size below 1 MB.

### Phase 1 — Matrix, packed Shamir, Merkle, DECS (implemented; experimental only)

Deliverables:

- `matrix.rs`, `sharing.rs`, `decs.rs`;
- Merkle commitment wrapper for packed rows;
- unit and property tests for share/reconstruct/degree checks;
- tamper tests for Merkle openings and DECS responses.

Gate: all primitive tests pass; no proof prover yet.

### Phase 2 — PACS/LPPC compiler (relation compiler implemented; experimental only)

Deliverables:

- `constraints.rs`;
- lowering for `Mul`, `Add`, `AddConst`, `MulConst`, `AssertEq`;
- range bit constraints;
- Poseidon2 membership path constraints;
- differential tests against the v2 circuit evaluator.

Gate: broaden differential coverage and independently review the row layout
and compiler against FR25b before using it in a prover.

### Phase 3 — Range-only end-to-end proof (3–5 weeks)

Deliverables:

- `prover.rs`, `verifier.rs`, `proof.rs`, `transcript.rs`;
- range-only v3 proof;
- canonical serialization and negative tests;
- first size/time benchmark.

Gate:

- max proof size for range-only ≤ 150 KB (tentative);
- verifier target ≤ 50 ms on the benchmark host (tentative);
- no security claim yet.

If this gate fails badly, stop before integrating membership.

### Phase 4 — Full combined circuit (3–6 weeks)

Deliverables:

- combined range + membership v3 proof with the same `x`;
- context binding;
- 4/8/16/32-member benchmark matrix;
- split-witness and boundary tests.

Gate:

- max serialized proof **< 1,000,000 bytes** for all supported cases;
- design target < 250 KB;
- completeness and adversarial tests pass.

### Phase 5 — Hardening and evidence (2–4 weeks)

Deliverables:

- malformed-proof/fuzz/resource-bound tests;
- cross-version v2/v3 rejection tests;
- prove/verify timing and memory report;
- `V3_BENCHMARKS.md`;
- API and migration notes.

Gate: no panics, no unbounded allocation, no acceptance of non-canonical
encodings, no v2/v3 confusion.

### Phase 6 — Security write-up and external review (8–16 weeks, external)

Deliverables:

- `V3_SOUNDNESS.md` (or equivalent) with the full analysis;
- `V3_AUDIT_PACKAGE.md`;
- independent cryptographer review;
- independent audit.

Gate: named external sign-off. Until then, v3 is `BLOCKED-REVIEW` /
`BLOCKED-AUDIT` and must not be described as production-secure.

Estimated prototype effort: **3–5 months** for Phases 0–5. Review/audit is
the long pole and is outside my control.

---

## 10. Testing plan

### 10.1 Unit tests

- Shamir share/reconstruct for `(ℓ+1, N)`.
- Degree checks accept valid sharings and reject off-degree sharings.
- Packing/unpacking round-trips.
- Merkle root/path correctness and tamper rejection.
- DECS accepts honest responses, rejects inconsistent commitments.
- PACS constraint evaluation for every gate type.
- Canonical `Fr` encoding/decoding.

### 10.2 Property/differential tests

- Random valid witnesses for range, membership, and combined statements.
- Random invalid witnesses: out-of-range, wrong leaf, wrong index, wrong root,
  wrong depth, wrong member count, padded-leaf index.
- Differential test: v2 circuit evaluation and v3 constraint evaluation must
  agree on the same witness.
- Split-witness test: range-valid/membership-invalid and
  membership-valid/range-invalid witnesses must not be combined.

### 10.3 Proof-negative tests

- Tamper every proof section: header, params, statement, context, roots,
  opened rows, paths, DECS responses, PACS responses, assertions.
- Wrong expected statement/context must fail.
- Wrong circuit hash must fail.
- Replayed proof under a different context must fail.
- Non-canonical `Fr` bytes must fail.
- Truncated proof, extra trailing bytes, and oversized lengths must fail.
- V2 proof bytes into v3 verifier: reject.
- V3 proof bytes into v2 verifier: reject.

### 10.4 Resource tests

- Maximum proof size enforced before allocation.
- Maximum vector lengths and Merkle path depth.
- No unbounded memory from attacker-controlled counts.
- Prover peak memory measured for 32 members.

### 10.5 Benchmarks

- Statement sizes: 4, 8, 16, 32 members.
- Range-only, membership-only, combined.
- Multiple parameter candidates; report the chosen set.
- Exact bytes from `to_bytes()`.
- Prove/verify medians and max proof size.
- Record host, compiler, and build profile.

### 10.6 V2 preservation

- `tests/v2_soundness_gap.rs` is not modified or weakened.
- All existing v2 tests continue to pass.
- V2 proof format and security docs are not rewritten to describe v3.

---

## 11. Security analysis obligations

V3 must not inherit v2's 2/3 claim. The new analysis must cover:

1. **Threshold sharing privacy.** Opened parties learn nothing about the
   witness beyond what the statement reveals.
2. **Soundness.** The LPPC combinatorial, DECS, and MPC false-positive terms,
   plus all Fiat–Shamir/query losses.
3. **Knowledge soundness/extraction.** A successful proof implies an
   extractable witness, not just a passing transcript.
4. **Zero knowledge.** Simulation of the opened views and commitments, and
   the Fiat-Shamir conversion in the random-oracle model.
5. **Fiat-Shamir binding.** Statement, circuit hash, context, params, and all
   pre-challenge values absorbed in a fixed order.
6. **Domain separation.** BLAKE3 domains for commitments, seeds, challenges,
   and grinding; no cross-protocol reuse.
7. **Canonical encoding.** No malleability from non-canonical field bytes or
   ambiguous lengths.
8. **Concrete parameter calculation.** `≤ 2^-127` target with margin, capped
   by the BN254 `Fr` ceiling.
9. **Implementation assumptions.** Hash collision resistance, PRG/commitment
   binding/hiding, and Poseidon2 cryptanalysis are external assumptions.
10. **Side channels and memory.** Out of scope for the formal proof, but
    documented for the audit package.

No production or 128-bit claim is allowed before external review.

---

## 12. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| TCitH-MT parameter search cannot reach < 1 MB | Hard failure | Stop at Phase 0/3; report measured result; do not weaken security |
| DECS/proximity implementation is subtle | Soundness bug | Spec tests, paper cross-check, external review |
| PACS compiler changes circuit semantics | Wrong statement accepted/rejected | Differential tests against v2 evaluator; adversarial witness tests |
| Prover memory/time is too high | Practical failure | Benchmark early; bounded matrices; streaming/parallel hashing if needed |
| Packing does not help enough | Size miss | Parameter search; larger `s`/`N`; if still failing, stop |
| Fiat-Shamir/transcript mismatch | Soundness/ZK failure | Single transcript module; absorption-order tests; test vectors |
| v2/v3 confusion | Protocol confusion | Separate magic/version/namespace; cross-rejection tests |
| Audit unavailable | Cannot deploy | Keep `BLOCKED-AUDIT`; no production claim |
| Scope creep into SNARK/KKW | Wrong design | Explicit non-goals; TCitH-MT only |

---

## 13. Acceptance criteria

V3 is considered technically successful only if all of these hold:

### Functional

- [ ] One proof proves range and membership together on the same `x`.
- [ ] The verifier recompiles the canonical circuit and checks its hash.
- [ ] V2 behavior, tests, and proof format are unchanged.
- [ ] V2 and v3 proofs are mutually rejected.
- [ ] All statement sizes 4/8/16/32 work.

### Size

- [ ] Maximum serialized proof < **1,000,000 bytes** for every supported case.
- [ ] Design target < **250 KB**.
- [ ] Size is measured from actual bytes, not estimated from parameters.

### Security/process

- [ ] Written soundness calculation targets `≤ 2^-127`.
- [ ] No 128-bit, production, or post-quantum claim.
- [ ] Independent review completed.
- [ ] Independent audit completed.
- [ ] V3 status updated only after named sign-off.

### Performance

Provisional targets, to be confirmed at Phase 3:

- [ ] Verifier wall time ≤ 100 ms for 32 members on the benchmark host.
- [ ] Prover wall time ≤ 10 s for 32 members on the benchmark host.
- [ ] Peak prover memory bounded and recorded.

If these provisional targets are unrealistic, the Phase 3 benchmark replaces
them with measured, documented targets; they are not silent relaxations of
the size or security requirements.

---

## 14. Open decisions requiring confirmation

1. **Hard size limit:** assume **1,000,000 bytes** (not 1 MiB). Confirm if the
   real limit is 1 MiB or a Fabric channel value.
2. **Maximum supported set size:** assume 32 members, matching current v2
   benchmarks. Confirm if larger sets must be supported.
3. **Context binding:** preserve the existing 32-byte context. Confirm.
4. **Old proof compatibility:** v2 proofs remain valid forever. Confirm.
5. **Prover resource budget:** confirm acceptable prove time and peak memory
   for the target deployment.
6. **New dependency:** v3 adds TCitH-MT/DECS/PACS mathematics. Confirm that a
   new external review/audit budget is available.
7. **No fallback:** if TCitH-MT cannot meet the size target with a reviewed
   parameter set, the plan stops rather than switching to a SNARK or silently
   lowering security. Confirm.

---

## 15. Current status and next action

Phase 0's model and Phase 1's primitives are complete. Phase 2 has a relation
compiler and differential tests for valid and invalid combined witnesses; it
does not yet implement the randomized LPPC aggregation or a proof system.
Before starting the prover, review the compiler's vector ordering against
FR25b and complete the Fiat–Shamir/query analysis for the exact transcript.
Keep all parameters experimental until those obligations and independent
review are complete.

---

## 16. Summary

V2's 27.4 MB proof is large because it opens two of three parties and sends
all 1,774 Mul shares for 219 repetitions. That design cannot be patched into
a sub-1 MB proof without changing the protocol.

V3 replaces the proof core with extended TCitH-MT:

- many virtual parties with packed Shamir sharing;
- Merkle commitments to a packed witness matrix;
- a degree-enforcing commitment;
- a Ligero-style PACS/LPPC constraint check;
- Fiat-Shamir with a new, versioned transcript.

The relation stays the same: one `x`, range and membership checked together in
one circuit and one proof. The current model predicts roughly 197 KiB, with a
hard acceptance limit below 1 MB. That remains an estimate until measured. The
old v2 path remains untouched. V3 requires its own soundness proof and external
review before any security or deployment claim.
