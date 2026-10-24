# NovaMPC v2 Hardening Roadmap

**Status:** implementation roadmap and source of truth for the v2 hardening work.  
**Baseline commit:** `65d3153` (`[STEP-10] Document v2 security proof and gaps`).  
**Target:** keep the **2/3 per-repetition** soundness bound, keep **BN254 `Fr`**, and target **~127-bit overall security**.  
**Non-goals:** no 1/3 redesign, no larger field, no 128-bit claim, no new proof system.

The code and tests must be real and reproducible. A green test suite is necessary but is **not** a security proof. Steps 03 and 05 require external cryptographic review before any security claim is made.

---

## 0. How the implementing agent must use this file

1. Read this file completely before changing code.
2. Check the progress table below and the commit history:
   ```bash
   git log --oneline --grep='\[STEP-'
   git status --short
   ```
3. Execute the steps in order. Do not skip a step because it looks easy or because a later step seems more interesting.
4. After each step:
   - run the commands listed in that step;
   - run `cargo fmt --check`;
   - update the progress table in this file;
   - commit with a message beginning with `[STEP-XX]`.
5. If interrupted:
   - inspect `git status` and `git diff`;
   - find the last `[STEP-XX]` commit;
   - finish or revert partial work before moving on;
   - resume at the first step marked `TODO`, `IN PROGRESS`, `BLOCKED-REVIEW`, or `BLOCKED-AUDIT`.
6. Never amend or force-push published commits. Add a new commit instead.
7. A step is not `DONE` if tests fail. Steps 03 and 05 are not `DONE` without the named external review/sign-off.

### Commit message convention

Every commit must contain the step number:

```text
[STEP-01] Add mandatory statement pinning and context binding
[STEP-01] Update v2 tests and serialization for proof version 3
[STEP-02] Add v2 transaction API
```

Multiple commits per step are allowed; every one repeats the same `[STEP-XX]` prefix. Include in the body what was tested:

```text
Tests: cargo test --lib v2:: -- --test-threads=1
```

---

## 1. Fixed decisions and non-goals

These are deliberate constraints. Do not "improve" them without a new decision from the project owner.

| Decision | Consequence |
|---|---|
| Keep the 2/3 per-repetition schedule | Do not attempt a 1/3 redesign. Do not claim 1/3. Prove and use the 2/3 bound. |
| Keep BN254 `Fr` | Root collision ceiling is ~127 bits, not 128. Do not claim 128-bit end-to-end. |
| Keep Poseidon2 constants and field | Do not regenerate constants or swap hashes. |
| No new trusted-root type/trait | The API requires a caller-supplied expected statement. The caller authenticates the root. |
| v1 remains as legacy | Deprecate and document; do not present v1 as part of the secure path. |
| Context is a 32-byte hash | The proof stores a context hash, not arbitrary raw context bytes. |
| Proof format changes | Bump `V2_PROOF_VERSION`; old proofs must fail cleanly. |
| M = 223 / 277 recommended | 218 / 272 are bare minima; 223 / 277 include ~3 bits of margin. |

**Do not add:** a new field, a new hash, a new proof system, a new dependency, a speculative constant-time layer, or a "trusted root" abstraction that the library cannot actually authenticate.

---

## 2. Baseline commands

Run these before starting and after each step. The baseline is known to have passed the v2-specific suites; a full `--all-targets` run previously exceeded 600 seconds.

```bash
cargo fmt --check
cargo test --lib v2:: -- --test-threads=1
cargo test --test v2_integration --test v2_soundness_gap -- --test-threads=1
cargo clippy --all-targets
```

For the full suite, use a longer timeout or run it in the background:

```bash
timeout 1800 cargo test --all-targets
```

Do not silently lower a repetition count or remove a test to make the suite faster.

---

## 3. Progress table

The agent must update this table at the end of every step. Keep the commit hash of the last commit for that step.

| Step | Fixes covered | Status | Last commit | Notes |
|---|---|---|---|---|
| 00 | Roadmap/baseline | DONE | `65d3153` | Baseline recorded; roadmap added in this commit |
| 01 | Fix 3, Fix 4 | DONE | `351222e` | Context + mandatory statement pinning; proof v3 |
| 02 | Fix 1, Fix 2 | DONE | `d8840e3` | v2 transaction API + caller-supplied statement |
| 03 | Fix 5 | BLOCKED-REVIEW | `8fbffe4` | 2/3 dossier written; awaiting named external reviewer |
| 04 | Fix 6 | DONE | `0fcd1e1` | M = 218/272 minima and 223/277 presets |
| 05 | Fix 7 | BLOCKED-AUDIT | `2965cd5` | Audit package written; awaiting independent audit |
| 06 | Fix 8 | IN PROGRESS | — | Adversarial and serialization tests; high-M evidence |
| 07 | Fix 1/2 support | TODO | — | Deprecate v1, docs, claim matrix |
| 08 | All | TODO | — | Final verification |

### Baseline and evidence notes

- Baseline at Step 00: v2 integration, transaction, and soundness-gap suites
  passed. The v2 library count is now **99** (the roadmap's expected 97 predates
  the two Step 04 preset tests).
- Step 06 evidence: 8 adversarial tests, 2 soundness-gap tests (range forgery
  plus combined-circuit port), and the ignored high-M release run
  (`M=223`: 2,279,379 bytes / 114 ms prove / 43 ms verify; `M=277`:
  2,853,947 bytes / 127 ms prove / 53 ms verify).
- Steps 03 and 05 are **not** DONE: no named external reviewer or auditor has
  signed off. Do not mark them DONE on self-review.

Allowed statuses: `TODO`, `IN PROGRESS`, `DONE`, `BLOCKED-REVIEW`, `BLOCKED-AUDIT`, `BLOCKED-CODE`.  
Use `BLOCKED-REVIEW`/`BLOCKED-AUDIT` for steps 03 and 05 until a named human signs off. Do not mark them `DONE` based on self-review.

---

## 4. Step 00 — Baseline and tracking

**Goal:** establish that the current tree is understood and that the roadmap is committed.

### Tasks

1. Run the baseline commands in Section 2.
2. Record any pre-existing failures or warnings; do not fix unrelated code in this step.
3. Confirm the current v2 suites pass. The expected baseline is: 97 v2 library tests, 6 v2 integration tests, 1 soundness-gap test.
4. Commit this file.

### Commit

```text
[STEP-00] Add v2 hardening roadmap
```

### Definition of done

- Baseline results recorded in the commit body.
- This roadmap committed.
- No source code changed.

---

## 5. Step 01 — [Fix 3 + Fix 4] Mandatory statement pinning and context binding

**Why first:** these changes alter the v2 proof format and verifier API. The transaction API must be built on the final safe API, not retrofitted later.

### 5.1 Context binding

Add a domain-separated context hash:

```rust
pub fn hash_context_v2(context: &[u8]) -> [u8; 32];
```

- Use BLAKE3 with a dedicated domain string, e.g. `"NovaMPC-v2/context/v1"`.
- Length-prefix the input before hashing so `("ab", "c")` and `("a", "bc")` cannot collide by concatenation.
- Add tests for deterministic output and different inputs producing different hashes.

Add to `V2Proof`:

```rust
pub context: [u8; 32],
```

- The proof stores the hash, not raw context bytes.
- Serialize it in `to_bytes`; require exactly 32 bytes in `from_bytes`.
- A missing/short/long context must be rejected.
- Changing the context hash must invalidate the proof.

Add the context to the Fiat–Shamir transcript:

```rust
absorb(&mut hasher, b"context", context);
```

Use a distinct absorption tag. Do not silently fold it into the statement encoding.

### 5.2 Proof version bump

- Set `V2_PROOF_VERSION = 3`.
- Update the suite/version tests.
- Old version-2 proofs must be rejected with a clear error.
- Do not add a compatibility path that accepts version 2.

### 5.3 Proving API

Add a context parameter to the v2 proving entry points:

```rust
pub fn prove(compiled: &CompiledV2, witness: &[Fr], context: [u8; 32], params: &V2Params) -> Result<V2Proof>;
pub fn prove_statement(statement: &StatementV2, witness: &[Fr], context: [u8; 32], params: &V2Params) -> Result<V2Proof>;
pub fn prove_range(lo: u32, hi: u32, value: u32, context: [u8; 32], params: &V2Params) -> Result<V2Proof>;
pub fn prove_membership(..., context: [u8; 32], params: &V2Params) -> Result<V2Proof>;
pub fn prove_combined(..., context: [u8; 32], params: &V2Params) -> Result<V2Proof>;
```

Update every call site, including tests and benchmarks. Use the compiler errors as the checklist.

### 5.4 Verification API

Make the raw verifiers crate-private:

```rust
pub(crate) fn verify(proof: &V2Proof, params: &V2Params) -> Result<()>;
pub(crate) fn verify_bytes(bytes: &[u8], params: &V2Params) -> Result<()>;
```

Add the only public verification entry points:

```rust
pub fn verify_statement(
    proof: &V2Proof,
    expected_statement: &StatementV2,
    expected_context: [u8; 32],
    params: &V2Params,
) -> Result<()>;

pub fn verify_bytes_statement(
    bytes: &[u8],
    expected_statement: &StatementV2,
    expected_context: [u8; 32],
    params: &V2Params,
) -> Result<()>;
```

`verify_statement` must:

1. Compare `proof.statement` with `expected_statement`.
2. Compare `proof.context` with `expected_context`.
3. Only then run the internal `verify`.

Return a `VerificationFailed` error on either mismatch. Do not rely on callers reading a warning comment.

Update all external tests to use `verify_statement` / `verify_bytes_statement`. The internal `src/v2/proof.rs` tests may continue to use the crate-private raw functions.

### 5.5 Tests for this step

Add or update tests covering:

- context round-trip through `to_bytes`/`from_bytes`;
- wrong context rejected by `verify_statement`;
- statement mismatch rejected;
- context tamper invalidates the proof;
- version 2 proof bytes rejected;
- missing/truncated/trailing context bytes rejected;
- `verify_statement` succeeds only with both the expected statement and expected context;
- the existing soundness-gap test still compiles and runs with the new proof field.

### 5.6 Commands

```bash
cargo fmt --check
cargo test --lib v2:: -- --test-threads=1
cargo test --test v2_integration --test v2_soundness_gap -- --test-threads=1
cargo clippy --all-targets
```

### Commit(s)

```text
[STEP-01] Add context binding and bump v2 proof format to version 3
[STEP-01] Enforce statement pinning in the public v2 verifier
[STEP-01] Update v2 tests for context binding and proof version 3
```

### Definition of done

- No public `verify` / `verify_bytes` remains.
- `verify_statement` and `verify_bytes_statement` are the public verifier entry points.
- Context is in the proof, serialization, and transcript.
- Old version-2 proofs are rejected.
- All v2 tests updated and passing.
- `src/v2/proof.rs` and `V2_SECURITY_ANALYSIS.md` references to the old API are updated.

---

## 6. Step 02 — [Fix 1 + Fix 2] v2 transaction API with a trusted statement

**Goal:** provide the transaction-facing v2 API without allowing the proof to supply the root.

### 6.1 New module

Add `src/v2/transaction.rs` and `pub mod transaction;` in `src/v2/mod.rs`.

Types:

```rust
pub struct TransactionStatementV2 {
    pub amount_range: (u32, u32),
    pub authorized_set_root: Fr,
    pub merkle_depth: u32,
    pub num_members: u32,
    pub context: Vec<u8>,
}

pub struct TransactionWitnessV2 {
    pub secret_value: u32,
    pub merkle_proof: MerkleProofV2,
}
```

Use `Fr`, not `u32`, for the root. Use `u32` for `merkle_depth` and `num_members` to match the v2 statement types.

Functions:

```rust
pub fn create_transaction_proof_v2(
    statement: &TransactionStatementV2,
    witness: &TransactionWitnessV2,
    params: &V2Params,
) -> Result<V2Proof>;

pub fn verify_transaction_proof_v2(
    proof: &V2Proof,
    expected_statement: &TransactionStatementV2,
    params: &V2Params,
) -> Result<()>;
```

Implementation requirements:

- `create_transaction_proof_v2`:
  - validate the range via `RangeStatementV2::new`;
  - validate membership via `MembershipStatementV2::new` (non-empty set, canonical depth);
  - compile the combined circuit with `compile_combined`;
  - build the witness with `CompiledV2::witness_for(secret_value, Some(&merkle_proof))`;
  - hash `statement.context` with `hash_context_v2`;
  - call the v2 prover.
- `verify_transaction_proof_v2`:
  - build the expected `StatementV2::Combined` from `expected_statement` only;
  - hash `expected_statement.context` with `hash_context_v2`;
  - call `verify_statement` with the expected statement and context;
  - never read the root or statement from `proof` to construct the expected values.

### 6.2 Trust boundary documentation

Add a doc comment:

> `expected_statement` MUST be reconstructed from authenticated ledger/consensus state. This function intentionally has no `verify(proof)` overload. Never construct the expected statement from the proof or from untrusted client input. The library verifies a relation about the statement; it does not authenticate the statement.

This is the code-level implementation of Fix 2. Do not add a `TrustedRoot` trait/newtype; the API shape and integration test are the enforcement.

### 6.3 v1 relationship

- Do not call `crate::tx_validation` from the v2 module.
- Do not convert a v1 `u32` root to `Fr`.
- Do not accept v1 `Proof`/`ProofParams` in the v2 transaction API.
- Update README/examples to show the v2 API. Keep v1 examples clearly labeled legacy.

### 6.4 Tests

Add `tests/v2_transaction.rs` (or similar) covering:

- honest v2 transaction proof verifies against a statement built from a mock ledger root;
- attacker proof for an attacker-chosen root is rejected when the expected root is the ledger root;
- wrong range, wrong member count, wrong depth, wrong context are rejected;
- a v2 proof is not accepted by the v1 transaction verifier (type/format separation; at minimum test the serialized formats cannot be confused);
- no `u32` root appears in the v2 transaction API.

### 6.5 Commands

```bash
cargo fmt --check
cargo test --lib v2:: -- --test-threads=1
cargo test --test v2_integration --test v2_soundness_gap --test v2_transaction -- --test-threads=1
cargo clippy --all-targets
```

### Commit(s)

```text
[STEP-02] Add v2 transaction API with Fr root and context
[STEP-02] Add trusted-statement transaction tests
```

### Definition of done

- New v2 transaction API compiles and works end-to-end.
- The expected root/statement comes from the caller, never from the proof.
- v1 types are not used by the new API.
- Root-substitution and context-substitution tests fail closed.
- README/examples point to the v2 transaction API.

---

## 7. Step 03 — [Fix 5] 2/3 soundness and extraction dossier

**Important:** this is a research/documentation step, not a code-only step. An AI agent can produce a careful proof draft and adversarial evidence; it cannot certify the theorem. Mark the step `BLOCKED-REVIEW` until a named cryptographer signs off.

**Goal:** establish the exact 2/3 bound and the limits of the extraction argument, using the actual code after Steps 01–02.

### 7.1 Documents

Update `V2_SECURITY_ANALYSIS.md` and add `V2_SOUNDNESS_2_3.md` with:

1. **Scope and non-claims.** State that this is a proof draft, not a machine-checked proof or audit.
2. **Protocol and transcript.** Describe the v3 proof format, context hash, circuit hash, commitments, assertion rows, and challenge derivation.
3. **Assumptions.** List them explicitly: canonical circuit, commitment binding, transcript encoding, ideal challenge, MPC algebra, canonical field sampling, implementation, no side channels.
4. **Completeness.** State the honest-prover lemma and what it depends on.
5. **Per-repetition soundness lemma.** For a false statement and a fixed pre-challenge prefix, at most two of the three hidden-party choices can accept. Give the proof, including the exact skipped-Mul edge and assertion-share argument.
6. **Tightness.** Keep the concrete false-range forgery and explain why it attains 2/3. Do not hide it. State that at `M=218/272` the event is below the 127-bit target; at `M=96` it is not.
7. **Parallel repetition and grinding.** Derive `q * (2/3)^M` and the bit formula `M*log2(3/2) - log2(q)`. Define `q` and give a table for `q=1`, `q=2^20`, `q=2^32`.
8. **Knowledge soundness / extraction.** State the special-soundness observation (three transcripts for a fixed prefix), then the Fiat–Shamir forking extractor. Identify every loss term and every unresolved step. If a full extractor cannot be proved, say so explicitly; do not claim knowledge soundness.
9. **Zero knowledge.** Keep the simulator sketch and list the missing proof steps. Do not claim ZK.
10. **Parameter table.** State the 127-bit ceiling, the 2/3 bound, and the bare/with-margin repetition counts.
11. **Review gate.** Add a table for reviewer name, date, scope, and verdict. Until signed, the status is `DRAFT / AWAITING REVIEW`.

### 7.2 Code/test work

- Ensure `tests/v2_soundness_gap.rs` still demonstrates the 2/3 event at `M=1`.
- Add a test or script that records the parameter arithmetic for `M=218/223/272/277`; keep it deterministic.
- Do not change the protocol to chase 1/3. Only fix a gap if the analysis shows an attack **better than 2/3**. If such a better attack is found, stop and open a new decision; do not silently change the schedule.
- Do not change README to say "proven" before review.

### 7.3 Commands

```bash
cargo test --test v2_soundness_gap -- --nocapture
cargo test --lib v2:: -- --test-threads=1
```

### Commit(s)

```text
[STEP-03] Draft 2/3 soundness and extraction analysis
[STEP-03] Add parameter arithmetic checks for the 127-bit target
```

### Definition of done

- The dossier is internally consistent and references the actual v3 code.
- The concrete 2/3 attack and the `q*(2/3)^M` bound are both documented.
- The extraction/ZK gaps are explicit, not hand-waved.
- Status is `BLOCKED-REVIEW` until a named human cryptographer signs off.
- No claim of a completed security proof in README or code comments.

---

## 8. Step 04 — [Fix 6] Parameter presets for ~127-bit

**Goal:** make the secure parameter choice explicit and hard to confuse with the old `M=96` preset.

### 8.1 Constants and presets

In `src/v2/suite.rs` add documented constants and constructors:

```rust
pub const SECURE_127_TARGET_BITS: u32 = 127;
pub const SECURE_127_Q1_MIN_REPETITIONS: u32 = 218;
pub const SECURE_127_Q32_MIN_REPETITIONS: u32 = 272;

impl V2Params {
    /// M=223, ~130.4-bit proof soundness at q=1; ~127-bit overall cap.
    pub fn secure_127() -> Self { Self::new(3, 223) }

    /// M=277, ~130.0-bit proof soundness with q=2^32; ~127-bit overall cap.
    pub fn secure_127_grinding_2_32() -> Self { Self::new(3, 277) }
}
```

- Keep `balanced()` (`M=96`) for legacy tests/benchmarks, but its doc must say **not secure** and that it is only for format/testing.
- Do not silently change `balanced()` to a secure value; that would hide the parameter choice and break the historical comparison.
- Document the arithmetic:
  - `M=218`: `218*log2(3/2) ≈ 127.5` at `q=1`.
  - `M=272`: `272*log2(3/2) - 32 ≈ 127.1` at `q=2^32`.
  - `M=223`: ~130.4 at `q=1` (margin).
  - `M=277`: ~130.0 at `q=2^32` (margin).
- State clearly that the BN254 root collision ceiling is ~127 bits; the proof margin does not raise the overall cap above 127.

### 8.2 Transaction API

- Update `v2::transaction` docs/examples to use `secure_127()` or `secure_127_grinding_2_32()`.
- Do not make `M=96` the default in the transaction API.
- If the caller passes arbitrary `V2Params`, document that they are responsible for the security level. Do not guess `q`.

### 8.3 Tests

- Unit-test the constants against the formula using deterministic arithmetic (floating point is acceptable in tests only).
- Assert `secure_127().num_repetitions == 223` and `secure_127_grinding_2_32().num_repetitions == 277`.
- Assert `balanced().num_repetitions == 96` and that its doc/test labels it insecure.
- Keep fast tests on `fast_insecure()`; a full `M=223/277` proof belongs in the ignored high-M test (Step 06).

### 8.4 Commands

```bash
cargo fmt --check
cargo test --lib v2:: -- --test-threads=1
cargo test --test v2_transaction -- --test-threads=1
cargo clippy --all-targets
```

### Commit(s)

```text
[STEP-04] Add secure_127 parameter presets
[STEP-04] Document 127-bit parameter arithmetic and update transaction examples
```

### Definition of done

- Secure presets exist and are tested.
- `M=96` is clearly legacy/test-only.
- README/V2 design docs no longer imply that `M=96` is a 128-bit setting.
- No 128-bit claim remains.

---

## 9. Step 05 — [Fix 7] Audit dossier: knowledge soundness, ZK, side channels, primitives

**Important:** an audit is not a proof, and an AI self-review is not an independent audit. Mark `BLOCKED-AUDIT` until an external reviewer signs off. The agent's job is to prepare a complete, honest package and fix issues the reviewers identify.

### 9.1 Deliverable: `V2_AUDIT_PACKAGE.md`

Include:

1. **Scope and threat model.** Assets, adversary capabilities, trust boundaries, what is in/out of scope.
2. **Code map.** v2 field, Poseidon2, Merkle, circuit, predicate, MPC, commitment, seed tree, proof, transaction.
3. **Cryptographic assumptions.** Poseidon2 instance and collision resistance; BLAKE3 commitments/transcript; ChaCha RNG; ideal-challenge model; canonical field encoding.
4. **Proof status.** 2/3 soundness dossier status; knowledge soundness and ZK explicitly unresolved or reviewed; extraction losses; `q` budget.
5. **Side-channel checklist.** Secret-dependent branches, variable-time field/group operations, RNG use, memory zeroization, proof parsing, error messages. State clearly what is **not** established; do not claim constant-time without analysis.
6. **Primitive pins.** Poseidon2 constants/upstream SHA-256; BLAKE3 and ChaCha versions; domain separation strings; suite/version IDs.
7. **Test evidence.** Commands and results, including the high-M test and adversarial suite.
8. **Known gaps and non-claims.** v1 legacy path, 127-bit ceiling, conditional challenge model, no 128-bit claim.
9. **Reviewer sign-off table.** Name, date, scope, findings, verdict.

### 9.2 Code and docs

- Fix only concrete issues found by static analysis or reviewer findings. Do not add speculative cryptography.
- Update `README.md` to point to the audit package and to state the exact claim status.
- Do not mark the audit complete without a named external reviewer.

### 9.3 Commands

```bash
cargo fmt --check
cargo clippy --all-targets
cargo test --all-targets
```

### Commit(s)

```text
[STEP-05] Add v2 audit package and limitation checklist
[STEP-05] Align security claims with the 127-bit ceiling
```

### Definition of done

- Package is complete and honest.
- All known gaps are listed; none are hidden.
- External audit status is `AWAITING AUDIT` or `COMPLETED` with sign-off.
- No README/code comment claims ZK, knowledge soundness, side-channel resistance, or 128-bit security without evidence.

---

## 10. Step 06 — [Fix 8] Adversarial and serialization tests

**Goal:** make the failure modes executable, especially the ones introduced by the API changes.

### 10.1 New test files

Add:

- `tests/v2_adversarial.rs`
- `tests/v2_transaction.rs` (if not already created in Step 02)
- `tests/v2_high_m.rs` (ignored by default)

Use `V2Params::fast_insecure()` for normal tests; use `secure_127()` only in the ignored high-M test.

### 10.2 Required cases

**Statement and root substitution**

- Valid proof for statement A; `verify_statement` with statement B fails.
- Valid proof for root A; expected transaction statement with root B fails.
- Attacker-controlled root, ledger expected root: fails.
- Wrong `num_members` / `depth`: fails.
- Proof for range-only statement presented as combined: fails.

**Context and replay**

- Proof with context A verifies with A.
- Same proof with expected context B fails.
- Mutating the proof's context hash fails transcript verification.
- Document that context binding prevents cross-context replay; it does not replace an outer transaction nonce. Do not claim replay protection beyond the bound context.

**Membership / combined**

- Wrong private value against a valid Merkle path: prover rejects.
- Wrong leaf index, sibling, root, count, or depth: verifier rejects.
- Attempt to port the known range hidden-party forgery to membership/combined. If it succeeds, record it as a new known gap and do **not** claim the soundness issue is fixed. If it fails, keep the test as a regression.
- Do not weaken the existing `v2_soundness_gap` test.

**Serialization**

- Wrong magic, version 2, unsupported version, wrong params, wrong statement, wrong context length.
- Truncated proof; trailing bytes; non-canonical `Fr` encoding; oversized lengths; duplicate/unknown statement tags.
- `from_bytes` must never panic.

**v1/v2 separation**

- v1 serialized proof is not accepted as a v2 proof and vice versa.
- The v2 transaction API does not reference v1 types.
- v1 is deprecated/legacy, not silently accepted.

**High-M**

- `#[ignore]` test at `M=223` (and `M=277` if runtime permits) using `secure_127*`.
- Assert the proof verifies, print proof size and elapsed time.
- Run in release:
  ```bash
  cargo test --release --test v2_high_m -- --ignored --nocapture
  ```
- Record results in `README.md` or the audit package. Do not silently reduce `M` because the test is slow.

### 10.3 Commands

```bash
cargo fmt --check
cargo test --test v2_adversarial --test v2_transaction --test v2_integration --test v2_soundness_gap -- --test-threads=1
cargo test --release --test v2_high_m -- --ignored --nocapture
cargo clippy --all-targets
```

### Commit(s)

```text
[STEP-06] Add v2 adversarial tests for statement, root, context, and serialization
[STEP-06] Add ignored high-M proof test and record size/time
```

### Definition of done

- All normal tests pass.
- The high-M test is run at least once and results recorded.
- Every known failure mode has a regression test.
- No test uses the raw verifier from outside the crate.

---

## 11. Step 07 — Deprecate v1 and update the public story

**Goal:** make the secure path unambiguous. v1 remains for historical comparison, but it is not part of the claimed secure transaction path.

### 11.1 Deprecation

Mark the v1 transaction API deprecated:

```rust
#[deprecated(note = "v1 uses a 32-bit set-membership root; use v2::transaction")]
```

Apply to the v1 transaction statement/witness and the `create_transaction_proof` / `verify_transaction_proof` functions. Add `#[allow(deprecated)]` where the v1 tests intentionally exercise it.

Do not delete v1 unless the project owner explicitly asks. Do not present it as secure. If a future deployment needs a single exposed path, add a `legacy-v1` feature in a separate decision; that is not part of this roadmap.

### 11.2 Documentation

Update:

- `README.md`: v2 transaction API, context, statement pinning, M presets, ~127-bit cap, v1 legacy, no production claim until audit.
- `GUIDE.md` and any integration notes: replace v1 examples with v2; if a v1 example is retained, label it legacy.
- `V2_DESIGN.md`: context, proof version 3, safe verifier, M.
- `V2_SECURITY_ANALYSIS.md`: v3 transcript, 2/3 bound, q, 127-bit ceiling.
- `fixes.md`: progress table.

Search for stale references:

```bash
git grep -n "authorized_set_root: u32"
git grep -n "verify(&proof" 
git grep -n "M=96\|M = 96"
git grep -n "128-bit\|128 bit"
```

Each remaining occurrence must be clearly legacy/test-only or removed.

### 11.3 Tests

- Add a test or documentation check that the secure transaction example uses `v2::transaction` and `secure_127*`.
- Ensure v1 and v2 proof formats cannot be confused.
- Ensure no README example calls the raw v2 verifier.

### 11.4 Commit(s)

```text
[STEP-07] Deprecate v1 transaction API and update v2 integration docs
[STEP-07] Remove stale 128-bit and raw-verifier claims from documentation
```

### Definition of done

- v1 is deprecated and clearly legacy.
- All examples use the v2 transaction API.
- No documentation claims 128-bit or production security.
- The 2/3 and 127-bit limitations are easy to find.

---

## 12. Step 08 — Final verification and claim review

**Goal:** prove the implementation is complete and the claim is exactly what the evidence supports.

### 12.1 Commands

```bash
cargo fmt --check
cargo clippy --all-targets
cargo test --lib v2:: -- --test-threads=1
cargo test --test v2_integration --test v2_soundness_gap --test v2_adversarial --test v2_transaction -- --test-threads=1
cargo test --release --test v2_high_m -- --ignored --nocapture
timeout 1800 cargo test --all-targets
```

If `--all-targets` times out, run the remaining suites individually and document exactly what was and was not run. Do not claim a full green run without evidence.

### 12.2 Static checks

```bash
git grep -n "pub fn verify(" src/v2/proof.rs
git grep -n "pub fn verify_bytes(" src/v2/proof.rs
git grep -n "authorized_set_root: u32" src
git grep -n "128-bit\|128 bit\|production-secure\|proven secure" README.md *.md
git grep -n "TODO\|unimplemented!\|todo!" src/v2
```

Expected:

- raw v2 verifiers are `pub(crate)`, not `pub`;
- no v2 transaction API uses `u32` for the root;
- no doc claims 128-bit or production security;
- no unresolved TODO in the v2 path;
- legacy v1 references are labeled.

### 12.3 Final claim matrix

Update `README.md` with a short table:

| Claim | Status |
|---|---|
| v2 root is BN254 `Fr`, ~127-bit collision ceiling | implemented/tested |
| Transaction API uses `Fr` root + count/depth + context | implemented/tested |
| Statement pinning is mandatory | implemented/tested |
| Root is caller-authenticated, not proof-supplied | implemented/tested (API shape) |
| 2/3 soundness bound and extraction | draft / awaiting external review |
| Knowledge soundness | not claimed unless reviewed |
| Zero knowledge | not claimed unless reviewed |
| Side channels | not claimed unless audited |
| 128-bit end-to-end | **not claimed** |
| Production deployment | **not claimed** |

### 12.4 Final commit

```text
[STEP-08] Final v2 verification and security claim review
```

### Definition of done

- All implementation and test steps are complete.
- The progress table is up to date with commit hashes.
- External review/audit status is explicit.
- The final claim is ~127-bit under stated assumptions, not 128-bit and not "unconditionally secure."
- No code or documentation overclaims.

---

## 13. What the final claim may look like

Only after Steps 01–08 and the external review/audit gates:

> “The v2 transaction path uses a BN254 `Fr` set-membership root (~127-bit generic collision ceiling), a mandatory expected statement and context, an authenticated external root, and a 2/3-per-repetition MPCitH proof with `M=223` (q=1) or `M=277` (q=2^32). Under assumptions A1–A6 and the named audit/review, this provides approximately 127-bit security. v1 is legacy and is not part of the secure path. We do not claim 128-bit security, zero knowledge, or production readiness beyond the reviewed scope.”

If the 2/3 proof or audit is not completed, the claim must stop at:

> “Implementation and tests are complete; the security proof/audit is pending.”

Do not write the stronger claim early.
