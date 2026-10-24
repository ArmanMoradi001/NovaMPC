# Project Architecture & Technical Guide: Privacy-Preserving Transaction Validation via MPC-in-the-Head

> **Scope and status:** this guide describes the **legacy v1** architecture
> (`u32` arithmetic, MiMC root, SHA3 transcript). It is retained for research
> context. The hardened **v2** path lives under `src/v2/`, uses BN254 `Fr` plus
> Poseidon2, proof format v3 with a caller-pinned statement and context hash,
> and is documented in [`README.md`](README.md), [`V2_DESIGN.md`](V2_DESIGN.md),
> and [`V2_AUDIT_PACKAGE.md`](V2_AUDIT_PACKAGE.md). The v1 transaction API is
> `#[deprecated]`; use `v2::transaction` for new work. Neither path is approved
> for production deployment, and v2 knowledge soundness, zero knowledge, and
> side-channel resistance remain unaudited.

> Crate: `mpcith-zk` (`src/lib.rs`) — MPC-in-the-Head ZKP over `Z_{2^32}` (wrapping `u32` arithmetic).
> Paradigm: Ishai et al. STOC'07 MPCitH + ZKBoo / Picnic / KKW cut-and-choose + Fiat-Shamir.
> No trusted setup. Symmetric-key-only primitives (BLAKE3, SHA3-256, ChaCha20, MiMC) — no number-theoretic assumptions. Using symmetric primitives does **not** by itself establish post-quantum security: this **prototype has no end-to-end security proof, no audit, and makes no post-quantum or production-security claim** (see `README.md` → Security Considerations).

---

## 1. Executive Summary

This system proves statements of the form:

> “I know a secret witness `w` such that `Circuit(w) == public_output`”

without revealing `w`. The prover **simulates an N-party MPC execution of an arithmetic circuit in its head**, commits to each virtual party’s view, and lets a Fiat-Shamir-derived challenge select `N-1` views to open. The verifier replays the opened parties deterministically from their seeds and checks:

1. commitments authenticate under a per-repetition Merkle root,
2. opened views are MPC-consistent (linear gates locally, `Mul` via ZKBoo cross-check),
3. reconstructed `AssertEq` / output sums equal public constants.

Confidential transaction validation is the target application (`src/tx_validation.rs`, **v1 legacy/deprecated**; the v2 equivalent is `src/v2/transaction.rs`): prove `lo <= secret_value <= hi ∧ secret_value ∈ authorized_set ∧ context_binding` where the set is Merkle-authenticated and the block/channel `context` is transcript-bound for replay protection. The API is Fabric-oriented; there is no chaincode integration in this tree.

Key cryptographic primitives:

| Primitive | Role | Implementation |
| :--- | :--- | :--- |
| **MPC-in-the-Head** | ZK from MPC: `N=3` virtual parties, `M` repetitions, 2-of-3 opening | `src/mpc.rs`, `src/sharing.rs`, `src/proof.rs` |
| **MiMC Feistel hash** | Circuit-friendly hash (`Add`+`Mul` only) for in-circuit Merkle hashing | `src/mimc.rs` (`MIMC_ROUNDS=64`) |
| **Merkle trees (dual)** | (a) MiMC/`u32` state tree for `SetMembership`; (b) BLAKE3/`[u8;32]` commitment tree per repetition | `src/merkle.rs`, `src/commit_merkle.rs` |
| **Seed tree (GGM)** | Compress `N-1` opened seeds to `O(log N)` co-path | `src/seed_tree.rs` |
| **Fiat-Shamir transform** | Non-interactive challenge `e[i] ∈ [0,N)` via SHA3-256 + ChaCha20 expansion | `src/fiat_shamir.rs` |
| **Commitments** | Per-party hiding/binding commitments via keyed BLAKE3 | `src/commitment.rs` |

Soundness per repetition is `(N-1)/N = 2/3` at `N=3` (ZKBoo 2-of-3 opening). Total soundness error `((N-1)/N)^M`, i.e. `M·log2(N/(N-1))` forgery-model estimate bits — a repetition count, **not** an end-to-end security claim for this prototype. The 2/3 figure is a model estimate for the custom transcript: the skipped-`Mul` and published-share consistency arguments are not formally proved here, and the Fiat-Shamir transform adds a grinding/query loss (see the project's cryptographic review notes). `N` is **fixed to 3** (`ProofParams::validate()` enforces it) because the multiplication check is the ZKBoo 3-party verifiable scheme.

---

## 2. High-Level Architecture

### 2.1 End-to-end ZKP pipeline

```text
Secret Inputs (witness w)
   │
   ▼
Arithmetic Circuit C  (src/circuit.rs + src/predicate.rs)
   │  Gates: Add / Mul / AddConst / MulConst / AssertEq over Z_{2^32}
   ▼
MPC Simulation, N=3 parties  (src/sharing.rs + src/mpc.rs)
   │  Additive sharing; linear gates local; Mul via ZKBoo + zero-shares
   ▼
Commitment & Merkle Tree  (src/commitment.rs + src/commit_merkle.rs + src/seed_tree.rs)
   │  com[rep][p] = BLAKE3_key(domain(rep,p) || rand || seed_p || view_bytes_p)
   │  root[rep] = BLAKE3-Merkle(com[rep][0..N]); seeds from GGM tree
   ▼
Fiat-Shamir Challenge  (src/fiat_shamir.rs)
   │  e = SHA3-256("mpcith-zk:fiat-shamir:v1" || roots || shares || pubs || H(C))
   │  expanded via ChaCha20 → hidden_party[rep] ∈ [0,N)
   ▼
Proof Generation & Verification  (src/proof.rs + src/tx_validation.rs)
      open N-1 views/rep (co-path + auth paths) → Verifier recomputes & asserts
```

Mermaid equivalent:

```mermaid
flowchart LR
  S[Secret Inputs<br/>witness w] --> C[Arithmetic Circuit C<br/>Add/Mul/Const/AssertEq over Z_2^32]
  C --> M[MPC Simulation<br/>N=3 additive shares<br/>ZKBoo Mul + zero-shares]
  M --> K[Commitment & Merkle Tree<br/>BLAKE3 com per view<br/>root per repetition]
  K --> F[Fiat-Shamir Challenge<br/>SHA3-256 transcript<br/>hidden party per rep]
  F --> P[Proof Generation<br/>co-path + opened views<br/>output/assert shares]
  P --> V[Verification<br/>recompute seeds/views<br/>check sums & consistency]
```

### 2.2 Prover workflow

1. **Compile** `Predicate`/`CompoundPredicate` → `Circuit` (`predicate.compile()`).
2. **Evaluate** circuit natively on `w` to check satisfiability; record `expected_outputs`, `assert_constraints`.
3. For each repetition `rep ∈ [0,M)`:
   a. Sample 32-byte `root_seed`; expand via `SeedTree::build(root_seed, N)` → `N` leaf `PartySeed`s.
   b. Secret-share each witness word with per-party ChaCha20 RNGs (`Sharing::share_with_rngs`); party `N-1` gets the residual share.
   c. Emulate circuit gate-by-gate (`run_mpc_emulation`); record per-party `mul_output_shares` + residual inputs → `PartyView`.
   d. Commit: `commit_view(rep, p, seed_p, view_bytes_p, rand_p)` → `CommitmentMatrix`; build `CommitTree` → `commitment_root[rep]`. Collect `output_shares`, `assert_shares` (all parties, all reps).
4. **Challenge**: `derive_challenges(roots || encode_public_shares(...) || public_inputs || H(C), M, N)` → `hidden_party[rep]`.
5. **Open**: for each `rep`, transmit `N-1` `OpenedView`s (view + randomness + BLAKE3 auth path) + GGM `co_path(hidden)` + public share matrices.

### 2.3 Verifier workflow (`verify_unchecked`, crate-private)

1. Check `proof.public_inputs == expected`, repetition count, `hash_circuit(embedded) == circuit_hash`.
2. `validate_proof_structure()`: bounds on wires/gates (`MAX_* = 2^22`), wire-index ranges, `hidden_party < N`, opened multiset `== {0..N}\{hidden}`, share-row dimensions, auth-path/co-path lengths. Fail-closed, no panics on hostile input.
3. Recompute Fiat-Shamir challenges identically; reject on `hidden_party` mismatch.
4. Per repetition:
   a. `reconstruct_leaves_from_co_path(co_path, hidden, N)` → opened seeds.
   b. `recompute_linear_shares()` per opened party (seed RNG for inputs, except residual party uses transmitted shares; `Mul` outputs taken from proof).
   c. Recompute `commit_view` with reconstructed seed, verify BLAKE3 Merkle proof against `commitment_root`.
   d. `verify_party_view()`: linear-gate consistency + ZKBoo `Mul` cross-check when neighbour also opened.
   e. Cross-check revealed `assert_shares`/`output_shares` against recomputed wire shares (anti-equivocation).
   f. Value checks: `Σ_p assert_shares[gate][p] == expected` for **every** `AssertEq`; `Σ_p output_shares[out][p] == circuit-derived expected` (prefer `assert_expected_for_output`, else `proof.expected_outputs`). The fallback `expected_outputs` is prover-supplied and **not** transcript-bound, so it is only meaningful for output wires without an `AssertEq` target; current predicates always assert their outputs.
5. Public wrappers (`verify_predicate`, `verify_compound`, `verify_transaction_proof`) first **recompile the intended predicate/statement and compare `hash_circuit`** — this closes circuit-substitution (prover embedding a tautology).

---

## 3. Cryptographic & Mathematical Foundation

### 3.1 MiMC Feistel Hash (`src/mimc.rs`)

SHA-256 costs ~25k AND-gates per compression — prohibitive inside MPCitH where every `Mul` gate adds per-repetition view data and verifier work. MiMC uses only field additions and cubings, i.e. `Add`/`Mul` gates natively.

Round function over `Z_{2^32}` (wrapping `u32`, **not** a prime field `GF(p)`). The cube map is not a permutation modulo `2^32` (e.g. `0^3 ≡ 2048^3 ≡ 0`), and the construction has no leaf/internal domain separation. It is adequate only for this prototype's functional tests: the resulting 32-bit root gives ≈`2^16` birthday collision resistance and must **not** be used for high-security set binding. (The project's cryptographic review notes separate this set-binding weakness from soundness of the circuit relation.) The round function is:

```text
new_left  = right
new_right = left + (right + k + c_r)^3   (mod 2^32)
```

where `k=0` in the 2n/n keyless hash variant (key folded into state), and `c_r` is the round constant.

- `mimc_constants(n)`: deterministic `BLAKE3("mimc-mpcith-zk-v1" || LE32(counter))` streamed as LE `u32`s. No trusted setup.
- `MIMC_ROUNDS = 64`.
- `build_mimc_hash(builder, left, right, rounds) -> (left_out, right_out)`: emits per round `AddConst(right,c_i) → Mul(temp,temp) → Mul(sq,temp) → Add(left,cu)` (2 `Mul` + 2 `Add` per round), then `MulConst(x,1)` copies so outputs are trailing wires. Only `hash_left` is used as Merkle parent.
- `mimc_hash_native(l, r, rounds)`: plain `wrapping_add`/`wrapping_mul` reference for witness generation and native tree building. Unit-tested for circuit/native agreement.

Merkle parent = `mimc_hash_native(l,r).0`. Depth-`d` membership costs `d·64·2` `Mul` gates — the dominant cost of `SetMembership`.

### 3.2 Arithmetic Circuit (`src/circuit.rs`, `src/predicate.rs`)

Choice: **arithmetic circuit over the ring `Z_{2^32}`** instead of boolean circuit.

- Native machine-word semantics; addition/multiplication map 1:1 to gates.
- Linear gates (`Add`, `AddConst`, `MulConst`, `AssertEq`-copy) are **non-interactive** in MPC: each party computes its share locally (`Sharing::add/add_const/mul_const`).
- Only `Mul` is **non-linear / interactive**: requires correlated randomness (ZKBoo zero-shares) and its output share must be committed and cross-checked. `Gate::is_interactive()` returns true only for `Mul`.
- `Gate::Xor` exists as an enum variant but is **rejected** by `run_mpc_emulation` / `verify_party_view` / `recompute_linear_shares`. All real XOR logic goes through `CircuitBuilder::xor()`, which expands `XOR(a,b) = Σ_i (a_i + b_i − 2·a_i·b_i)·2^i` using bit-decomposition constraints + `Mul` gates (see §4 `circuit.rs` row).

Gate set:

```rust
Add{left,right,output}           // wires[o] = wires[l] + wires[r] (wrapping)
Mul{left,right,output}            // wires[o] = wires[l] * wires[r] (wrapping) — interactive
Xor{..}                          // legacy; emulation returns CircuitError
AddConst{input,constant,output}   // + public constant (party 0 adds it in MPC)
MulConst{input,constant,output}   // * public constant (all parties scale)
AssertEq{input,expected,output}   // copy + require wires[input]==expected
```

Builder notes: `CircuitBuilder::new(n)` allocates inputs `0..n`; `new_with_reserved_xor_inputs(n,k)` pre-reserves `64·k` contiguous input wires for `xor()` bit slots (fixes historical input-interleaving bug). `bit_decompose_on(input, bits)`: booleanity `b·(b−1)==0` + reconstruction `Σ b_i·2^i − input == 0` via `MulConst(input, 0xFFFF_FFFF)` for negation.

Predicate compilations (`src/predicate.rs`):

- `AdditionCheck{s}`: `add(0,1); assert_eq(sum,s)`. Witness `[x,y]`, pubs `[s]`.
- `MultiplicationCheck{p}`: `mul(0,1); assert_eq(prod,p)`.
- `XorCheck{expected_xor}`: reserved-inputs builder + `xor(0,1); assert_eq`. Witness `[x,y]+64` bits, pubs `[x ^ y]`.
- `RangeCheck{lo,hi}`: `width=hi-lo` (require `<2^31`, audit C-2), `k=bits_needed(width)`; layout `[x, x_bits(32), shifted_bits(k), slack_bits(k)]`; `shifted=x−lo`, `slack=width−shifted`; decompose all three; output dummy `0`. Algebraic range argument (given the booleanity/reconstruction constraints): `shifted+slack==width ∧ shifted,slack ∈ [0,2^k)` ⇒ `0<=shifted<=width` for `k<=31`; this is a circuit-relation property, not a protocol soundness proof.
- `SetMembership{members}`: native `MerkleTree::build(members)` → `root` (sole pub); witness `[leaf,index,bits(d),siblings(d)]`, `d=log2(pad_len)`; decompose index, enforce `index < members.len()` via ripple-carry overflow circuit (`constrain_index_below_num_members`, audit F-1, zero extra witness wires), bit-select left/right per level, MiMC up, `assert_eq(computed,root)`.
- `CompoundPredicate::And`: `merge_same_witness_circuits` — concatenates inputs/intermediates and prepends 3 link gates (`MulConst(right0,−1); Add(left0,neg); AssertEq(diff,0)`) forcing both halves to share primary input wire 0 (audit C-3). `range_and_membership[_for_verify]` builds `RangeCheck ∧ SetMembership`.

### 3.3 Merkle Trees (`src/merkle.rs`, `src/commit_merkle.rs`)

Two **deliberately separate** trees:

| Tree | Hash | Leaf type | Evaluated in-circuit? | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `MerkleTree` (`src/merkle.rs`) | MiMC-2n/n (`.0` word), `MIMC_ROUNDS` | `u32` | **Yes** — recomputed gate-by-gate in `SetMembership` | State/set inclusion: root is public input; witness carries `(leaf,index,bits,siblings)` |
| `CommitTree` (`src/commit_merkle.rs`) | BLAKE3(`left\|\|right`) | `[u8;32]` (a `Commitment`) | **No** — native only | Per-repetition view-commitment authentication: leaves = `com[rep][0..N]` (all `N` parties), root replaces transmitting hidden commitment |

Both use flat heap layout (`nodes[1]`=root, children `2i,2i+1`, `base=1<<depth`), zero-padding to next power of two, `prove_membership(idx)` returning bottom-up siblings, `verify()` recomputing with sided hashing. **Both** `verify()` methods reject any `leaf_index` with unconsumed bits after the path (a claimed position deeper than the path describes, e.g. `i + 2^depth`); the `CommitMerkleProof` check was added to match `MerkleProof`. `CommitMerkleProof{leaf,leaf_index,siblings,root}` is reconstructed by the verifier from the recomputed `commit_view` leaf + transmitted `commitment_auth_path`.

This split is load-bearing: MiMC must match the circuit; BLAKE3 commitments must **not** be circuit-evaluated (would be enormous) — they only need native binding/hiding.

### 3.4 Seed Tree (`src/seed_tree.rs`)

Naively revealing `N-1` 32-byte seeds per repetition costs `(N-1)·32·M` bytes (e.g. `~12.6 KB` at `N=3,M=219` — before views). The GGM tree compresses this to `log2(N_padded)·32·M`.

Construction (length-doubling PRG from BLAKE3):

```text
left_child  = BLAKE3(parent || 0x00)
right_child = BLAKE3(parent || 0x01)
```

- `SeedTree::build(root_seed, N)`: 1-indexed heap `nodes[1..2·n_padded]`; `n_padded = N.next_power_of_two()`; internal nodes `1..n_padded` expanded top-down; `leaf_seeds()` = first `N` leaves. Padding leaves (`N..n_padded`) derived but never used/committed.
- `co_path(hidden)`: sibling at each level from hidden leaf up to (not incl.) root — `depth = trailing_zeros(n_padded)` entries, leaf-level first.
- `reconstruct_leaves_from_co_path(co_path, hidden, N)`: validates lengths/indices (returns `VerificationFailed`, never panics on hostile input), expands each co-path sibling subtree downward, discards padding, returns `N` entries with `hidden` slot zeroed (must not be used).
- Per-repetition prover flow: `root_seed ← thread_rng`; `SeedTree::build` → `PartySeed`s → emulation; later `tree.co_path(hidden)` stored in `RepetitionProof.co_path`. Verifier calls reconstruct + `PartySeed.0.to_rng(b"mpcith-party-share")` / zero-share PRG to replay opened parties bit-for-bit.

At `N=3`: `n_padded=4`, `depth=2`, co-path = 64 bytes/rep vs 64 bytes naive — no saving yet, but the mechanism is required for correctness (seed determinism) and scales as `O(log N)`.

---

## 4. Module Breakdown & Source File Map

| File | Responsibilities | Key Structs / Functions |
| :--- | :--- | :--- |
| `src/mimc.rs` | MiMC-2n/n Feistel: BLAKE3-derived round constants; in-circuit builder + native reference | `MIMC_ROUNDS=64`, `mimc_constants()`, `build_mimc_hash()`, `mimc_hash_native()` |
| `src/merkle.rs` | Native MiMC/`u32` Merkle tree for set/state membership (circuit-matched) | `MerkleTree::build/root/prove_membership`, `MerkleProof{leaf,leaf_index,siblings,root}::verify()` (rejects indices with bits beyond the path depth) |
| `src/commit_merkle.rs` | Native BLAKE3/`[u8;32]` Merkle tree for per-rep view commitments (never in-circuit) | `CommitTree::build/root/prove_membership`, `CommitMerkleProof::verify()` (rejects leftover index bits), `blake3_hash_pair()` |
| `src/seed_tree.rs` | GGM binary seed tree: PRG expansion, co-path, reconstruction | `SeedTree::build/leaf_seeds/co_path`, `build_seed_tree()`, `get_co_path()`, `reconstruct_leaves_from_co_path()`, `derive_child()` |
| `src/mpc.rs` | MPC emulation: ZKBoo 3-party Mul, view recomputation, per-party verification | `PartyView{party_idx,seed,mul_output_shares,residual_input_shares}`, `MpcExecution`, `run_mpc_emulation()`, `recompute_linear_shares()`, `verify_party_view()`, `zero_share()`, `mul_output_share()`, `OpenedNeighbor` |
| `src/sharing.rs` | Additive sharing over `Z_{2^32}`; deterministic per-party RNGs | `Sharing::share/share_with_rngs/share_xor/reconstruct/add/add_const/mul_const/xor`, `SharedTrace`, `PartySeed::random/to_rng()` |
| `src/circuit.rs` | Circuit IR + evaluation + builder (incl. XOR expansion, bit decomposition) | `Gate::{Add,Mul,Xor,AddConst,MulConst,AssertEq}`, `Circuit::{evaluate,outputs,num_mul_gates,assert_constraints,assert_expected_for_output}`, `CircuitBuilder::{add,mul,xor,add_const,mul_const,assert_eq,build}`, `bit_decompose[_on]()` |
| `src/predicate.rs` | High-level statements → circuits; witness builders; compound AND merge | `Predicate::{compile,generate_witness,witness_size}`, `CompoundPredicate::{compile,range_and_membership[_for_verify],generate_witness}`, `compile_{addition,multiplication,xor,range,set_membership}[_from_root]()`, `constrain_index_below_num_members()`, `remap_gate()` |
| `src/tx_validation.rs` | **v1 legacy/deprecated** Fabric-oriented API (no chaincode integration): range∧membership + context-bound replay protection | `TransactionStatement{amount_range,authorized_set_root,merkle_depth,num_members,context}`, `TransactionWitness{secret_value,merkle_proof}`, `create_transaction_proof()`, `verify_transaction_proof()`, `hash_context_to_{bytes,words}()`, `encode_public_inputs()` |
| `src/fiat_shamir.rs` | Fiat-Shamir: SHA3-256 transcript hash + ChaCha20 challenge expansion; circuit hashing | `derive_challenges()`, `hash_circuit()` |
| `src/commitment.rs` | Keyed-BLAKE3 commitments; per-view domain separation; commitment matrix | `Commitment`, `CommitmentOpening`, `commit()`, `verify_commitment()`, `commit_view(rep,party,seed,msgs,rand)`, `CommitmentMatrix` |
| `src/params.rs` | Soundness/size parameters; `N==3` enforcement | `ProofParams{num_parties,num_repetitions,field_element_bytes}`, `::low_n/balanced/fast_insecure/secure_100/secure_128/fabric_recommended/for_soundness_bits`, `soundness_bits()`, `estimated_proof_bytes()`, `validate()` |
| `src/proof.rs` | Prove/verify orchestration; proof wire format; structural validation | `Proof`, `RepetitionProof{hidden_party,commitment_root,co_path,opened_views,output_shares,assert_shares}`, `OpenedView`, `prove/prove_compound/prove_compiled` (`prove_compiled` validates `ProofParams` for every caller), `verify_unchecked(pub(crate))`, `verify_predicate/verify_compound`, `validate_proof_structure()`, `MAX_PROOF_CIRCUIT_{WIRES,GATES}` |
| `src/error.rs` | Error taxonomy (`thiserror`) | `MpcithError::{VerificationFailed,InvalidParams,CircuitError,CommitmentMismatch,SerializationError,InvalidWitness,ConsistencyCheckFailed}` |
| `src/bin/demo.rs` | Demo binary exercising Addition/Multiplication/XOR/SetMembership + param analysis | `run_demo()`, `main()` (fast + balanced runs) |
| `src/lib.rs` | Crate root, module decls, public re-exports | `pub mod {circuit,commitment,commit_merkle,error,fiat_shamir,merkle,mimc,mpc,params,predicate,proof,seed_tree,sharing,tx_validation,v2}` |

Supporting: `tests/integration.rs` (end-to-end), `benches/mpcith_bench.rs` (Criterion), `benchmark_results.txt`.

---

## 5. End-to-End Execution Flow (Prover vs. Verifier)

Walk-through of `src/proof.rs::prove_compiled` and `verify_unchecked`, as exercised by `src/bin/demo.rs::run_demo`.

### Step 1 — Parameter setup & input preparation

```rust
let params = ProofParams::balanced(); // N=3, M=96
let pred = Predicate::AdditionCheck { expected_sum: 7 };
let proof = prove(pred.clone(), &[3, 4], &[7], &params)?;
assert!(verify_predicate(&pred, &proof, &[7], &params)?);
```

- `prove_compiled` calls `params.validate()` first — rejecting `N != 3` and `M < 1` — so every proving path (including `create_transaction_proof`) returns `InvalidParams` before hashing, witness evaluation, or MPC work. `create_transaction_proof` also validates `params` before its Merkle-path checks and circuit compilation.
- `predicate.compile()` → `CompiledPredicate{circuit, public_inputs, witness_size}`.
- `prove_compiled`: `circuit_hash = hash_circuit(circuit)` (SHA3 over wire counts + typed gate list); `circuit.evaluate(witness)` must succeed else `InvalidWitness`; snapshot `expected_outputs = circuit.outputs(trace)`, `assert_constraints = circuit.assert_constraints()`, `output_start = num_wires − num_outputs`.

### Step 2 — Seed tree expansion & MPC state initialisation

Per repetition `rep`:

```rust
root_seed ← thread_rng().fill_bytes(32);
tree = SeedTree::build(root_seed, N);          // BLAKE3(parent||0x00/0x01)
seeds: Vec<PartySeed> = tree.leaf_seeds();
party_rngs[p] = seeds[p].to_rng(b"mpcith-party-share"); // BLAKE3(seed||domain) → ChaCha20
for value in witness:
    shared_trace.push(Sharing::share_with_rngs(value, N, &mut party_rngs));
```

Parties `0..N-1` draw from their seed RNG; party `N-1` receives the residual `value − Σ_{i<N-1} share_i` (not seed-derivable — hence `residual_input_shares` in the view).

### Step 3 — Circuit execution across N virtual parties

`run_mpc_emulation(circuit, witness, seeds, rng)` iterates gates in topological order, pushing one `Sharing` per gate (so `shared_trace.wires[output]` aligns with gate order):

- `Add`: `shares[l]+shares[r]` per party (local).
- `Mul` (ZKBoo, `nonlinear_idx` increments per gate):
  ```text
  r_i(g) = PRG(seed_i, "mpcith-zero-share"||LE(nonlinear_idx))
         − PRG(seed_{i+1}, ...)                      (mod 2^32)
  z_i    = x_i·y_i + x_i·y_{i+1} + x_{i+1}·y_i + r_i(g)
  ```
  `Σ r_i = 0` by telescoping construction ⇒ `Σ z_i = x·y`. Shared helper `mul_output_share()` used by both prover and verifier.
- `AddConst`/`MulConst`/`AssertEq`: local (`AddConst` adds constant only on party 0’s share).
- `Xor`: hard error — must have been expanded by `CircuitBuilder::xor()` at compile time.

Result: `MpcExecution{views, shared_trace, output_values}`. Each `PartyView` stores `seed`, `mul_output_shares` (one `u32` per `Mul` gate, circuit order), and `residual_input_shares` (non-empty only for party `N-1`).

Per-rep public share matrices are also snapshotted:

```rust
output_shares[o][p] = shared_trace.wires[output_start+o].shares[p];
assert_shares[g][p] = shared_trace.wires[assert_constraints[g].0].shares[p];
```

### Step 4 — View commitment & Merkle tree root calculation

```rust
rand_p ← rng(32);
com[rep][p] = commit_view(rep, p, &seed_p, &view.to_commitment_bytes(), &rand_p);
// commit() = BLAKE3_derive_key("mpcith-zk commitment v1", domain||randomness||data)
// domain  = "mpcith-view:rep={rep}:party={p}"
commit_trees[rep] = CommitTree::build(&com[rep][0..N]); // BLAKE3 pairwise, all N leaves
```

`PartyView::to_commitment_bytes()` = `seed || mul_output_shares(LE) || residual_input_shares(LE)`. The verifier later recomputes this from the **reconstructed** seed (`to_commitment_bytes_with_seed`), so a prover cannot equivocate seeds vs. views.

### Step 5 — Non-interactive challenge generation via Fiat-Shamir

```rust
commit_bytes = concat over rep of ( commitment_root[rep] || encode_public_shares(assert[rep], output[rep]) );
challenges = derive_challenges(&commit_bytes, public_inputs, &circuit_hash, M, N);
// derive: seed = SHA3-256("mpcith-zk:fiat-shamir:v1" || commit_bytes || pubs(LE) || H(C) || M(LE) || N(LE))
//         ChaCha20(seed).gen_range(0..N) × M
```

Binding `roots + public share matrices + public inputs + circuit hash` **before** opening prevents adaptive share/commitment selection. Transaction proofs additionally bind `SHA3(domain||len||context)` as 8 public words (§`tx_validation.rs`).

### Step 6 — Opening phase & proof packaging

```rust
for (rep, hidden) in challenges:
    opened_views = [ OpenedView{view, randomness, auth_path=commit_tree.prove_membership(p).siblings}
                     for p in 0..N if p != hidden ];
    co_path = SeedTree::build(root_seeds[rep], N).co_path(hidden);
    repetitions.push(RepetitionProof{hidden_party:hidden, commitment_root, co_path,
                                     opened_views, output_shares, assert_shares});
Proof{public_inputs, expected_outputs, repetitions, params, circuit, circuit_hash,
      num_circuit_wires, num_circuit_outputs}
```

Note `PartyView.seed` is `#[serde(skip)]` — seeds travel only via co-path. `serialized_size()` = `bincode::serialize(self).len()`.

### Step 7 — Verifier reconstruction & assertions

`verify_predicate` / `verify_compound` / `verify_transaction_proof` → independent recompile + `hash_circuit` equality → `verify_unchecked` (§2.3 steps 1–4). Concretely per opened party `p` with reconstructed seed `s_p`:

1. `ws_p = recompute_linear_shares(C, s_p, p, N, mul_shares_p, residual_p)` — input shares from seed RNG (or transmitted residuals for `p=N-1`), linear gates replayed, `Mul` outputs plugged from proof.
2. `recomputed = commit_view(rep, p, s_p, view.to_commitment_bytes_with_seed(s_p), randomness_p)`; `CommitMerkleProof{leaf: recomputed.0, leaf_index: p, siblings: auth_path, root}.verify()`.
3. `verify_party_view(C, ws_p, p, s_p, next_opened)`: `Add`/`AddConst`/`MulConst`/`AssertEq`-copy equalities; `Mul` recomputed via `mul_output_share(x_p,y_p,x_next,y_next, zero_share(s_p,s_next,idx))` iff neighbour opened (else skipped — exactly one party per rep skips, by 2-of-3 design).
4. `assert_shares[g][p] == ws_p[assert_wire_g]` and `output_shares[o][p] == ws_p[output_start+o]` (revealed-vs-committed cross-check).
5. Global sums: `Σ_p assert_shares[g][p] == expected_g ∀g`; `Σ_p output_shares[o][p] == circuit-derived expected ∀o`.

Any failure → `VerificationFailed` / `CommitmentMismatch{party,repetition}` / `ConsistencyCheckFailed(party)`. Success → `Ok(true)`.

---

## 6. How to Run & Test

Requires Rust 1.70+, 2021 edition.

```bash
# Build (release enables LTO + a single codegen unit per Cargo.toml)
cargo build --release

# Demo binary — Addition, Multiplication, XOR, SetMembership (fast params)
# + one balanced-params run + soundness/size table
cargo run --bin demo --release

# Tests (unit per module + tests/integration.rs end-to-end)
cargo test
cargo test --release   # timing-representative

# Benchmarks (Criterion; single-predicate, membership scaling, compound/tx)
cargo bench
```

### Modifying parameters (`src/params.rs`)

```rust
ProofParams::fast_insecure() // N=3, M=10,  ≈2^-6   — tests/bench only
ProofParams::low_n()         // N=3, M=64,  ≈2^-37  — tests/demos
ProofParams::balanced()      // N=3, M=96,  ≈2^-56  — default demos
ProofParams::secure_100()    // N=3, M=171, ≈2^-100 repetition-count estimate — fabric_recommended() sizing preset, NOT a production recommendation
ProofParams::secure_128()    // N=3, M=219, ≈2^-128 interactive repetition estimate — the end-to-end Fiat-Shamir claim is lower after grinding/query loss (see the project's cryptographic review notes)
ProofParams::for_soundness_bits(bits, n) // M = ceil(bits / log2(n/(n-1)))
```

- `num_parties` **must** be `3` — anything else fails `validate()`. The ZKBoo multiplication gadget, zero-share differencing, and neighbour-opening logic are all specialised to 3 parties.
- Soundness: `params.soundness_bits()` = `M·log2(N/(N-1))` repetition-model estimate bits. Doubling `M` doubles bits, linearly grows proof size (`estimated_proof_bytes(circuit, num_public_inputs) -> Result<usize>`, which validates the params and uses checked arithmetic: invalid or overflowing inputs return `InvalidParams` instead of panicking or wrapping) and prove/verify time.
- `field_element_bytes = 4` (`u32` word). Do not change without auditing every `to_le_bytes` / share-encoding site.
- Demo speed: `src/bin/demo.rs` uses `fast_insecure` for all but one run; switch the `balanced` block to `secure_100()` to preview higher-repetition sizes (≈74 KB estimator for Addition; MBs for compound/tx circuits dominated by MiMC `Mul` shares × `M`).
- Transaction tuning (**v1 legacy/deprecated**): `TransactionStatement{amount_range, authorized_set_root, merkle_depth, num_members, context}` with `create_transaction_proof(&statement, &witness, &params)` and `verify_transaction_proof(&proof, &statement, &params)`. `authorized_set_root` is the **32-bit MiMC root**, not a 256-bit commitment: this API demonstrates the flow and is not a production-privacy design. Keep `hi−lo < 2^31` (range bound), `depth = num_members.next_power_of_two().trailing_zeros()`, and set a fresh `context` (block hash/channel) per proof. For new work use `v2::transaction` with `V2Params::secure_127()` or `secure_127_grinding_2_32()` and an `Fr` root from authenticated ledger state.

### Proof-size / soundness quick reference

| Params | M | Repetition-estimate* | Addition proof |
| :--- | :--- | :--- | :--- |
| `fast_insecure()` | 10 | ≈2^-6 | ≈4.5 KB |
| `low_n()` | 64 | ≈2^-37 | ≈27.7 KB |
| `balanced()` | 96 | ≈2^-56 | ≈41.4 KB |
| `secure_100()` | 171 | ≈2^-100 | ≈73.7 KB |
| `secure_128()` | 219 | ≈2^-128 | ≈94.3 KB |

\* `M·log2(N/(N-1))` under the per-repetition forgery model; **not** an end-to-end security claim (see `README.md` → Security Considerations). The Fiat-Shamir transform adds a grinding/query loss of roughly `log2(q)` transcript-hash queries, so the `M=219` interactive estimate is not a 128-bit non-interactive claim. Addition-proof sizes are `estimated_proof_bytes` upper bounds for the `AdditionCheck` circuit.

Compound (`RangeCheck ∧ SetMembership`) and transaction proofs are dominated by MiMC `Mul`-share volume and grow roughly linearly with `M`; see `README.md` benchmarks and `benchmark_results.txt` for sizes.
