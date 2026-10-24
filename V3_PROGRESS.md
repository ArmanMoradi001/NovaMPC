# V3 progress log

Experimental TCitH-MT/ΠLigero prototype. No security claim. V2 unchanged.

## P1.1 — suite identifiers, parameters, validation (`a94afb6`)

- Completed: `src/v3/{mod,suite,params}.rs` wired via `src/lib.rs`; structural
  validation (ranges, `ℓ < N`, `d_β + 2 ≤ N`); three experimental presets
  (published-reference-τ1, prototype-τ2, fast-insecure-test); derived degrees
  `d_β = s+ℓ−1`, `d_α = 2(s+ℓ−1)` tested against Phase 0 values.
- Validation: `cargo test --lib v3::` — 4 passed.
## P1.2 — packed witness-matrix layout (`cf14f7d`)

- Completed: `src/v3/matrix.rs` (`MatrixDims`, `pack_witness`, `unpack_matrix`);
  generic flat packing checks `n=46` at `s=120`, `n=41` at `s=133` for
  `3·1774+95`. The Phase 2 LPPC compiler uses column-aligned triples and
  separately padded inputs, giving 46 and 43 rows respectively.
- Validation: `cargo test --lib v3::` — 7 passed.
- Next step: P1.3 packed Shamir sharing (`sharing.rs`).
## P1.3 — packed Shamir sharing (`bc6848a`)

- Completed: `src/v3/sharing.rs` — fixed points (`ω_k=k`, `e_i=s+i`),
  `P = I_v + F·R` sharing, Lagrange `reconstruct` (needs `s+ℓ` shares),
  coefficient interpolation + `degree_within_bound`; tamper/input tests.
- Validation: `cargo test --lib v3::` — 11 passed.
- Next step: P1.4 Merkle commitment/opening support (`commit.rs`).
## P1.4 — Merkle commitment/opening (`8fb1082`)

- Completed: `src/v3/commit.rs` — domain-separated BLAKE3 leaf/internal
  commits (canonical `Fr` encoding reused from v2), root/path/verify with
  odd-layer duplication; tamper and input tests.
- Validation: `cargo test --lib v3::` — 15 passed.
- Next step: P1.5 degree-enforcing round (`decs.rs`).
## P1.5 — degree-enforcing round (`e3b260e`)

- Completed: `src/v3/decs.rs` — `Γ`-combination (zero-padded), exact
  `poly_degree`/`meets_degree`, response evaluation, `verify_responses`
  (consistency + interpolated degree); honest/high-degree/tamper tests.
- Validation: `cargo test --lib v3::` — 19 passed.
- Next step: Phase 2 constraint representation (`constraints.rs`); open item:
  exact PACS/`m₂` count for the combined circuit.

## Phase 1 gate — foundations complete, no prover yet

- All primitive tests pass (`cargo test --lib v3::` — 19 passed).
- No V2 regression (`cargo test --lib` — 285 passed, 0 failed).
- V2 code/tests/proofs untouched; `git status` shows only the pre-existing
  `fixes.md` deletion plus new untracked/experimental v3 files.
- Next step: P2.1 PACS/LPPC constraint compiler over the existing combined
  V2 circuit with same-`x` semantics and V2 differential tests.

## P2.1 — LPPC relation compiler (`eb49b3f`)

- Completed: `src/v3/constraints.rs` compiles V2 gates into the FR25b
  `ΠLigero` relation: packed multiplication triples, one quadratic family per
  up-to-`s` gates, and sparse global linear equations for multiplication
  operands plus every `AssertEq`.
- Same-input property: V2 private inputs are placed once in the extended
  witness; all affine wire expressions reference that one input vector.
- 32-member combined circuit counts: 1,774 Mul gates, 94 `AssertEq`,
  `m₁=ceil(1774/120)=15`, `m₂=2·1774+94=3642`; column-aligned matrix is 46×120.
  At the `s=133` reference point it is 43 rows, so the size model and Phase 0
  table were corrected from the previous generic-flat estimate.
- Differential checks: every member in the 4-member set and a seeded random
  12-member set pass both V2 and V3; out-of-range and wrong-path witnesses fail
  both. A small mixed-gate circuit and a range circuit also pass/fail
  consistently.
- Validation: `cargo test` — 290 library tests and all integration suites
  passed (two expensive V2 high-M tests remain intentionally ignored). Model rerun gives
  197.0 KiB for the recommended prototype point and 88.2 KiB for the `τ=1`
  reference point after row-alignment correction. The DECS helper's imports
  were subsequently cleaned up.
- Security status: this direct relation checker does not implement LPPC's
  randomized aggregation, MPC, DECS transcript, or Fiat–Shamir proof; it makes
  no security claim.
- Documentation/model correction: commit `793bad8` updates the Phase 0 size
  model to count column-aligned `a/b/c` chunks and revises the stale V3 design
  note. The recommended point stays at 197.0 KiB; `s=133` reference layout is
  43 rows, not 41.
- Randomized differential coverage: commit `13fdbaf` checks every member of a
  seeded 12-member set plus seeded out-of-range and wrong-path mutations.
- Phase 2 gate: complete for relation lowering and current deterministic
  differential cases. This does not establish correctness of the eventual MPC
  proof implementation or replace external review.
- Next step: before Phase 3 prover work, independently review vector/row
  ordering against FR25b and complete the exact Q-ROM/grinding analysis. Keep
  extraction and ZK arguments open; do not call parameters secure.

## Pre-Phase-3 DECS audit

- Review found that the local degree-test helper accepted only `d+1` opened
  evaluations. That is insufficient: any `d+1` values interpolate to a
  degree-at-most-`d` polynomial. `verify_responses` now requires `d+2`
  distinct protocol points, consistent with the `binom(N,d_beta+2)` term used
  in the FR25b soundness bound. A regression test confirms the `d+1` case is
  rejected.
- This is a helper-level check only. The DECS transcript, its exact message
  encoding, and proof-size accounting have not been implemented or verified.
- Validation after the fix: `cargo test --lib v3::decs::` — 4 passed;
  `cargo test --quiet` — 290 library tests and all integration suites passed
  (two existing expensive tests remain ignored).
- Phase 3 remains gated on the promised independent FR25b row/order and
  Fiat–Shamir/QROM analysis. No security claim is made.

## P3.1 — ΠLigero vector/row ordering audit (independent re-check)

- Re-read FR25b §6.3 (packs, column tuples `w^(k)`, Protocol 8) and §6.4
  (`w = a||b||c`, `|w| = 3|C|`, one quadratic `f = c−a·b` per lane,
  `m2 = 2|C|+|y|`, footnote-12 input handling) against `constraints.rs`.
- Finding: no mismatch requiring a fix. Our per-group `(a,b,c)` rows are a
  permutation of the paper's `a||b||c` packing — same relation family with
  permuted `A` columns, hence a valid LPPC instance of the analyzed form.
  Appended inputs use the paper's allowed (non-optimized) form and are
  counted in the size model; zero padding in the short final group is
  constraint-neutral (`0 = 0·0`). Recorded in the `constraints.rs` header.
- Validation: no code change; `cargo test --lib v3::constraints` re-run below.
- Next step: P3.2 DECS helper audit against the paper's protocol messages.
