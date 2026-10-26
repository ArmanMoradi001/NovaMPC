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
## P3.2 — DECS helper audit against FR25b's protocol

- Re-read FR25b §4.2 (Theorem 1), §5 (Eqs. 12–14, `Q` alignment, mask `JuK`),
  and Protocol 5 (steps 1–1b, 7–8) against `src/v3/decs.rs`.
- Findings recorded in the `decs.rs` header: (a) the paper's verifier check
  is hash-equality of reconstructed `Pξ` against pre-committed `h1'`, not a
  degree test on the interpolant (vacuous at `dβ+1` points) — the P3.0 `d+2`
  requirement is a stricter harness check, not the protocol equation;
  (b) challenge timing is `h1 → Γ → h1'` before MPC randomness and `I`;
  (c) `|S| = dβ+1−ℓ`, `S ∩ I = ∅`; (d) Phase 3 must add `X`-shift alignment,
  mask sharing, and `h1'`; (e) the model's `(dβ+1)·η` term matches the
  paper's transcript list (`S`-responses + opened mask shares). No helper
  logic changed.
- Validation: `cargo test --lib v3::decs` re-run below.
- Next step: P3.3 exact interactive protocol specification.
## P3.3 — exact interactive protocol (`875b23e`)

- Wrote `V3_PROTOCOL.md`: per-repetition message table (salt + `h1`, `Γ`,
  `h1'`, batching `γ/γ'`, broadcast hash, `I`, openings + `S/Sξ`
  responses), five verifier checks each tied to a Protocol 5 / Lemma 3 /
  Theorem 1 justification, byte-to-Eq.16 mapping, and the interactive
  `ε₁` terms for both parameter points.
- Specified-but-unreviewed deltas vs FR25b: `2λ` salt (SmallWood practice),
  single collapsed broadcast hash (`t = 1` for ΠLigero), `κi = 0`.
- Validation: documentation only; model numbers re-verified against
  `v3_phase0_model.py` output.
- Next step: P3.4 Fiat–Shamir/QROM analysis and gate decision.
## P3.4 — Fiat–Shamir/QROM analysis and gate decision (`acc7ca9`)

- Wrote `V3_FIAT_SHAMIR.md`: FS construction (3 challenges × τ, `κi = 0`),
  classical-ROM template (SmallWood Thm 9: `ΣQ²/2^{2λ} + ΣQi·εi/2^{κi}`),
  KZ20a (eprint 2020/837) forgery shape and why FR25b's τ rule alone is
  insufficient, concrete numbers (`τ=2`: `Q·ε² ≈ 2^{−227}` worst round,
  collision floor `≈2^{−128}`; `τ=1`: `≈2^{−64}`, fails), QROM coverage
  gap (DFMS19 is 3-round-only; SmallWood/FR25b classical), five precise
  open proof obligations.
- Gate: CONDITIONAL GO for implementation (protocol fully specified, no
  invented formulas); NO-GO for any security claim until obligations 1–5
  are derived and reviewed.
- Validation: documentation + `v3_phase0_model.py` numbers only; no code
  changed in this step.
## P4.1 — transcript and proof codec (`bd30f2f`)

- Completed: `src/v3/transcript.rs` (domain-separated BLAKE3 transcript,
  `h1 → Γ → h1' → (γ,γ') → hB → I` challenge order, deterministic ChaCha
  sampling, canonical `circuit_hash_v3`, `hash_fr_vecs`) and `src/v3/proof.rs`
  (typed `V3Proof`, canonical codec with magic/version/canonical-Fr/caps/no
  trailing bytes, V2-magic rejection).
- Validation: `cargo test --lib v3::` — 30 passed.
## P4.2 — prover: hints, commitments, responses (`504606c`)

- Completed: `src/v3/sharing.rs` += `random_poly`/`eval_poly_all`/
  `random_poly_shares`; new `src/v3/hints.rs` (Π$/Π0/ΠΣ0 derivation,
  Lemma-1 parameters, Δu1 correction; 3 tests); new `src/v3/prover.rs`
  (`prove_combined_v3`, combined-only): packed/mask/hint sharing, Merkle
  leaves, Γ challenge, Pξ + h1', per-batch γ/γ' batching, canonical+S
  broadcasts, deterministic S/S′/Sξ complements, canonical `V3Proof`
  encoding.
- DECS alignment follows the paper's stated word-rule (`X^{dβ−deg}`,
  zero shift for full-degree columns); the printed Eq. 13 exponent would
  misalign packed columns and is not used (recorded in `prover.rs`).
- Validation: e2e honest-path verified (see P4.4); `cargo test --lib v3::`
  green.
## P4.3 — verifier: all five protocol checks (`9fcb6a1`)

- Completed: `src/v3/verifier.rs` (`verify_combined_v3`): header binding
  (params/statement/context/circuit-hash equality), recomputed challenges,
  exact-count enforcement, Merkle path checks, per-batch broadcast
  recomputation + interpolation + hB comparison, outcome checks
  (α=0, Σα′=Σγ′t), DECS recomputation + interpolation + h1' comparison.
  S/S′/Sξ use the deterministic smallest-not-opened rule both sides (sets
  never transmitted; recorded refinement of `V3_PROTOCOL.md` §1 row 7).
- Validation: e2e + tamper tests pass (see P4.4).
## P4.4 — tests, measurements, model comparison (`b301217`)

- Completed: `tests/v3_prototype.rs` — honest accept + codec round-trip,
  seeded determinism, false-statement prove refusal, wrong
  statement/context/params rejection, byte-flip sweep + structural share /
  DECS / root / broadcast-hash tamper rejection. 5 passed (debug).
- Measured (release, 32-member combined `[1,1000]`, prototype point
  `N=8192,ℓ=30,s=120,η=6,ρ=1,τ=2`, seeded RNG): **215,034 bytes**,
  prove ~411 s, verify ~200 s, peak RSS ~57 MB (one-off example, removed
  after recording). Size is deterministic across runs.
- Model comparison: Phase-0 model predicts 201,728 B; measured is +6.6%.
  Investigated, not tuned: the paper's size equation assumes the optimized
  broadcast reconstruction (`(dα+1)−ℓ−s` + `(d2+1)−ℓ−1` shares via a
  constrained solve), while this prototype sends the full interpolation
  sets (`dα+1−ℓ`, `d2+1−ℓ`: +121 Fr/batch = +7.7 KB) for a simpler
  interpolate-and-hash verifier. Remainder (~5.6 KB) is unmodeled
  framing: statement/context echo, length prefixes, path side bits,
  per-leaf randomness, Δu1. The model itself is unchanged (it matches the
  paper); the implementation delta is documented here. Margin holds:
  4.65× under 1 MB, 35 KB under the 250 KB design target.
- Fast-params cross-check (4-member, `N=32,ℓ=3,s=8,η=2,τ=1`): measured
  41,517 B vs model 40,644 B (+2.1%, same framing causes).
- Known limitations: single-threaded unoptimized prover/verifier (minute
  scale at N=8192); optimization gap above recorded as future work, not
  implemented; combined-only API; ρ>1 and τ>2 paths compile and run but
  are exercised only at ρ=τ=1 in tests.
- Validation: `cargo test --lib` full suite green (see gate); V2
  untouched.
- Next step: P4 gate record.

## P4 gate — experimental implementation complete, no security claim

- Prototype prover/verifier/transcript/codec implemented per
  `V3_PROTOCOL.md`, commits `bd30f2f`/`504606c`/`9fcb6a1`/`b301217`.
- Checks: `cargo test --lib` — 300 passed; `tests/v3_prototype.rs` — 5
  passed; release measurement 215,034 B / prove ~411 s / verify ~200 s /
  peak RSS ~57 MB at the prototype point (4.65× under 1 MB).
- This is an experimental prototype only: presets experimental, P3.4
  obligations (extractor, KZ-aware τ proof, QROM, grinding, ZK, review)
  all open. Not secure, not zero-knowledge, not 127-bit.
- V2 code/tests/docs unchanged; pre-existing `fixes.md` deletion and
  untracked files preserved; nothing pushed.
## P6.1 — verify DECS source equations (`77869e4`)

- Obtained an authoritative FR25b copy (eprint PDF via Wayback snapshot
  2025-12-09; JoC version) after the audit-phase retrieval failures.
  Verified directly: Eq. 13 (basic `JξK`), Eq. 14 (plain concatenation,
  NO shifts), Eq. 15 (`Pξ := Γ·Q + Pu`), Theorem 1
  (`C(N,d+2)/|F|^η` + proof Eqs. 7–9), Theorem 2/Eq. 16 (MT bound),
  Lemma 1 (Π$ `n`/`δ`/last-degree), Π0 (`×P0`), ΠΣ0 (`Δu1` + footnote 10
  Lagrange correction), Protocol 5 (message order, `S`/`Sξ` sizes,
  hash-equality checks), §6.4 ΠLigero (`m1`/`m2`/degrees), Eq. 18 size
  formula, KZ selection rules, footnote-12 input optimization.
- Findings vs implementation: (a) mask folded into Γ (deviation,
  detection mechanism preserved); (b) the "word-rule vs printed Eq. 13"
  note referred to text absent from this revision — withdrawn; the
  `X`-shifts are an implementation-side conservative strengthening.
  `V3_PROTOCOL.md` corrected (rows 2–3, check 3, new §1b deviations).
- Next step: P6.2 variant DECS lemma + decision.
## P6.2 — DECS variant lemma + decision (`25d4912`)

- Wrote the algebraic comparison (paper `Pξ = Γ·Q + Pu`, plain-concat
  Eq. 14, no shifts anywhere in the JoC revision vs implemented
  mask-in-Γ plus `X`-shifted tail columns) and a variant DECS lemma
  adapting Theorem 1 Eqs. 7–9: same `C(N,dβ+2)/|F|^η` term; shifts
  preserve leading coefficients and only strengthen the per-column cap;
  mask folding is covered by the same union bound (paper's coefficient-1
  mask is the a-fortiori special case).
- Decision recorded in `V3_AUDIT.md` F1 resolution: different but sound,
  no code change (removing shifts / re-adding standalone `Pu` is churn
  with no security benefit). F1 transfer question answered for the DECS
  term; interactive soundness stays CONDITIONAL (composed per-rep
  write-up + τ-composition still required).
- Validation: primary-source equations re-checked line by line; no code
  touched (only docs).

## P6 gate — DECS deviation resolved as different-but-sound; no code change

- F1 closed as a blocking unknown: primary source verified (Eqs. 13–15,
  Thm 1/2, Lemma 1, Π0/ΠΣ0, P5, §6.4, Eq. 18, KZ rules); variant DECS
  lemma written with the identical `C(N,dβ+2)/|F|^η` term; decision: no
  prover/verifier change (shifts are conservative; mask folding covered
  by the same union bound; exact-paper-match edits would be churn).
- Verdicts: interactive soundness stays CONDITIONAL (narrowed: composed
  per-rep write-up + τ-composition still required); classical-ROM, QROM,
  PoK, ZK stay NO-GO; no security claim of any kind.
- Validation: docs only; `git diff` confirms zero `src/`/`tests/`
  changes in Phase 6; V2 and pre-existing workspace changes preserved;
  nothing pushed.
- Next step: only the F2/open-obligation proof work (extractor, KZ-aware
  τ, QROM-or-classical scope, ZK) or external review can advance claims;
  no implementation work is gated on this phase.
