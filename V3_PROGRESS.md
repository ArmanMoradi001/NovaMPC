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

## P7.1 — exact experiment + single-repetition bound (`07971b5`)

- Wrote `V3_INTERACTIVE_SOUNDNESS.md` §§1–2: idealized interactive
  counterpart of the as-built sequential schedule (τ sequential full
  reps, fresh uniform challenges per rep/row/batch, accept-iff-all;
  salt public and shared, independence from fresh verifier coins);
  adversary adaptive across reps (history = auxiliary input);
  binding/collision escapes as assumptions. Single-rep bound
  `ε₁ ≤ p + (1−p)·C(dα,ℓ)/C(N,ℓ) + C(N,dβ+2)/|F|^η` with per-term
  justification (FP batching, opening/threshold special soundness,
  Phase 6 DECS lemma) tied to the actual verifier checks and relation
  shape.
- Validation: docs only; numbers recomputed independently
  (`/tmp/p7_recompute.py`).

## P7.2 — τ-composition + numbers + audit updates (`be82a51`)

- Proved `ε_τ ≤ (ε₁)^τ` for the as-built sequential schedule by
  conditional induction (uniform single-rep game per history slice);
  documented why BIN parallel-repetition pathology and KZ grinding do
  not apply to the interactive bound (FS-only), and why shared
  salt/witness do not couple verifier coins. Stated the bound for the
  idealized experiment only — the shipped FS object inherits nothing
  without Phase 8.
- Recomputed per-preset table (prototype `2^−291.05`, reference
  combined `2^−127.83`, fast `2^−2.12`); reference combined value is
  weaker than its threshold term alone — term-by-term accounting
  matters. Precondition `dα+1 ≤ N` checked per preset (F4 gap noted as
  checked-precondition, not invariant).
- Updated `V3_AUDIT.md` (F1 resolution pointer, verdict basis,
  assumptions, fixes list) to record the delivered per-rep write-up.
- Validation: no code touched; `git diff` scope checked.

## P7 gate — interactive soundness derived, no claim; Phase 8 cleared to proceed

- Delivered: exact interactive experiment spec, single-rep bound with
  per-term justification, τ-composition proof for the sequential
  schedule, recomputed per-preset table, audit updates. No code
  changed; V2 and pre-existing files preserved; nothing pushed.
- Verdicts: interactive soundness CONDITIONAL (derived, unreviewed;
  needs independent review + per-rep/τ write-up acceptance); all other
  verdicts unchanged (classical-ROM/QROM/PoK/ZK NO-GO).
- Remaining blockers for any claim: Phase 8 FS analysis (KZ-aware τ,
  extractor ledger, QROM-or-classical scope, grinding) + independent
  review + audit. F1 narrowed to review-only; F2 untouched.
- Phase 8 may proceed: the interactive bound is the correct input to
  FS analysis (it defines the per-round `εi` the KZ/extractor
  accounting must start from).

## P8.1 — repetition separation fix (`7d7b16f`)

- Finding reproduced pre-fix: `cloned_repetition_slot_is_rejected`
  FAILED (cloned rep accepted) while honest τ=2 verified — identical
  `h1` at two slots derived identical `Γ`/batching/`I`, collapsing
  repetition amplification to a single rep's cost. Adversary-chosen
  repetition, not RNG failure.
- Fix: explicit `rep_index` absorbed in the transcript prefix
  (`transcript.rs`, both prover/verifier call sites pass the loop
  index); domain v1→v2; proof format v1→v2 so old-schedule proofs fail
  closed at parse. No wire-format fields added (index is a loop
  counter); size model unchanged.
- Tests: pre-fix red run recorded above; post-fix green — new
  transcript unit test (index separates all three challenge rounds;
  same index deterministic), cloned-slot rejection, honest τ=2
  verify + round-trip, v1-format rejection. Full suite green
  (301 lib incl. 36 v3; all integration incl. 7-test v3_prototype).
- Docs: `V3_PROTOCOL.md` (rep index in transcript), `V3_FIAT_SHAMIR.md`
  (construction now binds rep index), `V3_AUDIT.md` F3 (confirmed +
  fixed).
- Validation: `cargo test` full suite, zero failures.

## P8.1 gate — repetition separation repaired; FS proof still open

- Delivered: reproduced amplification collapse, narrow fix (rep index
  in transcript prefix + domain/format versioning), regression tests,
  doc updates. No V2 changes; pre-existing workspace state preserved;
  nothing pushed.
- Verdicts: unchanged (interactive CONDITIONAL; classical-ROM, QROM,
  PoK, ZK NO-GO). This fix repairs only cross-repetition separation.
  It does NOT prove FS security, KZ-aware repetition, ROM extraction,
  QROM security, PoK, or ZK, and makes no 127-bit claim.
- Remaining blockers for any claim: Phase 8 FS analysis (KZ-aware τ,
  extractor ledger, QROM-or-classical scope, grinding) + independent
  review + audit. Old-schedule (v1) proofs are rejected at parse.

## P8.2 — classical-ROM FS reduction: round-by-round union bound (docs only)

- Derived a classical-ROM reduction for the exact as-built transcript
  (3 challenges × τ sequential reps, rep index bound post-P8.1):
  per-round, per-query bad events (`ε_decs` via Phase 6 variant lemma,
  `ε_fp = |F|^−ρ` with tuple-counting bookkeeping, `ε_thr` via
  special soundness with deterministic `S(I)`), union-bounded over the
  adversary's `Q` queries: `Pr[Forge] ≤ Q·(ε_decs + ε_fp + ε_thr) +
  Coll + Bias`, with ChaCha20-PRG and sampling-bias terms listed as
  explicit assumptions. Grinding (`κi = 0`) is priced in `Q`; KZ
  cross-round allocation is covered conservatively (every query priced),
  which is why the bound is loose rather than wrong.
- Recomputed per preset at `Q = 2^64`: prototype ≈ `2^{−81.5}`,
  reference ≈ `2^{−63.8}`, fast vacuous. Collision floor `2^{−128}`
  negligible throughout. No preset reaches classical 127-bit.
- Withdrew the `Q·ε^τ` template as a claim (no composition theorem;
  KZ contradicts naive multiplication). Verdict: classical-ROM NO-GO
  stands, now on a derived failing bound rather than an absent one;
  missing piece narrowed to a tight KZ-aware composition theorem (or
  parameters meeting 127-bit under a proven bound — frozen here).
  PoK/ZK/QROM unchanged NO-GO. No code touched; V2 untouched.

## P8.2 gate — classical-ROM analysis complete; NO-GO stands with derivation

- Delivered: exact-transcript model (post-P8.1 schedule), round-by-round
  union-bound reduction with explicit query bookkeeping, grinding/KZ/
  collision/extraction analysis, per-preset recomputation, audit +
  doc updates. Zero code changes; V2 and pre-existing workspace state
  preserved; nothing pushed.
- Verdicts: classical-ROM NO-GO (derived bound tops out ≈ `2^{−81}`;
  tight KZ-aware composition missing); interactive CONDITIONAL;
  QROM/PoK/ZK NO-GO — all unchanged in direction, now with stated
  derivations instead of open accounting gaps. No 127-bit (or any-bits)
  claim is made or supported.
- Remaining blockers for any claim: tight KZ-aware composition theorem
  (or proven-bound-satisfying parameters — frozen), ROM extractor
  ledger + PoK forking analysis, QROM lift or explicit classical-only
  scope, ZK simulator, independent review + audit.
- Next step: only external review of the Phase 6–8 derivations, or a
  new phase with an explicit mandate (e.g. parameter redesign under a
  proven bound, grinding analysis with size update, QROM treatment).

## P8.3 — parameter feasibility under the union bound (docs only)

- Wrote `V3_PARAMETER_FEASIBILITY.md`: searched `N ∈ {4096,…,65536}`,
  `ℓ ∈ {16,…,64}`, `s ∈ {48,…,512}`, `ρ ∈ {1,2}`, `τ ∈ {1,2}` with the
  Phase 8.2 bound at `Q = 2^64`, model sizes + measured overhead, and
  release-baseline-fitted work estimates (±5× stated).
- Result: ~1000 grid points pass numerically (e.g. `N=65536, ℓ=24,
  s=96, η=6`: total `≈ 2^{−127.9}`, wire `≈ 97 KiB`, prove/verify
  minutes-to-tens-of-minutes, ~150 MB RSS), but every pass sits at
  total `≈ 2^{−128}` — the Q²/2^256 collision floor caps all margins
  at ~1 bit by construction. τ=1 strictly dominates (bound ignores
  extra reps); ρ=1 likewise.
- Recommendation recorded: numbers fit, proofs don't exist — no
  adoption, no retuning, no claim. Next: review + tight analysis, or a
  separately-mandated track (parameter redesign under proven bound /
  grinding / QROM); minute-scale proving is a deployment question in
  its own right.
- Validation: scan script kept in /tmp (not committed); structural
  counts verified against a throwaway example (removed); no code
  changed; `git diff --stat` shows docs only.

## P8.3 gate — feasibility recorded; NO-GO stands, no code or preset changes

- Delivered: bounded domain search (`N ≤ 65536`, validated ranges +
  F4 condition), per-candidate bound/size/work accounting, honest
  thin-margin finding (collision floor caps all passes at ~1 bit),
  τ=1/ρ=1 dominance result, recommendation to neither adopt nor retune.
- Verdicts unchanged: classical-ROM NO-GO (now with a derived failing
  bar for frozen presets and a conditional numerical pass set for
  unexplored points — neither is a claim); interactive CONDITIONAL;
  QROM/PoK/ZK NO-GO. V2 untouched; pre-existing workspace state
  preserved (fixes.md deletion predates this work; examples/ restored
  to prior contents); nothing pushed.
- Next step: only external review of the Phase 6–8 derivations, or a
  new phase with an explicit mandate. No implementation work is gated
  on this phase.

## P9.1 — external security review packet (docs only)

- Wrote `V3_EXTERNAL_REVIEW.md`: self-contained reviewer packet with
  protocol summary, verdicts (GO functionality only; NO-GO everywhere
  security-relevant), the three core derivations with assumptions,
  six reviewer questions answered with explicit status labels
  (established vs argued-not-proved vs open), source trail (Phase 6
  Wayback snapshot; eprint 403/404 today; KZ/DFMS19 abstract-only),
  and reproducibility/limits.
- Findings while drafting: one imprecision corrected in
  `V3_FIAT_SHAMIR.md` §2 (unqueried-input case now bounded by the
  per-round ε as a fresh uniform draw, absorbed as Q+1 ≈ Q, instead of
  the incorrect 2^{−256}-guessing formulation; numerically nil, no
  verdict change). No code changed; no parameters touched.
- Validation: model script rerun (calibration 130.8 vs 130.0 KiB);
  `cargo test --lib v3::` green (35 passed); per-preset terms
  recomputed independently (agree to 0.1 bit); all code citations in
  the packet verified against current sources.

## P9 gate — review packet delivered; independent review still required

- Delivered: `V3_EXTERNAL_REVIEW.md` plus one precision fix to the
  §2 union-bound bookkeeping. No code, parameter, or proof-format
  changes. V2 and pre-existing workspace state preserved
  (`fixes.md` deletion predates this work; untracked files untouched);
  nothing pushed.
- The packet explicitly asks the reviewer to check: DECS variant
  lemma's bad-E enclosure step; interactive special-soundness
  extraction (cited, not written); F4 precondition enforcement;
  τ-composition's irrelevance to deployed proofs; KZ-aware tight
  bound (missing); per-digest collision bookkeeping; ChaCha20-PRG and
  sampling-bias assumptions; Q=2^64 budget.
- Next step: only actual external review, or a new phase with an
  explicit mandate. No implementation work is gated on this phase.

## P10 — V3 verifier performance

- Measured the existing prototype point (`N=8192, ℓ=30, s=120, η=6,
  ρ=1, τ=2`; 32-member combined statement; 215,034-byte proof) with a
  temporary release benchmark (`cargo run --offline --release --example
  v3_bench_tmp`; untracked harness, not committed). Before changes:
  `prove_ms=420193.7`, `proof_bytes=215034`,
  `verify_ms[0]=216844.8`, `verify_ms[1]=202727.5`. The dominant cost
  was repeated Gaussian elimination to interpolate the same
  fixed-coordinate LPPC polynomials across 3,642 constraints.
- Reused the fixed interpolation transform (`FixedInterpolator`: one
  Vandermonde inversion, O(s²) per interpolation), replaced
  cubic-time verifier/prover interpolation with an O(n²) Lagrange
  implementation (`interpolate_coeffs_fast`), and evaluated sparse LPPC
  constraints directly from lane coefficients
  (`eval_linear_jb_sparse`), skipping per-constraint polynomial
  construction and repeated evaluation. After changes (two runs):
  `prove_ms=5514.9/5763.8`, same `proof_bytes=215034`,
  `verify_ms=305.7/299.8` and `300.3/300.3`. Verification is ~700×
  faster at the same proof size; proving is ~74× faster in the same
  harness. Proof bytes are byte-length-identical and verification
  behavior is unchanged (exact field arithmetic; same unique
  interpolants).
- Added equivalence tests for the interpolation transform and basis
  weights (`fast_interpolation_matches_reference`,
  `fixed_interpolator_matches_reference`,
  `sparse_jb_evaluation_matches_pack_polys`) plus a verifier
  regression test (`tampered_broadcast_shares_reject`). `cargo test`
  passed: 304 library tests and all integration suites (two
  pre-existing expensive V2 tests remain ignored; one pre-existing
  warning in untouched `src/v3/hints.rs`).
- These are algebra-preserving performance changes; they do not
  address the still-open V3 security claims, and no cryptographic
  security is claimed on the basis of this work. V2 and unrelated
  worktree state preserved (`fixes.md` deletion predates this work;
  untracked files untouched); nothing pushed.
