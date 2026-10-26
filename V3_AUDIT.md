# V3 adversarial correctness and security audit (Phase 5)

Scope: `src/v3/*` (prover, verifier, transcript, codec, constraints, hints,
sharing, commit, params, suite, matrix, decs), `tests/v3_prototype.rs`,
`V3_PROTOCOL.md`, `V3_FIAT_SHAMIR.md`, `V3_PHASE0.md`, `v3_phase0_model.py`.
No prover/verifier logic was changed during this audit. No code changes
are made by this audit except this document.

Method: line-by-line trace of every prover message, challenge derivation,
and verifier check against the written protocol; independent re-derivation
of the parameter/soundness/size arithmetic (script in `/tmp`, not in repo);
parser hardening review; test-coverage review. All `file:line` references
below are against commit `f2bc1c8`.

Method limitation (updated Phase 6): the audit-phase retrieval failures
are superseded for FR25b — the JoC-revision full text was obtained via a
Wayback snapshot of the eprint PDF, and every equation used in the F1
resolution was verified against it (Eqs. 13–16, 18; Theorems 1–2; Lemma 1;
Π0/ΠΣ0 + footnote 10; Protocol 5; §6.4 ΠLigero; KZ selection rules).
SmallWood full text remains unverified-in-this-session; its Theorem 9 is
used only as a structural template, explicitly not as an established
bound. This audit is still not a substitute for external cryptographic
review.

## Verdicts

| Property | Verdict | Basis |
|---|---|---|
| Prototype correctness (honest path works; malformed/tampered proofs rejected as implemented) | **GO** | E2E tests pass; every message/check traced prover↔verifier; no logic defect found (findings F3–F8 are non-blocking) |
| Interactive soundness | **CONDITIONAL** | Check structure matches the paper's mechanism; DECS term re-established for the as-built combination (F1 resolution: variant lemma, same numerical term); composed per-repetition write-up + τ-composition still unproven |
| Classical-ROM (Fiat–Shamir) security | **NO-GO** | No extractor accounting for this transcript; no KZ-aware τ proof (F2) |
| QROM security | **NO-GO** | No applicable result (DFMS19 is 3-round-only); correctly unclaimed |
| Proof of knowledge | **NO-GO** | No extractor; correctly unclaimed |
| Zero knowledge | **NO-GO** | No simulator; DECS-mask deviation changes the ZK surface; correctly unclaimed |

Nothing here supports a "127-bit secure" (or any-bits secure) claim.

## Source-to-code protocol mapping

| Paper element (FR25b) | Protocol doc | Prover | Verifier | Assessment |
|---|---|---|---|---|
| P5.1 commit `h1` over packed shares | `V3_PROTOCOL.md` §1 row 1 | `prover.rs:141-187` (share → `leaf_commit` → `merkle_root`) | `verifier.rs:177-206` recompute + `verify_path` | Match. Leaf binds index/count/values/rand (`commit.rs:26-36`); path fold rules consistent both sides; odd-duplication handled identically |
| P5.1a–b `Γ`, `Pξ`, `h1'` | §1 rows 2–3 | `prover.rs:191-223` (absorb `h1`, sample Γ, eval over first `dβ+1`, interpolate, hash) | `verifier.rs:157-162` (same absorb/sample order) + `:338-369` (recompute at `I`, interpolate over `Sξ∪I`, hash-compare) | Match, with deviation F1 (mask folded into Γ; word-rule shifts) |
| Prot. 8 step 4 batching `γ,γ'` | §1 row 4 | `prover.rs:230-231` (counters `2b`/`2b+1`, lengths `m1`/`m2`) | `verifier.rs:167-169` (identical tags/counters/lengths) | Match |
| P5.4–5 broadcast hash `hB` (`t=1` collapse for ΠLigero) | §1 row 5 | `prover.rs:245-265` (canonical first-`d+1` shares, hash) | `verifier.rs:305-335` (interpolate, canonical eval, hash-compare) | Match. Canonical index convention (0-based) consistent both sides |
| P5.6 opening set `I`, `|I|=ℓ` | §1 row 6 | `prover.rs:269` | `verifier.rs:172` (same tag/counter) | Match. Fisher–Yates prefix gives distinct indices (`transcript.rs:128-141`) |
| P5.7 openings + `S`/`S′`/`Sξ` complements | §1 row 7 | `prover.rs:270-272` + `:310-320` | `verifier.rs:173-175` recomputed (never transmitted) | Match. Disjointness by construction (`complement_set` excludes `I`) |
| P5.8 checks 1–4 + statement binding (check 5) | §2 | — | `verifier.rs:59-82` header/circuit-hash binding; `:225-333` broadcasts+outcome; `:338-369` DECS | Match. Outcome `α=0^s` via ω-evals (`:315-319`); `Σα′=Σγ′t` (`:324-332`) |
| Eq. 16 size accounting | `V3_PHASE0.md` §4 | `proof.rs:116-187` codec | — | Reconciled with delta, see F6 |

Challenge order verified identical on both sides: absorb `h1` →
sample Γ → absorb `h1'` → sample `(γ,γ')` → absorb `hB` → sample `I`.
`decs.rs` helpers (`combine_rows`, `verify_responses`, degree tests) are
confirmed harness-only: zero references from `prover.rs`/`verifier.rs`
(the only in-tree user is `hints.rs` tests). The P3.2 separation note is
accurate; the as-implemented DECS check is reconstruction-and-hash-equality
as the paper requires.

## Findings (ordered by severity)

### F1 [Medium] — DECS combination deviates from FR25b Eq. 14 (resolved Phase 6: different but sound)

Paper construction (verified JoC revision): `Pξ = Γ·Q + Pu` (Eq. 15),
mask added with coefficient 1, `Q` plain concatenation (Eq. 14, no
shifts). Implementation (`prover.rs:201-217`,
`verifier.rs:345-361`): `Pξ_k = Σ_q Γ[k][q]·Q̃_q` over ALL committed columns
including the `η` mask packs — no standalone `Pu` term — with `X`-shifts
on sub-maximal tail-hint columns. See F1 resolution below; the pre-Phase-6
"printed Eq. 13 exponent" note is withdrawn (that text is absent from the
JoC revision).

Why medium, not high: the detection mechanism the bound actually uses is
fully preserved — `h1'` pre-commitment before `I` is sampled
(`prover.rs:223` vs `:269`; `verifier.rs:162` vs `:172`), reconstruction
over exactly `dβ+1` points, hash-equality (`verifier.rs:369`). For fixed
committed shares with an over-degree component, the formal `Pξ` has degree
`> dβ` except on a proper Γ-subspace (≤ `1/|F|` per row), independently of
whether the mask carries weight 1 or a random weight. The union-bound shape
`C(N,dβ+2)/|F|^η` is therefore expected to go through analogously — but
"expected" is not a proof. The as-implemented combination needs its own
written Theorem-1-style argument before any bound is cited. Same for the
τ-composition: the `thr^τ` (`−291.1`) figure in the docs is naive
powering, not a proven parallel-repetition statement for this transcript.

Reproduction: code reading suffices (compare `prover.rs:207-217` with the
documented Eq. 14). Honest execution is unaffected (both sides compute the
same function; e2e passes).

#### F1 resolution (Phase 6): different but sound — no code change

Primary source obtained (FR25b eprint PDF via Wayback snapshot
2025-12-09, JoC version). Verified: Eq. 13 is the basic `JξK` relation
(no shifts); Eq. 14 is plain concatenation `Q := Pw|Pβ1|…` (NO
degree-alignment shifts anywhere in the revision); Eq. 15 is
`Pξ := Γ·Q + Pu` with `Pu` at coefficient 1; Theorem 1 gives
`C(N,d+2)/|F|^η` with the per-row `≤ 1/|F|` drop argument; Theorem 2 /
Eq. 16 gives the MT bound with the `C(N,dβ+2)/|F|^η` term; Lemma 1,
Π0 (`×P0`), ΠΣ0 (`Δu1` + Lagrange correction per footnote 10), Protocol 5
message order / `S` sizes / hash-equality checks, §6.4 ΠLigero
(`m1`/`m2`/degrees), Eq. 18 size formula, and the KZ selection rules all
match the implementation's structure. The earlier "word-rule vs printed
Eq. 13" note described text absent from this revision and is withdrawn
(see `V3_PROTOCOL.md` §1b).

Algebraic comparison. For each committed column `q` with N-point
interpolant `P_q`, the implementation uses the effective column
`Q̃_q(X) := X^{shift_q}·P_q(X)` (`shift_q = 0` for witness/mask/full-degree
hints, `shift_q = dβ − deg_claimed` for the two short Π$ tails) and
responds `Pξ_k = Σ_q Γ_{kq}·Q̃_q` — i.e. the paper's construction with
(i) `Pu` absorbed as Γ-weighted columns and (ii) sub-maximal columns
shifted up to exactly `dβ`.

Variant DECS lemma (as-implemented combination). If
`max_q deg Q̃_q > dβ` then the DECS part accepts with probability at most
`C(N,dβ+2)/|F|^η` (plus hash-collision probability) — the identical
numerical term as Theorem 1. Proof sketch, adapting FR25b Theorem 1
Eqs. 7–9 (verified above): fix the commitment (hence all `Q̃_q`); for each
`E ⊂ [N]`, `|E| = dβ+2`, call `E` bad if some column interpolant through
`E` exceeds `dβ` (`≤ C(N,dβ+2)` such sets); for fixed bad `E` with nonzero
leading-coefficient vector, row `k` drops degree only if `Γ_k` lies in a
proper hyperplane — probability exactly `≤ 1/|F|` over uniform `Γ_k`
(mask columns are just more coordinates; the paper's coefficient-1 mask
is the special case where cancellation is impossible rather than
improbable — a fortiori covered); rows independent → `≤ |F|^−η` per bad
`E`; union bound gives the term. Shifts are monic, preserving leading
coefficients, and only make the check strictly stronger (a tail column is
held to its claimed degree, not just the uniform cap). Acceptance via a
pre-committed `h1'` matching the `Sξ∪I` interpolant is enclosed by the
same bad-`E` event up to hash collisions (same reduction structure as the
paper's §5 step). ∎-sketch.

Consequences: the interactive bound's DECS term transfers with unchanged
value; the FP term (`1/|F|^ρ`, identical batching) and threshold term
(`C(dα,ℓ)/C(N,ℓ)`, identical checks/set sizes) use only the `¬DEF`
consequence (valid sharings of degree `≤ dβ`), which the lemma supplies.
The padding-lane analysis is unaffected. No code change is justified:
removing shifts or re-introducing standalone `Pu` would be churn with no
security benefit (the remaining mask-form deviation persists either way
and is covered by the lemma).

F1 verdict evolution: the transfer question is answered for the DECS
term. Interactive soundness stays CONDITIONAL: the composed
per-repetition write-up and τ-composition proof are still required
before any claim (narrowed from the original F1).

### F2 [Medium] — No ROM-FS accounting exists for this exact transcript; KZ-aware τ selection unproven

Confirmed by inspection: nothing in the repo derives an extractor,
per-round failure events, `Qi` bookkeeping, grinding analysis, or a
KZ-aware repetition rule for the `Γ → (γ,γ') → I` × `τ` transcript with
`κi = 0`. `V3_FIAT_SHAMIR.md` is explicit that its numbers
(`Q·ε² ≈ 2^{−227}` worst round, collision floor `≈ 2^{−128}`, `τ=1` failing
at `≈ 2^{−64}`) are template estimates, and my recomputation reproduces
them exactly — the arithmetic is right, but arithmetic is not a proof.
Any classical-ROM claim is therefore unjustified today. This restates the
open obligations, upgraded to a finding because the audit verified the gap
is real and located (missing: straightline-extractor failure-event
ledger; first-challenge grinding game across `τ`; digest-size collision
term for the mixed 256-bit/254-bit hashes).

### F3 [Low] — No repetition index in the transcript

`TranscriptV3::new` absorbs an identical prefix per repetition
(`transcript.rs:62-83`); per-rep separation comes only from differing `h1`
values (fresh sharing randomness per rep, `prover.rs:91-96`). Two reps
with colliding `h1` (RNG reuse/catastrophe) would draw identical
challenges. Add a rep index to the absorbed prefix (both sides) as
defense-in-depth. Not exploitable under honest randomness.

### F4 [Low] — `validate()` does not enforce `dα+1 ≤ N`

`params.rs:99-156` checks `dβ+2 ≤ N` but never `dα+1 ≤ N` (needed for the
`S` set, `prover.rs:270`/`verifier.rs:173`). Failure mode is safe
(`complement_set` returns `Err`, prove/verify fail closed), but it fails
late instead of at parameter validation. Add `broadcast_degree()+1 ≤
num_parties` to `validate()`. Note `d2+1 ≤ N` is implied by it
(`d2 < dα` for `ℓ ≥ 1`), and `dβ+1 ≤ N` is already covered.

### F5 [Low] — Padding lanes are unconstrained free variables

The short final group is zero-padded (`constraints.rs:392-401`) and the
quadratic check covers all `s` lanes (`constraints.rs:408-416`). Padding
cells appear in no linear constraint, so a malicious prover can set them
to any consistent triple — analyzed benign: they cannot affect assertions
(no linear references), and using them to cancel a real gate failure
requires predicting `γ` after commitment (caught by the `1/|F|^ρ`
batching argument). Optionally constrain padding lanes to zero or document
as-is.

### F6 [Low/Info] — Measured-vs-model size delta reconciled; margin holds

Measured 215,034 B vs model 201,728 B (+13,306 B, +6.6%). Attribution
verified: (a) full interpolation `S`-sets instead of the paper's
constrained solve: `+121` Fr/batch (`S`: 269 vs 149; `S′`: 239 vs 238),
i.e. `121·32·2 = 7,744` B — recomputed, matches; direction is
conservative (more shares, same determined polynomial), security-neutral;
(b) framing remainder ≈ 5.6 KB, of which ≈ 1.7 KB is the model's
`log2|F|`-bits-vs-32-byte-words convention (Eq. 16 measures `253.6`
bits/Fr; the wire uses 32 canonical bytes) plus statement echo, length
prefixes, path side-bits, per-leaf randomness (`2·30·32 = 1,920` B),
`Δu1` (64 B) — approximately reconciled with a small residual. Margin
holds: 4.65× under 1 MB, 35 KB under the 250 KB design target. No tuning
performed or needed.

### F7 [Info] — Confirmed separations (positive findings)

- `decs.rs` is test-harness-only; the live DECS check is hash-equality —
  the P3.0 `d+2` requirement cannot be mistaken for protocol logic.
- `verify_responses`' `d+2`-point rule is strictly stronger than the
  protocol's check and is never on the prove/verify path.
- Cross-version rejection holds both directions by construction: V3 magic
  `NMPCV3T\0` vs V2 `NMPCV2P\0` (`suite.rs:8`, `src/v2/proof.rs:39,182`);
  V3 parser rejects V2 magic (tested, `proof.rs:352-358`).
- `S`/`S′`/`Sξ` are recomputed, never transmitted — no attacker-controlled
  point sets; interpolation inputs are always `d+1` distinct points
  (challenge `I` distinct by construction; complements disjoint).
- Tampered S-shares reduce to `hB` mismatch (same binding as tested paths).

### F8 [Info] — Coverage and hygiene notes

- No V3 test exercises `x == lo` / `x == hi` boundaries differentially
  (V2 builder covers them; V3 relies on builder+differential agreement).
  Minor gap; relation logic is builder-derived so risk is low.
- No committed tests for `ρ > 1`, `τ > 2`, or the `N = 8192` path
  (prototype point covered only by the removed one-off example); paths
  compile and the `ρ`/`τ` loops are exercised at 1.
- Dead public helpers: `TranscriptV3::sample_u64` (`transcript.rs:123`),
  `V3Params::threshold` (test-only use), `MatrixDims::index` (test-only
  use). Harmless; remove or keep as test utilities.
- `V3Suite` carries Poseidon2/framing ids (`suite.rs:32-34`) but the
  transcript absorbs only protocol+field ids (`transcript.rs:66-67`).
  Benign: both are fixed code constants with no agility (circuit is
  recompiled from vendored constants), and the protocol id versions the
  suite. No action required beyond this note.
- `verifier.rs:159-161` length guard is dead code (`sample_frs` always
  returns `n`); harmless.

## Recalculated parameter/security table

Independently recomputed (`lgamma` binomials, `log2|F| = 253.5967`,
birthday ceiling `2^126.80`). Interactive per-repetition bound
`ε₁ = 1/|F|^ρ + C(dα,ℓ)/C(N,ℓ) + C(N,dβ+2)/|F|^η`, `dα = 2(s+ℓ−1)`:

| Point | thr₁ | DECS | FP | `thr×τ` (naive) | `Q·thr^τ`, Q=2⁶⁴ | Status |
|---|---|---|---|---|---|---|
| Prototype `N=8192,ℓ=30,s=120,η=6,ρ=1,τ=2` | −145.53 | −440.68 | −253.60 | −291.05 | −227.05 | Matches docs; claim blocked by F1/F2 |
| Reference `N=8192,ℓ=27,s=133,η=5,ρ=1,τ=1` | −128.13 | −130.26 | −253.60 | −128.13 | −64.13 | Fails KZ-aware accounting; interop only |
| Fast test `N=32,ℓ=3,s=8,η=2,ρ=1,τ=1` | −2.12 | −479.44 | −253.60 | −2.12 | +61.88 | Insecure by design; tests only |

Assumptions the table depends on (all unproven for the as-built
transcript): ROM BLAKE3/XOF; PRG hiding; Merkle binding; Poseidon2
external; `N < |F|`; composed per-repetition write-up + τ-composition
(F1-resolution lemma covers only the DECS term); straightline
extraction; classical-only scope. The `Q·ε` column is template
arithmetic, not a bound. Collision floor `≈ Q²/2^{2λ} ≈ 2^{−128}`
per round oracle (classical) is consistent with the ≈127-bit field
ceiling; nothing may target `2^{−128}`.

## Fixes and proofs required before any security claim

1. Write the composed per-repetition interactive argument for the
   as-built transcript (FP + threshold/special-soundness terms on top of
   the Phase 6 DECS lemma) and instantiate it for our LPPC parameters;
   then the τ-repetition composition (narrowed remainder of F1).
2. Write the KZ-aware τ-selection proof for the exact
   `Γ → (γ,γ') → I` transcript (F2).
3. Write the classical-ROM straightline-extractor ledger (per-round
   `Qi·εi`, digest-size collision term) or restrict scope explicitly;
   decide grinding (`κi`) with size-equation update (F2).
4. QROM lift or explicit classical-only claim scope (open obligation b).
5. ZK simulator + knowledge-extractor arguments; independent
   cryptographic review and audit (open obligations).
6. Non-blocking hardening: rep index in transcript (F3); `dα+1 ≤ N` in
   `validate()` (F4); boundary differential tests; committed `N=8192`
   regression test if the path must stay supported.

## Test/procedure notes

- `cargo test --lib v3::` re-run: 34 passed, 0 failed (state unchanged;
  no code touched by this audit).
- Soundness/size numbers recomputed independently in `/tmp` (not in
  repo); calibration row and both parameter points reproduce the
  documented values to 0.1 bit.
- Full e2e suite (`tests/v3_prototype.rs`, 5 tests) not re-run (slow
  debug build; results recorded at P4 gate stand; no code changed
  since).
- V2 and all pre-existing files untouched: tracked diff is exactly the
  pre-existing `fixes.md` deletion; `src/`, `tests/`, `V2_*` unmodified.
