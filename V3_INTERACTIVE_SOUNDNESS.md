# V3 interactive soundness derivation (Phase 7)

Mathematical analysis only. No code changed. No security claim is made:
this derives the soundness bound for the **idealized interactive
counterpart** of the implemented schedule. The shipped object derives all
challenges by Fiat–Shamir hashing and inherits **nothing** here without
Phase 8. Proof-of-knowledge, zero-knowledge, QROM, and grinding analysis
remain open as before.

Primary sources (verified full text, Phase 6): FR25b JoC revision —
Theorem 2/Eq. 16, Theorem 1/§4 DECS game, §5 composition argument,
Lemma 1/3, Protocol 8 steps 4/7, P5, §6.4 ΠLigero specialization.

## 1. Exact interactive experiment

**As-built schedule** (`prover.rs:90-96`, `verifier.rs:110-117`): `τ`
**sequential**, fully computed repetitions; the verifier accepts iff every
repetition accepts. Per repetition (`V3_PROTOCOL.md` §1 rows 1–7):
commit `h1` → challenge `Γ` → `h1'` → challenges `(γ,γ')` → `hB` →
challenge `I` (`|I| = ℓ`) → openings (`S`/`S′`/`Sξ` as deterministic
complements, recomputed both sides). Each repetition draws fresh sharing
randomness (`rng` advances across `prove_rep` calls) and builds a fresh
transcript instance; only `salt` is shared across reps.

**Idealized experiment analyzed here.** Identical schedule and checks,
except every challenge (`Γ`, `(γ,γ')`, `I`, per repetition) is fresh
**uniform** randomness, independent across reps, batches, and rows.
`salt` is a fixed public string (its only role is transcript domain
separation; independence comes from fresh verifier coins, not from
`salt`).

**Adversary.** Malicious PPT prover `P̃`, fixed false combined statement
(no witness satisfies range ∧ membership for one `x`), fully adaptive:
rep-`i` strategy may depend arbitrarily on reps `< i` (history = auxiliary
input). Binding/collision breaks (Merkle, BLAKE3) are escape events per
FR25b's convention (Theorem 2's extractor may output a collision
instead of a witness); the bound below is stated modulo those escapes,
which are listed as assumptions.

## 2. Single-repetition bound, implemented variant

Fix one repetition, condition on arbitrary prior history (fresh coins
make the bound history-independent). Split as in the verified §5
argument: `DEF` vs `¬DEF`, then false-positive vs not.

**Term A — DECS failure: `C(N,dβ+2)/|F|^η`.** Phase 6 variant lemma
(`V3_AUDIT.md`, F1 resolution): with the as-built
`Pξ_k = Σ_q Γ_{kq}·Q̃_q` (mask folded in, shifts applied), if any
effective column exceeds degree `dβ` the verifier's reconstruction check
passes with probability at most `C(N,dβ+2)/|F|^η` (union bound over
`(dβ+2)`-sets; per-set `|F|^−η` over the `η` independent `Γ` rows;
shifts are monic so the per-row `1/|F|` step is unchanged, and the check
is strictly stronger on tail columns). Applies because the code
implements exactly that check (`verifier.rs:338-369`: recompute at `I`,
interpolate over `Sξ∪I` (`dβ+1` points), hash-compare against `h1'`
committed before `I`).

**Term B — MPC false positive: `1/|F|^ρ`.** For fixed committed values
with the LPPC relation unsatisfied, each independent batching
`(γ,γ')` passes with probability at most `1/|F|`: the aggregated
`JαK`/`Jα′K` outcome equations are a nonzero linear form in the uniform
batching vector (paper Lemma 3 shape; our instance verified
same-shape in the P3.1 audit — permutation + appended inputs + zero
padding only widen `A`, which the argument does not depend on).
Padding lanes are fixed pre-challenge values, so no newGrinding dimension
appears; `ρ` batches use independent challenges
(`prover.rs:230-231`). Hence `≤ 1/|F|^ρ`.

**Term C — opening/threshold: `C(dα,ℓ)/C(N,ℓ)`.** Given `¬DEF`,
committed sharings are valid sharings of degree `≤ dβ`; derived
broadcasts satisfy `deg JαK ≤ dα = 2(s+ℓ−1)` and
`deg Jα′K ≤ d2 = 2s+ℓ−2 ≤ dα` (implementation enforces
`dα = 2·(params.broadcast_degree/2)` identically on both sides,
`prover.rs:132-134`, `verifier.rs:90-92`; `S`/`S′` sizes
`dα+1−ℓ` / `d2+1−ℓ` supply exactly the interpolation points the
verifier uses). The last round is `dα+1`-special-sound in `I`
(paper §5 argument, unchanged: deterministic `S(I)` keeps
distinct-`I` transcripts distinct; `dα+1` of them determine all
broadcast polys, hence a witness — contradiction on a false
statement). So `Pr[accept ∧ ¬FP ∧ ¬DEF] ≤ C(dα,ℓ)/C(N,ℓ)`.

**Combined single-rep bound** (same form as Theorem 2/Eq. 16 MT):

```text
ε₁ ≤ p + (1−p)·C(dα,ℓ)/C(N,ℓ) + C(N,dβ+2)/|F|^η,
p = 1/|F|^ρ,  dα = 2(s+ℓ−1),  dβ = s+ℓ−1 (hardcoded default).
```

Assumptions: `N` distinct evaluation points with `N < |F|`
(params cap `N ≤ 65536`); Merkle/BLAKE3 binding + collision resistance
(escape hatch); hint/mask distributions needed only for completeness
(soundness games fix arbitrary committed values); `dβ+2 ≤ N` enforced by
`validate()`; `dα+1 ≤ N` required for `S` (implied by practice, see F4).
The relation-specific content (combined range+membership, one `x`,
`m1 = ⌈M/s⌉`, `m2 = 2M+#AssertEq`, appended inputs, zero padding) enters
only through the LPPC shape the paper's argument already covers.

## 3. τ-repetition bound for the actual schedule

The schedule is **sequential**, not parallel: rep `i` completes fully
before rep `i+1` begins, each with fresh independent verifier coins, and
the verifier requires all `τ` accepts. Let `E_i` = "rep `i` accepts" and
`H_{i-1}` = prior history. Then
`Pr[∧E_i] = Π_i Pr[E_i | H_{i-1}]`, and each conditional is a fresh
single-rep game against the history-hardwired prover strategy with
independent coins — bounded by `ε₁` uniformly by §2 (game-based bounds
hold for arbitrary fixed prior transcript). Hence for the interactive
experiment:

```text
ε_τ ≤ (ε₁)^τ   (+ binding-escape terms, union-bounded over reps)
```

What this refutes and what it does not. (i) The BIN-parallel-repetition
pathology (soundness need not compose for parallel arguments) does not
apply: nothing is parallel here except the ρ MPC batches *inside* one
rep, whose composition is the independent-γ argument of Term B, not a
repetition theorem. (ii) KZ-style grinding does not exist in the
interactive experiment (challenges are uniform, ungrindable); it belongs
exclusively to Phase 8. (iii) Naively writing `ε^τ` would still be wrong
without this schedule analysis — the composition is proved here from
sequentiality + fresh coins, not assumed. Shared `salt`/witness/matrix
across reps are fixed public inputs and do not couple verifier coins.

## 4. Concrete interactive soundness per preset

`log2|F| = 253.5967` (ceiling ≈ `2^−126.8`; nothing may target `2^−128`).
`ε₁` combines all three terms (union form above); `ε_τ = (ε₁)^τ`.

| Preset | thr₁ | decs | fp | `ε₁` | `ε_τ` |
|---|---|---|---|---|---|
| Prototype `N=8192,ℓ=30,s=120,η=6,ρ=1,τ=2` | −145.53 | −440.68 | −253.60 | `2^−145.53` | **`2^−291.05`** |
| Reference `N=8192,ℓ=27,s=133,η=5,ρ=1,τ=1` | −128.13 | −130.26 | −253.60 | `2^−127.83` | `2^−127.83` |
| Fast test `N=32,ℓ=3,s=8,η=2,ρ=1,τ=1` | −2.12 | −479.44 | −253.60 | `2^−2.12` | `2^−2.12` |

Notes: the reference point's combined `ε₁` (`−127.83`) is weaker than
its threshold term alone (`−128.13`) because the DECS term contributes
at the same order — term-by-term accounting matters. The fast preset is
insecure by design (threshold term dominates at `−2.12`). All values
recomputed independently (`/tmp/p7_recompute.py`, `lgamma`
binomials); they reproduce prior docs to 0.1 bit, with the reference
combined value now stated exactly.

## 5. Verdict and remaining blockers

Interactive soundness for the idealized counterpart is **derived
(not independently reviewed)**: single-rep bound via Terms A–C above,
τ-composition proved for the as-built sequential schedule. This changes
nothing shippable: the implemented object uses Fiat–Shamir challenges,
so Phase 8 (FS loss, KZ-aware τ, extractor, QROM-or-classical scope)
and external review remain the gates for any claim. F1's remaining
piece (composed per-rep write-up) is substantially delivered here;
τ-composition is delivered here for the interactive experiment only.
