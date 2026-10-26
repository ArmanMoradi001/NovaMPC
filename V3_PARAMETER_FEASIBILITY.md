# V3 parameter feasibility under the Phase 8.2 union bound (Phase 8.3)

Analysis only. No code changed, no parameters adopted, no frozen preset
altered, no security claim made. This records what the *stated,
conditional* bound of `V3_FIAT_SHAMIR.md` §2 implies for parameters —
not what the protocol achieves.

## Verdict

Numerically, feasible points exist: e.g. `N=65536, ℓ=24, s=96, η=6,
ρ=1, τ=1` gives total bound `≈ 2^{−127.9}` with estimated wire size
`≈ 97 KiB` and estimated prove/verify times of minutes-to-tens-of-minutes.
**This is not a finding of security.** Every passing candidate clears
the bar by **at most ~1 bit**, because the accounting itself caps out at
the classical collision floor (`Q²/2^{256} = 2^{−128}` at `Q = 2^64`):
no candidate can do better under this bound, whatever its parameters.
Combined with unreviewed lemmas, a missing tight KZ-aware analysis, no
extractor, no QROM treatment, and no independent review, the correct
reading is: *the numbers fit, the proof does not exist.* Do not deploy,
do not label any point secure.

## 1. Bound, target, and assumptions (all carried over, none proved here)

Adversary: classical, `Q = 2^64` total RO queries (reference budget;
sensitivity noted below). Per Phase 8.2, for a fixed false statement:

```text
Adv ≤ Q·(ε_thr + ε_decs + ε_fp) + Coll(Q) + Bias
ε_thr = C(dα,ℓ)/C(N,ℓ),  dα = 2(s+ℓ−1)
ε_decs = C(N,dβ+2)/|F|^η, dβ = s+ℓ−1
ε_fp  = |F|^−ρ,           log2|F| = 253.5967
Coll(Q) ≤ Q²/2^{256} (= 2^{−128} at Q = 2^64)
Bias: ChaCha20 assumed PRG; Fisher–Yates modulo bias negligible.
```

Target: total `≤ 2^{−127}` (classical 127-bit). τ does not appear:
the bound takes the minimum over repetitions, so τ only adds size —
τ=1 strictly dominates under this bound (demonstrated, not assumed:
a τ=2 twin of the best row below costs ≈191 KiB for the identical
bound).

η rule: smallest `η ≤ 64` with `Q·ε_decs ≤ 2^{−132}` (keeps DECS
subdominant; ρ fixed at 1 since `Q·ε_fp = 2^{−189.6}` is already
negligible and ρ=2 only adds opened-share/broadcast bytes).

## 2. Searched domain (compatible with implementation + validation)

`N ∈ {4096, 8192, 16384, 32768, 65536}` (powers of two ≤
`MAX_V3_PARTIES`); `ℓ ∈ {16,20,24,30,32,40,48,64}`, `ℓ < N`;
`s ∈ {48,…,512}` (≤ 4096); `η ∈ [1,64]`, `ρ ∈ {1,2}`, `τ ∈ {1,2}`;
hard constraints `dβ+2 ≤ N` (validated in code) and `dα+1 ≤ N`
(F4: checked here, not enforced in code); identities
`dα = 2(s+ℓ−1)`, `dβ = s+ℓ−1` per `params.rs`. Circuit fixed:
`M = 1774` mult gates, `m2 = 3642`, 95 private inputs (32-member
combined `[1,1000]`). Structural counts (`m1`, packs, pack-pair
counts for the work model) measured per `s` from the real compiler
via a throwaway probe (removed after recording), not guessed.

## 3. Size model

Phase-0 Eq. 16 formula (`v3_phase0_model.py`) plus two documented
deltas: (a) exact `(s+1)` extra broadcast Fr per batch per rep
(`+τ·ρ·(s+1)·32` bytes — implementation sends full interpolation sets
where the paper assumes the constrained solve, P4.4); (b) framing
estimate `3700 + 32·ℓ·τ` bytes (statement/context echo, length
prefixes, path side bits, per-leaf randomness, Δu1; calibrated to the
measured +6.6% overhead at the prototype point, ±2 KB stated
uncertainty, **not re-measured per candidate**).

## 4. Work model (rough, clearly labeled extrapolation)

Single fitted constant `C ≈ 14.4 ns` per Fr-mult-equivalent, calibrated
from the release baseline (prove 411 s, verify 200 s at the prototype
point); independent fit on the verifier total agrees to 2%,
supporting the structural split (pack-polys build `O(P·s³)` dominates
both; prover rebuilds per rep, verifier builds once). Projected
`T_prove ≈ C·τ·[P·s³ + per-party terms]`,
`T_verify ≈ C·[P·s³ + τ·(opened-party terms)]`, memory ≈
`32·(N·num_q + P·s)` bytes + ~40 MB baseline overhead. Bands are
±5× on time, ±2× on memory; debug builds are orders of magnitude
slower and not comparable. These are planning numbers, not benchmarks.

## 5. Results (τ=1 throughout; τ=2 never wins on size)

| `N` | `ℓ` | `s` | `η` | bound `log2` (thr/decs/fp) | total | margin | wire est. | prove est. | verify est. | mem est. |
|---|---|---|---|---|---|---|---|---|---|---|
| 65536 | 24 | 96 | 6 | −196.2 / −253.1 / −253.6 | `2^{−127.9}` | 0.9 b | ~97 KiB | ~2–10 min | ~2–9 min | ~150 MB |
| 65536 | 24 | 80 | 6 | −201.5 / −399.9 / −253.6 | `2^{−128.0}` | 1.0 b | ~102 KiB | ~1–6 min | ~1–5 min | ~150 MB |
| 65536 | 24 | 64 | 5 | −207.8 / −296.6 / −253.6 | `2^{−128.0}` | 1.0 b | ~106 KiB | ~1–4 min | ~1–3 min | ~170 MB |
| 32768 | 30 | 112 | 6 | −208.1 / −199.5 / −253.6 | `2^{−128.0}` | 1.0 b | ~109 KiB | ~3–15 min | ~3–14 min | ~90 MB |
| 32768 | 30 | 96 | 6 | −213.6 / −326.1 / −253.6 | `2^{−128.0}` | 1.0 b | ~113 KiB | ~2–10 min | ~2–9 min | ~90 MB |

(1004 grid points pass numerically; all sit at total `≈ 2^{−128.0}` —
the collision floor, never better. Full scan in `/tmp/p83_scan2.py`,
analysis-only, not committed. Frozen presets for reference:
prototype `2^{−81.5}` / ~210 KiB; reference `2^{−63.8}` / ~97 KiB;
fast preset vacuous.)

Reading the table honestly:

- **Size is comfortable** (≈100–120 KiB vs 250 KB target, far under
  1 MB) — but size was never the binding constraint under this bound.
- **The binding constraint is the bound itself**, and every passing
  row clears it by ≤ ~1 bit, entirely because the collision term caps
  the total near `2^{−128}`. There is no headroom to absorb an
  assumption slip (larger `Q`, tighter collision bookkeeping, a
  DECS-term correction on review). This alone rules out treating any
  row as "127-bit secure".
- **Work is heavy**: minutes per proof and per verification, plus
  ~100–200 MB RSS, versus seconds-scale expectations for most
  deployments. `N = 65536` rows also commit the verifier to 16-deep
  Merkle paths and large openings. If the deployment needs interactive
  latency, this construction at these parameters is the wrong tool
  regardless of soundness.
- **τ = 1 and ρ = 1 dominate everywhere** under the proven bound:
  extra repetitions/batches add size (τ) or size (ρ) with zero bound
  improvement. This inverts the Phase 0 guidance (`τ = 2`
  recommended) — correctly, because Phase 7/8.2 give no composition
  theorem to spend repetitions on.

## 6. Recommendation and remaining blockers

Do not relax the size/runtime target to make numbers fit, do not adopt
any candidate, do not stop the mathematics either: the numbers say
*feasible in principle*, the proofs say *not established*. The
decision fork is:

1. **For any claim:** independent review of the Phase 6 DECS variant
   lemma and the Phase 7/8.2 derivations first; then a tight KZ-aware
   composition (which could substantially improve margins and shrink
   parameters — or refute them); then extractor/QROM treatment. Only
   a bound that survives that process can select parameters.
2. **For deployment practicality:** decide separately whether
   minute-scale proving/verifying is acceptable. If not, a different
   proof system is needed irrespective of §2–5 — the soundness work
   above does not fix performance.
3. **Do not weaken the security target, do not tune parameters to the
   model, do not implement anything from this analysis.**

Q-sensitivity for the record: the bound scales linearly in `Q`;
`Q = 2^80` costs 16 bits (all rows fail); smaller `Q` is not assumed.
Grinding (`κi = 0`) is priced in `Q`; no separate grinding term exists
to tune.
