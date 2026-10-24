# NovaMPC V3 — Phase 0 package

Status: **planning/analysis only**. No V3 code exists. No V3 security claim is made.
V2 source, proofs, tests, and documents are unchanged (verified: `git status` shows
no modification under `src/`, `tests/`, `V2_*.md`).

Run the reproducible model: `python3 v3_phase0_model.py` (pure stdlib).

Papers checked (full text, not abstracts):
- TCitH extended framework (FR25b): eprint 2023/1573, latest revision (JoC version).
- Threshold LSSS MPCitH: eprint 2022/1407 (background; superseded by FR25b analysis).
- SmallWood: eprint 2025/1085 (Table 2 reproduces the FR25b calibration row; its
  9-round/SmallWood-PCS analysis was used only for the Fiat–Shamir discussion).
- KKW (2018/475), Picnic3 (2020/427): cited in `version3.md` only for the
  fallback comparison; not re-derived here.

## 0. Corrections to `version3.md` (must fix before any prototype)

1. **Per-repetition soundness is NOT `1 / C(N, ℓ)`.** For the packed/quadratic
   LPPC instantiation the FR25b Theorem 2 (Eq. 15) bound is
   `ε ≈ 1/|F|^ρ + (1 − 1/|F|^ρ)·C(d_α,ℓ)/C(N,ℓ) + C(N,d_β+2)/|F|^η`
   with `d_α = 2·(s+ℓ−1)`. `1/C(N,ℓ)` holds only for unpacked linear MPC
   (`d_α = ℓ`). At the published point (`N=8192, ℓ=27, s=133`) the true term is
   `C(318,27)/C(8192,27) ≈ 2^−128`, not `1/C(8192,27) ≈ 2^−270`. The draft is
   optimistic by ~140 bits on this term.
2. **Parameter names are mixed across constructions.** `ℓ′` (PACS query count)
   and the LVCS/`β`-stacking parameters are SmallWood-ARK-only; FR25b
   TCitH-MT uses `ρ` = MPC parallel repetitions (false-positive `1/|F|^ρ`) and
   `τ` = outer PoK repetitions. `q`/grinding is SmallWood `κᵢ` proof-of-work,
   not V2's query-loss `q`. §1 maps every name to its defining paper section.
3. **The 130 KB reference is a reproduced FR25b row, not our circuit.**
   SmallWood Table 2, 256-bit/`deg=2`/`|C|=4096`/`|x|=100` row
   (`N=8192, ℓ=27, s=133, η=5, ρ=1` → 130.0 KB) is a TCitH-ΠLigero point.
   Scaling it by `1774/4096` is invalid; size follows Eq. 16 via
   column-aligned `a`, `b`, and `c` chunks plus input rows, followed by fixed
   DECS/Merkle terms. §4 derives sizes from the formula and calibrates (130.8
   KiB computed vs 130.0 KB published, 0.6%).
4. **Security target wording.** BN254 `Fr` (`log₂|F| ≈ 253.6`) caps generic
   collision resistance at ~2^127. Nothing may target 2^−128; the planning
   target is `≤ 2^−127` **with** Fiat–Shamir/query margin still to be derived.
   The `τ=1` published point has zero such margin and is not approvable.

## 1. Exact protocol variant and parameter map

Variant: **FR25b TCitH-MT applied to ΠLigero** (the LPPC MPC protocol of FR25b
§6.3–6.4), i.e. the construction behind the `TCitH-ΠLigero` Table 2 rows — Merkle
commitments, packed Shamir sharing, DECS proximity round, Ligero-style parallel/
aggregated constraint check. SmallWood-ARK is **not** selected (different PCS,
9 rounds, extra `ℓ′`/LVCS machinery).

| Symbol | Meaning | Defined in | Role in bound/size |
|---|---|---|---|
| `N` | parties / Merkle leaves, `N < \|F\|` | FR25b §2.1, §5 | `C(d_α,ℓ)/C(N,ℓ)`; auth paths `ℓ·log₂N·2λ` |
| `ℓ` | privacy threshold; verifier opens `ℓ` leaves; `(ℓ+1,N)` sharing | FR25b §2.3, Thm 2 | numerator/denominator above |
| `s` | packing width (witness cols) | Def. 1, §5 | `d_α=2(s+ℓ−1)`; `n=⌈(3\|C\|+\|x\|)/s⌉` |
| `d_β` | max hint degree (default `s+ℓ−1`) | §6.1, Eq. 15 | DECS term `C(N,d_β+2)/\|F\|^η` |
| `η` | DECS parallel reps | §4.2–4.3, Thm 1 | `η·(d_β+1)` field elements; set so term `≤ 2^−λ` |
| `ρ` | MPC parallel reps (false positive `1/\|F\|^ρ`) | §6.2–6.3 | `ρ` broadcast shares; set so term `≤ 2^−λ` |
| `τ` | outer PoK repetitions | Thm 2, §6.2 | multiplies proof sans `6λ`; threshold term `^τ` |
| `λ` | digest parameter (digests `2λ=256` bit) | §6.2 | header/roots/paths |
| `κᵢ`, `Q` | grinding bits / RO query bound | SmallWood §5.3 | **open**: no grinding assumed (`κᵢ=0`); `Q` TBD in Phase 1 |

## 2. Soundness bound

Per-repetition interactive bound (FR25b Thm 2, MT variant, `d=2` LPPC):

```text
ε₁ = 1/|F|^ρ + C(d_α,ℓ)/C(N,ℓ) + C(N,d_β+2)/|F|^η,   d_α = 2(s+ℓ−1)
ε(τ) ≈ (threshold term)^τ  (τ-fold repetition; DECS/FP terms per §6.2 selection)
```

Non-interactive security additionally loses Fiat–Shamir/KZ terms over the 7-round
transcript (FR25b §6.2–6.3 warning; SmallWood Thm 9 makes them explicit as
`ε₁..ε₄` with `Q`-query and `κᵢ`-grinding terms). Overall ceiling: BN254 `Fr`
≈ 2^−127.

Evaluated (BN254 `Fr`, `log₂|F|≈253.6`):

| Point | log₂ thr (`×τ`) | log₂ DECS | log₂ FP | Note |
|---|---|---|---|---|
| `N=8192,ℓ=27,s=133,η=5,ρ=1,τ=1` | −128.1 | −130.3 | −254 | interactive ≈ target; **no FS/Q margin** |
| `N=8192,ℓ=30,s=120,η=6,ρ=1,τ=2` (prototype) | −291.1 | −440.7 | −254 | ~160+ bits of headroom for FS/Q loss |
| `N=4096,ℓ=32,s=80,η=6,ρ=1,τ=2` | −275.6 | −780.2 | −254 | alt; larger but smaller N |
| `N=16384,ℓ=30,s=120,η=6,ρ=1,τ=2` | −351.1 | −288.7 | −254 | alt; DECS margin thinnest |

Assumptions: random-oracle BLAKE3/XOF, PRG hiding, Merkle binding, Poseidon2
cryptanalysis external, `N < |F|` (holds: `16384 ≪ |F|`). Unresolved obligations
(no parameter called secure): full `Q`-ROM Fiat–Shamir derivation for our exact
7-round transcript with `κᵢ=0`; PACS compiler soundness for bit/mux/Poseidon
constraints; extractor argument; grinding decision; external review + audit.

## 3. V2 32-member combined statement (measured, not estimated)

Built with the bench configuration (range `[1,1000]`, members `100,110,…,410`,
middle index) via the unchanged `compile_from_statement` path:

| members | depth | witness `Fr` | wires | gates | Mul | Add | AddC | MulC | Assert |
|---|---|---|---|---|---|---|---|---|---|
| 4 | 2 | 89 | 3706 | 3708 | 1048 | 1391 | 413 | 765 | 91 |
| 8 | 3 | 91 | 4533 | 4534 | 1290 | 1720 | 495 | 937 | 92 |
| 16 | 4 | 93 | 5360 | 5360 | 1532 | 2049 | 577 | 1109 | 93 |
| **32** | **5** | **95** | **6187** | **6186** | **1774** | **2378** | **659** | **1281** | **94** |

Cross-check: matches `V2_BENCHMARKS.md` (6186 gates / 1774 Mul at 32 members).
LPPC dimensions: `|C| = 1774` mult gates → extended witness `|w| = 3|C| =
5322` field elements (`a,b,c` operand vectors) plus 95 private input elements.
The compiler has `m₁ = ceil(|C|/s) = 15` quadratic constraint families at
`s=120`, each checking up to 120 multiplication lanes, and `m₂ = 2|C| +
#AssertEq = 3642` global linear constraints. The same private input vector is
used by all wire expressions. Column alignment requires
`n = 3·ceil(|C|/s) + ceil(|x|/s)` rows; for this circuit that is 46 at `s=120`
and 43 at `s=133`.

## 4. Proof-size model (from the published formula)

FR25b Eq. 16 (TCitH-MT, LPPC), bits:

```text
Size = 6λ + τ·[ (d_β+1)·η·log|F| + ℓ·(n + n_h·ρ)·log|F|
              + ((d−1)(s+ℓ−1) + (2s−2))·ρ·log|F| + 2λ·ℓ·log₂N ]
n_h = ⌈((d−1)(s+ℓ−1))/(d_β−ℓ+1)⌉ + ⌈(2s−1)/(d_β−ℓ+1)⌉ (= 4 at all points below)
```

Calibration: `C=4096,|x|=100` at the published point → **130.8 KiB computed vs
130.0 KB published** (0.6%; residual = KB-vs-KiB and `d_β`-default conventions).
The model is faithful; no mult-gate-ratio scaling is used.

Estimates for our `C=1774, x=95` circuit (BN254 `Fr`, `λ=128`):

| Point | Size | vs 1 MB hard limit | vs 250 KB design target |
|---|---|---|---|
| Published params `τ=1` | **88.2 KiB** | 11.3× headroom | fits |
| Prototype `N=8192,ℓ=30,s=120,η=6,τ=2` | **197.0 KiB** (201.7 kB) | **5.1× headroom** | fits (53 kB under) |
| Alt `N=4096,ℓ=32,s=80,τ=2` | 230.9 KiB | 4.3× | fits |
| Alt `N=16384,ℓ=30,s=120,τ=2` | 198.9 KiB | 5.0× | fits |

Assumptions stated: `d_β = s+ℓ−1`; auth path `ℓ·log₂N` digests of `2λ` bits;
`6λ` salt/root/hash overhead; canonical 32-byte `Fr`; no grinding counters, no
envelope overhead. Sensitivity: size is governed by `n` (sublinear in `|C|`
via `s`) and the `τ=2` doubling — even doubled, margin exceeds 4×.

## 5. Go / no-go

**GO for prototyping (Phase 1–3 scope), with conditions; NO security claim.**

Evidence: (a) the design-note's blocking formula error is corrected and the true
bound still closes with large margin at `τ=2`; (b) a faithful published-formula
model calibrates to 0.6% and predicts **~197 KiB worst-case** for the recommended
point — 5× under the 1 MB hard limit and under the 250 KB design target;
(c) the V2 relation to be proven is frozen and measured above (1774 Mul, 95-`Fr`
witness, shared-`x` semantics preserved for the compiler).

Conditions: parameters stay named `experimental`; `τ=1` points are not used for
any security-facing test; the exact PACS/`m₂` count is now recorded from the
Phase 2 compiler. The `Q`-ROM Fiat–Shamir derivation (`κᵢ` decision) and measured
(not modeled) proof size/prove/verify remain required before any security or
deployment language. If the prototype misses 1 MB with a written `≤ 2^−127`
calculation, stop per `version3.md` §7.3 — no silent parameter reduction.

Limits of this package: literature review and relation-compiler count; no
end-to-end proof implementation, no timings, no ZK/extraction analysis;
SmallWood-ARK migration (smaller sizes, e.g. 86.6 KB
at `|C|=4096`) deliberately deferred to keep one variant and one review surface.
