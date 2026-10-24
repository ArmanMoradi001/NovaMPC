# V3 exact interactive protocol (TCitH-MT / ΠLigero)

Experimental specification. No security claim. References are to FR25b
(eprint 2023/1573, JoC revision): `§5` = TCitH-MT with degree enforcement,
`§6.1` = hint-generation protocols Π0/ΠΣ0, `§6.3` = Πlppc (Protocol 8),
`§6.4` = ΠLigero specialization, `P5` = Protocol 5 (steps cited as P5.k).

## 0. Public parameters and relation

- Field BN254 `Fr`; suite `V3_SUITE`; params `(N, ℓ, s, η, ρ, τ)` (all
  experimental); statement = existing `StatementV2::Combined` (range
  `[lo,hi]` + membership `(root, n, depth)`); 32-byte context.
- Relation: `ConstraintProgramV2`-compiled LPPC instance (§6.4, audited in
  P3.1): `M` mult gates → `m1 = ⌈M/s⌉` quadratic pack constraints
  `f = c−a·b`, `m2 = 2M + #AssertEq` global linear constraints
  (`A·w = t`); witness `w` = per-group `(a,b,c)` rows + appended input rows.
- Degrees: witness/hint-input degree `s+ℓ−1`; broadcast `dα = 2(s+ℓ−1)`
  (dominates `2s+ℓ−2` since `ℓ ≥ 1`); hint cap `dβ = s+ℓ−1` (default).
  False-positive rate `p = 1/|F|^ρ` (Lemma 3 + parallel-repetition note).

## 1. Messages (one PoK repetition; repeat independently ×τ)

Prover holds `w`; both sides hold statement, params, context.

| # | Dir | Message | FR25b basis |
|---|---|---------|-------------|
| 1 | P→V | `salt ∈ {0,1\}^{2λ}` (fresh per proof), Merkle root `h1` over `N` leaves `com_i = Com(JwK_i ∥ JuK_i ∥ JβK_i… ; ρ_i)` (witness packs, DECS mask packs, hint packs of JvK/Jv′K) | P5.1; salt follows SmallWood §5.3 (multi-proof binding), absent in FR25b — recorded delta |
| 2 | V→P | `Γ ∈ F^{η×\|Q\|}`, `\|Q\|` = total committed packs (witness + mask + hints) | P5.1a–b, Eq. 13–14 |
| 3 | P→V | `h1' = Hash(Pξ)`, `Pξ = Γ·Q + Pu` (degree-aligned per Eq. 13) | P5.1b |
| 4 | V→P | batching `γ ∈ F^{m1}`, `γ' ∈ F^{m2}` | Prot. 8 step 4 |
| 5 | P→V | `hB = Hash(JαK[1..dα+1] ∥ Jα′K[…])` (one broadcast round; ΠLigero needs no adaptive hints, so P5's `t`-loop collapses) | P5.4–5 with `t = 1` |
| 6 | V→P | opening set `I ⊂ [N]`, `\|I\| = ℓ` | P5.6 |
| 7 | P→V | for opened `I`: all share values + Merkle paths; broadcast shares `S` (`\|S\| = dα+1−ℓ` for `JαK`, `2s−1` for `Jα′K`, disjoint from `I`); DECS responses `Pξ(e_i)`, `i ∈ Sξ`, `\|Sξ\| = dβ+1−ℓ`, `Sξ ∩ I = ∅` | P5.7 |
| 8 | V | checks below; accept iff all pass | P5.8 |

Per-repetition proof bytes map 1:1 onto Eq. 16: `ℓ·(n+nh·ρ)` opened shares
(`nh = ⌈((d−1)(s+ℓ−1))/(dβ−ℓ+1)⌉ + ⌈(2s−1)/(dβ−ℓ+1)⌉` hint packs),
`(d−1)(s+ℓ−1)+(2s−2)` broadcast shares (`dα+1−ℓ−s` and `(2s+ℓ−2)+1−ℓ−1`
after recomputation/fixed-outcome deductions), `(dβ+1)·η` DECS elements
(`(dβ+1−ℓ)·η` responses + `ℓ·η` opened mask shares), `ℓ·logN` hashes of
`2λ` bits per path, plus the amortized `6λ` (`salt`, `h1`, `h1'`, `hB`-class
digests). No grinding counters (`κi = 0`, matches FR25b; SmallWood-style
proof-of-work explicitly deferred).

## 2. Verifier checks (each with its justification)

1. **Commitment binding**: recompute `h1` from opened leaves + paths.
   (P5.8, share-commitment check.)
2. **Party computation**: from opened shares recompute
   `JαK|_I = JvK|_I + Σγ_j f_j(JwK|_I)`,
   `Jα′K|_I = Jv′K|_I + Σγ'_j ⟨JA_jK, JwK|_I⟩`; interpolate full broadcasts
   with `S` shares; check `hB`. (P5.8, parties'-computation check; Lemma 3
   gives the `1/|F|^ρ` false-positive term.)
3. **DECS**: recompute `Pξ(e_i) = Γ·Q(e_i)+Pu(e_i)` for `i ∈ I`; interpolate
   over `Sξ ∪ I` (`dβ+1` points); check equality with hashed `h1'`. (P5.8
   DECS check; Theorem 1 gives `C(N,dβ+2)/|F|^η`.)
4. **Outcome**: `α = 0^s`, `Σα'_i = Σγ'_j t_j`. (Protocol 8 step 7; the
   `#AssertEq` equations sit inside `A·w = t`, so the V2 assertions and the
   shared-`x` semantics are enforced here.)
5. **Statement binding**: recompute the LPPC instance from the expected
   statement (never prover-supplied) and reject on circuit-hash mismatch;
   reject wrong suite/params/context, non-canonical `Fr`, trailing bytes,
   oversized vectors. (Implementation rule; same trust boundary as V2.)

## 3. Soundness terms (interactive, per repetition; Theorem 2, Eq. 15)

```text
ε₁ = 1/|F|^ρ + C(dα,ℓ)/C(N,ℓ) + C(N,dβ+2)/|F|^η,   dα = 2(s+ℓ−1)
```

Prototype point (`N=8192, ℓ=30, s=120, η=6, ρ=1, τ=2`):
per-rep `−145.5 / −440.7 / −253.6` bits; `τ=2` naive `−291.1` on the
threshold term. Reference `τ=1` point: `−128.1`, i.e. zero FS margin
(experimental/interop only). Full non-interactive accounting — including
query/grinding losses and the KZ parallel-repetition effect — is written
down in `V3_FIAT_SHAMIR.md`, where the open proof obligations live.
