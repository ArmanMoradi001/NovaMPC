# V3 Fiat–Shamir analysis and gate decision (classical ROM + QROM)

Experimental. No security claim is made. Primary sources only; nothing here
is guessed — where the cited literature does not cover this exact protocol,
that is stated as an open question.

## 1. FS construction specified for implementation

Three FS challenges per PoK repetition, in transcript order
(`V3_PROTOCOL.md` §1): `Γ` (after `salt, rep-index, h1`), batching
`(γ,γ')` (after `h1'`), opening set `I` (after `hB`). Each challenge =
`XOF(domain ‖ transcript-so-far)` covering statement, params, context,
rep index, and all prior messages. No grinding (`κi = 0`, as in FR25b;
SmallWood-style proof-of-work explicitly deferred — adding it later
changes the size equation). `τ` repetitions are independent (fresh
sharing randomness per repetition) with per-repetition challenges bound
to distinct rep indices (Phase 8.1 fix: identical rep payloads at
different indices derive different challenges; transcript domain v2,
proof format v2). This construction is implementable from the cited
templates (FR25b P5 + SmallWood Fig. 8 structure); the *loss bound*
below is what remains open.

## 2. Classical-ROM reduction: round-by-round union bound

Status: derivation, not a tight bound, not independently reviewed. This
section replaces the earlier `Q·ε^τ` template estimate, which is
withdrawn as a claim: no composition theorem justifying it was proved,
and KZ-style grinding is precisely the reason naive `ε^τ`
multiplication fails for multi-round Fiat–Shamir. What follows is proved
only to the standard of a classical-ROM union bound over adversary
queries, using the Phase 6 DECS lemma and the Phase 7 interactive terms
as per-round, per-query bounds.

### 2.1 Exact transcript modelled

Per repetition `r` (`rep_index` bound in the prefix post-P8.1; domain
`.../transcript/v2`): prefix absorbs suite, all params, statement
fields, context, circuit hash, 32-byte salt, `rep_index`. Then,
in order: prover message `h1` (Merkle root); challenge `Γ`
(`η·num_q` field elements from one 32-byte squeeze,
`V3_TR_TAG_GAMMA`/counter 0, ChaCha20-expanded, rejection-sampled);
`h1' = Hash(Pξ coeffs)`; per batch `b` challenges `(γ,γ')`
(`V3_TR_TAG_BATCH`, counters `2b`/`2b+1`); `hB = Hash(canonical
broadcast shares)`; challenge opening set `I` (`V3_TR_TAG_OPEN`,
counter 0, Fisher–Yates from one squeeze); prover messages (opened
shares+paths, `S`/`S′`/`Sξ` responses, `Δu1` corrections). The verifier
recomputes every challenge deterministically and accepts iff all `τ`
reps pass. `S`/`S′`/`Sξ` are deterministic functions of `I`,
recomputed both sides, never transmitted. No grinding (`κi = 0`):
each challenge value is pinned by a single squeeze of a fixed input.

### 2.2 Adversary, queries, and what must be bounded

Classical adversary `A` makes at most `Q` total RO queries (BLAKE3
modelled as RO, 256-bit outputs) then outputs one proof; `Forge` =
verifier accepts on a fixed false statement. Every challenge value in
a verifying proof equals the RO output on a transcript-determined
input, so each challenge is either a fresh uniform draw (input never
queried before: guessing probability `≤ 2^{−256}` per value, folded
into the collision terms) or the output of one of `A`'s `Q` queries.
Union bound over queries is therefore legitimate for every round, with
no independence assumption across reps: it suffices to bound
`Pr[rep 0 accepts]`, since forgery requires all reps to accept.

Fix one query input (hence one fixed prefix: statement, params,
context, salt, rep index, and all prover messages absorbed so far).
The fresh output is uniform and independent of history. Per-round bad
events and their bounds (all from verified sources or Phase 6/7
lemmas):

- **DECS round (`Γ`).** If the committed columns contain an
  over-degree effective column (`max_q deg Q̃_q > dβ`, a property of
  the fixed `h1`), the Phase 6 variant lemma gives acceptance of the
  DECS check with probability at most
  `ε_decs := C(N,dβ+2)/|F|^η` (union over `(dβ+2)`-subsets, `|F|^−η`
  per set from the `η` independent `Γ` rows; `h1'`-after-`Γ` choice
  and later `I` are inside the lemma's game, as verified against
  FR25b Theorem 1 Eqs. 7–9). The lemma is unreviewed — the bound
  below is conditional on it.
- **Batching round (`(γ,γ')`, `ρ` pairs).** For fixed prior transcript
  with a violated LPPC relation, all `ρ` aggregated outcome checks
  pass with probability at most `ε_fp := |F|^−ρ` (Phase 7 Term B:
  nonzero linear form per independent batch). Tuple-counting: a
  batching attempt is identified by its full `2ρ`-squeeze prefix;
  determinism means distinct attempts need distinct prefixes, of
  which at most `Q` exist — so at most `Q` attempts, each `≤ ε_fp`.
- **Opening round (`I`).** For fixed prefix with valid sharings
  (`¬DEF`) and no false positive, the fraction of opening sets
  admitting any accepting completion is at most
  `ε_thr := C(dα,ℓ)/C(N,ℓ)` (Phase 7 Term C: `dα+1`-special
  soundness; deterministic `S(I)` preserves distinct-`I`
  transcripts). Fisher–Yates modulo bias (`n ≤ 65536` vs 64-bit
  draws) is negligible (`≤ 2^{−48}`-scale) and listed, not hidden.

Summing over the at-most-`Q` queries that can serve each round
(the same `Q` budget reused as a universal cap — no
per-round splitting assumption needed):

```text
Pr[Forge] ≤ Q·(ε_decs + ε_fp + ε_thr) + Coll(Q) + Bias,
```

with `Coll(Q) ≲ Q²/2^{256}` covering Merkle binding, `h1'`/`hB`/
circuit-hash collisions and unqueried-challenge guesses, and `Bias`
covering ChaCha20-PRG distinguishing (the 32-byte seeds expand
deterministically; ChaCha20 is *assumed* pseudorandom — explicit
assumption, not proved here) plus Fisher–Yates modulo bias
(negligible).

### 2.3 Grinding and KZ, precisely placed

`κi = 0` means grinding has no proof-of-work gate: grinding IS making
RO queries, and every grind attempt is priced in `Q` above — the union
bound already charges the adversary per query regardless of strategy,
including KZ-style allocation of queries across rounds and reps. What
the bound does *not* do is exploit that all `τ` reps must pass: it
bounds by rep 0 alone and is therefore loose. A tighter KZ-aware
composition (the missing theorem) could only *lower* the bound, never
raise it — but looseness cuts the other way for claims: NO-GO stands
because even this accounted bound fails the target (see §2.4), and
because KZ [KZ20a, abstract-verified: MQDSS 128-bit → ≈2^95 forgery]
shows naive `ε^τ` composition is false for multi-round FS, so the
withdrawn `Q·ε^τ ≈ 2^{−227}` template must not be used as evidence of
anything.

### 2.4 Recomputed per-preset bounds (`Q = 2^64` classical queries)

`log2|F| = 253.5967`. All `ε` values independently recomputed
(`lgamma` binomials; agree with the audit table to 0.1 bit).

| Preset | `Q·ε_decs` | `Q·ε_fp` | `Q·ε_thr` | Union bound (dominant term) | Verdict |
|---|---|---|---|---|---|
| Prototype `N=8192,ℓ=30,s=120,η=6,ρ=1,τ=2` | `2^{−376.7}` | `2^{−189.6}` | **`2^{−81.5}`** | `≈ 2^{−81.5}` | **NO-GO** (needs `≤ 2^{−127}`; short by ~45 bits) |
| Reference `N=8192,ℓ=27,s=133,η=5,ρ=1,τ=1` | `2^{−66.3}` | `2^{−189.6}` | `2^{−64.1}` | `≈ 2^{−63.8}` | **NO-GO** |
| Fast test `N=32,ℓ=3,s=8,η=2,ρ=1,τ=1` | vacuous (`ε_thr = 2^{−2.12}`) | — | `≈ 2^{+61.9}` | vacuous (`> 1`) | **NO-GO** (insecure by design) |

Collision floor `Q²/2^{256} ≈ 2^{−128}` is negligible next to the
threshold term in every case (it would matter only if the threshold
term were fixed — it is not part of this phase to tune parameters).
The bound scales linearly in `Q` (stated budget `Q = 2^64` classical
queries; `Q = 2^80` costs 16 more bits). No parameter set reaches a
defensible classical 127-bit level under the only reduction proved
here.

### 2.5 What this derivation does and does not establish

Establishes: a rigorous-per-query union-bound *upper* bound on
classical-ROM forgery for the exact as-built transcript (modulo the
listed assumptions: Phase 6 DECS lemma as stated, ChaCha20 PRG,
negligible sampling biases, collision terms as bounded). It prices
grinding, repeated/related prefixes (each new salt/`h1` needs fresh
downstream queries; rep indices keep reps' squeeze inputs disjoint —
P8.1 is load-bearing for the bookkeeping), and deterministic `S` sets.
Refutes: any use of `Q·ε^τ` (≈ `2^{−227}`) or bare `ε₁^τ`
(≈ `2^{−291}`) as a classical-ROM security level — unproved here and
contradicted in spirit by KZ.
Leaves open (unchanged): a *tight* KZ-aware multi-round composition
theorem for this transcript; a straightline or rewinding extractor
ledger (needed for proof of knowledge, §4 item 1/2); QROM lift (§3);
zero-knowledge simulation (unchanged NO-GO).

## 3. QROM: what the cited sources do and do not cover

- DFMS19 (eprint 2019/190, abstract verified): generic QROM preservation
  for **3-round** sigma protocols with a `Q`-dependent loss. Our protocol
  has 3 FS challenges × τ repetitions (7-round-equivalent structure), so
  DFMS19 does not directly apply.
- SmallWood Theorem 9 is classical-ROM; no quantum bound was found in the
  paper. FR25b's treatment is classical plus the KZ warning.
- The applicable tool class (multi-round FS in the QROM,
  e.g. Don–Fehr–Majenz measure-and-reprogram lineage) has not been applied
  to this transcript here. A post-quantum claim therefore has no basis in
  the cited sources — consistent with V2, which likewise makes no PQ
  claim. Open obligation (b).

## 4. Precise open questions (block claims, not implementation)

1. Extractor accounting for our transcript (classical ROM, `κi = 0`):
   the §2 bound is pure soundness (no rewinding). Proof of knowledge
   needs a straightline or rewinding extractor ledger across the
   `3τ` challenge points with explicit forking/runtime loss —
   unproven and unbounded here.
2. Tight KZ-aware composition for this exact transcript: §2 prices
   every query and is valid, but bounds by rep 0 alone. A theorem
   exploiting that all `τ` reps must pass (KZ-style allocation
   analysis) is the missing piece for any bound stronger than §2.4.
3. QROM lift, or an explicitly classical-only claim scope.
4. Grinding decision (`κi > 0` changes proof size; unanalyzed).
   Note: with `κi = 0`, grinding is already priced in `Q`; a grinding
   parameter would change the transcript and the size equation, not
   rescue the current bound.
5. Pre-existing: ZK simulator (mask-folding changes the ZK surface;
   no simulator written), independent review, audit.

## 5. Gate decision (Phase 8.2)

**NO-GO for any classical-ROM 127-bit claim.** The §2 union-bound
reduction is the strongest statement proved here, and it tops out near
`2^{−81}` for the best preset — about 45 bits short — with the threshold
round as the binding constraint. This is not a tightness complaint that
can be argued away: without the missing tight KZ-aware composition
theorem (§4 item 2), no stronger classical number is justified, and the
QROM lift (§4 item 3), extractor ledger (§4 item 1), and independent
review remain open regardless. Nothing may be called 127-bit (or
otherwise) secure. No code changes result from this phase; the
implementation, presets, and proof format are untouched, and the
stop-condition parameter freeze is respected (no tuning was performed
to chase the bound).

## 6. Phase 8.3 feasibility note (no code, no preset changes)

A bounded parameter search under the §2 bound (`Q = 2^64`) finds
numerically passing points — e.g. `N=65536, ℓ=24, s=96, η=6, ρ=1,
τ=1`: total `≈ 2^{−127.9}`, modeled wire size `≈ 97 KiB`. Full table,
domain, work estimates, and caveats: `V3_PARAMETER_FEASIBILITY.md`.
Two structural consequences, both derived not assumed:

- τ (and ρ > 1) buy nothing under the proven bound: the §2 reduction
  bounds forgery by rep 0 alone, so extra repetitions only add size.
  τ=1 strictly dominates; this supersedes the Phase 0 `τ = 2`
  recommendation, which relied on unproved composition.
- Every passing point sits at total `≈ 2^{−128}`, i.e. the collision
  floor — margins can never exceed ~1 bit under this accounting, by
  construction, not by parameter choice.

These are feasibility *numbers under stated assumptions*, not
evidence of security. §5's NO-GO stands unchanged: the bound is
unreviewed, the tight KZ-aware analysis is missing, and the margin
is too thin to absorb it.
