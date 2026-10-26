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

## 2. Classical ROM: the applicable template and its cost

SmallWood Theorem 9 (verified in full text) gives the directly transferable
structure for a DECS-based FS proof: `ε ≤ ΣQ²/2^{2λ} + Σ Qi·εi/2^{κi}` —
a union bound over the adversary's queries *per FS round* (`Qi·εi`), plus
grinding denominators and a collision term. Applied structurally to our
three challenge rounds (`εΓ`, `εbatch`, `εopen` from `V3_PROTOCOL.md` §3,
`κi = 0`):

- Kales–Zaverucha [KZ20a] (eprint 2020/837, abstract verified): FS
  compilers of multi-round ID with parallel repetition admit a generic
  forgery that grinds the early challenges — MQDSS-L1's 128-bit claim fell
  to ≈2^95; mitigation is KZ-aware repetition counts. FR25b's τ rule
  (`ε^τ ≤ 2^{−λ}`, no `Q` factor) does not account for this and is
  therefore insufficient on its own for a non-interactive claim.
- Numbers (BN254 `Fr`, classical `Q = 2^64` queries per round oracle):
  - Prototype `τ=2`: `Q·εopen² ≈ 2^{−227}`, `Q·εdecs² ≈ 2^{−817}`,
    `Q·εfp² ≈ 2^{−443}`; collision floor `≈ Q²/2^{2λ} ≈ 2^{−128}` × small
    round factor — i.e. component margins are ample and binding/collision
    is the binding constraint, consistent with the ~127-bit field ceiling.
  - Reference `τ=1`: `Q·εopen ≈ 2^{−64}` — fails under KZ-aware
    accounting. Confirmed experimental/interop-only.
- These are *estimates from the template*, not a proof: the
  SmallWood-style straightline-extractor accounting for OUR exact
  transcript (failure events per round, `Qi` bookkeeping, digest-size
  collision term, KZ-aware τ selection across the first challenge) has not
  been written. That derivation is open obligation (a) below.

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

1. Extractor accounting for our transcript (classical ROM, `κi = 0`).
2. KZ-aware τ-selection proof for the first-challenge (`Γ`) grinding game.
3. QROM lift, or an explicitly classical-only claim scope.
4. Grinding decision (`κi > 0` changes proof size; unanalyzed).
5. Pre-existing: extraction/ZK arguments, independent review, audit.

## 5. Gate decision

**CONDITIONAL GO for Phase-3 implementation** (honest prover, verifier,
transcript mechanics, canonical encoding) with all presets experimental:
the interactive protocol is fully specified from FR25b, the message/size
mapping is verified, and no formula had to be invented. **NO-GO for any
security claim**: nothing may be called 127-bit (or otherwise) secure
until obligations 1–5 are derived and independently reviewed. If a later
phase finds the transcript or sizes cannot meet the targets with a proven
bound, stop per the V3 stop conditions rather than weakening anything.
