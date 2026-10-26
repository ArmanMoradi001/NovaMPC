# V3 external security review packet (Phase 9)

Status: **experimental research prototype. No security claim is made.**
This packet collects what exists for an independent cryptographer to
assess; it is not itself a review, an audit, or evidence of security.
No code was changed in this phase; the only edit besides this file is a
one-paragraph precision fix in `V3_FIAT_SHAMIR.md` §2 (documented
below), which changes no number and no verdict.

The system under review is NovaMPC V3, an MPC-in-the-Head
zero-knowledge proof for one combined statement (32-bit range check
AND set membership for the same private input `x`), built as
TCitH-MT over a Ligero-style LPPC constraint system compiled from the
existing V2 circuit (`src/v2/` untouched). The prover/verifier are
implemented (`src/v3/`); all parameter sets are explicitly
experimental.

## 1. Protocol summary

**Statement.** Public: range `[lo,hi]`, Merkle set root plus
`(num_members, depth)`, 32-byte context. Private: one `u32` witness
`x` shared by both checks (same-`x` enforced because range bits and
membership path derive from one wire vector; see `V3_PROTOCOL.md` §0,
`constraints.rs` compiler + differential tests).

**Relation.** The V2 arithmetic circuit (6186 gates / 1774 Mul for the
32-member combined case) is compiled once into an LPPC instance:
`m1 = ⌈M/s⌉` quadratic families `c − a·b = 0` over packed `(a,b,c)`
rows, plus `m2 = 2M + #AssertEq` global linear constraints
(`2·1774+94 = 3642` at the reference point), appended private-input
packs, zero-padded tail lanes (`V3_PROTOCOL.md` §0; P3.1 audit).

**Interactive protocol (idealized; `V3_PROTOCOL.md` §1, rows 1–8).**
Per repetition, prover sends Merkle root `h1` over packed Shamir
shares; verifier sends challenge matrix `Γ ∈ F^{η×num_q}`;
prover sends `h1' = Hash(Pξ)`; verifier sends batching challenges
`(γ,γ')` per MPC batch (`ρ` batches); prover sends broadcast hash
`hB`; verifier sends opening set `I`, `|I| = ℓ`; prover opens the
`I` parties (shares + Merkle paths) plus deterministic complement
sets `S` (`dα+1−ℓ` shares), `S′`, `Sξ` (`dβ+1−ℓ` responses) that both
sides recompute identically (never transmitted). `τ` repetitions run
sequentially; the verifier accepts iff all accept. The two implemented
deviations from FR25b are: (a) the DECS mask is folded into `Γ` as
ordinary columns (no standalone `Pu` term), and (b) sub-maximal Π$
tail-hint columns carry an `X^{dβ−deg}` alignment shift
(`prover.rs:149-171`, `verifier.rs:213-223`).

**Fiat–Shamir transcript (as implemented).** Prefix (domain
`.../transcript/v2`, post-P8.1): suite, params, statement fields,
context, circuit hash, salt, **`rep_index`** (`transcript.rs:87`).
Per rep, in order: absorb `h1`; squeeze `Γ`
(`V3_TR_TAG_GAMMA`/counter 0, ChaCha20 from 32-byte BLAKE3 output);
absorb `h1'`; squeeze `(γ,γ')` per batch (tag `V3_TR_TAG_BATCH`,
counters `2b`/`2b+1`); absorb `hB`; squeeze opening set `I`
(`V3_TR_TAG_OPEN`/counter 0, Fisher–Yates). No grinding
(`κi = 0`). Parameters `N ≤ 65536`, field BN254 `Fr`
(`log2|F| ≈ 253.6`); canonical 32-byte encodings; strict parse
(magic, version 2, length caps, no trailing bytes).

**Experimental presets (frozen, NOT approved).** Prototype
`N=8192,ℓ=30,s=120,η=6,ρ=1,τ=2` (~197 KiB model / ~210 KiB measured);
reference `N=8192,ℓ=27,s=133,η=5,ρ=1,τ=1`; fast insecure
`N=32,ℓ=3,s=8,η=2,ρ=1,τ=1`. Phase 8.3 explored further points
(`V3_PARAMETER_FEASIBILITY.md`); none adopted.

## 2. Security claims and non-claims

| Property | Verdict | Basis |
|---|---|---|
| Prototype correctness (honest path works; malformed/tampered proofs rejected as implemented) | **GO** | E2E + tamper tests pass; P8.1 cloned-repetition rejection test passes |
| Interactive soundness (idealized counterpart) | **CONDITIONAL** | Per-rep bound + τ-composition derived (`V3_INTERACTIVE_SOUNDNESS.md`), unreviewed |
| Classical-ROM (Fiat–Shamir) security | **NO-GO** | Round-by-round union bound derived for the exact transcript (`V3_FIAT_SHAMIR.md` §2); tops out ≈ `2^{−81}` for the best preset — fails 127-bit. No tight KZ-aware composition |
| QROM security | **NO-GO** | No applicable result (DFMS19 is 3-round-only) |
| Proof of knowledge | **NO-GO** | No extractor; no forking/rewinding ledger |
| Zero knowledge | **NO-GO** | No simulator; DECS-mask/X-shift deviations change the ZK surface |

No parameter set is called secure anywhere in this packet.

## 3. Core derivations to review

Reviewer entry points, with what each assumes. Everything below is
unreviewed unless marked verified-by-construction (code facts I checked
directly against the implementation in this phase).

**(a) DECS variant lemma (F1 resolution, `V3_AUDIT.md` §F1).**
Statement: with the as-built `Pξ_k = Σ_q Γ_{kq}·Q̃_q`, if some effective
column exceeds degree `dβ`, the DECS check passes with probability at
most `C(N,dβ+2)/|F|^η` (plus hash collisions). Proof *sketch* adapts
FR25b Theorem 1 Eqs. 7–9: fix commitment ⇒ union bound over
`(dβ+2)`-subsets `E`; per bad `E`, each `Γ` row drops degree with
probability `≤ 1/|F|` (nonzero leading-coefficient vector ⇒ proper
hyperplane); `η` independent rows ⇒ `|F|^−η` per `E`. Assumes:
binding commitments (Merkle/BLAKE3), uniform `Γ`, `N` distinct
evaluation points, shifts monic (true: `X^{shift}`), and — asserted,
not proved — that acceptance via a pre-committed `h1'` matching the
`Sξ∪I` interpolant is enclosed by the same bad-`E` event (the paper's
§5 step). Tail shifts make the check *strictly stronger* than the
paper's (per-column claimed degree, not just uniform cap `dβ`).

**(b) Interactive per-repetition bound (Phase 7, `V3_INTERACTIVE_SOUNDNESS.md`
§2).** `ε₁ ≤ p + (1−p)·C(dα,ℓ)/C(N,ℓ) + C(N,dβ+2)/|F|^η`,
`p = 1/|F|^ρ`, `dα = 2(s+ℓ−1)`, `dβ = s+ℓ−1`. Terms: DECS (from (a));
batching false positive (Lemma-3 shape: nonzero linear form in fresh
uniform `(γ,γ')` per batch, `ρ` independent batches ⇒ `|F|^−ρ`;
padding lanes are fixed pre-challenge values, no new randomness);
threshold (`dα+1`-special soundness: distinct `I` give distinct
transcripts via deterministic `S(I)`; needs the paper's extraction
argument, cited not reconstructed). Assumes the (a) lemma plus an
unwritten extractor for the special-soundness step.

**(c) τ-composition, interactive only (`V3_INTERACTIVE_SOUNDNESS.md`
§3).** Schedule is sequential with fresh verifier coins per rep;
`Pr[∧E_i] = Π_i Pr[E_i|H_{i-1}]`, each conditional bounded by `ε₁`.
This conditioning argument is standard probability (history as
auxiliary input) and does not depend on the cipher suite. It says
nothing about the deployed non-interactive proofs, whose challenges
are derived, not fresh — KZ grinding lives exactly in that gap.

**(d) Classical-ROM union bound (`V3_FIAT_SHAMIR.md` §2, Phase 8.2).**
For one forgery attempt set: `Pr[Forge] ≤ Q·(ε_decs + ε_fp + ε_thr) +
Coll(Q) + Bias`, with `Q = 2^64` classical RO queries assumed as the
budget (not derived). Per-round, per-*query* structure: fix the
transcript prefix in a query; the fresh output is uniform, so the
interactive per-round bounds apply; union-bound over the at-most-`Q`
queries that can serve each round (batching tuples counted by distinct
prefixes — determinism means one tuple per prefix set; rep index keeps
reps' squeeze inputs disjoint, which is why P8.1 is load-bearing for
the bookkeeping). `Coll(Q) ≲ Q²/2^{256}` envelopes Merkle binding,
`h1'`/`hB`/circuit-hash collisions. Assumes: ChaCha20 is a PRG
(expansion of 32-byte seeds; not proved here), Fisher–Yates modulo
bias negligible (`n ≤ 65536` vs 64-bit draws), canonical encodings
reject non-field values (implemented + tested), and the §2
failure-event for DECS coincides with the F1 lemma's game
(unreviewed). Deliberately loose: it bounds by rep 0 alone and ignores
that all τ reps must pass.
*Phase 9 correction to §2:* the original text folded the
never-queried-input case into collisions at guessing probability
`2^{−256}`; that understates it. An unqueried challenge is one fresh
uniform draw, bounded by the same per-round ε (absorbed as Q+1 ≈ Q).
Fixed in place; numbers unchanged (negligible either way), reasoning
now stated correctly.

**(e) Feasibility numbers (Phase 8.3, `V3_PARAMETER_FEASIBILITY.md`).**
`v3_phase0_model.py` reproduces the published calibration row to
0.6% (130.8 vs 130.0 KiB; rerun this phase). Per-preset interactive
terms recomputed independently here via `lgamma` binomials (agree
with docs to 0.1 bit): prototype thr `−145.53`, decs `−440.68`,
fp `−253.60`; reference thr `−128.13`, decs `−130.26`; fast vacuous.
Phase 8.3 grid search found numerical passes only at total
`≈ 2^{−128}` — i.e. at the collision floor, with ≤1-bit margin and
no headroom. Work estimates are order-of-magnitude extrapolations
from one release baseline, not benchmarks.

## 4. Reviewer questions

**Q1. Does the DECS variant lemma cover the mask-folded construction
and X-shifts?** Partially — see 3(a). What I verified directly: the
as-built combination preserves the exact mechanism the paper's bound
uses (pre-commit `h1'` before verifier randomness that selects `I`;
reconstruction over `dβ+1` points; hash-equality check), and the two
deviations are soundness-neutral-to-conservative *as far as the
sketch shows* (mask columns are just more coordinates for the
union bound; shifts are monic and only strengthen the per-column
check). What is NOT established: the "enclosed by the same bad-E
event" step linking acceptance-via-hash to the combinatorial union
bound, and any accounting of the shifted tail columns' exact claimed
degrees. Needs reviewer check against FR25b Theorem 1 Eqs. 7–9.
**Status: unproven; blocks any DECS-dependent claim.**

**Q2. Does the interactive single-rep bound apply to the combined
relation?** Structure matches the paper's §5/Lemma 3 shape (P3.1:
permuted `a‖b‖c` layout, appended inputs widen `A` only, zero-padded
tail lanes are fixed pre-challenge). Open: (i) the F1 lemma above;
(ii) the special-soundness extraction is cited, not written;
(iii) `dα+1 ≤ N` is checked per preset but not enforced by
`validate()` (F4) — a deployment using other parameters must enforce
it. **Status: conditional (i–iii); no independent extraction exists.**

**Q3. Is the sequential τ-composition valid against adaptive
provers?** Yes as far as it goes: conditioning on fixed history is
standard; no independence assumption is used; shared salt/witness are
fixed public inputs that do not couple fresh verifier coins. This
argument is the least uncertain piece of the package. It buys
nothing for the shipped proofs, whose challenges are FS-derived.
**Status: valid for the idealized experiment only.**

**Q4. Is the classical-ROM union bound valid for this exact
three-stage × τ transcript, including grinding, repeated prefixes,
and collisions?** The bookkeeping is sound as an upper bound *given*
the per-round lemmas: rep index separates reps' squeeze domains
(P8.1, code-verified); tuple counting bounds batching attempts by
`Q`; deterministic `S(I)` needs no extra queries; per-tag counters
(`0`; `2b,2b+1`; `0`) keep rounds distinct. Grinding is priced as
queries (`κi = 0` means no PoW gate to model). Collision envelope
`Q²/2^{256}` covers binding/hash steps coarsely. The bound is
deliberately loose (rep-0 only) and tops out ≈ `2^{−81}`.
**Status: valid-as-upper-bound modulo unreviewed lemmas; insufficient
for 127-bit by ~45 bits — NO-GO stands.**

**Q5. Are collisions, query budget, and sampling biases accounted
for?** Enumerated in §2: `Coll(Q)` envelope (no per-digest
bookkeeping — flagged as coarse but conservative for an upper
bound); `Q = 2^64` classical queries is a stated assumption, not a
derived bound (sensitivity: `Q = 2^80` costs 16 bits); ChaCha20-PRG
assumed; Fisher–Yates bias negligible (`≤ 2^{−48}`-scale claimed —
reviewer may wish to verify the constant); salt grinding priced in
`Q`; transcript v1 proofs rejected at parse (version bump tested).
**Status: accounted at envelope level; per-digest tightening and the
PRG assumption are open items, neither load-bearing for the verdict.**

**Q6. Does any parameter set reach a defensible classical 127-bit
claim?** No. Frozen presets fail under the only derived bound
(prototype `≈ 2^{−81}`, reference `≈ 2^{−64}`, fast vacuous).
Exploratory grid points reach only `≈ 2^{−128}` total — i.e. the
collision floor itself — with ≤1-bit margin, under unreviewed
lemmas and a knowingly loose bound. The withdrawn `Q·ε^τ ≈ 2^{−227}`
must not be used (no composition theorem; KZ shows naive
multi-round composition fails). **Status: NO-GO, no candidate
defensible.**

## 5. Source trail

- FR25b JoC revision (eprint 2023/1573): obtained once as a PDF via
  Wayback snapshot 2025-12-09 (Phase 6 record). Verified then:
  Eq. 13 (basic `JξK`), Eq. 14 (plain concatenation, no
  degree-alignment shifts), Eq. 15 (`Pξ := Γ·Q + Pu`), Theorem 1
  (per-row `1/|F|` drop, union over `(dβ+2)`-sets), Theorem 2 /
  Eq. 16 MT bound (`C(N,dβ+2)/|F|^η` DECS term), Π$ Lemma 1
  parameters, Π0/ΠΣ0 construction incl. footnote-10 Lagrange
  correction, Protocol 5 message order and `S`-set sizes,
  hash-equality checks, §6.4 ΠLigero specialization
  (`m1 = ⌈M/s⌉`, `m2`, degrees), Eq. 18 size formula, KZ selection
  rules. **I could not re-verify the full text in this environment
  (eprint returns 403/404 today); all equation-level claims above
  rest on the Phase 6 record, and the packet marks every downstream
  use as conditional on it.**
- KZ20a (eprint 2020/837): abstract verified only — generic
  multi-round FS forgery exists; MQDSS 128-bit → ≈2^95 forgery;
  mitigation is KZ-aware repetition counts. No attack formula is
  used or reproduced here.
- DFMS19 (eprint 2019/190): abstract verified only — QROM
  preservation for **3-round** sigma protocols. Our transcript is
  7-round-equivalent (3 challenges × τ), so it does not apply.
- SmallWood Theorem 9: recorded as "verified in full text" during
  Phase 6; I did not re-verify it, and the packet does not rely on
  it — the §2 bound is derived, not transferred.

## 6. Reproducibility and limits

- Code (unchanged by all audit phases): `cargo test --lib v3::`
  green (35 tests, includes P8.1 rep-index separation unit test);
  `tests/v3_prototype.rs` honest/tamper/negative-path tests pass;
  P8.1 added an explicit cloned-repetition rejection test
  (fails pre-fix by construction, passes post-fix).
- Model: `python3 v3_phase0_model.py` reproduces the published
  130.0 KB calibration row at 130.8 KiB (rerun this phase) and all
  per-preset soundness/size numbers used above (recomputed
  independently with `lgamma` binomials; agree to 0.1 bit).
- Measurements cited (not re-run): prototype proof 215,034 bytes
  (release, 32-member combined statement), prove ~411 s /
  verify ~200 s, peak RSS ~57 MB (P4.4, one-off example, removed
  after recording). Phase 8.3 work estimates are extrapolations
  from this single baseline (±5× stated), not benchmarks.
- Not committed / not reproducible from the repo: `/tmp`
  recomputation scripts, the Wayback PDF snapshot, the throwaway
  structural probe (removed per P4.4 convention).
- Pre-existing workspace state preserved (`fixes.md` deletion,
  untracked `examples/`, `.freebuff/`, `.ua`, `correct.md`);
  `git diff --stat` for this phase shows docs only (verified below).

**Bottom line for the reviewer.** The honest summary is: a coherent
but unreviewed derivation chain (F1 variant lemma → Phase 7
interactive bound → Phase 8.2 FS union bound → Phase 8.3 feasibility
scan) that fails to reach 127-bit classical security (≈ `2^{−81}` at
best under the only bound actually derived), with the tight analysis,
extractor, QROM treatment, ZK argument, and independent review all
missing. The decision requested of you is not whether to ship — that
is NO-GO on this evidence — but whether the derivations are sound as
far as they go, and exactly where they stop being so.
