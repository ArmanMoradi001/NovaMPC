# NovaMPC v2 protocol notes (STEP-06)

Status: algebraic correctness notes for the field port. These notes are not a
security proof. The v2 proof format and full verifier do not exist yet.

## 1. What is algebraically checked

The following facts are checked by unit tests and follow directly from field
arithmetic in `Fr`:

- **Additive reconstruction.** For a sharing `(s_0, s_1, s_2)`, with
  `s_2 = v - s_0 - s_1`, the sum is `v`. The first two shares are sampled
  uniformly by rejection sampling from 32-byte ChaCha output; the last share is
  the residual.
- **Linear gates.** `Add`, `AddConst`, and `MulConst` are evaluated locally on
  every party's share. Adding a constant to party 0's share and multiplying all
  shares by a public constant preserve reconstruction.
- **Multiplication.** With
  `r_i(g) = PRF(seed_i, g) - PRF(seed_{i+1}, g)` and
  `z_i = x_i*y_i + x_i*y_{i+1} + x_{i+1}*y_i + r_i(g)`,
  the three `r_i` telescope to zero and the three `z_i` reconstruct to `x*y` in
  `Fr`. This is the existing 3-party ZKBoo schedule with field operations in
  place of `Z_{2^32}` operations.
- **Honest views.** Recomputing each party's wire shares from its seed,
  claimed multiplication shares, and (for the residual party) transmitted input
  shares reproduces the emulation trace.
- **Opened-neighbour check.** If a party and its right neighbour are both
  opened, a modified multiplication-output share is detected. If the right
  neighbour is hidden, that multiplication check is skipped by the 2-of-3
  opening schedule.
- **Rejection sampling.** A 32-byte draw is accepted only when it is below the
  BN254 scalar modulus. Modulus and above-modulus draws are rejected, not
  reduced. Zero and `p-1` are accepted.
- **Domain separation.** Party share expansion and zero-share expansion use
  distinct, versioned BLAKE3-derived ChaCha20 domains. Zero-share domains also
  bind the multiplication-gate index as a fixed-width big-endian value.

## 2. What is not proven

No claim is made that v2 is sound, zero-knowledge, 128-bit secure, or
production-ready. In particular:

- The cut-and-choose/Fiat-Shamir conversion is not proved here.
- Commitment binding and hiding, seed-tree reconstruction, and view binding are
  not yet exercised by a v2 proof.
- The public assertion rows are not yet implemented. The notes below describe
  the intended construction and its known gap.
- The field change does not remove the need for independent cryptanalytic
  review of Poseidon2, the tagged framing, or the custom MPC protocol.

## 3. Hidden neighbour and the multiplication gap

With `N=3`, the verifier opens two parties and hides one. For each opened
party `p`, the multiplication share `z_p` can be recomputed only if party
`p+1 (mod 3)` is also opened. If the hidden party is `h`, exactly one opened
party has `p+1 = h`; that party's multiplication check is skipped. The other
opened party's check succeeds.

The skipped check is not recovered by opening the hidden party's share. A
cheating prover can therefore choose the hidden party's multiplication share
(and its downstream shares) to make an inconsistent execution look consistent to
the verifier. The standard 2-of-3 thinking gives a rough per-gate cheating
probability, but this repository does not prove an end-to-end soundness bound.
The earlier `(1/N)^M`-style wording is not a valid end-to-end claim.

## 4. Public assertion/output rows

V2 has no unasserted output list. Every public result must be constrained by a
v2 assertion gate. At the proof layer, assertion rows will publish every party's
share of the asserted wire before the challenge is derived. The verifier will
check that the published shares sum to the expected public value.

The hidden party's published assertion share is transcript-bound but is not
checked against the hidden party's committed view. A malicious prover can make
a failing assertion pass by fixing one party's published share; that repaired
row passes when the repaired party is the hidden party, roughly a `1/3` event
per row. Combined with the skipped multiplication check, this is the source of
the heuristic `(2/3)^M` gap. It is not a theorem and must not be advertised as a
soundness level until STEP-10 supplies a precise argument or the protocol is
changed.

V1's `expected_outputs` fallback is deliberately not carried into v2. Any v2
wire claimed as an output must be forced through an assertion; there is no
prover-supplied default output.

## 5. Field-port boundary

The multiplication formula, party role assignment, share generation order, and
2-of-3 opening schedule are unchanged from the existing 3-party path; the ring
operations are replaced by `Fr` operations. One deliberate v2 circuit change is
that `AssertEq` is a terminal constraint with no output wire, rather than a copy
gate. Assertion shares are therefore shares of the asserted input wire, not
shares of a separate copy wire. This change is explicit here and is reflected in
the v2 proof layer.
