# NovaMPC v2 protocol notes (STEP-06, updated at STEP-09)

Status: algebraic correctness and implementation notes for the field and proof
path. These notes are not a security proof. The v2 proof format and verifier are
implemented, but no end-to-end soundness, zero-knowledge, or production-security
claim is made.

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
- V2 proof code exercises commitment paths, seed-tree reconstruction, and view
  binding, but BLAKE3 binding/hiding and the seed-tree PRG are cryptographic
  assumptions, not theorems established by these tests.
- The public assertion rows are implemented, but the hidden-party share is not
  tied to the hidden committed view. That gap remains part of the protocol
  analysis below.
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
v2 assertion gate. The STEP-08 proof layer publishes every party's share of each
asserted wire before the challenge is derived. The verifier checks that the
published shares sum to the expected public value and that each opened party's
published share matches its recomputed wire share. The hidden party's row is
only checked through the sum.

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

## 6. Implemented v2 proof layer (STEP-08)

This section records implementation facts, not security claims.

- **Type and version.** `v2::proof::V2Proof` carries version `2`, its
  `V2Params` (`N=3`), the `StatementV2`, and one proof repetition per
  challenge. It is a separate Rust type from the v1 `Proof`. Serialized v2
  proofs start with the magic `NMPCV2P\0`; v1 bincode proofs do not.
- **Canonical wire format.** Fields are 32-byte canonical big-endian `Fr`
  values. Vector lengths and counts are explicit big-endian `u32` values, and
  SHA/PRG domain lengths use big-endian `u64` values. Decoding rejects a
  non-canonical field encoding, a wrong magic or version, malformed lengths,
  truncation, and trailing bytes. The decoder is not `serde`/`bincode`.
- **Verifier circuit source.** The proof contains no circuit and no
  `expected_outputs`. `verify` validates the statement, recompiles the canonical
  circuit with `compile_from_statement`, hashes that circuit, and uses only that
  circuit. A proof therefore cannot substitute a different gate sequence.
- **Transcript.** The transcript binds, in order: the protocol identifier,
  proof/suite version, field identifier, pinned Poseidon2 instance identifier,
  tagged-framing identifier, `N`, `M`, statement type tag, canonical statement
  values, canonical circuit hash, every repetition commitment root, and every
  assertion-share row (including row lengths). Challenges are derived only after
  all of those values are absorbed. The challenge PRG seed is derived by a
  domain-separated BLAKE3 call, and the hiding party index is sampled uniformly
  from `0..N`.
- **Commitment components.** V2 uses a domain-separated BLAKE3 seed tree,
  domain-separated BLAKE3 view commitments binding repetition, party, seed,
  length-prefixed view payload and randomness, and a domain-separated BLAKE3
  commitment Merkle tree. The member-set root remains the separate tagged
  Poseidon2 tree from STEP-03. None of these v2 trees reinterpret a v1 tree.
- **Verifier checks.** For each repetition, verification reconstructs the
  opened seed-tree leaves from the co-path, recomputes every opened party's wire
  shares, checks each opened view commitment under the repetition root, checks
  linear gates and every Mul gate whose right neighbour is opened, checks each
  opened party's assertion shares against recomputed wire values, and checks
  every assertion row sum against the public constant. A hidden party's view and
  assertion share are not opened.
- **Resource bounds.** `V2Params` rejects `N != 3`, `M == 0`, and
  `M > 65536`. Decoding caps path depth, Mul/residual/assertion vector lengths,
  and the total serialized proof at 1 GiB before allocating or verifying. These
  are denial-of-service bounds, not security parameters. The `balanced()` preset
  (`M=96`) is only a repetition-count preset and is not a security claim.

## 7. What STEP-08 does not establish

The transcript/commitment binding above is an implementation property, not a
proof of knowledge soundness or zero knowledge. In particular, the hidden-party
assertion row, the hidden-party committed view, and the skipped
hidden-neighbour multiplication share are not checked against one another. The
heuristic `(2/3)^M` discussion in section 4 remains a gap report, not a theorem.
Independent review of Poseidon2, BLAKE3 usage, the seed tree, the commitment
trees, and the Fiat-Shamir conversion is still required before any security or
deployment claim.

## 8. Benchmarks and migration

STEP-09 measurements are in [`V2_BENCHMARKS.md`](V2_BENCHMARKS.md); the v1-to-v2
root/proof cutover is in [`V2_MIGRATION.md`](V2_MIGRATION.md). The measurements
show that v2 proofs are substantially larger than v1 because they carry 32-byte
field shares. The MPC protocol remains unproven; STEP-10 has not been
completed, and no benchmark result is a security qualification.
