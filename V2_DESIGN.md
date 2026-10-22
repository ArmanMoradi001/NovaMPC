# NovaMPC v2 design note (STEP-00)

Status: design freeze for a versioned v2 membership/range path. The v2 path is
implemented through STEP-10; the v1 `u32`/MiMC path remains unchanged. The
security proof/gap report is in [`V2_SECURITY_ANALYSIS.md`](V2_SECURITY_ANALYSIS.md).
No v2 deployment or production-security claim is made.

## 1. Scope and version boundary

V2 is a separate API and wire format for:

- membership of a private `u32` value in a public, committed set;
- a range check on that same value;
- one combined proof for both conditions.

The v1 modules, public types, serialized proofs, and 32-bit MiMC set roots are
not reinterpreted. V2 lives under `src/v2/` (or an equivalently explicit
versioned namespace) and uses its own proof/version identifiers. A v1 proof is
never accepted as v2, and a v1 root is never silently treated as a v2 root.

Migration is not a byte conversion: the old 32-bit root cannot be widened into
a field root without the original member list. Authorized sets must be rebuilt
from their members (or re-registered) before v2 proofs can be issued. Old
proofs and old roots are rejected on the v2 path.

## 2. Field and encoding

- Field: BN254 scalar field, `ark_bn254::Fr`.
- Modulus: `21888242871839275222246405745257275088548364400416034343698204186575808495617`
  (about 254 bits).
- Wire encoding: exactly 32 bytes, canonical big-endian field element.
- Deserialization rejects any 32-byte value greater than or equal to the
  modulus. It must not call a reducing decoder on untrusted bytes and must not
  silently map non-canonical input into the field.
- `u32 -> Fr` is the explicit embedding `Fr::from(value as u64)`. No signed or
  wrapping conversion is used.
- A 32-bit tree index/depth/member-count is encoded as a `u32` and embedded in
  `Fr` only where the framing explicitly says so.

Canonical encoding is a protocol value, not a Rust `usize`/`u64` memory dump.
No platform-dependent `usize::to_le_bytes()` is used on the wire.

## 3. Pinned Poseidon2 instance

Source: Horizen Labs `poseidon2` repository,
<https://github.com/HorizenLabs/poseidon2>, commit
`055bde3f4782731ba5f5ce5888a440a94327eaf3` (2024-11-25).

Pinned file:
`plain_implementations/src/poseidon2/poseidon2_instance_bn256.rs`
(SHA-256 `7b34cc6574424ea4ea56af1a8b568f99c449e092ceaa372e5226c4308937e7ac`).

Instance parameters, matching the upstream BN254 scalar-field instance:

| Parameter | Value |
|---|---|
| state width `t` | 3 |
| S-box degree `d` | 5 (`x^5`) |
| full rounds `R_F` | 8 (4 at the start, 4 at the end) |
| partial rounds `R_P` | 56 |
| total rounds | 64 |
| internal diagonal `MAT_DIAG3_M_1` | `[1, 1, 2]` |
| round constants | upstream `RC3`, 64 rows of 3 field elements |

The permutation order is exactly the upstream order:

1. initial external matrix multiplication;
2. 4 full rounds: add all round constants, apply `x^5` to all lanes,
   external matrix;
3. 56 partial rounds: add round constant to lane 0, apply `x^5` to lane 0,
   internal matrix;
4. 4 full rounds as in step 2, with no terminal matrix.

Upstream known-answer vector for `permutation([0, 1, 2])`:

```
out[0] = 0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033
out[1] = 0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570
out[2] = 0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8
```

The exact upstream constants are vendored from the pinned file and must match
this vector byte-for-byte. Constants are not regenerated, truncated, or
replaced by a different Poseidon variant.

### 3.1 NovaMPC v2 tagged hash framing

Upstream publishes the permutation and a two-input compression
`permutation([a, b, 0])[0]`; it does not publish a domain-separated set-hash
framing. V2 therefore defines one fixed, minimal framing around the pinned
permutation. This framing is part of the NovaMPC v2 protocol, not a claim that
upstream specifies it.

All inputs below are field elements. The single primitive is the pinned
permutation.

```
compress(tag, x, y) = permutation([tag, x, y])[0]

TAG_LEAF  = Fr(1)
TAG_NODE  = Fr(2)
TAG_ROOT  = Fr(3)

leaf(m)          = compress(TAG_LEAF, Fr(m), 0)          // m is u32
empty_leaf       = compress(TAG_LEAF, Fr(2^32), 0)       // reserved marker
node(left,right) = compress(TAG_NODE, left, right)
root(root,n,d)   = compress(TAG_ROOT, root, Fr( (d << 32) + n ))
```

`n` (number of real members) and `d` (tree depth) are each constrained to
`u32`, so the packed metadata value is unambiguous. The reserved empty-leaf
marker `2^32` cannot equal any embedded `u32`, so padding cannot collide with a
real member through the leaf encoding. The three tags are distinct protocol
constants and are fixed for the lifetime of v2.

The framing is fixed-width and length-unambiguous for the three v2 uses. Any
future variable-length input requires a new, explicitly versioned framing and
must not be squeezed into this one.

This construction gives a generic collision target of about 2^127, not 2^128,
because the output is one ~254-bit field element. It is not a post-quantum
claim, and it does not prove the surrounding MPC-in-the-head protocol.

## 4. Merkle tree semantics

- Leaves are ordered in the order supplied to the set builder; v2 does not
  sort silently.
- Duplicate `u32` members are rejected when building a set.
- A non-empty set of `n` members is padded to `next_power_of_two(n)` leaves
  with `empty_leaf`. There is no duplicate-last-leaf padding.
- `depth = 0` for `n = 1`, otherwise `depth = ceil(log2(n))`.
- Internal nodes use `node(left, right)` with the child order preserved; the
  membership path carries an explicit direction bit per level.
- The published root is `root(top, n, depth)`, binding the set size and depth.
  A root for a different `n`/`d` is a different public statement.
- Membership verification rejects `index >= n`, including indices that point
  at padded slots, and rejects any high index bit left over after consuming the
  path. The circuit enforces the same index bound and the same leaf value.

## 5. V2 relation and circuit boundary

V2 will use only the gates needed for the supported statements: private input,
add, multiply, add-constant, multiply-constant, assert-equal, and the
Poseidon2 gadget. All wires and constants are `Fr`; no v2 gate uses `u32`
wrapping arithmetic.

The field change applies to shares and MPC multiplication, not only to the
Merkle root. The v2 protocol keeps the existing 3-party ZKBoo opening schedule
(`N=3`) and ports the multiplication-share formula to `Fr`. Changing `N` would
require a different multiplication protocol and is out of scope.

The combined relation must use the same private `x` wire for the range check
and the membership leaf. Compiling two independent witnesses and hoping they
match is forbidden.

Range checks use boolean decompositions and exact reconstruction in `Fr` with
public `u32` bounds; they never rely on field wraparound as integer comparison.

## 6. Transcript and proof versioning

V2 uses a distinct proof version and a fixed transcript identifier including:

- protocol version, field identifier, Poseidon2 instance identifier and
  framing identifier;
- `N`, `M`;
- canonical public inputs, set root, member count, depth, range bounds;
- circuit hash and per-repetition commitment roots;
- all pre-challenge public share rows.

Variable-length data gets explicit length prefixes and fixed-width encodings.
The transcript does not hash platform-dependent `usize` bytes. V2 removes the
unasserted `expected_outputs` fallback: every v2 output must be constrained by
the circuit. Proof shape and bounds are validated before hashing
attacker-controlled circuits or allocating based on proof data.

## 7. Security claims and limitations

This design note does not claim that v2 is production-secure, 128-bit secure,
or post-quantum secure.

- BN254 `Fr` has a generic collision ceiling near 127 bits; widening the old
  root to 32 bytes does not by itself repair a 32-bit commitment.
- Poseidon2 parameter security is an external cryptanalytic assumption. The
  pinned instance and framing need independent review.
- STEP-10 analysed the custom MPC-in-the-head protocol, its 3-party opening
  schedule, public assertion/output rows, hidden-neighbor multiplication gap,
  seed-tree co-path, and Fiat-Shamir conversion. It derives a conditional
  `(2/3)^M` soundness bound and records a concrete tight forgery, but
  knowledge soundness, zero knowledge, and the concrete cryptographic
  assumptions remain unproven. See `V2_SECURITY_ANALYSIS.md`.
- A larger hash or more repetitions alone do not establish protocol soundness.
  At `M=96` the conditional bound is about `2^-56.16`; `M=219` is not a clean
  128-bit claim.
- V1 remains a research baseline with a 32-bit MiMC root and must not be
  described as production-secure. Neither v1 nor v2 is approved for
  deployment.

## 8. Planned implementation gates

The implementation follows `correct.md` in order: canonical field encoding
(STEP-01), native Poseidon2 and KATs (STEP-02), native field Merkle tree
(STEP-03), minimal `Fr` circuit (STEP-04), Poseidon2 circuit gadget (STEP-05),
`Fr` shares/MPC identities (STEP-06), range/membership/combined builders
(STEP-07), versioned proof/transcript (STEP-08), benchmarks/migration note
(STEP-09), and the separate security-analysis proof/gap report (STEP-10,
`V2_SECURITY_ANALYSIS.md`).
