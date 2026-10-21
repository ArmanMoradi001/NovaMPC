# NovaMPC v1 to v2 migration note

Status: migration guidance for the versioned v2 path. It is not a security or
production-readiness claim. **The MPC protocol remains unproven; STEP-10 has not
been completed.**

## Roots are not upgradeable in place

A v1 set root is a 32-bit MiMC value. A v2 root is a BN254 `Fr` root produced by
the tagged Poseidon2 tree in `MerkleTreeV2`. There is no safe conversion from an
old root alone:

- the old root is a digest, not the member set;
- widening or re-hashing the old 32-bit value does not authenticate any v2
  leaves;
- a v2 proof must be bound to the v2 root, canonical member count, and depth.

Rebuild the v2 root from the **original authoritative member set** using
`MerkleTreeV2::build(&members)`. Publish the new v2 root together with
`num_members()` and `depth()`. Do not accept a caller-supplied count/depth pair
that is not the canonical pair for that set.

## Proof migration

- Do not reinterpret v1 proof bytes as v2. `V2Proof::from_bytes` requires the v2
  magic and version and rejects v1 bincode bytes.
- Do not translate v1 proof fields into a `V2Proof` in memory. V1 and v2 use
  different fields, hashes, transcript identifiers, and MPC share domains.
- Old v1 proofs must be rejected by the v2 verifier. If old proofs must remain
  valid during a transition, keep the v1 verifier and v1 roots in a separate,
  explicitly versioned path; never let that path accept v2 roots or proofs.
- Regenerate proofs against the new v2 root/count/depth. A v2 proof is bound to
  the canonical circuit and the public statement; a changed root, count, depth,
  or range fails verification.

## Suggested cutover sequence

1. Freeze the authoritative member list for the migration epoch.
2. Build the v2 tree from that list and record the new root, count, and depth.
3. Deploy the v2 verifier identifiers and reject v1 proofs on the v2 path.
4. Regenerate client proofs using `prove_membership` or `prove_combined` with
   the v2 authentication path.
5. Keep the v1 path only if backward compatibility is explicitly required, and
   document that its 32-bit root has the v1 limitations.

Root widening alone does not make NovaMPC secure, and neither v1 nor v2 has an
end-to-end security proof in this tree.
