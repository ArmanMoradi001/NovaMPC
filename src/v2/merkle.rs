//! Native v2 Merkle tree for the committed `u32` member set.
//!
//! Leaves are ordered, duplicate members are rejected, and padding uses a
//! domain-separated empty leaf. The published root is bound to both the real
//! member count and the tree depth.
//!
//! Native tree correctness is not a proof of MPC soundness. The circuit path
//! must enforce the same relation and the v2 protocol still needs its separate
//! security analysis.

use std::collections::HashSet;

use ark_bn254::Fr;
use thiserror::Error;

use crate::v2::poseidon2::{self, encode_hash};

/// Proof that one leaf belongs to a v2 member-set tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProofV2 {
    /// The hashed leaf value. For a real member this is `hash_leaf(member)`.
    pub leaf: Fr,
    /// Position in the ordered leaf array, before padding.
    pub leaf_index: u32,
    /// Bottom-up sibling hashes, starting at the leaf level.
    pub siblings: Vec<Fr>,
}

/// Errors returned while building or querying a v2 set tree.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum V2MerkleError {
    /// A set must contain at least one member.
    #[error("v2 member set must not be empty")]
    EmptySet,

    /// The member count cannot be represented in the v2 root metadata.
    #[error("v2 member set has too many members: {0}")]
    TooManyMembers(usize),

    /// Duplicate members are not allowed in a committed set.
    #[error("duplicate v2 member: {0}")]
    DuplicateMember(u32),

    /// The requested leaf index is not a real member slot.
    #[error("v2 leaf index {index} is out of range for {num_members} members")]
    IndexOutOfRange { index: u32, num_members: u32 },
}

/// Ordered, duplicate-free v2 Merkle tree over embedded `u32` members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTreeV2 {
    root: Fr,
    num_members: u32,
    depth: u32,
    /// 1-indexed heap layout; leaves start at `1 << depth`.
    nodes: Vec<Fr>,
}

impl MerkleTreeV2 {
    /// Build a v2 tree from an ordered member list.
    ///
    /// Empty sets and duplicate members are rejected. Non-power-of-two sizes
    /// are padded with the fixed `hash_empty_leaf()` value, not by repeating
    /// the last member.
    pub fn build(members: &[u32]) -> Result<Self, V2MerkleError> {
        if members.is_empty() {
            return Err(V2MerkleError::EmptySet);
        }
        if members.len() > u32::MAX as usize {
            return Err(V2MerkleError::TooManyMembers(members.len()));
        }

        let mut seen = HashSet::with_capacity(members.len());
        for &member in members {
            if !seen.insert(member) {
                return Err(V2MerkleError::DuplicateMember(member));
            }
        }

        let num_members = members.len() as u32;
        let depth = depth_for_members(num_members);
        let leaf_count = 1usize
            .checked_shl(depth)
            .ok_or(V2MerkleError::TooManyMembers(members.len()))?;
        let node_count = leaf_count
            .checked_mul(2)
            .ok_or(V2MerkleError::TooManyMembers(members.len()))?;
        let mut nodes = vec![Fr::from(0u64); node_count];

        for (offset, &member) in members.iter().enumerate() {
            nodes[leaf_count + offset] = poseidon2::hash_leaf(member);
        }
        let empty_leaf = poseidon2::hash_empty_leaf();
        for slot in nodes
            .iter_mut()
            .skip(leaf_count + members.len())
            .take(leaf_count - members.len())
        {
            *slot = empty_leaf;
        }

        for parent in (1..leaf_count).rev() {
            nodes[parent] = poseidon2::hash_node(nodes[2 * parent], nodes[2 * parent + 1]);
        }

        let root = poseidon2::hash_root(nodes[1], num_members, depth);
        Ok(Self {
            root,
            num_members,
            depth,
            nodes,
        })
    }

    /// Published root, bound to member count and depth.
    pub fn root(&self) -> Fr {
        self.root
    }

    /// Canonical 32-byte big-endian root encoding.
    pub fn root_bytes(&self) -> [u8; 32] {
        encode_hash(&self.root)
    }

    /// Number of real members (padding slots are excluded).
    pub fn num_members(&self) -> u32 {
        self.num_members
    }

    /// Tree depth: 0 for a one-member set.
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// Number of leaves after power-of-two padding.
    pub fn padded_len(&self) -> usize {
        self.nodes.len() / 2
    }

    /// Produce a membership path for a real member slot.
    ///
    /// Padding slots are not valid member positions and are rejected.
    pub fn prove_membership(&self, leaf_index: u32) -> Result<MerkleProofV2, V2MerkleError> {
        if leaf_index >= self.num_members {
            return Err(V2MerkleError::IndexOutOfRange {
                index: leaf_index,
                num_members: self.num_members,
            });
        }

        let leaf_count = self.padded_len();
        let mut index = leaf_count + leaf_index as usize;
        let mut siblings = Vec::with_capacity(self.depth as usize);
        while index > 1 {
            siblings.push(self.nodes[index ^ 1]);
            index >>= 1;
        }

        Ok(MerkleProofV2 {
            leaf: self.nodes[leaf_count + leaf_index as usize],
            leaf_index,
            siblings,
        })
    }

    /// Verify a membership path against this tree's root, count, and depth.
    pub fn verify_membership(&self, proof: &MerkleProofV2) -> bool {
        verify_membership_statement(self.root, self.num_members, self.depth, proof)
    }

    /// Verify a path and additionally bind it to a concrete `u32` member.
    pub fn verify_member(&self, member: u32, proof: &MerkleProofV2) -> bool {
        proof.leaf == poseidon2::hash_leaf(member) && self.verify_membership(proof)
    }
}

/// Verify a path against an externally supplied v2 statement.
///
/// The count/depth pair must be the canonical pair for the set size. This
/// prevents accepting a path under a different tree shape or a different root
/// metadata interpretation.
pub fn verify_membership_statement(
    root: Fr,
    num_members: u32,
    depth: u32,
    proof: &MerkleProofV2,
) -> bool {
    if num_members == 0 || depth != depth_for_members(num_members) {
        return false;
    }
    if proof.leaf_index >= num_members {
        return false;
    }
    if proof.siblings.len() != depth as usize {
        return false;
    }

    let mut node = proof.leaf;
    let mut index = proof.leaf_index;
    for sibling in &proof.siblings {
        node = if index & 1 == 0 {
            poseidon2::hash_node(node, *sibling)
        } else {
            poseidon2::hash_node(*sibling, node)
        };
        index >>= 1;
    }

    // Any unconsumed high index bit would describe a position outside this
    // tree, even if the supplied siblings happened to reproduce the root.
    if index != 0 {
        return false;
    }

    poseidon2::hash_root(node, num_members, depth) == root
}

/// Canonical depth for `num_members` real leaves: `ceil(log2(n))`, with
/// depth 0 for a single member.
pub fn depth_for_members(num_members: u32) -> u32 {
    debug_assert!(num_members > 0);
    if num_members == 1 {
        0
    } else {
        u32::BITS - (num_members - 1).leading_zeros()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_all_members_verify(members: &[u32]) {
        let tree = MerkleTreeV2::build(members).unwrap();
        assert_eq!(tree.num_members(), members.len() as u32);
        assert_eq!(tree.depth(), depth_for_members(members.len() as u32));
        for (index, &member) in members.iter().enumerate() {
            let proof = tree.prove_membership(index as u32).unwrap();
            assert_eq!(proof.leaf, poseidon2::hash_leaf(member));
            assert!(tree.verify_membership(&proof), "index {index} failed");
            assert!(tree.verify_member(member, &proof), "member {member} failed");
        }
    }

    #[test]
    fn sizes_one_three_four_five_verify_every_member() {
        assert_all_members_verify(&[42]);
        assert_all_members_verify(&[10, 20, 42]);
        assert_all_members_verify(&[1, 2, 3, 4]);
        assert_all_members_verify(&[7, 11, 99, 1000, 65_535]);
    }

    #[test]
    fn ordered_leaves_make_order_part_of_the_root() {
        let a = MerkleTreeV2::build(&[1, 2]).unwrap();
        let b = MerkleTreeV2::build(&[2, 1]).unwrap();
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn duplicate_members_are_rejected() {
        assert_eq!(
            MerkleTreeV2::build(&[5, 1, 5]),
            Err(V2MerkleError::DuplicateMember(5))
        );
    }

    #[test]
    fn empty_set_is_rejected() {
        assert_eq!(MerkleTreeV2::build(&[]), Err(V2MerkleError::EmptySet));
    }

    #[test]
    fn padded_slot_is_not_a_member_position() {
        let tree = MerkleTreeV2::build(&[10, 20, 42]).unwrap();
        assert_eq!(tree.padded_len(), 4);
        assert_eq!(
            tree.prove_membership(3),
            Err(V2MerkleError::IndexOutOfRange {
                index: 3,
                num_members: 3
            })
        );

        // A hand-built path for the padding slot must also fail even though the
        // leaf itself is the tree's empty leaf.
        let forged = MerkleProofV2 {
            leaf: poseidon2::hash_empty_leaf(),
            leaf_index: 3,
            siblings: tree.prove_membership(2).unwrap().siblings,
        };
        assert!(!tree.verify_membership(&forged));
    }

    #[test]
    fn out_of_range_and_high_index_bits_are_rejected() {
        let tree = MerkleTreeV2::build(&[10, 20, 42]).unwrap();
        let mut proof = tree.prove_membership(2).unwrap();
        proof.leaf_index = 3;
        assert!(!tree.verify_membership(&proof));

        proof.leaf_index = 4;
        assert!(!tree.verify_membership(&proof));

        proof.leaf_index = 2 + tree.padded_len() as u32;
        assert!(!tree.verify_membership(&proof));

        proof.leaf_index = u32::MAX;
        assert!(!tree.verify_membership(&proof));
    }

    #[test]
    fn wrong_sibling_is_rejected() {
        let tree = MerkleTreeV2::build(&[10, 20, 42]).unwrap();
        let mut proof = tree.prove_membership(1).unwrap();
        proof.siblings[0] += Fr::from(1u64);
        assert!(!tree.verify_membership(&proof));
    }

    #[test]
    fn wrong_count_depth_and_root_are_rejected() {
        let tree = MerkleTreeV2::build(&[10, 20, 42]).unwrap();
        let proof = tree.prove_membership(1).unwrap();

        assert!(!verify_membership_statement(
            tree.root(),
            4,
            2,
            &proof
        ));
        assert!(!verify_membership_statement(
            tree.root(),
            3,
            1,
            &proof
        ));
        assert!(!verify_membership_statement(
            tree.root(),
            3,
            3,
            &proof
        ));
        assert!(!verify_membership_statement(
            tree.root() + Fr::from(1u64),
            3,
            2,
            &proof
        ));
    }

    #[test]
    fn single_member_depth_zero_is_supported() {
        let tree = MerkleTreeV2::build(&[42]).unwrap();
        assert_eq!(tree.depth(), 0);
        let proof = tree.prove_membership(0).unwrap();
        assert!(proof.siblings.is_empty());
        assert!(tree.verify_member(42, &proof));
        assert!(!tree.verify_member(43, &proof));

        let mut bad = proof;
        bad.leaf_index = 1;
        assert!(!tree.verify_membership(&bad));
    }

    #[test]
    fn root_bytes_are_stable_and_domain_separated() {
        let tree = MerkleTreeV2::build(&[10, 20, 42]).unwrap();
        let bytes = tree.root_bytes();
        assert_eq!(
            hex::encode(bytes),
            "20cfc970f02af396314ee64096a042f63d1a3141d61ff9ddc0c6922266581e68"
        );
        assert_eq!(
            hex::encode(MerkleTreeV2::build(&[42]).unwrap().root_bytes()),
            "06ad35ed7c6f0d7d6ceeb3749b75caf9b103ec652f187fdb2ca4ed0e01a7ed23"
        );
        assert_eq!(
            hex::encode(MerkleTreeV2::build(&[1, 2, 3, 4]).unwrap().root_bytes()),
            "2585e3492193f30ba7598ab2c69a7d3b134e54f01a32b11fd3fc7cbcb86db802"
        );
        assert_eq!(bytes.len(), 32);
        assert_eq!(tree.root_bytes(), bytes);
        assert_ne!(
            tree.root_bytes(),
            MerkleTreeV2::build(&[10, 20, 43]).unwrap().root_bytes()
        );
        assert_ne!(
            tree.root_bytes(),
            MerkleTreeV2::build(&[10, 20, 42, 99]).unwrap().root_bytes()
        );
    }

    #[test]
    fn root_binds_count_even_for_same_top_node() {
        // A two-member tree's top node is reused with different metadata only
        // in this test; real builds must produce different roots because the
        // count and depth are part of the root hash.
        let two = MerkleTreeV2::build(&[1, 2]).unwrap();
        let top = poseidon2::hash_node(poseidon2::hash_leaf(1), poseidon2::hash_leaf(2));
        assert_eq!(
            two.root(),
            poseidon2::hash_root(top, 2, 1),
            "root must include metadata"
        );
        assert_ne!(two.root(), poseidon2::hash_root(top, 3, 1));
    }
}
