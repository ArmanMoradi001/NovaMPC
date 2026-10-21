//! V2 commitment Merkle tree.
//!
//! This authenticates the N per-party view commitments under one root per
//! repetition. It is a BLAKE3 tree, separate from the Poseidon2 member-set
//! tree, and uses v2-specific leaf/internal/padding domains.

use crate::{MpcithError, Result};

const COMMIT_NODE_CONTEXT: &str = "NovaMPC-v2/commit-node/v1";
const COMMIT_EMPTY_CONTEXT: &str = "NovaMPC-v2/commit-empty/v1";
const MAX_LEAVES: usize = 1 << 16;

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);
    blake3::derive_key(COMMIT_NODE_CONTEXT, &input)
}

/// Fixed domain-separated padding leaf for commitment trees.
pub fn empty_commitment_leaf() -> [u8; 32] {
    blake3::derive_key(COMMIT_EMPTY_CONTEXT, &[])
}

/// A single commitment membership proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitProofV2 {
    pub leaf: [u8; 32],
    pub leaf_index: u32,
    pub siblings: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

impl CommitProofV2 {
    /// Fold the path and compare with `root`. The caller must also check that
    /// `siblings.len()` equals the expected tree depth.
    pub fn verify(&self) -> bool {
        let mut current = self.leaf;
        let mut index = self.leaf_index;
        for sibling in &self.siblings {
            let (left, right) = if index & 1 == 0 {
                (&current, sibling)
            } else {
                (sibling, &current)
            };
            current = hash_pair(left, right);
            index >>= 1;
        }
        index == 0 && current == self.root
    }
}

/// A complete v2 commitment tree in 1-indexed heap layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitTreeV2 {
    leaves: Vec<[u8; 32]>,
    nodes: Vec<[u8; 32]>,
    depth: usize,
    num_real_leaves: usize,
}

impl CommitTreeV2 {
    /// Build a tree over the supplied commitment leaves, padding to the next
    /// power of two with [`empty_commitment_leaf`].
    pub fn build(leaves: &[[u8; 32]]) -> Result<Self> {
        if leaves.is_empty() || leaves.len() > MAX_LEAVES {
            return Err(MpcithError::InvalidParams(format!(
                "v2 commitment tree requires 1..={MAX_LEAVES} leaves, got {}",
                leaves.len()
            )));
        }
        let n = leaves.len().next_power_of_two();
        let depth = n.trailing_zeros() as usize;
        let base = 1usize << depth;
        let mut nodes = vec![[0u8; 32]; 2 * base];
        let mut padded = vec![empty_commitment_leaf(); n];
        padded[..leaves.len()].copy_from_slice(leaves);

        for (index, leaf) in padded.iter().enumerate() {
            nodes[base + index] = *leaf;
        }
        for parent in (1..base).rev() {
            nodes[parent] = hash_pair(&nodes[2 * parent], &nodes[2 * parent + 1]);
        }

        Ok(Self {
            leaves: padded,
            nodes,
            depth,
            num_real_leaves: leaves.len(),
        })
    }

    pub fn root(&self) -> [u8; 32] {
        self.nodes[1]
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn num_real_leaves(&self) -> usize {
        self.num_real_leaves
    }

    /// Produce a path for a real (non-padding) leaf.
    pub fn prove_membership(&self, leaf_index: usize) -> Result<CommitProofV2> {
        if leaf_index >= self.num_real_leaves {
            return Err(MpcithError::InvalidParams(format!(
                "v2 commitment leaf index {leaf_index} is not a real leaf ({} real leaves)",
                self.num_real_leaves
            )));
        }
        let base = 1usize << self.depth;
        let mut siblings = Vec::with_capacity(self.depth);
        let mut pos = base + leaf_index;
        for _ in 0..self.depth {
            let sibling = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
            siblings.push(self.nodes[sibling]);
            pos /= 2;
        }
        Ok(CommitProofV2 {
            leaf: self.leaves[leaf_index],
            leaf_index: leaf_index as u32,
            siblings,
            root: self.root(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(count: usize) -> Vec<[u8; 32]> {
        (0..count)
            .map(|i| blake3::derive_key("test-commit-leaf", &(i as u64).to_be_bytes()))
            .collect()
    }

    #[test]
    fn every_real_leaf_verifies_across_sizes() {
        for count in [1usize, 2, 3, 4, 5, 8, 9] {
            let leaves = leaves(count);
            let tree = CommitTreeV2::build(&leaves).unwrap();
            assert_eq!(tree.num_real_leaves(), count);
            for index in 0..count {
                let proof = tree.prove_membership(index).unwrap();
                assert_eq!(proof.siblings.len(), tree.depth());
                assert_eq!(proof.leaf, leaves[index]);
                assert!(proof.verify(), "leaf {index} of {count}");
            }
        }
    }

    #[test]
    fn padding_leaf_is_not_a_real_index() {
        let tree = CommitTreeV2::build(&leaves(3)).unwrap();
        assert!(tree.prove_membership(3).is_err());
        assert_eq!(tree.depth(), 2);
        assert_ne!(empty_commitment_leaf(), [0u8; 32]);
    }

    #[test]
    fn tampering_is_rejected() {
        let leaves = leaves(3);
        let tree = CommitTreeV2::build(&leaves).unwrap();
        let valid = tree.prove_membership(1).unwrap();
        assert!(valid.verify());

        let mut bad_leaf = valid.clone();
        bad_leaf.leaf[0] ^= 1;
        assert!(!bad_leaf.verify());

        let mut bad_sibling = valid.clone();
        bad_sibling.siblings[0][0] ^= 1;
        assert!(!bad_sibling.verify());

        let mut bad_root = valid.clone();
        bad_root.root[0] ^= 1;
        assert!(!bad_root.verify());

        let mut high_index = valid.clone();
        high_index.leaf_index += 1 << high_index.siblings.len();
        assert!(!high_index.verify());
    }

    #[test]
    fn deterministic_roots_and_order_sensitivity() {
        let a = leaves(3);
        let b = vec![a[1], a[0], a[2]];
        assert_eq!(
            CommitTreeV2::build(&a).unwrap().root(),
            CommitTreeV2::build(&a).unwrap().root()
        );
        assert_ne!(
            CommitTreeV2::build(&a).unwrap().root(),
            CommitTreeV2::build(&b).unwrap().root()
        );
        assert!(CommitTreeV2::build(&[]).is_err());
    }
}
