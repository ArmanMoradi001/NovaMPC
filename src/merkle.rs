//! Native Merkle tree using MiMC as the hash function.
//!
//! Used by the prover to build the tree and generate authentication paths
//! before entering the MPC-in-the-Head proof system.

use crate::mimc::mimc_hash_native;

/// A Merkle proof for a single leaf.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf: u32,
    pub leaf_index: usize,
    pub siblings: Vec<u32>,
    pub root: u32,
}

impl MerkleProof {
    /// Recompute the root from leaf + siblings and check it matches `self.root`.
    pub fn verify(&self) -> bool {
        let mut current = self.leaf;
        let mut idx = self.leaf_index;
        for &sibling in &self.siblings {
            let (l, r) = if idx % 2 == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            current = mimc_hash_native(l, r, crate::mimc::MIMC_ROUNDS).0;
            idx /= 2;
        }
        current == self.root
    }
}

/// A complete Merkle tree stored in a flat binary-heap layout.
///
/// Index 1 is the root; children of node `i` are at `2i` and `2i+1`.
/// Leaves occupy indices `base..base+len` where `base = 1 << depth`.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    leaves: Vec<u32>,
    nodes: Vec<u32>,
    depth: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from `leaves`.
    ///
    /// If `leaves.len()` is not a power of two it is rounded up to the next
    /// power of two by padding with zeros.
    ///
    /// # Errors
    /// Returns `InvalidParams` if `leaves` is empty. An empty tree has no
    /// root and no provable positions, so construction fails instead of
    /// producing a degenerate tree (or panicking downstream).
    pub fn build(leaves: &[u32]) -> crate::Result<Self> {
        if leaves.is_empty() {
            return Err(crate::MpcithError::InvalidParams(
                "Cannot build a Merkle tree from an empty leaf set".into(),
            ));
        }
        let n = leaves.len().next_power_of_two();
        let depth = n.trailing_zeros() as usize;
        let base = 1usize << depth;

        // nodes[0] is unused; root is at 1.
        let mut nodes = vec![0u32; 2 * base];
        let mut leaves_padded = vec![0u32; n];
        leaves_padded[..leaves.len()].copy_from_slice(leaves);

        // Place leaves.
        for (i, &v) in leaves_padded.iter().enumerate() {
            nodes[base + i] = v;
        }

        // Build internal nodes bottom-up.
        for level in (1..=depth).rev() {
            let level_base = 1usize << (level - 1);
            let child_base = 1usize << level;
            for i in 0..level_base {
                let left = nodes[child_base + 2 * i];
                let right = nodes[child_base + 2 * i + 1];
                nodes[level_base + i] = mimc_hash_native(left, right, crate::mimc::MIMC_ROUNDS).0;
            }
        }

        Ok(Self {
            leaves: leaves_padded,
            nodes,
            depth,
        })
    }

    /// Return the Merkle root.
    pub fn root(&self) -> u32 {
        self.nodes[1]
    }

    /// Produce an authentication proof for the leaf at `leaf_index`.
    pub fn prove_membership(&self, leaf_index: usize) -> MerkleProof {
        assert!(leaf_index < self.leaves.len(), "leaf_index out of range");
        let base = 1usize << self.depth;
        let mut siblings = Vec::with_capacity(self.depth);
        let mut pos = base + leaf_index;

        for _ in 0..self.depth {
            let sibling = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
            siblings.push(self.nodes[sibling]);
            pos /= 2;
        }

        MerkleProof {
            leaf: self.leaves[leaf_index],
            leaf_index,
            siblings,
            root: self.root(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_build_returns_error() {
        // An empty leaf set has no root and no provable positions:
        // construction must fail with a clear error, never panic and never
        // produce a degenerate tree.
        let result = MerkleTree::build(&[]);
        assert!(
            matches!(result, Err(crate::MpcithError::InvalidParams(_))),
            "empty build must return InvalidParams"
        );
    }

    #[test]
    fn test_single_leaf_tree_preserved() {
        // Depth-0 tree: the root IS the leaf and its (empty) path verifies.
        let tree = MerkleTree::build(&[42]).unwrap();
        assert_eq!(tree.root(), 42);
        let proof = tree.prove_membership(0);
        assert!(proof.verify(), "single-leaf proof must verify");
    }

    #[test]
    fn test_three_leaves_padded_preserved() {
        // Non-power-of-two sets pad with zeros; every real member keeps a
        // valid authentication path.
        let tree = MerkleTree::build(&[7, 8, 9]).unwrap();
        for i in 0..3 {
            assert!(
                tree.prove_membership(i).verify(),
                "proof for leaf {i} of padded set failed"
            );
        }
    }

    #[test]
    fn test_four_leaves_deterministic_root() {
        let tree = MerkleTree::build(&[10, 20, 30, 42]).unwrap();
        let root1 = tree.root();
        let root2 = MerkleTree::build(&[10, 20, 30, 42]).unwrap().root();
        assert_eq!(root1, root2);
        assert_ne!(root1, 0);
    }

    #[test]
    fn test_four_leaves_all_proofs_valid() {
        let tree = MerkleTree::build(&[10, 20, 30, 42]).unwrap();
        for i in 0..4 {
            let proof = tree.prove_membership(i);
            assert!(proof.verify(), "proof for leaf {i} failed");
        }
    }

    #[test]
    fn test_tampered_sibling_fails() {
        let tree = MerkleTree::build(&[10, 20, 30, 42]).unwrap();
        let mut proof = tree.prove_membership(1);
        proof.siblings[0] ^= 1;
        assert!(!proof.verify());
    }

    #[test]
    fn test_tampered_leaf_fails() {
        let tree = MerkleTree::build(&[10, 20, 30, 42]).unwrap();
        let mut proof = tree.prove_membership(2);
        proof.leaf = 99;
        assert!(!proof.verify());
    }

    #[test]
    fn test_eight_leaves() {
        let vals: Vec<u32> = (1..=8).collect();
        let tree = MerkleTree::build(&vals).unwrap();
        let root = tree.root();
        assert_ne!(root, 0);

        // Rebuild is deterministic.
        assert_eq!(root, MerkleTree::build(&vals).unwrap().root());

        for i in 0..8 {
            let proof = tree.prove_membership(i);
            assert!(proof.verify(), "proof for leaf {i} failed");
        }
    }
}
