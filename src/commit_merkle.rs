/// BLAKE3-based Merkle tree for per-reputation commitment authentication.
///
/// This tree operates on raw `[u8; 32]` commitment bytes and is never
/// evaluated inside an arithmetic circuit. It is intentionally separate
/// from `crate::merkle::MerkleTree`, which uses MiMC over `u32` leaves
/// and must match the in-circuit MiMC hashing used by `SetMembership`.

/// Hash a pair of 32-byte nodes with BLAKE3.
fn blake3_hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// A Merkle proof for a single commitment leaf.
#[derive(Debug, Clone)]
pub struct CommitMerkleProof {
    pub leaf: [u8; 32],
    pub leaf_index: usize,
    pub siblings: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

impl CommitMerkleProof {
    /// Recompute the root from leaf + siblings and check it matches `self.root`.
    pub fn verify(&self) -> bool {
        let mut current = self.leaf;
        let mut idx = self.leaf_index;
        for sibling in &self.siblings {
            let (l, r) = if idx % 2 == 0 {
                (&current, sibling)
            } else {
                (sibling, &current)
            };
            current = blake3_hash_pair(l, r);
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
pub struct CommitTree {
    leaves: Vec<[u8; 32]>,
    nodes: Vec<[u8; 32]>,
    depth: usize,
}

impl CommitTree {
    /// Build a Merkle tree from `leaves`.
    ///
    /// If `leaves.len()` is not a power of two it is rounded up to the next
    /// power of two by padding with zeros.
    pub fn build(leaves: &[[u8; 32]]) -> Self {
        let n = leaves.len().next_power_of_two();
        let depth = n.trailing_zeros() as usize;
        let base = 1usize << depth;

        let zero = [0u8; 32];
        // nodes[0] is unused; root is at 1.
        let mut nodes = vec![zero; 2 * base];
        let mut leaves_padded = vec![zero; n];
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
                nodes[level_base + i] = blake3_hash_pair(&left, &right);
            }
        }

        Self {
            leaves: leaves_padded,
            nodes,
            depth,
        }
    }

    /// Return the Merkle root.
    pub fn root(&self) -> [u8; 32] {
        self.nodes[1]
    }

    /// Produce an authentication proof for the leaf at `leaf_index`.
    pub fn prove_membership(&self, leaf_index: usize) -> CommitMerkleProof {
        assert!(leaf_index < self.leaves.len(), "leaf_index out of range");
        let base = 1usize << self.depth;
        let mut siblings = Vec::with_capacity(self.depth);
        let mut pos = base + leaf_index;

        for _ in 0..self.depth {
            let sibling = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
            siblings.push(self.nodes[sibling]);
            pos /= 2;
        }

        CommitMerkleProof {
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
    fn test_four_leaves_deterministic_root() {
        let leaves = [[10u8; 32], [20u8; 32], [30u8; 32], [42u8; 32]];
        let tree = CommitTree::build(&leaves);
        let root1 = tree.root();
        let root2 = CommitTree::build(&leaves).root();
        assert_eq!(root1, root2);
        assert_ne!(root1, [0u8; 32]);
    }

    #[test]
    fn test_four_leaves_all_proofs_valid() {
        let leaves = [[10u8; 32], [20u8; 32], [30u8; 32], [42u8; 32]];
        let tree = CommitTree::build(&leaves);
        for i in 0..4 {
            let proof = tree.prove_membership(i);
            assert!(proof.verify(), "proof for leaf {i} failed");
        }
    }

    #[test]
    fn test_tampered_sibling_fails() {
        let leaves = [[10u8; 32], [20u8; 32], [30u8; 32], [42u8; 32]];
        let tree = CommitTree::build(&leaves);
        let mut proof = tree.prove_membership(1);
        proof.siblings[0][0] ^= 1;
        assert!(!proof.verify());
    }

    #[test]
    fn test_tampered_leaf_fails() {
        let leaves = [[10u8; 32], [20u8; 32], [30u8; 32], [42u8; 32]];
        let tree = CommitTree::build(&leaves);
        let mut proof = tree.prove_membership(2);
        proof.leaf[0] ^= 0xFF;
        assert!(!proof.verify());
    }

    #[test]
    fn test_eight_leaves() {
        let leaves: Vec<[u8; 32]> = (1u32..=8).map(|v| {
            let mut buf = [0u8; 32];
            buf[..4].copy_from_slice(&v.to_le_bytes());
            buf
        }).collect();
        let tree = CommitTree::build(&leaves);
        let root = tree.root();
        assert_ne!(root, [0u8; 32]);
        assert_eq!(root, CommitTree::build(&leaves).root());
        for i in 0..8 {
            let proof = tree.prove_membership(i);
            assert!(proof.verify(), "proof for leaf {i} failed");
        }
    }
}
