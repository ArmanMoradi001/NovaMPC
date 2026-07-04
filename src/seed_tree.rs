//! GGM-style binary seed tree for the MPC-in-the-Head protocol.
//!
//! One root seed per repetition expands into N leaf seeds (one per virtual
//! party) via a length-doubling PRG modelled by BLAKE3 left/right child
//! derivation:
//!
//!   left_child  = BLAKE3(parent ‖ 0x00)
//!   right_child = BLAKE3(parent ‖ 0x01)
//!
//! When opening N-1 parties (hiding party `h`), the prover transmits the
//! **co-path**: one sibling seed per level from the hidden leaf up to the
//! root — `log₂(N_padded)` × 32 bytes instead of `(N-1)` × 32 bytes.
//! The verifier re-expands each co-path subtree to recover all N-1
//! non-hidden leaf seeds.
//!
//! ## Non-power-of-2 party counts
//!
//! The tree is built for `N_padded = num_parties.next_power_of_two()`.
//! Leaf positions `num_parties .. N_padded` are **padding nodes**: their
//! seeds are derived from the tree during construction but are never used
//! as party seeds, never committed to, and never transmitted.  When the
//! hidden party index is adjacent to a padding leaf, co-path level 0 covers
//! only that padding leaf — but higher co-path levels always cover real
//! parties, so the reconstruction remains authenticated.
//! `reconstruct_leaves_from_co_path` silently discards padding leaves and
//! returns exactly `num_parties` entries.

const SIDE_LEFT: u8 = 0x00;
const SIDE_RIGHT: u8 = 0x01;

/// Derive a child seed from a parent seed using BLAKE3.
fn derive_child(parent: &[u8; 32], side: u8) -> [u8; 32] {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(parent);
    input[32] = side;
    *blake3::hash(&input).as_bytes()
}

/// A complete binary seed tree stored in binary-heap order (1-indexed).
///
/// `nodes[1]` is the root; children of `nodes[i]` are `nodes[2i]` and
/// `nodes[2i+1]`.  Leaf nodes occupy `nodes[n_padded .. 2 * n_padded]`.
pub struct SeedTree {
    /// All tree nodes; `nodes[0]` is unused (1-indexed heap).
    nodes: Vec<[u8; 32]>,
    /// Number of leaves padded to the next power of two.
    pub n_padded: usize,
    /// Actual number of parties (≤ n_padded).
    pub num_parties: usize,
}

impl SeedTree {
    /// Build a seed tree for `num_parties` parties from `root_seed`.
    ///
    /// This is the named entry point called `build_seed_tree` in the module
    /// spec; it is also available as a standalone function below.
    pub fn build(root_seed: [u8; 32], num_parties: usize) -> Self {
        assert!(num_parties >= 2, "need at least 2 parties");
        let n_padded = num_parties.next_power_of_two();
        let mut nodes = vec![[0u8; 32]; 2 * n_padded + 1]; // 1-indexed
        nodes[1] = root_seed;

        // Expand top-down: internal nodes at indices 1 .. n_padded.
        for i in 1..n_padded {
            nodes[2 * i] = derive_child(&nodes[i], SIDE_LEFT);
            nodes[2 * i + 1] = derive_child(&nodes[i], SIDE_RIGHT);
        }

        Self {
            nodes,
            n_padded,
            num_parties,
        }
    }

    /// Return the first `num_parties` leaf seeds (party 0 .. N-1).
    pub fn leaf_seeds(&self) -> Vec<[u8; 32]> {
        self.nodes[self.n_padded..self.n_padded + self.num_parties].to_vec()
    }

    /// Return the co-path for hiding leaf at `hidden_index`.
    ///
    /// The result contains `log₂(n_padded)` seeds ordered from the **leaf
    /// level** (index 0) up to **just below the root** (last index).
    pub fn co_path(&self, hidden_index: usize) -> Vec<[u8; 32]> {
        assert!(hidden_index < self.num_parties, "hidden_index out of range");
        let depth = self.n_padded.trailing_zeros() as usize;
        let mut result = Vec::with_capacity(depth);
        let mut pos = self.n_padded + hidden_index; // leaf position in heap

        for _ in 0..depth {
            let sibling = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
            result.push(self.nodes[sibling]);
            pos /= 2;
        }

        result
    }
}

// ─── Public named API ────────────────────────────────────────────────────────

/// Build a seed tree and return only the `num_parties` leaf seeds.
///
/// Convenience wrapper around [`SeedTree::build`] + [`SeedTree::leaf_seeds`].
pub fn build_seed_tree(root_seed: [u8; 32], num_parties: usize) -> Vec<[u8; 32]> {
    SeedTree::build(root_seed, num_parties).leaf_seeds()
}

/// Get the co-path for the hidden leaf at `hidden_index` in a tree rooted at
/// `root_seed` with `num_parties` leaves.
///
/// Returns `log₂(num_parties.next_power_of_two())` sibling seeds.
pub fn get_co_path(root_seed: [u8; 32], num_parties: usize, hidden_index: usize) -> Vec<[u8; 32]> {
    let tree = SeedTree::build(root_seed, num_parties);
    tree.co_path(hidden_index)
}

/// Reconstruct all N-1 non-hidden leaf seeds from the co-path.
///
/// Returns a `Vec` of length `num_parties`.  The slot at `hidden_index` is
/// left as all-zeros and **must not** be used as a party seed.
///
/// # Panics
///
/// Panics if `co_path.len() != log₂(num_parties.next_power_of_two())`.
pub fn reconstruct_leaves_from_co_path(
    co_path: &[[u8; 32]],
    hidden_index: usize,
    num_parties: usize,
) -> Vec<[u8; 32]> {
    let n_padded = num_parties.next_power_of_two();
    let depth = n_padded.trailing_zeros() as usize;
    assert_eq!(
        co_path.len(),
        depth,
        "co_path length ({}) must equal tree depth ({depth})",
        co_path.len()
    );

    let mut leaves = vec![[0u8; 32]; n_padded];
    let mut hidden_pos = n_padded + hidden_index;

    // Walk from the hidden leaf up to the root.
    // At each level, the co-path entry is the sibling of the hidden-path node;
    // expand that sibling's entire subtree downward into leaf seeds.
    for &sibling_seed in co_path {
        let sibling_pos = if hidden_pos % 2 == 0 {
            hidden_pos + 1
        } else {
            hidden_pos - 1
        };
        expand_subtree(&sibling_seed, sibling_pos, n_padded, &mut leaves);
        hidden_pos /= 2;
    }

    // Return only the first num_parties leaves; padding slots are discarded.
    leaves[..num_parties].to_vec()
}

/// Recursively expand a subtree rooted at binary-heap position `pos`
/// into the flat `leaves` slice (leaf index `i` maps to `leaves[i]`).
fn expand_subtree(seed: &[u8; 32], pos: usize, n_padded: usize, leaves: &mut [[u8; 32]]) {
    if pos >= n_padded {
        // This is a leaf node.
        let idx = pos - n_padded;
        if idx < leaves.len() {
            leaves[idx] = *seed;
        }
        return;
    }
    let left = derive_child(seed, SIDE_LEFT);
    let right = derive_child(seed, SIDE_RIGHT);
    expand_subtree(&left, 2 * pos, n_padded, leaves);
    expand_subtree(&right, 2 * pos + 1, n_padded, leaves);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Core correctness check: build → co_path → reconstruct round-trips.
    fn round_trip(num_parties: usize, hidden: usize) {
        let root = [0xABu8; 32];
        let tree = SeedTree::build(root, num_parties);
        let leaves = tree.leaf_seeds();
        let co = tree.co_path(hidden);
        let recon = reconstruct_leaves_from_co_path(&co, hidden, num_parties);

        for i in 0..num_parties {
            if i != hidden {
                assert_eq!(
                    recon[i], leaves[i],
                    "leaf {i} mismatch (N={num_parties}, hidden={hidden})"
                );
            }
        }
    }

    // ── Required tests (per task spec) ───────────────────────────────────────

    #[test]
    fn test_n16_hidden7() {
        round_trip(16, 7);
    }

    #[test]
    fn test_n3_non_power_of_two() {
        // N=3 → N_padded=4, depth=2, co-path has 2 entries.
        for h in 0..3 {
            round_trip(3, h);
        }
    }

    #[test]
    fn test_n5_non_power_of_two() {
        // N=5 → N_padded=8, depth=3, co-path has 3 entries.
        for h in 0..5 {
            round_trip(5, h);
        }
    }

    // ── Additional coverage ───────────────────────────────────────────────────

    #[test]
    fn test_n16_all_hidden_indices() {
        for h in 0..16 {
            round_trip(16, h);
        }
    }

    #[test]
    fn test_build_seed_tree_standalone() {
        let leaves = build_seed_tree([1u8; 32], 4);
        assert_eq!(leaves.len(), 4);
        // All leaves must be distinct.
        for i in 0..4 {
            for j in (i + 1)..4 {
                assert_ne!(leaves[i], leaves[j], "leaves {i} and {j} collide");
            }
        }
    }

    #[test]
    fn test_determinism() {
        assert_eq!(
            build_seed_tree([7u8; 32], 8),
            build_seed_tree([7u8; 32], 8),
            "build_seed_tree must be deterministic"
        );
    }

    #[test]
    fn test_different_roots_differ() {
        let a = build_seed_tree([0u8; 32], 4);
        let b = build_seed_tree([1u8; 32], 4);
        assert_ne!(a, b);
    }

    #[test]
    fn test_co_path_length() {
        for &n in &[2usize, 3, 4, 5, 8, 16] {
            let tree = SeedTree::build([0u8; 32], n);
            let expected_depth = n.next_power_of_two().trailing_zeros() as usize;
            assert_eq!(
                tree.co_path(0).len(),
                expected_depth,
                "co-path depth wrong for N={n}"
            );
        }
    }
}
