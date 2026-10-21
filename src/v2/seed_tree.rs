//! V2-specific GGM seed tree.
//!
//! The tree shape matches the existing 3-party schedule, but child derivation
//! is domain-separated under a v2-only BLAKE3 context. V1 seed trees are not
//! reused or reinterpreted.

use crate::{MpcithError, Result};

const SIDE_LEFT: u8 = 0x00;
const SIDE_RIGHT: u8 = 0x01;
const SEED_TREE_CONTEXT: &str = "NovaMPC-v2/seed-tree-child/v1";

/// Conservative bound for malformed parameter sets. The v2 protocol fixes N=3.
const MAX_PARTIES: usize = 1 << 16;

fn derive_child(parent: &[u8; 32], side: u8) -> [u8; 32] {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(parent);
    input[32] = side;
    blake3::derive_key(SEED_TREE_CONTEXT, &input)
}

/// Binary seed tree in 1-indexed heap order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedTreeV2 {
    nodes: Vec<[u8; 32]>,
    n_padded: usize,
    num_parties: usize,
}

impl SeedTreeV2 {
    /// Build a v2 seed tree from a root seed.
    pub fn build(root_seed: [u8; 32], num_parties: usize) -> Result<Self> {
        if num_parties < 2 || num_parties > MAX_PARTIES {
            return Err(MpcithError::InvalidParams(format!(
                "v2 seed tree requires 2..={MAX_PARTIES} parties, got {num_parties}"
            )));
        }
        let n_padded = num_parties.next_power_of_two();
        let mut nodes = vec![[0u8; 32]; 2 * n_padded + 1];
        nodes[1] = root_seed;
        for i in 1..n_padded {
            nodes[2 * i] = derive_child(&nodes[i], SIDE_LEFT);
            nodes[2 * i + 1] = derive_child(&nodes[i], SIDE_RIGHT);
        }
        Ok(Self {
            nodes,
            n_padded,
            num_parties,
        })
    }

    /// First `num_parties` leaf seeds.
    pub fn leaf_seeds(&self) -> Vec<[u8; 32]> {
        self.nodes[self.n_padded..self.n_padded + self.num_parties].to_vec()
    }

    /// Co-path for a hidden party, ordered leaf level upward.
    pub fn co_path(&self, hidden_index: usize) -> Result<Vec<[u8; 32]>> {
        if hidden_index >= self.num_parties {
            return Err(MpcithError::VerificationFailed(format!(
                "v2 hidden index {hidden_index} out of range for {} parties",
                self.num_parties
            )));
        }
        let depth = self.n_padded.trailing_zeros() as usize;
        let mut result = Vec::with_capacity(depth);
        let mut pos = self.n_padded + hidden_index;
        for _ in 0..depth {
            let sibling = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
            result.push(self.nodes[sibling]);
            pos /= 2;
        }
        Ok(result)
    }
}

/// Reconstruct all non-hidden leaf seeds from a v2 co-path.
///
/// The hidden slot is filled with zeros and must never be used as a party
/// seed. The proof layer only accesses non-hidden indices.
pub fn reconstruct_leaves_from_co_path(
    co_path: &[[u8; 32]],
    hidden_index: usize,
    num_parties: usize,
) -> Result<Vec<[u8; 32]>> {
    if num_parties < 2 || num_parties > MAX_PARTIES {
        return Err(MpcithError::VerificationFailed(format!(
            "v2 seed tree requires 2..={MAX_PARTIES} parties, got {num_parties}"
        )));
    }
    let n_padded = num_parties.next_power_of_two();
    let depth = n_padded.trailing_zeros() as usize;
    if co_path.len() != depth {
        return Err(MpcithError::VerificationFailed(format!(
            "v2 co_path length {} does not equal tree depth {depth}",
            co_path.len()
        )));
    }
    if hidden_index >= num_parties {
        return Err(MpcithError::VerificationFailed(format!(
            "v2 hidden index {hidden_index} out of range for {num_parties} parties"
        )));
    }

    let mut leaves = vec![[0u8; 32]; n_padded];
    let mut hidden_pos = n_padded + hidden_index;
    for &sibling_seed in co_path {
        let sibling_pos = if hidden_pos % 2 == 0 {
            hidden_pos + 1
        } else {
            hidden_pos - 1
        };
        expand_subtree(&sibling_seed, sibling_pos, n_padded, &mut leaves);
        hidden_pos /= 2;
    }
    Ok(leaves[..num_parties].to_vec())
}

fn expand_subtree(seed: &[u8; 32], pos: usize, n_padded: usize, leaves: &mut [[u8; 32]]) {
    if pos >= n_padded {
        let index = pos - n_padded;
        if index < leaves.len() {
            leaves[index] = *seed;
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

    fn round_trip(num_parties: usize, hidden: usize) {
        let tree = SeedTreeV2::build([0xABu8; 32], num_parties).unwrap();
        let leaves = tree.leaf_seeds();
        let co_path = tree.co_path(hidden).unwrap();
        let reconstructed = reconstruct_leaves_from_co_path(&co_path, hidden, num_parties).unwrap();
        assert_eq!(reconstructed.len(), num_parties);
        for party in 0..num_parties {
            if party != hidden {
                assert_eq!(reconstructed[party], leaves[party], "party {party}");
            }
        }
    }

    #[test]
    fn three_party_round_trip_for_every_hidden_index() {
        for hidden in 0..3 {
            round_trip(3, hidden);
        }
    }

    #[test]
    fn other_party_counts_round_trip() {
        for parties in [2usize, 4, 5, 8] {
            for hidden in 0..parties {
                round_trip(parties, hidden);
            }
        }
    }

    #[test]
    fn deterministic_and_domain_separated_shape() {
        let a = SeedTreeV2::build([7u8; 32], 3).unwrap();
        let b = SeedTreeV2::build([7u8; 32], 3).unwrap();
        let c = SeedTreeV2::build([8u8; 32], 3).unwrap();
        assert_eq!(a, b);
        assert_ne!(a.leaf_seeds(), c.leaf_seeds());
        assert_eq!(a.co_path(0).unwrap().len(), 2);
        assert_eq!(a.co_path(1).unwrap().len(), 2);
        assert_eq!(a.co_path(2).unwrap().len(), 2);
    }

    #[test]
    fn malformed_paths_and_indices_are_errors() {
        let tree = SeedTreeV2::build([9u8; 32], 3).unwrap();
        let co_path = tree.co_path(1).unwrap();
        assert!(reconstruct_leaves_from_co_path(&co_path[..1], 1, 3).is_err());
        assert!(reconstruct_leaves_from_co_path(&co_path, 3, 3).is_err());
        let mut too_long = co_path.clone();
        too_long.push([0u8; 32]);
        assert!(reconstruct_leaves_from_co_path(&too_long, 1, 3).is_err());
        assert!(SeedTreeV2::build([0u8; 32], 0).is_err());
        assert!(SeedTreeV2::build([0u8; 32], 1).is_err());
        assert!(tree.co_path(3).is_err());
    }
}
