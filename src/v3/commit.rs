//! Merkle commitment and opening support (FR25b Fig. 3, TCitH-MT side).
//!
//! Each packed share row is committed as `com_i = H(leaf payload)` and the
//! prover commits the Merkle root `h1` over all `N` rows. Opening a set `I`
//! of rows reveals the row values plus authentication paths; the verifier
//! recomputes the root. Hashing is BLAKE3 with fixed domain separators and
//! canonical big-endian field encoding (`crate::v2::field::encode_fr`).
//!
//! This module owns the tree mechanics only. What is committed per row (share
//! data, masks, randomness) is fixed by the prover/verifier in Phase 3.

use blake3::Hasher;

use crate::v2::field::encode_fr;
use crate::{MpcithError, Result};
use ark_bn254::Fr;

/// Domain separator for Merkle leaves.
pub const V3_LEAF_DOMAIN: &[u8] = b"NovaMPC-v3/leaf/v1";
/// Domain separator for internal Merkle nodes.
pub const V3_NODE_DOMAIN: &[u8] = b"NovaMPC-v3/node/v1";

/// Commit one share row: `H(domain || row_index_be || count_be || Fr... ||
/// randomness)`. `row_index` binds the leaf position; `randomness` is the
/// per-row hiding randomness (32 bytes, e.g. from the seed tree / PRG).
pub fn leaf_commit(row_index: u32, values: &[Fr], randomness: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(V3_LEAF_DOMAIN);
    h.update(&row_index.to_be_bytes());
    h.update(&(values.len() as u32).to_be_bytes());
    for v in values {
        h.update(&encode_fr(v));
    }
    h.update(randomness);
    *h.finalize().as_bytes()
}

/// Internal node: `H(domain || left || right)`.
fn node_commit(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(V3_NODE_DOMAIN);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Compute the Merkle root over `leaves`. An odd layer duplicates its last
/// node. Fails on an empty leaf set.
pub fn merkle_root(leaves: &[[u8; 32]]) -> Result<[u8; 32]> {
    if leaves.is_empty() {
        return Err(MpcithError::InvalidParams(
            "v3 merkle tree needs at least one leaf".into(),
        ));
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            next.push(node_commit(&pair[0], right));
        }
        layer = next;
    }
    Ok(layer[0])
}

/// One authentication-path step: the sibling hash and whether the sibling is
/// the left child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathStep {
    pub sibling: [u8; 32],
    pub sibling_is_left: bool,
}

/// Authentication path for `index`, from leaf layer to root.
pub fn merkle_path(leaves: &[[u8; 32]], index: usize) -> Result<Vec<PathStep>> {
    if leaves.is_empty() || index >= leaves.len() {
        return Err(MpcithError::InvalidParams(format!(
            "v3 merkle path index {index} out of {} leaves",
            leaves.len()
        )));
    }
    let mut path = Vec::new();
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;
    while layer.len() > 1 {
        let sibling_idx = if idx % 2 == 0 {
            if idx + 1 < layer.len() { idx + 1 } else { idx }
        } else {
            idx - 1
        };
        path.push(PathStep {
            sibling: layer[sibling_idx],
            sibling_is_left: idx % 2 == 1,
        });
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            next.push(node_commit(&pair[0], right));
        }
        layer = next;
        idx /= 2;
    }
    Ok(path)
}

/// Verify an authentication path against `root` for a tree of `num_leaves`.
pub fn verify_path(
    leaf: &[u8; 32],
    index: usize,
    path: &[PathStep],
    root: &[u8; 32],
    num_leaves: usize,
) -> Result<bool> {
    if num_leaves == 0 || index >= num_leaves {
        return Err(MpcithError::InvalidParams(format!(
            "v3 merkle verify index {index} out of {num_leaves} leaves"
        )));
    }
    // Path length must equal the tree height.
    let mut height = 0;
    let mut width = num_leaves;
    while width > 1 {
        width = width.div_ceil(2);
        height += 1;
    }
    if path.len() != height {
        return Ok(false);
    }
    let mut cur = *leaf;
    let mut idx = index;
    for step in path {
        cur = if step.sibling_is_left {
            if idx % 2 == 0 {
                return Ok(false);
            }
            node_commit(&step.sibling, &cur)
        } else {
            node_commit(&cur, &step.sibling)
        };
        idx /= 2;
    }
    Ok(cur == *root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let vals = [Fr::from(i as u64), Fr::from((i * 7) as u64)];
                leaf_commit(i as u32, &vals, &[i as u8; 32])
            })
            .collect()
    }

    #[test]
    fn root_and_paths_verify_for_powers_of_two_and_odd_counts() {
        for n in [1usize, 2, 3, 5, 32] {
            let leaves = test_leaves(n);
            let root = merkle_root(&leaves).unwrap();
            for i in 0..n {
                let path = merkle_path(&leaves, i).unwrap();
                assert!(verify_path(&leaves[i], i, &path, &root, n).unwrap());
            }
        }
    }

    #[test]
    fn leaf_commit_binds_index_values_and_randomness() {
        let vals = [Fr::from(1u64)];
        let a = leaf_commit(0, &vals, &[0u8; 32]);
        assert_ne!(a, leaf_commit(1, &vals, &[0u8; 32]));
        assert_ne!(a, leaf_commit(0, &[Fr::from(2u64)], &[0u8; 32]));
        assert_ne!(a, leaf_commit(0, &vals, &[1u8; 32]));
        assert_eq!(a, leaf_commit(0, &vals, &[0u8; 32]));
    }

    #[test]
    fn tampered_leaf_sibling_index_or_root_fails() {
        let leaves = test_leaves(8);
        let root = merkle_root(&leaves).unwrap();
        let path = merkle_path(&leaves, 3).unwrap();
        // Wrong leaf.
        let mut bad_leaf = leaves[3];
        bad_leaf[0] ^= 1;
        assert!(!verify_path(&bad_leaf, 3, &path, &root, 8).unwrap());
        // Wrong index.
        assert!(!verify_path(&leaves[3], 4, &path, &root, 8).unwrap());
        // Flipped sibling side.
        let mut bad_path = path.clone();
        bad_path[0].sibling_is_left = !bad_path[0].sibling_is_left;
        assert!(!verify_path(&leaves[3], 3, &bad_path, &root, 8).unwrap());
        // Wrong root.
        let mut bad_root = root;
        bad_root[0] ^= 1;
        assert!(!verify_path(&leaves[3], 3, &path, &bad_root, 8).unwrap());
        // Truncated path.
        assert!(!verify_path(&leaves[3], 3, &path[..path.len() - 1], &root, 8).unwrap());
    }

    #[test]
    fn bad_inputs_are_rejected() {
        assert!(merkle_root(&[]).is_err());
        let leaves = test_leaves(4);
        assert!(merkle_path(&leaves, 4).is_err());
        assert!(merkle_path(&[], 0).is_err());
        assert!(verify_path(&leaves[0], 4, &[], &[0u8; 32], 4).is_err());
    }
}
