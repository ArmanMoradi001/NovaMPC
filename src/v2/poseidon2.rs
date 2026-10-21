//! Native Poseidon2 hash wrapper for the v2 BN254 membership path.
//!
//! The permutation is the Horizen Labs BN254 instance pinned in
//! `V2_DESIGN.md`; the tagged compression framing around it is the NovaMPC v2
//! protocol framing, not an upstream-defined set hash.

mod poseidon2_constants;

use std::sync::LazyLock;

use ark_bn254::Fr;

use crate::v2::field::{decode_fr, encode_fr, fr_from_u32, FieldEncodingError};

use self::poseidon2_constants::{MAT_DIAG3_M_1_HEX, RC3_HEX};

/// State width of the pinned Poseidon2 BN254 instance.
pub const STATE_WIDTH: usize = 3;
/// Number of full rounds (4 at the start and 4 at the end).
pub const ROUNDS_F: usize = 8;
/// Number of partial rounds.
pub const ROUNDS_P: usize = 56;
/// Total rounds.
pub const ROUNDS: usize = ROUNDS_F + ROUNDS_P;

/// Fixed v2 domain tag for leaf hashing.
pub const TAG_LEAF: u64 = 1;
/// Fixed v2 domain tag for internal-node hashing.
pub const TAG_NODE: u64 = 2;
/// Fixed v2 domain tag for root-metadata hashing.
pub const TAG_ROOT: u64 = 3;

/// Reserved leaf input that cannot be produced by embedding a `u32` member.
pub const EMPTY_LEAF_MARKER: u64 = 1u64 << 32;

/// Parsed, immutable Poseidon2 parameters.
pub struct Poseidon2Params {
    /// Upstream `MAT_DIAG3_M_1`.
    pub mat_internal_diag_m_1: [Fr; STATE_WIDTH],
    /// Upstream `RC3` round constants.
    pub round_constants: [[Fr; STATE_WIDTH]; ROUNDS],
}

impl Poseidon2Params {
    fn from_upstream_hex() -> Self {
        let mut diag = [Fr::from(0u64); STATE_WIDTH];
        for (dst, src) in diag.iter_mut().zip(MAT_DIAG3_M_1_HEX.iter()) {
            *dst = parse_upstream_hex(src);
        }

        let mut round_constants = [[Fr::from(0u64); STATE_WIDTH]; ROUNDS];
        for (dst_row, src_row) in round_constants.iter_mut().zip(RC3_HEX.iter()) {
            for (dst, src) in dst_row.iter_mut().zip(src_row.iter()) {
                *dst = parse_upstream_hex(src);
            }
        }

        Self {
            mat_internal_diag_m_1: diag,
            round_constants,
        }
    }
}

fn parse_upstream_hex(value: &str) -> Fr {
    let bytes = hex::decode(
        value
            .strip_prefix("0x")
            .expect("upstream Poseidon2 constant must have 0x prefix"),
    )
    .expect("upstream Poseidon2 constant must be valid hex");
    decode_fr(&bytes).expect("upstream Poseidon2 constant must be canonical BN254 Fr")
}

/// Return the pinned parameter set.
pub fn params() -> &'static Poseidon2Params {
    static PARAMS: LazyLock<Poseidon2Params> = LazyLock::new(Poseidon2Params::from_upstream_hex);
    &PARAMS
}

fn sbox(value: Fr) -> Fr {
    let squared = value * value;
    squared * squared * value
}

fn add_round_constants(state: &mut [Fr; STATE_WIDTH], round: usize) {
    let constants = &params().round_constants[round];
    for (lane, constant) in state.iter_mut().zip(constants.iter()) {
        *lane += *constant;
    }
}

fn apply_sbox_all(state: &mut [Fr; STATE_WIDTH]) {
    for lane in state.iter_mut() {
        *lane = sbox(*lane);
    }
}

fn matmul_external(state: &mut [Fr; STATE_WIDTH]) {
    // circ(2, 1, 1): every lane becomes lane + sum(state).
    let sum = state[0] + state[1] + state[2];
    for lane in state.iter_mut() {
        *lane += sum;
    }
}

fn matmul_internal(state: &mut [Fr; STATE_WIDTH]) {
    let sum = state[0] + state[1] + state[2];
    let diag = &params().mat_internal_diag_m_1;
    for (lane, diagonal) in state.iter_mut().zip(diag.iter()) {
        *lane = (*lane * *diagonal) + sum;
    }
}

/// Apply the exact pinned Poseidon2 BN254 permutation to a 3-lane state.
pub fn permutation(mut state: [Fr; STATE_WIDTH]) -> [Fr; STATE_WIDTH] {
    // Initial external matrix.
    matmul_external(&mut state);

    // First four full rounds.
    for round in 0..(ROUNDS_F / 2) {
        add_round_constants(&mut state, round);
        apply_sbox_all(&mut state);
        matmul_external(&mut state);
    }

    // 56 partial rounds.
    for round in (ROUNDS_F / 2)..(ROUNDS_F / 2 + ROUNDS_P) {
        state[0] += params().round_constants[round][0];
        state[0] = sbox(state[0]);
        matmul_internal(&mut state);
    }

    // Final four full rounds, with no terminal matrix.
    for round in (ROUNDS_F / 2 + ROUNDS_P)..ROUNDS {
        add_round_constants(&mut state, round);
        apply_sbox_all(&mut state);
        matmul_external(&mut state);
    }

    state
}

/// Fixed-width tagged compression around the pinned permutation.
pub fn compress(tag: u64, x: Fr, y: Fr) -> Fr {
    permutation([Fr::from(tag), x, y])[0]
}

/// Hash one embedded `u32` member.
pub fn hash_leaf(value: u32) -> Fr {
    compress(TAG_LEAF, fr_from_u32(value), Fr::from(0u64))
}

/// Domain-separated leaf used for padding slots.
///
/// The reserved marker `2^32` is not the embedding of any `u32`, so an empty
/// slot cannot collide with a real member at the leaf-encoding layer.
pub fn hash_empty_leaf() -> Fr {
    compress(TAG_LEAF, Fr::from(EMPTY_LEAF_MARKER), Fr::from(0u64))
}

/// Hash an ordered pair of child nodes.
pub fn hash_node(left: Fr, right: Fr) -> Fr {
    compress(TAG_NODE, left, right)
}

/// Pack the root metadata exactly as `(depth << 32) | num_members`.
///
/// Both inputs are `u32`, so the packed value is unambiguous. Shared by the
/// native and circuit paths so the framing cannot drift between them.
pub fn root_metadata(num_members: u32, depth: u32) -> u64 {
    ((depth as u64) << 32) | (num_members as u64)
}

/// Bind a Merkle root to the number of real members and tree depth.
pub fn hash_root(root: Fr, num_members: u32, depth: u32) -> Fr {
    compress(TAG_ROOT, root, Fr::from(root_metadata(num_members, depth)))
}

/// Canonical 32-byte encoding of a v2 hash output.
pub fn encode_hash(value: &Fr) -> [u8; 32] {
    encode_fr(value)
}

/// Strict canonical decoding of a v2 hash output.
pub fn decode_hash(bytes: &[u8]) -> Result<Fr, FieldEncodingError> {
    decode_fr(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fr_hex(value: &str) -> Fr {
        parse_upstream_hex(value)
    }

    #[test]
    fn upstream_bn254_known_answer_vector_matches() {
        let output = permutation([Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)]);
        assert_eq!(
            output[0],
            fr_hex("0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033")
        );
        assert_eq!(
            output[1],
            fr_hex("0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570")
        );
        assert_eq!(
            output[2],
            fr_hex("0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8")
        );
    }

    #[test]
    fn constant_shape_is_pinned() {
        let params = params();
        assert_eq!(params.round_constants.len(), 64);
        assert_eq!(
            params.mat_internal_diag_m_1,
            [Fr::from(1u64), Fr::from(1u64), Fr::from(2u64)]
        );
        // First and last upstream RC3 rows are non-zero sentinels that catch a
        // truncated or shifted table.
        assert_eq!(
            params.round_constants[0][0],
            fr_hex("0x1d066a255517b7fd8bddd3a93f7804ef7f8fcde48bb4c37a59a09a1a97052816")
        );
        assert_eq!(
            params.round_constants[63][2],
            fr_hex("0x0fc1bbceba0590f5abbdffa6d3b35e3297c021a3a409926d0e2d54dc1c84fda6")
        );
    }

    #[test]
    fn permutation_is_deterministic_and_input_sensitive() {
        let a = permutation([Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
        assert_eq!(
            a,
            permutation([Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)])
        );
        assert_ne!(
            a,
            permutation([Fr::from(1u64), Fr::from(3u64), Fr::from(2u64)])
        );
        assert_ne!(
            a,
            permutation([Fr::from(2u64), Fr::from(2u64), Fr::from(3u64)])
        );
    }

    #[test]
    fn tags_separate_leaf_node_and_root_uses() {
        let leaf = hash_leaf(7);
        let node_with_same_lanes = hash_node(Fr::from(7u64), Fr::from(0u64));
        assert_ne!(leaf, node_with_same_lanes);
        assert_ne!(hash_root(leaf, 1, 0), leaf);
    }

    #[test]
    fn node_hash_preserves_order() {
        let left = hash_leaf(1);
        let right = hash_leaf(2);
        assert_ne!(hash_node(left, right), hash_node(right, left));
    }

    #[test]
    fn root_binds_count_and_depth() {
        let root = hash_node(hash_leaf(1), hash_leaf(2));
        let base = hash_root(root, 2, 1);
        assert_ne!(base, hash_root(root, 3, 1));
        assert_ne!(base, hash_root(root, 2, 2));
        assert_ne!(base, hash_root(hash_node(root, root), 2, 1));
    }

    #[test]
    fn empty_leaf_is_distinct_from_real_leaves() {
        let empty = hash_empty_leaf();
        for value in [0u32, 1, u32::MAX] {
            assert_ne!(empty, hash_leaf(value));
        }
    }

    #[test]
    fn framing_vectors_are_stable() {
        assert_eq!(
            hex::encode(encode_hash(&hash_leaf(0))),
            "063c4e8cac9a858304f0035b069255b069288c2af698ececf362cd8ec8c96665"
        );
        assert_eq!(
            hex::encode(encode_hash(&hash_leaf(1))),
            "277530b5f2b87dfe4535f43bb1998eda77736b4b05d15d983503566743c88031"
        );
        assert_eq!(
            hex::encode(encode_hash(&hash_empty_leaf())),
            "28f84666849cd98f73f7daddabe8fc711eb9feb71321b216aba8833908020ad7"
        );
        assert_eq!(
            hex::encode(encode_hash(&hash_node(hash_leaf(0), hash_leaf(1)))),
            "130dd76f9b995f771b514a5fbf1c40ab17e38f0cb1fc436d57f15cfb9f7cf99f"
        );
        assert_eq!(
            hex::encode(encode_hash(&hash_root(
                hash_node(hash_leaf(0), hash_leaf(1)),
                2,
                1
            ))),
            "07a5d9356258c294fe58c9d29055c7728a2f587e53ade66cb39396affd61089c"
        );
    }

    #[test]
    fn canonical_hash_encoding_round_trips() {
        let digest = hash_node(hash_leaf(10), hash_leaf(20));
        let bytes = encode_hash(&digest);
        assert_eq!(bytes.len(), 32);
        assert_eq!(decode_hash(&bytes).unwrap(), digest);
        assert_eq!(encode_hash(&digest), bytes);
    }
}
