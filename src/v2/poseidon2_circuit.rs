//! Poseidon2 circuit gadget for v2.
//!
//! The round order, constants, matrices, domain tags, and output lane mirror
//! the native wrapper in [`crate::v2::poseidon2`]. The S-box uses exactly three
//! multiplication gates (`x2=x*x`, `x4=x2*x2`, `x5=x4*x`).

use ark_bn254::Fr;

use crate::v2::circuit::{CircuitBuilderV2, Wire};
use crate::v2::poseidon2::{self, EMPTY_LEAF_MARKER, ROUNDS, ROUNDS_F, ROUNDS_P, STATE_WIDTH};

fn sbox(builder: &mut CircuitBuilderV2, input: Wire) -> Wire {
    let squared = builder.mul(input, input);
    let fourth = builder.mul(squared, squared);
    builder.mul(fourth, input)
}

fn matmul_external(
    builder: &mut CircuitBuilderV2,
    state: [Wire; STATE_WIDTH],
) -> [Wire; STATE_WIDTH] {
    let pair = builder.add(state[0], state[1]);
    let sum = builder.add(pair, state[2]);
    let lane0 = builder.add(state[0], sum);
    let lane1 = builder.add(state[1], sum);
    let lane2 = builder.add(state[2], sum);
    [lane0, lane1, lane2]
}

fn matmul_internal(
    builder: &mut CircuitBuilderV2,
    state: [Wire; STATE_WIDTH],
) -> [Wire; STATE_WIDTH] {
    let pair = builder.add(state[0], state[1]);
    let sum = builder.add(pair, state[2]);
    let diag = &poseidon2::params().mat_internal_diag_m_1;
    let mut output = [state[0]; STATE_WIDTH];
    for lane in 0..STATE_WIDTH {
        let scaled = builder.mul_const(state[lane], diag[lane]);
        output[lane] = builder.add(scaled, sum);
    }
    output
}

/// Emit the exact pinned Poseidon2 permutation over circuit wires.
pub fn permutation_gadget(
    builder: &mut CircuitBuilderV2,
    mut state: [Wire; STATE_WIDTH],
) -> [Wire; STATE_WIDTH] {
    let params = poseidon2::params();

    state = matmul_external(builder, state);

    for round in 0..(ROUNDS_F / 2) {
        for lane in 0..STATE_WIDTH {
            state[lane] = builder.add_const(state[lane], params.round_constants[round][lane]);
        }
        for lane in 0..STATE_WIDTH {
            state[lane] = sbox(builder, state[lane]);
        }
        state = matmul_external(builder, state);
    }

    for round in (ROUNDS_F / 2)..(ROUNDS_F / 2 + ROUNDS_P) {
        state[0] = builder.add_const(state[0], params.round_constants[round][0]);
        state[0] = sbox(builder, state[0]);
        state = matmul_internal(builder, state);
    }

    for round in (ROUNDS_F / 2 + ROUNDS_P)..ROUNDS {
        for lane in 0..STATE_WIDTH {
            state[lane] = builder.add_const(state[lane], params.round_constants[round][lane]);
        }
        for lane in 0..STATE_WIDTH {
            state[lane] = sbox(builder, state[lane]);
        }
        state = matmul_external(builder, state);
    }

    state
}

/// Create a field-zero wire from an existing wire using a linear gate.
pub fn zero_wire(builder: &mut CircuitBuilderV2, seed: Wire) -> Wire {
    builder.mul_const(seed, Fr::from(0u64))
}

fn tagged_state(builder: &mut CircuitBuilderV2, zero: Wire, tag: u64, x: Wire, y: Wire) -> Wire {
    let tag_wire = builder.add_const(zero, Fr::from(tag));
    permutation_gadget(builder, [tag_wire, x, y])[0]
}

/// Circuit equivalent of native `compress(tag, x, y)`.
pub fn compress_gadget(builder: &mut CircuitBuilderV2, tag: u64, x: Wire, y: Wire) -> Wire {
    let zero = zero_wire(builder, x);
    tagged_state(builder, zero, tag, x, y)
}

/// Circuit equivalent of `hash_leaf(value)` for an embedded `u32` wire.
pub fn hash_leaf_gadget(builder: &mut CircuitBuilderV2, value: Wire) -> Wire {
    let zero = zero_wire(builder, value);
    tagged_state(builder, zero, poseidon2::TAG_LEAF, value, zero)
}

/// Circuit equivalent of `hash_empty_leaf()`.
pub fn hash_empty_leaf_gadget(builder: &mut CircuitBuilderV2, seed: Wire) -> Wire {
    let zero = zero_wire(builder, seed);
    let marker = builder.add_const(zero, Fr::from(EMPTY_LEAF_MARKER));
    tagged_state(builder, zero, poseidon2::TAG_LEAF, marker, zero)
}

/// Circuit equivalent of `hash_node(left, right)`.
pub fn hash_node_gadget(builder: &mut CircuitBuilderV2, left: Wire, right: Wire) -> Wire {
    let zero = zero_wire(builder, left);
    tagged_state(builder, zero, poseidon2::TAG_NODE, left, right)
}

/// Circuit equivalent of `hash_root(root, num_members, depth)`.
pub fn hash_root_gadget(
    builder: &mut CircuitBuilderV2,
    root: Wire,
    num_members: u32,
    depth: u32,
) -> Wire {
    let zero = zero_wire(builder, root);
    let metadata = builder.add_const(zero, Fr::from(poseidon2::root_metadata(num_members, depth)));
    tagged_state(builder, zero, poseidon2::TAG_ROOT, root, metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::circuit::{CircuitErrorV2, GateV2};
    use crate::v2::poseidon2::{
        hash_empty_leaf, hash_leaf, hash_node, hash_root, permutation, root_metadata,
    };

    fn gate_counts(circuit: &crate::v2::circuit::CircuitV2) -> (usize, usize) {
        let total = circuit.gates().len();
        let mul = circuit
            .gates()
            .iter()
            .filter(|gate| matches!(gate, GateV2::Mul { .. }))
            .count();
        (total, mul)
    }

    #[test]
    fn permutation_gadget_matches_upstream_vector_and_native() {
        let mut builder = CircuitBuilderV2::new(3);
        let outputs = permutation_gadget(&mut builder, [Wire(0), Wire(1), Wire(2)]);
        let circuit = builder.build();
        let values = circuit
            .evaluate(&[Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)])
            .unwrap();
        let native = permutation([Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)]);
        for lane in 0..STATE_WIDTH {
            assert_eq!(values[outputs[lane].index()], native[lane]);
        }
    }

    #[test]
    fn permutation_gadget_matches_native_on_edge_and_deterministic_inputs() {
        let mut inputs = vec![
            [Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)],
            [Fr::from(1u64), Fr::from(0u64), Fr::from(0u64)],
            [-Fr::from(1u64), Fr::from(0u64), Fr::from(0u64)],
            [Fr::from(u32::MAX as u64), Fr::from(0u64), Fr::from(1u64)],
        ];
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..32 {
            let mut next = || {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                Fr::from(state)
            };
            inputs.push([next(), next(), next()]);
        }

        let mut builder = CircuitBuilderV2::new(3);
        let outputs = permutation_gadget(&mut builder, [Wire(0), Wire(1), Wire(2)]);
        let circuit = builder.build();
        for input in inputs {
            let values = circuit.evaluate(&input).unwrap();
            let native = permutation(input);
            for lane in 0..STATE_WIDTH {
                assert_eq!(values[outputs[lane].index()], native[lane]);
            }
        }
    }

    #[test]
    fn hash_gadgets_match_native_framing() {
        let mut builder = CircuitBuilderV2::new(2);
        let leaf = hash_leaf_gadget(&mut builder, Wire(0));
        let empty = hash_empty_leaf_gadget(&mut builder, Wire(1));
        let node = hash_node_gadget(&mut builder, leaf, Wire(1));
        let root = hash_root_gadget(&mut builder, node, 3, 1);
        let circuit = builder.build();

        let value = Fr::from(42u64);
        let sibling = hash_leaf(7);
        let values = circuit.evaluate(&[value, sibling]).unwrap();

        assert_eq!(values[leaf.index()], hash_leaf(42));
        assert_eq!(values[empty.index()], hash_empty_leaf());
        assert_eq!(values[node.index()], hash_node(hash_leaf(42), sibling));
        assert_eq!(
            values[root.index()],
            hash_root(hash_node(hash_leaf(42), sibling), 3, 1)
        );
    }

    #[test]
    fn root_metadata_matches_native_packing() {
        let mut builder = CircuitBuilderV2::new(1);
        let root = hash_root_gadget(&mut builder, Wire(0), 5, 3);
        let circuit = builder.build();
        let value = Fr::from(99u64);
        let values = circuit.evaluate(&[value]).unwrap();
        assert_eq!(
            values[root.index()],
            hash_root(value, 5, 3),
            "metadata pack mismatch: {}",
            root_metadata(5, 3)
        );
    }

    #[test]
    fn tampered_output_or_witness_fails() {
        let mut builder = CircuitBuilderV2::new(3);
        let outputs = permutation_gadget(&mut builder, [Wire(0), Wire(1), Wire(2)]);
        builder.assert_eq(outputs[0], Fr::from(123u64));
        let circuit = builder.build();
        assert!(matches!(
            circuit.evaluate(&[Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)]),
            Err(CircuitErrorV2::UnsatisfiedAssertion { .. })
        ));

        let mut builder = CircuitBuilderV2::new(1);
        let leaf = hash_leaf_gadget(&mut builder, Wire(0));
        builder.assert_eq(leaf, hash_leaf(42));
        let circuit = builder.build();
        assert!(circuit.evaluate(&[Fr::from(42u64)]).is_ok());
        assert!(matches!(
            circuit.evaluate(&[Fr::from(43u64)]),
            Err(CircuitErrorV2::UnsatisfiedAssertion { .. })
        ));
    }

    #[test]
    fn compression_and_depth_two_path_gate_counts_are_pinned() {
        let mut builder = CircuitBuilderV2::new(2);
        let _ = compress_gadget(&mut builder, poseidon2::TAG_NODE, Wire(0), Wire(1));
        let compression = builder.build();
        assert_eq!(gate_counts(&compression), (815, 240));

        let mut builder = CircuitBuilderV2::new(2);
        let leaf = hash_leaf_gadget(&mut builder, Wire(0));
        let node0 = hash_node_gadget(&mut builder, leaf, Wire(1));
        let node1 = hash_node_gadget(&mut builder, node0, Wire(1));
        let _root = hash_root_gadget(&mut builder, node1, 3, 2);
        let path = builder.build();
        // Leaf + two internal levels + root metadata.
        assert_eq!(gate_counts(&path), (3261, 960));
    }
}
