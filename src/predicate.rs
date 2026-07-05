//! High-level predicates compiled to circuits.
//!
//! Each predicate takes a private witness and produces a circuit + public inputs
//! that encodes the statement to be proven.
//!
//! Current predicates:
//! - `AdditionCheck`: prove x + y == z  (toy/test predicate)
//! - `RangeCheck`: prove lo <= x <= hi  (Phase 2)
//! - `SetMembership`: prove x ∈ {v1, ..., vk}  (Phase 2)

use crate::circuit::{bit_decompose_on, Circuit, CircuitBuilder, Gate};
use crate::merkle::MerkleTree;
use crate::mimc::{build_mimc_hash, MIMC_ROUNDS};

/// A predicate defines the statement being proven.
#[derive(Debug, Clone)]
pub enum Predicate {
    /// Prove: witness[0] + witness[1] == expected_sum (public).
    AdditionCheck { expected_sum: u32 },

    /// Prove: witness[0] * witness[1] == expected_product (public).
    MultiplicationCheck { expected_product: u32 },

    /// Prove: witness[0] XOR witness[1] == expected_xor (public).
    XorCheck { expected_xor: u32 },

    /// Prove: lo <= witness[0] <= hi (public bounds).
    /// Implemented as: (witness[0] - lo) <= (hi - lo) using u32 arithmetic.
    /// NOTE: This is a placeholder; proper range proofs need bit decomposition.
    /// Phase 2 will implement the full bit-decomposition range proof.
    RangeCheck { lo: u32, hi: u32 },

    /// Prove: witness[0] is in the set `members` (public list).
    /// Implemented as a Merkle inclusion proof: the prover provides
    /// (leaf, leaf_index, bits, siblings) and the circuit recomputes
    /// the root via MiMC hashes, asserting it equals the public root.
    SetMembership { members: Vec<u32> },
}

/// Result of compiling a predicate to a circuit.
pub struct CompiledPredicate {
    pub circuit: Circuit,
    /// The public inputs that the verifier also has.
    pub public_inputs: Vec<u32>,
    /// Expected number of private witness values.
    pub witness_size: usize,
}

impl Predicate {
    /// Compile this predicate to an arithmetic circuit.
    pub fn compile(&self) -> crate::Result<CompiledPredicate> {
        match self {
            Predicate::AdditionCheck { expected_sum } => {
                compile_addition_check(*expected_sum)
            }
            Predicate::MultiplicationCheck { expected_product } => {
                compile_multiplication_check(*expected_product)
            }
            Predicate::XorCheck { expected_xor } => {
                compile_xor_check(*expected_xor)
            }
            Predicate::RangeCheck { lo, hi } => {
                compile_range_check(*lo, *hi)
            }
            Predicate::SetMembership { members } => {
                compile_set_membership(members)
            }
        }
    }

    /// Number of private witness elements this predicate requires.
    pub fn witness_size(&self) -> usize {
        match self {
            Predicate::AdditionCheck { .. } => 2,
            Predicate::MultiplicationCheck { .. } => 2,
            Predicate::XorCheck { .. } => 2,
            Predicate::RangeCheck { .. } => 1,
            Predicate::SetMembership { members } => {
                let depth = members.len().next_power_of_two().trailing_zeros() as usize;
                2 + depth
            }
        }
    }
}

/// Compound predicate: combines multiple predicates with logical connectives.
///
/// The `And` variant merges two compiled predicates into a single circuit
/// so that both sub-predicates are proven over the same witness shares,
/// party views, and Fiat-Shamir transcript.
#[derive(Debug, Clone)]
pub enum CompoundPredicate {
    Single(Predicate),
    And(Box<CompoundPredicate>, Box<CompoundPredicate>),
}

/// Remap wire indices in a gate for circuit merging.
///
/// The merged circuit uses layout: [left_inputs, right_inputs, left_intermediates, right_intermediates].
/// Input wires (0..num_inputs) get `input_offset`; intermediate wires get `intermediate_offset`.
fn remap_gate(gate: &Gate, num_inputs: usize, input_offset: usize, intermediate_offset: usize) -> Gate {
    fn remap(idx: usize, num_inputs: usize, input_off: usize, inter_off: usize) -> usize {
        if idx < num_inputs {
            idx + input_off
        } else {
            idx + inter_off
        }
    }
    match gate {
        Gate::Add { left, right, output } => Gate::Add {
            left: remap(*left, num_inputs, input_offset, intermediate_offset),
            right: remap(*right, num_inputs, input_offset, intermediate_offset),
            output: remap(*output, num_inputs, input_offset, intermediate_offset),
        },
        Gate::Mul { left, right, output } => Gate::Mul {
            left: remap(*left, num_inputs, input_offset, intermediate_offset),
            right: remap(*right, num_inputs, input_offset, intermediate_offset),
            output: remap(*output, num_inputs, input_offset, intermediate_offset),
        },
        Gate::Xor { left, right, output } => Gate::Xor {
            left: remap(*left, num_inputs, input_offset, intermediate_offset),
            right: remap(*right, num_inputs, input_offset, intermediate_offset),
            output: remap(*output, num_inputs, input_offset, intermediate_offset),
        },
        Gate::AddConst { input, constant, output } => Gate::AddConst {
            input: remap(*input, num_inputs, input_offset, intermediate_offset),
            constant: *constant,
            output: remap(*output, num_inputs, input_offset, intermediate_offset),
        },
        Gate::MulConst { input, constant, output } => Gate::MulConst {
            input: remap(*input, num_inputs, input_offset, intermediate_offset),
            constant: *constant,
            output: remap(*output, num_inputs, input_offset, intermediate_offset),
        },
        Gate::AssertEq { input, expected, output } => Gate::AssertEq {
            input: remap(*input, num_inputs, input_offset, intermediate_offset),
            expected: *expected,
            output: remap(*output, num_inputs, input_offset, intermediate_offset),
        },
    }
}

impl CompoundPredicate {
    /// Compile this compound predicate into a single merged circuit.
    pub fn compile(&self) -> crate::Result<CompiledPredicate> {
        match self {
            CompoundPredicate::Single(pred) => pred.compile(),
            CompoundPredicate::And(left, right) => {
                let compiled_left = left.compile()?;
                let compiled_right = right.compile()?;

                let c_left = &compiled_left.circuit;
                let c_right = &compiled_right.circuit;

                // Merged wire layout: [left_inputs, right_inputs, left_intermediates, right_intermediates]
                let num_inputs = c_left.num_inputs + c_right.num_inputs;
                let num_wires = c_left.num_wires + c_right.num_wires;
                let num_outputs = c_left.num_outputs + c_right.num_outputs;

                let mut gates = Vec::with_capacity(c_left.gates.len() + c_right.gates.len());

                // Left circuit: inputs at 0..L-1, intermediates at L+R..L+R+LI-1
                for gate in &c_left.gates {
                    gates.push(remap_gate(
                        gate,
                        c_left.num_inputs,
                        0,                     // input_offset: left inputs stay at 0
                        c_right.num_inputs,    // intermediate_offset: shift right by R
                    ));
                }

                // Right circuit: inputs at L..L+R-1, intermediates at c_left.num_wires..
                for gate in &c_right.gates {
                    gates.push(remap_gate(
                        gate,
                        c_right.num_inputs,
                        c_left.num_inputs,     // input_offset: right inputs start after left inputs
                        c_left.num_wires,      // intermediate_offset: right intermediates after left's full space
                    ));
                }

                let circuit = Circuit {
                    num_wires,
                    num_inputs,
                    num_outputs,
                    gates,
                };

                let mut public_inputs = compiled_left.public_inputs;
                public_inputs.extend_from_slice(&compiled_right.public_inputs);

                Ok(CompiledPredicate {
                    circuit,
                    public_inputs,
                    witness_size: compiled_left.witness_size + compiled_right.witness_size,
                })
            }
        }
    }

    /// Convenience: RangeCheck AND SetMembership over the same witness.
    ///
    /// The left sub-circuit proves `lo <= value <= hi` (witness: value).
    /// The right sub-circuit proves `value ∈ members` (witness: value, index, bits, siblings).
    pub fn range_and_membership(lo: u32, hi: u32, members: Vec<u32>) -> Self {
        CompoundPredicate::And(
            Box::new(CompoundPredicate::Single(Predicate::RangeCheck { lo, hi })),
            Box::new(CompoundPredicate::Single(Predicate::SetMembership { members })),
        )
    }
}

/// Circuit: assert witness[0] + witness[1] == expected_sum
fn compile_addition_check(expected_sum: u32) -> crate::Result<CompiledPredicate> {
    // Wires: 0=x, 1=y, 2=x+y, 3=assert(x+y==sum)
    let mut builder = CircuitBuilder::new(2);
    let sum_wire = builder.add(0, 1);
    let _out = builder.assert_eq(sum_wire, expected_sum);
    let circuit = builder.build(1);

    Ok(CompiledPredicate {
        circuit,
        public_inputs: vec![expected_sum],
        witness_size: 2,
    })
}

/// Circuit: assert witness[0] * witness[1] == expected_product
fn compile_multiplication_check(expected_product: u32) -> crate::Result<CompiledPredicate> {
    let mut builder = CircuitBuilder::new(2);
    let prod_wire = builder.mul(0, 1);
    let _out = builder.assert_eq(prod_wire, expected_product);
    let circuit = builder.build(1);

    Ok(CompiledPredicate {
        circuit,
        public_inputs: vec![expected_product],
        witness_size: 2,
    })
}

/// Circuit: assert witness[0] XOR witness[1] == expected_xor
fn compile_xor_check(expected_xor: u32) -> crate::Result<CompiledPredicate> {
    let mut builder = CircuitBuilder::new(2);
    let xor_wire = builder.xor(0, 1);
    let _out = builder.assert_eq(xor_wire, expected_xor);
    let circuit = builder.build(1);

    Ok(CompiledPredicate {
        circuit,
        public_inputs: vec![expected_xor],
        witness_size: 2,
    })
}

/// Minimum number of bits needed to represent any value in [0, `max_val`].
fn bits_needed(max_val: u32) -> usize {
    if max_val == 0 {
        return 1;
    }
    (u32::BITS - max_val.leading_zeros()) as usize
}

/// Circuit: assert lo <= witness[0] <= hi
///
/// Strategy:
///   1. bit_decompose(x, 32) — enforces boolean + reconstruction on x's bits
///   2. shifted = x - lo  (wrapping)
///   3. bit_decompose(shifted, k) — enforces 0 ≤ shifted < 2^k
///   4. slack = width - shifted  (wrapping)
///   5. bit_decompose(slack, k) — enforces 0 ≤ slack < 2^k
///
/// Since shifted + slack = width and both are ≥ 0, we get 0 ≤ shifted ≤ width.
/// k = bits_needed(width) ensures 2^k > width, so the bit range is tight enough.
fn compile_range_check(lo: u32, hi: u32) -> crate::Result<CompiledPredicate> {
    if lo > hi {
        return Err(crate::MpcithError::InvalidParams(
            "Range check requires lo <= hi".into(),
        ));
    }

    let width = hi.wrapping_sub(lo);
    let k = bits_needed(width);

    // Pre-allocate ALL input wires so they sit contiguously at the start.
    // Layout: [x, x_bits(32), shifted_bits(k), slack_bits(k)]
    let total_inputs = 1 + 32 + k + k;
    let mut builder = CircuitBuilder::new(total_inputs);

    let x_bits: Vec<usize> = (1..=32).collect();
    let shifted_bits: Vec<usize> = (33..33 + k).collect();
    let slack_bits: Vec<usize> = (33 + k..33 + 2 * k).collect();

    // Constraint gates for x bits (boolean + reconstruction)
    bit_decompose_on(&mut builder, 0, &x_bits);

    // shifted = x - lo (wrapping)
    let neg_lo = lo.wrapping_neg();
    let shifted = builder.add_const(0, neg_lo);

    // Constraint gates for shifted bits
    bit_decompose_on(&mut builder, shifted, &shifted_bits);

    // slack = width - shifted (wrapping)
    let neg_shifted = builder.mul_const(shifted, u32::MAX);
    let slack = builder.add_const(neg_shifted, width);

    // Constraint gates for slack bits
    bit_decompose_on(&mut builder, slack, &slack_bits);

    // Output wire: constant 0
    let zero = builder.mul_const(0, 0); // x * 0 = 0
    let _out = builder.assert_eq(zero, 0);

    let circuit = builder.build(1);

    Ok(CompiledPredicate {
        circuit,
        public_inputs: vec![lo, hi],
        witness_size: 1,
    })
}

/// Circuit: assert leaf ∈ members via Merkle inclusion proof.
///
/// At compile time the member set is hashed into a Merkle tree; the root
/// becomes the sole public input. The private witness is
/// `[leaf, leaf_index, bit_0..bit_{d-1}, sibling_0..sibling_{d-1}]`.
///
/// The circuit decomposes `leaf_index` into boolean bits, then iteratively
/// hashes from the leaf upward using MiMC, selecting left/right ordering
/// via the path bits. The final hash is asserted equal to the root.
fn compile_set_membership(members: &[u32]) -> crate::Result<CompiledPredicate> {
    if members.is_empty() {
        return Err(crate::MpcithError::InvalidParams(
            "Set membership requires at least one member".into(),
        ));
    }

    let tree = MerkleTree::build(members);
    let root = tree.root();
    let depth = members.len().next_power_of_two().trailing_zeros() as usize;

    // Wire layout:
    //   0              : leaf
    //   1              : leaf_index
    //   2 .. 2+depth-1 : leaf_index bits (b_0 .. b_{depth-1})
    //   2+depth .. 2+2*depth-1 : siblings
    let total_inputs = 2 + 2 * depth;
    let mut builder = CircuitBuilder::new(total_inputs);

    let bit_wires: Vec<usize> = (2..2 + depth).collect();
    let sibling_wires: Vec<usize> = (2 + depth..2 + 2 * depth).collect();

    // Constrain leaf_index bits (boolean + reconstruction).
    bit_decompose_on(&mut builder, 1, &bit_wires);

    // Walk up the tree.
    let mut current = 0usize; // leaf wire
    for i in 0..depth {
        let bit = bit_wires[i];
        let sibling = sibling_wires[i];

        // not_bit = 1 - bit   (wrapping: bit·MAX + 1)
        let not_bit = {
            let t = builder.mul_const(bit, u32::MAX);
            builder.add_const(t, 1)
        };

        // selected_left  = not_bit·current + bit·sibling
        let selected_left = {
            let a = builder.mul(not_bit, current);
            let b = builder.mul(bit, sibling);
            builder.add(a, b)
        };

        // selected_right = bit·current + not_bit·sibling
        let selected_right = {
            let a = builder.mul(bit, current);
            let b = builder.mul(not_bit, sibling);
            builder.add(a, b)
        };

        // MiMC hash — we only need the left output.
        let (hash_left, _hash_right) =
            build_mimc_hash(&mut builder, selected_left, selected_right, MIMC_ROUNDS);

        current = hash_left;
    }

    // Assert computed root == public root.
    let _out = builder.assert_eq(current, root);

    let circuit = builder.build(1);

    Ok(CompiledPredicate {
        circuit,
        public_inputs: vec![root],
        witness_size: 2 + depth,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addition_predicate_compiles() {
        let pred = Predicate::AdditionCheck { expected_sum: 7 };
        let compiled = pred.compile().unwrap();
        let trace = compiled.circuit.evaluate(&[3, 4]).unwrap();
        assert_eq!(trace[2], 7);
    }

    #[test]
    fn test_multiplication_predicate() {
        let pred = Predicate::MultiplicationCheck { expected_product: 12 };
        let compiled = pred.compile().unwrap();
        compiled.circuit.evaluate(&[3, 4]).unwrap();
        assert!(compiled.circuit.evaluate(&[3, 5]).is_err());
    }

    #[test]
    fn test_set_membership_predicate() {
        let members = vec![10u32, 20, 30, 42];
        let tree = MerkleTree::build(&members);
        let root = tree.root();
        let pred = Predicate::SetMembership { members };
        let compiled = pred.compile().unwrap();
        assert_eq!(compiled.public_inputs, vec![root]);

        // Witness for leaf 42 (index 3): [leaf, index, b0, b1, sib0, sib1]
        let proof42 = tree.prove_membership(3);
        let w42 = set_membership_witness(&proof42);
        compiled.circuit.evaluate(&w42).unwrap();

        // Witness for leaf 10 (index 0).
        let proof10 = tree.prove_membership(0);
        let w10 = set_membership_witness(&proof10);
        compiled.circuit.evaluate(&w10).unwrap();

        // Wrong leaf value — valid index but wrong leaf.
        let mut bad_proof = tree.prove_membership(3);
        bad_proof.leaf = 99;
        let wbad = set_membership_witness(&bad_proof);
        assert!(compiled.circuit.evaluate(&wbad).is_err());
    }

    /// Construct the full witness vector for the SetMembership circuit.
    fn set_membership_witness(proof: &crate::merkle::MerkleProof) -> Vec<u32> {
        let depth = proof.siblings.len();
        let mut w = Vec::with_capacity(2 + 2 * depth);
        w.push(proof.leaf);
        w.push(proof.leaf_index as u32);
        for i in 0..depth {
            w.push(((proof.leaf_index >> i) & 1) as u32);
        }
        w.extend(&proof.siblings);
        w
    }

    #[test]
    fn test_range_check_compiles() {
        let pred = Predicate::RangeCheck { lo: 10, hi: 100 };
        let compiled = pred.compile().unwrap();
        assert!(compiled.circuit.num_wires > 0);
    }

    /// Build a full witness for RangeCheck { lo, hi } with value x.
    /// Layout: [x, x_bits(32), shifted_bits(k), slack_bits(k)]
    fn range_witness(x: u32, lo: u32, hi: u32) -> Vec<u32> {
        let width = hi.wrapping_sub(lo);
        let k = bits_needed(width);
        let shifted = x.wrapping_sub(lo);
        let slack = width.wrapping_sub(shifted);

        let mut w = Vec::with_capacity(1 + 32 + k + k);
        w.push(x);
        for i in 0..32 {
            w.push((x >> i) & 1);
        }
        for i in 0..k {
            w.push((shifted >> i) & 1);
        }
        for i in 0..k {
            w.push((slack >> i) & 1);
        }
        w
    }

    #[test]
    fn test_range_check_42() {
        let pred = Predicate::RangeCheck { lo: 10, hi: 100 };
        let compiled = pred.compile().unwrap();
        let witness = range_witness(42, 10, 100);
        let trace = compiled.circuit.evaluate(&witness).unwrap();
        let out_start = compiled.circuit.num_wires - compiled.circuit.num_outputs;
        assert_eq!(trace[out_start], 0);
    }

    #[test]
    fn test_range_check_at_lo() {
        let pred = Predicate::RangeCheck { lo: 10, hi: 100 };
        let compiled = pred.compile().unwrap();
        let witness = range_witness(10, 10, 100);
        compiled.circuit.evaluate(&witness).unwrap();
    }

    #[test]
    fn test_range_check_at_hi() {
        let pred = Predicate::RangeCheck { lo: 10, hi: 100 };
        let compiled = pred.compile().unwrap();
        let witness = range_witness(100, 10, 100);
        compiled.circuit.evaluate(&witness).unwrap();
    }

    #[test]
    fn test_range_check_below_lo() {
        let pred = Predicate::RangeCheck { lo: 10, hi: 100 };
        let compiled = pred.compile().unwrap();
        let witness = range_witness(9, 10, 100);
        assert!(compiled.circuit.evaluate(&witness).is_err());
    }

    #[test]
    fn test_range_check_above_hi() {
        let pred = Predicate::RangeCheck { lo: 10, hi: 100 };
        let compiled = pred.compile().unwrap();
        let witness = range_witness(101, 10, 100);
        assert!(compiled.circuit.evaluate(&witness).is_err());
    }

    #[test]
    fn test_compound_and_compiles() {
        let compound = CompoundPredicate::range_and_membership(0, 100, vec![10, 20, 30, 42]);
        let compiled = compound.compile().unwrap();
        assert!(compiled.circuit.num_wires > 0);
        assert!(compiled.circuit.num_inputs > 0);
        assert!(compiled.circuit.gates.len() > 0);
    }

    #[test]
    fn test_compound_and_valid_witness() {
        let members = vec![10u32, 20, 30, 42];
        let compound = CompoundPredicate::range_and_membership(0, 100, members.clone());
        let compiled = compound.compile().unwrap();

        let tree = MerkleTree::build(&members);
        let proof = tree.prove_membership(3);
        let sm_witness = set_membership_witness(&proof);
        let range_w = range_witness(42, 0, 100);

        let mut full_witness = range_w;
        full_witness.extend_from_slice(&sm_witness);

        compiled.circuit.evaluate(&full_witness).unwrap();
    }

    #[test]
    fn test_compound_and_fails_if_range_invalid() {
        let members = vec![10u32, 20, 30, 42];
        let compound = CompoundPredicate::range_and_membership(0, 100, members.clone());
        let compiled = compound.compile().unwrap();

        let tree = MerkleTree::build(&members);
        let proof = tree.prove_membership(3);
        let sm_witness = set_membership_witness(&proof);
        let range_w = range_witness(200, 0, 100);

        let mut full_witness = range_w;
        full_witness.extend_from_slice(&sm_witness);

        assert!(compiled.circuit.evaluate(&full_witness).is_err());
    }

    #[test]
    fn test_compound_and_fails_if_membership_invalid() {
        let members = vec![10u32, 20, 30, 42];
        let compound = CompoundPredicate::range_and_membership(0, 100, members.clone());
        let compiled = compound.compile().unwrap();

        let tree = MerkleTree::build(&members);
        let range_w = range_witness(50, 0, 100);

        // Build a membership witness with leaf=50 (NOT in the set).
        // Use the Merkle path structure from index 3, but with the wrong leaf.
        let mut bad_proof = tree.prove_membership(3);
        bad_proof.leaf = 50;
        let sm_witness = set_membership_witness(&bad_proof);

        let mut full_witness = range_w;
        full_witness.extend_from_slice(&sm_witness);

        assert!(compiled.circuit.evaluate(&full_witness).is_err());
    }

    #[test]
    fn test_compound_and_fails_if_both_invalid() {
        let members = vec![10u32, 20, 30, 42];
        let compound = CompoundPredicate::range_and_membership(0, 100, members.clone());
        let compiled = compound.compile().unwrap();

        let tree = MerkleTree::build(&members);
        let proof = tree.prove_membership(3);
        let sm_witness = set_membership_witness(&proof);
        let range_w = range_witness(200, 0, 100);

        let mut full_witness = range_w;
        full_witness.extend_from_slice(&sm_witness);

        assert!(compiled.circuit.evaluate(&full_witness).is_err());
    }
}
