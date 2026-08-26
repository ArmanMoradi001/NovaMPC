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
            Predicate::AdditionCheck { expected_sum } => compile_addition_check(*expected_sum),
            Predicate::MultiplicationCheck { expected_product } => {
                compile_multiplication_check(*expected_product)
            }
            Predicate::XorCheck { expected_xor } => compile_xor_check(*expected_xor),
            Predicate::RangeCheck { lo, hi } => compile_range_check(*lo, *hi),
            Predicate::SetMembership { members } => compile_set_membership(members),
        }
    }

    /// Generate the full private witness vector for a given secret value.
    ///
    /// For `RangeCheck`: returns `[x, x_bits(32), shifted_bits(k), slack_bits(k)]`.
    /// For `SetMembership`: returns `[leaf, leaf_index, bits, siblings]`.
    /// Other variants return an error (use `prove()` with an explicit witness).
    pub fn generate_witness(&self, secret_value: u32) -> crate::Result<Vec<u32>> {
        match self {
            Predicate::RangeCheck { lo, hi } => Ok(range_witness_vec(secret_value, *lo, *hi)),
            Predicate::SetMembership { members } => {
                let idx = members
                    .iter()
                    .position(|&m| m == secret_value)
                    .ok_or_else(|| {
                        crate::MpcithError::InvalidWitness(format!(
                            "Value {secret_value} is not in the member set"
                        ))
                    })?;
                let tree = MerkleTree::build(members);
                let proof = tree.prove_membership(idx);
                Ok(set_membership_witness_vec(&proof))
            }
            _ => Err(crate::MpcithError::InvalidParams(format!(
                "generate_witness is not supported for this predicate variant"
            ))),
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
/// The `And` variant merges two compiled predicates into a single circuit so
/// that both sub-predicates are proven over the SAME primary witness value:
/// the merged circuit contains an explicit equality link
/// `left_input_0 == right_input_0 (mod 2^32)` (see
/// [`CompoundPredicate::merge_same_witness_circuits`]), enforced by the MPC
/// verification path like any other assertion. This matches
/// [`CompoundPredicate::generate_witness`], which derives both halves from a
/// single secret value.
#[derive(Debug, Clone)]
pub enum CompoundPredicate {
    Single(Predicate),
    And(Box<CompoundPredicate>, Box<CompoundPredicate>),
}

/// Remap wire indices in a gate for circuit merging.
///
/// The merged circuit uses layout: [left_inputs, right_inputs, left_intermediates, right_intermediates].
/// Input wires (0..num_inputs) get `input_offset`; intermediate wires get `intermediate_offset`.
fn remap_gate(
    gate: &Gate,
    num_inputs: usize,
    input_offset: usize,
    intermediate_offset: usize,
) -> Gate {
    fn remap(idx: usize, num_inputs: usize, input_off: usize, inter_off: usize) -> usize {
        if idx < num_inputs {
            idx + input_off
        } else {
            idx + inter_off
        }
    }
    match gate {
        Gate::Add {
            left,
            right,
            output,
        } => Gate::Add {
            left: remap(*left, num_inputs, input_offset, intermediate_offset),
            right: remap(*right, num_inputs, input_offset, intermediate_offset),
            output: remap(*output, num_inputs, input_offset, intermediate_offset),
        },
        Gate::Mul {
            left,
            right,
            output,
        } => Gate::Mul {
            left: remap(*left, num_inputs, input_offset, intermediate_offset),
            right: remap(*right, num_inputs, input_offset, intermediate_offset),
            output: remap(*output, num_inputs, input_offset, intermediate_offset),
        },
        Gate::Xor {
            left,
            right,
            output,
        } => Gate::Xor {
            left: remap(*left, num_inputs, input_offset, intermediate_offset),
            right: remap(*right, num_inputs, input_offset, intermediate_offset),
            output: remap(*output, num_inputs, input_offset, intermediate_offset),
        },
        Gate::AddConst {
            input,
            constant,
            output,
        } => Gate::AddConst {
            input: remap(*input, num_inputs, input_offset, intermediate_offset),
            constant: *constant,
            output: remap(*output, num_inputs, input_offset, intermediate_offset),
        },
        Gate::MulConst {
            input,
            constant,
            output,
        } => Gate::MulConst {
            input: remap(*input, num_inputs, input_offset, intermediate_offset),
            constant: *constant,
            output: remap(*output, num_inputs, input_offset, intermediate_offset),
        },
        Gate::AssertEq {
            input,
            expected,
            output,
        } => Gate::AssertEq {
            input: remap(*input, num_inputs, input_offset, intermediate_offset),
            expected: *expected,
            output: remap(*output, num_inputs, input_offset, intermediate_offset),
        },
    }
}

impl CompoundPredicate {
    /// Merge two sub-circuit wire/gate spaces into one AND circuit and append
    /// a same-witness equality link between their primary inputs
    /// (security audit finding C-3).
    ///
    /// Every `Predicate` designates input wire 0 as its primary secret value
    /// (`RangeCheck`: x; `SetMembership`: leaf; arithmetic checks: first
    /// operand). Without the link, a malicious prover could satisfy the two
    /// sub-predicates with *different* values (e.g. range-prove 50 while
    /// membership-proving 42), breaking the intended
    /// `RangeCheck(x) ∧ SetMembership(x)` semantics.
    ///
    /// Wire layout: `[left inputs | right inputs | 3 link wires |
    /// left intermediates | right intermediates]`. The link wires sit
    /// immediately after the inputs so the trailing `num_outputs` wires —
    /// the circuit's declared outputs — remain exactly the concatenation of
    /// the two sub-circuits' outputs, preserving prior output semantics.
    ///
    /// The link enforces `left_val == right_val (mod 2^32)`:
    ///   neg  = MulConst(right_val, u32::MAX)   // -right_val mod 2^32
    ///   diff = Add(left_val, neg)              //  left_val - right_val
    ///   AssertEq(diff, 0)                      // exact equality over Z_{2^32}
    ///
    /// Used identically by [`CompoundPredicate::And`] and
    /// [`CompoundPredicate::range_and_membership_for_verify`] so prover and
    /// verifier derive byte-identical (equal-hash) circuits.
    fn merge_same_witness_circuits(c_left: &Circuit, c_right: &Circuit) -> Circuit {
        const LINK_WIRES: usize = 3;
        let left_val = 0usize;             // left sub-predicate's primary input
        let right_val = c_left.num_inputs; // right sub-predicate's primary input

        let num_inputs = c_left.num_inputs + c_right.num_inputs;
        let num_wires = c_left.num_wires + c_right.num_wires + LINK_WIRES;
        let num_outputs = c_left.num_outputs + c_right.num_outputs;

        let mut gates =
            Vec::with_capacity(c_left.gates.len() + c_right.gates.len() + LINK_WIRES);

        // The link gates read ONLY input wires, so they are emitted FIRST.
        // This matters for the MPC emulator: it pushes wire sharings in gate
        // execution order, so a gate's declared output index must equal
        // `num_inputs + <its index in the gate list>`. Emitting the links
        // first makes their output wires (num_inputs..num_inputs+3) line up,
        // while every sub-circuit intermediate keeps its shifted position.
        let neg_right = num_inputs;
        let diff = num_inputs + 1;
        let link_out = num_inputs + 2;
        gates.push(Gate::MulConst {
            input: right_val,
            constant: u32::MAX,
            output: neg_right,
        });
        gates.push(Gate::Add {
            left: left_val,
            right: neg_right,
            output: diff,
        });
        gates.push(Gate::AssertEq {
            input: diff,
            expected: 0,
            output: link_out,
        });

        for gate in &c_left.gates {
            gates.push(remap_gate(
                gate,
                c_left.num_inputs,
                0,
                c_right.num_inputs + LINK_WIRES,
            ));
        }

        for gate in &c_right.gates {
            gates.push(remap_gate(
                gate,
                c_right.num_inputs,
                c_left.num_inputs,
                c_left.num_wires + LINK_WIRES,
            ));
        }

        Circuit {
            num_wires,
            num_inputs,
            num_outputs,
            gates,
        }
    }

    /// Compile this compound predicate into a single merged circuit.
    pub fn compile(&self) -> crate::Result<CompiledPredicate> {
        match self {
            CompoundPredicate::Single(pred) => pred.compile(),
            CompoundPredicate::And(left, right) => {
                let compiled_left = left.compile()?;
                let compiled_right = right.compile()?;
                let circuit = Self::merge_same_witness_circuits(
                    &compiled_left.circuit,
                    &compiled_right.circuit,
                );

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
            Box::new(CompoundPredicate::Single(Predicate::SetMembership {
                members,
            })),
        )
    }

    /// Build the same compound circuit as `range_and_membership` from the
    /// *public* fields available to the verifier (root, depth and member
    /// count), WITHOUT needing the full member set. Used by
    /// `verify_transaction_proof` to independently derive the expected
    /// circuit hash and detect circuit substitution attacks.
    ///
    /// `num_members` MUST equal the true length of the authorized set the
    /// root was built from: it is a public constant inside the F-1
    /// index-bound constraint (`leaf_index < num_members`), so an incorrect
    /// count produces a different circuit hash and verification fails
    /// closed — it can never loosen the constraint.
    pub fn range_and_membership_for_verify(
        lo: u32,
        hi: u32,
        root: u32,
        depth: usize,
        num_members: usize,
    ) -> crate::Result<CompiledPredicate> {
        let left = compile_range_check(lo, hi)?;
        let right = compile_set_membership_from_root(root, depth, num_members)?;
        // Merge identically to CompoundPredicate::And::compile() — including
        // the C-3 same-witness equality link — so the verifier's circuit
        // hash matches the prover's exactly.
        let circuit = Self::merge_same_witness_circuits(&left.circuit, &right.circuit);
        let mut public_inputs = left.public_inputs;
        public_inputs.extend_from_slice(&right.public_inputs);
        Ok(CompiledPredicate {
            circuit,
            public_inputs,
            witness_size: left.witness_size + right.witness_size,
        })
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
    let mut builder = CircuitBuilder::new_with_reserved_xor_inputs(2, 1);
    let xor_wire = builder.xor(0, 1)?;
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

    // Soundness guard (audit finding C-2): the construction proves
    // `0 <= shifted < 2^k` and `0 <= slack < 2^k` with
    // `k = bits_needed(width)`. When `width >= 2^31`, `k = 32`, and a 32-bit
    // boolean decomposition is satisfiable by EVERY u32 — the range
    // constraint degenerates to `shifted + slack == width (mod 2^32)`,
    // which any out-of-range `x` can satisfy via `slack = width - shifted`.
    // Restrict the supported domain to `width < 2^31` (k <= 31), for which
    // the construction is provably sound (no aliasing slack value exists).
    let width = hi.wrapping_sub(lo);
    if width >= 1u32 << 31 {
        return Err(crate::MpcithError::InvalidParams(format!(
            "RangeCheck requires hi - lo < 2^31 (got width {width}); \
             wider ranges make the bit-decomposition range proof vacuous"
        )));
    }    let k = bits_needed(width);

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

/// Enforce `leaf_index < num_members` inside the circuit (audit finding F-1).
///
/// [`crate::merkle::MerkleTree::build`] pads non-power-of-two member lists
/// with zero leaves at indices `[num_members, 2^depth)`. Those padded slots
/// have perfectly valid authentication paths, so without an explicit bound a
/// prover could open a padded slot and "prove" that the padding value is a
/// member of the set.
///
/// The constraint exploits the already-enforced `depth`-bit decomposition of
/// `leaf_index` (`bit_wires`; booleanity is guaranteed by the caller via
/// `bit_decompose_on`):
///
/// ```text
///     index < num_members
///   ⟺ index + (2^depth − num_members) ≤ 2^depth − 1
///   ⟺ adding the public constant pad = 2^depth − num_members to the index
///     produces no carry out of bit depth−1
/// ```
///
/// The ripple-carry overflow bit is computed with the existing gate set from
/// the boolean index wires and public constants only:
///
/// ```text
///     c₀ = 0
///     c_{i+1} = bᵢ·pᵢ + cᵢ·(bᵢ ⊕ pᵢ)      (pᵢ = i-th bit of pad)
///     AssertEq(c_depth, 0)
/// ```
///
/// This costs O(depth) gates and **zero** additional witness wires, and is
/// emitted identically by both compilation paths (`compile_set_membership`
/// and `compile_set_membership_from_root`) so the prover/verifier circuit
/// hashes continue to match. A verifier that compiles with a different
/// `num_members` derives a different circuit hash and fails closed.
fn constrain_index_below_num_members(
    builder: &mut CircuitBuilder,
    bit_wires: &[usize],
    num_members: usize,
) {
    let depth = bit_wires.len();
    debug_assert!(num_members >= 1, "empty sets are rejected at compile time");
    debug_assert!(num_members <= 1usize << depth);

    let pad = ((1u32 << depth) as u64).wrapping_sub(num_members as u64) as u32;

    // `None` models a carry that is structurally zero (no wire needed yet).
    let mut carry: Option<usize> = None;
    for (i, &b) in bit_wires.iter().enumerate() {
        let p = (pad >> i) & 1;
        debug_assert!(p <= 1);
        carry = match (p, carry) {
            (0, None) => None,
            // p = 0: c' = c · b
            (0, Some(c)) => Some(builder.mul(c, b)),
            // p = 1, carry still zero: c' = b
            (1, None) => Some(b),
            // p = 1: c' = b + c·¬b   (= b OR c)
            (1, Some(c)) => {
                let not_b = {
                    let t = builder.mul_const(b, u32::MAX);
                    builder.add_const(t, 1)
                };
                let c_not_b = builder.mul(c, not_b);
                Some(builder.add(b, c_not_b))
            }
            _ => unreachable!("pad bit is a single bit"),
        };
    }

    // Carry-out of the addition must be 0: index + pad fits in depth bits,
    // i.e. index < num_members.
    if let Some(top) = carry {
        builder.assert_eq(top, 0);
    }
}

/// Circuit: assert leaf ∈ members via Merkle inclusion proof.
///
/// At compile time the member set is hashed into a Merkle tree; the root
/// becomes the sole public input. The private witness is
/// `[leaf, leaf_index, bit_0..bit_{d-1}, sibling_0..sibling_{d-1}]`.
///
/// The circuit decomposes `leaf_index` into boolean bits, constrains
/// `leaf_index < members.len()` (see
/// [`constrain_index_below_num_members`] — this closes the padded-slot
/// soundness hole, since `MerkleTree::build` pads with zeros), then
/// iteratively hashes from the leaf upward using MiMC, selecting left/right
/// ordering via the path bits. The final hash is asserted equal to the root.
fn compile_set_membership(members: &[u32]) -> crate::Result<CompiledPredicate> {
    if members.is_empty() {
        return Err(crate::MpcithError::InvalidParams(
            "Set membership requires at least one member".into(),
        ));
    }

    let tree = MerkleTree::build(members);
    let root = tree.root();
    let depth = members.len().next_power_of_two().trailing_zeros() as usize;
    if depth >= 32 {
        return Err(crate::MpcithError::InvalidParams(format!(
            "Set membership supports at most 2^31 members (got depth {depth})"
        )));
    }

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

    // Soundness constraint (audit finding F-1): the padded slots of the
    // Merkle tree must not be provable positions. Enforce
    // `leaf_index < members.len()` cryptographically, in-circuit.
    constrain_index_below_num_members(&mut builder, &bit_wires, members.len());

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

/// Like [`compile_set_membership`] but takes the Merkle `root`, tree
/// `depth` **and the public member count** directly instead of the full
/// member list. This lets the verifier independently reconstruct the exact
/// same circuit (and hence its hash) from the public statement alone,
/// without ever seeing the private members. The member count MUST be the
/// true `members.len()` of the set the root was built from: it is baked
/// into the F-1 index-bound constraint, so a wrong count yields a
/// different circuit hash and fails closed at verification time.
///
/// Depth-0 sets (a single member) are fully supported with semantics
/// identical to [`compile_set_membership`]: the tree is a bare leaf, so
/// there are no bit/path/hash gates and the circuit is exactly
/// `AssertEq(leaf == root)`. This is sound by construction — any accepting
/// proof forces the witness equal to the sole public member — and keeps
/// the prover/verification compilers symmetric for every depth.
fn compile_set_membership_from_root(
    root: u32,
    depth: usize,
    num_members: usize,
) -> crate::Result<CompiledPredicate> {
    if depth >= 32 {
        return Err(crate::MpcithError::InvalidParams(format!(
            "Set membership supports at most 2^31 members (got depth {depth})"
        )));
    }
    // For depth 0 this admits exactly num_members == 1: a one-element set
    // has a single-leaf tree whose root IS that member. The circuit built
    // below degenerates to `leaf == root` with no path elements.
    if num_members == 0 || num_members > (1usize << depth) {
        return Err(crate::MpcithError::InvalidParams(format!(
            "Member count {num_members} inconsistent with tree depth {depth}"
        )));
    }
    let total_inputs = 2 + 2 * depth;
    let mut builder = CircuitBuilder::new(total_inputs);

    let bit_wires: Vec<usize> = (2..2 + depth).collect();
    let sibling_wires: Vec<usize> = (2 + depth..2 + 2 * depth).collect();

    bit_decompose_on(&mut builder, 1, &bit_wires);

    // Soundness constraint (audit finding F-1): identical to the proving
    // path so both compilers derive hash-equal circuits.
    constrain_index_below_num_members(&mut builder, &bit_wires, num_members);

    let mut current = 0usize;
    for i in 0..depth {
        let bit = bit_wires[i];
        let sibling = sibling_wires[i];
        let not_bit = {
            let t = builder.mul_const(bit, u32::MAX);
            builder.add_const(t, 1)
        };
        let selected_left = {
            let a = builder.mul(not_bit, current);
            let b = builder.mul(bit, sibling);
            builder.add(a, b)
        };
        let selected_right = {
            let a = builder.mul(bit, current);
            let b = builder.mul(not_bit, sibling);
            builder.add(a, b)
        };
        let (hash_left, _hash_right) =
            build_mimc_hash(&mut builder, selected_left, selected_right, MIMC_ROUNDS);
        current = hash_left;
    }

    let _out = builder.assert_eq(current, root);
    let circuit = builder.build(1);

    Ok(CompiledPredicate {
        circuit,
        public_inputs: vec![root],
        witness_size: 2 + depth,
    })
}

/// Helper: build the full RangeCheck witness for value x in [lo, hi].
fn range_witness_vec(x: u32, lo: u32, hi: u32) -> Vec<u32> {
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

/// Helper: build the full SetMembership witness from a MerkleProof.
fn set_membership_witness_vec(proof: &crate::merkle::MerkleProof) -> Vec<u32> {
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

impl CompoundPredicate {
    /// Generate the full compound witness for a given secret value.
    ///
    /// For `And`: concatenates left witness ++ right witness.
    /// For `Single`: delegates to `Predicate::generate_witness`.
    pub fn generate_witness(&self, secret_value: u32) -> crate::Result<Vec<u32>> {
        match self {
            CompoundPredicate::Single(pred) => pred.generate_witness(secret_value),
            CompoundPredicate::And(left, right) => {
                let mut w = left.generate_witness(secret_value)?;
                w.extend_from_slice(&right.generate_witness(secret_value)?);
                Ok(w)
            }
        }
    }
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
        let pred = Predicate::MultiplicationCheck {
            expected_product: 12,
        };
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

    // ── C-2 regression: supported RangeCheck domain is hi - lo < 2^31 ─────

    fn range_compile(lo: u32, hi: u32) -> crate::Result<CompiledPredicate> {
        Predicate::RangeCheck { lo, hi }.compile()
    }

    #[test]
    fn test_c2_width_zero_supported() {
        // width = 0: equality constraint x == lo.
        let compiled = range_compile(5, 5).unwrap();
        assert!(compiled.circuit.evaluate(&range_witness(5, 5, 5)).is_ok());
        assert!(compiled.circuit.evaluate(&range_witness(4, 5, 5)).is_err());
        assert!(compiled.circuit.evaluate(&range_witness(6, 5, 5)).is_err());
    }

    #[test]
    fn test_c2_width_one_supported() {
        // width = 1: exactly two admissible values.
        let compiled = range_compile(10, 11).unwrap();
        assert!(compiled.circuit.evaluate(&range_witness(10, 10, 11)).is_ok());
        assert!(compiled.circuit.evaluate(&range_witness(11, 10, 11)).is_ok());
        assert!(compiled.circuit.evaluate(&range_witness(9, 10, 11)).is_err());
        assert!(compiled.circuit.evaluate(&range_witness(12, 10, 11)).is_err());
    }

    #[test]
    fn test_c2_width_2p31_minus_2_supported() {
        // width = 2^31 - 2 → k = 31, largest tight-but-sound boundary region.
        let lo = 1u32;
        let hi = 2u32 * (1 << 30) - 1; // width = 2^31 - 2
        assert_eq!(hi - lo, (1u32 << 31) - 2);
        let compiled = range_compile(lo, hi).unwrap();
        assert!(compiled.circuit.evaluate(&range_witness(lo, lo, hi)).is_ok());
        assert!(compiled.circuit.evaluate(&range_witness(hi, lo, hi)).is_ok());
        assert!(
            compiled
                .circuit
                .evaluate(&range_witness(lo + (hi - lo) / 2, lo, hi))
                .is_ok()
        );
        assert!(compiled.circuit.evaluate(&range_witness(lo - 1, lo, hi)).is_err());
        assert!(compiled.circuit.evaluate(&range_witness(hi + 1, lo, hi)).is_err());
    }

    #[test]
    fn test_c2_width_2p31_minus_1_supported() {
        // width = 2^31 - 1 → k = 31, the maximum supported width.
        let lo = 0u32;
        let hi = (1u32 << 31) - 1;
        let compiled = range_compile(lo, hi).unwrap();
        for &x in &[lo, hi, 1u32 << 30] {
            assert!(compiled.circuit.evaluate(&range_witness(x, lo, hi)).is_ok());
        }
        assert!(compiled.circuit.evaluate(&range_witness(hi + 1, lo, hi)).is_err());
    }

    #[test]
    fn test_c2_width_2p31_rejected() {
        let err = range_compile(0, 1u32 << 31)
            .err()
            .expect("width = 2^31 must be rejected");
        assert!(
            matches!(err, crate::MpcithError::InvalidParams(_)),
            "width = 2^31 must be rejected as InvalidParams, got {err:?}"
        );
    }

    #[test]
    fn test_c2_width_gt_2p31_rejected() {
        for (lo, hi) in [
            (0u32, (1u32 << 31) + 5),
            (0u32, u32::MAX),
            (12345u32, u32::MAX),
        ] {
            let err = range_compile(lo, hi)
                .err()
                .expect("width > 2^31 must be rejected");
            assert!(
                matches!(err, crate::MpcithError::InvalidParams(_)),
                "width > 2^31 must be rejected as InvalidParams, got {err:?}"
            );
        }
    }

    #[test]
    fn test_c2_boundary_values() {
        let (lo, hi) = (100u32, 200u32);
        let compiled = range_compile(lo, hi).unwrap();
        assert!(compiled.circuit.evaluate(&range_witness(99, lo, hi)).is_err()); // x = lo-1
        assert!(compiled.circuit.evaluate(&range_witness(100, lo, hi)).is_ok()); // x = lo
        assert!(compiled.circuit.evaluate(&range_witness(200, lo, hi)).is_ok()); // x = hi
        assert!(compiled.circuit.evaluate(&range_witness(201, lo, hi)).is_err()); // x = hi+1
    }

    #[test]
    fn test_c2_values_near_u32_max() {
        // Supported high range: width = 100, ending at u32::MAX.
        let lo = u32::MAX - 100;
        let hi = u32::MAX;
        let compiled = range_compile(lo, hi).unwrap();
        assert!(compiled.circuit.evaluate(&range_witness(u32::MAX, lo, hi)).is_ok());
        assert!(compiled.circuit.evaluate(&range_witness(u32::MAX - 50, lo, hi)).is_ok());
        assert!(compiled.circuit.evaluate(&range_witness(lo, lo, hi)).is_ok());

        // Below lo rejected...
        assert!(compiled.circuit.evaluate(&range_witness(lo - 1, lo, hi)).is_err());
        // ...including the wrap-aliasing attempt x = 0: shifted would be
        // 2^32 - lo = 101 > width, forcing slack = width - shifted to wrap
        // to a huge value that fails the k=7-bit decomposition.
        assert!(compiled.circuit.evaluate(&range_witness(0, lo, hi)).is_err());

        // A range reaching u32::MAX but wider than 2^31 is unsupported.
        assert!(range_compile(0, u32::MAX).is_err());
        assert!(range_compile(1, u32::MAX).is_err());
    }

    // ── F-1 regression: padded Merkle slots are not provable positions ────

    /// Witness for an arbitrary (leaf, leaf_index) against the tree built
    /// from `members` — lets tests aim at padded slots directly.
    fn membership_witness_at(members: &[u32], idx: usize, leaf: u32) -> Vec<u32> {
        let tree = MerkleTree::build(members);
        let mp = tree.prove_membership(idx);
        let depth = mp.siblings.len();
        let mut w = vec![leaf, idx as u32];
        for i in 0..depth {
            w.push(((idx >> i) & 1) as u32);
        }
        w.extend(&mp.siblings);
        w
    }

    #[test]
    fn test_f1_padded_zero_leaf_unprovable_3set() {
        // THE attack: members = {7,8,9} pads to [7,8,9,0]; the attacker must
        // NOT be able to prove 0 ∈ S via padded index 3. The circuit itself
        // (not prove()) must reject it: index 3 violates index < 3.
        let members = vec![7u32, 8, 9];
        let compiled = Predicate::SetMembership { members: members.clone() }
            .compile()
            .unwrap();
        let w = membership_witness_at(&members, 3, 0);
        assert_eq!(w[0], 0, "padded slot must hold zero");
        assert!(
            compiled.circuit.evaluate(&w).is_err(),
            "padded index 3 must violate the circuit's index < len constraint"
        );
    }

    #[test]
    fn test_f1_all_real_members_provable_3set() {
        let members = vec![7u32, 8, 9];
        let compiled = Predicate::SetMembership { members: members.clone() }
            .compile()
            .unwrap();
        for (idx, &value) in members.iter().enumerate() {
            let w = membership_witness_at(&members, idx, value);
            compiled.circuit.evaluate(&w).unwrap_or_else(|e| {
                panic!("real member {value} at index {idx} must satisfy the circuit: {e}")
            });
        }
    }

    #[test]
    fn test_f1_five_element_set_padding_rejected() {
        // 5 members pad to 8 leaves: indices 5,6,7 are padded zeros.
        let members = vec![11u32, 22, 33, 44, 55];
        let compiled = Predicate::SetMembership { members: members.clone() }
            .compile()
            .unwrap();
        for (idx, &value) in members.iter().enumerate() {
            let w = membership_witness_at(&members, idx, value);
            compiled.circuit.evaluate(&w).unwrap_or_else(|e| {
                panic!("real member {value} at index {idx} must be provable: {e}")
            });
        }
        for idx in 5..8usize {
            let w = membership_witness_at(&members, idx, 0);
            assert!(
                compiled.circuit.evaluate(&w).is_err(),
                "padded index {idx} must be rejected"
            );
            // A garbage leaf at a padded position must also fail (root check).
            let w2 = membership_witness_at(&members, idx, 12345);
            assert!(compiled.circuit.evaluate(&w2).is_err());
        }
        // Proving that the padding VALUE is a member must be impossible.
        let w3 = membership_witness_at(&members, 6, 0);
        assert!(compiled.circuit.evaluate(&w3).is_err());
    }

    #[test]
    fn test_f1_power_of_two_set_all_members_provable() {
        // No padding exists; the constraint is vacuous (pad = 0) and every
        // real member must still verify.
        let members = vec![10u32, 20, 30, 42];
        let compiled = Predicate::SetMembership { members: members.clone() }
            .compile()
            .unwrap();
        for (idx, &value) in members.iter().enumerate() {
            let w = membership_witness_at(&members, idx, value);
            compiled.circuit.evaluate(&w).unwrap_or_else(|e| {
                panic!("power-of-two set member {value} at index {idx}: {e}")
            });
        }
        // Out-of-range index 4 does not exist even as a padded slot here.
        // Build its witness manually (siblings copied from index 3's path):
        // the constraint must reject it regardless of which check fires
        // first (index < len or the MiMC root equality).
        let mut w = membership_witness_at(&members, 3, 0);
        w[1] = 4; // claimed leaf_index
        for i in 0..2 {
            w[2 + i] = ((4 >> i) & 1) as u32; // bits of 4 = [0, 0]
        }
        assert!(compiled.circuit.evaluate(&w).is_err());
    }

    #[test]
    fn test_f1_single_member_set_depth0_still_works() {
        // depth = 0: no index bits exist, so the carry-chain constraint is
        // skipped — sound because the circuit forces leaf == root == the
        // sole member directly. No new depth-0 bug may be introduced.
        let members = vec![42u32];
        let pred = Predicate::SetMembership { members: members.clone() };
        let compiled = pred.compile().unwrap();
        let w = membership_witness_at(&members, 0, 42);
        compiled.circuit.evaluate(&w).unwrap();
        let mut bad = membership_witness_at(&members, 0, 43);
        bad[0] = 43;
        assert!(compiled.circuit.evaluate(&bad).is_err());
    }

    #[test]
    fn test_f1_empty_set_rejected() {
        let err = Predicate::SetMembership { members: vec![] }
            .compile()
            .err()
            .expect("empty set must not compile");
        assert!(matches!(err, crate::MpcithError::InvalidParams(_)));
    }

    #[test]
    fn test_f1_compiler_paths_hash_equal_with_bound() {
        // Prover path and verification path must derive hash-equal circuits
        // when (and only when) the member count matches.
        let members = vec![10u32, 20, 30, 42, 50]; // non-power-of-two → padding + bound active
        let lo = 0u32;
        let hi = 100u32;
        let prover = CompoundPredicate::range_and_membership(lo, hi, members.clone())
            .compile()
            .unwrap();

        let tree = MerkleTree::build(&members);
        let root = tree.root();
        let depth = members.len().next_power_of_two().trailing_zeros() as usize;

        let verifier = CompoundPredicate::range_and_membership_for_verify(
            lo, hi, root, depth, members.len(),
        )
        .unwrap();
        assert_eq!(
            crate::fiat_shamir::hash_circuit(&prover.circuit),
            crate::fiat_shamir::hash_circuit(&verifier.circuit),
            "both compilation paths must embed identical index-bound constraints"
        );

        // Fail-closed: a WRONG member count must change the circuit hash.
        for wrong in [members.len() - 1, members.len() + 1, 1] {
            let bad = CompoundPredicate::range_and_membership_for_verify(
                lo, hi, root, depth, wrong,
            );
            match bad {
                Ok(compiled_bad) => assert_ne!(
                    crate::fiat_shamir::hash_circuit(&prover.circuit),
                    crate::fiat_shamir::hash_circuit(&compiled_bad.circuit),
                    "wrong count {wrong} must yield a different (stricter) circuit"
                ),
                Err(_) => {} // rejected outright — also fail-closed
            }
        }
    }

    #[test]
    fn test_f1_absurd_depth_rejected_before_shift() {
        // Defensive guard: hostile/oversized depths must not reach the
        // `1u32 << depth` shift inside the constraint builder.
        let err = compile_set_membership_from_root(12345, 40, 100)
            .err()
            .expect("depth 40 must be rejected");
        assert!(matches!(err, crate::MpcithError::InvalidParams(_)));
    }

    // ── F-6 regression: symmetric depth-0 (single-member) semantics ───────

    #[test]
    fn test_f6_depth0_circuit_is_leaf_eq_root_and_symmetric() {
        let members = vec![42u32];
        let tree = MerkleTree::build(&members);
        assert_eq!(tree.root(), 42, "single-leaf tree root must be the member");

        // Prover-side circuit: leaf == root, no hash/path gates.
        let prover = Predicate::SetMembership { members: members.clone() }
            .compile()
            .unwrap();
        assert_eq!(prover.circuit.gates.len(), 1);
        assert!(matches!(
            prover.circuit.gates[0],
            Gate::AssertEq { input: 0, expected: 42, .. }
        ));

        // Verification-side compiler must produce a hash-equal circuit.
        let verifier = compile_set_membership_from_root(tree.root(), 0, 1).unwrap();
        assert_eq!(
            crate::fiat_shamir::hash_circuit(&prover.circuit),
            crate::fiat_shamir::hash_circuit(&verifier.circuit),
            "depth-0 circuits from both compilers must be identical"
        );
        // And through the compound paths used by transaction verification.
        let cp = CompoundPredicate::range_and_membership(0, 100, members.clone())
            .compile()
            .unwrap();
        let cv = CompoundPredicate::range_and_membership_for_verify(0, 100, tree.root(), 0, 1)
            .unwrap();
        assert_eq!(
            crate::fiat_shamir::hash_circuit(&cp.circuit),
            crate::fiat_shamir::hash_circuit(&cv.circuit),
            "depth-0 compound circuits must match across compilers"
        );

        // Circuit semantics: the member satisfies it; any other value fails.
        compiled_eval_ok(&prover.circuit, &[42u32, 0]);
        assert!(prover.circuit.evaluate(&[43u32, 0]).is_err());
    }

    /// Build the canonical single-member witness and evaluate.
    fn compiled_eval_ok(circuit: &Circuit, w: &[u32]) {
        circuit
            .evaluate(w)
            .unwrap_or_else(|e| panic!("depth-0 honest witness must satisfy circuit: {e}"));
    }

    #[test]
    fn test_f6_depth0_end_to_end_prove_verify() {
        // members = [42], secret = 42 → prove + verify MUST succeed.
        let params = crate::params::ProofParams::fast_insecure();
        let members = vec![42u32];
        let pred = Predicate::SetMembership { members: members.clone() };
        let tree = MerkleTree::build(&members);
        let root = tree.root();

        let w = set_membership_witness_vec(&tree.prove_membership(0));
        assert_eq!(w.len(), 2, "depth-0 witness is exactly [leaf, index]");

        let proof = crate::prove(pred.clone(), &w, &[root], &params)
            .unwrap_or_else(|e| panic!("single-member membership proof must exist: {e}"));
        assert!(
            crate::verify_predicate(&pred, &proof, &[root], &params).unwrap(),
            "single-member membership proof must verify"
        );
    }

    #[test]
    fn test_f6_depth0_wrong_secret_rejected_end_to_end() {
        // members = [42], secret = 43 → MUST fail at every level.
        let params = crate::params::ProofParams::fast_insecure();
        let members = vec![42u32];
        let tree = MerkleTree::build(&members);
        let root = tree.root();
        let pred = Predicate::SetMembership { members };

        // generate_witness refuses non-members outright.
        assert!(pred.generate_witness(43).is_err());

        // A hand-crafted witness for 43 cannot satisfy the circuit...
        assert!(crate::prove(pred.clone(), &[43u32, 0], &[43], &params).is_err());
        // ...and even against the TRUE public root the claim fails.
        assert!(crate::prove(pred, &[43u32, 0], &[root], &params).is_err());
    }

    #[test]
    fn test_f6_depth0_compound_end_to_end_prove_verify() {
        // Compound RangeCheck ∧ SetMembership over a one-element set,
        // proven with the compound API and verified through the
        // independently-compiled verification circuit.
        let params = crate::params::ProofParams::fast_insecure();
        let members = vec![42u32];
        let compound = CompoundPredicate::range_and_membership(0, 100, members.clone());
        let witness = compound.generate_witness(42).unwrap();
        let public_inputs = vec![0u32, 100, MerkleTree::build(&members).root()];
        let proof = crate::prove_compound(compound.clone(), &witness, &public_inputs, &params)
            .expect("single-member compound proof must exist");
        assert!(
            crate::verify_compound(&compound, &proof, &public_inputs, &params).unwrap(),
            "single-member compound proof must verify"
        );

        // Decoy value outside the range but inside nothing: unprovable.
        assert!(compound.generate_witness(43).is_err());
    }

    #[test]
    fn test_f6_depth0_count_mismatch_still_fail_closed() {
        // depth 0 admits exactly one member; anything else must be rejected.
        for bad in [0usize, 2, 5] {
            let err = compile_set_membership_from_root(42, 0, bad)
                .err()
                .expect("inconsistent count/depth must be rejected");
            assert!(matches!(err, crate::MpcithError::InvalidParams(_)));
        }
    }
}
