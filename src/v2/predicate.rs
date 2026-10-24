//! V2 range, membership, and combined circuit builders.
//!
//! Public statement values (bounds, root, member count, depth) are embedded
//! as field constants in the circuit. The witness vector contains only the
//! private value, its bit decomposition, the index bits, and Merkle siblings.
//! The combined builder uses one private `x` wire for both checks.

use ark_bn254::Fr;

use crate::v2::circuit::{CircuitBuilderV2, CircuitErrorV2, CircuitV2, Wire};
use crate::v2::merkle::{depth_for_members, verify_membership_statement, MerkleProofV2};
use crate::v2::poseidon2;
use crate::v2::poseidon2_circuit::{hash_leaf_gadget, hash_node_gadget, hash_root_gadget};
use crate::{MpcithError, Result};

/// Public parameters for a 32-bit inclusive range check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeStatementV2 {
    pub lo: u32,
    pub hi: u32,
}

impl RangeStatementV2 {
    /// Validate an inclusive range.
    pub fn new(lo: u32, hi: u32) -> Result<Self> {
        if lo > hi {
            return Err(MpcithError::InvalidParams(format!(
                "v2 range has lo={lo} > hi={hi}"
            )));
        }
        Ok(Self { lo, hi })
    }
}

/// Public parameters for a v2 set-membership statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipStatementV2 {
    /// Final root, including root metadata.
    pub root: Fr,
    /// Number of real members, excluding padding.
    pub num_members: u32,
    /// Canonical tree depth for `num_members`.
    pub depth: u32,
}

impl MembershipStatementV2 {
    /// Validate a membership statement against the canonical tree shape.
    pub fn new(root: Fr, num_members: u32, depth: u32) -> Result<Self> {
        if num_members == 0 {
            return Err(MpcithError::InvalidParams(
                "v2 membership set must not be empty".into(),
            ));
        }
        let expected_depth = depth_for_members(num_members);
        if depth != expected_depth {
            return Err(MpcithError::InvalidParams(format!(
                "v2 membership depth {depth} is not canonical for {num_members} members (expected {expected_depth})"
            )));
        }
        Ok(Self {
            root,
            num_members,
            depth,
        })
    }
}

/// Statement compiled into a v2 circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatementV2 {
    Range(RangeStatementV2),
    Membership(MembershipStatementV2),
    Combined {
        range: RangeStatementV2,
        membership: MembershipStatementV2,
    },
}

impl StatementV2 {
    /// Stable statement-type tag used by the v2 transcript and proof encoding.
    pub fn type_tag(&self) -> u8 {
        match self {
            Self::Range(_) => 1,
            Self::Membership(_) => 2,
            Self::Combined { .. } => 3,
        }
    }

    pub fn range(&self) -> Option<&RangeStatementV2> {
        match self {
            Self::Range(range) => Some(range),
            Self::Membership(_) => None,
            Self::Combined { range, .. } => Some(range),
        }
    }

    pub fn membership(&self) -> Option<&MembershipStatementV2> {
        match self {
            Self::Range(_) => None,
            Self::Membership(membership) => Some(membership),
            Self::Combined { membership, .. } => Some(membership),
        }
    }

    /// Public values in transcript order.
    ///
    /// Range: `[lo, hi]`.
    /// Membership: `[root, num_members, depth]`.
    /// Combined: `[lo, hi, root, num_members, depth]`.
    ///
    /// These are embedded constants, not witness inputs.
    pub fn public_values(&self) -> Vec<Fr> {
        match self {
            Self::Range(range) => vec![Fr::from(range.lo as u64), Fr::from(range.hi as u64)],
            Self::Membership(membership) => vec![
                membership.root,
                Fr::from(membership.num_members as u64),
                Fr::from(membership.depth as u64),
            ],
            Self::Combined { range, membership } => vec![
                Fr::from(range.lo as u64),
                Fr::from(range.hi as u64),
                membership.root,
                Fr::from(membership.num_members as u64),
                Fr::from(membership.depth as u64),
            ],
        }
    }
}

/// Private wire layout for a compiled v2 circuit.
#[derive(Debug, Clone)]
struct LayoutV2 {
    num_inputs: usize,
    x: Wire,
    x_bits: [Wire; 32],
    range_shifted_bits: Vec<Wire>,
    range_slack_bits: Vec<Wire>,
    index_bits: Option<[Wire; 32]>,
    siblings: Vec<Wire>,
    index_slack_bits: Vec<Wire>,
}

struct WireCursor {
    next: usize,
}

impl WireCursor {
    fn new() -> Self {
        Self { next: 0 }
    }

    fn alloc(&mut self) -> Wire {
        let wire = Wire(self.next);
        self.next += 1;
        wire
    }

    fn alloc_many(&mut self, count: usize) -> Vec<Wire> {
        (0..count).map(|_| self.alloc()).collect()
    }
}

impl LayoutV2 {
    fn allocate(range_bits: Option<usize>, membership: Option<(usize, usize)>) -> Self {
        let mut cursor = WireCursor::new();
        let x = cursor.alloc();
        let mut x_bits = [Wire(0); 32];
        for bit in x_bits.iter_mut() {
            *bit = cursor.alloc();
        }

        let (range_shifted_bits, range_slack_bits) = match range_bits {
            Some(bits) => (cursor.alloc_many(bits), cursor.alloc_many(bits)),
            None => (Vec::new(), Vec::new()),
        };

        let (index_bits, siblings, index_slack_bits) = match membership {
            Some((depth, index_bits_count)) => {
                let mut index_bits = [Wire(0); 32];
                for bit in index_bits.iter_mut() {
                    *bit = cursor.alloc();
                }
                (
                    Some(index_bits),
                    cursor.alloc_many(depth),
                    cursor.alloc_many(index_bits_count),
                )
            }
            None => (None, Vec::new(), Vec::new()),
        };

        Self {
            num_inputs: cursor.next,
            x,
            x_bits,
            range_shifted_bits,
            range_slack_bits,
            index_bits,
            siblings,
            index_slack_bits,
        }
    }
}

/// A compiled v2 statement plus its circuit and private witness layout.
#[derive(Debug, Clone)]
pub struct CompiledV2 {
    circuit: CircuitV2,
    statement: StatementV2,
    layout: LayoutV2,
}

impl CompiledV2 {
    pub fn circuit(&self) -> &CircuitV2 {
        &self.circuit
    }

    pub fn statement(&self) -> &StatementV2 {
        &self.statement
    }

    /// Number of private witness inputs.
    pub fn witness_size(&self) -> usize {
        self.circuit.num_inputs()
    }

    /// Build a checked private witness for a true statement.
    ///
    /// Range statements take `proof = None`. Membership and combined
    /// statements require a proof that matches the statement root, count,
    /// depth, value, and index. This is the prover-side witness builder; it
    /// refuses false statements rather than producing a bad witness.
    pub fn witness_for(&self, value: u32, proof: Option<&MerkleProofV2>) -> Result<Vec<Fr>> {
        match self.statement.range() {
            Some(range) => {
                if value < range.lo || value > range.hi {
                    return Err(MpcithError::InvalidWitness(format!(
                        "v2 range witness {value} is outside [{} , {}]",
                        range.lo, range.hi
                    )));
                }
            }
            None => {}
        }

        match self.statement.membership() {
            Some(membership) => {
                let proof = proof.ok_or_else(|| {
                    MpcithError::InvalidWitness(
                        "v2 membership witness requires a Merkle proof".into(),
                    )
                })?;
                if proof.leaf != poseidon2::hash_leaf(value) {
                    return Err(MpcithError::InvalidWitness(
                        "v2 membership proof leaf does not match the private value".into(),
                    ));
                }
                if !verify_membership_statement(
                    membership.root,
                    membership.num_members,
                    membership.depth,
                    proof,
                ) {
                    return Err(MpcithError::InvalidWitness(
                        "v2 membership proof does not match the statement".into(),
                    ));
                }
                Ok(self.build_witness_raw(value, proof.leaf_index, &proof.siblings))
            }
            None => {
                if proof.is_some() {
                    return Err(MpcithError::InvalidParams(
                        "v2 range-only witness must not carry a membership proof".into(),
                    ));
                }
                Ok(self.build_witness_raw(value, 0, &[]))
            }
        }
    }

    /// Build the private witness without checking statement truth.
    ///
    /// This is intentionally private to this module and used only by negative
    /// tests. It encodes wrapped 32-bit differences so the circuit evaluator,
    /// not the witness builder, is what rejects a false candidate.
    fn build_witness_raw(&self, value: u32, leaf_index: u32, siblings: &[Fr]) -> Vec<Fr> {
        let mut witness = vec![Fr::from(0u64); self.layout.num_inputs];
        witness[self.layout.x.index()] = Fr::from(value as u64);
        set_bits(&mut witness, &self.layout.x_bits, value, 32);

        if let Some(range) = self.statement.range() {
            let shifted = value.wrapping_sub(range.lo);
            let slack = range.hi.wrapping_sub(value);
            set_bits(
                &mut witness,
                &self.layout.range_shifted_bits,
                shifted,
                self.layout.range_shifted_bits.len(),
            );
            set_bits(
                &mut witness,
                &self.layout.range_slack_bits,
                slack,
                self.layout.range_slack_bits.len(),
            );
        }

        if let Some(membership) = self.statement.membership() {
            let index_bits = self
                .layout
                .index_bits
                .as_ref()
                .expect("membership layout must include index bits");
            set_bits(&mut witness, index_bits, leaf_index, 32);
            for (wire, sibling) in self.layout.siblings.iter().zip(siblings.iter()) {
                witness[wire.index()] = *sibling;
            }
            let index_slack = (membership.num_members - 1).wrapping_sub(leaf_index);
            set_bits(
                &mut witness,
                &self.layout.index_slack_bits,
                index_slack,
                self.layout.index_slack_bits.len(),
            );
        }

        witness
    }

    /// Evaluate a candidate witness, returning the circuit's structured error
    /// if the statement is false.
    pub fn evaluate(&self, witness: &[Fr]) -> std::result::Result<Vec<Fr>, CircuitErrorV2> {
        self.circuit.evaluate(witness)
    }
}

fn bits_needed(max_value: u32) -> usize {
    if max_value == 0 {
        1
    } else {
        (u32::BITS - max_value.leading_zeros()) as usize
    }
}

fn bit_fr(value: u32, bit: usize) -> Fr {
    debug_assert!(bit < 32);
    Fr::from(((value >> bit) & 1) as u64)
}

fn set_bits(witness: &mut [Fr], wires: &[Wire], value: u32, count: usize) {
    for (bit, wire) in wires.iter().take(count).enumerate() {
        witness[wire.index()] = bit_fr(value, bit);
    }
}

fn constrain_bits(builder: &mut CircuitBuilderV2, bits: &[Wire]) {
    for &bit in bits {
        let one_minus = builder.add_const(bit, -Fr::from(1u64));
        let product = builder.mul(bit, one_minus);
        builder.assert_eq(product, Fr::from(0u64));
    }
}

fn reconstruct_bits(builder: &mut CircuitBuilderV2, bits: &[Wire]) -> Wire {
    debug_assert!(!bits.is_empty());
    let mut value = bits[0];
    for (bit, wire) in bits.iter().enumerate().skip(1) {
        let term = builder.mul_const(*wire, Fr::from(1u64 << bit));
        value = builder.add(value, term);
    }
    value
}

fn constrain_u32(builder: &mut CircuitBuilderV2, x: Wire, x_bits: &[Wire; 32]) {
    constrain_bits(builder, x_bits);
    let reconstructed = reconstruct_bits(builder, x_bits);
    builder.assert_eq_wire(reconstructed, x);
}

fn add_range_constraints(
    builder: &mut CircuitBuilderV2,
    x: Wire,
    shifted_bits: &[Wire],
    slack_bits: &[Wire],
    range: &RangeStatementV2,
) {
    let shifted_wire = builder.add_const(x, -Fr::from(range.lo as u64));
    constrain_bits(builder, shifted_bits);
    let shifted_reconstructed = reconstruct_bits(builder, shifted_bits);
    builder.assert_eq_wire(shifted_reconstructed, shifted_wire);

    let width = range.hi - range.lo;
    let neg_shifted = builder.mul_const(shifted_wire, -Fr::from(1u64));
    let slack_wire = builder.add_const(neg_shifted, Fr::from(width as u64));
    constrain_bits(builder, slack_bits);
    let slack_reconstructed = reconstruct_bits(builder, slack_bits);
    builder.assert_eq_wire(slack_reconstructed, slack_wire);
}

fn add_membership_constraints(
    builder: &mut CircuitBuilderV2,
    x: Wire,
    index_bits: &[Wire; 32],
    index_slack_bits: &[Wire],
    siblings: &[Wire],
    membership: &MembershipStatementV2,
) {
    constrain_bits(builder, index_bits);
    let index = reconstruct_bits(builder, index_bits);

    // index <= num_members - 1 as integers. Both index and slack are bounded
    // by 32 bits, so this field equality cannot wrap modulo p.
    constrain_bits(builder, index_slack_bits);
    let slack = reconstruct_bits(builder, index_slack_bits);
    let index_plus_slack = builder.add(index, slack);
    builder.assert_eq(
        index_plus_slack,
        Fr::from((membership.num_members - 1) as u64),
    );

    let mut node = hash_leaf_gadget(builder, x);
    for level in 0..membership.depth as usize {
        let bit = index_bits[level];
        let sibling = siblings[level];

        let neg_node = builder.mul_const(node, -Fr::from(1u64));
        let sibling_minus_node = builder.add(sibling, neg_node);
        let term = builder.mul(bit, sibling_minus_node);
        let left = builder.add(node, term);
        let neg_term = builder.mul_const(term, -Fr::from(1u64));
        let right = builder.add(sibling, neg_term);
        node = hash_node_gadget(builder, left, right);
    }

    let computed_root = hash_root_gadget(builder, node, membership.num_members, membership.depth);
    builder.assert_eq(computed_root, membership.root);
}

/// Compile an inclusive 32-bit range statement.
pub fn compile_range(lo: u32, hi: u32) -> Result<CompiledV2> {
    let range = RangeStatementV2::new(lo, hi)?;
    let range_bits = bits_needed(hi - lo);
    let layout = LayoutV2::allocate(Some(range_bits), None);
    let mut builder = CircuitBuilderV2::new(layout.num_inputs);
    constrain_u32(&mut builder, layout.x, &layout.x_bits);
    add_range_constraints(
        &mut builder,
        layout.x,
        &layout.range_shifted_bits,
        &layout.range_slack_bits,
        &range,
    );
    Ok(CompiledV2 {
        circuit: builder.build(),
        statement: StatementV2::Range(range),
        layout,
    })
}

/// Compile a set-membership statement from public root/count/depth values.
pub fn compile_membership(root: Fr, num_members: u32, depth: u32) -> Result<CompiledV2> {
    let membership = MembershipStatementV2::new(root, num_members, depth)?;
    let index_bits_count = bits_needed(num_members - 1);
    let layout = LayoutV2::allocate(None, Some((depth as usize, index_bits_count)));
    let mut builder = CircuitBuilderV2::new(layout.num_inputs);
    constrain_u32(&mut builder, layout.x, &layout.x_bits);
    add_membership_constraints(
        &mut builder,
        layout.x,
        layout
            .index_bits
            .as_ref()
            .expect("membership layout must include index bits"),
        &layout.index_slack_bits,
        &layout.siblings,
        &membership,
    );
    Ok(CompiledV2 {
        circuit: builder.build(),
        statement: StatementV2::Membership(membership),
        layout,
    })
}

/// Recompile the canonical circuit for a public statement.
///
/// This is the verifier's circuit source. A v2 proof never supplies a circuit,
/// so an attacker cannot substitute a different gate sequence.
pub fn compile_from_statement(statement: &StatementV2) -> Result<CompiledV2> {
    match statement {
        StatementV2::Range(range) => compile_range(range.lo, range.hi),
        StatementV2::Membership(membership) => {
            compile_membership(membership.root, membership.num_members, membership.depth)
        }
        StatementV2::Combined { range, membership } => compile_combined(
            range.lo,
            range.hi,
            membership.root,
            membership.num_members,
            membership.depth,
        ),
    }
}

/// Compile one circuit for `lo <= x <= hi` AND `x` in the committed set.
///
/// The range and membership checks both read the same `x` wire and the same
/// `x_bits`; there is no second private value to link.
pub fn compile_combined(
    lo: u32,
    hi: u32,
    root: Fr,
    num_members: u32,
    depth: u32,
) -> Result<CompiledV2> {
    let range = RangeStatementV2::new(lo, hi)?;
    let membership = MembershipStatementV2::new(root, num_members, depth)?;
    let range_bits = bits_needed(hi - lo);
    let index_bits_count = bits_needed(num_members - 1);
    let layout = LayoutV2::allocate(Some(range_bits), Some((depth as usize, index_bits_count)));
    let mut builder = CircuitBuilderV2::new(layout.num_inputs);
    constrain_u32(&mut builder, layout.x, &layout.x_bits);
    add_range_constraints(
        &mut builder,
        layout.x,
        &layout.range_shifted_bits,
        &layout.range_slack_bits,
        &range,
    );
    add_membership_constraints(
        &mut builder,
        layout.x,
        layout
            .index_bits
            .as_ref()
            .expect("membership layout must include index bits"),
        &layout.index_slack_bits,
        &layout.siblings,
        &membership,
    );
    Ok(CompiledV2 {
        circuit: builder.build(),
        statement: StatementV2::Combined { range, membership },
        layout,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::merkle::MerkleTreeV2;

    fn tree(members: &[u32]) -> MerkleTreeV2 {
        MerkleTreeV2::build(members).unwrap()
    }

    fn membership_compiled(tree: &MerkleTreeV2) -> CompiledV2 {
        compile_membership(tree.root(), tree.num_members(), tree.depth()).unwrap()
    }

    fn valid_proof(tree: &MerkleTreeV2, index: u32) -> MerkleProofV2 {
        tree.prove_membership(index).unwrap()
    }

    #[test]
    fn range_accepts_bounds_and_inside_values() {
        let compiled = compile_range(10, 100).unwrap();
        for value in [10u32, 11, 55, 99, 100] {
            let witness = compiled.witness_for(value, None).unwrap();
            assert!(compiled.evaluate(&witness).is_ok(), "value {value}");
        }
    }

    #[test]
    fn range_rejects_outside_values_at_evaluation_and_witness_checks() {
        let compiled = compile_range(10, 100).unwrap();
        for value in [0u32, 9, 101, u32::MAX] {
            assert!(
                compiled.witness_for(value, None).is_err(),
                "witness builder accepted {value}"
            );
            let raw = compiled.build_witness_raw(value, 0, &[]);
            assert!(
                compiled.evaluate(&raw).is_err(),
                "circuit accepted out-of-range {value}"
            );
        }
    }

    #[test]
    fn range_rejects_inverted_bounds() {
        assert!(compile_range(11, 10).is_err());
    }

    #[test]
    fn range_full_u32_domain_does_not_wrap() {
        let compiled = compile_range(0, u32::MAX).unwrap();
        for value in [0u32, 1, 1 << 31, u32::MAX - 1, u32::MAX] {
            let witness = compiled.witness_for(value, None).unwrap();
            assert!(compiled.evaluate(&witness).is_ok(), "value {value}");
        }
    }

    #[test]
    fn range_zero_width_is_exact() {
        let compiled = compile_range(42, 42).unwrap();
        assert!(compiled
            .evaluate(&compiled.witness_for(42, None).unwrap())
            .is_ok());
        for value in [41u32, 43] {
            let raw = compiled.build_witness_raw(value, 0, &[]);
            assert!(compiled.evaluate(&raw).is_err(), "value {value}");
        }
    }

    #[test]
    fn membership_accepts_every_real_member() {
        let tree = tree(&[10, 20, 42]);
        let compiled = membership_compiled(&tree);
        for index in 0..tree.num_members() {
            let value = [10u32, 20, 42][index as usize];
            let proof = valid_proof(&tree, index);
            let witness = compiled.witness_for(value, Some(&proof)).unwrap();
            assert!(compiled.evaluate(&witness).is_ok(), "member {value}");
        }
    }

    #[test]
    fn membership_rejects_non_member_padded_index_and_wrong_sibling() {
        let tree = tree(&[10, 20, 42]);
        let compiled = membership_compiled(&tree);
        let proof = valid_proof(&tree, 1);

        let raw = compiled.build_witness_raw(30, proof.leaf_index, &proof.siblings);
        assert!(compiled.evaluate(&raw).is_err(), "non-member accepted");

        let raw = compiled.build_witness_raw(42, 3, &proof.siblings);
        assert!(compiled.evaluate(&raw).is_err(), "padded index accepted");

        let mut bad_siblings = proof.siblings.clone();
        bad_siblings[0] += Fr::from(1u64);
        let raw = compiled.build_witness_raw(20, proof.leaf_index, &bad_siblings);
        assert!(compiled.evaluate(&raw).is_err(), "wrong sibling accepted");

        // Same sibling, wrong direction: index 0 instead of index 1.
        let raw = compiled.build_witness_raw(20, 0, &proof.siblings);
        assert!(compiled.evaluate(&raw).is_err(), "wrong direction accepted");
    }

    #[test]
    fn membership_statement_rejects_noncanonical_depth() {
        let tree = tree(&[10, 20, 42]);
        assert!(compile_membership(tree.root(), 3, 1).is_err());
        assert!(compile_membership(tree.root(), 3, 3).is_err());
        assert!(compile_membership(tree.root(), 0, 0).is_err());
    }

    #[test]
    fn membership_wrong_count_or_root_fails_evaluation() {
        let tree = tree(&[10, 20, 42]);
        let proof = valid_proof(&tree, 1);

        let wrong_count = compile_membership(tree.root(), 4, 2).unwrap();
        let raw = wrong_count.build_witness_raw(20, proof.leaf_index, &proof.siblings);
        assert!(wrong_count.evaluate(&raw).is_err());

        let wrong_root = compile_membership(tree.root() + Fr::from(1u64), 3, 2).unwrap();
        let raw = wrong_root.build_witness_raw(20, proof.leaf_index, &proof.siblings);
        assert!(wrong_root.evaluate(&raw).is_err());
    }

    #[test]
    fn combined_accepts_in_range_member() {
        let tree = tree(&[10, 20, 42]);
        let compiled = compile_combined(10, 50, tree.root(), 3, 2).unwrap();
        let proof = valid_proof(&tree, 1);
        let witness = compiled.witness_for(20, Some(&proof)).unwrap();
        assert!(compiled.evaluate(&witness).is_ok());
    }

    #[test]
    fn combined_rejects_in_range_non_member_and_member_out_of_range() {
        let tree = tree(&[10, 20, 42]);
        let compiled = compile_combined(10, 50, tree.root(), 3, 2).unwrap();
        let proof = valid_proof(&tree, 0);

        // 30 is in range but has no leaf in the set.
        let raw = compiled.build_witness_raw(30, proof.leaf_index, &proof.siblings);
        assert!(compiled.evaluate(&raw).is_err(), "non-member accepted");

        // 42 is a member but outside [50, 100].
        let out_of_range = compile_combined(50, 100, tree.root(), 3, 2).unwrap();
        let proof42 = valid_proof(&tree, 2);
        let raw = out_of_range.build_witness_raw(42, proof42.leaf_index, &proof42.siblings);
        assert!(
            out_of_range.evaluate(&raw).is_err(),
            "out-of-range accepted"
        );
    }

    #[test]
    fn combined_rejects_padded_index() {
        let tree = tree(&[10, 20, 42]);
        let compiled = compile_combined(10, 50, tree.root(), 3, 2).unwrap();
        let proof = valid_proof(&tree, 1);
        let raw = compiled.build_witness_raw(20, 3, &proof.siblings);
        assert!(compiled.evaluate(&raw).is_err());
    }

    #[test]
    fn combined_uses_one_x_wire_and_one_x_bit_decomposition() {
        let tree = tree(&[10, 20, 42]);
        let compiled = compile_combined(10, 50, tree.root(), 3, 2).unwrap();
        let proof = valid_proof(&tree, 1);
        let mut witness = compiled.witness_for(20, Some(&proof)).unwrap();

        // Keep the membership leaf at 20 but claim the range bits of 10. The
        // shared reconstruction constraint must reject this split witness.
        witness[compiled.layout.x.index()] = Fr::from(20u64);
        set_bits(&mut witness, &compiled.layout.x_bits, 10, 32);
        assert!(
            compiled.evaluate(&witness).is_err(),
            "combined circuit accepted mismatched x and x_bits"
        );

        // Keep the range value at 20 but use a membership path for 10. The
        // leaf hash from the shared x wire must not match the old path.
        let proof10 = valid_proof(&tree, 0);
        let raw = compiled.build_witness_raw(20, proof10.leaf_index, &proof10.siblings);
        assert!(
            compiled.evaluate(&raw).is_err(),
            "combined circuit accepted mismatched membership path"
        );
    }

    #[test]
    fn public_statement_values_are_exact_and_ordered() {
        let tree = tree(&[10, 20, 42]);
        let range = compile_range(10, 50).unwrap();
        assert_eq!(
            range.statement().public_values(),
            vec![Fr::from(10u64), Fr::from(50u64)]
        );

        let membership = compile_membership(tree.root(), 3, 2).unwrap();
        assert_eq!(
            membership.statement().public_values(),
            vec![tree.root(), Fr::from(3u64), Fr::from(2u64)]
        );

        let combined = compile_combined(10, 50, tree.root(), 3, 2).unwrap();
        assert_eq!(
            combined.statement().public_values(),
            vec![
                Fr::from(10u64),
                Fr::from(50u64),
                tree.root(),
                Fr::from(3u64),
                Fr::from(2u64),
            ]
        );
    }

    #[test]
    fn witness_sizes_match_expected_layouts() {
        let tree = tree(&[10, 20, 42]);
        let range = compile_range(10, 100).unwrap();
        let range_bits = bits_needed(90);
        assert_eq!(range.witness_size(), 1 + 32 + 2 * range_bits);

        let membership = compile_membership(tree.root(), 3, 2).unwrap();
        let index_bits = bits_needed(2);
        assert_eq!(membership.witness_size(), 1 + 32 + 32 + 2 + index_bits);

        let combined = compile_combined(10, 100, tree.root(), 3, 2).unwrap();
        assert_eq!(
            combined.witness_size(),
            1 + 32 + 2 * range_bits + 32 + 2 + index_bits
        );
    }
}
