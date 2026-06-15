//! High-level predicates compiled to circuits.
//!
//! Each predicate takes a private witness and produces a circuit + public inputs
//! that encodes the statement to be proven.
//!
//! Current predicates:
//! - `AdditionCheck`: prove x + y == z  (toy/test predicate)
//! - `RangeCheck`: prove lo <= x <= hi  (Phase 2)
//! - `SetMembership`: prove x ∈ {v1, ..., vk}  (Phase 2)

use crate::circuit::{Circuit, CircuitBuilder};

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
    /// Implemented as a linear scan: OR of (witness[0] - m_i == 0) for each m_i.
    /// Phase 2 will implement this with proper zero-check gates.
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
            Predicate::SetMembership { .. } => 1,
        }
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

/// Circuit: assert lo <= witness[0] <= hi
///
/// Strategy (simplified, for u32):
///   shifted = witness[0] - lo               (should be >= 0 if witness >= lo)
///   width   = hi - lo
///   We assert shifted <= width by asserting shifted * (shifted - width - 1) wraps
///   correctly. This is a placeholder; Phase 2 implements bit decomposition.
///
/// For now: compile as two assertions using the trick that
///   lo <= x <= hi  iff  (x - lo) <= (hi - lo)
/// We implement this as a multiplication-based range check:
///   assert (x - lo) * (hi - x + 1) != 0  ... (not quite right)
///
/// SIMPLIFIED PLACEHOLDER: assert (x - lo + 0) and (hi - x + 0) are "valid"
/// by asserting their sum equals (hi - lo). Full bit-decomposition in Phase 2.
fn compile_range_check(lo: u32, hi: u32) -> crate::Result<CompiledPredicate> {
    if lo > hi {
        return Err(crate::MpcithError::InvalidParams(
            "Range check requires lo <= hi".into(),
        ));
    }

    // Circuit:
    //   wire 0: witness x
    //   wire 1: x - lo   (= shifted_x, must satisfy 0 <= shifted_x <= hi-lo)
    //   wire 2: hi - lo  (constant, public)
    //   wire 3: (hi-lo) - shifted_x  (= hi - x, must be >= 0)
    //   wire 4: shifted_x + ((hi-lo) - shifted_x)  must == (hi-lo)  [sanity]
    //   wire 5: assert wire4 == (hi-lo)
    //
    // NOTE: This does NOT fully enforce the range in Z_{2^32} arithmetic
    // without bit decomposition. It is a structural placeholder showing
    // the circuit shape. Full range proof via bit decomposition is Phase 2.

    let width = hi.wrapping_sub(lo);

    let mut builder = CircuitBuilder::new(1); // witness: wire 0 = x
    // shifted_x = x - lo = x + (2^32 - lo)  [wrapping subtraction]
    let neg_lo = lo.wrapping_neg();
    let shifted = builder.add_const(0, neg_lo);       // wire 1: x - lo (wrapping)
    // upper_slack = (hi - lo) - shifted_x = width - shifted_x (wrapping)
    let neg_shifted = builder.mul_const(shifted, u32::MAX); // wire 2: -shifted (wrapping, * (2^32-1) not quite neg)
    // Proper negate: -a = a.wrapping_neg() = add_const(mul_const(a, 0xFFFFFFFF), 1)
    let neg_shifted_fixed = builder.add_const(neg_shifted, 1); // wire 3: -shifted_x
    let upper_slack = builder.add_const(neg_shifted_fixed, width); // wire 4: width - shifted_x
    // Assert: shifted + upper_slack == width  (i.e., they are complementary)
    let sum = builder.add(shifted, upper_slack);       // wire 5: shifted + upper_slack
    let _out = builder.assert_eq(sum, width);          // wire 6

    let circuit = builder.build(1);

    Ok(CompiledPredicate {
        circuit,
        public_inputs: vec![lo, hi],
        witness_size: 1,
    })
}

/// Circuit: assert witness[0] ∈ members
///
/// Strategy: linear scan with zero-product trick.
///   product = (x - m_0) * (x - m_1) * ... * (x - m_{k-1})
///   assert product == 0
///
/// If x equals any member, one factor is zero, so the product is zero.
/// This requires k-1 multiplication gates.
fn compile_set_membership(members: &[u32]) -> crate::Result<CompiledPredicate> {
    if members.is_empty() {
        return Err(crate::MpcithError::InvalidParams(
            "Set membership requires at least one member".into(),
        ));
    }

    // Wire 0: witness x
    // Wire 1: x - m_0
    // Wire 2: x - m_1
    // ...
    // Wire k: x - m_{k-1}
    // Wire k+1: (x-m_0) * (x-m_1)
    // Wire k+2: prev * (x-m_2)
    // ...
    // Final wire: assert product == 0

    let mut builder = CircuitBuilder::new(1);

    // Compute (x - m_i) for each member.
    let diff_wires: Vec<usize> = members
        .iter()
        .map(|&m| {
            let neg_m = m.wrapping_neg();
            builder.add_const(0, neg_m)
        })
        .collect();

    // Fold with multiplication: product = diff_wires[0] * diff_wires[1] * ...
    let product_wire = if diff_wires.len() == 1 {
        diff_wires[0]
    } else {
        let mut acc = builder.mul(diff_wires[0], diff_wires[1]);
        for &w in &diff_wires[2..] {
            acc = builder.mul(acc, w);
        }
        acc
    };

    // Assert product == 0.
    let _out = builder.assert_eq(product_wire, 0);
    let circuit = builder.build(1);

    // public_inputs for the proof system = expected output wire values.
    // The member list is encoded in the circuit itself (as constants).
    // The output wire must reconstruct to 0.
    Ok(CompiledPredicate {
        circuit,
        public_inputs: vec![0u32],
        witness_size: 1,
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
        let pred = Predicate::SetMembership { members: members.clone() };
        let compiled = pred.compile().unwrap();

        // Valid member.
        compiled.circuit.evaluate(&[42]).unwrap();
        compiled.circuit.evaluate(&[10]).unwrap();

        // Not a member — product is non-zero, AssertEq should fail.
        assert!(compiled.circuit.evaluate(&[99]).is_err());
    }

    #[test]
    fn test_range_check_compiles() {
        let pred = Predicate::RangeCheck { lo: 10, hi: 100 };
        let compiled = pred.compile().unwrap();
        assert!(compiled.circuit.num_wires > 0);
    }
}
