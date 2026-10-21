//! Minimal v2 arithmetic circuit over BN254 `Fr`.
//!
//! The type is intentionally small: private inputs, add, multiply,
//! add-constant, multiply-constant, and assert-equal. There is no XOR gate and
//! no `u32` wrapping arithmetic on this path.

use ark_bn254::Fr;
use thiserror::Error;

/// Explicit wire index in a v2 circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Wire(pub usize);

impl Wire {
    /// Construct an explicit wire reference. The evaluator validates it.
    pub fn new(index: usize) -> Self {
        Self(index)
    }

    /// Return the numeric wire index.
    pub fn index(self) -> usize {
        self.0
    }
}

/// A v2 gate. All constants are field elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateV2 {
    /// `output = left + right`.
    Add {
        left: Wire,
        right: Wire,
        output: Wire,
    },
    /// `output = left * right`.
    Mul {
        left: Wire,
        right: Wire,
        output: Wire,
    },
    /// `output = input + constant`.
    AddConst {
        input: Wire,
        constant: Fr,
        output: Wire,
    },
    /// `output = input * constant`.
    MulConst {
        input: Wire,
        constant: Fr,
        output: Wire,
    },
    /// Require `input == expected`.
    AssertEq { input: Wire, expected: Fr },
}

/// A validated-shape v2 circuit. Construction is normally through
/// [`CircuitBuilderV2`]; the evaluator re-checks topology so a malformed
/// circuit returns an error instead of panicking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitV2 {
    num_inputs: usize,
    num_wires: usize,
    gates: Vec<GateV2>,
}

impl CircuitV2 {
    /// Number of private input wires (the leading wire range).
    pub fn num_inputs(&self) -> usize {
        self.num_inputs
    }

    /// Total number of wires, including inputs.
    pub fn num_wires(&self) -> usize {
        self.num_wires
    }

    /// Gates in evaluation order.
    pub fn gates(&self) -> &[GateV2] {
        &self.gates
    }

    /// Evaluate the circuit on a witness.
    ///
    /// Wires are SSA-style: every gate output must be the next fresh wire, and
    /// every operand must already be defined. This rejects forward references,
    /// duplicate outputs, gaps, and unused trailing wires rather than silently
    /// accepting an accidental vector order.
    pub fn evaluate(&self, witness: &[Fr]) -> Result<Vec<Fr>, CircuitErrorV2> {
        if witness.len() != self.num_inputs {
            return Err(CircuitErrorV2::InputArity {
                expected: self.num_inputs,
                actual: witness.len(),
            });
        }

        let mut wires = vec![None; self.num_wires];
        for (wire, value) in wires.iter_mut().take(self.num_inputs).zip(witness.iter()) {
            *wire = Some(*value);
        }

        let mut next_wire = self.num_inputs;
        for (gate_index, gate) in self.gates.iter().enumerate() {
            match gate {
                GateV2::Add {
                    left,
                    right,
                    output,
                } => {
                    let left = read_wire(&wires, *left, self.num_wires, gate_index)?;
                    let right = read_wire(&wires, *right, self.num_wires, gate_index)?;
                    define_wire(
                        &mut wires,
                        *output,
                        left + right,
                        self.num_wires,
                        gate_index,
                        &mut next_wire,
                    )?;
                }
                GateV2::Mul {
                    left,
                    right,
                    output,
                } => {
                    let left = read_wire(&wires, *left, self.num_wires, gate_index)?;
                    let right = read_wire(&wires, *right, self.num_wires, gate_index)?;
                    define_wire(
                        &mut wires,
                        *output,
                        left * right,
                        self.num_wires,
                        gate_index,
                        &mut next_wire,
                    )?;
                }
                GateV2::AddConst {
                    input,
                    constant,
                    output,
                } => {
                    let input = read_wire(&wires, *input, self.num_wires, gate_index)?;
                    define_wire(
                        &mut wires,
                        *output,
                        input + *constant,
                        self.num_wires,
                        gate_index,
                        &mut next_wire,
                    )?;
                }
                GateV2::MulConst {
                    input,
                    constant,
                    output,
                } => {
                    let input = read_wire(&wires, *input, self.num_wires, gate_index)?;
                    define_wire(
                        &mut wires,
                        *output,
                        input * *constant,
                        self.num_wires,
                        gate_index,
                        &mut next_wire,
                    )?;
                }
                GateV2::AssertEq { input, expected } => {
                    let value = read_wire(&wires, *input, self.num_wires, gate_index)?;
                    if value != *expected {
                        return Err(CircuitErrorV2::UnsatisfiedAssertion {
                            gate: gate_index,
                            left: value,
                            right: *expected,
                        });
                    }
                }
            }
        }

        if next_wire != self.num_wires {
            return Err(CircuitErrorV2::UnusedWires {
                defined: next_wire,
                num_wires: self.num_wires,
            });
        }

        let mut values = Vec::with_capacity(self.num_wires);
        for (index, wire) in wires.into_iter().enumerate() {
            values.push(wire.ok_or(CircuitErrorV2::WireNotDefined {
                gate: self.gates.len(),
                wire: Wire(index),
            })?);
        }
        Ok(values)
    }
}

fn read_wire(
    wires: &[Option<Fr>],
    wire: Wire,
    num_wires: usize,
    gate: usize,
) -> Result<Fr, CircuitErrorV2> {
    if wire.0 >= num_wires {
        return Err(CircuitErrorV2::WireOutOfRange {
            gate,
            wire,
            num_wires,
        });
    }
    wires[wire.0].ok_or(CircuitErrorV2::WireNotDefined { gate, wire })
}

fn define_wire(
    wires: &mut [Option<Fr>],
    output: Wire,
    value: Fr,
    num_wires: usize,
    gate: usize,
    next_wire: &mut usize,
) -> Result<(), CircuitErrorV2> {
    if output.0 >= num_wires {
        return Err(CircuitErrorV2::WireOutOfRange {
            gate,
            wire: output,
            num_wires,
        });
    }
    if output.0 != *next_wire {
        return Err(CircuitErrorV2::NonSequentialOutput {
            gate,
            expected: *next_wire,
            actual: output.0,
        });
    }
    wires[output.0] = Some(value);
    *next_wire += 1;
    Ok(())
}

/// Structured evaluation/validation errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CircuitErrorV2 {
    /// Witness length does not match the declared private input count.
    #[error("invalid witness length: expected {expected}, got {actual}")]
    InputArity { expected: usize, actual: usize },

    /// A gate referenced a wire outside the declared wire range.
    #[error("gate {gate}: wire {wire:?} is out of range (num_wires={num_wires})")]
    WireOutOfRange {
        gate: usize,
        wire: Wire,
        num_wires: usize,
    },

    /// A gate referenced a wire that has not been defined yet.
    #[error("gate {gate}: wire {wire:?} is not defined yet")]
    WireNotDefined { gate: usize, wire: Wire },

    /// A gate output was not the next fresh wire (gap, reuse, or reordering).
    #[error("gate {gate}: output wire {actual} is not the next fresh wire {expected}")]
    NonSequentialOutput {
        gate: usize,
        expected: usize,
        actual: usize,
    },

    /// An assertion gate saw a different value.
    #[error("gate {gate}: assertion failed (left={left:?}, right={right:?})")]
    UnsatisfiedAssertion {
        gate: usize,
        left: Fr,
        right: Fr,
    },

    /// The circuit declared more wires than its gates define.
    #[error("circuit defines {defined} wires but declares {num_wires}")]
    UnusedWires { defined: usize, num_wires: usize },
}

/// Builder for [`CircuitV2`].
#[derive(Debug, Clone)]
pub struct CircuitBuilderV2 {
    num_inputs: usize,
    num_wires: usize,
    gates: Vec<GateV2>,
}

impl CircuitBuilderV2 {
    /// Start a circuit with `num_inputs` leading private input wires.
    pub fn new(num_inputs: usize) -> Self {
        Self {
            num_inputs,
            num_wires: num_inputs,
            gates: Vec::new(),
        }
    }

    fn alloc(&mut self) -> Wire {
        let wire = Wire(self.num_wires);
        self.num_wires += 1;
        wire
    }

    /// `output = left + right`.
    pub fn add(&mut self, left: Wire, right: Wire) -> Wire {
        let output = self.alloc();
        self.gates.push(GateV2::Add {
            left,
            right,
            output,
        });
        output
    }

    /// `output = left * right`.
    pub fn mul(&mut self, left: Wire, right: Wire) -> Wire {
        let output = self.alloc();
        self.gates.push(GateV2::Mul {
            left,
            right,
            output,
        });
        output
    }

    /// `output = input + constant`.
    pub fn add_const(&mut self, input: Wire, constant: Fr) -> Wire {
        let output = self.alloc();
        self.gates.push(GateV2::AddConst {
            input,
            constant,
            output,
        });
        output
    }

    /// `output = input * constant`.
    pub fn mul_const(&mut self, input: Wire, constant: Fr) -> Wire {
        let output = self.alloc();
        self.gates.push(GateV2::MulConst {
            input,
            constant,
            output,
        });
        output
    }

    /// Require `input == expected`.
    pub fn assert_eq(&mut self, input: Wire, expected: Fr) {
        self.gates.push(GateV2::AssertEq { input, expected });
    }

    /// Require two wires to be equal, using only the allowed v2 gate set.
    pub fn assert_eq_wire(&mut self, left: Wire, right: Wire) {
        let negated = self.mul_const(right, -Fr::from(1u64));
        let difference = self.add(left, negated);
        self.assert_eq(difference, Fr::from(0u64));
    }

    /// Finish the circuit. The evaluator performs the topology checks.
    pub fn build(self) -> CircuitV2 {
        CircuitV2 {
            num_inputs: self.num_inputs,
            num_wires: self.num_wires,
            gates: self.gates,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_circuit(num_inputs: usize, num_wires: usize, gates: Vec<GateV2>) -> CircuitV2 {
        CircuitV2 {
            num_inputs,
            num_wires,
            gates,
        }
    }

    #[test]
    fn addition_and_multiplication_use_field_arithmetic() {
        let mut builder = CircuitBuilderV2::new(2);
        let sum = builder.add(Wire(0), Wire(1));
        let product = builder.mul(Wire(0), Wire(1));
        // (u32::MAX + 2) and (u32::MAX * 2), not wrapping-u32 results.
        builder.assert_eq(sum, Fr::from(0x1_0000_0001u64));
        builder.assert_eq(product, Fr::from(0x1_ffff_fffeu64));
        let circuit = builder.build();

        let values = circuit
            .evaluate(&[Fr::from(u32::MAX as u64), Fr::from(2u64)])
            .unwrap();
        assert_eq!(values[sum.index()], Fr::from(0x1_0000_0001u64));
        assert_eq!(values[product.index()], Fr::from(0x1_ffff_fffeu64));
    }

    #[test]
    fn modulus_wrap_is_field_wrap_not_u32_wrap() {
        let modulus_minus_one = -Fr::from(1u64);
        let mut builder = CircuitBuilderV2::new(2);
        let sum = builder.add(Wire(0), Wire(1));
        builder.assert_eq(sum, Fr::from(0u64));
        let circuit = builder.build();

        let values = circuit
            .evaluate(&[modulus_minus_one, Fr::from(1u64)])
            .unwrap();
        assert_eq!(values[sum.index()], Fr::from(0u64));
        // A u32 implementation would not have wrapped this pair either; check
        // a second case where the distinction is visible.
        let mut builder = CircuitBuilderV2::new(2);
        let sum = builder.add(Wire(0), Wire(1));
        builder.assert_eq(sum, Fr::from(0x1_0000_0001u64));
        let circuit = builder.build();
        let values = circuit
            .evaluate(&[Fr::from(u32::MAX as u64), Fr::from(2u64)])
            .unwrap();
        assert_eq!(values[sum.index()], Fr::from(0x1_0000_0001u64));
        assert_ne!(values[sum.index()], Fr::from(1u64));
    }

    #[test]
    fn constants_and_assertions_evaluate() {
        let mut builder = CircuitBuilderV2::new(1);
        let shifted = builder.add_const(Wire(0), Fr::from(5u64));
        let scaled = builder.mul_const(shifted, Fr::from(3u64));
        builder.assert_eq(scaled, Fr::from(21u64));
        let circuit = builder.build();

        let values = circuit.evaluate(&[Fr::from(2u64)]).unwrap();
        assert_eq!(values[scaled.index()], Fr::from(21u64));
    }

    #[test]
    fn assert_eq_wire_uses_allowed_gates() {
        let mut builder = CircuitBuilderV2::new(2);
        builder.assert_eq_wire(Wire(0), Wire(1));
        let circuit = builder.build();
        assert!(circuit
            .evaluate(&[Fr::from(7u64), Fr::from(7u64)])
            .is_ok());
        assert!(matches!(
            circuit.evaluate(&[Fr::from(7u64), Fr::from(8u64)]),
            Err(CircuitErrorV2::UnsatisfiedAssertion { .. })
        ));
    }

    #[test]
    fn rejects_wrong_witness_length() {
        let circuit = CircuitBuilderV2::new(1).build();
        assert_eq!(
            circuit.evaluate(&[]),
            Err(CircuitErrorV2::InputArity {
                expected: 1,
                actual: 0
            })
        );
        assert_eq!(
            circuit.evaluate(&[Fr::from(1u64), Fr::from(2u64)]),
            Err(CircuitErrorV2::InputArity {
                expected: 1,
                actual: 2
            })
        );
    }

    #[test]
    fn rejects_out_of_range_wire_reference() {
        let circuit = direct_circuit(
            1,
            2,
            vec![GateV2::Add {
                left: Wire(0),
                right: Wire(2),
                output: Wire(1),
            }],
        );
        assert_eq!(
            circuit.evaluate(&[Fr::from(1u64)]),
            Err(CircuitErrorV2::WireOutOfRange {
                gate: 0,
                wire: Wire(2),
                num_wires: 2
            })
        );
    }

    #[test]
    fn rejects_forward_wire_reference() {
        let circuit = direct_circuit(
            1,
            3,
            vec![
                GateV2::Add {
                    left: Wire(0),
                    right: Wire(2),
                    output: Wire(1),
                },
                GateV2::AddConst {
                    input: Wire(1),
                    constant: Fr::from(1u64),
                    output: Wire(2),
                },
            ],
        );
        assert_eq!(
            circuit.evaluate(&[Fr::from(1u64)]),
            Err(CircuitErrorV2::WireNotDefined {
                gate: 0,
                wire: Wire(2)
            })
        );
    }

    #[test]
    fn rejects_non_sequential_or_reused_output_wire() {
        let circuit = direct_circuit(
            1,
            3,
            vec![GateV2::AddConst {
                input: Wire(0),
                constant: Fr::from(1u64),
                output: Wire(2),
            }],
        );
        assert_eq!(
            circuit.evaluate(&[Fr::from(1u64)]),
            Err(CircuitErrorV2::NonSequentialOutput {
                gate: 0,
                expected: 1,
                actual: 2
            })
        );

        let circuit = direct_circuit(
            1,
            3,
            vec![
                GateV2::AddConst {
                    input: Wire(0),
                    constant: Fr::from(1u64),
                    output: Wire(1),
                },
                GateV2::AddConst {
                    input: Wire(1),
                    constant: Fr::from(1u64),
                    output: Wire(1),
                },
            ],
        );
        assert_eq!(
            circuit.evaluate(&[Fr::from(1u64)]),
            Err(CircuitErrorV2::NonSequentialOutput {
                gate: 1,
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn rejects_unsatisfied_assertion_and_unused_wires() {
        let circuit = direct_circuit(
            1,
            1,
            vec![GateV2::AssertEq {
                input: Wire(0),
                expected: Fr::from(2u64),
            }],
        );
        assert!(matches!(
            circuit.evaluate(&[Fr::from(1u64)]),
            Err(CircuitErrorV2::UnsatisfiedAssertion { gate: 0, .. })
        ));

        let circuit = direct_circuit(1, 2, vec![]);
        assert_eq!(
            circuit.evaluate(&[Fr::from(1u64)]),
            Err(CircuitErrorV2::UnusedWires {
                defined: 1,
                num_wires: 2
            })
        );
    }

    #[test]
    fn explicit_wire_indexes_survive_building() {
        let mut builder = CircuitBuilderV2::new(2);
        let sum = builder.add(Wire(0), Wire(1));
        let product = builder.mul(sum, Wire(0));
        let circuit = builder.build();
        assert_eq!(sum, Wire(2));
        assert_eq!(product, Wire(3));
        assert_eq!(circuit.num_inputs(), 2);
        assert_eq!(circuit.num_wires(), 4);
        assert_eq!(circuit.gates().len(), 2);
        let values = circuit
            .evaluate(&[Fr::from(3u64), Fr::from(4u64)])
            .unwrap();
        assert_eq!(values[2], Fr::from(7u64));
        assert_eq!(values[3], Fr::from(21u64));
    }
}
