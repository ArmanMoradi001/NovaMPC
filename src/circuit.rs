//! Boolean/arithmetic circuit representation.
//!
//! We work over Z_{2^32} (u32 arithmetic, wrapping).
//! Gates operate on wire indices into a wire vector.
//! The first `num_inputs` wires are the witness (private inputs).
//! The last `num_outputs` wires hold the circuit output.
//!
//! Evaluation produces a *trace*: the value of every wire, which is what
//! each MPC party holds a share of.

use serde::{Deserialize, Serialize};

/// A single gate in the arithmetic circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Gate {
    /// output_wire = left_wire + right_wire  (mod 2^32)
    Add {
        left: usize,
        right: usize,
        output: usize,
    },
    /// output_wire = left_wire * right_wire  (mod 2^32)
    /// Note: multiplication requires inter-party communication in MPC.
    Mul {
        left: usize,
        right: usize,
        output: usize,
    },
    /// output_wire = left_wire XOR right_wire  (bitwise)
    Xor {
        left: usize,
        right: usize,
        output: usize,
    },
    /// output_wire = input_wire + constant  (mod 2^32)
    AddConst {
        input: usize,
        constant: u32,
        output: usize,
    },
    /// output_wire = input_wire * constant  (mod 2^32)
    MulConst {
        input: usize,
        constant: u32,
        output: usize,
    },
    /// Asserts output_wire == expected (checked during verification).
    /// The "output" wire simply copies the input wire.
    AssertEq {
        input: usize,
        expected: u32,
        output: usize,
    },
}

impl Gate {
    /// Returns the output wire index.
    pub fn output_wire(&self) -> usize {
        match self {
            Gate::Add { output, .. }
            | Gate::Mul { output, .. }
            | Gate::Xor { output, .. }
            | Gate::AddConst { output, .. }
            | Gate::MulConst { output, .. }
            | Gate::AssertEq { output, .. } => *output,
        }
    }

    /// Returns true if this gate requires inter-party communication (i.e., is non-linear).
    pub fn is_interactive(&self) -> bool {
        matches!(self, Gate::Mul { .. })
    }
}

/// A complete arithmetic circuit over Z_{2^32}.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Circuit {
    /// Total number of wires (inputs + intermediate + outputs).
    pub num_wires: usize,
    /// Number of input (witness) wires (indices 0..num_inputs).
    pub num_inputs: usize,
    /// Number of output wires (last num_outputs wires).
    pub num_outputs: usize,
    /// Gates in topological order.
    pub gates: Vec<Gate>,
}

impl Circuit {
    /// Evaluate the circuit on a concrete witness.
    /// Returns the full wire assignment (trace).
    pub fn evaluate(&self, witness: &[u32]) -> crate::Result<Vec<u32>> {
        if witness.len() != self.num_inputs {
            return Err(crate::MpcithError::CircuitError(format!(
                "Expected {} witness values, got {}",
                self.num_inputs,
                witness.len()
            )));
        }

        let mut wires = vec![0u32; self.num_wires];
        // Load witness into input wires.
        wires[..self.num_inputs].copy_from_slice(witness);

        for gate in &self.gates {
            match gate {
                Gate::Add { left, right, output } => {
                    wires[*output] = wires[*left].wrapping_add(wires[*right]);
                }
                Gate::Mul { left, right, output } => {
                    wires[*output] = wires[*left].wrapping_mul(wires[*right]);
                }
                Gate::Xor { left, right, output } => {
                    wires[*output] = wires[*left] ^ wires[*right];
                }
                Gate::AddConst { input, constant, output } => {
                    wires[*output] = wires[*input].wrapping_add(*constant);
                }
                Gate::MulConst { input, constant, output } => {
                    wires[*output] = wires[*input].wrapping_mul(*constant);
                }
                Gate::AssertEq { input, expected, output } => {
                    wires[*output] = wires[*input];
                    if wires[*input] != *expected {
                        return Err(crate::MpcithError::CircuitError(format!(
                            "AssertEq failed: wire {} = {}, expected {}",
                            input, wires[*input], expected
                        )));
                    }
                }
            }
        }

        Ok(wires)
    }

    /// Returns the output wire values given a full trace.
    pub fn outputs<'a>(&self, trace: &'a [u32]) -> &'a [u32] {
        &trace[self.num_wires - self.num_outputs..]
    }

    /// Number of multiplication (interactive) gates.
    pub fn num_mul_gates(&self) -> usize {
        self.gates.iter().filter(|g| g.is_interactive()).count()
    }
}

/// Builder for circuits — cleaner than constructing directly.
#[derive(Debug, Default)]
pub struct CircuitBuilder {
    num_inputs: usize,
    next_wire: usize,
    gates: Vec<Gate>,
}

impl CircuitBuilder {
    pub fn new(num_inputs: usize) -> Self {
        Self {
            num_inputs,
            next_wire: num_inputs,
            gates: Vec::new(),
        }
    }

    fn alloc(&mut self) -> usize {
        let w = self.next_wire;
        self.next_wire += 1;
        w
    }

    /// Allocate a new input (witness) wire and return its index.
    pub fn add_input(&mut self) -> usize {
        let w = self.next_wire;
        self.next_wire += 1;
        self.num_inputs += 1;
        w
    }

    pub fn add(&mut self, left: usize, right: usize) -> usize {
        let output = self.alloc();
        self.gates.push(Gate::Add { left, right, output });
        output
    }

    pub fn mul(&mut self, left: usize, right: usize) -> usize {
        let output = self.alloc();
        self.gates.push(Gate::Mul { left, right, output });
        output
    }

    pub fn xor(&mut self, left: usize, right: usize) -> usize {
        let output = self.alloc();
        self.gates.push(Gate::Xor { left, right, output });
        output
    }

    pub fn add_const(&mut self, input: usize, constant: u32) -> usize {
        let output = self.alloc();
        self.gates.push(Gate::AddConst { input, constant, output });
        output
    }

    pub fn mul_const(&mut self, input: usize, constant: u32) -> usize {
        let output = self.alloc();
        self.gates.push(Gate::MulConst { input, constant, output });
        output
    }

    pub fn assert_eq(&mut self, input: usize, expected: u32) -> usize {
        let output = self.alloc();
        self.gates.push(Gate::AssertEq { input, expected, output });
        output
    }

    pub fn build(self, num_outputs: usize) -> Circuit {
        Circuit {
            num_wires: self.next_wire,
            num_inputs: self.num_inputs,
            num_outputs,
            gates: self.gates,
        }
    }
}

/// Bit-decompose an input wire into `bit_count` individual bit wires.
///
/// Allocates `bit_count` new **input** wires for the prover to supply the
/// bit values, then adds constraint gates that enforce:
///   1. Each bit is boolean:  b_i * (b_i - 1) == 0
///   2. Reconstruction:       Σ b_i · 2^i == input_wire
///
/// Returns the wire indices of the allocated bit wires (b_0 .. b_{n-1}).
pub fn bit_decompose(
    builder: &mut CircuitBuilder,
    input_wire: usize,
    bit_count: usize,
) -> Vec<usize> {
    let bit_wires: Vec<usize> = (0..bit_count).map(|_| builder.add_input()).collect();

    // Boolean checks: b_i * (b_i - 1) == 0
    for &b in &bit_wires {
        let b_minus_1 = builder.add_const(b, u32::MAX); // b + (2^32-1) ≡ b - 1
        let product = builder.mul(b, b_minus_1);
        builder.assert_eq(product, 0);
    }

    // Reconstruction: sum = Σ b_i * 2^i
    let mut sum = bit_wires[0];
    for i in 1..bit_count {
        let weighted = builder.mul_const(bit_wires[i], 1u32 << i);
        sum = builder.add(sum, weighted);
    }

    // Assert sum == input_wire.
    // XOR(a, a) == 0, so xor(sum, input_wire) should be 0 when equal.
    let diff = builder.xor(sum, input_wire);
    builder.assert_eq(diff, 0);

    bit_wires
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addition_circuit() {
        // Circuit: assert x + y == 7
        let mut builder = CircuitBuilder::new(2); // wires 0=x, 1=y
        let sum = builder.add(0, 1);               // wire 2 = x + y
        let _out = builder.assert_eq(sum, 7);       // wire 3, asserts == 7
        let circuit = builder.build(1);

        let trace = circuit.evaluate(&[3, 4]).unwrap();
        assert_eq!(trace[2], 7);

        // Wrong witness should fail
        assert!(circuit.evaluate(&[3, 5]).is_err());
    }

    #[test]
    fn test_multiplication_circuit() {
        // Circuit: z = x * y, assert z == 12
        let mut builder = CircuitBuilder::new(2);
        let prod = builder.mul(0, 1);
        let _out = builder.assert_eq(prod, 12);
        let circuit = builder.build(1);

        let trace = circuit.evaluate(&[3, 4]).unwrap();
        assert_eq!(trace[2], 12);
    }

    #[test]
    fn test_bit_decompose_42() {
        let mut builder = CircuitBuilder::new(1);
        let bits = bit_decompose(&mut builder, 0, 32);
        let circuit = builder.build(0);

        let value = 42u32;
        let mut witness = vec![value];
        for i in 0..32 {
            witness.push((value >> i) & 1);
        }

        let trace = circuit.evaluate(&witness).unwrap();
        for i in 0..32 {
            let expected_bit = (value >> i) & 1;
            assert_eq!(trace[bits[i]], expected_bit, "bit {i} mismatch");
        }
    }

    #[test]
    fn test_bit_decompose_rejects_non_bit() {
        let mut builder = CircuitBuilder::new(1);
        let _bits = bit_decompose(&mut builder, 0, 32);
        let circuit = builder.build(0);

        let value = 42u32;
        let mut witness = vec![value];
        for i in 0..32 {
            if i == 3 {
                witness.push(2); // not a valid boolean value
            } else {
                witness.push((value >> i) & 1);
            }
        }

        assert!(circuit.evaluate(&witness).is_err());
    }

    #[test]
    fn test_bit_decompose_reconstruction() {
        for &value in &[0u32, 1, 255, 65535, u32::MAX] {
            let mut builder = CircuitBuilder::new(1);
            let _bits = bit_decompose(&mut builder, 0, 32);
            let circuit = builder.build(0);

            let mut witness = vec![value];
            for i in 0..32 {
                witness.push((value >> i) & 1);
            }

            assert!(circuit.evaluate(&witness).is_ok(), "Failed for value {value}");
        }
    }
}
