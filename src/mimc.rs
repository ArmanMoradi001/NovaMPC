//! MiMC-2n/n Feistel hash, built as an arithmetic circuit.
//!
//! MiMC is circuit-friendly: it uses only addition and multiplication gates
//! (no bit operations), making it ideal for MPC-in-the-Head proofs.
//!
//! The Feistel variant maps (left, right) → (left', right') where each round:
//!   new_left  = right
//!   new_right = left + (right + c_i)^3

use crate::circuit::CircuitBuilder;

/// Default number of MiMC rounds (≥ 64 gives adequate security margin).
pub const MIMC_ROUNDS: usize = 64;

/// Domain separator for deterministic round-constant generation.
const MIMC_DOMAIN: &[u8] = b"mimc-mpcith-zk-v1";

/// Generate `num_rounds` round constants deterministically from
/// BLAKE3(MIMC_DOMAIN ‖ counter).
pub fn mimc_constants(num_rounds: usize) -> Vec<u32> {
    let mut constants = Vec::with_capacity(num_rounds);
    let mut counter = 0u32;
    while constants.len() < num_rounds {
        let mut input = MIMC_DOMAIN.to_vec();
        input.extend_from_slice(&counter.to_le_bytes());
        let h = blake3::hash(&input);
        let bytes = h.as_bytes();
        let mut i = 0;
        while i + 4 <= bytes.len() && constants.len() < num_rounds {
            constants.push(u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]));
            i += 4;
        }
        counter += 1;
    }
    constants
}

/// Build the MiMC-2n/n Feistel network inside an arithmetic circuit.
///
/// Returns `(left_out, right_out)` — wire indices of the two output words.
/// Both are guaranteed to be the **last** wires allocated by this function,
/// so the caller can set `num_outputs = 2` when calling `builder.build()`.
pub fn build_mimc_hash(
    builder: &mut CircuitBuilder,
    left_wire: usize,
    right_wire: usize,
    num_rounds: usize,
) -> (usize, usize) {
    let constants = mimc_constants(num_rounds);
    let mut left = left_wire;
    let mut right = right_wire;

    for &ci in constants.iter().take(num_rounds) {
        let temp = builder.add_const(right, ci);    // right + c_i
        let sq = builder.mul(temp, temp);            // (right + c_i)^2
        let cu = builder.mul(sq, temp);              // (right + c_i)^3
        let new_right = builder.add(left, cu);       // left + (right + c_i)^3
        let new_left = right;

        left = new_left;
        right = new_right;
    }

    // Copy to fresh wires so they are the two trailing wires in the circuit.
    let left_out = builder.mul_const(left, 1);
    let right_out = builder.mul_const(right, 1);
    (left_out, right_out)
}

/// Compute MiMC-2n/n natively (no circuit), for witness generation.
pub fn mimc_hash_native(left: u32, right: u32, num_rounds: usize) -> (u32, u32) {
    let constants = mimc_constants(num_rounds);
    let mut left = left;
    let mut right = right;

    for &ci in constants.iter().take(num_rounds) {
        let temp = right.wrapping_add(ci);
        let cu = temp.wrapping_mul(temp).wrapping_mul(temp);
        let new_right = left.wrapping_add(cu);
        let new_left = right;

        left = new_left;
        right = new_right;
    }

    (left, right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mimc_native_and_circuit_agree() {
        let cases: [(u32, u32); 4] = [(0, 0), (1, 0), (0, 1), (42, 1337)];
        for &(l, r) in &cases {
            let native = mimc_hash_native(l, r, MIMC_ROUNDS);

            let mut builder = CircuitBuilder::new(2);
            let _ = build_mimc_hash(&mut builder, 0, 1, MIMC_ROUNDS);
            let circuit = builder.build(2);
            let trace = circuit.evaluate(&[l, r]).unwrap();
            let out = circuit.outputs(&trace);
            assert_eq!(
                (out[0], out[1]),
                native,
                "mismatch for input ({l}, {r})"
            );
        }
    }

    #[test]
    fn test_mimc_different_inputs_different_outputs() {
        let pairs = [
            (0u32, 0u32),
            (1, 0),
            (0, 1),
            (42, 1337),
            (1337, 42),
            (u32::MAX, u32::MAX),
        ];
        let hashes: Vec<_> = pairs
            .iter()
            .map(|&(l, r)| mimc_hash_native(l, r, MIMC_ROUNDS))
            .collect();
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "collision between pairs {i} and {j}"
                );
            }
        }
    }

    #[test]
    fn test_mimc_constants_deterministic() {
        let a = mimc_constants(MIMC_ROUNDS);
        let b = mimc_constants(MIMC_ROUNDS);
        assert_eq!(a, b);
        assert_eq!(a.len(), MIMC_ROUNDS);
        // Spot-check: first constant should not be zero (extremely unlikely).
        assert_ne!(a[0], 0);
    }
}
