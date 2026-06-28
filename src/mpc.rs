//! MPC-in-the-Head emulation.
//!
//! All wire shares are kept in the additive domain (Z_{2^32}).
//! Non-linear gates (Mul, Xor) reconstruct the value, compute the result,
//! then re-share it additively. This is correct for the MPCitH proof structure:
//! the prover simulates all parties and records their views.

use crate::{
    circuit::{Circuit, Gate},
    sharing::{PartySeed, SharedTrace, Sharing},
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Broadcast message for a multiplication gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastMessage {
    pub sender: usize,
    pub output_wire: usize,
    pub left_share: u32,
    pub right_share: u32,
}

/// A single party's complete view of the execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyView {
    pub party_idx: usize,
    pub seed: [u8; 32],
    pub broadcast_messages: Vec<BroadcastMessage>,
    /// All wire shares for this party (one per wire, additive domain).
    pub wire_shares: Vec<u32>,
}

impl PartyView {
    pub fn to_commitment_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.seed);
        for msg in &self.broadcast_messages {
            bytes.extend_from_slice(&msg.sender.to_le_bytes());
            bytes.extend_from_slice(&msg.output_wire.to_le_bytes());
            bytes.extend_from_slice(&msg.left_share.to_le_bytes());
            bytes.extend_from_slice(&msg.right_share.to_le_bytes());
        }
        bytes
    }
}

/// Result of running the MPC emulation for one repetition.
#[derive(Debug, Clone)]
pub struct MpcExecution {
    pub views: Vec<PartyView>,
    pub shared_trace: SharedTrace,
    pub output_values: Vec<u32>,
}

/// Run the MPC-in-the-Head emulation for one repetition.
pub fn run_mpc_emulation<R: RngCore + CryptoRng>(
    circuit: &Circuit,
    witness: &[u32],
    party_seeds: &[PartySeed],
    rng: &mut R,
) -> crate::Result<MpcExecution> {
    let num_parties = party_seeds.len();
    assert!(num_parties >= 2);

    let mut shared_trace = SharedTrace::new(circuit.num_wires, num_parties);
    let mut party_broadcasts: Vec<Vec<BroadcastMessage>> = vec![Vec::new(); num_parties];

    // Share the witness wires additively.
    for &value in witness.iter() {
        shared_trace.wires.push(Sharing::share(value, num_parties, rng));
    }

    // Evaluate gates. All outputs are stored as additive sharings.
    for gate in &circuit.gates {
        match gate {
            Gate::Add { left, right, output: _ } => {
                let s = shared_trace.wires[*left].add(&shared_trace.wires[*right]);
                shared_trace.wires.push(s);
            }
            Gate::Mul { left, right, output } => {
                // Broadcast left+right shares, then reconstruct and re-share.
                let broadcasts: Vec<BroadcastMessage> = (0..num_parties)
                    .map(|p| BroadcastMessage {
                        sender: p,
                        output_wire: *output,
                        left_share: shared_trace.wires[*left].shares[p],
                        right_share: shared_trace.wires[*right].shares[p],
                    })
                    .collect();
                for p in 0..num_parties {
                    party_broadcasts[p].push(broadcasts[p].clone());
                }
                let x = shared_trace.wires[*left].reconstruct();
                let y = shared_trace.wires[*right].reconstruct();
                shared_trace.wires.push(Sharing::share(x.wrapping_mul(y), num_parties, rng));
            }
            Gate::Xor { left, right, output: _ } => {
                // Reconstruct, XOR, re-share additively.
                let x = shared_trace.wires[*left].reconstruct();
                let y = shared_trace.wires[*right].reconstruct();
                shared_trace.wires.push(Sharing::share(x ^ y, num_parties, rng));
            }
            Gate::AddConst { input, constant, output: _ } => {
                // Add constant to party 0's share only.
                let s = shared_trace.wires[*input].add_const(*constant);
                shared_trace.wires.push(s);
            }
            Gate::MulConst { input, constant, output: _ } => {
                let s = shared_trace.wires[*input].mul_const(*constant);
                shared_trace.wires.push(s);
            }
            Gate::AssertEq { input, expected: _, output: _ } => {
                let s = shared_trace.wires[*input].clone();
                shared_trace.wires.push(s);
            }
        }
    }

    let output_start = circuit.num_wires - circuit.num_outputs;
    let output_values: Vec<u32> = (output_start..circuit.num_wires)
        .map(|w| shared_trace.wires[w].reconstruct())
        .collect();

    let views: Vec<PartyView> = (0..num_parties)
        .map(|p| PartyView {
            party_idx: p,
            seed: party_seeds[p].0,
            broadcast_messages: party_broadcasts[p].clone(),
            wire_shares: shared_trace.party_view(p),
        })
        .collect();

    Ok(MpcExecution { views, shared_trace, output_values })
}

/// Verify a single party's view is consistent with linear gates.
/// Mul and Xor gates are non-local (re-shared), so only Add/AddConst/MulConst
/// are checked locally. Mul is checked via broadcast messages.
pub fn verify_party_view(
    circuit: &Circuit,
    view: &PartyView,
    _public_inputs: &[u32],
    _num_parties: usize,
) -> crate::Result<()> {
    let ws = &view.wire_shares;

    // Check multiplication broadcast consistency.
    for msg in view.broadcast_messages.iter().filter(|m| m.sender == view.party_idx) {
        for gate in &circuit.gates {
            if let Gate::Mul { left, right, output } = gate {
                if *output == msg.output_wire {
                    if msg.left_share != ws[*left] || msg.right_share != ws[*right] {
                        return Err(crate::MpcithError::ConsistencyCheckFailed(view.party_idx));
                    }
                }
            }
        }
    }

    // Check linear gates locally.
    for gate in &circuit.gates {
        match gate {
            Gate::Add { left, right, output } => {
                let expected = ws[*left].wrapping_add(ws[*right]);
                if ws[*output] != expected {
                    return Err(crate::MpcithError::ConsistencyCheckFailed(view.party_idx));
                }
            }
            Gate::AddConst { input, constant, output } => {
                // Only party 0 gets the constant added.
                let expected = if view.party_idx == 0 {
                    ws[*input].wrapping_add(*constant)
                } else {
                    ws[*input]
                };
                if ws[*output] != expected {
                    return Err(crate::MpcithError::ConsistencyCheckFailed(view.party_idx));
                }
            }
            Gate::MulConst { input, constant, output } => {
                let expected = ws[*input].wrapping_mul(*constant);
                if ws[*output] != expected {
                    return Err(crate::MpcithError::ConsistencyCheckFailed(view.party_idx));
                }
            }
            // Mul, Xor, AssertEq: non-local or copy, skip.
            Gate::Mul { .. } | Gate::Xor { .. } | Gate::AssertEq { .. } => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::CircuitBuilder;
    use rand::thread_rng;

    fn make_addition_circuit() -> Circuit {
        let mut b = CircuitBuilder::new(2);
        let sum = b.add(0, 1);
        let _out = b.assert_eq(sum, 7);
        b.build(1)
    }

    #[test]
    fn test_mpc_emulation_addition() {
        let circuit = make_addition_circuit();
        let mut rng = thread_rng();
        let seeds: Vec<PartySeed> = (0..3).map(|_| PartySeed::random(&mut rng)).collect();
        let exec = run_mpc_emulation(&circuit, &[3u32, 4u32], &seeds, &mut rng).unwrap();

        assert_eq!(exec.output_values, vec![7]);
        assert_eq!(exec.shared_trace.wires[0].reconstruct(), 3);
        assert_eq!(exec.shared_trace.wires[1].reconstruct(), 4);
        assert_eq!(exec.shared_trace.wires[2].reconstruct(), 7);
    }

    #[test]
    fn test_view_consistency() {
        let circuit = make_addition_circuit();
        let mut rng = thread_rng();
        let seeds: Vec<PartySeed> = (0..3).map(|_| PartySeed::random(&mut rng)).collect();
        let exec = run_mpc_emulation(&circuit, &[3u32, 4u32], &seeds, &mut rng).unwrap();

        for view in &exec.views {
            verify_party_view(&circuit, view, &[7], 3).unwrap();
        }
    }
}
