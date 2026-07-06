//! MPC-in-the-Head emulation.
//!
//! All wire shares are kept in the additive domain (Z_{2^32}).
//! Non-linear gates (Mul) reconstruct the value, compute the result,
//! then re-share it additively.  Linear gates (Add, AddConst, MulConst,
//! Xor, AssertEq) are computed locally from input shares.
//!
//! Each party's randomness is derived deterministically from its seed via
//! a per-party ChaCha20 RNG, so the verifier can recompute any opened
//! party's wire shares from the seed alone.  Only Mul-gate output shares
//! (freshly re-shared from a global RNG) are stored in the proof.

use crate::{
    circuit::{Circuit, Gate},
    sharing::{PartySeed, SharedTrace, Sharing},
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Broadcast message for a multiplication gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastMessage {
    pub left_share: u32,
    pub right_share: u32,
}

/// A single party's complete view of the execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyView {
    pub party_idx: usize,
    /// The party's 32-byte seed. Skipped during serialization — the verifier
    /// reconstructs it from the seed-tree co-path instead of reading it from
    /// the proof, saving (N‑1) × 32 bytes per repetition.
    #[serde(skip)]
    pub seed: [u8; 32],
    pub broadcast_messages: Vec<BroadcastMessage>,
    /// One u32 per multiplication gate, in circuit order.
    pub mul_output_shares: Vec<u32>,
    /// Full wire shares — kept for in-memory use and tamper detection but
    /// NOT serialized (the verifier recomputes them from the seed).
    #[serde(skip)]
    pub wire_shares: Vec<u32>,
}

impl PartyView {
    pub fn to_commitment_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.seed);
        for msg in &self.broadcast_messages {
            bytes.extend_from_slice(&msg.left_share.to_le_bytes());
            bytes.extend_from_slice(&msg.right_share.to_le_bytes());
        }
        for &share in &self.mul_output_shares {
            bytes.extend_from_slice(&share.to_le_bytes());
        }
        bytes
    }

    pub fn to_commitment_bytes_with_seed(&self, seed: &[u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(seed);
        for msg in &self.broadcast_messages {
            bytes.extend_from_slice(&msg.left_share.to_le_bytes());
            bytes.extend_from_slice(&msg.right_share.to_le_bytes());
        }
        for &share in &self.mul_output_shares {
            bytes.extend_from_slice(&share.to_le_bytes());
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
pub fn run_mpc_emulation(
    circuit: &Circuit,
    witness: &[u32],
    party_seeds: &[PartySeed],
    global_rng: &mut (impl RngCore + CryptoRng),
) -> crate::Result<MpcExecution> {
    let num_parties = party_seeds.len();
    assert!(num_parties >= 2);

    let mut shared_trace = SharedTrace::new(circuit.num_wires, num_parties);
    let mut party_broadcasts: Vec<Vec<BroadcastMessage>> = vec![Vec::new(); num_parties];

    let mut party_rngs: Vec<_> = party_seeds
        .iter()
        .map(|s| s.to_rng(b"mpcith-party-share"))
        .collect();

    for &value in witness.iter() {
        shared_trace
            .wires
            .push(Sharing::share_with_rngs(value, num_parties, &mut party_rngs));
    }

    for gate in &circuit.gates {
        match gate {
            Gate::Add {
                left,
                right,
                output: _,
            } => {
                let s = shared_trace.wires[*left].add(&shared_trace.wires[*right]);
                shared_trace.wires.push(s);
            }
            Gate::Mul {
                left,
                right,
                output: _,
            } => {
                for p in 0..num_parties {
                    party_broadcasts[p].push(BroadcastMessage {
                        left_share: shared_trace.wires[*left].shares[p],
                        right_share: shared_trace.wires[*right].shares[p],
                    });
                }
                let x = shared_trace.wires[*left].reconstruct();
                let y = shared_trace.wires[*right].reconstruct();
                shared_trace
                    .wires
                    .push(Sharing::share(x.wrapping_mul(y), num_parties, global_rng));
            }
            Gate::Xor {
                left,
                right,
                output: _,
            } => {
                let x = shared_trace.wires[*left].reconstruct();
                let y = shared_trace.wires[*right].reconstruct();
                shared_trace
                    .wires
                    .push(Sharing::share(x ^ y, num_parties, global_rng));
            }
            Gate::AddConst {
                input,
                constant,
                output: _,
            } => {
                let s = shared_trace.wires[*input].add_const(*constant);
                shared_trace.wires.push(s);
            }
            Gate::MulConst {
                input,
                constant,
                output: _,
            } => {
                let s = shared_trace.wires[*input].mul_const(*constant);
                shared_trace.wires.push(s);
            }
            Gate::AssertEq {
                input,
                expected: _,
                output: _,
            } => {
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
        .map(|p| {
            let mul_output_shares: Vec<u32> = circuit
                .gates
                .iter()
                .filter_map(|g| {
                    if matches!(g, Gate::Mul { .. } | Gate::Xor { .. }) {
                        if let Gate::Mul { output, .. } | Gate::Xor { output, .. } = g {
                            Some(shared_trace.wires[*output].shares[p])
                        } else {
                            unreachable!()
                        }
                    } else {
                        None
                    }
                })
                .collect();
            PartyView {
                party_idx: p,
                seed: party_seeds[p].0,
                broadcast_messages: party_broadcasts[p].clone(),
                mul_output_shares,
                wire_shares: shared_trace.party_view(p),
            }
        })
        .collect();

    Ok(MpcExecution {
        views,
        shared_trace,
        output_values,
    })
}

/// Recompute a party's full wire-share vector from its seed and the
/// circuit structure, plus the non-deterministic Mul-gate output shares.
pub fn recompute_linear_shares(
    circuit: &Circuit,
    seed: &[u8; 32],
    party_idx: usize,
    _num_parties: usize,
    mul_output_shares: &[u32],
) -> Vec<u32> {
    let party_seed = PartySeed(*seed);
    let mut party_rng = party_seed.to_rng(b"mpcith-party-share");

    let total_wires = circuit.num_wires;
    let mut shares = vec![0u32; total_wires];

    // Derive this party's shares of witness/input wires from the RNG.
    for i in 0..circuit.num_inputs {
        shares[i] = party_rng.next_u32();
    }

    // Walk the gates in circuit order.
    let mut nonlinear_idx = 0;
    for gate in &circuit.gates {
        match gate {
            Gate::Add {
                left,
                right,
                output,
            } => {
                shares[*output] = shares[*left].wrapping_add(shares[*right]);
            }
            Gate::Mul { output, .. } | Gate::Xor { output, .. } => {
                shares[*output] = mul_output_shares[nonlinear_idx];
                nonlinear_idx += 1;
            }
            Gate::AddConst {
                input,
                constant,
                output,
            } => {
                shares[*output] = if party_idx == 0 {
                    shares[*input].wrapping_add(*constant)
                } else {
                    shares[*input]
                };
            }
            Gate::MulConst {
                input,
                constant,
                output,
            } => {
                shares[*output] = shares[*input].wrapping_mul(*constant);
            }
            Gate::AssertEq {
                input,
                output, ..
            } => {
                shares[*output] = shares[*input];
            }
        }
    }

    shares
}

/// Verify a single party's view is consistent with linear gates.
pub fn verify_party_view(
    circuit: &Circuit,
    wire_shares: &[u32],
    party_idx: usize,
    broadcast_messages: &[BroadcastMessage],
) -> crate::Result<()> {
    let mul_gates: Vec<(usize, usize)> = circuit
        .gates
        .iter()
        .filter_map(|g| {
            if let Gate::Mul { left, right, .. } = g {
                Some((*left, *right))
            } else {
                None
            }
        })
        .collect();

    for (msg, (left, right)) in broadcast_messages.iter().zip(mul_gates.iter()) {
        if msg.left_share != wire_shares[*left] || msg.right_share != wire_shares[*right] {
            return Err(crate::MpcithError::ConsistencyCheckFailed(party_idx));
        }
    }

    for gate in &circuit.gates {
        match gate {
            Gate::Add {
                left,
                right,
                output,
            } => {
                let expected = wire_shares[*left].wrapping_add(wire_shares[*right]);
                if wire_shares[*output] != expected {
                    return Err(crate::MpcithError::ConsistencyCheckFailed(party_idx));
                }
            }
            Gate::AddConst {
                input,
                constant,
                output,
            } => {
                let expected = if party_idx == 0 {
                    wire_shares[*input].wrapping_add(*constant)
                } else {
                    wire_shares[*input]
                };
                if wire_shares[*output] != expected {
                    return Err(crate::MpcithError::ConsistencyCheckFailed(party_idx));
                }
            }
            Gate::MulConst {
                input,
                constant,
                output,
            } => {
                let expected = wire_shares[*input].wrapping_mul(*constant);
                if wire_shares[*output] != expected {
                    return Err(crate::MpcithError::ConsistencyCheckFailed(party_idx));
                }
            }
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
            let ws = recompute_linear_shares(
                &circuit,
                &view.seed,
                view.party_idx,
                3,
                &view.mul_output_shares,
            );
            verify_party_view(&circuit, &ws, view.party_idx, &view.broadcast_messages).unwrap();
        }
    }
}
