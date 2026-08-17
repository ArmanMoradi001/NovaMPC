//! MPC-in-the-Head emulation.
//!
//! All wire shares are kept in the additive domain (Z_{2^32}).
//! Multiplication gates use the standard ZKBoo/ZKB++ 3-party verifiable
//! multiplication scheme: each party i holds its own seed plus its right
//! neighbour's seed ((i+1) % 3), which lets it derive a correlated
//! "zero-share" r_i(g) for every non-linear gate g such that
//! r_0 + r_1 + r_2 == 0 (mod 2^32).  The Mul output share is then
//!
//! `z_i = x_i*y_i + x_i*y_{i+1} + x_{i+1}*y_i + r_i(g)`   (mod 2^32)
//!
//! which the verifier can recompute from the opened parties' seeds alone.
//! Xor gates are still handled with the old reconstruct-and-reshare scheme
//! and are NOT verified (see [`verify_party_view`]).  Linear gates (Add,
//! AddConst, MulConst, AssertEq) are computed locally from input shares.
//!
//! Each party's randomness is derived deterministically from its seed via
//! a per-party ChaCha20 RNG, so the verifier can recompute any opened
//! party's wire shares from the seed alone.  Only non-linear gate output
//! shares are stored in the proof.

use crate::{
    circuit::{Circuit, Gate},
    sharing::{PartySeed, SharedTrace, Sharing},
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Domain tag for the zero-sharing PRG.  The non-linear gate index is
/// appended as bytes so the same party pair gets independent zero-shares
/// for different gates.
const ZERO_SHARE_TAG: &[u8] = b"mpcith-zero-share";

fn zero_share_domain(nonlinear_idx: usize) -> Vec<u8> {
    let mut domain = ZERO_SHARE_TAG.to_vec();
    domain.extend_from_slice(&nonlinear_idx.to_le_bytes());
    domain
}

/// Party i's correlated-randomness "zero share" for the non-linear gate at
/// `nonlinear_idx`:
///
/// `r_i = PRG(seed_i, tag) - PRG(seed_{i+1}, tag)`   (mod 2^32)
///
/// where `seed_{i+1}` is party i's right neighbour's seed.  Every
/// PRG(seed_j) term appears exactly once with `+` and once with `-` across
/// the three parties, so `r_0 + r_1 + r_2 == 0 (mod 2^32)` always, by
/// construction.  The PRG is the existing ChaCha20-from-seed mechanism in
/// [`PartySeed::to_rng`].
fn zero_share(own_seed: &[u8; 32], next_seed: &[u8; 32], nonlinear_idx: usize) -> u32 {
    let domain = zero_share_domain(nonlinear_idx);
    let own = PartySeed(*own_seed).to_rng(&domain).next_u32();
    let next = PartySeed(*next_seed).to_rng(&domain).next_u32();
    own.wrapping_sub(next)
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
    /// One u32 per non-linear gate (Mul, Xor), in circuit order.
    pub mul_output_shares: Vec<u32>,
    /// Input-wire shares of the *residual* party (index N-1).  Additive input
    /// sharing gives the last party the residual `value − Σ_{i<N-1} share_i`,
    /// which is NOT derivable from that party's seed alone, so it is
    /// transmitted and committed like [`mul_output_shares`].  Empty for all
    /// other parties.  The verifier uses these to rebuild the residual party's
    /// input wires instead of drawing them from its seed RNG.
    pub residual_input_shares: Vec<u32>,
    /// Full wire shares — kept for in-memory use and tamper detection but
    /// NOT serialized (the verifier recomputes them from the seed).
    #[serde(skip)]
    pub wire_shares: Vec<u32>,
}

impl PartyView {
    pub fn to_commitment_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.seed);
        for &share in &self.mul_output_shares {
            bytes.extend_from_slice(&share.to_le_bytes());
        }
        for &share in &self.residual_input_shares {
            bytes.extend_from_slice(&share.to_le_bytes());
        }
        bytes
    }

    pub fn to_commitment_bytes_with_seed(&self, seed: &[u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(seed);
        for &share in &self.mul_output_shares {
            bytes.extend_from_slice(&share.to_le_bytes());
        }
        for &share in &self.residual_input_shares {
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
    assert_eq!(
        num_parties, 3,
        "the verifiable ZKBoo multiplication scheme requires exactly 3 parties"
    );

    let mut shared_trace = SharedTrace::new(circuit.num_wires, num_parties);

    let mut party_rngs: Vec<_> = party_seeds
        .iter()
        .map(|s| s.to_rng(b"mpcith-party-share"))
        .collect();

    for &value in witness.iter() {
        shared_trace
            .wires
            .push(Sharing::share_with_rngs(value, num_parties, &mut party_rngs));
    }

    // Index of the current non-linear (Mul/Xor) gate within `mul_output_shares`
    // and within the zero-sharing PRG domain.  Incremented for every Mul/Xor
    // gate so prover and verifier agree on the domain tag per gate.
    let mut nonlinear_idx = 0;

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
                // ZKBoo verifiable multiplication over Z_{2^32}.  Party i's
                // output share is computed from its own input shares (x_i, y_i)
                // and its right neighbour's (x_{i+1}, y_{i+1}), plus the
                // correlated zero-share r_i(g):
                //     z_i = x_i*y_i + x_i*y_{i+1} + x_{i+1}*y_i + r_i(g)
                let x = &shared_trace.wires[*left].shares;
                let y = &shared_trace.wires[*right].shares;
                let mut z = vec![0u32; num_parties];
                for p in 0..num_parties {
                    let next = (p + 1) % num_parties;
                    let r = zero_share(&party_seeds[p].0, &party_seeds[next].0, nonlinear_idx);
                    z[p] = x[p]
                        .wrapping_mul(y[p])
                        .wrapping_add(x[p].wrapping_mul(y[next]))
                        .wrapping_add(x[next].wrapping_mul(y[p]))
                        .wrapping_add(r);
                }
                nonlinear_idx += 1;
                shared_trace.wires.push(Sharing { shares: z });
            }
            Gate::Xor {
                left,
                right,
                output: _,
            } => {
                // TODO(security): Xor gate output shares are NOT verified by
                // the verifier (see verify_party_view).  We keep the old
                // reconstruct-and-reshare here; a proper fix requires bit-level
                // GF(2) sharing.  The counter is still advanced so that
                // mul_output_shares indices stay aligned.
                let x = shared_trace.wires[*left].reconstruct();
                let y = shared_trace.wires[*right].reconstruct();
                shared_trace
                    .wires
                    .push(Sharing::share(x ^ y, num_parties, global_rng));
                nonlinear_idx += 1;
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
            // The last party's input shares are residuals
            // (`value − Σ_{i<N-1} share_i`) and so cannot be re-derived from
            // its seed; transmit them so the verifier can rebuild its input
            // wires.  Other parties draw all input shares from their own seed
            // RNGs, so they transmit nothing.
            let residual_input_shares: Vec<u32> = if p == num_parties - 1 {
                (0..circuit.num_inputs)
                    .map(|w| shared_trace.wires[w].shares[p])
                    .collect()
            } else {
                Vec::new()
            };
            PartyView {
                party_idx: p,
                seed: party_seeds[p].0,
                mul_output_shares,
                residual_input_shares,
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
/// circuit structure, plus the non-deterministic Mul/Xor-gate output shares.
///
/// For the *residual* party (index `num_parties-1`) the input wires cannot be
/// derived from its seed (they are `value − Σ_{i<N-1} share_i`), so the
/// transmitted `residual_input_shares` are used instead of the seed RNG.
pub fn recompute_linear_shares(
    circuit: &Circuit,
    seed: &[u8; 32],
    party_idx: usize,
    num_parties: usize,
    mul_output_shares: &[u32],
    residual_input_shares: &[u32],
) -> Vec<u32> {
    let party_seed = PartySeed(*seed);
    let mut party_rng = party_seed.to_rng(b"mpcith-party-share");

    let total_wires = circuit.num_wires;
    let mut shares = vec![0u32; total_wires];

    let is_residual_party = party_idx == num_parties - 1 && !residual_input_shares.is_empty();
    for i in 0..circuit.num_inputs {
        shares[i] = if is_residual_party {
            residual_input_shares[i]
        } else {
            party_rng.next_u32()
        };
    }

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

/// Verify a single party's view is consistent with the circuit.
///
/// Linear gates (Add, AddConst, MulConst) are fully checked.  Mul gates are
/// checked using the ZKBoo 3-party verifiable-multiplication formula whenever
/// this party's right neighbour (`(party_idx+1) % 3`) is ALSO opened, i.e.
/// `next_opened` is `Some((next_seed, next_wire_shares))`: the verifier then
/// has both parties' wire shares and both seeds and can fully recompute the
/// claimed `mul_output_shares` entry.  When the neighbour is the hidden party
/// the share is structurally unverifiable by design in this 2-of-3 scheme and
/// is skipped — the OTHER opened party's share always gets fully checked,
/// because with only 1 of 3 parties hidden, at least one opened party always
/// has its neighbour opened too.
///
/// Xor gates are currently NOT checked (the additive Z_{2^32} sharing cannot
/// verify XOR locally); AssertEq just copies its input through and output
/// correctness is handled separately.  Both are flagged with TODO(security).
pub fn verify_party_view(
    circuit: &Circuit,
    wire_shares: &[u32],
    party_idx: usize,
    party_seed: &[u8; 32],
    next_opened: Option<(&[u8; 32], &[u32])>,
) -> crate::Result<()> {
    let mut nonlinear_idx = 0;
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
            Gate::Mul { left, right, output } => {
                if let Some((next_seed, next_shares)) = next_opened {
                    // Recompute this party's Mul output share from both parties'
                    // seeds and wire shares:
                    //     z_p = x_p*y_p + x_p*y_{p+1} + x_{p+1}*y_p + r_p(g)
                    let r = zero_share(party_seed, next_seed, nonlinear_idx);
                    let expected = wire_shares[*left]
                        .wrapping_mul(wire_shares[*right])
                        .wrapping_add(wire_shares[*left].wrapping_mul(next_shares[*right]))
                        .wrapping_add(next_shares[*left].wrapping_mul(wire_shares[*right]))
                        .wrapping_add(r);
                    if wire_shares[*output] != expected {
                        return Err(crate::MpcithError::ConsistencyCheckFailed(party_idx));
                    }
                }
                // else: this party's right neighbour is the hidden party — its
                // Mul share is structurally unverifiable from opened data alone
                // (standard for the 2-of-3 scheme).
                nonlinear_idx += 1;
            }
            Gate::Xor { .. } => {
                // TODO(security): Xor gate output shares are not verified.  The
                // current additive Z_{2^32} sharing cannot check XOR locally; a
                // proper fix requires bit-level GF(2) sharing.
                nonlinear_idx += 1;
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
            Gate::AssertEq { .. } => {
                // TODO(security): AssertEq / output correctness is handled in a
                // follow-up task.  The gate just copies its input wire through.
            }
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

        // All three views are available (no hidden party), so every party's
        // right neighbour is "opened": pass its seed and wire shares.
        let all_ws: Vec<Vec<u32>> = (0..3)
            .map(|p| {
                recompute_linear_shares(
                    &circuit,
                    &seeds[p].0,
                    p,
                    3,
                    &exec.views[p].mul_output_shares,
                    &exec.views[p].residual_input_shares,
                )
            })
            .collect();
        for p in 0..3 {
            let next = (p + 1) % 3;
            verify_party_view(
                &circuit,
                &all_ws[p],
                p,
                &seeds[p].0,
                Some((&seeds[next].0, &all_ws[next])),
            )
            .unwrap();
        }
    }

    fn make_multiplication_circuit() -> Circuit {
        let mut b = CircuitBuilder::new(2);
        let prod = b.mul(0, 1);
        let _out = b.assert_eq(prod, 12);
        b.build(1)
    }

    /// Full emulation + verification for the ZKBoo Mul scheme with all three
    /// parties' views available.
    fn verify_all_views(circuit: &Circuit, seeds: &[PartySeed], exec: &MpcExecution) {
        let all_ws: Vec<Vec<u32>> = (0..3)
            .map(|p| {
                recompute_linear_shares(
                    circuit,
                    &seeds[p].0,
                    p,
                    3,
                    &exec.views[p].mul_output_shares,
                    &exec.views[p].residual_input_shares,
                )
            })
            .collect();
        for p in 0..3 {
            let next = (p + 1) % 3;
            verify_party_view(
                circuit,
                &all_ws[p],
                p,
                &seeds[p].0,
                Some((&seeds[next].0, &all_ws[next])),
            )
            .unwrap();
        }
    }

    #[test]
    fn test_zkboo_mul_shares_reconstruct() {
        let circuit = make_multiplication_circuit();
        let mut rng = thread_rng();
        let seeds: Vec<PartySeed> = (0..3).map(|_| PartySeed::random(&mut rng)).collect();
        let exec = run_mpc_emulation(&circuit, &[3u32, 4u32], &seeds, &mut rng).unwrap();

        assert_eq!(exec.output_values, vec![12]);
        assert_eq!(exec.shared_trace.wires[2].reconstruct(), 12);

        // The three per-party shares of the Mul output wire sum to x*y.
        let sum: u32 = exec
            .views
            .iter()
            .map(|v| v.mul_output_shares[0])
            .fold(0u32, |a, s| a.wrapping_add(s));
        assert_eq!(sum, 12);

        verify_all_views(&circuit, &seeds, &exec);
    }

    #[test]
    fn test_mul_share_tampering_detected() {
        let circuit = make_multiplication_circuit();
        let mut rng = thread_rng();
        let seeds: Vec<PartySeed> = (0..3).map(|_| PartySeed::random(&mut rng)).collect();
        let exec = run_mpc_emulation(&circuit, &[3u32, 4u32], &seeds, &mut rng).unwrap();

        let all_ws: Vec<Vec<u32>> = (0..3)
            .map(|p| {
                recompute_linear_shares(
                    &circuit,
                    &seeds[p].0,
                    p,
                    3,
                    &exec.views[p].mul_output_shares,
                    &exec.views[p].residual_input_shares,
                )
            })
            .collect();

        // Tamper party 0's claimed Mul output share.  Since party 0's right
        // neighbour (party 1) is opened, the verifier must detect it.
        let prod_wire = circuit
            .gates
            .iter()
            .find_map(|g| match g {
                Gate::Mul { output, .. } => Some(*output),
                _ => None,
            })
            .unwrap();
        let mut tampered = all_ws[0].clone();
        tampered[prod_wire] = tampered[prod_wire].wrapping_add(1);
        assert!(
            verify_party_view(
                &circuit,
                &tampered,
                0,
                &seeds[0].0,
                Some((&seeds[1].0, &all_ws[1])),
            )
            .is_err(),
            "tampered Mul share with opened neighbour must be rejected"
        );

        // But when the neighbour is the hidden party, the share is skipped by
        // design (2-of-3 scheme): no error is raised.
        verify_party_view(
            &circuit,
            &tampered,
            0,
            &seeds[0].0,
            None,
        )
        .unwrap();
    }
}
