//! V2 MPC-in-the-head emulation over BN254 `Fr`.
//!
//! This is a field port of the existing 3-party ZKBoo multiplication schedule.
//! The schedule is intentionally unchanged:
//!
//! `z_i = x_i*y_i + x_i*y_{i+1} + x_{i+1}*y_i + r_i(g)`
//! `r_i(g) = PRF(seed_i, g) - PRF(seed_{i+1}, g)`
//!
//! so `Σ r_i = 0` and `Σ z_i = x*y` in `Fr`.
//!
//! These are algebraic correctness checks only. They are not a soundness or
//! zero-knowledge proof for the surrounding MPC-in-the-head protocol; see
//! `V2_PROTOCOL_NOTES.md`.

use ark_bn254::Fr;

use crate::v2::circuit::{CircuitV2, GateV2, Wire};
use crate::v2::sharing::{sample_fr, PartySeedV2, SharedTraceV2, SharingV2};
use crate::{MpcithError, Result};

const PARTY_SHARE_TAG: &[u8] = b"NovaMPC-v2/party-share/v1";
const ZERO_SHARE_TAG: &[u8] = b"NovaMPC-v2/zero-share/v1";

fn zero_share_domain(nonlinear_idx: usize) -> Vec<u8> {
    let mut domain = ZERO_SHARE_TAG.to_vec();
    domain.extend_from_slice(&(nonlinear_idx as u64).to_be_bytes());
    domain
}

/// Party `i`'s correlated zero-share for a multiplication gate.
///
/// `r_i = PRF(seed_i, tag) - PRF(seed_{i+1}, tag)` in `Fr`; the three shares
/// telescope to zero.
pub fn zero_share(own_seed: &[u8; 32], next_seed: &[u8; 32], nonlinear_idx: usize) -> Fr {
    let domain = zero_share_domain(nonlinear_idx);
    let mut own_rng = PartySeedV2(*own_seed).to_rng(&domain);
    let mut next_rng = PartySeedV2(*next_seed).to_rng(&domain);
    sample_fr(&mut own_rng) - sample_fr(&mut next_rng)
}

/// ZKBoo multiplication output share for party `p`.
pub fn mul_output_share(x_p: Fr, y_p: Fr, x_next: Fr, y_next: Fr, r: Fr) -> Fr {
    x_p * y_p + x_p * y_next + x_next * y_p + r
}

/// Data needed to recheck one opened party's right neighbour.
#[derive(Debug, Clone, Copy)]
pub struct OpenedNeighborV2<'a> {
    /// Right neighbour's seed.
    pub seed: &'a [u8; 32],
    /// Right neighbour's full wire-share vector.
    pub wire_shares: &'a [Fr],
}

/// One party's committed/opened view for a v2 repetition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyViewV2 {
    /// Party index.
    pub party_idx: usize,
    /// Party seed. The proof layer reconstructs this from the seed tree.
    pub seed: [u8; 32],
    /// One share per multiplication gate, in circuit order.
    pub mul_output_shares: Vec<Fr>,
    /// Input-wire shares for the residual party only; empty otherwise.
    pub residual_input_shares: Vec<Fr>,
}

/// Canonical, length-prefixed encoding of the non-seed part of a view.
///
/// The seed is committed separately by the proof layer. Counts are explicit so
/// that different vector shapes cannot produce the same byte string.
pub fn encode_view_payload(mul_output_shares: &[Fr], residual_input_shares: &[Fr]) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(16 + 32 * (mul_output_shares.len() + residual_input_shares.len()));
    bytes.extend_from_slice(&(mul_output_shares.len() as u64).to_be_bytes());
    for share in mul_output_shares {
        bytes.extend_from_slice(&crate::v2::field::encode_fr(share));
    }
    bytes.extend_from_slice(&(residual_input_shares.len() as u64).to_be_bytes());
    for share in residual_input_shares {
        bytes.extend_from_slice(&crate::v2::field::encode_fr(share));
    }
    bytes
}

impl PartyViewV2 {
    /// Canonical bytes for the committed view, including the seed.
    pub fn to_commitment_bytes_with_seed(&self, seed: &[u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            32 + 32 * (self.mul_output_shares.len() + self.residual_input_shares.len()),
        );
        bytes.extend_from_slice(seed);
        for share in &self.mul_output_shares {
            bytes.extend_from_slice(&crate::v2::field::encode_fr(share));
        }
        for share in &self.residual_input_shares {
            bytes.extend_from_slice(&crate::v2::field::encode_fr(share));
        }
        bytes
    }

    /// Canonical bytes using this view's stored seed.
    pub fn to_commitment_bytes(&self) -> Vec<u8> {
        self.to_commitment_bytes_with_seed(&self.seed)
    }

    /// Length-prefixed non-seed payload used by the v2 view commitment.
    pub fn to_commitment_payload(&self) -> Vec<u8> {
        encode_view_payload(&self.mul_output_shares, &self.residual_input_shares)
    }
}

/// Result of one v2 MPC emulation run.
#[derive(Debug, Clone)]
pub struct MpcExecutionV2 {
    /// Per-party generated views.
    pub views: Vec<PartyViewV2>,
    /// Full shared wire trace.
    pub shared_trace: SharedTraceV2,
}

/// Run the v2 3-party emulation for one repetition.
pub fn run_mpc_emulation(
    circuit: &CircuitV2,
    witness: &[Fr],
    party_seeds: &[PartySeedV2],
) -> Result<MpcExecutionV2> {
    let num_parties = party_seeds.len();
    if num_parties != 3 {
        return Err(MpcithError::InvalidParams(
            "v2 ZKBoo emulation requires exactly 3 parties".into(),
        ));
    }
    if witness.len() != circuit.num_inputs() {
        return Err(MpcithError::InvalidWitness(format!(
            "v2 witness has length {}, circuit declares {} inputs",
            witness.len(),
            circuit.num_inputs()
        )));
    }

    let mut party_rngs: Vec<_> = party_seeds
        .iter()
        .map(|seed| seed.to_rng(PARTY_SHARE_TAG))
        .collect();

    let mut wires: Vec<Option<SharingV2>> = vec![None; circuit.num_wires()];
    for (index, value) in witness.iter().enumerate() {
        wires[index] = Some(SharingV2::share_with_rngs(
            *value,
            num_parties,
            &mut party_rngs,
        ));
    }

    let mut next_wire = circuit.num_inputs();
    let mut nonlinear_idx = 0usize;
    for (gate_index, gate) in circuit.gates().iter().enumerate() {
        let define = |wires: &mut Vec<Option<SharingV2>>,
                      output: Wire,
                      value: SharingV2,
                      next_wire: &mut usize|
         -> Result<()> {
            if output.index() >= circuit.num_wires() {
                return Err(MpcithError::CircuitError(format!(
                    "v2 gate {gate_index} output wire {} is out of range",
                    output.index()
                )));
            }
            if output.index() != *next_wire {
                return Err(MpcithError::CircuitError(format!(
                    "v2 gate {gate_index} output wire {} is not the next fresh wire {next_wire}",
                    output.index()
                )));
            }
            wires[output.index()] = Some(value);
            *next_wire += 1;
            Ok(())
        };

        match gate {
            GateV2::Add {
                left,
                right,
                output,
            } => {
                let right_value = read_share(&wires, *right, gate_index, circuit.num_wires())?;
                let value =
                    read_share(&wires, *left, gate_index, circuit.num_wires())?.add(&right_value);
                define(&mut wires, *output, value, &mut next_wire)?;
            }
            GateV2::Mul {
                left,
                right,
                output,
            } => {
                let x = read_share(&wires, *left, gate_index, circuit.num_wires())?;
                let y = read_share(&wires, *right, gate_index, circuit.num_wires())?;
                let mut z = Vec::with_capacity(num_parties);
                for party in 0..num_parties {
                    let next = (party + 1) % num_parties;
                    let r = zero_share(&party_seeds[party].0, &party_seeds[next].0, nonlinear_idx);
                    z.push(mul_output_share(
                        x.shares[party],
                        y.shares[party],
                        x.shares[next],
                        y.shares[next],
                        r,
                    ));
                }
                nonlinear_idx += 1;
                define(&mut wires, *output, SharingV2 { shares: z }, &mut next_wire)?;
            }
            GateV2::AddConst {
                input,
                constant,
                output,
            } => {
                let value = read_share(&wires, *input, gate_index, circuit.num_wires())?
                    .add_const(*constant);
                define(&mut wires, *output, value, &mut next_wire)?;
            }
            GateV2::MulConst {
                input,
                constant,
                output,
            } => {
                let value = read_share(&wires, *input, gate_index, circuit.num_wires())?
                    .mul_const(*constant);
                define(&mut wires, *output, value, &mut next_wire)?;
            }
            GateV2::AssertEq { input, .. } => {
                // Assertion gates have no output wire. The value-level check is
                // performed by the proof layer from published assertion shares.
                let _ = read_share(&wires, *input, gate_index, circuit.num_wires())?;
            }
        }
    }

    if next_wire != circuit.num_wires() {
        return Err(MpcithError::CircuitError(format!(
            "v2 circuit defines {next_wire} wires but declares {}",
            circuit.num_wires()
        )));
    }

    let wires: Vec<SharingV2> = wires
        .into_iter()
        .enumerate()
        .map(|(index, wire)| {
            wire.ok_or_else(|| {
                MpcithError::CircuitError(format!("v2 wire {index} was not defined"))
            })
        })
        .collect::<Result<_>>()?;
    let shared_trace = SharedTraceV2 { wires, num_parties };

    let views: Vec<PartyViewV2> = (0..num_parties)
        .map(|party| {
            let mul_output_shares = circuit
                .gates()
                .iter()
                .filter_map(|gate| match gate {
                    GateV2::Mul { output, .. } => {
                        Some(shared_trace.wires[output.index()].shares[party])
                    }
                    _ => None,
                })
                .collect();
            let residual_input_shares = if party == num_parties - 1 {
                (0..circuit.num_inputs())
                    .map(|wire| shared_trace.wires[wire].shares[party])
                    .collect()
            } else {
                Vec::new()
            };
            PartyViewV2 {
                party_idx: party,
                seed: party_seeds[party].0,
                mul_output_shares,
                residual_input_shares,
            }
        })
        .collect();

    Ok(MpcExecutionV2 {
        views,
        shared_trace,
    })
}

fn read_share(
    wires: &[Option<SharingV2>],
    wire: Wire,
    gate_index: usize,
    num_wires: usize,
) -> Result<SharingV2> {
    if wire.index() >= num_wires {
        return Err(MpcithError::CircuitError(format!(
            "v2 gate {gate_index} references out-of-range wire {}",
            wire.index()
        )));
    }
    wires[wire.index()].clone().ok_or_else(|| {
        MpcithError::CircuitError(format!(
            "v2 gate {gate_index} references undefined wire {}",
            wire.index()
        ))
    })
}

/// Recompute a party's full wire shares from its seed and claimed Mul shares.
///
/// The residual party's input shares are not seed-derivable and must be
/// supplied. Non-residual parties must not supply residual shares.
pub fn recompute_linear_shares(
    circuit: &CircuitV2,
    seed: &[u8; 32],
    party_idx: usize,
    num_parties: usize,
    mul_output_shares: &[Fr],
    residual_input_shares: &[Fr],
) -> Result<Vec<Fr>> {
    if num_parties != 3 || party_idx >= num_parties {
        return Err(MpcithError::InvalidParams(
            "v2 recomputation requires 3 parties and a valid party index".into(),
        ));
    }
    let is_residual_party = party_idx == num_parties - 1;
    if is_residual_party {
        if residual_input_shares.len() != circuit.num_inputs() {
            return Err(MpcithError::VerificationFailed(format!(
                "residual party has {} input shares, expected {}",
                residual_input_shares.len(),
                circuit.num_inputs()
            )));
        }
    } else if !residual_input_shares.is_empty() {
        return Err(MpcithError::VerificationFailed(
            "non-residual party must not carry residual input shares".into(),
        ));
    }

    let num_mul_gates = circuit
        .gates()
        .iter()
        .filter(|gate| matches!(gate, GateV2::Mul { .. }))
        .count();
    if mul_output_shares.len() != num_mul_gates {
        return Err(MpcithError::VerificationFailed(format!(
            "party {party_idx} has {} Mul shares, expected {num_mul_gates}",
            mul_output_shares.len()
        )));
    }

    let mut party_rng = PartySeedV2(*seed).to_rng(PARTY_SHARE_TAG);
    let mut shares: Vec<Option<Fr>> = vec![None; circuit.num_wires()];
    for wire in 0..circuit.num_inputs() {
        shares[wire] = Some(if is_residual_party {
            residual_input_shares[wire]
        } else {
            sample_fr(&mut party_rng)
        });
    }

    let mut next_wire = circuit.num_inputs();
    let mut nonlinear_idx = 0usize;
    for (gate_index, gate) in circuit.gates().iter().enumerate() {
        let define = |shares: &mut Vec<Option<Fr>>,
                      output: Wire,
                      value: Fr,
                      next_wire: &mut usize|
         -> Result<()> {
            if output.index() >= circuit.num_wires() {
                return Err(MpcithError::CircuitError(format!(
                    "v2 gate {gate_index} output wire {} is out of range",
                    output.index()
                )));
            }
            if output.index() != *next_wire {
                return Err(MpcithError::CircuitError(format!(
                    "v2 gate {gate_index} output wire {} is not the next fresh wire {next_wire}",
                    output.index()
                )));
            }
            shares[output.index()] = Some(value);
            *next_wire += 1;
            Ok(())
        };

        match gate {
            GateV2::Add {
                left,
                right,
                output,
            } => {
                let value = read_value(&shares, *left, gate_index, circuit.num_wires())?
                    + read_value(&shares, *right, gate_index, circuit.num_wires())?;
                define(&mut shares, *output, value, &mut next_wire)?;
            }
            GateV2::Mul { output, .. } => {
                let value = mul_output_shares[nonlinear_idx];
                nonlinear_idx += 1;
                define(&mut shares, *output, value, &mut next_wire)?;
            }
            GateV2::AddConst {
                input,
                constant,
                output,
            } => {
                let value = if party_idx == 0 {
                    read_value(&shares, *input, gate_index, circuit.num_wires())? + *constant
                } else {
                    read_value(&shares, *input, gate_index, circuit.num_wires())?
                };
                define(&mut shares, *output, value, &mut next_wire)?;
            }
            GateV2::MulConst {
                input,
                constant,
                output,
            } => {
                let value =
                    read_value(&shares, *input, gate_index, circuit.num_wires())? * *constant;
                define(&mut shares, *output, value, &mut next_wire)?;
            }
            GateV2::AssertEq { input, .. } => {
                let _ = read_value(&shares, *input, gate_index, circuit.num_wires())?;
            }
        }
    }

    if next_wire != circuit.num_wires() {
        return Err(MpcithError::CircuitError(format!(
            "v2 circuit defines {next_wire} wires but declares {}",
            circuit.num_wires()
        )));
    }

    shares
        .into_iter()
        .enumerate()
        .map(|(index, share)| {
            share.ok_or_else(|| {
                MpcithError::CircuitError(format!("v2 wire {index} was not defined"))
            })
        })
        .collect()
}

fn read_value(
    shares: &[Option<Fr>],
    wire: Wire,
    gate_index: usize,
    num_wires: usize,
) -> Result<Fr> {
    if wire.index() >= num_wires {
        return Err(MpcithError::CircuitError(format!(
            "v2 gate {gate_index} references out-of-range wire {}",
            wire.index()
        )));
    }
    shares[wire.index()].ok_or_else(|| {
        MpcithError::CircuitError(format!(
            "v2 gate {gate_index} references undefined wire {}",
            wire.index()
        ))
    })
}

fn read_party_share(
    shares: &[Fr],
    wire: Wire,
    gate_index: usize,
    num_wires: usize,
    party_idx: usize,
) -> Result<Fr> {
    if wire.index() >= num_wires || wire.index() >= shares.len() {
        return Err(MpcithError::CircuitError(format!(
            "v2 gate {gate_index} references out-of-range wire {} while checking party {party_idx}",
            wire.index()
        )));
    }
    Ok(shares[wire.index()])
}

/// Verify one opened party's view.
///
/// Linear gates are fully checked. A Mul share is recomputed only when the
/// right neighbour is also opened; otherwise that share is skipped by the
/// 2-of-3 opening schedule. Assertion values are checked by the proof layer,
/// not from one party's share.
pub fn verify_party_view(
    circuit: &CircuitV2,
    wire_shares: &[Fr],
    party_idx: usize,
    party_seed: &[u8; 32],
    next_opened: Option<OpenedNeighborV2<'_>>,
) -> Result<()> {
    if wire_shares.len() != circuit.num_wires() {
        return Err(MpcithError::VerificationFailed(format!(
            "party {party_idx} wire-share vector has length {}, expected {}",
            wire_shares.len(),
            circuit.num_wires()
        )));
    }
    if let Some(next) = next_opened {
        if next.wire_shares.len() != circuit.num_wires() {
            return Err(MpcithError::VerificationFailed(format!(
                "neighbour wire-share vector has length {}, expected {}",
                next.wire_shares.len(),
                circuit.num_wires()
            )));
        }
    }

    let mut nonlinear_idx = 0usize;
    for (gate_index, gate) in circuit.gates().iter().enumerate() {
        match gate {
            GateV2::Add {
                left,
                right,
                output,
            } => {
                let left = read_party_share(
                    wire_shares,
                    *left,
                    gate_index,
                    circuit.num_wires(),
                    party_idx,
                )?;
                let right = read_party_share(
                    wire_shares,
                    *right,
                    gate_index,
                    circuit.num_wires(),
                    party_idx,
                )?;
                let output = read_party_share(
                    wire_shares,
                    *output,
                    gate_index,
                    circuit.num_wires(),
                    party_idx,
                )?;
                if output != left + right {
                    return Err(MpcithError::ConsistencyCheckFailed(party_idx));
                }
            }
            GateV2::Mul {
                left,
                right,
                output,
            } => {
                if let Some(next) = next_opened {
                    let left_wire = *left;
                    let right_wire = *right;
                    let left = read_party_share(
                        wire_shares,
                        left_wire,
                        gate_index,
                        circuit.num_wires(),
                        party_idx,
                    )?;
                    let right = read_party_share(
                        wire_shares,
                        right_wire,
                        gate_index,
                        circuit.num_wires(),
                        party_idx,
                    )?;
                    let output = read_party_share(
                        wire_shares,
                        *output,
                        gate_index,
                        circuit.num_wires(),
                        party_idx,
                    )?;
                    let next_left = read_party_share(
                        next.wire_shares,
                        left_wire,
                        gate_index,
                        circuit.num_wires(),
                        party_idx,
                    )?;
                    let next_right = read_party_share(
                        next.wire_shares,
                        right_wire,
                        gate_index,
                        circuit.num_wires(),
                        party_idx,
                    )?;
                    let r = zero_share(party_seed, next.seed, nonlinear_idx);
                    let expected = mul_output_share(left, right, next_left, next_right, r);
                    if output != expected {
                        return Err(MpcithError::ConsistencyCheckFailed(party_idx));
                    }
                }
                nonlinear_idx += 1;
            }
            GateV2::AddConst {
                input,
                constant,
                output,
            } => {
                let input = read_party_share(
                    wire_shares,
                    *input,
                    gate_index,
                    circuit.num_wires(),
                    party_idx,
                )?;
                let output = read_party_share(
                    wire_shares,
                    *output,
                    gate_index,
                    circuit.num_wires(),
                    party_idx,
                )?;
                let expected = if party_idx == 0 {
                    input + *constant
                } else {
                    input
                };
                if output != expected {
                    return Err(MpcithError::ConsistencyCheckFailed(party_idx));
                }
            }
            GateV2::MulConst {
                input,
                constant,
                output,
            } => {
                let input = read_party_share(
                    wire_shares,
                    *input,
                    gate_index,
                    circuit.num_wires(),
                    party_idx,
                )?;
                let output = read_party_share(
                    wire_shares,
                    *output,
                    gate_index,
                    circuit.num_wires(),
                    party_idx,
                )?;
                if output != input * *constant {
                    return Err(MpcithError::ConsistencyCheckFailed(party_idx));
                }
            }
            GateV2::AssertEq { input, .. } => {
                let _ = read_party_share(
                    wire_shares,
                    *input,
                    gate_index,
                    circuit.num_wires(),
                    party_idx,
                )?;
                // Value-level check lives in the proof layer.
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::circuit::{CircuitBuilderV2, Wire};
    use crate::v2::sharing::PartySeedV2;
    use rand::{rngs::StdRng, SeedableRng};

    fn seeds() -> Vec<PartySeedV2> {
        vec![
            PartySeedV2([11u8; 32]),
            PartySeedV2([22u8; 32]),
            PartySeedV2([33u8; 32]),
        ]
    }

    fn composite_circuit() -> (CircuitV2, Vec<Fr>, Vec<Fr>) {
        let mut builder = CircuitBuilderV2::new(3);
        let sum = builder.add(Wire(0), Wire(1));
        let product = builder.mul(sum, Wire(2));
        builder.assert_eq(product, Fr::from(56u64));
        let circuit = builder.build();
        let witness = vec![Fr::from(3u64), Fr::from(5u64), Fr::from(7u64)];
        let native = circuit.evaluate(&witness).unwrap();
        (circuit, witness, native)
    }

    #[test]
    fn honest_execution_reconstructs_every_wire() {
        let (circuit, witness, native) = composite_circuit();
        let seeds = seeds();
        let execution = run_mpc_emulation(&circuit, &witness, &seeds).unwrap();
        assert_eq!(execution.shared_trace.wires.len(), native.len());
        for (wire, expected) in native.iter().enumerate() {
            assert_eq!(execution.shared_trace.reconstruct_wire(wire), *expected);
        }
        assert_eq!(execution.shared_trace.reconstruct_wire(3), Fr::from(8u64));
        assert_eq!(execution.shared_trace.reconstruct_wire(4), Fr::from(56u64));
    }

    #[test]
    fn views_recompute_and_verify_with_opened_neighbours() {
        let (circuit, witness, _) = composite_circuit();
        let seeds = seeds();
        let execution = run_mpc_emulation(&circuit, &witness, &seeds).unwrap();

        let all_wire_shares: Vec<Vec<Fr>> = (0..3)
            .map(|party| {
                recompute_linear_shares(
                    &circuit,
                    &seeds[party].0,
                    party,
                    3,
                    &execution.views[party].mul_output_shares,
                    &execution.views[party].residual_input_shares,
                )
                .unwrap()
            })
            .collect();

        for party in 0..3 {
            for wire in 0..circuit.num_wires() {
                assert_eq!(
                    all_wire_shares[party][wire],
                    execution.shared_trace.wires[wire].shares[party]
                );
            }
            let next = (party + 1) % 3;
            verify_party_view(
                &circuit,
                &all_wire_shares[party],
                party,
                &seeds[party].0,
                Some(OpenedNeighborV2 {
                    seed: &seeds[next].0,
                    wire_shares: &all_wire_shares[next],
                }),
            )
            .unwrap();
        }
    }

    #[test]
    fn zero_shares_telescope_for_many_gates() {
        let seeds = seeds();
        for gate in 0..64 {
            let r0 = zero_share(&seeds[0].0, &seeds[1].0, gate);
            let r1 = zero_share(&seeds[1].0, &seeds[2].0, gate);
            let r2 = zero_share(&seeds[2].0, &seeds[0].0, gate);
            assert_eq!(r0 + r1 + r2, Fr::from(0u64), "gate {gate}");
        }
    }

    #[test]
    fn mixed_linear_and_multiplication_circuit_reconstructs() {
        let mut builder = CircuitBuilderV2::new(4);
        let first = builder.add(Wire(0), Wire(1));
        let second = builder.mul(first, Wire(2));
        let third = builder.add(second, Wire(3));
        let shifted = builder.add_const(third, Fr::from(3u64));
        let scaled = builder.mul_const(shifted, Fr::from(7u64));
        let circuit = builder.build();

        let witnesses = [
            [
                Fr::from(2u64),
                Fr::from(3u64),
                Fr::from(4u64),
                Fr::from(5u64),
            ],
            [
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            ],
            [
                -Fr::from(1u64),
                Fr::from(2u64),
                -Fr::from(3u64),
                Fr::from(4u64),
            ],
        ];
        let seeds = seeds();
        for witness in witnesses {
            let native = circuit.evaluate(&witness).unwrap();
            let execution = run_mpc_emulation(&circuit, &witness, &seeds).unwrap();
            for (wire, expected) in native.iter().enumerate() {
                assert_eq!(execution.shared_trace.reconstruct_wire(wire), *expected);
            }
            assert_eq!(
                execution.shared_trace.reconstruct_wire(scaled.index()),
                expected_scaled(&witness)
            );
        }
    }

    fn expected_scaled(witness: &[Fr]) -> Fr {
        let first = witness[0] + witness[1];
        let second = first * witness[2];
        let third = second + witness[3];
        (third + Fr::from(3u64)) * Fr::from(7u64)
    }

    #[test]
    fn multiplication_shares_reconstruct_product() {
        let mut builder = CircuitBuilderV2::new(2);
        let product = builder.mul(Wire(0), Wire(1));
        builder.assert_eq(product, Fr::from(12u64));
        let circuit = builder.build();
        let witness = [Fr::from(3u64), Fr::from(4u64)];
        let seeds = seeds();
        let execution = run_mpc_emulation(&circuit, &witness, &seeds).unwrap();

        let sum = execution
            .views
            .iter()
            .map(|view| view.mul_output_shares[0])
            .fold(Fr::from(0u64), |acc, share| acc + share);
        assert_eq!(sum, Fr::from(12u64));
    }

    #[test]
    fn tampered_opened_mul_share_is_rejected() {
        let mut builder = CircuitBuilderV2::new(2);
        let product = builder.mul(Wire(0), Wire(1));
        builder.assert_eq(product, Fr::from(12u64));
        let circuit = builder.build();
        let witness = [Fr::from(3u64), Fr::from(4u64)];
        let seeds = seeds();
        let execution = run_mpc_emulation(&circuit, &witness, &seeds).unwrap();

        let all_wire_shares: Vec<Vec<Fr>> = (0..3)
            .map(|party| {
                recompute_linear_shares(
                    &circuit,
                    &seeds[party].0,
                    party,
                    3,
                    &execution.views[party].mul_output_shares,
                    &execution.views[party].residual_input_shares,
                )
                .unwrap()
            })
            .collect();

        let mut tampered = all_wire_shares[0].clone();
        tampered[2] += Fr::from(1u64);
        assert!(verify_party_view(
            &circuit,
            &tampered,
            0,
            &seeds[0].0,
            Some(OpenedNeighborV2 {
                seed: &seeds[1].0,
                wire_shares: &all_wire_shares[1],
            }),
        )
        .is_err());

        // With the right neighbour hidden, the 2-of-3 schedule skips this
        // particular multiplication-share check by design.
        verify_party_view(&circuit, &tampered, 0, &seeds[0].0, None).unwrap();
    }

    #[test]
    fn residual_and_mul_share_shapes_are_checked() {
        let (circuit, witness, _) = composite_circuit();
        let seeds = seeds();
        let execution = run_mpc_emulation(&circuit, &witness, &seeds).unwrap();

        assert!(recompute_linear_shares(
            &circuit,
            &seeds[2].0,
            2,
            3,
            &execution.views[2].mul_output_shares,
            &[],
        )
        .is_err());
        assert!(recompute_linear_shares(
            &circuit,
            &seeds[0].0,
            0,
            3,
            &execution.views[0].mul_output_shares,
            &[Fr::from(1u64)],
        )
        .is_err());
        assert!(recompute_linear_shares(&circuit, &seeds[0].0, 0, 3, &[], &[],).is_err());
    }

    #[test]
    fn deterministic_seed_domains_do_not_leak_v1_shares() {
        let seed = PartySeedV2([44u8; 32]);
        let mut v2_rng = seed.to_rng(PARTY_SHARE_TAG);
        let mut other_rng = seed.to_rng(b"NovaMPC-v2/other/v1");
        assert_ne!(sample_fr(&mut v2_rng), sample_fr(&mut other_rng));
    }

    #[test]
    fn honest_views_use_std_rng_only_for_test_setup() {
        // Keep a deterministic test RNG available without making protocol
        // randomness injectable through the emulation API.
        let mut rng = StdRng::from_seed([55u8; 32]);
        let _ = PartySeedV2::random(&mut rng);
    }
}
