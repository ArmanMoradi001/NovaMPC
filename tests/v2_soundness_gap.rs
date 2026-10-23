//! Executable evidence for the STEP-10 soundness-gap report.
//!
//! This test intentionally constructs a **false** range statement and shows
//! that the v2 verifier can accept it. It is not a regression test asserting
//! that v2 is sound; it records a known protocol failure so the security note
//! cannot drift away from the implemented behaviour.
//!
//! Construction (one repetition, N = 3):
//!
//! * Choose a false value `x = 101` for the statement `10 <= x <= 100`.
//! * Set the private range slack to `hi - x = -1`, encoded by a non-boolean
//!   first slack bit (`-1`). All other bits are ordinary 0/1 bits.
//! * Run an honest MPC emulation. The only failing assertion is the boolean
//!   check `b * (b - 1) == 0` for that slack bit.
//! * Subtract the reconstructed product from party 0's claimed Mul-output
//!   share. This makes the published assertion share row sum to zero, while
//!   leaving parties 1 and 2 completely honest.
//! * If the Fiat-Shamir challenge hides party 0 (h = 0), party 0 is not opened.
//!   If it hides party 1 (h = 1), party 0 is opened but its right neighbour
//!   (party 1) is hidden, so the verifier skips party 0's Mul check. Both
//!   cases accept. Only h = 2 opens party 0 with an opened right neighbour and
//!   catches the bad Mul share.
//!
//! The expected acceptance probability per challenge attempt is therefore
//! 2/3. The loop samples independent commitment prefixes. For each prefix the
//! Fiat-Shamir challenge selects one hidden party; the forged proof is
//! accepted when that challenge is 0 or 1 and rejected when it is 2. The
//! printed count is a sample, not a precise estimate of 2/3.
//!
//! See `V2_SECURITY_ANALYSIS.md` for the proof/gap discussion. This test must
//! not be used to claim that the protocol is secure.

use ark_bn254::Fr;
use mpcith_zk::v2::circuit::{CircuitV2, GateV2};
use mpcith_zk::v2::commit_tree::CommitTreeV2;
use mpcith_zk::v2::commitment::commit_view_v2;
use mpcith_zk::v2::mpc::{
    encode_view_payload, recompute_linear_shares, run_mpc_emulation, PartyViewV2,
};
use mpcith_zk::v2::predicate::{compile_range, RangeStatementV2, StatementV2};
use mpcith_zk::v2::proof::{
    hash_context_v2, verify_statement, OpenedViewV2, RepetitionProofV2, V2Proof,
};
use mpcith_zk::v2::seed_tree::SeedTreeV2;
use mpcith_zk::v2::sharing::PartySeedV2;
use mpcith_zk::v2::suite::{V2Params, V2_PROOF_VERSION};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

fn context() -> [u8; 32] {
    hash_context_v2(b"v2-soundness-gap")
}

fn assertions(circuit: &CircuitV2) -> Vec<(usize, Fr)> {
    circuit
        .gates()
        .iter()
        .filter_map(|gate| match gate {
            GateV2::AssertEq { input, expected } => Some((input.index(), *expected)),
            _ => None,
        })
        .collect()
}

/// Build a witness for the false range statement. The layout is the canonical
/// range layout: `[x, x_bits(32), shifted_bits, slack_bits]`, where the bit
/// counts are `bits_needed(hi - lo)`.
fn false_range_witness(circuit: &CircuitV2, value: u32, lo: u32, hi: u32) -> Vec<Fr> {
    let range_bits = (circuit.num_inputs() - 33) / 2;
    let mut witness = vec![Fr::from(0u64); circuit.num_inputs()];
    witness[0] = Fr::from(value as u64);

    for bit in 0..32 {
        witness[1 + bit] = Fr::from(((value >> bit) & 1) as u64);
    }

    let shifted = value.wrapping_sub(lo);
    for bit in 0..range_bits {
        witness[33 + bit] = Fr::from(((shifted >> bit) & 1) as u64);
    }

    // hi - value == -1 for value = hi + 1. Encode that field value as a
    // non-boolean first slack bit; the remaining bits are zero. The shift
    // and x decompositions are still valid, so only this boolean constraint
    // fails in the honest emulation.
    let slack_offset = 33 + range_bits;
    witness[slack_offset] = Fr::from(hi as u64) - Fr::from(value as u64);
    witness
}

fn rebuild_views(
    circuit: &CircuitV2,
    seeds: &[PartySeedV2],
    execution: &mpcith_zk::v2::mpc::MpcExecutionV2,
) -> Vec<Vec<Fr>> {
    (0..seeds.len())
        .map(|party| {
            recompute_linear_shares(
                circuit,
                &seeds[party].0,
                party,
                seeds.len(),
                &execution.views[party].mul_output_shares,
                &execution.views[party].residual_input_shares,
            )
            .expect("honest recomputation")
        })
        .collect()
}

/// Turn the modified execution into one v2 repetition for a chosen hidden
/// party. Both h = 0 and h = 1 are built from the same pre-challenge prefix
/// (commitment root and assertion rows).
fn forge_repetition(
    hidden: usize,
    seeds: &[PartySeedV2],
    tree: &SeedTreeV2,
    commit_tree: &CommitTreeV2,
    randomness: &[[u8; 32]],
    views: &[PartyViewV2],
    assert_shares: Vec<Vec<Fr>>,
) -> RepetitionProofV2 {
    let co_path = tree.co_path(hidden).expect("co-path");
    let mut opened_views = Vec::with_capacity(seeds.len() - 1);
    for party in 0..seeds.len() {
        if party == hidden {
            continue;
        }
        let view = &views[party];
        let auth = commit_tree
            .prove_membership(party)
            .expect("commitment auth path");
        opened_views.push(OpenedViewV2 {
            party_idx: party as u32,
            mul_output_shares: view.mul_output_shares.clone(),
            residual_input_shares: view.residual_input_shares.clone(),
            commitment_randomness: randomness[party],
            commitment_auth_path: auth.siblings,
        });
    }
    RepetitionProofV2 {
        hidden_party: hidden as u32,
        commitment_root: commit_tree.root(),
        co_path,
        opened_views,
        assert_shares,
    }
}

#[test]
fn known_gap_accepts_false_range_statement_for_two_of_three_hidden_parties() {
    let compiled = compile_range(10, 100).expect("compile range");
    let circuit = compiled.circuit();
    let statement = StatementV2::Range(RangeStatementV2::new(10, 100).unwrap());
    assert_eq!(compiled.statement(), &statement);

    // The witness is false and the authoritative evaluator rejects it.
    let witness = false_range_witness(circuit, 101, 10, 100);
    assert!(
        circuit.evaluate(&witness).is_err(),
        "test setup requires a witness the circuit rejects"
    );
    assert!(compiled.witness_for(101, None).is_err());

    let params = V2Params::new(3, 1);
    let mut rng = StdRng::from_seed([0x5Au8; 32]);
    let attempts = 48usize;
    let mut accepted = 0usize;
    let mut caught_at_h2 = 0usize;
    let mut last_errors = Vec::new();

    for _attempt in 0..attempts {
        let mut root_seed = [0u8; 32];
        rng.fill_bytes(&mut root_seed);
        let tree = SeedTreeV2::build(root_seed, 3).expect("seed tree");
        let seeds: Vec<PartySeedV2> = tree.leaf_seeds().into_iter().map(PartySeedV2).collect();
        let mut execution = run_mpc_emulation(circuit, &witness, &seeds).expect("honest emulation");

        // Locate the single boolean-check Mul output that the false slack bit
        // makes non-zero in the honest execution.
        let mut mul_outputs = Vec::new();
        let mut mul_idx = 0usize;
        for gate in circuit.gates() {
            if let GateV2::Mul { output, .. } = gate {
                mul_outputs.push((mul_idx, output.index()));
                mul_idx += 1;
            }
        }

        let mut bad_mul = None;
        for (wire, expected) in assertions(circuit) {
            if expected != Fr::from(0u64) {
                continue;
            }
            if let Some(&(index, _)) = mul_outputs.iter().find(|(_, w)| *w == wire) {
                let reconstructed = execution.shared_trace.reconstruct_wire(wire);
                if reconstructed != Fr::from(0u64) {
                    bad_mul = Some((index, reconstructed));
                    break;
                }
            }
        }
        let (bad_index, bad_value) =
            bad_mul.expect("the false slack bit must produce one failed boolean check");

        // Party 0 is the sacrificial party. Its Mul equation is wrong by
        // `bad_value`; parties 1 and 2 keep their honest Mul shares.
        execution.views[0].mul_output_shares[bad_index] -= bad_value;

        let party_shares = rebuild_views(circuit, &seeds, &execution);

        // Build the published assertion rows from the modified execution.
        let assert_shares: Vec<Vec<Fr>> = assertions(circuit)
            .into_iter()
            .map(|(wire, expected)| {
                let row: Vec<Fr> = (0..3).map(|party| party_shares[party][wire]).collect();
                let sum = row.iter().fold(Fr::from(0u64), |acc, share| acc + *share);
                assert_eq!(sum, expected, "fabricated assertion row must sum correctly");
                row
            })
            .collect();

        // Commit to all three views under one repetition root.
        let mut randomness = Vec::with_capacity(3);
        let mut leaves = Vec::with_capacity(3);
        for party in 0..3 {
            let mut random = [0u8; 32];
            rng.fill_bytes(&mut random);
            let payload = encode_view_payload(
                &execution.views[party].mul_output_shares,
                &execution.views[party].residual_input_shares,
            );
            leaves.push(commit_view_v2(
                0,
                party as u32,
                &seeds[party].0,
                &payload,
                &random,
            ));
            randomness.push(random);
        }
        let commit_tree = CommitTreeV2::build(&leaves).expect("commitment tree");

        // The challenge is derived from the commitment root and assertion
        // rows, not from the hidden party. Build all three openings against
        // the same prefix.
        let mut results = Vec::new();
        let mut accepted_this_attempt = false;
        for hidden in [0usize, 1, 2] {
            let repetition = forge_repetition(
                hidden,
                &seeds,
                &tree,
                &commit_tree,
                &randomness,
                &execution.views,
                assert_shares.clone(),
            );
            let proof = V2Proof {
                version: V2_PROOF_VERSION,
                params: params.clone(),
                statement: statement.clone(),
                context: context(),
                repetitions: vec![repetition],
            };
            let result = verify_statement(&proof, &statement, context(), &params);
            if result.is_ok() {
                accepted_this_attempt = true;
                assert_ne!(
                    hidden, 2,
                    "the false statement must not survive the h=2 checked-neighbour case"
                );
            }
            results.push((hidden, result));
        }

        if accepted_this_attempt {
            // The derived challenge selected party 0 or party 1. The candidate
            // opening for that hidden party passes; the other two candidates
            // fail the hidden-party equality check. This is the 2-of-3
            // acceptance event described in the security note.
            accepted += 1;
        } else {
            // The challenge hides party 2, which opens party 0 *and* its right
            // neighbour. Party 0's bad Mul equation is checked and rejected.
            let h2_error = results
                .iter()
                .find(|(hidden, _)| *hidden == 2)
                .and_then(|(_, result)| result.as_ref().err());
            assert!(
                matches!(
                    h2_error,
                    Some(mpcith_zk::MpcithError::ConsistencyCheckFailed(0))
                ),
                "h=2 must catch the fabricated Mul share, got {h2_error:?}"
            );
            caught_at_h2 += 1;
        }
        last_errors = results
            .into_iter()
            .map(|(hidden, result)| format!("h={hidden}: {result:?}"))
            .collect();
    }

    assert!(accepted > 0, "no favourable 2-of-3 challenge was found");
    assert!(
        caught_at_h2 > 0,
        "no h=2 challenge exercised the rejected case"
    );
    assert_eq!(
        accepted + caught_at_h2,
        attempts,
        "every attempt must be either an accepted h=0/h=1 proof or a caught h=2 proof; last: {last_errors:?}"
    );
    println!(
        "known-gap evidence: {accepted}/{attempts} sampled Fiat-Shamir challenges selected h=0 or h=1 \
         and accepted the false range proof; {caught_at_h2}/{attempts} selected h=2 and were rejected"
    );
}
