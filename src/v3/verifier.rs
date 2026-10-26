//! Experimental V3 verifier (checks `V3_PROTOCOL.md` §2).
//!
//! Recompiles the LPPC relation from the expected statement (never from
//! the proof), recomputes every challenge from the transcript, and requires
//! exact counts and byte-equality everywhere. Returns `Ok(())` only if all
//! five checks pass. No security claim.

use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};

use crate::v2::field::encode_fr;
use crate::v2::predicate::StatementV2;
use crate::v3::commit::verify_path;
use crate::v3::constraints::ConstraintProgramV3;
use crate::v3::hints::{correction_basis_eval, zero_mask_eval, PiDollarV3};
use crate::v3::params::V3Params;
use crate::v3::proof::V3Proof;
use crate::v3::prover::complement_set;
use crate::v3::sharing::{interpolate_coeffs_fast, party_point, FixedInterpolator};
use crate::v3::transcript::{
    circuit_hash_v3, hash_fr_vecs, TranscriptV3, V3_HASH_TAG_BROADCAST, V3_HASH_TAG_PXI,
    V3_TR_TAG_BATCH, V3_TR_TAG_GAMMA, V3_TR_TAG_OPEN,
};
use crate::{MpcithError, Result};

/// Merkle tree height for `n` leaves with duplication of the odd node.
fn tree_height(mut n: usize) -> usize {
    let mut h = 0;
    while n > 1 {
        n = n.div_ceil(2);
        h += 1;
    }
    h
}

/// Verify a combined proof against the expected statement, context, and
/// parameters (all caller-supplied, never proof-supplied).
pub fn verify_combined_v3(
    proof: &V3Proof,
    statement: &StatementV2,
    context: [u8; 32],
    params: &V3Params,
) -> Result<()> {
    params.validate()?;
    let (lo, hi, root, num_members, depth) = match statement {
        StatementV2::Combined { range, membership } => (
            range.lo,
            range.hi,
            membership.root,
            membership.num_members,
            membership.depth,
        ),
        _ => {
            return Err(MpcithError::InvalidParams(
                "v3 prototype verifies combined statements only".into(),
            ))
        }
    };
    // Check 5 (header): the proof must echo exactly the expected values.
    if proof.params != *params {
        return Err(MpcithError::VerificationFailed(
            "v3 proof parameters differ from expected".into(),
        ));
    }
    if proof.range_lo != lo
        || proof.range_hi != hi
        || proof.set_root != encode_fr(&root)
        || proof.num_members != num_members
        || proof.depth != depth
        || proof.context != context
    {
        return Err(MpcithError::VerificationFailed(
            "v3 proof statement or context differs from expected".into(),
        ));
    }
    let compiled = crate::v2::predicate::compile_from_statement(statement)?;
    let circuit_hash = circuit_hash_v3(compiled.circuit());
    if proof.circuit_hash != circuit_hash {
        return Err(MpcithError::VerificationFailed(
            "v3 proof circuit hash differs from expected".into(),
        ));
    }
    let program = ConstraintProgramV3::compile(compiled.circuit(), params)?;

    let s = params.packing_width as usize;
    let ell = params.privacy_threshold as usize;
    let n = params.num_parties as usize;
    let eta = params.decs_reps as usize;
    let rho = params.mpc_reps as usize;
    let d_beta = params.hint_degree() as usize;
    let d_alpha = params.broadcast_degree() as usize;
    let d2 = 2 * s + ell - 2;
    let n_w = program.dims().num_rows;
    let m1 = program.m1();

    let pi_v = PiDollarV3::for_target(s, ell, d_beta, d_alpha - s)?;
    let pi_vp = PiDollarV3::for_target(s, ell, d_beta, d2)?;
    let n_hints = pi_v.num_hints + pi_vp.num_hints;
    let num_q = n_w + eta + rho * n_hints;
    // Lane interpolation transform shared by all repetitions: the LPPC lane
    // points are fixed, so invert once instead of per-constraint.
    let lane_interp = program.lane_interpolator()?;

    if proof.reps.len() != params.pok_reps as usize {
        return Err(MpcithError::VerificationFailed(format!(
            "v3 proof has {} repetitions, expected {}",
            proof.reps.len(),
            params.pok_reps
        )));
    }

    for (rep_index, rep) in proof.reps.iter().enumerate() {
        verify_rep(
            rep, &program, &lane_interp, params, s, ell, n, eta, rho,
            d_beta, d_alpha, d2, n_w, m1, num_q, n_hints,
            &pi_v, &pi_vp, &context, &circuit_hash, &proof.salt,
            lo, hi, &proof.set_root, num_members, depth,
            rep_index as u32,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_rep(
    rep: &crate::v3::proof::RepProofV3,
    program: &ConstraintProgramV3,
    lane_interp: &FixedInterpolator,
    params: &V3Params,
    s: usize, ell: usize, n: usize, eta: usize, rho: usize,
    d_beta: usize, d_alpha: usize, d2: usize, n_w: usize, m1: usize,
    num_q: usize, n_hints: usize,
    pi_v: &PiDollarV3,
    pi_vp: &PiDollarV3,
    context: &[u8; 32],
    circuit_hash: &[u8; 32],
    salt: &[u8; 32],
    lo: u32, hi: u32, set_root: &[u8; 32], num_members: u32, depth: u32,
    rep_index: u32,
) -> Result<()> {
    let fail = |msg: &str| MpcithError::VerificationFailed(msg.into());

    if rep.opened.len() != ell {
        return Err(fail("v3 wrong opened-party count"));
    }
    if rep.delta_u1.len() != rho {
        return Err(fail("v3 wrong correction count"));
    }
    if rep.broadcast_alpha.len() != rho || rep.broadcast_alpha_prime.len() != rho {
        return Err(fail("v3 wrong batch count"));
    }
    if rep.decs_responses.len() != eta {
        return Err(fail("v3 wrong DECS row count"));
    }

    let mut tr = TranscriptV3::new(
        params.num_parties, params.privacy_threshold, params.packing_width,
        params.decs_reps, params.mpc_reps, params.pok_reps,
        lo, hi, set_root, num_members, depth, context, circuit_hash, salt, rep_index,
    );
    tr.absorb_hash(b"h1", &rep.commitment_root);
    let gamma = tr.sample_frs(V3_TR_TAG_GAMMA, 0, eta * num_q);
    if gamma.len() != eta * num_q {
        return Err(fail("v3 challenge length mismatch"));
    }
    tr.absorb_hash(b"h1p", &rep.decs_hash);

    // Batching challenges (verifier recomputes; not transmitted).
    let mut gammas: Vec<Vec<Fr>> = Vec::with_capacity(rho);
    let mut gamma_ps: Vec<Vec<Fr>> = Vec::with_capacity(rho);
    for b in 0..rho {
        gammas.push(tr.sample_frs(V3_TR_TAG_BATCH, (2 * b) as u32, m1));
        gamma_ps.push(tr.sample_frs(V3_TR_TAG_BATCH, (2 * b + 1) as u32, program.m2()));
    }
    tr.absorb_hash(b"hb", &rep.broadcast_hash);
    let opened_idx = tr.sample_subset(V3_TR_TAG_OPEN, 0, n, ell)?;
    let s_set = complement_set(n, &opened_idx, d_alpha + 1 - ell)?;
    let sp_set = complement_set(n, &opened_idx, d2 + 1 - ell)?;
    let sx_set = complement_set(n, &opened_idx, d_beta + 1 - ell)?;

    // --- Check 1: recompute leaves, verify paths against h1. ---
    let height = tree_height(n);
    let mut opened_shares: Vec<Vec<Fr>> = Vec::with_capacity(ell);
    for (o, want) in rep.opened.iter().zip(opened_idx.iter()) {
        if o.party_index != *want {
            return Err(fail("v3 opened party differs from challenge"));
        }
        if o.shares.len() != num_q {
            return Err(fail("v3 wrong share count in opened party"));
        }
        if o.path.len() != height || o.path_left.len() != height {
            return Err(fail("v3 wrong authentication path length"));
        }
        let leaf = crate::v3::commit::leaf_commit(o.party_index, &o.shares, &o.leaf_randomness);
        let path: Vec<crate::v3::commit::PathStep> = o
            .path
            .iter()
            .zip(o.path_left.iter())
            .map(|(sib, left)| crate::v3::commit::PathStep {
                sibling: *sib,
                sibling_is_left: *left,
            })
            .collect();
        let ok = verify_path(&leaf, o.party_index as usize, &path, &rep.commitment_root, n)
            .map_err(|e| fail(&format!("v3 path shape invalid: {e}")))?;
        if !ok {
            return Err(fail("v3 authentication path mismatch"));
        }
        opened_shares.push(o.shares.clone());
    }
    // Q-column layout: witness packs, mask packs, per-batch hints.

    // Helper: share value of Q column q at (opened position k).
    let q_at = |q: usize, k: usize| -> Fr { opened_shares[k][q] };
    // X-shift per Q column (word-rule; mirrors the prover).
    let mut q_shift: Vec<usize> = Vec::with_capacity(num_q);
    for _ in 0..n_w {
        q_shift.push(d_beta - (s + ell - 1));
    }
    for _ in 0..eta {
        q_shift.push(0);
    }
    for _ in 0..rho {
        for d in pi_v.hint_degrees(d_beta).iter().chain(pi_vp.hint_degrees(d_beta).iter()) {
            q_shift.push(d_beta - d);
        }
    }

    // --- Per-batch broadcast + outcome checks (2, 4). ---
    let mut hb_inputs: Vec<Vec<Fr>> = Vec::new();
    for b in 0..rho {
        let hint0 = n_w + eta + b * n_hints;
        // Derive JvK/Jv′K at the opened parties from opened hint shares.
        let jv: Vec<Fr> = (0..ell)
            .map(|k| {
                let e = party_point(s, opened_idx[k] as usize);
                let hv: Vec<Fr> = (0..pi_v.num_hints).map(|j| q_at(hint0 + j, k)).collect();
                let mut acc = Fr::zero();
                let mut power = Fr::one();
                for h in &hv {
                    acc += *h * power;
                    power *= e.pow([pi_v.delta as u64]);
                }
                acc * zero_mask_at(s, opened_idx[k] as usize)
            })
            .collect();
        let jvp: Vec<Fr> = (0..ell)
            .map(|k| {
                let e = party_point(s, opened_idx[k] as usize);
                let mut hv: Vec<Fr> =
                    (0..pi_vp.num_hints).map(|j| q_at(hint0 + pi_v.num_hints + j, k)).collect();
                hv[0] += rep.delta_u1[b]
                    * correction_basis_eval(s, party_point(s, opened_idx[k] as usize));
                let mut acc = Fr::zero();
                let mut power = Fr::one();
                for h in &hv {
                    acc += *h * power;
                    power *= e.pow([pi_vp.delta as u64]);
                }
                acc
            })
            .collect();
        // Recompute broadcasts at I.
        let w_at = |pack: usize, k: usize| -> Fr { opened_shares[k][pack] };
        let mut alpha_i = Vec::with_capacity(ell);
        for k in 0..ell {
            let mut acc = jv[k];
            for (g, group) in program.parallel_groups().iter().enumerate() {
                let a = w_at(group.a_row, k);
                let bb = w_at(group.b_row, k);
                let c = w_at(group.c_row, k);
                acc += gammas[b][g] * (c - a * bb);
            }
            alpha_i.push(acc);
        }
        // Sparse LPPC path: lane Lagrange weights at this opened party,
        // shared by all constraints; cost scales with nonzero terms.
        let lane_bases: Vec<Vec<Fr>> = opened_idx
            .iter()
            .map(|i| lane_interp.basis_evals(party_point(s, *i as usize)))
            .collect();
        let mut alpha_p_i = Vec::with_capacity(ell);
        for k in 0..ell {
            let pack_values: Vec<Fr> =
                (0..n_w).map(|pack| w_at(pack, k)).collect();
            let jb = program.eval_linear_jb_sparse(&lane_bases[k], &pack_values)?;
            let mut acc = jvp[k];
            for (jb_j, gp_j) in jb.iter().zip(gamma_ps[b].iter()) {
                acc += *gp_j * *jb_j;
            }
            alpha_p_i.push(acc);
        }
        // Interpolate with S shares; exact sizes enforced.
        if rep.broadcast_alpha[b].len() != s_set.len()
            || rep.broadcast_alpha_prime[b].len() != sp_set.len()
        {
            return Err(fail("v3 wrong broadcast share count"));
        }
        let mut pts_a: Vec<Fr> = opened_idx.iter().map(|i| party_point(s, *i as usize)).collect();
        let mut vals_a = alpha_i;
        for (idx, v) in s_set.iter().zip(rep.broadcast_alpha[b].iter()) {
            pts_a.push(party_point(s, *idx));
            vals_a.push(*v);
        }
        let mut pts_p: Vec<Fr> = opened_idx.iter().map(|i| party_point(s, *i as usize)).collect();
        let mut vals_p = alpha_p_i;
        for (idx, v) in sp_set.iter().zip(rep.broadcast_alpha_prime[b].iter()) {
            pts_p.push(party_point(s, *idx));
            vals_p.push(*v);
        }
        let poly_a = interpolate_coeffs_fast(&pts_a, &vals_a).map_err(|e| fail(&format!("v3 {e}")))?;
        let poly_p = interpolate_coeffs_fast(&pts_p, &vals_p).map_err(|e| fail(&format!("v3 {e}")))?;
        // Canonical shares must reproduce hB.
        let canon_a: Vec<Fr> = (0..d_alpha + 1)
            .map(|i| crate::v3::sharing::eval_poly(&poly_a, party_point(s, i)))
            .collect();
        let canon_p: Vec<Fr> = (0..d2 + 1)
            .map(|i| crate::v3::sharing::eval_poly(&poly_p, party_point(s, i)))
            .collect();
        hb_inputs.push(canon_a);
        hb_inputs.push(canon_p);
        // Check 4: outcome α = 0, Σα′ = Σγ′t.
        let alpha_secret: Vec<Fr> = (0..s)
            .map(|k| crate::v3::sharing::eval_poly(&poly_a, crate::v3::sharing::coord_point(k)))
            .collect();
        if alpha_secret.iter().any(|v| !v.is_zero()) {
            return Err(fail("v3 broadcast outcome is not zero"));
        }
        let alpha_p_secret: Vec<Fr> = (0..s)
            .map(|k| crate::v3::sharing::eval_poly(&poly_p, crate::v3::sharing::coord_point(k)))
            .collect();
        // Σ α′ = Σ_j γ′_j t_j, where t_j is the constraint rhs.
        let mut rhs_sum = Fr::zero();
        for (j, constraint) in program.linear_constraints().iter().enumerate() {
            rhs_sum += gamma_ps[b][j] * constraint.rhs;
        }
        let got_sum: Fr = alpha_p_secret.iter().sum();
        if got_sum != rhs_sum {
            return Err(fail("v3 aggregated linear outcome mismatch"));
        }
    }
    if hash_fr_vecs(V3_HASH_TAG_BROADCAST, &hb_inputs) != rep.broadcast_hash {
        return Err(fail("v3 broadcast hash mismatch"));
    }

    // --- Check 3: DECS reconstruction-equality against h1'. ---
    if rep.decs_responses.len() != eta
        || rep.decs_responses.iter().any(|r| r.len() != sx_set.len())
    {
        return Err(fail("v3 wrong DECS response shape"));
    }
    let mut pxi_coeffs: Vec<Vec<Fr>> = Vec::with_capacity(eta);
    for k in 0..eta {
        let mut pts: Vec<Fr> = Vec::with_capacity(ell + sx_set.len());
        let mut vals: Vec<Fr> = Vec::with_capacity(ell + sx_set.len());
        for pos in 0..ell {
            let e = party_point(s, opened_idx[pos] as usize);
            pts.push(e);
            let mut acc = Fr::zero();
            for q in 0..num_q {
                let qv = if q_shift[q] == 0 {
                    q_at(q, pos)
                } else {
                    q_at(q, pos) * e.pow([q_shift[q] as u64])
                };
                acc += gamma[k * num_q + q] * qv;
            }
            vals.push(acc);
        }
        for (j, idx) in sx_set.iter().enumerate() {
            pts.push(party_point(s, *idx));
            vals.push(rep.decs_responses[k][j]);
        }
        pxi_coeffs
            .push(interpolate_coeffs_fast(&pts, &vals).map_err(|e| fail(&format!("v3 {e}")))?);
    }
    if hash_fr_vecs(V3_HASH_TAG_PXI, &pxi_coeffs) != rep.decs_hash {
        return Err(fail("v3 DECS hash mismatch"));
    }
    Ok(())
}

fn zero_mask_at(s: usize, party: usize) -> Fr {
    zero_mask_eval(s, party)
}
