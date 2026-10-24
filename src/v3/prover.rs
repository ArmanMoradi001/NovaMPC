//! Experimental V3 prover (TCitH-MT / ΠLigero, `V3_PROTOCOL.md` §1).
//!
//! Honest-prover mechanics only — no zero-knowledge, extraction, or
//! Fiat-Shamir security claim. Combined range-and-membership statements
//! only. All randomness comes from the caller-supplied RNG (seeded in
//! tests, making the whole proof deterministic).
//!
//! DECS alignment note: `Q` columns carry the word-rule shift `X^{dβ−deg}`
//! (see `V3_PROGRESS.md` P4.2); at the default `dβ = s+ℓ−1` every witness,
//! mask, and full-degree hint column has shift 0 and only the two short
//! Π$ tail hints shift. The printed Eq. 13 exponent would misalign packed
//! witness columns and is not used.

use ark_bn254::Fr;
use ark_ff::{Field, Zero};
use rand::RngCore;

use crate::v2::field::encode_fr;
use crate::v2::merkle::MerkleProofV2;
use crate::v2::predicate::{
    MembershipStatementV2, RangeStatementV2, StatementV2,
};
use crate::v3::commit::{leaf_commit, merkle_path, merkle_root};
use crate::v3::constraints::ConstraintProgramV3;
use crate::v3::hints::{
    correction_basis_eval, eval_hint_polys, sample_hint_polys, sigma_correction,
    zero_mask_eval, PiDollarV3,
};
use crate::v3::params::V3Params;
use crate::v3::proof::{OpenedPartyV3, RepProofV3, V3Proof};
use crate::v3::sharing::{eval_poly, interpolate_coeffs, party_point, share};
use crate::v3::transcript::{
    circuit_hash_v3, hash_fr_vecs, TranscriptV3, V3_HASH_TAG_BROADCAST, V3_HASH_TAG_PXI,
    V3_TR_TAG_BATCH, V3_TR_TAG_GAMMA, V3_TR_TAG_OPEN,
};
use crate::{MpcithError, Result};

/// Smallest indices not in `exclude`, in order (deterministic opening
/// complement for the `S`/`S′`/`Sξ` sets; the verifier recomputes the same
/// rule, so the sets are never transmitted).
pub(crate) fn complement_set(total: usize, exclude: &[u32], count: usize) -> Result<Vec<usize>> {
    let excluded: std::collections::BTreeSet<u32> = exclude.iter().copied().collect();
    let out: Vec<usize> = (0..total)
        .filter(|i| !excluded.contains(&(*i as u32)))
        .take(count)
        .collect();
    if out.len() != count {
        return Err(MpcithError::InvalidParams(format!(
            "v3 cannot select {count} parties outside the opened set of {total}"
        )));
    }
    Ok(out)
}

fn sample_fr(rng: &mut impl RngCore) -> Fr {
    use ark_ff::UniformRand;
    Fr::rand(rng)
}

/// Prove a combined range-and-membership statement (same private `x`).
/// Only `StatementV2::Combined` is supported; anything else is rejected.
#[allow(clippy::too_many_arguments)]
pub fn prove_combined_v3(
    lo: u32,
    hi: u32,
    root: Fr,
    num_members: u32,
    depth: u32,
    value: u32,
    merkle_proof: &MerkleProofV2,
    context: [u8; 32],
    params: &V3Params,
    rng: &mut impl RngCore,
) -> Result<V3Proof> {
    params.validate()?;
    let statement = StatementV2::Combined {
        range: RangeStatementV2::new(lo, hi)?,
        membership: MembershipStatementV2::new(root, num_members, depth)?,
    };
    let compiled = crate::v2::predicate::compile_from_statement(&statement)?;
    let program = ConstraintProgramV3::compile(compiled.circuit(), params)?;
    let inputs = compiled.witness_for(value, Some(merkle_proof))?;
    let matrix = program.witness_matrix(compiled.circuit(), &inputs)?;
    let circuit_hash = circuit_hash_v3(compiled.circuit());

    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);
    let set_root = encode_fr(&root);

    let mut reps = Vec::with_capacity(params.pok_reps as usize);
    for _ in 0..params.pok_reps {
        reps.push(prove_rep(
            &matrix, &program, params, &context, &circuit_hash, &salt,
            lo, hi, &set_root, num_members, depth, rng,
        )?);
    }

    Ok(V3Proof {
        params: *params,
        range_lo: lo,
        range_hi: hi,
        set_root,
        num_members,
        depth,
        context,
        circuit_hash,
        salt,
        reps,
    })
}

#[allow(clippy::too_many_arguments)]
fn prove_rep(
    matrix: &[Vec<Fr>],
    program: &ConstraintProgramV3,
    params: &V3Params,
    context: &[u8; 32],
    circuit_hash: &[u8; 32],
    salt: &[u8; 32],
    lo: u32,
    hi: u32,
    set_root: &[u8; 32],
    num_members: u32,
    depth: u32,
    rng: &mut impl RngCore,
) -> Result<RepProofV3> {
    let s = params.packing_width as usize;
    let ell = params.privacy_threshold as usize;
    let n = params.num_parties as usize;
    let eta = params.decs_reps as usize;
    let rho = params.mpc_reps as usize;
    let d_beta = params.hint_degree() as usize;
    let d_alpha = params.broadcast_degree() as usize;
    let d2 = 2 * s + ell - 2; // deg Jα′K
    let n_w = matrix.len();
    let m1 = program.m1();

    let pi_v = PiDollarV3::for_target(s, ell, d_beta, d_alpha - s)?;
    let pi_vp = PiDollarV3::for_target(s, ell, d_beta, d2)?;

    // --- 1. Committed shares: witness packs, mask packs, hint packs. ---
    // Q-column order (fixed convention): witness packs, mask packs, then
    // per MPC batch Π0 hints followed by ΠΣ0 hints.
    let mut q_shares: Vec<Vec<Fr>> = Vec::new();
    let mut q_shift: Vec<usize> = Vec::new();
    for pack in matrix {
        let r: Vec<Fr> = (0..ell).map(|_| sample_fr(rng)).collect();
        q_shares.push(share(s, ell, n, pack, &r)?);
        q_shift.push(d_beta - (s + ell - 1));
    }
    for _ in 0..eta {
        let secret: Vec<Fr> = (0..s).map(|_| sample_fr(rng)).collect();
        let r: Vec<Fr> = (0..ell).map(|_| sample_fr(rng)).collect();
        q_shares.push(share(s, ell, n, &secret, &r)?);
        q_shift.push(0);
    }
    struct BatchCommit {
        v_polys: Vec<Vec<Fr>>,
        vp_polys: Vec<Vec<Fr>>,
        delta_u1: Fr,
    }
    let mut batch_commits: Vec<BatchCommit> = Vec::new();
    for _ in 0..rho {
        let v_polys = sample_hint_polys(&pi_v.hint_degrees(d_beta), rng);
        let vp_polys = sample_hint_polys(&pi_vp.hint_degrees(d_beta), rng);
        let delta_u1 = sigma_correction(s, pi_vp.delta, &vp_polys);
        for polys in [&v_polys, &vp_polys] {
            for p in polys {
                q_shares.push(crate::v3::sharing::eval_poly_all(p, s, n));
                q_shift.push(d_beta - (p.len() - 1));
            }
        }
        batch_commits.push(BatchCommit { v_polys, vp_polys, delta_u1 });
    }
    debug_assert_eq!(q_shares.len(), n_w + eta + rho * (pi_v.num_hints + pi_vp.num_hints));

    let mut leaf_rand = vec![[0u8; 32]; n];
    for r in leaf_rand.iter_mut() {
        rng.fill_bytes(&mut *r);
    }
    let leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| {
            let values: Vec<Fr> = q_shares.iter().map(|v| v[i]).collect();
            leaf_commit(i as u32, &values, &leaf_rand[i])
        })
        .collect();
    let h1 = merkle_root(&leaves)?;

    // --- 2-3. Γ challenge, Pξ evaluation, h1'. ---
    let num_q = q_shares.len();
    let mut tr = TranscriptV3::new(
        params.num_parties, params.privacy_threshold, params.packing_width,
        params.decs_reps, params.mpc_reps, params.pok_reps,
        lo, hi, set_root, num_members, depth, context, circuit_hash, salt,
    );
    tr.absorb_hash(b"h1", &h1);
    let gamma = tr.sample_frs(V3_TR_TAG_GAMMA, 0, eta * num_q);
    // Pξ_k(e_i) for the first dβ+1 parties; interpolate to coefficients.
    let canon_d: Vec<usize> = (0..d_beta + 1).collect();
    let mut pxi_coeffs: Vec<Vec<Fr>> = Vec::with_capacity(eta);
    for k in 0..eta {
        let evals: Vec<Fr> = canon_d
            .iter()
            .map(|i| {
                let e = party_point(s, *i);
                let mut acc = Fr::zero();
                for (q, col) in q_shares.iter().enumerate() {
                    let shift = q_shift[q];
                    let qv = if shift == 0 {
                        col[*i]
                    } else {
                        col[*i] * e.pow([shift as u64])
                    };
                    acc += gamma[k * num_q + q] * qv;
                }
                acc
            })
            .collect();
        let pts: Vec<Fr> = canon_d.iter().map(|i| party_point(s, *i)).collect();
        pxi_coeffs.push(interpolate_coeffs(&pts, &evals)?);
    }
    let h1p = hash_fr_vecs(V3_HASH_TAG_PXI, &pxi_coeffs);
    tr.absorb_hash(b"h1p", &h1p);

    // --- 4-5. Batching challenges, broadcasts, hB. ---
    let pack_polys = program.linear_pack_polys()?;
    let mut batch_alpha: Vec<Vec<Fr>> = Vec::new(); // canonical JαK shares
    let mut batch_alpha_p: Vec<Vec<Fr>> = Vec::new();
    for (b, commit) in batch_commits.iter().enumerate() {
        let g = tr.sample_frs(V3_TR_TAG_BATCH, (2 * b) as u32, m1);
        let gp = tr.sample_frs(V3_TR_TAG_BATCH, (2 * b + 1) as u32, program.m2());
        // Derived mask sharings at all parties (full vectors, then select).
        let jt = pi_v.derive(s, &eval_hint_polys(&commit.v_polys, s, n))?;
        let jv: Vec<Fr> = jt
            .iter()
            .enumerate()
            .map(|(i, v)| *v * zero_mask_eval(s, i))
            .collect();
        let mut vp_corr = eval_hint_polys(&commit.vp_polys, s, n);
        for i in 0..n {
            vp_corr[0][i] += commit.delta_u1 * correction_basis_eval(s, party_point(s, i));
        }
        let jvp = pi_vp.derive(s, &vp_corr)?;
        // Broadcast shares at canonical index sets.
        let canon_a: Vec<usize> = (0..d_alpha + 1).collect();
        let alpha: Vec<Fr> = canon_a
            .iter()
            .map(|i| broadcast_alpha_at(program, &q_shares[..n_w], &jv, &g, *i))
            .collect::<Result<Vec<Fr>>>()?;
        let canon_ap: Vec<usize> = (0..d2 + 1).collect();
        let alpha_p: Vec<Fr> = canon_ap
            .iter()
            .map(|i| {
                broadcast_alpha_prime_at(&pack_polys, &q_shares[..n_w], &jvp, &gp, s, *i)
            })
            .collect::<Result<Vec<Fr>>>()?;
        batch_alpha.push(alpha);
        batch_alpha_p.push(alpha_p);
    }
    let mut hb_inputs: Vec<Vec<Fr>> = Vec::new();
    for (a, ap) in batch_alpha.iter().zip(batch_alpha_p.iter()) {
        hb_inputs.push(a.clone());
        hb_inputs.push(ap.clone());
    }
    let hb = hash_fr_vecs(V3_HASH_TAG_BROADCAST, &hb_inputs);
    tr.absorb_hash(b"hb", &hb);

    // --- 6-7. Opening set, complements, packaged openings. ---
    let opened_idx = tr.sample_subset(V3_TR_TAG_OPEN, 0, n, ell)?;
    let s_set = complement_set(n, &opened_idx, d_alpha + 1 - ell)?;
    let sp_set = complement_set(n, &opened_idx, d2 + 1 - ell)?;
    let sx_set = complement_set(n, &opened_idx, d_beta + 1 - ell)?;

    // S responses need full broadcast vectors: evaluate the interpolated
    // polys (recovered from canonical shares) at S.
    let mut s_alpha: Vec<Vec<Fr>> = Vec::new();
    let mut s_alpha_p: Vec<Vec<Fr>> = Vec::new();
    for (a, ap) in batch_alpha.iter().zip(batch_alpha_p.iter()) {
        let pa = interpolate_coeffs(
            &(0..d_alpha + 1).map(|i| party_point(s, i)).collect::<Vec<Fr>>(),
            a,
        )?;
        let pap = interpolate_coeffs(
            &(0..d2 + 1).map(|i| party_point(s, i)).collect::<Vec<Fr>>(),
            ap,
        )?;
        s_alpha.push(s_set.iter().map(|i| eval_poly(&pa, party_point(s, *i))).collect());
        s_alpha_p.push(sp_set.iter().map(|i| eval_poly(&pap, party_point(s, *i))).collect());
    }
    // DECS responses Pξ(e_i), i in Sξ.
    let mut decs_resp: Vec<Vec<Fr>> = Vec::with_capacity(eta);
    for k in 0..eta {
        let mut row = Vec::with_capacity(sx_set.len());
        for i in &sx_set {
            let e = party_point(s, *i);
            let mut acc = Fr::zero();
            for (q, col) in q_shares.iter().enumerate() {
                let qv = if q_shift[q] == 0 {
                    col[*i]
                } else {
                    col[*i] * e.pow([q_shift[q] as u64])
                };
                acc += gamma[k * num_q + q] * qv;
            }
            row.push(acc);
        }
        decs_resp.push(row);
    }

    let mut opened = Vec::with_capacity(ell);
    for oi in &opened_idx {
        let path = merkle_path(&leaves, *oi as usize)?;
        opened.push(OpenedPartyV3 {
            party_index: *oi,
            shares: q_shares.iter().map(|v| v[*oi as usize]).collect(),
            path: path.iter().map(|s| s.sibling).collect(),
            path_left: path.iter().map(|s| s.sibling_is_left).collect(),
            leaf_randomness: leaf_rand[*oi as usize],
        });
    }

    Ok(RepProofV3 {
        commitment_root: h1,
        decs_hash: h1p,
        broadcast_hash: hb,
        opened,
        broadcast_alpha: s_alpha,
        broadcast_alpha_prime: s_alpha_p,
        decs_responses: decs_resp,
        delta_u1: batch_commits.iter().map(|c| c.delta_u1).collect(),
    })
}

/// `JαK_i = JvK_i + Σ_g γ_g·(c−a·b)` at party `i` (Protocol 8 step 5).
fn broadcast_alpha_at(
    program: &ConstraintProgramV3,
    wshares: &[Vec<Fr>],
    jv: &[Fr],
    gamma: &[Fr],
    party: usize,
) -> Result<Fr> {
    let mut acc = jv[party];
    for (g, group) in program.parallel_groups().iter().enumerate() {
        let a = wshares[group.a_row][party];
        let b = wshares[group.b_row][party];
        let c = wshares[group.c_row][party];
        acc += gamma[g] * (c - a * b);
    }
    Ok(acc)
}

/// `Jα′K_i = Jv′K_i + Σ_j γ′_j·Jb_j,i` at party `i`, with
/// `Jb_j,i = Σ_p JA_j(p)(e_i)·w_{p,i}` (Protocol 8 step 5, §6.3).
fn broadcast_alpha_prime_at(
    pack_polys: &[Vec<(usize, Vec<Fr>)>],
    wshares: &[Vec<Fr>],
    jvp: &[Fr],
    gamma_p: &[Fr],
    s: usize,
    party: usize,
) -> Result<Fr> {
    let e = party_point(s, party);
    let mut acc = jvp[party];
    for (j, polys) in pack_polys.iter().enumerate() {
        let mut jb = Fr::zero();
        for (pack, poly) in polys {
            jb += eval_poly(poly, e) * wshares[*pack][party];
        }
        acc += gamma_p[j] * jb;
    }
    Ok(acc)
}
