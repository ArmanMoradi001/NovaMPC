//! Versioned v2 proof generation and verification.
//!
//! V2 does not embed a circuit in the proof. The verifier recompiles the
//! canonical circuit from the public statement, hashes that circuit, and then
//! checks the MPCitH transcript. This removes the v1 circuit-substitution
//! foot-gun and the v1 `expected_outputs` fallback.
//!
//! The transcript binds the suite, field, Poseidon2 instance, framing, N, M,
//! statement values, circuit hash, every repetition commitment root, and every
//! pre-challenge assertion-share row. It does not prove soundness or
//! zero-knowledge; see `V2_PROTOCOL_NOTES.md`.

use ark_bn254::Fr;
use rand::{thread_rng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::v2::circuit::{CircuitV2, GateV2};
use crate::v2::commit_tree::{CommitProofV2, CommitTreeV2};
use crate::v2::commitment::commit_view_v2;
use crate::v2::field::{decode_fr, encode_fr};
use crate::v2::merkle::MerkleProofV2;
use crate::v2::mpc::{
    encode_view_payload, recompute_linear_shares, run_mpc_emulation, verify_party_view,
    MpcExecutionV2, OpenedNeighborV2,
};
use crate::v2::predicate::{
    compile_combined, compile_from_statement, compile_membership, compile_range, CompiledV2,
    MembershipStatementV2, RangeStatementV2, StatementV2,
};
use crate::v2::seed_tree::{reconstruct_leaves_from_co_path, SeedTreeV2};
use crate::v2::sharing::PartySeedV2;
use crate::v2::suite::{
    V2Params, V2Suite, MAX_V2_REPETITIONS, V2_FIELD_ID, V2_PROOF_VERSION, V2_SUITE,
};
use crate::{MpcithError, Result};

/// Magic prefix for canonical v2 proof bytes. V1 bincode proofs do not start
/// with this value.
pub const V2_PROOF_MAGIC: [u8; 8] = *b"NMPCV2P\0";

const CIRCUIT_HASH_CONTEXT: &str = "NovaMPC-v2/circuit-hash/v1";
const TRANSCRIPT_CONTEXT: &str = "NovaMPC-v2/transcript/v1";
const CHALLENGE_CONTEXT: &str = "NovaMPC-v2/challenge-rng/v1";

const MAX_V2_MUL_SHARES: usize = 1 << 20;
const MAX_V2_RESIDUAL_SHARES: usize = 1 << 20;
const MAX_V2_ASSERT_ROWS: usize = 1 << 20;
const MAX_V2_PATH_DEPTH: usize = 64;
// A three-party repetition always contains two opened-view headers and two
// two-node paths. This lower bound prevents a tiny malformed proof from
// reserving space for the maximum repetition count.
const MIN_V2_REPETITION_BYTES: usize = 256;
/// Absolute decoder bound for a serialized v2 proof. This is a resource bound,
/// not a security parameter. Larger proofs are rejected before decoding.
pub const MAX_V2_PROOF_BYTES: usize = 1 << 30;

/// One opened party view in a v2 proof. The seed is deliberately absent: the
/// verifier reconstructs it from the V2 seed-tree co-path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedViewV2 {
    pub party_idx: u32,
    pub mul_output_shares: Vec<Fr>,
    pub residual_input_shares: Vec<Fr>,
    pub commitment_randomness: [u8; 32],
    pub commitment_auth_path: Vec<[u8; 32]>,
}

/// One repetition of a v2 cut-and-choose proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepetitionProofV2 {
    pub hidden_party: u32,
    pub commitment_root: [u8; 32],
    pub co_path: Vec<[u8; 32]>,
    pub opened_views: Vec<OpenedViewV2>,
    /// `[assertion_idx][party]`, pre-challenge and transcript-bound.
    pub assert_shares: Vec<Vec<Fr>>,
}

/// A complete v2 proof. No circuit and no prover-supplied expected outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Proof {
    pub version: u16,
    pub params: V2Params,
    pub statement: StatementV2,
    pub repetitions: Vec<RepetitionProofV2>,
}

impl V2Proof {
    /// Canonical fixed-width encoding. All variable-length vectors have u32
    /// length prefixes; field elements are 32-byte big-endian canonical values.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&V2_PROOF_MAGIC);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.params.num_parties.to_be_bytes());
        out.extend_from_slice(&self.params.num_repetitions.to_be_bytes());
        encode_statement(&mut out, &self.statement);

        let rep_count = u32_len(self.repetitions.len(), "v2 repetitions")?;
        out.extend_from_slice(&rep_count.to_be_bytes());
        for rep in &self.repetitions {
            out.extend_from_slice(&rep.hidden_party.to_be_bytes());
            out.extend_from_slice(&rep.commitment_root);

            let co_len = u32_len(rep.co_path.len(), "v2 co-path")?;
            out.extend_from_slice(&co_len.to_be_bytes());
            for seed in &rep.co_path {
                out.extend_from_slice(seed);
            }

            let opened_len = u32_len(rep.opened_views.len(), "v2 opened views")?;
            out.extend_from_slice(&opened_len.to_be_bytes());
            for view in &rep.opened_views {
                out.extend_from_slice(&view.party_idx.to_be_bytes());

                let mul_len = u32_len(view.mul_output_shares.len(), "v2 Mul shares")?;
                out.extend_from_slice(&mul_len.to_be_bytes());
                for share in &view.mul_output_shares {
                    out.extend_from_slice(&encode_fr(share));
                }

                let residual_len = u32_len(view.residual_input_shares.len(), "v2 residual shares")?;
                out.extend_from_slice(&residual_len.to_be_bytes());
                for share in &view.residual_input_shares {
                    out.extend_from_slice(&encode_fr(share));
                }

                out.extend_from_slice(&view.commitment_randomness);
                let auth_len = u32_len(view.commitment_auth_path.len(), "v2 commitment auth path")?;
                out.extend_from_slice(&auth_len.to_be_bytes());
                for node in &view.commitment_auth_path {
                    out.extend_from_slice(node);
                }
            }

            let rows_len = u32_len(rep.assert_shares.len(), "v2 assertion rows")?;
            out.extend_from_slice(&rows_len.to_be_bytes());
            for row in &rep.assert_shares {
                let row_len = u32_len(row.len(), "v2 assertion row")?;
                out.extend_from_slice(&row_len.to_be_bytes());
                for share in row {
                    out.extend_from_slice(&encode_fr(share));
                }
            }
        }
        if out.len() > MAX_V2_PROOF_BYTES {
            return Err(MpcithError::InvalidParams(format!(
                "v2 proof encoding is {} bytes, exceeding maximum {MAX_V2_PROOF_BYTES}",
                out.len()
            )));
        }
        Ok(out)
    }

    /// Strict canonical decoder. Rejects wrong magic/version, malformed
    /// lengths, non-canonical field bytes, and trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_V2_PROOF_BYTES {
            return Err(ser_err(format!(
                "v2 proof is {} bytes, exceeding maximum {MAX_V2_PROOF_BYTES}",
                bytes.len()
            )));
        }
        let mut reader = Reader::new(bytes);

        if reader.take(8)? != V2_PROOF_MAGIC {
            return Err(ser_err("not a v2 proof (bad magic)".into()));
        }
        let version = reader.u16()?;
        if version != V2_PROOF_VERSION {
            return Err(ser_err(format!(
                "unsupported v2 proof version {version}, expected {V2_PROOF_VERSION}"
            )));
        }
        let params = V2Params::new(reader.u32()?, reader.u32()?);
        params
            .validate()
            .map_err(|e| ser_err(format!("invalid v2 proof parameters: {e}")))?;
        let num_parties = params.num_parties as usize;
        let tree_depth = tree_depth(params.num_parties);

        let statement = decode_statement(&mut reader)?;

        let rep_count = reader.len(
            "repetitions",
            MIN_V2_REPETITION_BYTES,
            MAX_V2_REPETITIONS as usize,
        )?;
        if rep_count != params.num_repetitions as usize {
            return Err(ser_err(format!(
                "v2 proof has {rep_count} repetitions, parameters declare {}",
                params.num_repetitions
            )));
        }
        let mut repetitions = Vec::with_capacity(rep_count);
        for _ in 0..rep_count {
            let hidden_party = reader.u32()?;
            if hidden_party as usize >= num_parties {
                return Err(ser_err(format!(
                    "v2 hidden party {hidden_party} out of range"
                )));
            }
            let commitment_root = reader.hash32()?;

            let co_len = reader.len("co-path", 32, MAX_V2_PATH_DEPTH)?;
            if co_len != tree_depth {
                return Err(ser_err(format!(
                    "v2 co-path has {co_len} nodes, expected {tree_depth}"
                )));
            }
            let mut co_path = Vec::with_capacity(co_len);
            for _ in 0..co_len {
                co_path.push(reader.hash32()?);
            }

            let opened_count = reader.len("opened views", 1, num_parties - 1)?;
            if opened_count != num_parties - 1 {
                return Err(ser_err(format!(
                    "v2 proof has {opened_count} opened views, expected {}",
                    num_parties - 1
                )));
            }
            let mut opened_views = Vec::with_capacity(opened_count);
            for _ in 0..opened_count {
                let party_idx = reader.u32()?;
                if party_idx as usize >= num_parties || party_idx == hidden_party {
                    return Err(ser_err(format!(
                        "v2 opened party {party_idx} is invalid for hidden party {hidden_party}"
                    )));
                }

                let mul_len = reader.len("Mul shares", 32, MAX_V2_MUL_SHARES)?;
                let mut mul_output_shares = Vec::with_capacity(mul_len);
                for _ in 0..mul_len {
                    mul_output_shares.push(reader.fr()?);
                }

                let residual_len = reader.len("residual shares", 32, MAX_V2_RESIDUAL_SHARES)?;
                if party_idx as usize != num_parties - 1 && residual_len != 0 {
                    return Err(ser_err(format!(
                        "v2 party {party_idx} carries residual input shares"
                    )));
                }
                let mut residual_input_shares = Vec::with_capacity(residual_len);
                for _ in 0..residual_len {
                    residual_input_shares.push(reader.fr()?);
                }

                let commitment_randomness = reader.hash32()?;
                let auth_len = reader.len("commitment auth path", 32, MAX_V2_PATH_DEPTH)?;
                if auth_len != tree_depth {
                    return Err(ser_err(format!(
                        "v2 commitment auth path has {auth_len} nodes, expected {tree_depth}"
                    )));
                }
                let mut commitment_auth_path = Vec::with_capacity(auth_len);
                for _ in 0..auth_len {
                    commitment_auth_path.push(reader.hash32()?);
                }

                opened_views.push(OpenedViewV2 {
                    party_idx,
                    mul_output_shares,
                    residual_input_shares,
                    commitment_randomness,
                    commitment_auth_path,
                });
            }

            let row_count =
                reader.len("assertion rows", 4 + num_parties * 32, MAX_V2_ASSERT_ROWS)?;
            let mut assert_shares = Vec::new();
            for _ in 0..row_count {
                let row_len = reader.u32()? as usize;
                if row_len != num_parties {
                    return Err(ser_err(format!(
                        "v2 assertion row length {row_len}, expected {num_parties}"
                    )));
                }
                let mut row = Vec::with_capacity(row_len);
                for _ in 0..row_len {
                    row.push(reader.fr()?);
                }
                assert_shares.push(row);
            }

            repetitions.push(RepetitionProofV2 {
                hidden_party,
                commitment_root,
                co_path,
                opened_views,
                assert_shares,
            });
        }

        if reader.remaining() != 0 {
            return Err(ser_err(format!(
                "v2 proof has {} trailing bytes",
                reader.remaining()
            )));
        }

        Ok(Self {
            version,
            params,
            statement,
            repetitions,
        })
    }

    pub fn serialized_size(&self) -> Result<usize> {
        Ok(self.to_bytes()?.len())
    }
}

fn u32_len(value: usize, what: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| MpcithError::InvalidParams(format!("{what} length {value} does not fit u32")))
}

fn ser_err(message: String) -> MpcithError {
    MpcithError::SerializationError(message)
}

fn encode_statement(out: &mut Vec<u8>, statement: &StatementV2) {
    out.push(statement.type_tag());
    match statement {
        StatementV2::Range(range) => {
            out.extend_from_slice(&range.lo.to_be_bytes());
            out.extend_from_slice(&range.hi.to_be_bytes());
        }
        StatementV2::Membership(membership) => {
            out.extend_from_slice(&encode_fr(&membership.root));
            out.extend_from_slice(&membership.num_members.to_be_bytes());
            out.extend_from_slice(&membership.depth.to_be_bytes());
        }
        StatementV2::Combined { range, membership } => {
            out.extend_from_slice(&range.lo.to_be_bytes());
            out.extend_from_slice(&range.hi.to_be_bytes());
            out.extend_from_slice(&encode_fr(&membership.root));
            out.extend_from_slice(&membership.num_members.to_be_bytes());
            out.extend_from_slice(&membership.depth.to_be_bytes());
        }
    }
}

fn decode_statement(reader: &mut Reader<'_>) -> Result<StatementV2> {
    let tag = reader.u8()?;
    let statement = match tag {
        1 => {
            let lo = reader.u32()?;
            let hi = reader.u32()?;
            StatementV2::Range(
                RangeStatementV2::new(lo, hi)
                    .map_err(|e| ser_err(format!("invalid v2 range statement: {e}")))?,
            )
        }
        2 => {
            let root = reader.fr()?;
            let num_members = reader.u32()?;
            let depth = reader.u32()?;
            StatementV2::Membership(
                MembershipStatementV2::new(root, num_members, depth)
                    .map_err(|e| ser_err(format!("invalid v2 membership statement: {e}")))?,
            )
        }
        3 => {
            let lo = reader.u32()?;
            let hi = reader.u32()?;
            let root = reader.fr()?;
            let num_members = reader.u32()?;
            let depth = reader.u32()?;
            let range = RangeStatementV2::new(lo, hi)
                .map_err(|e| ser_err(format!("invalid v2 range statement: {e}")))?;
            let membership = MembershipStatementV2::new(root, num_members, depth)
                .map_err(|e| ser_err(format!("invalid v2 membership statement: {e}")))?;
            StatementV2::Combined { range, membership }
        }
        other => return Err(ser_err(format!("unknown v2 statement tag {other}"))),
    };
    Ok(statement)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(count)
            .ok_or_else(|| ser_err("v2 proof length overflow".into()))?;
        if end > self.bytes.len() {
            return Err(ser_err(format!(
                "truncated v2 proof: need {count} bytes, only {} remain",
                self.remaining()
            )));
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn fr(&mut self) -> Result<Fr> {
        let bytes = self.take(32)?;
        decode_fr(bytes).map_err(|e| ser_err(format!("non-canonical v2 field element: {e}")))
    }

    fn hash32(&mut self) -> Result<[u8; 32]> {
        let bytes = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn len(&mut self, label: &str, min_item_bytes: usize, max: usize) -> Result<usize> {
        let value = self.u32()? as usize;
        if value > max {
            return Err(ser_err(format!(
                "v2 {label} length {value} exceeds maximum {max}"
            )));
        }
        if min_item_bytes > 0 && value > self.remaining() / min_item_bytes {
            return Err(ser_err(format!(
                "v2 {label} length {value} exceeds remaining proof bytes"
            )));
        }
        Ok(value)
    }
}

// ─── Circuit hashing and transcript ──────────────────────────────────────────

fn absorb(hasher: &mut blake3::Hasher, label: &[u8], bytes: &[u8]) {
    hasher.update(&(label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn absorb_u8(hasher: &mut blake3::Hasher, label: &[u8], value: u8) {
    absorb(hasher, label, &[value]);
}

fn absorb_u32(hasher: &mut blake3::Hasher, label: &[u8], value: u32) {
    absorb(hasher, label, &value.to_be_bytes());
}

fn absorb_u64(hasher: &mut blake3::Hasher, label: &[u8], value: u64) {
    absorb(hasher, label, &value.to_be_bytes());
}

fn absorb_fr(hasher: &mut blake3::Hasher, label: &[u8], value: &Fr) {
    absorb(hasher, label, &encode_fr(value));
}

const GATE_ADD: u8 = 1;
const GATE_MUL: u8 = 2;
const GATE_ADD_CONST: u8 = 3;
const GATE_MUL_CONST: u8 = 4;
const GATE_ASSERT_EQ: u8 = 5;

/// Canonical hash of the v2 circuit, including every gate and field constant.
/// The verifier hashes its independently recompiled circuit; no proof-supplied
/// circuit is ever hashed.
pub fn hash_circuit_v2(circuit: &CircuitV2) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CIRCUIT_HASH_CONTEXT);
    absorb(&mut hasher, b"field", V2_FIELD_ID);
    absorb(&mut hasher, b"version", &V2_PROOF_VERSION.to_be_bytes());
    absorb_u64(&mut hasher, b"num-inputs", circuit.num_inputs() as u64);
    absorb_u64(&mut hasher, b"num-wires", circuit.num_wires() as u64);
    absorb_u64(&mut hasher, b"num-gates", circuit.gates().len() as u64);
    for gate in circuit.gates() {
        match gate {
            GateV2::Add {
                left,
                right,
                output,
            } => {
                absorb_u8(&mut hasher, b"gate", GATE_ADD);
                absorb_u64(&mut hasher, b"left", left.index() as u64);
                absorb_u64(&mut hasher, b"right", right.index() as u64);
                absorb_u64(&mut hasher, b"output", output.index() as u64);
            }
            GateV2::Mul {
                left,
                right,
                output,
            } => {
                absorb_u8(&mut hasher, b"gate", GATE_MUL);
                absorb_u64(&mut hasher, b"left", left.index() as u64);
                absorb_u64(&mut hasher, b"right", right.index() as u64);
                absorb_u64(&mut hasher, b"output", output.index() as u64);
            }
            GateV2::AddConst {
                input,
                constant,
                output,
            } => {
                absorb_u8(&mut hasher, b"gate", GATE_ADD_CONST);
                absorb_u64(&mut hasher, b"input", input.index() as u64);
                absorb_fr(&mut hasher, b"constant", constant);
                absorb_u64(&mut hasher, b"output", output.index() as u64);
            }
            GateV2::MulConst {
                input,
                constant,
                output,
            } => {
                absorb_u8(&mut hasher, b"gate", GATE_MUL_CONST);
                absorb_u64(&mut hasher, b"input", input.index() as u64);
                absorb_fr(&mut hasher, b"constant", constant);
                absorb_u64(&mut hasher, b"output", output.index() as u64);
            }
            GateV2::AssertEq { input, expected } => {
                absorb_u8(&mut hasher, b"gate", GATE_ASSERT_EQ);
                absorb_u64(&mut hasher, b"input", input.index() as u64);
                absorb_fr(&mut hasher, b"expected", expected);
            }
        }
    }
    *hasher.finalize().as_bytes()
}

struct TranscriptRepV2<'a> {
    commitment_root: [u8; 32],
    assert_shares: &'a [Vec<Fr>],
}

fn transcript_hash(
    statement: &StatementV2,
    params: &V2Params,
    circuit_hash: &[u8; 32],
    reps: &[TranscriptRepV2<'_>],
    suite: &V2Suite,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(TRANSCRIPT_CONTEXT);
    absorb(&mut hasher, b"protocol", suite.protocol_id);
    absorb(&mut hasher, b"version", &suite.version.to_be_bytes());
    absorb(&mut hasher, b"field", suite.field_id);
    absorb(&mut hasher, b"poseidon2", suite.poseidon2_id);
    absorb(&mut hasher, b"framing", suite.framing_id);
    absorb_u32(&mut hasher, b"num-parties", params.num_parties);
    absorb_u32(&mut hasher, b"num-repetitions", params.num_repetitions);
    absorb_u8(&mut hasher, b"statement-type", statement.type_tag());
    let public_values = statement.public_values();
    absorb_u32(
        &mut hasher,
        b"statement-value-count",
        public_values.len() as u32,
    );
    for value in &public_values {
        absorb_fr(&mut hasher, b"statement-value", value);
    }
    absorb(&mut hasher, b"circuit-hash", circuit_hash);
    absorb_u32(&mut hasher, b"repetition-count", reps.len() as u32);
    for (rep, material) in reps.iter().enumerate() {
        absorb_u32(&mut hasher, b"repetition", rep as u32);
        absorb(&mut hasher, b"commitment-root", &material.commitment_root);
        absorb_u32(
            &mut hasher,
            b"assertion-row-count",
            material.assert_shares.len() as u32,
        );
        for row in material.assert_shares {
            absorb_u32(&mut hasher, b"assertion-row-length", row.len() as u32);
            for share in row {
                absorb_fr(&mut hasher, b"assertion-share", share);
            }
        }
    }
    *hasher.finalize().as_bytes()
}

fn derive_challenges(transcript: &[u8; 32], params: &V2Params) -> Vec<u32> {
    let seed = blake3::derive_key(CHALLENGE_CONTEXT, transcript);
    let mut rng = ChaCha20Rng::from_seed(seed);
    (0..params.num_repetitions)
        .map(|_| rng.gen_range(0..params.num_parties))
        .collect()
}

fn tree_depth(num_parties: u32) -> usize {
    num_parties.next_power_of_two().trailing_zeros() as usize
}

fn assert_gates(circuit: &CircuitV2) -> Vec<(usize, Fr)> {
    circuit
        .gates()
        .iter()
        .filter_map(|gate| match gate {
            GateV2::AssertEq { input, expected } => Some((input.index(), *expected)),
            _ => None,
        })
        .collect()
}

fn num_mul_gates(circuit: &CircuitV2) -> usize {
    circuit
        .gates()
        .iter()
        .filter(|gate| matches!(gate, GateV2::Mul { .. }))
        .count()
}

// ─── Structural validation ───────────────────────────────────────────────────

fn validate_structure(proof: &V2Proof, params: &V2Params, circuit: &CircuitV2) -> Result<()> {
    let malformed =
        |message: String| MpcithError::VerificationFailed(format!("malformed v2 proof: {message}"));

    if proof.version != V2_PROOF_VERSION {
        return Err(malformed(format!(
            "proof version {}, expected {V2_PROOF_VERSION}",
            proof.version
        )));
    }
    if proof.params != *params {
        return Err(malformed(
            "proof parameters do not match verifier parameters".into(),
        ));
    }
    if proof.repetitions.len() != params.num_repetitions as usize {
        return Err(malformed(format!(
            "proof has {} repetitions, expected {}",
            proof.repetitions.len(),
            params.num_repetitions
        )));
    }

    let num_parties = params.num_parties as usize;
    let depth = tree_depth(params.num_parties);
    let expected_mul = num_mul_gates(circuit);
    let expected_asserts = assert_gates(circuit).len();

    for (rep_idx, rep) in proof.repetitions.iter().enumerate() {
        let ctx = |message: String| malformed(format!("repetition {rep_idx}: {message}"));
        let hidden = rep.hidden_party as usize;
        if hidden >= num_parties {
            return Err(ctx(format!(
                "hidden party {} out of range for {num_parties} parties",
                rep.hidden_party
            )));
        }
        if rep.co_path.len() != depth {
            return Err(ctx(format!(
                "co-path has {} nodes, expected {depth}",
                rep.co_path.len()
            )));
        }
        if rep.opened_views.len() != num_parties - 1 {
            return Err(ctx(format!(
                "expected {} opened views, got {}",
                num_parties - 1,
                rep.opened_views.len()
            )));
        }

        let mut seen = vec![false; num_parties];
        for view in &rep.opened_views {
            let party = view.party_idx as usize;
            if party >= num_parties {
                return Err(ctx(format!("opened party {} out of range", view.party_idx)));
            }
            if party == hidden {
                return Err(ctx(format!("opened view claims hidden party {party}")));
            }
            if seen[party] {
                return Err(ctx(format!("duplicate opened party {party}")));
            }
            seen[party] = true;

            if view.mul_output_shares.len() != expected_mul {
                return Err(ctx(format!(
                    "party {party}: {} Mul shares, expected {expected_mul}",
                    view.mul_output_shares.len()
                )));
            }
            let expected_residual = if party == num_parties - 1 {
                circuit.num_inputs()
            } else {
                0
            };
            if view.residual_input_shares.len() != expected_residual {
                return Err(ctx(format!(
                    "party {party}: {} residual input shares, expected {expected_residual}",
                    view.residual_input_shares.len()
                )));
            }
            if view.commitment_auth_path.len() != depth {
                return Err(ctx(format!(
                    "party {party}: commitment auth path has {} nodes, expected {depth}",
                    view.commitment_auth_path.len()
                )));
            }
        }
        for (party, &opened) in seen.iter().enumerate() {
            if !opened && party != hidden {
                return Err(ctx(format!(
                    "non-hidden party {party} is missing from opened views"
                )));
            }
        }

        if rep.assert_shares.len() != expected_asserts {
            return Err(ctx(format!(
                "{} assertion rows, expected {expected_asserts}",
                rep.assert_shares.len()
            )));
        }
        for row in &rep.assert_shares {
            if row.len() != num_parties {
                return Err(ctx(format!(
                    "assertion row has {} shares, expected {num_parties}",
                    row.len()
                )));
            }
        }
    }
    Ok(())
}

// ─── Proving ─────────────────────────────────────────────────────────────────

struct RepDataV2 {
    tree: SeedTreeV2,
    execution: MpcExecutionV2,
    randomness: Vec<[u8; 32]>,
    commit_tree: CommitTreeV2,
    assert_shares: Vec<Vec<Fr>>,
}

/// Prove a precompiled v2 statement.
///
/// The circuit is recompiled from the statement and compared with `compiled`,
/// so the proof always follows the verifier's canonical circuit.
pub fn prove(compiled: &CompiledV2, witness: &[Fr], params: &V2Params) -> Result<V2Proof> {
    params.validate()?;
    let canonical = compile_from_statement(compiled.statement())?;
    if canonical.circuit() != compiled.circuit() {
        return Err(MpcithError::InvalidParams(
            "compiled v2 circuit does not match its canonical statement circuit".into(),
        ));
    }
    let circuit = canonical.circuit();
    if witness.len() != circuit.num_inputs() {
        return Err(MpcithError::InvalidWitness(format!(
            "v2 witness has length {}, circuit declares {} inputs",
            witness.len(),
            circuit.num_inputs()
        )));
    }
    circuit.evaluate(witness).map_err(|e| {
        MpcithError::InvalidWitness(format!("v2 witness does not satisfy circuit: {e}"))
    })?;

    let num_parties = params.num_parties as usize;
    let assertions = assert_gates(circuit);
    let circuit_hash = hash_circuit_v2(circuit);
    let mut rng = thread_rng();
    let mut reps = Vec::with_capacity(params.num_repetitions as usize);

    for repetition in 0..params.num_repetitions {
        let mut root_seed = [0u8; 32];
        rng.fill_bytes(&mut root_seed);
        let tree = SeedTreeV2::build(root_seed, num_parties)?;
        let seeds: Vec<PartySeedV2> = tree.leaf_seeds().into_iter().map(PartySeedV2).collect();
        let execution = run_mpc_emulation(circuit, witness, &seeds)?;

        let assert_shares: Vec<Vec<Fr>> = assertions
            .iter()
            .map(|(wire, _)| {
                (0..num_parties)
                    .map(|party| execution.shared_trace.wires[*wire].shares[party])
                    .collect()
            })
            .collect();

        let mut commitments = Vec::with_capacity(num_parties);
        let mut randomness = Vec::with_capacity(num_parties);
        for party in 0..num_parties {
            let mut random = [0u8; 32];
            rng.fill_bytes(&mut random);
            let view = &execution.views[party];
            let payload = encode_view_payload(&view.mul_output_shares, &view.residual_input_shares);
            commitments.push(commit_view_v2(
                repetition,
                party as u32,
                &view.seed,
                &payload,
                &random,
            ));
            randomness.push(random);
        }
        let commit_tree = CommitTreeV2::build(&commitments)?;

        reps.push(RepDataV2 {
            tree,
            execution,
            randomness,
            commit_tree,
            assert_shares,
        });
    }

    let transcript_reps: Vec<TranscriptRepV2<'_>> = reps
        .iter()
        .map(|rep| TranscriptRepV2 {
            commitment_root: rep.commit_tree.root(),
            assert_shares: &rep.assert_shares,
        })
        .collect();
    let transcript = transcript_hash(
        canonical.statement(),
        params,
        &circuit_hash,
        &transcript_reps,
        &V2_SUITE,
    );
    let challenges = derive_challenges(&transcript, params);

    let mut repetition_proofs = Vec::with_capacity(reps.len());
    for (data, &hidden) in reps.iter().zip(challenges.iter()) {
        let hidden = hidden as usize;
        let co_path = data.tree.co_path(hidden)?;
        let mut opened_views = Vec::with_capacity(num_parties - 1);
        for party in 0..num_parties {
            if party == hidden {
                continue;
            }
            let view = &data.execution.views[party];
            let auth = data.commit_tree.prove_membership(party)?;
            opened_views.push(OpenedViewV2 {
                party_idx: party as u32,
                mul_output_shares: view.mul_output_shares.clone(),
                residual_input_shares: view.residual_input_shares.clone(),
                commitment_randomness: data.randomness[party],
                commitment_auth_path: auth.siblings,
            });
        }
        repetition_proofs.push(RepetitionProofV2 {
            hidden_party: hidden as u32,
            commitment_root: data.commit_tree.root(),
            co_path,
            opened_views,
            assert_shares: data.assert_shares.clone(),
        });
    }

    Ok(V2Proof {
        version: V2_PROOF_VERSION,
        params: params.clone(),
        statement: canonical.statement().clone(),
        repetitions: repetition_proofs,
    })
}

/// Prove a public statement with a caller-supplied canonical witness.
///
/// The witness layout is the one produced by [`CompiledV2::witness_for`]. This
/// entry point exists for callers that already have a witness; most users
/// should prefer the mode-specific helpers below.
pub fn prove_statement(
    statement: &StatementV2,
    witness: &[Fr],
    params: &V2Params,
) -> Result<V2Proof> {
    let compiled = compile_from_statement(statement)?;
    prove(&compiled, witness, params)
}

/// Convenience wrapper for a range-only proof.
pub fn prove_range(lo: u32, hi: u32, value: u32, params: &V2Params) -> Result<V2Proof> {
    let compiled = compile_range(lo, hi)?;
    let witness = compiled.witness_for(value, None)?;
    prove(&compiled, &witness, params)
}

/// Convenience wrapper for a membership-only proof.
pub fn prove_membership(
    root: Fr,
    num_members: u32,
    depth: u32,
    value: u32,
    membership_proof: &MerkleProofV2,
    params: &V2Params,
) -> Result<V2Proof> {
    let compiled = compile_membership(root, num_members, depth)?;
    let witness = compiled.witness_for(value, Some(membership_proof))?;
    prove(&compiled, &witness, params)
}

/// Convenience wrapper for a combined range-and-membership proof.
pub fn prove_combined(
    lo: u32,
    hi: u32,
    root: Fr,
    num_members: u32,
    depth: u32,
    value: u32,
    membership_proof: &MerkleProofV2,
    params: &V2Params,
) -> Result<V2Proof> {
    let compiled = compile_combined(lo, hi, root, num_members, depth)?;
    let witness = compiled.witness_for(value, Some(membership_proof))?;
    prove(&compiled, &witness, params)
}

// ─── Verification ────────────────────────────────────────────────────────────

/// Verify a v2 proof against the statement embedded in it.
///
/// Applications that require a specific statement must use
/// [`verify_statement`] or compare `proof.statement` themselves.
pub fn verify(proof: &V2Proof, params: &V2Params) -> Result<()> {
    params.validate()?;
    if proof.version != V2_PROOF_VERSION {
        return Err(MpcithError::VerificationFailed(format!(
            "v2 proof version {}, expected {V2_PROOF_VERSION}",
            proof.version
        )));
    }
    if proof.params != *params {
        return Err(MpcithError::VerificationFailed(
            "v2 proof parameters do not match verifier parameters".into(),
        ));
    }

    let canonical = compile_from_statement(&proof.statement)?;
    let circuit = canonical.circuit();
    validate_structure(proof, params, circuit)?;

    let circuit_hash = hash_circuit_v2(circuit);
    let transcript_reps: Vec<TranscriptRepV2<'_>> = proof
        .repetitions
        .iter()
        .map(|rep| TranscriptRepV2 {
            commitment_root: rep.commitment_root,
            assert_shares: &rep.assert_shares,
        })
        .collect();
    let transcript = transcript_hash(
        &proof.statement,
        params,
        &circuit_hash,
        &transcript_reps,
        &V2_SUITE,
    );
    let challenges = derive_challenges(&transcript, params);
    let num_parties = params.num_parties as usize;
    let assertions = assert_gates(circuit);

    for (rep_idx, (rep, &expected_hidden)) in
        proof.repetitions.iter().zip(challenges.iter()).enumerate()
    {
        if rep.hidden_party != expected_hidden {
            return Err(MpcithError::VerificationFailed(format!(
                "v2 repetition {rep_idx}: hidden party mismatch (expected {expected_hidden}, got {})",
                rep.hidden_party
            )));
        }
        let hidden = rep.hidden_party as usize;

        let seeds = reconstruct_leaves_from_co_path(&rep.co_path, hidden, num_parties)?;

        let mut opened_index_of = vec![usize::MAX; num_parties];
        let mut all_wire_shares = Vec::with_capacity(rep.opened_views.len());
        for view in &rep.opened_views {
            let party = view.party_idx as usize;
            let wire_shares = recompute_linear_shares(
                circuit,
                &seeds[party],
                party,
                num_parties,
                &view.mul_output_shares,
                &view.residual_input_shares,
            )?;
            opened_index_of[party] = all_wire_shares.len();
            all_wire_shares.push(wire_shares);
        }

        for (opened_idx, view) in rep.opened_views.iter().enumerate() {
            let party = view.party_idx as usize;
            let payload = encode_view_payload(&view.mul_output_shares, &view.residual_input_shares);
            let computed = commit_view_v2(
                rep_idx as u32,
                party as u32,
                &seeds[party],
                &payload,
                &view.commitment_randomness,
            );
            let commitment_proof = CommitProofV2 {
                leaf: computed,
                leaf_index: view.party_idx,
                siblings: view.commitment_auth_path.clone(),
                root: rep.commitment_root,
            };
            if !commitment_proof.verify() {
                return Err(MpcithError::CommitmentMismatch {
                    party,
                    repetition: rep_idx,
                });
            }

            let next = (party + 1) % num_parties;
            let next_opened = if next != hidden {
                let next_idx = opened_index_of[next];
                if next_idx == usize::MAX {
                    return Err(MpcithError::VerificationFailed(format!(
                        "v2 repetition {rep_idx}: opened neighbour {next} is missing"
                    )));
                }
                Some(OpenedNeighborV2 {
                    seed: &seeds[next],
                    wire_shares: &all_wire_shares[next_idx],
                })
            } else {
                None
            };

            verify_party_view(
                circuit,
                &all_wire_shares[opened_idx],
                party,
                &seeds[party],
                next_opened,
            )?;

            for (assert_idx, (wire, _)) in assertions.iter().enumerate() {
                if rep.assert_shares[assert_idx][party] != all_wire_shares[opened_idx][*wire] {
                    return Err(MpcithError::VerificationFailed(format!(
                        "v2 repetition {rep_idx}: party {party} assertion share mismatch for assertion {assert_idx}"
                    )));
                }
            }
        }

        for (assert_idx, (_, expected)) in assertions.iter().enumerate() {
            let sum = rep.assert_shares[assert_idx]
                .iter()
                .fold(Fr::from(0u64), |acc, share| acc + *share);
            if sum != *expected {
                return Err(MpcithError::VerificationFailed(format!(
                    "v2 repetition {rep_idx}: assertion {assert_idx} reconstructed {sum:?}, expected {expected:?}"
                )));
            }
        }
    }

    Ok(())
}

/// Decode and verify a canonical serialized v2 proof.
pub fn verify_bytes(bytes: &[u8], params: &V2Params) -> Result<()> {
    let proof = V2Proof::from_bytes(bytes)?;
    verify(&proof, params)
}

/// Verify a proof and require it to be for the caller's expected statement.
pub fn verify_statement(
    proof: &V2Proof,
    expected_statement: &StatementV2,
    params: &V2Params,
) -> Result<()> {
    if proof.statement != *expected_statement {
        return Err(MpcithError::VerificationFailed(
            "v2 proof statement does not match expected statement".into(),
        ));
    }
    verify(proof, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::merkle::MerkleTreeV2;

    fn params() -> V2Params {
        V2Params::new(3, 4)
    }

    fn range_proof() -> V2Proof {
        prove_range(10, 100, 42, &params()).unwrap()
    }

    fn membership_fixture() -> (MerkleTreeV2, V2Proof) {
        let tree = MerkleTreeV2::build(&[10, 20, 42]).unwrap();
        let member_proof = tree.prove_membership(1).unwrap();
        let proof = prove_membership(
            tree.root(),
            tree.num_members(),
            tree.depth(),
            20,
            &member_proof,
            &params(),
        )
        .unwrap();
        (tree, proof)
    }

    fn combined_proof() -> V2Proof {
        let tree = MerkleTreeV2::build(&[10, 20, 42]).unwrap();
        let member_proof = tree.prove_membership(1).unwrap();
        prove_combined(
            10,
            50,
            tree.root(),
            tree.num_members(),
            tree.depth(),
            20,
            &member_proof,
            &params(),
        )
        .unwrap()
    }

    fn transcript_for(proof: &V2Proof, suite: &V2Suite) -> [u8; 32] {
        let compiled = compile_from_statement(&proof.statement).unwrap();
        let hash = hash_circuit_v2(compiled.circuit());
        let reps: Vec<TranscriptRepV2<'_>> = proof
            .repetitions
            .iter()
            .map(|rep| TranscriptRepV2 {
                commitment_root: rep.commitment_root,
                assert_shares: &rep.assert_shares,
            })
            .collect();
        transcript_hash(&proof.statement, &proof.params, &hash, &reps, suite)
    }

    #[test]
    fn range_membership_and_combined_round_trip() {
        let p = range_proof();
        verify(&p, &params()).unwrap();
        verify_statement(&p, &p.statement, &params()).unwrap();
        assert_eq!(p.version, V2_PROOF_VERSION);
        assert_eq!(p.params, params());

        let (_tree, p) = membership_fixture();
        verify(&p, &params()).unwrap();

        let p = combined_proof();
        verify(&p, &params()).unwrap();
    }

    #[test]
    fn wrong_statement_is_rejected() {
        let proof = range_proof();
        let wrong = StatementV2::Range(RangeStatementV2 { lo: 10, hi: 99 });
        assert!(verify_statement(&proof, &wrong, &params()).is_err());

        let mut tampered = proof.clone();
        tampered.statement = wrong;
        assert!(verify(&tampered, &params()).is_err());

        let (_tree, membership) = membership_fixture();
        let mut tampered = membership.clone();
        if let StatementV2::Membership(m) = &mut tampered.statement {
            m.root += Fr::from(1u64);
        }
        assert!(verify(&tampered, &params()).is_err());

        let mut tampered = membership.clone();
        if let StatementV2::Membership(m) = &mut tampered.statement {
            m.num_members = 4;
            m.depth = 2;
        }
        assert!(verify(&tampered, &params()).is_err());

        let mut tampered = membership;
        if let StatementV2::Membership(m) = &mut tampered.statement {
            m.depth = 1;
        }
        assert!(verify(&tampered, &params()).is_err());
    }

    #[test]
    fn version_parameters_and_shape_tampering_are_rejected() {
        let base = membership_fixture().1;
        verify(&base, &params()).unwrap();

        let mut p = base.clone();
        p.version = 1;
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.params.num_repetitions += 1;
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.params.num_parties = 4;
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.repetitions.pop();
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.repetitions[0].hidden_party = (p.repetitions[0].hidden_party + 1) % 3;
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.repetitions[0].opened_views.pop();
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.repetitions[0].opened_views[1] = p.repetitions[0].opened_views[0].clone();
        assert!(verify(&p, &params()).is_err());

        // Level 0 can be the unused padding sibling when the hidden party is
        // the last real leaf. Level 1 always covers at least one opened party
        // for the three-party tree.
        let mut p = base.clone();
        p.repetitions[0].co_path[1][0] ^= 1;
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.repetitions[0].co_path.pop();
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.repetitions[0].opened_views[0].commitment_auth_path[0][0] ^= 1;
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.repetitions[0].opened_views[0].commitment_auth_path.pop();
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.repetitions[0].opened_views[0].mul_output_shares[0] += Fr::from(1u64);
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.repetitions[0].opened_views[0].mul_output_shares.pop();
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.repetitions[0].opened_views[0].commitment_randomness[0] ^= 1;
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.repetitions[0].commitment_root[0] ^= 1;
        assert!(verify(&p, &params()).is_err());

        let mut p = base.clone();
        p.repetitions[0].assert_shares[0][0] += Fr::from(1u64);
        assert!(verify(&p, &params()).is_err());

        let mut p = base;
        p.repetitions[0].assert_shares[0].pop();
        assert!(verify(&p, &params()).is_err());
    }

    #[test]
    fn serialization_round_trips_and_rejects_bad_headers() {
        let proof = range_proof();
        let bytes = proof.to_bytes().unwrap();
        assert_eq!(proof.serialized_size().unwrap(), bytes.len());
        let decoded = V2Proof::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, proof);
        verify_bytes(&bytes, &params()).unwrap();

        for proof in [membership_fixture().1, combined_proof()] {
            let bytes = proof.to_bytes().unwrap();
            assert_eq!(V2Proof::from_bytes(&bytes).unwrap(), proof);
        }

        // Replace a serialized Mul share (a decoded field element) with the
        // modulus itself. The decoder must reject it rather than reduce it.
        let target = encode_fr(&proof.repetitions[0].opened_views[0].mul_output_shares[0]);
        let offset = bytes
            .windows(32)
            .position(|window| window == target)
            .expect("serialized Mul share must be present");
        let mut noncanonical = bytes.clone();
        noncanonical[offset..offset + 32].copy_from_slice(&modulus_bytes());
        assert!(V2Proof::from_bytes(&noncanonical).is_err());

        let mut bad = bytes.clone();
        bad[0] ^= 1;
        assert!(V2Proof::from_bytes(&bad).is_err());
        assert!(verify_bytes(&bad, &params()).is_err());

        let mut bad = bytes.clone();
        bad[8] ^= 1;
        assert!(V2Proof::from_bytes(&bad).is_err());

        let mut bad = bytes.clone();
        bad.pop();
        assert!(V2Proof::from_bytes(&bad).is_err());

        let mut bad = bytes;
        bad.push(0);
        assert!(V2Proof::from_bytes(&bad).is_err());
        assert!(V2Proof::from_bytes(b"not a v2 proof").is_err());
    }

    #[test]
    fn reader_rejects_noncanonical_field_elements() {
        let good = encode_fr(&Fr::from(42u64));
        let mut reader = Reader::new(&good);
        assert_eq!(reader.fr().unwrap(), Fr::from(42u64));

        let modulus = modulus_bytes();
        let mut reader = Reader::new(&modulus);
        assert!(reader.fr().is_err());
    }

    fn modulus_bytes() -> [u8; 32] {
        let mut modulus = encode_fr(&-Fr::from(1u64));
        for byte in modulus.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        modulus
    }

    #[test]
    fn transcript_binds_suite_statement_circuit_and_public_rows() {
        let proof = range_proof();
        let base = transcript_for(&proof, &V2_SUITE);

        let wrong_version = V2Suite {
            version: 3,
            ..V2_SUITE
        };
        let wrong_field = V2Suite {
            field_id: &b"BN254-Fr-wrong"[..],
            ..V2_SUITE
        };
        let wrong_poseidon = V2Suite {
            poseidon2_id: &b"wrong-poseidon2"[..],
            ..V2_SUITE
        };
        let wrong_framing = V2Suite {
            framing_id: &b"wrong-framing"[..],
            ..V2_SUITE
        };
        let wrong_protocol = V2Suite {
            protocol_id: &b"wrong-protocol"[..],
            ..V2_SUITE
        };
        assert_ne!(base, transcript_for(&proof, &wrong_version));
        assert_ne!(base, transcript_for(&proof, &wrong_field));
        assert_ne!(base, transcript_for(&proof, &wrong_poseidon));
        assert_ne!(base, transcript_for(&proof, &wrong_framing));
        assert_ne!(base, transcript_for(&proof, &wrong_protocol));

        let mut changed = proof.clone();
        if let StatementV2::Range(range) = &mut changed.statement {
            range.hi = 99;
        }
        assert_ne!(base, transcript_for(&changed, &V2_SUITE));

        changed = proof.clone();
        changed.params.num_repetitions += 1;
        assert_ne!(base, transcript_for(&changed, &V2_SUITE));

        changed = proof.clone();
        changed.params.num_parties = 4;
        assert_ne!(base, transcript_for(&changed, &V2_SUITE));

        let compiled = compile_from_statement(&proof.statement).unwrap();
        let mut circuit_hash = hash_circuit_v2(compiled.circuit());
        let reps: Vec<TranscriptRepV2<'_>> = proof
            .repetitions
            .iter()
            .map(|rep| TranscriptRepV2 {
                commitment_root: rep.commitment_root,
                assert_shares: &rep.assert_shares,
            })
            .collect();
        let before = transcript_hash(
            &proof.statement,
            &proof.params,
            &circuit_hash,
            &reps,
            &V2_SUITE,
        );
        circuit_hash[0] ^= 1;
        let after = transcript_hash(
            &proof.statement,
            &proof.params,
            &circuit_hash,
            &reps,
            &V2_SUITE,
        );
        assert_ne!(before, after);

        let mut changed = proof.clone();
        changed.repetitions[0].commitment_root[0] ^= 1;
        assert_ne!(base, transcript_for(&changed, &V2_SUITE));

        let mut changed = proof;
        changed.repetitions[0].assert_shares[0][0] += Fr::from(1u64);
        assert_ne!(base, transcript_for(&changed, &V2_SUITE));
    }

    #[test]
    fn circuit_hash_is_deterministic_and_statement_sensitive() {
        let a = compile_range(10, 100).unwrap();
        let b = compile_range(10, 101).unwrap();
        assert_eq!(hash_circuit_v2(a.circuit()), hash_circuit_v2(a.circuit()));
        assert_ne!(hash_circuit_v2(a.circuit()), hash_circuit_v2(b.circuit()));
    }
}
