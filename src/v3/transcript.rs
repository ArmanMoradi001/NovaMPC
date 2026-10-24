//! Deterministic transcript and challenge derivation (mechanics only).
//!
//! Message order and challenge dependencies follow `V3_PROTOCOL.md` §1:
//! statement/params/context/suite/circuit-hash/salt absorbed first, then
//! `h1 → Γ → h1' → (γ,γ') → hB → I` with each challenge bound to the full
//! prefix. This is the Fiat–Shamir *mechanism*; it carries no security
//! claim — the QROM/grinding/extractor obligations in `V3_FIAT_SHAMIR.md`
//! remain open. Under a seeded prover RNG the whole transcript is
//! deterministic, which the tests rely on.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand_chacha::ChaCha20Rng;
use rand::{RngCore, SeedableRng};

use crate::v2::circuit::{CircuitV2, GateV2};
use crate::v2::field::encode_fr;
use crate::{MpcithError, Result};

/// Transcript domain: statement and suite binding prefix.
pub const V3_TR_DOMAIN_INIT: &[u8] = b"NovaMPC-v3/transcript/v1";
/// Challenge tag: DECS matrix `Γ`.
pub const V3_TR_TAG_GAMMA: &[u8] = b"v3-decs-challenge";
/// Challenge tag: MPC batching randomness `(γ, γ')`.
pub const V3_TR_TAG_BATCH: &[u8] = b"v3-mpc-batch";
/// Challenge tag: opening set `I`.
pub const V3_TR_TAG_OPEN: &[u8] = b"v3-opening";

/// Hash tag: degree-enforcing polynomial vector `Pξ`.
pub const V3_HASH_TAG_PXI: &[u8] = b"NovaMPC-v3/hash/paxi/v1";
/// Hash tag: broadcast shares.
pub const V3_HASH_TAG_BROADCAST: &[u8] = b"NovaMPC-v3/hash/broadcast/v1";

/// Running transcript. Clone the hasher per squeeze so challenges never
/// disturb the absorbed state.
#[derive(Clone)]
pub struct TranscriptV3 {
    state: blake3::Hasher,
}

impl TranscriptV3 {
    /// Open a transcript bound to everything the verifier pins: suite,
    /// parameters, expected statement, context, circuit hash, and salt.
    /// No challenge may be drawn before `h1` is absorbed (call
    /// [`Self::absorb_h1`] first).
    pub fn new(
        num_parties: u32,
        privacy_threshold: u32,
        packing_width: u32,
        decs_reps: u32,
        mpc_reps: u32,
        pok_reps: u32,
        range_lo: u32,
        range_hi: u32,
        set_root: &[u8; 32],
        num_members: u32,
        depth: u32,
        context: &[u8; 32],
        circuit_hash: &[u8; 32],
        salt: &[u8; 32],
    ) -> Self {
        let mut t = Self {
            state: blake3::Hasher::new(),
        };
        t.absorb(b"init", V3_TR_DOMAIN_INIT);
        t.absorb(b"suite-protocol", crate::v3::suite::V3_PROTOCOL_ID);
        t.absorb(b"suite-field", crate::v3::suite::V3_FIELD_ID);
        t.absorb_u32(b"parties", num_parties);
        t.absorb_u32(b"privacy", privacy_threshold);
        t.absorb_u32(b"packing", packing_width);
        t.absorb_u32(b"decs", decs_reps);
        t.absorb_u32(b"mpc", mpc_reps);
        t.absorb_u32(b"pok", pok_reps);
        t.absorb_u32(b"lo", range_lo);
        t.absorb_u32(b"hi", range_hi);
        t.absorb(b"root", set_root);
        t.absorb_u32(b"num-members", num_members);
        t.absorb_u32(b"depth", depth);
        t.absorb(b"context", context);
        t.absorb(b"circuit", circuit_hash);
        t.absorb(b"salt", salt);
        t
    }

    /// Absorb a labeled byte string with `u64`-BE length prefixes (V2 style).
    pub fn absorb(&mut self, label: &[u8], bytes: &[u8]) {
        self.state.update(&(label.len() as u64).to_be_bytes());
        self.state.update(label);
        self.state.update(&(bytes.len() as u64).to_be_bytes());
        self.state.update(bytes);
    }

    pub fn absorb_u32(&mut self, label: &[u8], value: u32) {
        self.absorb(label, &value.to_be_bytes());
    }

    pub fn absorb_hash(&mut self, label: &[u8], hash: &[u8; 32]) {
        self.absorb(label, hash);
    }

    /// Squeeze 32 challenge bytes bound to the current state plus a tag.
    fn squeeze(&self, tag: &[u8], counter: u32) -> [u8; 32] {
        let mut h = self.state.clone();
        h.update(&(tag.len() as u64).to_be_bytes());
        h.update(tag);
        h.update(&counter.to_be_bytes());
        *h.finalize().as_bytes()
    }

    fn challenge_rng(&self, tag: &[u8], counter: u32) -> ChaCha20Rng {
        ChaCha20Rng::from_seed(self.squeeze(tag, counter))
    }

    /// Sample `n` field elements for the challenge `tag` (counter selects
    /// the repetition/batch: caller passes a unique counter per draw).
    pub fn sample_frs(&self, tag: &[u8], counter: u32, n: usize) -> Vec<Fr> {
        let mut rng = self.challenge_rng(tag, counter);
        (0..n).map(|_| Fr::rand(&mut rng)).collect()
    }

    /// Sample one `u64` for the challenge `tag`.
    pub fn sample_u64(&self, tag: &[u8], counter: u32) -> u64 {
        self.challenge_rng(tag, counter).next_u64()
    }

    /// Draw the opening subset: `k` distinct party indices in `[0, n)`,
    /// partial Fisher–Yates, deterministic for a fixed transcript.
    pub fn sample_subset(&self, tag: &[u8], counter: u32, n: usize, k: usize) -> Result<Vec<u32>> {
        if k > n || n == 0 {
            return Err(MpcithError::InvalidParams(format!(
                "v3 cannot open {k} of {n} parties"
            )));
        }
        let mut rng = self.challenge_rng(tag, counter);
        let mut indices: Vec<u32> = (0..n as u32).collect();
        for i in 0..k {
            let j = i + (rng.next_u64() as usize % (n - i));
            indices.swap(i, j);
        }
        Ok(indices[..k].to_vec())
    }
}

/// Canonical circuit hash binding the exact gate sequence (check 5).
pub fn circuit_hash_v3(circuit: &CircuitV2) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"NovaMPC-v3/circuit/v1");
    h.update(&(circuit.num_inputs() as u64).to_be_bytes());
    for gate in circuit.gates() {
        match gate {
            GateV2::Add { left, right, output } => {
                h.update(b"add");
                h.update(&(left.index() as u64).to_be_bytes());
                h.update(&(right.index() as u64).to_be_bytes());
                h.update(&(output.index() as u64).to_be_bytes());
            }
            GateV2::Mul { left, right, output } => {
                h.update(b"mul");
                h.update(&(left.index() as u64).to_be_bytes());
                h.update(&(right.index() as u64).to_be_bytes());
                h.update(&(output.index() as u64).to_be_bytes());
            }
            GateV2::AddConst { input, constant, output } => {
                h.update(b"addc");
                h.update(&(input.index() as u64).to_be_bytes());
                h.update(&encode_fr(constant));
                h.update(&(output.index() as u64).to_be_bytes());
            }
            GateV2::MulConst { input, constant, output } => {
                h.update(b"mulc");
                h.update(&(input.index() as u64).to_be_bytes());
                h.update(&encode_fr(constant));
                h.update(&(output.index() as u64).to_be_bytes());
            }
            GateV2::AssertEq { input, expected } => {
                h.update(b"assert");
                h.update(&(input.index() as u64).to_be_bytes());
                h.update(&encode_fr(expected));
            }
        }
    }
    *h.finalize().as_bytes()
}

/// Hash a vector of field-element vectors (DECS `Pξ` coefficients or
/// broadcast share vectors) under a domain tag.
pub fn hash_fr_vecs(tag: &[u8], vecs: &[Vec<Fr>]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&(vecs.len() as u64).to_be_bytes());
    for v in vecs {
        h.update(&(v.len() as u64).to_be_bytes());
        for x in v {
            h.update(&encode_fr(x));
        }
    }
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_circuit() -> CircuitV2 {
        use crate::v2::circuit::{CircuitBuilderV2, Wire};
        let mut b = CircuitBuilderV2::new(2);
        let s = b.add(Wire(0), Wire(1));
        let p = b.mul(s, Wire(1));
        let sh = b.add_const(p, Fr::from(3u64));
        b.assert_eq(sh, Fr::from(11u64));
        b.build()
    }

    fn test_transcript() -> TranscriptV3 {
        TranscriptV3::new(32, 3, 8, 2, 1, 1, 1, 1000, &[7u8; 32], 4, 2, &[9u8; 32], &[11u8; 32], &[13u8; 32])
    }

    #[test]
    fn challenges_are_deterministic_and_prefix_bound() {
        let t = test_transcript();
        assert_eq!(
            t.sample_frs(V3_TR_TAG_GAMMA, 0, 4),
            t.sample_frs(V3_TR_TAG_GAMMA, 0, 4)
        );
        assert_ne!(
            t.sample_frs(V3_TR_TAG_GAMMA, 0, 4),
            t.sample_frs(V3_TR_TAG_GAMMA, 1, 4)
        );
        let mut t2 = t.clone();
        t2.absorb_hash(b"h1", &[1u8; 32]);
        assert_ne!(
            t.sample_frs(V3_TR_TAG_GAMMA, 0, 4),
            t2.sample_frs(V3_TR_TAG_GAMMA, 0, 4)
        );
        // Different tags never collide in output.
        assert_ne!(
            t.sample_frs(V3_TR_TAG_GAMMA, 0, 4),
            t.sample_frs(V3_TR_TAG_BATCH, 0, 4)
        );
    }

    #[test]
    fn subset_draw_is_a_valid_distinct_prefix() {
        let t = test_transcript();
        let s = t.sample_subset(V3_TR_TAG_OPEN, 0, 32, 3).unwrap();
        assert_eq!(s.len(), 3);
        assert!(s.iter().all(|i| (*i as usize) < 32));
        let mut sorted = s.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 3);
        assert_eq!(s, t.sample_subset(V3_TR_TAG_OPEN, 0, 32, 3).unwrap());
        assert!(t.sample_subset(V3_TR_TAG_OPEN, 0, 4, 5).is_err());
    }

    #[test]
    fn circuit_hash_binds_gate_sequence() {
        let c = test_circuit();
        let h = circuit_hash_v3(&c);
        assert_eq!(h, circuit_hash_v3(&c));
        let mut b = crate::v2::circuit::CircuitBuilderV2::new(2);
        use crate::v2::circuit::Wire;
        let s = b.add(Wire(1), Wire(0));
        let p = b.mul(s, Wire(1));
        let sh = b.add_const(p, Fr::from(3u64));
        b.assert_eq(sh, Fr::from(11u64));
        assert_ne!(h, circuit_hash_v3(&b.build()));
    }
}
