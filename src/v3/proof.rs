//! Experimental V3 proof type and canonical encoding.
//!
//! The proof carries no statement authority: suite, parameters, statement,
//! context, and circuit hash are echoed in the header and the verifier
//! requires byte-equality with its expected values (check 5). No logic
//! lives here — see `prover.rs` / `verifier.rs`.

use ark_bn254::Fr;

use crate::v2::field::{decode_fr, encode_fr, FIELD_ELEMENT_BYTES};
use crate::v3::params::V3Params;
use crate::{MpcithError, Result};

/// Hard caps for structural parsing (exact counts enforced at verify time).
const MAX_VEC_LEN: usize = 1 << 20;
const MAX_PATH_LEN: usize = 64;

/// One opened party: index, all committed share values, Merkle path, and
/// the leaf randomness needed to recompute the leaf commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedPartyV3 {
    pub party_index: u32,
    pub shares: Vec<Fr>,
    pub path: Vec<[u8; 32]>,
    /// Sibling-is-left flag per path step (verifier recomputes the fold).
    pub path_left: Vec<bool>,
    pub leaf_randomness: [u8; 32],
}

/// One PoK repetition: pre/post-challenge commitments plus openings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepProofV3 {
    pub commitment_root: [u8; 32],
    pub decs_hash: [u8; 32],
    pub broadcast_hash: [u8; 32],
    pub opened: Vec<OpenedPartyV3>,
    /// `JαK` shares on `S` (`dα+1−ℓ` values) per MPC batch.
    pub broadcast_alpha: Vec<Vec<Fr>>,
    /// `Jα′K` shares on `S′` (`2s−1` values) per MPC batch.
    pub broadcast_alpha_prime: Vec<Vec<Fr>>,
    /// DECS responses: `η × |Sξ|` field elements.
    pub decs_responses: Vec<Vec<Fr>>,
    /// ΠΣ0 corrections, one per MPC batch.
    pub delta_u1: Vec<Fr>,
}

/// Experimental V3 proof. No security claim attaches to this format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3Proof {
    pub params: V3Params,
    pub range_lo: u32,
    pub range_hi: u32,
    pub set_root: [u8; 32],
    pub num_members: u32,
    pub depth: u32,
    pub context: [u8; 32],
    pub circuit_hash: [u8; 32],
    pub salt: [u8; 32],
    pub reps: Vec<RepProofV3>,
}

fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > bytes.len() {
        return Err(MpcithError::SerializationError(
            "v3 proof truncated at u32".into(),
        ));
    }
    let v = u32::from_be_bytes(bytes[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(v)
}

fn read_bytes32(bytes: &[u8], pos: &mut usize) -> Result<[u8; 32]> {
    if *pos + 32 > bytes.len() {
        return Err(MpcithError::SerializationError(
            "v3 proof truncated at 32 bytes".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[*pos..*pos + 32]);
    *pos += 32;
    Ok(out)
}

fn read_vec<T>(bytes: &[u8], pos: &mut usize, read_elem: impl Fn(&[u8], &mut usize) -> Result<T>) -> Result<Vec<T>> {
    let len = read_u32(bytes, pos)? as usize;
    if len > MAX_VEC_LEN {
        return Err(MpcithError::SerializationError(format!(
            "v3 vector length {len} exceeds cap"
        )));
    }
    let mut out = Vec::with_capacity(len.min(1024));
    for _ in 0..len {
        out.push(read_elem(bytes, pos)?);
    }
    Ok(out)
}

fn read_fr(bytes: &[u8], pos: &mut usize) -> Result<Fr> {
    if *pos + FIELD_ELEMENT_BYTES > bytes.len() {
        return Err(MpcithError::SerializationError(
            "v3 proof truncated at field element".into(),
        ));
    }
    let v = decode_fr(&bytes[*pos..*pos + FIELD_ELEMENT_BYTES]).map_err(|e| {
        MpcithError::SerializationError(format!("v3 non-canonical field element: {e}"))
    })?;
    *pos += FIELD_ELEMENT_BYTES;
    Ok(v)
}

impl V3Proof {
    /// Canonical serialization. Exact byte length is the measured proof size.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(crate::v3::suite::V3_PROOF_MAGIC);
        out.extend_from_slice(&crate::v3::suite::V3_PROOF_FORMAT_VERSION.to_be_bytes());
        write_u32(&mut out, self.params.num_parties);
        write_u32(&mut out, self.params.privacy_threshold);
        write_u32(&mut out, self.params.packing_width);
        write_u32(&mut out, self.params.decs_reps);
        write_u32(&mut out, self.params.mpc_reps);
        write_u32(&mut out, self.params.pok_reps);
        write_u32(&mut out, self.range_lo);
        write_u32(&mut out, self.range_hi);
        out.extend_from_slice(&self.set_root);
        write_u32(&mut out, self.num_members);
        write_u32(&mut out, self.depth);
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.circuit_hash);
        out.extend_from_slice(&self.salt);
        write_u32(&mut out, self.reps.len() as u32);
        for rep in &self.reps {
            out.extend_from_slice(&rep.commitment_root);
            out.extend_from_slice(&rep.decs_hash);
            out.extend_from_slice(&rep.broadcast_hash);
            write_u32(&mut out, rep.opened.len() as u32);
            for o in &rep.opened {
                write_u32(&mut out, o.party_index);
                write_u32(&mut out, o.shares.len() as u32);
                for s in &o.shares {
                    out.extend_from_slice(&encode_fr(s));
                }
                if o.path.len() != o.path_left.len() || o.path.len() > MAX_PATH_LEN {
                    return Err(MpcithError::SerializationError(
                        "v3 malformed authentication path".into(),
                    ));
                }
                write_u32(&mut out, o.path.len() as u32);
                for (sib, left) in o.path.iter().zip(o.path_left.iter()) {
                    out.extend_from_slice(sib);
                    out.push(u8::from(*left));
                }
                out.extend_from_slice(&o.leaf_randomness);
            }
            write_u32(&mut out, rep.broadcast_alpha.len() as u32);
            for v in &rep.broadcast_alpha {
                write_u32(&mut out, v.len() as u32);
                for x in v {
                    out.extend_from_slice(&encode_fr(x));
                }
            }
            write_u32(&mut out, rep.broadcast_alpha_prime.len() as u32);
            for v in &rep.broadcast_alpha_prime {
                write_u32(&mut out, v.len() as u32);
                for x in v {
                    out.extend_from_slice(&encode_fr(x));
                }
            }
            write_u32(&mut out, rep.decs_responses.len() as u32);
            for v in &rep.decs_responses {
                write_u32(&mut out, v.len() as u32);
                for x in v {
                    out.extend_from_slice(&encode_fr(x));
                }
            }
            write_u32(&mut out, rep.delta_u1.len() as u32);
            for x in &rep.delta_u1 {
                out.extend_from_slice(&encode_fr(x));
            }
        }
        Ok(out)
    }

    /// Strict parse: magic, version, canonical field elements, length caps,
    /// no trailing bytes. Structural only — semantic checks are the
    /// verifier's job.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut pos = 0usize;
        if pos + 8 > bytes.len() {
            return Err(MpcithError::SerializationError(
                "v3 proof truncated at magic".into(),
            ));
        }
        if bytes[pos..pos + 8] != *crate::v3::suite::V3_PROOF_MAGIC {
            return Err(MpcithError::SerializationError(
                "v3 proof has wrong magic (not a v3 proof)".into(),
            ));
        }
        pos += 8;
        if pos + 2 > bytes.len() {
            return Err(MpcithError::SerializationError(
                "v3 proof truncated at version".into(),
            ));
        }
        let version = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
        pos += 2;
        if version != crate::v3::suite::V3_PROOF_FORMAT_VERSION {
            return Err(MpcithError::SerializationError(format!(
                "v3 proof has unsupported version {version}"
            )));
        }
        let params = V3Params::new(
            read_u32(bytes, &mut pos)?,
            read_u32(bytes, &mut pos)?,
            read_u32(bytes, &mut pos)?,
            read_u32(bytes, &mut pos)?,
            read_u32(bytes, &mut pos)?,
            read_u32(bytes, &mut pos)?,
        );
        let range_lo = read_u32(bytes, &mut pos)?;
        let range_hi = read_u32(bytes, &mut pos)?;
        let set_root = read_bytes32(bytes, &mut pos)?;
        let num_members = read_u32(bytes, &mut pos)?;
        let depth = read_u32(bytes, &mut pos)?;
        let context = read_bytes32(bytes, &mut pos)?;
        let circuit_hash = read_bytes32(bytes, &mut pos)?;
        let salt = read_bytes32(bytes, &mut pos)?;
        let reps = read_vec(bytes, &mut pos, |b, p| {
            let commitment_root = read_bytes32(b, p)?;
            let decs_hash = read_bytes32(b, p)?;
            let broadcast_hash = read_bytes32(b, p)?;
            let opened = read_vec(b, p, |b, p| {
                let party_index = read_u32(b, p)?;
                let shares = read_vec(b, p, read_fr)?;
                let path_len = read_u32(b, p)? as usize;
                if path_len > MAX_PATH_LEN {
                    return Err(MpcithError::SerializationError(
                        "v3 authentication path exceeds cap".into(),
                    ));
                }
                let mut path = Vec::with_capacity(path_len);
                let mut path_left = Vec::with_capacity(path_len);
                for _ in 0..path_len {
                    path.push(read_bytes32(b, p)?);
                    if *p >= b.len() {
                        return Err(MpcithError::SerializationError(
                            "v3 proof truncated at path side bit".into(),
                        ));
                    }
                    match b[*p] {
                        0 => path_left.push(false),
                        1 => path_left.push(true),
                        _ => {
                            return Err(MpcithError::SerializationError(
                                "v3 path side bit must be 0 or 1".into(),
                            ));
                        }
                    }
                    *p += 1;
                }
                let leaf_randomness = read_bytes32(b, p)?;
                Ok(OpenedPartyV3 {
                    party_index,
                    shares,
                    path,
                    path_left,
                    leaf_randomness,
                })
            })?;
            let broadcast_alpha = read_vec(b, p, |b, p| read_vec(b, p, read_fr))?;
            let broadcast_alpha_prime = read_vec(b, p, |b, p| read_vec(b, p, read_fr))?;
            let decs_responses = read_vec(b, p, |b, p| read_vec(b, p, read_fr))?;
            let delta_u1 = read_vec(b, p, read_fr)?;
            Ok(RepProofV3 {
                commitment_root,
                decs_hash,
                broadcast_hash,
                opened,
                broadcast_alpha,
                broadcast_alpha_prime,
                decs_responses,
                delta_u1,
            })
        })?;
        if pos != bytes.len() {
            return Err(MpcithError::SerializationError(
                "v3 proof has trailing bytes".into(),
            ));
        }
        Ok(Self {
            params,
            range_lo,
            range_hi,
            set_root,
            num_members,
            depth,
            context,
            circuit_hash,
            salt,
            reps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_proof() -> V3Proof {
        V3Proof {
            params: V3Params::fast_insecure_test(),
            range_lo: 1,
            range_hi: 1000,
            set_root: [2u8; 32],
            num_members: 4,
            depth: 2,
            context: [3u8; 32],
            circuit_hash: [4u8; 32],
            salt: [5u8; 32],
            reps: vec![RepProofV3 {
                commitment_root: [6u8; 32],
                decs_hash: [7u8; 32],
                broadcast_hash: [8u8; 32],
                opened: vec![OpenedPartyV3 {
                    party_index: 9,
                    shares: vec![Fr::from(1u64), Fr::from(2u64)],
                    path: vec![[10u8; 32]],
                    path_left: vec![true],
                    leaf_randomness: [11u8; 32],
                }],
                broadcast_alpha: vec![vec![Fr::from(3u64)]],
                broadcast_alpha_prime: vec![vec![Fr::from(4u64)]],
                decs_responses: vec![vec![Fr::from(5u64)]],
                delta_u1: vec![Fr::from(6u64)],
            }],
        }
    }

    #[test]
    fn codec_round_trip_is_exact() {
        let proof = synthetic_proof();
        let bytes = proof.to_bytes().unwrap();
        assert_eq!(V3Proof::from_bytes(&bytes).unwrap(), proof);
    }

    #[test]
    fn codec_rejects_wrong_magic_version_and_trailing_bytes() {
        let proof = synthetic_proof();
        let mut bytes = proof.to_bytes().unwrap();
        // V2 magic must not parse as V3.
        let mut v2magic = bytes.clone();
        v2magic[..8].copy_from_slice(b"NMPCV2P\0");
        assert!(V3Proof::from_bytes(&v2magic).is_err());
        // Bad version.
        let mut badver = bytes.clone();
        badver[8] = 0xFF;
        assert!(V3Proof::from_bytes(&badver).is_err());
        // Trailing byte.
        bytes.push(0);
        assert!(V3Proof::from_bytes(&bytes).is_err());
        // Truncation.
        let short = &proof.to_bytes().unwrap()[..20];
        assert!(V3Proof::from_bytes(short).is_err());
    }

    #[test]
    fn codec_rejects_non_canonical_field_and_bad_side_bit() {
        // Non-canonical field element (exactly the modulus) is rejected.
        let mut modulus = [0u8; 32];
        modulus[..31].copy_from_slice(&[
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
            0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
            0x00,
        ]);
        modulus[31] = 0x01;
        let mut pos = 0;
        assert!(read_fr(&modulus, &mut pos).is_err());
        // A path side bit other than 0/1 is rejected: locate the synthetic
        // sibling [10u8; 32] in the encoding and corrupt the byte after it.
        let proof = synthetic_proof();
        let mut bytes = proof.to_bytes().unwrap();
        let sib: Vec<u8> = vec![10u8; 32];
        let at = bytes
            .windows(33)
            .position(|w| w[..32] == sib[..] && w[32] == 0x01)
            .expect("synthetic path encoding present");
        bytes[at + 32] = 0x02;
        assert!(V3Proof::from_bytes(&bytes).is_err());
    }
}
