//! Additive secret sharing over BN254 `Fr` for the v2 path.
//!
//! A value `v` is shared among N parties as `(s_0, ..., s_{N-1})` with
//! `s_0 + ... + s_{N-1} = v` in `Fr`. The first `N-1` shares are sampled
//! uniformly with rejection sampling; the last share is the residual. Any
//! `N-1` shares are independent of `v`.

use ark_bn254::Fr;
use rand::{CryptoRng, RngCore};
use rand_chacha::ChaCha20Rng;

use crate::v2::field::decode_fr;

/// A full additive sharing of one wire value across N parties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingV2 {
    /// `shares[i]` is party `i`'s share.
    pub shares: Vec<Fr>,
}

impl SharingV2 {
    /// Create a random additive sharing of `value`.
    pub fn share<R: RngCore + CryptoRng>(value: Fr, num_parties: usize, rng: &mut R) -> Self {
        assert!(num_parties >= 2, "need at least 2 parties");
        let mut shares = Vec::with_capacity(num_parties);
        let mut sum = Fr::from(0u64);
        for _ in 0..num_parties - 1 {
            let share = sample_fr(rng);
            sum += share;
            shares.push(share);
        }
        shares.push(value - sum);
        Self { shares }
    }

    /// Create an additive sharing using one RNG per non-residual party.
    ///
    /// The first `N-1` parties draw their shares from their own RNG streams;
    /// the last party receives the residual.
    pub fn share_with_rngs(value: Fr, num_parties: usize, party_rngs: &mut [impl RngCore]) -> Self {
        assert!(num_parties >= 2, "need at least 2 parties");
        assert!(
            party_rngs.len() >= num_parties - 1,
            "need at least N-1 party RNGs"
        );
        let mut shares = Vec::with_capacity(num_parties);
        let mut sum = Fr::from(0u64);
        for rng in party_rngs.iter_mut().take(num_parties - 1) {
            let share = sample_fr(rng);
            sum += share;
            shares.push(share);
        }
        shares.push(value - sum);
        Self { shares }
    }

    /// Reconstruct the shared value.
    pub fn reconstruct(&self) -> Fr {
        self.shares
            .iter()
            .fold(Fr::from(0u64), |acc, share| acc + *share)
    }

    /// Number of parties.
    pub fn num_parties(&self) -> usize {
        self.shares.len()
    }

    /// Gate-wise addition; linear, no interaction.
    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.num_parties(), other.num_parties());
        Self {
            shares: self
                .shares
                .iter()
                .zip(other.shares.iter())
                .map(|(a, b)| *a + *b)
                .collect(),
        }
    }

    /// Add a public constant to party 0's share only.
    pub fn add_const(&self, constant: Fr) -> Self {
        let mut shares = self.shares.clone();
        shares[0] += constant;
        Self { shares }
    }

    /// Multiply every share by a public constant; linear, no interaction.
    pub fn mul_const(&self, constant: Fr) -> Self {
        Self {
            shares: self.shares.iter().map(|share| *share * constant).collect(),
        }
    }
}

/// A full wire assignment, where each wire is additively shared.
#[derive(Debug, Clone)]
pub struct SharedTraceV2 {
    /// `wires[w]` is the sharing of wire `w`.
    pub wires: Vec<SharingV2>,
    /// Number of parties.
    pub num_parties: usize,
}

impl SharedTraceV2 {
    /// Reconstruct a single wire value.
    pub fn reconstruct_wire(&self, wire: usize) -> Fr {
        self.wires[wire].reconstruct()
    }
}

/// Per-party v2 seed used for deterministic share and zero-share expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartySeedV2(pub [u8; 32]);

impl PartySeedV2 {
    /// Sample a fresh seed from a cryptographic RNG.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self(seed)
    }

    /// Derive a ChaCha20 RNG from this seed and a fixed protocol domain.
    pub fn to_rng(&self, domain: &[u8]) -> ChaCha20Rng {
        use rand::SeedableRng;

        let mut material = Vec::with_capacity(self.0.len() + domain.len());
        material.extend_from_slice(&self.0);
        material.extend_from_slice(domain);
        let key = blake3::derive_key("NovaMPC-v2/party-rng/v1", &material);
        ChaCha20Rng::from_seed(key)
    }
}

/// Uniform field sampling by rejection from 32-byte ChaCha output.
///
/// A 256-bit draw is accepted only if its canonical big-endian value is below
/// the BN254 scalar modulus. No arbitrary byte string is reduced modulo `p`.
pub fn sample_fr<R: RngCore>(rng: &mut R) -> Fr {
    let mut bytes = [0u8; 32];
    loop {
        rng.fill_bytes(&mut bytes);
        if let Ok(value) = decode_fr(&bytes) {
            return value;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn test_rng() -> StdRng {
        StdRng::from_seed([7u8; 32])
    }

    #[test]
    fn shares_reconstruct_for_edge_and_random_values() {
        let mut rng = test_rng();
        let values = [
            Fr::from(0u64),
            Fr::from(1u64),
            -Fr::from(1u64),
            Fr::from(u32::MAX as u64),
            sample_fr(&mut rng),
        ];
        for value in values {
            for n in [2usize, 3, 5] {
                let sharing = SharingV2::share(value, n, &mut rng);
                assert_eq!(sharing.reconstruct(), value, "n={n}");
                assert_eq!(sharing.shares.len(), n);
            }
        }
    }

    #[test]
    fn linear_operations_are_local_and_reconstruct() {
        let mut rng = test_rng();
        let a = SharingV2::share(Fr::from(10u64), 3, &mut rng);
        let b = SharingV2::share(Fr::from(5u64), 3, &mut rng);
        assert_eq!(a.add(&b).reconstruct(), Fr::from(15u64));
        assert_eq!(a.add_const(Fr::from(7u64)).reconstruct(), Fr::from(17u64));
        assert_eq!(a.mul_const(Fr::from(3u64)).reconstruct(), Fr::from(30u64));
    }

    #[test]
    fn sharing_with_party_rngs_reconstructs() {
        let mut rngs = [test_rng(), StdRng::from_seed([8u8; 32])];
        let value = sample_fr(&mut test_rng());
        let sharing = SharingV2::share_with_rngs(value, 3, &mut rngs);
        assert_eq!(sharing.reconstruct(), value);
    }

    #[test]
    fn party_seed_domains_are_separated() {
        let seed = PartySeedV2([9u8; 32]);
        let mut a = seed.to_rng(b"domain-a");
        let mut b = seed.to_rng(b"domain-b");
        assert_ne!(sample_fr(&mut a), sample_fr(&mut b));
    }

    /// Deterministic RNG that returns a fixed sequence of 32-byte draws.
    struct ScriptedRng {
        chunks: Vec<[u8; 32]>,
        next: usize,
    }

    impl RngCore for ScriptedRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            assert_eq!(dest.len(), 32, "sampler must consume one 32-byte draw");
            dest.copy_from_slice(&self.chunks[self.next]);
            self.next += 1;
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    const MODULUS_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    fn chunk(value: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        out
    }

    #[test]
    fn rejection_sampling_rejects_modulus_and_accepts_next_draw() {
        let mut rng = ScriptedRng {
            chunks: vec![MODULUS_BE, chunk(5)],
            next: 0,
        };
        assert_eq!(sample_fr(&mut rng), Fr::from(5u64));
        assert_eq!(rng.next, 2);
    }

    #[test]
    fn rejection_sampling_accepts_zero_and_modulus_minus_one() {
        let mut minus_one = MODULUS_BE;
        minus_one[31] = 0x00;
        let mut rng = ScriptedRng {
            chunks: vec![chunk(0), minus_one],
            next: 0,
        };
        assert_eq!(sample_fr(&mut rng), Fr::from(0u64));
        assert_eq!(sample_fr(&mut rng), -Fr::from(1u64));
        assert_eq!(rng.next, 2);
    }

    #[test]
    fn rejection_sampling_rejects_all_ones_and_above_modulus() {
        let mut above = MODULUS_BE;
        above[31] = 0x02;
        let mut rng = ScriptedRng {
            chunks: vec![[0xffu8; 32], above, chunk(11)],
            next: 0,
        };
        assert_eq!(sample_fr(&mut rng), Fr::from(11u64));
        assert_eq!(rng.next, 3);
    }
}
