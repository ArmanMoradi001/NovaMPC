//! Additive secret sharing over Z_{2^32}.
//!
//! A value `v` is shared among N parties as (s_1, ..., s_N) where:
//!   s_1 + s_2 + ... + s_N = v  (mod 2^32)
//!   s_1, ..., s_{N-1} are uniformly random
//!   s_N = v - s_1 - ... - s_{N-1}
//!
//! This is *information-theoretically* secure: any N-1 shares reveal
//! nothing about v.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A full sharing of a single wire value across N parties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sharing {
    /// shares[i] is party i's share of the secret.
    pub shares: Vec<u32>,
}

impl Sharing {
    /// Create a new random additive sharing of `value` among `num_parties`.
    pub fn share<R: RngCore + CryptoRng>(
        value: u32,
        num_parties: usize,
        rng: &mut R,
    ) -> Self {
        assert!(num_parties >= 2, "Need at least 2 parties");
        let mut shares = vec![0u32; num_parties];

        // Generate N-1 random shares.
        let mut sum = 0u32;
        for share in shares.iter_mut().take(num_parties - 1) {
            *share = rng.next_u32();
            sum = sum.wrapping_add(*share);
        }
        // Last share is deterministic to ensure reconstruction.
        shares[num_parties - 1] = value.wrapping_sub(sum);

        Self { shares }
    }

    /// Create an additive sharing of `value` using per-party RNGs.
    ///
    /// Each party i (for i < N-1) draws r_i from `party_rngs[i]`; the last
    /// party's share is the residual so that shares reconstruct to `value`.
    pub fn share_with_rngs(
        value: u32,
        num_parties: usize,
        party_rngs: &mut [impl RngCore],
    ) -> Self {
        assert!(num_parties >= 2, "Need at least 2 parties");
        let mut shares = vec![0u32; num_parties];
        let mut sum = 0u32;
        for p in 0..num_parties - 1 {
            shares[p] = party_rngs[p].next_u32();
            sum = sum.wrapping_add(shares[p]);
        }
        shares[num_parties - 1] = value.wrapping_sub(sum);
        Self { shares }
    }

    /// Create a random XOR secret sharing of `value` among `num_parties`.
    /// Reconstruct by XOR-ing all shares.
    pub fn share_xor<R: RngCore + CryptoRng>(
        value: u32,
        num_parties: usize,
        rng: &mut R,
    ) -> Self {
        assert!(num_parties >= 2, "Need at least 2 parties");
        let mut shares = vec![0u32; num_parties];

        let mut xor_acc = 0u32;
        for share in shares.iter_mut().take(num_parties - 1) {
            *share = rng.next_u32();
            xor_acc ^= *share;
        }
        shares[num_parties - 1] = value ^ xor_acc;

        Self { shares }
    }

    /// Reconstruct the shared value from all shares.
    pub fn reconstruct(&self) -> u32 {
        self.shares.iter().fold(0u32, |acc, &s| acc.wrapping_add(s))
    }

    /// Number of parties.
    pub fn num_parties(&self) -> usize {
        self.shares.len()
    }

    /// Add two sharings gate-wise. Linear gates require no interaction.
    /// (s_1 + t_1) + (s_2 + t_2) + ... = (s + t)
    pub fn add(&self, other: &Sharing) -> Sharing {
        assert_eq!(self.num_parties(), other.num_parties());
        Sharing {
            shares: self
                .shares
                .iter()
                .zip(other.shares.iter())
                .map(|(&a, &b)| a.wrapping_add(b))
                .collect(),
        }
    }

    /// Add a public constant to a sharing.
    /// Only party 0 adds the constant to their share; others add 0.
    pub fn add_const(&self, constant: u32) -> Sharing {
        let mut shares = self.shares.clone();
        shares[0] = shares[0].wrapping_add(constant);
        Sharing { shares }
    }

    /// Multiply a sharing by a public constant. Linear — no interaction needed.
    pub fn mul_const(&self, constant: u32) -> Sharing {
        Sharing {
            shares: self.shares.iter().map(|&s| s.wrapping_mul(constant)).collect(),
        }
    }

    /// XOR two sharings element-wise.
    pub fn xor(&self, other: &Sharing) -> Sharing {
        assert_eq!(self.num_parties(), other.num_parties());
        Sharing {
            shares: self
                .shares
                .iter()
                .zip(other.shares.iter())
                .map(|(&a, &b)| a ^ b)
                .collect(),
        }
    }

    /// Reconstruct an XOR-shared value (shares are XOR-ed, not added).
    pub fn reconstruct_xor(&self) -> u32 {
        self.shares.iter().fold(0u32, |acc, &s| acc ^ s)
    }
}

/// A full wire assignment, where each wire is shared among N parties.
/// `shared_wires[w][p]` = party p's share of wire w.
#[derive(Debug, Clone)]
pub struct SharedTrace {
    pub wires: Vec<Sharing>,
    pub num_parties: usize,
}

impl SharedTrace {
    pub fn new(num_wires: usize, num_parties: usize) -> Self {
        Self {
            wires: Vec::with_capacity(num_wires),
            num_parties,
        }
    }

    /// Party p's complete view of the trace (all their shares).
    pub fn party_view(&self, party: usize) -> Vec<u32> {
        self.wires.iter().map(|s| s.shares[party]).collect()
    }

    /// Reconstruct a single wire value.
    pub fn reconstruct_wire(&self, wire: usize) -> u32 {
        self.wires[wire].reconstruct()
    }
}

/// Per-party seed used to deterministically generate that party's randomness.
/// In the full MPCitH protocol, seeds are committed to and later selectively
/// revealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartySeed(pub [u8; 32]);

impl PartySeed {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        PartySeed(seed)
    }

    /// Derive a ChaCha20 RNG from this seed + a domain tag.
    pub fn to_rng(&self, domain: &[u8]) -> rand_chacha::ChaCha20Rng {
        use rand::SeedableRng;
        // Combine seed and domain via BLAKE3.
        let combined = blake3::hash(&[self.0.as_slice(), domain].concat());
        let key: [u8; 32] = combined.into();
        rand_chacha::ChaCha20Rng::from_seed(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_share_reconstruct() {
        let mut rng = thread_rng();
        for value in [0u32, 1, 42, u32::MAX, 1337] {
            for n in [2usize, 3, 5, 16] {
                let sharing = Sharing::share(value, n, &mut rng);
                assert_eq!(sharing.reconstruct(), value, "n={n}, v={value}");
            }
        }
    }

    #[test]
    fn test_linear_operations() {
        let mut rng = thread_rng();
        let a = Sharing::share(10, 3, &mut rng);
        let b = Sharing::share(5, 3, &mut rng);

        assert_eq!(a.add(&b).reconstruct(), 15);
        assert_eq!(a.add_const(7).reconstruct(), 17);
        assert_eq!(a.mul_const(3).reconstruct(), 30);
        // XOR sharing is reconstructed by XOR-ing all shares, not adding them.
        let xa = Sharing::share_xor(10, 3, &mut rng);
        let xb = Sharing::share_xor(5, 3, &mut rng);
        assert_eq!(xa.xor(&xb).reconstruct_xor(), 10 ^ 5);
    }
}
