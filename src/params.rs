use serde::{Serialize, Deserialize};


/// Parameters controlling proof size vs soundness trade-off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofParams {
    /// Number of virtual MPC parties (N). Must be exactly 3: the protocol
    /// uses the ZKBoo 3-party verifiable multiplication scheme.
    pub num_parties: usize,

    /// Number of parallel repetitions (M).
    pub num_repetitions: usize,

    /// Size of each field element in bytes (we work over u32, so 4).
    pub field_element_bytes: usize,
}

impl ProofParams {
    /// Prototype parameters: N=3, M=64 → soundness ≈ 2^{-37} (M·log₂(3/2)).
    /// Larger proofs than `fast_insecure`, but still below 128-bit security;
    /// suitable for tests and demos, not production.
    pub fn low_n() -> Self {
        Self {
            num_parties: 3,
            num_repetitions: 64,
            field_element_bytes: 4,
        }
    }

    /// Balanced prototype parameters: N=3, M=96 → soundness ≈ 2^{-56}
    /// (M·log₂(3/2)).
    /// The protocol requires exactly 3 parties (ZKBoo 2-of-3 opening, per-rep
    /// error 2/3). A full 152-bit level would need M=260 repetitions; M=96 is
    /// kept as a practical demonstrator trade-off, not a 152-bit target.
    pub fn balanced() -> Self {
        Self {
            num_parties: 3,
            num_repetitions: 96,
            field_element_bytes: 4,
        }
    }

    /// Fast/test parameters: N=3, M=10 → soundness ≈ 2^{-6}.
    /// NOT secure, only for unit tests and benchmarks.
    pub fn fast_insecure() -> Self {
        Self {
            num_parties: 3,
            num_repetitions: 10,
            field_element_bytes: 4,
        }
    }

    /// Compute the minimum M such that `M * log2(N/(N-1)) >= target_bits`,
    /// then return a `ProofParams` with that M and the given N.
    ///
    /// The 2-of-3 ZKBoo opening lets a prover who forges one party's view
    /// pass whenever the hidden party is the forged one or its predecessor
    /// (2 of N outcomes), i.e. per-repetition error (N-1)/N for the N=3
    /// configuration used here (2/3). Requires `num_parties >= 2`.
    pub fn for_soundness_bits(target_bits: f64, num_parties: usize) -> Self {
        assert!(num_parties >= 2, "need at least 2 parties");
        let log2_gain =
            (num_parties as f64 / (num_parties - 1) as f64).log2();
        let m = (target_bits / log2_gain).ceil() as usize;
        Self {
            num_parties,
            num_repetitions: m,
            field_element_bytes: 4,
        }
    }

    /// 128-bit soundness with N=3: M=219 (per-rep error 2/3).
    pub fn secure_128() -> Self {
        Self::for_soundness_bits(128.0, 3)
    }

    /// 100-bit soundness with N=3: M=171 (per-rep error 2/3).
    /// Suitable for internal/permissioned networks where the threat model
    /// is weaker than internet-scale adversaries.
    pub fn secure_100() -> Self {
        Self::for_soundness_bits(100.0, 3)
    }

    /// Fabric-recommended parameters for a permissioned blockchain.
    ///
    /// Uses N=3, M=171 (100-bit soundness at per-rep error 2/3). For a
    /// permissioned blockchain with known, accountable validators, 100 bits
    /// of soundness against a computationally bounded adversary is a
    /// reasonable and standard choice.
    ///
    /// Reference: the Picnic specification (Chase et al., 2017) targets
    /// 128-bit post-quantum security for public-chain use. Permissioned
    /// settings with legal accountability allow lower security margins than
    /// public chains, since the adversary model includes reputational and
    /// legal consequences beyond computational cost.
    pub fn fabric_recommended() -> Self {
        Self::secure_100()
    }

    /// Compute soundness in bits: M * log2(N/(N-1)).
    ///
    /// In each repetition the verifier opens N-1 of N party views. A cheating
    /// prover who forges one party's view (including its commitment) escapes
    /// detection whenever the hidden party is the forged one or its
    /// predecessor's verifier-skipped share — 2 of N outcomes for this
    /// 2-of-3 ZKBoo scheme, i.e. per-repetition error 2/3 at N=3.
    /// Over M independent repetitions the soundness error is ((N-1)/N)^M,
    /// giving M * log2(N/(N-1)) bits of security.
    pub fn soundness_bits(&self) -> f64 {
        debug_assert!(self.num_parties >= 2);
        let n = self.num_parties as f64;
        (self.num_repetitions as f64) * ((n / (n - 1.0)).log2())
    }

    /// Approximate proof size in bytes (rough lower bound, no overhead).
    pub fn estimated_proof_bytes(&self, witness_size_words: usize, circuit_and_gates: usize) -> usize {
        let commitment_bytes = 32; // BLAKE3 output
        // Per repetition: (N-1) views + N commitments
        // Each view: seed (32B, serde-skipped in proof) + mul_output_shares
        let view_size = circuit_and_gates * self.field_element_bytes;
        let per_rep = (self.num_parties - 1) * view_size
            + self.num_parties * commitment_bytes;
        self.num_repetitions * per_rep + witness_size_words * self.field_element_bytes
    }

    /// Validate parameters are sensible.
    pub fn validate(&self) -> crate::Result<()> {
        if self.num_parties != 3 {
            return Err(crate::MpcithError::InvalidParams(
                "num_parties must be exactly 3 (the protocol uses the ZKBoo 3-party verifiable multiplication scheme)".into(),
            ));
        }
        if self.num_repetitions < 1 {
            return Err(crate::MpcithError::InvalidParams(
                "num_repetitions must be >= 1".into(),
            ));
        }
        Ok(())
    }
}

impl Default for ProofParams {
    /// Defaults to balanced (N=3, M=96) for ≈2^{-56} soundness.
    fn default() -> Self {
        Self::balanced()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soundness_bits_fast_insecure() {
        let p = ProofParams::fast_insecure();
        let bits = p.soundness_bits();
        let expected = 10.0 * (3.0_f64 / 2.0).log2();
        assert!((bits - expected).abs() < 1e-10,
            "fast_insecure: got {bits}, expected {expected}");
    }

    #[test]
    fn test_soundness_bits_balanced() {
        let p = ProofParams::balanced();
        let bits = p.soundness_bits();
        let expected = 96.0 * (3.0_f64 / 2.0).log2();
        assert!((bits - expected).abs() < 1e-10,
            "balanced: got {bits}, expected {expected}");
    }

    #[test]
    fn test_for_soundness_bits_128() {
        let p = ProofParams::for_soundness_bits(128.0, 3);
        assert_eq!(p.num_repetitions, 219);
        assert_eq!(p.num_parties, 3);
        assert!(p.soundness_bits() >= 128.0);
    }

    #[test]
    fn test_for_soundness_bits_100() {
        let p = ProofParams::for_soundness_bits(100.0, 3);
        assert_eq!(p.num_repetitions, 171);
        assert_eq!(p.num_parties, 3);
        assert!(p.soundness_bits() >= 100.0);
    }

    #[test]
    fn test_for_soundness_bits_152() {
        let p = ProofParams::for_soundness_bits(152.0, 3);
        assert_eq!(p.num_repetitions, 260);
        assert_eq!(p.num_parties, 3);
        assert!(p.soundness_bits() >= 152.0);
    }

    #[test]
    fn test_secure_128_soundness() {
        let p = ProofParams::secure_128();
        assert!(p.soundness_bits() >= 128.0);
        assert_eq!(p.num_parties, 3);
        assert_eq!(p.num_repetitions, 219);
    }
}
