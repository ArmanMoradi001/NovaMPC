use serde::{Serialize, Deserialize};


/// Parameters controlling proof size vs soundness trade-off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofParams {
    /// Number of virtual MPC parties (N). Must be >= 3.
    pub num_parties: usize,

    /// Number of parallel repetitions (M).
    pub num_repetitions: usize,

    /// Size of each field element in bytes (we work over u32, so 4).
    pub field_element_bytes: usize,
}

impl ProofParams {
    /// Conservative parameters: N=3, M=64 → soundness ≈ 2^{-101}.
    /// Larger proofs, simpler code (ZKBoo-style).
    pub fn low_n() -> Self {
        Self {
            num_parties: 3,
            num_repetitions: 64,
            field_element_bytes: 4,
        }
    }

    /// Balanced parameters: N=16, M=38 → soundness ≈ 2^{-152}.
    /// Smaller proofs, faster verification (Picnic-style).
    pub fn balanced() -> Self {
        Self {
            num_parties: 16,
            num_repetitions: 38,
            field_element_bytes: 4,
        }
    }

    /// Fast/test parameters: N=3, M=10 → soundness ≈ 2^{-16}.
    /// NOT secure, only for unit tests and benchmarks.
    pub fn fast_insecure() -> Self {
        Self {
            num_parties: 3,
            num_repetitions: 10,
            field_element_bytes: 4,
        }
    }

    /// Compute soundness in bits: M * log2(N).
    ///
    /// In each repetition the verifier opens N-1 of N party views.
    /// A cheating prover fabricating one view per repetition is caught unless
    /// the hidden party happens to be the fabricated one (probability 1/N).
    /// Over M independent repetitions the soundness error is (1/N)^M,
    /// giving M * log2(N) bits of security.
    pub fn soundness_bits(&self) -> f64 {
        (self.num_repetitions as f64) * ((self.num_parties as f64).log2())
    }

    /// Approximate proof size in bytes (rough lower bound, no overhead).
    pub fn estimated_proof_bytes(&self, witness_size_words: usize, circuit_and_gates: usize) -> usize {
        let commitment_bytes = 32; // BLAKE3 output
        // Per repetition: (N-1) views + N commitments
        // Each view: seed (32B) + broadcast messages (circuit_and_gates * field_bytes)
        let view_size = 32 + circuit_and_gates * self.field_element_bytes;
        let per_rep = (self.num_parties - 1) * view_size
            + self.num_parties * commitment_bytes;
        self.num_repetitions * per_rep + witness_size_words * self.field_element_bytes
    }

    /// Validate parameters are sensible.
    pub fn validate(&self) -> crate::Result<()> {
        if self.num_parties < 3 {
            return Err(crate::MpcithError::InvalidParams(
                "num_parties must be >= 3".into(),
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
    /// Defaults to balanced (N=16, M=38) for ≈2^{-152} soundness.
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
        let expected = 10.0 * (3.0_f64).log2();
        assert!((bits - expected).abs() < 1e-10,
            "fast_insecure: got {bits}, expected {expected}");
    }

    #[test]
    fn test_soundness_bits_balanced() {
        let p = ProofParams::balanced();
        let bits = p.soundness_bits();
        let expected = 38.0 * (16.0_f64).log2();
        assert!((bits - expected).abs() < 1e-10,
            "balanced: got {bits}, expected {expected}");
    }
}
