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
    /// Conservative parameters: N=3, M=64 → soundness ≈ 2^{-40}.
    /// Larger proofs, simpler code (ZKBoo-style).
    pub fn low_n() -> Self {
        Self {
            num_parties: 3,
            num_repetitions: 64,
            field_element_bytes: 4,
        }
    }

    /// Balanced parameters: N=16, M=38 → soundness ≈ 2^{-40}.
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
    /// Defaults to balanced (N=16, M=38) for ≈2^{-40} soundness.
    fn default() -> Self {
        Self::balanced()
    }
}
