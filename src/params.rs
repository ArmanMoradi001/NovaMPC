use serde::{Serialize, Deserialize};

use crate::circuit::{Circuit, Gate};


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

    /// Prototype preset with a 128-bit repetition-count estimate at N=3:
    /// M=219 (per-rep forgery error 2/3).
    ///
    /// The "128-bit" label counts only `M * log2(3/2)` under the
    /// per-repetition forgery model. It does not establish end-to-end
    /// cryptographic security for this prototype (custom MPCitH protocol,
    /// unaudited implementation, 32-bit Merkle root — see
    /// [`ProofParams::soundness_bits`]). Use for sizing experiments, not
    /// production security claims.
    pub fn secure_128() -> Self {
        Self::for_soundness_bits(128.0, 3)
    }

    /// Prototype preset with a 100-bit repetition-count estimate at N=3:
    /// M=171 (per-rep forgery error 2/3).
    ///
    /// As with [`ProofParams::secure_128`], the bit count is a repetition
    /// estimate only — not an end-to-end security claim for the prototype.
    pub fn secure_100() -> Self {
        Self::for_soundness_bits(100.0, 3)
    }

    /// Fabric-oriented sizing preset for a permissioned blockchain.
    ///
    /// Uses N=3, M=171 (100-bit repetition-count estimate at per-rep error
    /// 2/3). Permissioned settings with accountable validators may size
    /// proofs differently than public chains, but adopting this preset is
    /// not a security qualification: production use requires independent
    /// review of the protocol, implementation, and parameters.
    ///
    /// Reference: the Picnic specification (Chase et al., 2017) targets
    /// 128-bit post-quantum security for public-chain use. This prototype
    /// makes no comparable claim.
    pub fn fabric_recommended() -> Self {
        Self::secure_100()
    }

    /// Compute the prototype soundness estimate in bits: M * log2(N/(N-1)).
    ///
    /// In each repetition the verifier opens N-1 of N party views. A cheating
    /// prover who forges one party's view (including its commitment) escapes
    /// detection whenever the hidden party is the forged one or its
    /// predecessor's verifier-skipped share — 2 of N outcomes for this
    /// 2-of-3 ZKBoo scheme, i.e. per-repetition error 2/3 at N=3.
    /// Over M independent repetitions the forgery error is ((N-1)/N)^M,
    /// giving M * log2(N/(N-1)) estimate bits.
    ///
    /// This counts repetitions against the per-repetition forgery model
    /// only. It does not establish end-to-end cryptographic security for the
    /// custom protocol or its implementation: in particular, the membership
    /// Merkle root is a single 32-bit word (~2^16 birthday collision
    /// resistance) and must not be relied on for cryptographic strength.
    pub fn soundness_bits(&self) -> f64 {
        debug_assert!(self.num_parties >= 2);
        let n = self.num_parties as f64;
        (self.num_repetitions as f64) * ((n / (n - 1.0)).log2())
    }

    /// Estimated serialized proof size in bytes.
    ///
    /// Accounts for everything `Proof` serializes under bincode's fixed-width
    /// encoding: per repetition the hidden-party index, commitment root,
    /// GGM co-path, the `N-1` opened views (each: party index, per-`Mul`-gate
    /// output shares, residual input shares where present, commitment
    /// randomness, BLAKE3 authentication path), the per-`AssertEq` and
    /// per-output share rows, plus the fixed header (public inputs, expected
    /// outputs, embedded circuit with all gates, circuit hash, dimensions,
    /// params).
    ///
    /// # Assumptions — approximate upper bound, not exact
    /// - `usize` serializes as 8 bytes, `u32` as 4, enum variants as 4, and
    ///   every `Vec` carries an 8-byte length prefix (bincode 1.x).
    /// - Gate payloads use fixed widths per variant: `Add`/`Mul`/`Xor`
    ///   (three wire indices) take 28 bytes; `AddConst`/`MulConst`/`AssertEq`
    ///   (two indices plus one `u32` constant) take 24 bytes.
    /// - `PartyView.seed` is `#[serde(skip)]` and contributes 0 bytes.
    /// - The residual party's input shares (`4 × num_inputs` bytes) are
    ///   counted in **every** repetition. In reality they appear only when
    ///   the hidden party is not the residual party (~`(N-1)/N` of
    ///   repetitions), so actual proofs measure below this estimate by up
    ///   to one residual block per repetition.
    pub fn estimated_proof_bytes(&self, circuit: &Circuit, num_public_inputs: usize) -> usize {
        let n = self.num_parties;
        let m = self.num_repetitions;
        let tree_depth = n.next_power_of_two().trailing_zeros() as usize;

        let num_mul = circuit.num_mul_gates();
        let num_asserts = circuit.assert_constraints().len();
        let num_inputs = circuit.num_inputs;
        let num_outputs = circuit.num_outputs;

        // Exact fixed widths under bincode fixed-int encoding.
        let gates_bytes: usize = circuit
            .gates
            .iter()
            .map(|gate| match gate {
                Gate::Add { .. } | Gate::Mul { .. } | Gate::Xor { .. } => 4 + 3 * 8,
                Gate::AddConst { .. } | Gate::MulConst { .. } | Gate::AssertEq { .. } => {
                    4 + 2 * 8 + 4
                }
            })
            .sum();

        // One opened view: party_idx(8) + mul shares(8 + 4/mul gate) +
        // residual shares(8 + 4/input, residual party only) +
        // randomness(32) + auth path(8 + 32/depth level).
        let auth_path_bytes = 8 + tree_depth * 32;
        let plain_view_bytes = 8 + (8 + 4 * num_mul) + 8 + 32 + auth_path_bytes;
        let residual_view_bytes = plain_view_bytes + 4 * num_inputs;
        // Upper bound: the residual party is opened in every repetition.
        let opened_views_bytes = 8 + (n - 2) * plain_view_bytes + residual_view_bytes;

        let per_rep_bytes = 8 // hidden_party
            + 32 // commitment_root
            + (8 + tree_depth * 32) // co_path
            + opened_views_bytes
            + (8 + num_outputs * (8 + 4 * n)) // output_shares rows
            + (8 + num_asserts * (8 + 4 * n)); // assert_shares rows

        let fixed_bytes = (8 + 4 * num_public_inputs) // public_inputs
            + (8 + 4 * num_outputs) // expected_outputs
            + 8 // repetitions vec prefix
            + 3 * 8 // ProofParams
            + (8 + 8 + 8 + 8 + gates_bytes) // Circuit dims + gates
            + (8 + 32) // circuit_hash (SHA3-256)
            + 8 + 8; // num_circuit_wires + num_circuit_outputs

        m * per_rep_bytes + fixed_bytes
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

    /// The estimate must upper-bound the real serialized size, and the only
    /// permitted slack is the residual-share block in repetitions where the
    /// hidden party is the residual party (4 bytes × num_inputs per rep).
    fn check_estimate(
        params: &ProofParams,
        circuit: &crate::circuit::Circuit,
        num_public_inputs: usize,
        actual: usize,
    ) {
        let estimate = params.estimated_proof_bytes(circuit, num_public_inputs);
        assert!(
            actual <= estimate,
            "estimate must upper-bound actual size: actual={actual} estimate={estimate}"
        );
        let max_slack = params.num_repetitions * 4 * circuit.num_inputs;
        assert!(
            actual + max_slack >= estimate,
            "actual size too far below estimate: actual={actual} estimate={estimate} \
             max_slack={max_slack} (residual blocks only)"
        );
    }

    #[test]
    fn test_estimated_proof_bytes_addition() {
        // Tiny linear circuit: 2 inputs, [Add, AssertEq], 1 output.
        use crate::predicate::Predicate;

        let params = ProofParams::fast_insecure();
        let pred = Predicate::AdditionCheck { expected_sum: 7 };
        let compiled = pred.compile().unwrap();
        let proof = crate::proof::prove(pred, &[3, 4], &[7], &params).unwrap();
        check_estimate(&params, &compiled.circuit, 1, proof.serialized_size());
    }

    #[test]
    fn test_estimated_proof_bytes_range() {
        // Mul-heavy circuit with many assert rows and 53 witness inputs:
        // exercises per-Mul shares, assert-share rows, and residual blocks.
        use crate::predicate::Predicate;

        let params = ProofParams::fast_insecure();
        let (lo, hi) = (1u32, 1000u32);
        let pred = Predicate::RangeCheck { lo, hi };
        let witness = pred.generate_witness(500).unwrap();
        let compiled = pred.compile().unwrap();
        assert!(compiled.circuit.num_mul_gates() > 0);
        let proof = crate::proof::prove(pred, &witness, &[lo, hi], &params).unwrap();
        check_estimate(&params, &compiled.circuit, 2, proof.serialized_size());
    }

    #[test]
    fn test_estimated_proof_bytes_compound_tx_shape() {
        // Transaction-shaped compound circuit (range ∧ membership over a
        // 4-member set): exercises MiMC Mul volume plus index-bound asserts.
        use crate::predicate::CompoundPredicate;

        let params = ProofParams::fast_insecure();
        let members = vec![10u32, 20, 500, 999];
        let tree = crate::merkle::MerkleTree::build(&members).unwrap();
        let compound = CompoundPredicate::range_and_membership(0, 1000, members);
        let compiled = compound.compile().unwrap();
        let range_w = crate::predicate::Predicate::RangeCheck { lo: 0, hi: 1000 }
            .generate_witness(500)
            .unwrap();
        let mut full = range_w;
        full.extend_from_slice(&crate::predicate::set_membership_witness_vec(
            &tree.prove_membership(2),
        ));
        let public_inputs = vec![0u32, 1000, tree.root()];
        let proof =
            crate::proof::prove_compound(compound, &full, &public_inputs, &params).unwrap();
        check_estimate(&params, &compiled.circuit, public_inputs.len(), proof.serialized_size());
    }
}
