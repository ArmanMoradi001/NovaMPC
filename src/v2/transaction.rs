//! Transaction-facing v2 API.
//!
//! This module deliberately does **not** authenticate the set root. The caller
//! must reconstruct [`TransactionStatementV2`] from authenticated ledger or
//! consensus state and pass it to [`verify_transaction_proof_v2`]. A proof is
//! never allowed to supply the expected root, bounds, count, depth, or context.
//!
//! For deployment review, use [`V2Params::secure_127`] (`M = 223`, `q = 1`) or
//! [`V2Params::secure_127_grinding_2_32`] (`M = 277`, `q = 2^32`). The overall
//! claim remains capped at approximately 127 bits by the BN254 `Fr` root;
//! `balanced` and `fast_insecure` are test/benchmark presets only.

use ark_bn254::Fr;

use crate::v2::merkle::MerkleProofV2;
use crate::v2::predicate::{
    compile_from_statement, MembershipStatementV2, RangeStatementV2, StatementV2,
};
use crate::v2::proof::{hash_context_v2, prove, verify_statement, V2Proof};
use crate::v2::suite::V2Params;
use crate::{MpcithError, Result};

/// Public transaction statement for the v2 combined range-and-membership proof.
///
/// `authorized_set_root` must come from the ledger/consensus state controlled
/// by the verifier. It must never be copied from an untrusted proof or request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionStatementV2 {
    /// Inclusive amount range `(lo, hi)`.
    pub amount_range: (u32, u32),
    /// Authenticated v2 set root.
    pub authorized_set_root: Fr,
    /// Canonical depth for `num_members`.
    pub merkle_depth: u32,
    /// Number of real members in the set.
    pub num_members: u32,
    /// Session, chain, policy, or request context.
    pub context: Vec<u8>,
}

impl TransactionStatementV2 {
    /// Build the canonical v2 statement, validating the range and tree shape.
    pub fn to_statement_v2(&self) -> Result<StatementV2> {
        let range = RangeStatementV2::new(self.amount_range.0, self.amount_range.1)?;
        let membership = MembershipStatementV2::new(
            self.authorized_set_root,
            self.num_members,
            self.merkle_depth,
        )?;
        Ok(StatementV2::Combined { range, membership })
    }

    /// Hash the transaction context into the 32-byte value bound by the proof.
    ///
    /// An empty context is rejected so that accidental omission fails closed.
    pub fn context_hash(&self) -> Result<[u8; 32]> {
        if self.context.is_empty() {
            return Err(MpcithError::InvalidParams(
                "v2 transaction context must not be empty".into(),
            ));
        }
        Ok(hash_context_v2(&self.context))
    }
}

/// Private transaction witness for the v2 combined proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionWitnessV2 {
    /// Private amount and member value.
    pub secret_value: u32,
    /// Authentication path for `secret_value` under the statement's root.
    pub merkle_proof: MerkleProofV2,
}

/// Create a combined range-and-membership proof for a transaction statement.
pub fn create_transaction_proof_v2(
    statement: &TransactionStatementV2,
    witness: &TransactionWitnessV2,
    params: &V2Params,
) -> Result<V2Proof> {
    let statement_v2 = statement.to_statement_v2()?;
    let context = statement.context_hash()?;
    let compiled = compile_from_statement(&statement_v2)?;
    let witness = compiled.witness_for(witness.secret_value, Some(&witness.merkle_proof))?;
    prove(&compiled, &witness, context, params)
}

/// Verify a transaction proof against a caller-authenticated statement.
///
/// # Trust boundary
///
/// `expected_statement` MUST be reconstructed from authenticated ledger or
/// consensus state. This function intentionally has no `verify(proof)` overload
/// and never derives the root, range, count, depth, or context from `proof`.
/// The library checks the relation; it does not authenticate the statement.
pub fn verify_transaction_proof_v2(
    proof: &V2Proof,
    expected_statement: &TransactionStatementV2,
    params: &V2Params,
) -> Result<()> {
    let statement_v2 = expected_statement.to_statement_v2()?;
    let context = expected_statement.context_hash()?;
    verify_statement(proof, &statement_v2, context, params)
}
