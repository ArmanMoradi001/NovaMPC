//! # mpcith-zk
//!
//! MPC-in-the-Head Zero-Knowledge Proof library.
//!
//! Implements the MPCitH paradigm (Ishai et al., STOC 2007) with
//! Picnic/KKW-style cut-and-choose and Fiat-Shamir transformation.
//!
//! ## Architecture
//!
//! ```text
//! Circuit ──► MPC Emulator ──► Commitment Scheme ──► Fiat-Shamir
//!  (gates)    (N parties,       (BLAKE3 per view)     (SHA3-256
//!             additive shares)                          challenge)
//! ```

pub mod circuit;
pub mod commitment;
pub mod error;
pub mod fiat_shamir;
pub mod merkle;
pub mod mimc;
pub mod mpc;
pub mod params;
pub mod predicate;
pub mod proof;
pub mod seed_tree;
pub mod sharing;

pub use error::MpcithError;
pub use params::ProofParams;
pub use predicate::Predicate;
pub use proof::{Proof, prove, verify};

pub type Result<T> = std::result::Result<T, MpcithError>;
