//! Experimental V3 TCitH-MT/ΠLigero research prototype (FR25b).
//!
//! This module is **not secure, not reviewed, and not audited**. Every parameter
//! set is explicitly experimental. V2 is untouched: nothing here reinterprets a
//! v2 proof, and no v2 code depends on this module.
//!
//! Phase 1 covers protocol foundations only: suite identifiers, parameters and
//! validation, packed witness-matrix layout, Shamir sharing, Merkle
//! commitment/opening support, and the degree-enforcing round.

pub mod commit;
pub mod decs;
pub mod matrix;
pub mod params;
pub mod sharing;
pub mod suite;
