//! Versioned v2 field, hash, circuit, and proof path.
//!
//! V2 is deliberately separate from the v1 `u32`/MiMC path. Nothing in this
//! module reinterprets a v1 proof or a v1 set root.

pub mod field;
