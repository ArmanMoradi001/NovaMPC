//! Canonical encoding for the v2 BN254 scalar field.
//!
//! The v2 wire format is exactly 32 bytes of big-endian canonical field
//! element. Decoding is strict: values at or above the BN254 scalar modulus
//! are rejected rather than silently reduced.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use thiserror::Error;

/// Number of bytes in the canonical v2 field-element encoding.
pub const FIELD_ELEMENT_BYTES: usize = 32;

/// BN254 scalar modulus, big-endian. Kept as bytes so canonical-input
/// validation does not depend on a reducing decoder.
const MODULUS_BE: [u8; FIELD_ELEMENT_BYTES] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Error returned by strict canonical field decoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FieldEncodingError {
    /// The input was not exactly [`FIELD_ELEMENT_BYTES`] long.
    #[error("invalid field element length: expected {FIELD_ELEMENT_BYTES} bytes, got {0}")]
    WrongLength(usize),

    /// The input was a well-formed 32-byte integer but not less than the
    /// BN254 scalar modulus.
    #[error("non-canonical BN254 field element: value is at or above the modulus")]
    NonCanonical,
}

/// Encode a field element as 32 canonical big-endian bytes.
pub fn encode_fr(value: &Fr) -> [u8; FIELD_ELEMENT_BYTES] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; FIELD_ELEMENT_BYTES];
    // Arkworks returns exactly the modulus width for BN254 Fr. Keep the copy
    // explicit and checked rather than assuming a Vec length on the wire.
    debug_assert!(bytes.len() <= FIELD_ELEMENT_BYTES);
    out[FIELD_ELEMENT_BYTES - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Decode exactly 32 canonical big-endian bytes into a field element.
///
/// Returns [`FieldEncodingError::WrongLength`] for any other length and
/// [`FieldEncodingError::NonCanonical`] for an integer at or above the BN254
/// scalar modulus. The input is never reduced modulo the field.
pub fn decode_fr(bytes: &[u8]) -> Result<Fr, FieldEncodingError> {
    if bytes.len() != FIELD_ELEMENT_BYTES {
        return Err(FieldEncodingError::WrongLength(bytes.len()));
    }

    if bytes >= MODULUS_BE.as_slice() {
        return Err(FieldEncodingError::NonCanonical);
    }

    // The comparison above establishes that this is a canonical integer, so
    // this reduction is the identity on the accepted range.
    Ok(Fr::from_be_bytes_mod_order(bytes))
}

/// Explicit embedding of a `u32` into the v2 field.
///
/// This is the only supported integer-to-field conversion for v2 member
/// values and circuit constants. It is not a signed reinterpretation and not
/// a wrapping conversion.
pub fn fr_from_u32(value: u32) -> Fr {
    Fr::from(value as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BN254 scalar modulus minus one, big-endian.
    const MODULUS_MINUS_ONE_BE: [u8; FIELD_ELEMENT_BYTES] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x00,
    ];

    fn be_u64(value: u64) -> [u8; FIELD_ELEMENT_BYTES] {
        let mut bytes = [0u8; FIELD_ELEMENT_BYTES];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    #[test]
    fn encodes_zero_and_one_canonically() {
        assert_eq!(encode_fr(&Fr::from(0u64)), [0u8; FIELD_ELEMENT_BYTES]);
        assert_eq!(encode_fr(&Fr::from(1u64)), be_u64(1));
    }

    #[test]
    fn round_trips_small_values() {
        for value in [0u32, 1, 42, 0xffff_ffff] {
            let field = fr_from_u32(value);
            let encoded = encode_fr(&field);
            assert_eq!(decode_fr(&encoded).unwrap(), field);
        }
    }

    #[test]
    fn encodes_modulus_minus_one() {
        let value = decode_fr(&MODULUS_MINUS_ONE_BE).unwrap();
        assert_eq!(encode_fr(&value), MODULUS_MINUS_ONE_BE);
        assert_ne!(value, Fr::from(0u64));
    }

    #[test]
    fn rejects_modulus() {
        assert_eq!(
            decode_fr(&MODULUS_BE),
            Err(FieldEncodingError::NonCanonical)
        );
    }

    #[test]
    fn rejects_above_modulus() {
        let mut above = MODULUS_BE;
        above[31] = 0x02;
        assert_eq!(decode_fr(&above), Err(FieldEncodingError::NonCanonical));

        let mut all_ones = [0xffu8; FIELD_ELEMENT_BYTES];
        all_ones[0] = 0x30;
        assert_eq!(decode_fr(&all_ones), Err(FieldEncodingError::NonCanonical));
    }

    #[test]
    fn rejects_wrong_lengths() {
        for len in [0usize, 1, 31, 33, 64] {
            let bytes = vec![0u8; len];
            assert_eq!(
                decode_fr(&bytes),
                Err(FieldEncodingError::WrongLength(len)),
                "length {len} must be rejected"
            );
        }
    }

    #[test]
    fn u32_embedding_is_non_wrapping() {
        assert_eq!(fr_from_u32(u32::MAX), Fr::from(0xffff_ffffu64));
        assert_ne!(fr_from_u32(u32::MAX), Fr::from(-1i64));
    }

    #[test]
    fn rejects_non_canonical_leading_zero_variant() {
        // 33 bytes with a leading zero is still a wrong width. Length and
        // canonicality are separate checks.
        let mut bytes = vec![0u8; FIELD_ELEMENT_BYTES + 1];
        bytes[1..].copy_from_slice(&be_u64(1));
        assert_eq!(
            decode_fr(&bytes),
            Err(FieldEncodingError::WrongLength(FIELD_ELEMENT_BYTES + 1))
        );
    }
}
