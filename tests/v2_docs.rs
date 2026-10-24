//! Documentation consistency checks for the v2 secure path.
//!
//! These are text checks, not cryptographic tests. They keep the public story
//! aligned with the code after the Step 07 documentation update.

const README: &str = include_str!("../README.md");
const SOUNDNESS: &str = include_str!("../V2_SOUNDNESS_2_3.md");
const AUDIT: &str = include_str!("../V2_AUDIT_PACKAGE.md");

#[test]
fn readme_points_to_the_v2_transaction_api_and_secure_presets() {
    assert!(README.contains("use mpcith_zk::v2::transaction"));
    assert!(README.contains("create_transaction_proof_v2"));
    assert!(README.contains("verify_transaction_proof_v2"));
    assert!(README.contains("V2Params::secure_127()"));
    assert!(README.contains("secure_127_grinding_2_32()"));
    assert!(README.contains("expected` must be reconstructed from authenticated state"));
}

#[test]
fn readme_labels_v1_as_legacy_and_deprecated() {
    assert!(README.contains("Transaction Validation (v1 legacy)"));
    assert!(README.contains("#[deprecated]"));
    assert!(README.contains("32-bit membership root (v1 only)"));
}

#[test]
fn docs_keep_the_review_and_non_claim_status_visible() {
    assert!(SOUNDNESS.contains("DRAFT / AWAITING EXTERNAL REVIEW"));
    assert!(SOUNDNESS.contains("2/3"));
    assert!(SOUNDNESS.contains("127"));
    assert!(AUDIT.contains("AWAITING AUDIT"));
    assert!(AUDIT.contains("knowledge soundness"));
    assert!(AUDIT.contains("zero knowledge"));
}

#[test]
fn readme_does_not_show_the_raw_v2_verifier_as_public_api() {
    // The README may mention the crate-private verifier by name, but its code
    // examples must not call a bare verify/verify_bytes entry point.
    for forbidden in ["verify_bytes(&bytes", "proof::verify(", "verify(&proof"] {
        assert!(
            !README.contains(forbidden),
            "README example must use verify_statement/verify_bytes_statement, found {forbidden}"
        );
    }
}
