//! Deterministic checks for the 2/3 repetition-count arithmetic.
//!
//! The values are the conditional `q * (2/3)^M` bound from
//! `V2_SOUNDNESS_2_3.md`. This test does not establish a security proof; it
//! only prevents the documented arithmetic from drifting away from the code.

const LOG2_3_OVER_2: f64 = 0.584_962_500_721_156_2;

fn soundness_bits(m: u32, q_log2: u32) -> f64 {
    m as f64 * LOG2_3_OVER_2 - q_log2 as f64
}

fn assert_close(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < 1e-4,
        "expected {expected}, got {actual}"
    );
}

#[test]
fn parameter_table_matches_the_documented_2_3_bound() {
    for (m, q_log2) in [
        (96, 0),
        (96, 20),
        (96, 32),
        (218, 0),
        (223, 0),
        (272, 32),
        (277, 32),
    ] {
        println!(
            "M={m:3} q=2^{q_log2:2}: {:.4} bits",
            soundness_bits(m, q_log2)
        );
    }

    assert_close(soundness_bits(218, 0), 127.5218);
    assert_close(soundness_bits(223, 0), 130.4466);
    assert_close(soundness_bits(272, 32), 127.1098);
    assert_close(soundness_bits(277, 32), 130.0346);
    assert_close(soundness_bits(96, 0), 56.1564);

    // Bare minima clear 127 bits at the stated query budgets, without margin.
    assert!(soundness_bits(218, 0) >= 127.0);
    assert!(soundness_bits(272, 32) >= 127.0);

    // Recommended settings add roughly three bits of margin.
    assert!(soundness_bits(223, 0) > soundness_bits(218, 0) + 2.0);
    assert!(soundness_bits(277, 32) > soundness_bits(272, 32) + 2.0);

    // The old balanced preset is not a secure setting.
    assert!(soundness_bits(96, 0) < 57.0);

    // One repetition has exactly the 2/3 event.
    assert_close(soundness_bits(1, 0), LOG2_3_OVER_2);
}
