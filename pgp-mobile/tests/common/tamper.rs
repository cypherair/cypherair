//! Helpers for producing deterministic tampered ciphertext inputs in tests.

/// Flip a bit near the very end of the encrypted payload to target the auth/integrity trailer.
///
/// This is more stable than a midpoint bit-flip for tests that want to exercise
/// AEAD/MDC failure paths without corrupting packet headers or session-key packets.
#[allow(dead_code)]
pub fn tamper_near_payload_tail(ciphertext: &[u8]) -> Vec<u8> {
    let mut tampered = ciphertext.to_vec();
    let tamper_pos = tampered.len().saturating_sub(8);
    tampered[tamper_pos] ^= 0x01;
    tampered
}

/// Flip a bit at a fixed ratio of the ciphertext length.
#[allow(dead_code)]
pub fn tamper_at_ratio(ciphertext: &[u8], numerator: usize, denominator: usize) -> Vec<u8> {
    assert!(denominator > 0, "denominator must be non-zero");
    let mut tampered = ciphertext.to_vec();
    let tamper_pos = (tampered.len() * numerator / denominator).min(tampered.len() - 1);
    tampered[tamper_pos] ^= 0x01;
    tampered
}
