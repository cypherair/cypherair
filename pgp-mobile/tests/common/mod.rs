//! Shared test utilities for pgp-mobile integration tests.

pub mod fixtures;
pub mod format;
pub mod tamper;

#[allow(dead_code)]
pub fn load_fixture(name: &str) -> Vec<u8> {
    fixtures::load_fixture(name)
}

#[allow(dead_code)]
pub fn expected_plaintext() -> Vec<u8> {
    fixtures::expected_plaintext()
}

#[allow(dead_code)]
pub fn detect_message_format(ciphertext: &[u8]) -> (bool, bool) {
    format::detect_message_format(ciphertext)
}

#[allow(dead_code)]
pub fn tamper_near_payload_tail(ciphertext: &[u8]) -> Vec<u8> {
    tamper::tamper_near_payload_tail(ciphertext)
}

#[allow(dead_code)]
pub fn tamper_at_ratio(ciphertext: &[u8], numerator: usize, denominator: usize) -> Vec<u8> {
    tamper::tamper_at_ratio(ciphertext, numerator, denominator)
}
